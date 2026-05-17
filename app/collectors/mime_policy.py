"""Strict ingestion policy for collectors.

The threat model: a hostile or compromised source could serve binary content
(images, video, executables) under any URL we fetch. Storing image bytes
into the document table — even as a hex-elided placeholder row — creates
the chance of inadvertently caching CSAM or other illegal material from
onion sources. We want a hard rule: **textual content only, and only
content whose Content-Type AND first bytes both look textual.**

Allowlist, not denylist. Anything we haven't explicitly allowed is dropped.

This module is used by every collector that fetches arbitrary HTTP content
(currently `onion_collector` and `onion_discovery`). The RSS collector
delegates parsing to feedparser, which only extracts text fields, so the
risk surface there is bounded by feedparser's behavior.
"""
from __future__ import annotations

from typing import Tuple

# Allowed Content-Type prefixes. Anything not starting with one of these is
# rejected. We deliberately omit application/octet-stream, application/pdf,
# image/*, audio/*, video/*, application/zip, etc.
_ALLOWED_MIME_PREFIXES = (
    "text/html",
    "text/plain",
    "text/xml",
    "application/xhtml+xml",
    "application/xhtml",
    "application/xml",
    "application/rss+xml",
    "application/atom+xml",
    "application/json",        # for index pages that hand back JSON listings
)

# How many bytes to peek at when sniffing for "does this actually look textual?"
_SNIFF_BYTES = 1024

# Magic byte signatures of common binary file formats. If the response starts
# with any of these, reject regardless of what the server claimed.
_BINARY_MAGIC = (
    b"\xff\xd8\xff",            # JPEG
    b"\x89PNG\r\n\x1a\n",       # PNG
    b"GIF87a", b"GIF89a",       # GIF
    b"BM",                      # BMP (fragile; only 2 bytes — also a denylist hit)
    b"%PDF-",                   # PDF
    b"PK\x03\x04",              # ZIP / OOXML / APK / JAR / DOCX
    b"\x1f\x8b",                # gzip
    b"7z\xbc\xaf'\x1c",         # 7z
    b"Rar!\x1a\x07",            # RAR
    b"MZ",                      # PE/EXE (also a 2-byte hit — see comment below)
    b"\x7fELF",                 # ELF
    b"\x00\x00\x00 ftypisom",   # MP4 (offset 0)
    b"\x00\x00\x00\x18ftyp",    # MP4 / MOV family (any ftyp)
    b"RIFF",                    # WAV / AVI / WEBP container
    b"OggS",                    # OGG
    b"ID3",                     # MP3 with ID3 tag
    b"\xff\xfb", b"\xff\xf3", b"\xff\xf2",  # bare MP3 frame sync
    b"fLaC",                    # FLAC
    b"\x1aE\xdf\xa3",           # Matroska / WebM
)


def is_allowed_mime(content_type: str) -> bool:
    """Return True iff the Content-Type header is in the textual allowlist."""
    if not content_type:
        return False
    ct = content_type.lower().split(";", 1)[0].strip()
    return any(ct.startswith(prefix) for prefix in _ALLOWED_MIME_PREFIXES)


def looks_textual_bytes(body: bytes) -> bool:
    """Heuristic: does the start of this byte string look like text?

    Two rules:
      1. It does not start with a known binary magic signature.
      2. Of the first _SNIFF_BYTES, the fraction of NUL or non-printable
         (outside common ASCII + UTF-8 continuation bytes) is below 5%.
    """
    if not body:
        return True  # empty bodies are fine; nothing to ingest, but not "binary"
    sniff = body[:_SNIFF_BYTES]
    for magic in _BINARY_MAGIC:
        if sniff.startswith(magic):
            return False
    suspicious = 0
    for b in sniff:
        # Allow tab/newline/carriage-return + printable ASCII + UTF-8 cont.
        if b == 0:
            return False  # any NUL → binary
        if b < 0x09 or (b > 0x0D and b < 0x20):
            suspicious += 1
    return suspicious / max(1, len(sniff)) < 0.05


def should_ingest(content_type: str, body: bytes) -> Tuple[bool, str]:
    """Return (ok, reason). `reason` is a short string suitable for logging.

    A response only passes when both the declared MIME AND the magic-byte
    sniff agree that it's textual.
    """
    if not is_allowed_mime(content_type):
        return False, f"disallowed-mime:{content_type or 'missing'}"
    if not looks_textual_bytes(body):
        return False, "binary-magic-or-nul"
    return True, "ok"
