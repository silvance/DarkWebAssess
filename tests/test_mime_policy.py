"""Tests for the collector ingestion policy.

Pins down two safety properties:

  1. The Content-Type allowlist is strict — anything not explicitly listed
     (including no header at all, application/octet-stream, image/*, video/*,
     application/pdf, etc.) gets rejected.
  2. Magic-byte sniff backs up the MIME header — a JPEG / PNG / PDF / ZIP /
     EXE served as `text/html` is still caught.

The whole point is that a hostile or compromised onion source cannot trick
the collector into caching binary content (including imagery) into the
document store.
"""
from app.collectors.mime_policy import (
    is_allowed_mime,
    looks_textual_bytes,
    should_ingest,
)


# --- MIME allowlist -----------------------------------------------------
def test_allows_text_html():
    assert is_allowed_mime("text/html") is True
    assert is_allowed_mime("text/html; charset=utf-8") is True
    assert is_allowed_mime("TEXT/HTML") is True


def test_allows_text_plain_and_xml_and_json():
    assert is_allowed_mime("text/plain") is True
    assert is_allowed_mime("application/xhtml+xml") is True
    assert is_allowed_mime("application/rss+xml") is True
    assert is_allowed_mime("application/atom+xml") is True
    assert is_allowed_mime("application/json") is True


def test_rejects_missing_header():
    assert is_allowed_mime("") is False


def test_rejects_octet_stream():
    assert is_allowed_mime("application/octet-stream") is False


def test_rejects_image_mimes():
    for ct in ("image/jpeg", "image/png", "image/gif", "image/webp"):
        assert is_allowed_mime(ct) is False, ct


def test_rejects_video_and_audio():
    for ct in ("video/mp4", "video/quicktime", "audio/mpeg", "audio/ogg"):
        assert is_allowed_mime(ct) is False, ct


def test_rejects_archive_and_pdf():
    for ct in (
        "application/pdf",
        "application/zip",
        "application/x-rar-compressed",
        "application/x-7z-compressed",
        "application/x-msdownload",
    ):
        assert is_allowed_mime(ct) is False, ct


# --- Magic-byte sniff ---------------------------------------------------
def test_sniff_accepts_plain_text():
    assert looks_textual_bytes(b"Hello, world!\n") is True


def test_sniff_accepts_html():
    assert looks_textual_bytes(b"<!DOCTYPE html>\n<html><body>...</body></html>") is True


def test_sniff_accepts_utf8_with_multibyte():
    # Non-ASCII UTF-8 (cyrillic, emoji) should still pass — continuation
    # bytes are >= 0x80 but that's fine.
    assert looks_textual_bytes("Привет, мир! \U0001f600".encode("utf-8")) is True


def test_sniff_rejects_nul_bytes():
    assert looks_textual_bytes(b"hello\x00world more text") is False


def test_sniff_rejects_jpeg_magic():
    assert looks_textual_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF") is False


def test_sniff_rejects_png_magic():
    assert looks_textual_bytes(b"\x89PNG\r\n\x1a\n...") is False


def test_sniff_rejects_pdf_magic():
    assert looks_textual_bytes(b"%PDF-1.7\n%...") is False


def test_sniff_rejects_zip_magic():
    assert looks_textual_bytes(b"PK\x03\x04..." + b"\x00" * 100) is False


def test_sniff_rejects_pe_executable():
    assert looks_textual_bytes(b"MZ\x90\x00\x03\x00") is False


def test_sniff_accepts_empty_body():
    # Empty bodies are not "binary" — caller decides whether to ingest.
    assert looks_textual_bytes(b"") is True


# --- Combined policy ----------------------------------------------------
def test_should_ingest_text_html_with_text_body():
    ok, reason = should_ingest("text/html; charset=utf-8", b"<html>hi</html>")
    assert ok is True
    assert reason == "ok"


def test_should_ingest_rejects_when_mime_disallowed():
    ok, reason = should_ingest("application/octet-stream", b"hello")
    assert ok is False
    assert reason.startswith("disallowed-mime")


def test_should_ingest_rejects_when_body_is_binary_despite_lying_mime():
    """The headline safety property: server says text/html but bytes are a
    JPEG. Magic-byte sniff overrules the header."""
    ok, reason = should_ingest("text/html", b"\xff\xd8\xff\xe0lying jpeg as html")
    assert ok is False
    assert reason == "binary-magic-or-nul"


def test_should_ingest_rejects_missing_content_type():
    ok, reason = should_ingest("", b"<html>x</html>")
    assert ok is False
    assert reason.startswith("disallowed-mime")
