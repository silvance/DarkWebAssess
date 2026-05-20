"""Regex-based observable extraction.

Each extractor returns a list of dicts: {entity_type, entity_value, context}.
The public entrypoint is `extract_all(text) -> list[dict]`, which deduplicates
on (entity_type, entity_value).
"""
import ipaddress
import os
import re
from typing import Iterable, List

# --- Defanging support: re-fang text before extraction so observables that
# were posted as 1.2.3[.]4 or hxxps://example[.]com/ also match.
_DEFANG_REPLACEMENTS = [
    (re.compile(r"\[\.\]"), "."),
    (re.compile(r"\(\.\)"), "."),
    (re.compile(r"\{\.\}"), "."),
    (re.compile(r"\[dot\]", re.IGNORECASE), "."),
    (re.compile(r"\[at\]", re.IGNORECASE), "@"),
    (re.compile(r"\[@\]"), "@"),
    (re.compile(r"\bhxxps?://", re.IGNORECASE), lambda m: m.group(0).replace("xx", "tt", 1)),
]


def refang(text: str) -> str:
    out = text or ""
    for pattern, repl in _DEFANG_REPLACEMENTS:
        out = pattern.sub(repl, out)
    return out


# --- Patterns
URL_RE = re.compile(
    r"\bhttps?://[^\s<>\"'`]+",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
)
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
)
IPV4_RE = re.compile(
    r"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b"
)
IPV6_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"
)
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# Common file-extension TLDs that frequently produce false-positive "domains".
_BAD_DOMAIN_TLDS = {
    "exe", "dll", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "zip", "rar", "tar", "gz", "7z", "png", "jpg", "jpeg", "gif", "bmp",
    "svg", "mp3", "mp4", "mov", "avi", "txt", "log", "json", "xml",
    "py", "js", "ts", "go", "rs", "rb", "sh", "bat", "ps1", "sql",
    "html", "htm", "css", "yaml", "yml", "md", "csv", "ini", "conf",
}

CONTEXT_WINDOW = 80


def _context(text: str, start: int, end: int) -> str:
    a = max(0, start - CONTEXT_WINDOW)
    b = min(len(text), end + CONTEXT_WINDOW)
    snippet = text[a:b].strip()
    return re.sub(r"\s+", " ", snippet)


def _emit(matches: Iterable[re.Match], text: str, entity_type: str, transform=lambda v: v):
    out = []
    for m in matches:
        value = transform(m.group(0))
        if not value:
            continue
        out.append(
            {
                "entity_type": entity_type,
                "entity_value": value,
                "context": _context(text, m.start(), m.end()),
            }
        )
    return out


def extract_urls(text: str) -> List[dict]:
    out = []
    for m in URL_RE.finditer(text):
        url = m.group(0).rstrip(".,);:'\"")
        out.append(
            {
                "entity_type": "url",
                "entity_value": url,
                "context": _context(text, m.start(), m.end()),
            }
        )
    return out


def extract_emails(text: str) -> List[dict]:
    return _emit(EMAIL_RE.finditer(text), text, "email", str.lower)


def extract_ipv4(text: str) -> List[dict]:
    out = []
    for m in IPV4_RE.finditer(text):
        try:
            ip = ipaddress.IPv4Address(m.group(0))
        except ValueError:
            continue
        if ip.is_unspecified:
            continue
        out.append(
            {
                "entity_type": "ip",
                "entity_value": str(ip),
                "context": _context(text, m.start(), m.end()),
            }
        )
    return out


def extract_ipv6(text: str) -> List[dict]:
    out = []
    for m in IPV6_RE.finditer(text):
        try:
            ip = ipaddress.IPv6Address(m.group(0))
        except ValueError:
            continue
        out.append(
            {
                "entity_type": "ipv6",
                "entity_value": str(ip),
                "context": _context(text, m.start(), m.end()),
            }
        )
    return out


def extract_domains(text: str) -> List[dict]:
    out = []
    seen = set()
    for m in DOMAIN_RE.finditer(text):
        candidate = m.group(0).lower().rstrip(".")
        # Skip if it's actually an IP address.
        try:
            ipaddress.ip_address(candidate)
            continue
        except ValueError:
            pass
        tld = candidate.rsplit(".", 1)[-1]
        if tld in _BAD_DOMAIN_TLDS:
            continue
        if candidate.endswith(".onion"):
            # .onion hostnames are emitted by the onion extractor.
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        out.append(
            {
                "entity_type": "domain",
                "entity_value": candidate,
                "context": _context(text, m.start(), m.end()),
            }
        )
    return out


def extract_hashes(text: str) -> List[dict]:
    """Extract MD5, SHA1, SHA256 in that order, longest first to avoid overlap.

    SHA1 candidates immediately preceded by `0x` are skipped — those are
    Ethereum addresses, handled by the wallet extractor.
    """
    out = []
    consumed = []  # list of (start, end) of already-claimed hash positions
    for entity_type, regex in (
        ("sha256", SHA256_RE),
        ("sha1", SHA1_RE),
        ("md5", MD5_RE),
    ):
        for m in regex.finditer(text):
            if any(s <= m.start() < e for s, e in consumed):
                continue
            if entity_type == "sha1" and m.start() >= 2 and text[m.start() - 2 : m.start()].lower() == "0x":
                continue
            consumed.append((m.start(), m.end()))
            out.append(
                {
                    "entity_type": entity_type,
                    "entity_value": m.group(0).lower(),
                    "context": _context(text, m.start(), m.end()),
                }
            )
    return out


def extract_cves(text: str) -> List[dict]:
    return _emit(CVE_RE.finditer(text), text, "cve", str.upper)


# --- Optional Rust accelerator -----------------------------------------
# If `dwa_extractors` (the Rust extension built via PyO3 in
# crates/dwa_extractors/) is installed, we use it for the URL / email /
# IPv4 / IPv6 / hash / CVE hot path — typically 10-50x faster. Pure
# Python is the fallback; the project runs identically either way.
#
# DWA_DISABLE_RUST=1 forces the Python path even when the wheel is
# installed. Useful for:
#   - debugging an extraction difference suspected in the Rust side
#   - benchmarking the Python implementation against the Rust one on
#     the same hardware without uninstalling the wheel
#   - operator preference (e.g. you don't trust the bundled .so)
try:
    from dwa_extractors import extract_observables as _rust_extract_observables
    _HAVE_RUST = True
except ImportError:
    _rust_extract_observables = None  # type: ignore[assignment]
    _HAVE_RUST = False


def _rust_enabled() -> bool:
    """Whether the Rust accelerator should be used for this call.

    Checked on every call (not just at import) so DWA_DISABLE_RUST can
    be flipped at runtime — important for tests and for the operator
    toggling without restarting the process.
    """
    if not _HAVE_RUST:
        return False
    return os.getenv("DWA_DISABLE_RUST", "0").lower() not in ("1", "true", "yes", "on")


def _python_simple_observables(text: str) -> List[dict]:
    """Fallback: run the per-type Python extractors and concatenate."""
    out: List[dict] = []
    out.extend(extract_urls(text))
    out.extend(extract_emails(text))
    out.extend(extract_ipv4(text))
    out.extend(extract_ipv6(text))
    out.extend(extract_hashes(text))
    out.extend(extract_cves(text))
    return out


def extract_simple_observables(text: str) -> List[dict]:
    """Extract URL / email / IPv4 / IPv6 / MD5 / SHA1 / SHA256 / CVE.

    Routes through the Rust accelerator when available and not disabled,
    falls back to the pure-Python extractors otherwise. The two
    implementations are kept in sync by
    `tests/test_extractor_bench.py`, which asserts identical output on a
    synthetic corpus.
    """
    if _rust_enabled():
        return _rust_extract_observables(text)
    return _python_simple_observables(text)


def extract_all(text: str) -> List[dict]:
    if not text:
        return []
    # Lazy imports avoid a circular path during early app startup.
    from app.extractors.handles import extract_handles
    from app.extractors.leak_listings import extract_leak_indicators
    from app.extractors.named_entities import extract_named_entities
    from app.extractors.onion import extract_onions
    from app.extractors.wallets import extract_wallets

    cleaned = refang(text)
    results = []
    # Rust-accelerated path (URL/email/IPv4/IPv6/hashes/CVE).
    results.extend(extract_simple_observables(cleaned))
    # Python-only extractors (need TLD list, YAML lookups, etc.).
    results.extend(extract_onions(cleaned))
    results.extend(extract_domains(cleaned))
    results.extend(extract_wallets(cleaned))
    results.extend(extract_handles(cleaned))
    results.extend(extract_named_entities(cleaned))
    results.extend(extract_leak_indicators(cleaned))

    # De-dupe on (type, value), keep first context.
    seen = set()
    deduped = []
    for ent in results:
        key = (ent["entity_type"], ent["entity_value"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(ent)
    return deduped
