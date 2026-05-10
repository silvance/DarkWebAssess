"""Regex-based observable extraction.

Each extractor returns a list of dicts: {entity_type, entity_value, context}.
The public entrypoint is `extract_all(text) -> list[dict]`, which deduplicates
on (entity_type, entity_value).
"""
import ipaddress
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
    """Extract MD5, SHA1, SHA256 in that order, longest first to avoid overlap."""
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


def extract_all(text: str) -> List[dict]:
    if not text:
        return []
    cleaned = refang(text)
    results = []
    results.extend(extract_urls(cleaned))
    results.extend(extract_emails(cleaned))
    results.extend(extract_ipv4(cleaned))
    results.extend(extract_ipv6(cleaned))
    results.extend(extract_domains(cleaned))
    results.extend(extract_hashes(cleaned))
    results.extend(extract_cves(cleaned))

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
