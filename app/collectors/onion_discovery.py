"""Onion-discovery collector.

Fetches the operator-curated list of aggregator pages in
`onion_directories.yaml` and extracts any `.onion` URLs they list. Each
extracted URL is upserted as a PENDING candidate in `onion_candidates`.

Hard safety boundary
--------------------
- Discovery ONLY fetches the seeded directory URLs. It NEVER fetches a
  candidate URL it has just discovered. A candidate is just a string in
  the queue until the operator approves it and manually adds it to
  `sources.yaml`, after which the regular onion collector handles it.
- `transport=clearweb` uses plain HTTPS (no Tor). `transport=tor` routes
  through the local SOCKS5h proxy. The pydantic model enforces that the
  transport matches the URL scheme.
- We cap response size (`_MAX_BYTES`) and parse-time link count
  (`_MAX_LINKS_PER_PAGE`) so a hostile aggregator can't blow up the
  collector.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Iterable, List, Optional
from urllib.parse import urldefrag, urlparse

import requests
from bs4 import BeautifulSoup

from app.collectors.onion_collector import build_tor_session
from app.config import HTTP_TIMEOUT, ONION_REQUEST_TIMEOUT, USER_AGENT
from app.config_models import OnionDirectoryEntry
from app.extractors.onion import ONION_RE

log = logging.getLogger(__name__)

# Hard caps so a hostile aggregator can't DoS us.
_MAX_BYTES = 2_000_000          # 2 MB per page
_MAX_LINKS_PER_PAGE = 2_000     # don't process unbounded link soup
_MAX_TITLE_CHARS = 200

# Matches a .onion hostname inside a URL (path optional). Used as a fallback
# when an aggregator doesn't use proper <a href> markup.
_ONION_URL_RE = re.compile(
    r"\b(https?://(?:[a-z2-7]{56}|[a-z2-7]{16})\.onion(?:/[^\s\"'<>]*)?)",
    re.IGNORECASE,
)


@dataclass
class DiscoveredOnion:
    url: str            # normalized: lowercase host, no fragment
    host: str           # just the onion hostname
    title: Optional[str]
    source_name: str    # which aggregator listed it


def _normalize_onion_url(raw: str) -> Optional[tuple[str, str]]:
    """Return (canonical_url, host) or None if the URL isn't an onion URL."""
    try:
        url, _frag = urldefrag(raw.strip())
        parsed = urlparse(url)
    except (ValueError, AttributeError):
        return None
    if parsed.scheme not in ("http", "https"):
        return None
    host = (parsed.hostname or "").lower()
    if not host.endswith(".onion"):
        return None
    # Validate onion host shape (v2 16-char or v3 56-char on Tor base32).
    if not ONION_RE.fullmatch(host):
        return None
    # Re-assemble with lowercased host. Preserve path, drop port (onions
    # rarely use ports; if present, keep it).
    netloc = host
    if parsed.port:
        netloc = f"{host}:{parsed.port}"
    path = parsed.path or "/"
    canonical = f"{parsed.scheme}://{netloc}{path}"
    if parsed.query:
        canonical += f"?{parsed.query}"
    return canonical, host


def _fetch(directory: OnionDirectoryEntry) -> Optional[str]:
    """Fetch the directory page and return its HTML body (or None on failure).

    Streaming + size cap so an aggregator can't feed us a multi-GB response.
    """
    if directory.transport == "tor":
        session = build_tor_session()
        timeout = ONION_REQUEST_TIMEOUT
    else:
        session = requests.Session()
        session.headers.update({"User-Agent": USER_AGENT})
        timeout = HTTP_TIMEOUT
    try:
        resp = session.get(
            directory.url,
            timeout=timeout,
            allow_redirects=True,
            stream=True,
        )
    except requests.RequestException as exc:
        log.warning("discovery: fetch failed for %s: %s", directory.name, exc)
        return None
    try:
        if resp.status_code >= 400:
            log.warning(
                "discovery: %s returned HTTP %s", directory.name, resp.status_code
            )
            return None
        ctype = (resp.headers.get("Content-Type") or "").lower()
        if "html" not in ctype and "text" not in ctype:
            log.info(
                "discovery: %s served %s; skipping (need HTML)", directory.name, ctype
            )
            return None
        chunks: list[bytes] = []
        total = 0
        for chunk in resp.iter_content(chunk_size=65536):
            if not chunk:
                continue
            total += len(chunk)
            if total > _MAX_BYTES:
                log.warning(
                    "discovery: %s exceeded %d-byte cap; truncating",
                    directory.name, _MAX_BYTES,
                )
                break
            chunks.append(chunk)
        body = b"".join(chunks)
        return body.decode("utf-8", errors="replace")
    finally:
        resp.close()


def _extract_from_html(
    html: str, source_name: str
) -> List[DiscoveredOnion]:
    out: List[DiscoveredOnion] = []
    seen_urls: set[str] = set()
    soup = BeautifulSoup(html, "html.parser")

    # Pass 1: proper <a href=...> links.
    anchors = soup.find_all("a", href=True, limit=_MAX_LINKS_PER_PAGE)
    for a in anchors:
        href = a.get("href") or ""
        norm = _normalize_onion_url(href)
        if not norm:
            continue
        canonical, host = norm
        if canonical in seen_urls:
            continue
        seen_urls.add(canonical)
        title = (a.get_text(strip=True) or "")[:_MAX_TITLE_CHARS] or None
        out.append(DiscoveredOnion(
            url=canonical, host=host, title=title, source_name=source_name,
        ))

    # Pass 2: free-text fallback for aggregators that print URLs without <a>.
    # Bounded by re.findall — we already cap response bytes.
    if len(out) < _MAX_LINKS_PER_PAGE:
        text = soup.get_text(" ")
        for m in _ONION_URL_RE.finditer(text):
            norm = _normalize_onion_url(m.group(1))
            if not norm:
                continue
            canonical, host = norm
            if canonical in seen_urls:
                continue
            seen_urls.add(canonical)
            out.append(DiscoveredOnion(
                url=canonical, host=host, title=None, source_name=source_name,
            ))
            if len(out) >= _MAX_LINKS_PER_PAGE:
                break

    return out


def discover_from_directory(
    directory: OnionDirectoryEntry,
) -> List[DiscoveredOnion]:
    """Fetch one directory and return the onion URLs it lists. Never raises."""
    if not directory.enabled:
        return []
    html = _fetch(directory)
    if not html:
        return []
    return _extract_from_html(html, directory.name)


def discover_from_directories(
    directories: Iterable[OnionDirectoryEntry],
) -> List[DiscoveredOnion]:
    out: List[DiscoveredOnion] = []
    seen: set[str] = set()
    for d in directories:
        if not d.enabled:
            continue
        log.info("discovery: fetching %s (%s)", d.name, d.transport)
        for cand in discover_from_directory(d):
            if cand.url in seen:
                continue
            seen.add(cand.url)
            out.append(cand)
    return out
