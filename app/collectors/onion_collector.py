"""Tor onion (hidden service) HTTP collector.

Routes through a local Tor SOCKS5 proxy (default 127.0.0.1:9050). We use
the `socks5h://` scheme so DNS resolution happens at the Tor exit, never on
the host — that's important: a `socks5://` (no `h`) proxy would resolve
the hostname locally and leak which onion you're visiting to whatever DNS
resolver is on the box.

Scope guards (matching the project plan's safety boundaries):
- Only fetches the explicit URLs the operator put in `sources.yaml`. No
  crawling, no auto-discovery, no link following.
- Refuses to fetch a non-onion URL even when called directly — defense in
  depth in case someone misconfigures `type: onion` against a clearweb URL.
- One request per source per cycle. The scheduler's per-source backoff
  applies the same as for RSS, so an unresponsive onion gets an
  exponentially growing cooldown rather than being hammered.
"""
from __future__ import annotations

import logging
import re
from typing import Iterator, Optional
from urllib.parse import urlparse

import requests

from app.config import (
    ONION_REQUEST_TIMEOUT,
    ONION_USER_AGENT,
    TOR_SOCKS_HOST,
    TOR_SOCKS_PORT,
)
from app.normalizer import html_to_text, normalize_document

log = logging.getLogger(__name__)

# v2 (16-char) and v3 (56-char) onion hostnames. Tor base32 alphabet is
# a-z and 2-7. Match the host portion of a URL only.
_ONION_HOST_RE = re.compile(
    r"^(?:[a-z2-7]{56}|[a-z2-7]{16})\.onion$",
    re.IGNORECASE,
)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_BINARY_PREVIEW_LIMIT = 200


def is_onion_url(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
    except (TypeError, ValueError):
        return False
    return _ONION_HOST_RE.match(host) is not None


def build_tor_session(
    *,
    host: Optional[str] = None,
    port: Optional[int] = None,
    user_agent: Optional[str] = None,
) -> requests.Session:
    """Return a `requests.Session` that routes through a Tor SOCKS5h proxy.

    Exposed so `tor-check` (the CLI smoke test) and tests can build a
    session without going through `collect_onion`.
    """
    session = requests.Session()
    proxy = f"socks5h://{host or TOR_SOCKS_HOST}:{port or TOR_SOCKS_PORT}"
    session.proxies.update({"http": proxy, "https": proxy})
    session.headers.update({
        "User-Agent": user_agent or ONION_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })
    return session


def _extract_title(html: str) -> Optional[str]:
    m = _TITLE_RE.search(html)
    if not m:
        return None
    title = re.sub(r"\s+", " ", m.group(1)).strip()
    return title or None


def collect_onion(source: dict) -> Iterator[dict]:
    """Fetch a single onion URL and yield one normalized document.

    Raises RuntimeError if the URL isn't a *.onion address — defense in
    depth even though the Pydantic model enforces this at config-load time.
    """
    name = source["name"]
    url = source["url"]
    if not is_onion_url(url):
        raise RuntimeError(f"refusing to fetch non-onion URL via Tor: {url!r}")

    session = build_tor_session()
    timeout = source.get("timeout") or ONION_REQUEST_TIMEOUT

    log.info("Onion fetch %s via %s:%s", name, TOR_SOCKS_HOST, TOR_SOCKS_PORT)
    resp = session.get(url, timeout=timeout, allow_redirects=True)
    resp.raise_for_status()

    content_type = (resp.headers.get("Content-Type") or "").lower()
    is_textual = (
        not content_type
        or "text/html" in content_type
        or "text/plain" in content_type
        or "application/xhtml" in content_type
    )

    if is_textual:
        body = resp.text
        text = html_to_text(body) if "html" in content_type or "<html" in body[:200].lower() else body
        title = _extract_title(body)
    else:
        # Don't ingest binary blobs as documents — record metadata only so
        # the source health page still shows the fetch happened.
        text = (
            f"(binary content, type={content_type or 'unknown'}, "
            f"{len(resp.content)} bytes; first {_BINARY_PREVIEW_LIMIT} bytes hex-elided)"
        )
        title = None

    yield normalize_document(
        source_name=name,
        source_type="onion",
        source_url=url,
        title=title,
        raw_text=text,
        author=None,
        published_at=None,
    )
