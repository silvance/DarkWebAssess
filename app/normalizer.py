import hashlib
import re
from datetime import datetime, timezone
from html import unescape
from typing import Optional

from bs4 import BeautifulSoup

WHITESPACE_RE = re.compile(r"\s+")


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def html_to_text(html: Optional[str]) -> str:
    if not html:
        return ""
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    text = soup.get_text(separator=" ")
    text = unescape(text)
    return WHITESPACE_RE.sub(" ", text).strip()


def content_hash(source_url: str, title: str, raw_text: str) -> str:
    h = hashlib.sha256()
    h.update((source_url or "").encode("utf-8"))
    h.update(b"||")
    h.update((title or "").encode("utf-8"))
    h.update(b"||")
    # Hash a normalized prefix of the text to dedupe near-identical articles.
    snippet = (raw_text or "")[:4096]
    h.update(snippet.encode("utf-8"))
    return h.hexdigest()


def normalize_document(
    source_name: str,
    source_type: str,
    source_url: str,
    title: Optional[str],
    raw_text: Optional[str],
    raw_html: Optional[str] = None,
    author: Optional[str] = None,
    language: Optional[str] = None,
    published_at: Optional[str] = None,
) -> dict:
    text = raw_text or html_to_text(raw_html)
    title_clean = (title or "").strip() or None
    return {
        "source_name": source_name,
        "source_type": source_type,
        "source_url": source_url or "",
        "title": title_clean,
        "author": author,
        "raw_text": text,
        "raw_html": raw_html,
        "language": language,
        "published_at": published_at,
        "retrieved_at": utcnow_iso(),
        "content_hash": content_hash(source_url or "", title_clean or "", text),
    }
