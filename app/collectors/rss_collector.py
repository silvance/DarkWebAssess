import logging
from calendar import timegm
from datetime import datetime, timezone
from typing import Iterator, Optional

import feedparser
import requests

from app.config import HTTP_TIMEOUT, USER_AGENT
from app.normalizer import html_to_text, normalize_document

log = logging.getLogger(__name__)


def _parse_published(entry) -> Optional[str]:
    for key in ("published_parsed", "updated_parsed", "created_parsed"):
        ts = entry.get(key)
        if ts:
            try:
                return datetime.fromtimestamp(timegm(ts), tz=timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
            except (TypeError, ValueError, OverflowError):
                continue
    return None


def _entry_text(entry) -> str:
    content_blocks = entry.get("content") or []
    for block in content_blocks:
        value = block.get("value") if isinstance(block, dict) else None
        if value:
            return html_to_text(value)
    summary = entry.get("summary") or entry.get("description") or ""
    return html_to_text(summary)


def fetch_feed(url: str) -> feedparser.FeedParserDict:
    headers = {"User-Agent": USER_AGENT}
    resp = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT)
    resp.raise_for_status()
    return feedparser.parse(resp.content)


def collect_rss(source: dict) -> Iterator[dict]:
    """Yield normalized documents for each entry in an RSS feed source.

    `source` is a dict from sources.yaml with keys: name, type, url, enabled.
    """
    name = source["name"]
    url = source["url"]
    parsed = fetch_feed(url)
    if parsed.bozo and not parsed.entries:
        raise RuntimeError(f"Failed to parse feed {url}: {parsed.bozo_exception}")

    for entry in parsed.entries:
        link = entry.get("link") or url
        title = entry.get("title")
        text = _entry_text(entry)
        author = entry.get("author")
        published = _parse_published(entry)
        yield normalize_document(
            source_name=name,
            source_type="rss",
            source_url=link,
            title=title,
            raw_text=text,
            author=author,
            published_at=published,
        )
