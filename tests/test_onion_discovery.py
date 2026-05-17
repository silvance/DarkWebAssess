"""Tests for the onion-discovery collector + candidate repository.

Two safety properties get pinned down here:

  1. URL normalization rejects non-onion hosts and malformed onion hostnames,
     so a hostile aggregator can't sneak a clearweb URL into the candidate
     queue.
  2. `upsert_onion_candidate` on re-discovery never resets the status — once
     rejected stays rejected. The whole point of the queue is that an
     operator's NO is durable.
"""
from __future__ import annotations

import os
import tempfile
from typing import Optional

import pytest

from app.collectors.onion_discovery import (
    DiscoveredOnion,
    _extract_from_html,
    _normalize_onion_url,
)
from app.database import get_connection, init_db
from app.repository import (
    get_onion_candidate,
    list_onion_candidates,
    set_onion_candidate_status,
    upsert_onion_candidate,
)


# --- URL normalization --------------------------------------------------
def test_normalize_lowercases_host_and_strips_fragment():
    raw = "http://ABCDEFGHIJKLMNOP.onion/path#frag"
    norm = _normalize_onion_url(raw)
    assert norm is not None
    url, host = norm
    assert url == "http://abcdefghijklmnop.onion/path"
    assert host == "abcdefghijklmnop.onion"


def test_normalize_accepts_v3_onion():
    v3 = "a" * 56
    raw = f"https://{v3}.onion/"
    norm = _normalize_onion_url(raw)
    assert norm is not None
    assert norm[1] == f"{v3}.onion"


def test_normalize_rejects_clearweb():
    assert _normalize_onion_url("https://example.com/") is None


def test_normalize_rejects_non_http_scheme():
    assert _normalize_onion_url("ftp://abcdefghijklmnop.onion/") is None


def test_normalize_rejects_malformed_onion_host():
    # "1" is not in the Tor base32 alphabet (a-z, 2-7).
    bad = "1bcdefghijklmnop.onion"
    assert _normalize_onion_url(f"http://{bad}/") is None


def test_normalize_rejects_wrong_length_onion():
    # 17 chars — neither v2 (16) nor v3 (56).
    bad = "a" * 17 + ".onion"
    assert _normalize_onion_url(f"http://{bad}/") is None


# --- HTML extraction ---------------------------------------------------
_AHMIA_LIKE_HTML = """
<html><body>
  <ul>
    <li><a href="http://abcdefghijklmnop.onion/">Onion News</a></li>
    <li><a href="https://example.com/">Clearweb decoy</a></li>
    <li><a href="http://duplicateabcdefg.onion/">Duplicate</a></li>
    <li><a href="http://DUPLICATEabcdefg.onion/">Duplicate (case)</a></li>
  </ul>
  <p>Raw text mention: http://qrstuvwxyzabcdef.onion/path</p>
</body></html>
"""


def test_extract_from_html_finds_unique_onions():
    found = _extract_from_html(_AHMIA_LIKE_HTML, source_name="ahmia")
    urls = {c.url for c in found}
    assert "http://abcdefghijklmnop.onion/" in urls
    assert "http://duplicateabcdefg.onion/" in urls
    assert "http://qrstuvwxyzabcdef.onion/path" in urls
    # No clearweb leak.
    assert not any("example.com" in u for u in urls)
    # Case-only duplicate collapsed.
    dup = [c for c in found if "duplicate" in c.host]
    assert len(dup) == 1


def test_extract_from_html_captures_link_text_as_title():
    found = _extract_from_html(_AHMIA_LIKE_HTML, source_name="ahmia")
    by_host = {c.host: c for c in found}
    assert by_host["abcdefghijklmnop.onion"].title == "Onion News"


def test_extract_from_html_source_name_is_propagated():
    found = _extract_from_html(_AHMIA_LIKE_HTML, source_name="some-index")
    assert all(c.source_name == "some-index" for c in found)


# --- Repository: candidate CRUD ----------------------------------------
@pytest.fixture
def conn():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    c = get_connection(path)
    try:
        yield c
    finally:
        c.close()
        os.unlink(path)


def _add(conn, url: str, host: Optional[str] = None,
         title: Optional[str] = None, source: str = "ahmia"):
    return upsert_onion_candidate(
        conn,
        url=url,
        host=host or url.split("//", 1)[1].split("/", 1)[0],
        title=title,
        source_name=source,
    )


def test_upsert_inserts_pending_on_first_seen(conn):
    row = _add(conn, "http://abcdefghijklmnop.onion/")
    assert row["status"] == "pending"
    assert row["times_seen"] == 1
    assert row["first_source"] == "ahmia"


def test_upsert_dedupes_on_url(conn):
    _add(conn, "http://abcdefghijklmnop.onion/", source="ahmia")
    row = _add(conn, "http://abcdefghijklmnop.onion/", source="dark.fail")
    assert row["times_seen"] == 2
    # Both sources merged in.
    import json
    sources = json.loads(row["sources_json"])
    assert set(sources) == {"ahmia", "dark.fail"}


def test_rediscovery_does_not_reset_rejected_status(conn):
    row = _add(conn, "http://abcdefghijklmnop.onion/")
    set_onion_candidate_status(conn, row["id"], "rejected", reviewed_by="alice")
    # Re-discover — same URL appears in another directory.
    refreshed = _add(conn, "http://abcdefghijklmnop.onion/", source="other-index")
    assert refreshed["status"] == "rejected"
    assert refreshed["times_seen"] == 2


def test_rediscovery_does_not_reset_approved_status(conn):
    row = _add(conn, "http://abcdefghijklmnop.onion/")
    set_onion_candidate_status(conn, row["id"], "approved")
    refreshed = _add(conn, "http://abcdefghijklmnop.onion/")
    assert refreshed["status"] == "approved"


def test_list_filters_by_status(conn):
    a = _add(conn, "http://abcdefghijklmnop.onion/")
    b = _add(conn, "http://qrstuvwxyzabcdef.onion/")
    set_onion_candidate_status(conn, b["id"], "rejected")
    pending = list_onion_candidates(conn, status="pending")
    rejected = list_onion_candidates(conn, status="rejected")
    assert {r["id"] for r in pending} == {a["id"]}
    assert {r["id"] for r in rejected} == {b["id"]}


def test_list_search_matches_url_and_title(conn):
    _add(conn, "http://abcdefghijklmnop.onion/", title="Marketplace alpha")
    _add(conn, "http://qrstuvwxyzabcdef.onion/", title="Forum beta")
    by_url = list_onion_candidates(conn, search="qrstuvwxyz")
    by_title = list_onion_candidates(conn, search="Marketplace")
    assert len(by_url) == 1 and by_url[0]["host"].startswith("qrst")
    assert len(by_title) == 1 and by_title[0]["title"] == "Marketplace alpha"


def test_set_status_returns_none_for_unknown_id(conn):
    assert set_onion_candidate_status(conn, 9999, "approved") is None


def test_set_status_rejects_invalid_status(conn):
    row = _add(conn, "http://abcdefghijklmnop.onion/")
    with pytest.raises(ValueError):
        set_onion_candidate_status(conn, row["id"], "yolo")


def test_get_candidate_returns_dict_or_none(conn):
    row = _add(conn, "http://abcdefghijklmnop.onion/")
    assert get_onion_candidate(conn, row["id"])["url"] == "http://abcdefghijklmnop.onion/"
    assert get_onion_candidate(conn, 9999) is None


# --- Safety: title length cap, sources_json shape ----------------------
def test_long_title_is_truncated_on_extract():
    long_title = "x" * 1000
    html = f'<a href="http://abcdefghijklmnop.onion/">{long_title}</a>'
    found = _extract_from_html(html, source_name="any")
    assert len(found) == 1
    assert found[0].title is not None
    assert len(found[0].title) <= 200
