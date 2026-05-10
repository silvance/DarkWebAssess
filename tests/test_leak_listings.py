"""Tests for the leak-listing extractor and the scoring boost it triggers."""
import os
import tempfile

import pytest

from app.database import get_connection, init_db
from app.extractors.entities import extract_all
from app.extractors.leak_listings import (
    extract_leak_deadlines,
    extract_leak_indicators,
    extract_leak_sizes,
    extract_leak_status,
)
from app.matching.scoring import score_and_persist
from app.repository import (
    insert_document,
    insert_entities,
    insert_match,
    upsert_watchlist_entry,
)


def values(entities, etype):
    return sorted(e["entity_value"] for e in entities if e["entity_type"] == etype)


# --- status patterns ----------------------------------------------------
def test_status_data_published_normalized():
    out = extract_leak_status("Update: DATA PUBLISHED on the leak site.")
    vals = [e["entity_value"] for e in out]
    assert "data_published" in vals


def test_status_auction_in_progress():
    out = extract_leak_status("AUCTION IN PROGRESS — bids close in 3 hours")
    vals = [e["entity_value"] for e in out]
    assert "auction_in_progress" in vals


def test_status_stage_release():
    out = extract_leak_status("Files leaked across multiple stages: STAGE 2 of 3.")
    vals = [e["entity_value"] for e in out]
    assert "stage_2" in vals


def test_status_negotiations_concluded():
    out = extract_leak_status("Negotiations concluded; no payment received.")
    vals = [e["entity_value"] for e in out]
    assert "negotiation_concluded" in vals


def test_status_does_not_fire_on_single_published():
    """`Published Jan 5, 2026` is news byline noise, not a leak status."""
    out = extract_leak_status("This article was Published on Jan 5, 2026.")
    assert out == []  # bare 'Published' must not match


def test_status_dedups_repeated_phrases():
    out = extract_leak_status("DATA PUBLISHED. Mirror: DATA PUBLISHED.")
    assert len([e for e in out if e["entity_value"] == "data_published"]) == 1


# --- size patterns ------------------------------------------------------
def test_size_extracted_when_leak_word_nearby():
    out = extract_leak_sizes("Stolen data archive: 5.2 TB available now.")
    vals = [e["entity_value"] for e in out]
    assert "5.2 TB" in vals


def test_size_normalizes_unit_to_uppercase():
    out = extract_leak_sizes("compromised database — 800 mb dumped")
    vals = [e["entity_value"] for e in out]
    assert "800 MB" in vals


def test_size_skipped_when_no_leak_context():
    """A Steam Deck review's '256 GB' must not be picked up."""
    out = extract_leak_sizes(
        "The Steam Deck OLED ships with 256 GB of NVMe storage and a 7-inch screen."
    )
    assert out == []


def test_size_dedups_identical_mentions():
    out = extract_leak_sizes("data dump 5.2 TB. mirror: data dump 5.2 TB.")
    assert len([e for e in out if e["entity_value"] == "5.2 TB"]) == 1


# --- deadline patterns --------------------------------------------------
def test_deadline_explicit_label():
    out = extract_leak_deadlines("DEADLINE: 2026-05-15 18:00 UTC")
    assert any("2026-05-15" in e["entity_value"] for e in out)


def test_deadline_relative_phrase():
    out = extract_leak_deadlines("Auction ends in 3 days remaining for bids.")
    vals = [e["entity_value"].lower() for e in out]
    assert any("3 days remaining" in v for v in vals)


def test_deadline_countdown_label():
    out = extract_leak_deadlines("COUNTDOWN: 12 hours 30 minutes")
    assert any("12 hours" in e["entity_value"] for e in out)


# --- combined extractor + extract_all -----------------------------------
def test_leak_indicators_appear_in_extract_all():
    text = (
        "Victim: ACME Corp. DATA PUBLISHED on the leak portal. "
        "Stolen archive: 5.2 TB. DEADLINE: 2026-05-15."
    )
    ents = extract_all(text)
    assert "data_published" in values(ents, "leak_status")
    assert "5.2 TB" in values(ents, "leak_size")
    assert any("2026-05-15" in v for v in values(ents, "leak_deadline"))


def test_extract_all_handles_empty_for_leak_indicators():
    assert extract_all("") == []


def test_indicators_dedup_by_type_and_value():
    text = "DATA PUBLISHED. DATA PUBLISHED again. Mirror: DATA PUBLISHED!"
    out = extract_leak_indicators(text)
    statuses = [e for e in out if e["entity_type"] == "leak_status"]
    assert len(statuses) == 1


# --- scoring boost ------------------------------------------------------
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


def _seed_doc(conn, *, raw_text="example.com appears here.") -> int:
    return insert_document(
        conn,
        {
            "source_name": "Test Feed",
            "source_type": "rss",
            "source_url": "https://example.com/post",
            "title": "Test",
            "raw_text": raw_text,
            "raw_html": None,
            "language": "en",
            "published_at": "2026-05-09T12:00:00Z",
            "retrieved_at": "2026-05-10T00:00:00Z",
            "content_hash": f"h-{hash(raw_text) & 0xFFFF}",
        },
    )


def _make_match(conn, doc_id):
    wid = upsert_watchlist_entry(
        conn,
        {"type": "domain", "value": "example.com", "severity": "medium", "enabled": True},
    )
    return insert_match(
        conn,
        document_id=doc_id,
        watchlist_id=wid,
        matched_value="example.com",
        match_type="exact_domain",
        context="ctx",
        severity="medium",
    )


def test_score_boost_applied_when_leak_status_present(conn):
    doc_id = _seed_doc(conn)
    insert_entities(
        conn,
        doc_id,
        [
            {"entity_type": "domain", "entity_value": "example.com", "context": ""},
            {"entity_type": "leak_status", "entity_value": "data_published", "context": ""},
        ],
    )
    match_id = _make_match(conn, doc_id)
    res, _ = score_and_persist(conn, match_id)
    assert any("leak-site indicators" in r for r in res.reasons)


def test_no_score_boost_without_leak_status(conn):
    doc_id = _seed_doc(conn)
    insert_entities(
        conn,
        doc_id,
        [{"entity_type": "domain", "entity_value": "example.com", "context": ""}],
    )
    match_id = _make_match(conn, doc_id)
    res, _ = score_and_persist(conn, match_id)
    assert not any("leak-site indicators" in r for r in res.reasons)
