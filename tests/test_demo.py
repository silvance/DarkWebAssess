"""Tests for demo-data seeding (`app/demo.py`).

Pins:
  - seed produces documents, entities, and matches through the REAL
    pipeline (not hand-faked rows)
  - the demo watchlist actually matches the demo documents (so a new
    user sees non-empty Matches)
  - seed is idempotent (re-seeding adds no duplicate documents)
  - clear removes exactly the demo rows and nothing else
"""
from __future__ import annotations

import os
import tempfile

import pytest

from app.database import get_connection, init_db
from app.demo import (
    DEMO_SOURCE_NAME,
    DEMO_TAG,
    clear_demo,
    seed_demo,
)
from app.repository import upsert_watchlist_entry


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


def _count(conn, table: str) -> int:
    return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def test_seed_populates_documents_entities_matches(conn):
    stats = seed_demo(conn)
    assert stats["documents_new"] >= 4
    assert stats["entities"] > 0
    assert stats["matches"] > 0
    # And they actually landed in the DB.
    assert _count(conn, "documents") >= 4
    assert _count(conn, "entities") > 0
    assert _count(conn, "matches") > 0


def test_seed_watchlist_matches_demo_docs(conn):
    """The whole point of the demo is a non-empty Matches page. Verify the
    demo watchlist hits the demo documents on multiple match types."""
    seed_demo(conn)
    match_types = {
        r[0] for r in conn.execute("SELECT DISTINCT match_type FROM matches").fetchall()
    }
    # The demo corpus is authored to trigger the CVE rule (exact_cve) and
    # at least one brand indicator (domain / email / keyword). Match types
    # carry an `exact_` prefix for the identity-based matchers.
    assert any("cve" in mt for mt in match_types)
    assert any(
        kind in mt
        for mt in match_types
        for kind in ("domain", "email", "keyword")
    )


def test_seed_marks_source_disabled(conn):
    """The demo source must be disabled so a real `collect` never tries to
    fetch the fake feed URL."""
    seed_demo(conn)
    row = conn.execute(
        "SELECT enabled FROM sources WHERE name = ?", (DEMO_SOURCE_NAME,)
    ).fetchone()
    assert row is not None
    assert row[0] == 0


def test_demo_watchlist_rows_are_tagged(conn):
    seed_demo(conn)
    tagged = conn.execute(
        "SELECT COUNT(*) FROM watchlist WHERE description LIKE ?", (f"%{DEMO_TAG}%",)
    ).fetchone()[0]
    assert tagged >= 4


def test_seed_is_idempotent(conn):
    first = seed_demo(conn)
    docs_after_first = _count(conn, "documents")
    second = seed_demo(conn)
    docs_after_second = _count(conn, "documents")
    # No new documents on the second run (content_hash dedupe).
    assert docs_after_second == docs_after_first
    assert second["documents_new"] == 0
    assert second["documents_dup"] >= first["documents_new"]


def test_clear_removes_only_demo_rows(conn):
    # Add a NON-demo watchlist row and a non-demo document first.
    upsert_watchlist_entry(conn, {
        "type": "domain", "value": "mine.example",
        "description": "my own rule (not demo)",
        "severity": "medium", "enabled": True,
    })
    conn.execute(
        """INSERT INTO documents
           (source_name, source_type, source_url, title, raw_text,
            retrieved_at, content_hash)
           VALUES ('My Feed','rss','https://mine.example/1','keep me',
                   'body', '2026-01-01T00:00:00Z', 'unique-hash-keepme')"""
    )
    conn.commit()

    seed_demo(conn)
    assert _count(conn, "documents") >= 5  # 4 demo + 1 mine
    assert _count(conn, "watchlist") >= 5

    clear_demo(conn)

    # Demo gone, mine survives.
    remaining_docs = [
        r[0] for r in conn.execute("SELECT source_name FROM documents").fetchall()
    ]
    assert DEMO_SOURCE_NAME not in remaining_docs
    assert "My Feed" in remaining_docs

    remaining_wl = [
        r[0] for r in conn.execute("SELECT value FROM watchlist").fetchall()
    ]
    assert "mine.example" in remaining_wl
    assert "acme-corp.example" not in remaining_wl


def test_clear_on_empty_db_is_safe(conn):
    # No seed first — clear must not raise and must report zeros.
    stats = clear_demo(conn)
    assert stats["documents"] == 0
    assert stats["watchlist"] == 0
