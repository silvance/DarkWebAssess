import os
import sqlite3
import tempfile

import pytest

from app.database import get_connection, init_db
from app.repository import insert_document
from app.search import escape_fts, fts_available, reindex, search_documents


def _has_fts5() -> bool:
    try:
        sqlite3.connect(":memory:").execute("CREATE VIRTUAL TABLE _t USING fts5(x)")
        return True
    except sqlite3.OperationalError:
        return False


pytestmark = pytest.mark.skipif(not _has_fts5(), reason="sqlite3 build lacks FTS5")


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


def _insert(conn, **kw):
    payload = {
        "source_name": "Test Feed",
        "source_type": "rss",
        "source_url": "https://example.com/a",
        "title": "Hello",
        "raw_text": "world",
        "raw_html": None,
        "language": None,
        "published_at": "2026-05-10T00:00:00Z",
        "retrieved_at": "2026-05-10T00:00:00Z",
        "content_hash": "h",
    }
    payload.update(kw)
    return insert_document(conn, payload)


# --- escape_fts ---------------------------------------------------------
def test_escape_quotes_each_token():
    assert escape_fts("ransomware leak") == '"ransomware" "leak"'


def test_escape_handles_empty():
    assert escape_fts("") == '""'
    assert escape_fts("   ") == '""'


def test_escape_strips_punctuation():
    assert escape_fts("(boot.exe)") == '"boot.exe"'


def test_escape_supports_prefix_wildcard():
    assert escape_fts("lock*") == '"lock"*'


# --- end-to-end search --------------------------------------------------
def test_fts_available(conn):
    assert fts_available(conn) is True


def test_search_finds_text_in_body(conn):
    _insert(
        conn,
        title="LockBit affiliate update",
        raw_text="The ransomware group LockBit posted a new victim.",
        source_url="https://example.com/lockbit",
        content_hash="h1",
    )
    rows = search_documents(conn, "lockbit ransomware")
    assert len(rows) == 1
    assert rows[0]["source_url"] == "https://example.com/lockbit"
    assert "<<" in rows[0]["snippet"] or "LockBit" in rows[0]["snippet"]


def test_search_filters_by_source(conn):
    _insert(conn, title="A", raw_text="lockbit", source_name="A Feed", source_url="https://a", content_hash="h-a")
    _insert(conn, title="B", raw_text="lockbit", source_name="B Feed", source_url="https://b", content_hash="h-b")
    rows = search_documents(conn, "lockbit", source_name="B Feed")
    assert len(rows) == 1
    assert rows[0]["source_name"] == "B Feed"


def test_search_no_match(conn):
    _insert(conn, title="x", raw_text="y", content_hash="hxy")
    assert search_documents(conn, "nonexistentterm") == []


def test_triggers_remove_deleted_docs(conn):
    doc_id = _insert(conn, title="t", raw_text="findme please", content_hash="h-del")
    assert len(search_documents(conn, "findme")) == 1
    conn.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
    conn.commit()
    assert search_documents(conn, "findme") == []


def test_reindex_after_manual_insert(conn):
    # Bypass triggers by inserting via raw SQL with FTS5 disabled momentarily.
    conn.executescript("DROP TRIGGER documents_ai")
    _insert(conn, title="manual", raw_text="rebuilt", content_hash="h-manual")
    assert search_documents(conn, "rebuilt") == []
    n = reindex(conn)
    assert n >= 1
    assert len(search_documents(conn, "rebuilt")) == 1
