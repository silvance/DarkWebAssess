import sqlite3
from contextlib import contextmanager
from pathlib import Path

from app.config import DATABASE_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    type TEXT NOT NULL,
    url TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_checked_at TEXT,
    last_success_at TEXT,
    last_error TEXT,
    error_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_name TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_url TEXT NOT NULL,
    title TEXT,
    author TEXT,
    raw_text TEXT,
    raw_html TEXT,
    language TEXT,
    published_at TEXT,
    retrieved_at TEXT NOT NULL,
    content_hash TEXT UNIQUE NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_documents_source ON documents(source_name);
CREATE INDEX IF NOT EXISTS idx_documents_retrieved ON documents(retrieved_at);

CREATE TABLE IF NOT EXISTS entities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL,
    entity_type TEXT NOT NULL,
    entity_value TEXT NOT NULL,
    context TEXT,
    first_seen TEXT NOT NULL,
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
    UNIQUE(document_id, entity_type, entity_value)
);
CREATE INDEX IF NOT EXISTS idx_entities_value ON entities(entity_value);
CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(entity_type);

CREATE TABLE IF NOT EXISTS watchlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL DEFAULT 'medium',
    enabled INTEGER NOT NULL DEFAULT 1,
    UNIQUE(type, value)
);

CREATE TABLE IF NOT EXISTS matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL,
    watchlist_id INTEGER NOT NULL,
    matched_value TEXT NOT NULL,
    match_type TEXT NOT NULL,
    context TEXT,
    severity TEXT NOT NULL DEFAULT 'medium',
    status TEXT NOT NULL DEFAULT 'new',
    created_at TEXT NOT NULL,
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
    FOREIGN KEY (watchlist_id) REFERENCES watchlist(id) ON DELETE CASCADE,
    UNIQUE(document_id, watchlist_id, matched_value)
);
CREATE INDEX IF NOT EXISTS idx_matches_status ON matches(status);
CREATE INDEX IF NOT EXISTS idx_matches_severity ON matches(severity);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    match_id INTEGER NOT NULL UNIQUE,
    channel TEXT NOT NULL,
    sent_at TEXT NOT NULL,
    success INTEGER NOT NULL,
    error TEXT,
    FOREIGN KEY (match_id) REFERENCES matches(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS enrichments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_value TEXT NOT NULL,
    provider TEXT NOT NULL,
    enriched_at TEXT NOT NULL,
    success INTEGER NOT NULL,
    result_json TEXT,
    error TEXT,
    UNIQUE(entity_type, entity_value, provider)
);
CREATE INDEX IF NOT EXISTS idx_enrichments_value ON enrichments(entity_type, entity_value);
CREATE INDEX IF NOT EXISTS idx_enrichments_provider ON enrichments(provider);
"""


def get_connection(db_path: str = DATABASE_PATH) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: str = DATABASE_PATH) -> None:
    with get_connection(db_path) as conn:
        conn.executescript(SCHEMA)
        conn.commit()


@contextmanager
def db_cursor(db_path: str = DATABASE_PATH):
    conn = get_connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
