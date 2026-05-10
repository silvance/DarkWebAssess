import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from app.config import DATABASE_PATH

log = logging.getLogger(__name__)

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
    score INTEGER,
    score_reasons TEXT,
    score_updated_at TEXT,
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
    FOREIGN KEY (watchlist_id) REFERENCES watchlist(id) ON DELETE CASCADE,
    UNIQUE(document_id, watchlist_id, matched_value)
);
CREATE INDEX IF NOT EXISTS idx_matches_status ON matches(status);
CREATE INDEX IF NOT EXISTS idx_matches_severity ON matches(severity);
CREATE INDEX IF NOT EXISTS idx_matches_score ON matches(score);

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

CREATE TABLE IF NOT EXISTS job_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_name TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    success INTEGER,
    message TEXT,
    duration_seconds REAL
);
CREATE INDEX IF NOT EXISTS idx_job_runs_name ON job_runs(job_name);
CREATE INDEX IF NOT EXISTS idx_job_runs_started ON job_runs(started_at);
"""

FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
    title, raw_text, source_name, source_url,
    content='documents', content_rowid='id',
    tokenize='porter unicode61'
);
"""

FTS_TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS documents_ai AFTER INSERT ON documents BEGIN
    INSERT INTO documents_fts(rowid, title, raw_text, source_name, source_url)
    VALUES (new.id, new.title, new.raw_text, new.source_name, new.source_url);
END;
CREATE TRIGGER IF NOT EXISTS documents_ad AFTER DELETE ON documents BEGIN
    INSERT INTO documents_fts(documents_fts, rowid, title, raw_text, source_name, source_url)
    VALUES('delete', old.id, old.title, old.raw_text, old.source_name, old.source_url);
END;
CREATE TRIGGER IF NOT EXISTS documents_au AFTER UPDATE ON documents BEGIN
    INSERT INTO documents_fts(documents_fts, rowid, title, raw_text, source_name, source_url)
    VALUES('delete', old.id, old.title, old.raw_text, old.source_name, old.source_url);
    INSERT INTO documents_fts(rowid, title, raw_text, source_name, source_url)
    VALUES (new.id, new.title, new.raw_text, new.source_name, new.source_url);
END;
"""


def _resolve_db_path(db_path):
    """Read DATABASE_PATH lazily so tests can monkeypatch the module global."""
    if db_path is not None:
        return db_path
    import app.database as _self
    return getattr(_self, "DATABASE_PATH", DATABASE_PATH)


def get_connection(db_path=None) -> sqlite3.Connection:
    path = _resolve_db_path(db_path)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Add columns / FTS index / triggers introduced after the initial schema."""
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(matches)")}
    for name, ddl in (
        ("score", "ALTER TABLE matches ADD COLUMN score INTEGER"),
        ("score_reasons", "ALTER TABLE matches ADD COLUMN score_reasons TEXT"),
        ("score_updated_at", "ALTER TABLE matches ADD COLUMN score_updated_at TEXT"),
    ):
        if name not in cols:
            conn.execute(ddl)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_matches_score ON matches(score)")

    # FTS5 + triggers (best-effort — sqlite without FTS5 just disables search).
    try:
        conn.executescript(FTS_SCHEMA)
        conn.executescript(FTS_TRIGGERS)
    except sqlite3.OperationalError as exc:
        log.warning("FTS5 unavailable; full-text search disabled: %s", exc)
        return

    # Backfill the FTS index from existing documents if it's empty.
    try:
        n_fts = conn.execute("SELECT COUNT(*) AS n FROM documents_fts").fetchone()["n"]
        n_docs = conn.execute("SELECT COUNT(*) AS n FROM documents").fetchone()["n"]
        if n_docs > 0 and n_fts == 0:
            conn.execute("INSERT INTO documents_fts(documents_fts) VALUES('rebuild')")
    except sqlite3.OperationalError as exc:
        log.warning("FTS5 backfill skipped: %s", exc)


def init_db(db_path=None) -> None:
    with get_connection(db_path) as conn:
        conn.executescript(SCHEMA)
        _migrate(conn)
        conn.commit()


@contextmanager
def db_cursor(db_path=None):
    conn = get_connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
