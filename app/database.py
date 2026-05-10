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
-- idx_matches_score is created in _migrate() so legacy DBs that pre-date the
-- score column don't trip on executescript() before _migrate runs.

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

CREATE TABLE IF NOT EXISTS llm_summaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    match_id INTEGER NOT NULL,
    model TEXT NOT NULL,
    summary_text TEXT NOT NULL,
    entities_json TEXT,
    why_it_matters TEXT,
    confidence TEXT,
    confidence_explanation TEXT,
    next_steps_json TEXT,
    unknowns_json TEXT,
    input_tokens INTEGER,
    output_tokens INTEGER,
    cache_read_input_tokens INTEGER,
    cache_creation_input_tokens INTEGER,
    created_at TEXT NOT NULL,
    UNIQUE(match_id, model),
    FOREIGN KEY (match_id) REFERENCES matches(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_llm_summaries_match ON llm_summaries(match_id);

CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    summary TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    severity TEXT NOT NULL DEFAULT 'medium',
    owner TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    closed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_updated ON cases(updated_at);

CREATE TABLE IF NOT EXISTS case_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    ref TEXT,
    label TEXT,
    body TEXT,
    added_at TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_case_evidence_case ON case_evidence(case_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_case_evidence_unique
    ON case_evidence(case_id, kind, ref) WHERE ref IS NOT NULL;

CREATE TABLE IF NOT EXISTS case_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    author TEXT,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_case_notes_case ON case_notes(case_id);

CREATE TABLE IF NOT EXISTS case_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    actor TEXT,
    payload_json TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_case_events_case ON case_events(case_id, created_at);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    title TEXT,
    generated_at TEXT NOT NULL,
    window_start TEXT,
    window_end TEXT,
    body_markdown TEXT,
    body_html TEXT,
    body_json TEXT,
    metadata_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_reports_name ON reports(name);
CREATE INDEX IF NOT EXISTS idx_reports_generated ON reports(generated_at);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'analyst',
    full_name TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_login_at TEXT,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    last_failed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT,
    actor_role TEXT,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    payload_json TEXT,
    ip_address TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
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
    # `:memory:` and other special paths shouldn't get a 5-second wait; only
    # set busy_timeout for real on-disk DBs where we expect concurrent access.
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    # Concurrent dashboard + scheduler access needs WAL so readers don't
    # block writers and vice versa. NORMAL sync trades a tiny durability
    # window on power loss for materially better throughput.
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
    except sqlite3.OperationalError:
        # Some build configurations (e.g. tmpfs without certain flags) may
        # reject WAL — fall back silently rather than fail to open the DB.
        pass
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Add columns / FTS index / triggers introduced after the initial schema."""
    match_cols = {r["name"] for r in conn.execute("PRAGMA table_info(matches)")}
    for name, ddl in (
        ("score", "ALTER TABLE matches ADD COLUMN score INTEGER"),
        ("score_reasons", "ALTER TABLE matches ADD COLUMN score_reasons TEXT"),
        ("score_updated_at", "ALTER TABLE matches ADD COLUMN score_updated_at TEXT"),
    ):
        if name not in match_cols:
            conn.execute(ddl)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_matches_score ON matches(score)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_matches_value ON matches(matched_value)")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_entities_doc_type ON entities(document_id, entity_type)"
    )

    # Phase-14 hardening: lockout requires a last_failed_at column.
    try:
        user_cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}
        if user_cols and "last_failed_at" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN last_failed_at TEXT")
    except sqlite3.OperationalError as exc:
        log.warning("users-table migration skipped: %s", exc)

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
