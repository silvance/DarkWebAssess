"""SQLite FTS5-backed full-text search over collected documents.

The FTS5 virtual table `documents_fts` is created in `app.database` along
with INSERT/UPDATE/DELETE triggers that keep it synchronized with the
canonical `documents` table.
"""
import re
import sqlite3
from typing import List, Optional

# Characters that confuse FTS5's parser when they appear bare in a token.
_FTS_STRIP = re.compile(r'["\(\)\[\]\{\}:!,]')


def escape_fts(query: str) -> str:
    """Build a safe FTS5 MATCH query from arbitrary user input.

    Each whitespace-delimited token becomes a phrase-quoted term, so the
    query is interpreted as "all of these phrases must appear" by FTS5's
    default AND semantics. Empty input returns a sentinel that matches
    nothing (so callers don't accidentally return everything).
    """
    if not query or not query.strip():
        return '""'
    tokens = []
    for raw in query.split():
        clean = _FTS_STRIP.sub("", raw).strip()
        if not clean:
            continue
        # Allow trailing wildcard prefix queries (e.g. `lock*`).
        if clean.endswith("*") and len(clean) > 1:
            tokens.append(f'"{clean[:-1]}"*')
        else:
            tokens.append(f'"{clean}"')
    return " ".join(tokens) if tokens else '""'


def fts_available(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='documents_fts'"
    ).fetchone()
    return row is not None


def search_documents(
    conn: sqlite3.Connection,
    query: str,
    source_name: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    limit: int = 50,
) -> List[dict]:
    """Search documents by full-text query plus optional filters.

    `since` / `until` are ISO timestamps compared against `retrieved_at`.
    """
    if not fts_available(conn):
        return []
    fts_query = escape_fts(query)
    sql = """
        SELECT
            d.id,
            d.title,
            d.source_name,
            d.source_url,
            d.retrieved_at,
            d.published_at,
            snippet(documents_fts, 1, '<<', '>>', '...', 18) AS snippet,
            documents_fts.rank AS rank
        FROM documents_fts
        JOIN documents d ON d.id = documents_fts.rowid
        WHERE documents_fts MATCH ?
    """
    params: list = [fts_query]
    if source_name:
        sql += " AND d.source_name = ?"
        params.append(source_name)
    if since:
        sql += " AND d.retrieved_at >= ?"
        params.append(since)
    if until:
        sql += " AND d.retrieved_at <= ?"
        params.append(until)
    sql += " ORDER BY documents_fts.rank LIMIT ?"
    params.append(int(limit))
    rows = conn.execute(sql, tuple(params)).fetchall()
    return [dict(r) for r in rows]


def reindex(conn: sqlite3.Connection) -> int:
    """Rebuild the FTS index from the canonical documents table."""
    if not fts_available(conn):
        return 0
    conn.execute("INSERT INTO documents_fts(documents_fts) VALUES('rebuild')")
    conn.commit()
    return conn.execute("SELECT COUNT(*) AS n FROM documents").fetchone()["n"]
