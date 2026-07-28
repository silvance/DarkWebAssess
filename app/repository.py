"""Thin SQL helpers for inserting and querying records."""
import sqlite3
from typing import Iterable, Optional

from app.normalizer import utcnow_iso


def upsert_source(conn: sqlite3.Connection, source: dict) -> int:
    cur = conn.execute(
        """
        INSERT INTO sources (name, type, url, enabled)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
            type=excluded.type,
            url=excluded.url,
            enabled=excluded.enabled
        """,
        (source["name"], source["type"], source["url"], int(source.get("enabled", True))),
    )
    conn.commit()
    row = conn.execute("SELECT id FROM sources WHERE name = ?", (source["name"],)).fetchone()
    return row["id"]


def mark_source_success(conn: sqlite3.Connection, name: str) -> None:
    now = utcnow_iso()
    conn.execute(
        """
        UPDATE sources
        SET last_checked_at = ?, last_success_at = ?, last_error = NULL, error_count = 0
        WHERE name = ?
        """,
        (now, now, name),
    )


def mark_source_error(conn: sqlite3.Connection, name: str, error: str) -> None:
    now = utcnow_iso()
    conn.execute(
        """
        UPDATE sources
        SET last_checked_at = ?, last_error = ?, error_count = error_count + 1
        WHERE name = ?
        """,
        (now, error[:500], name),
    )


def insert_document(conn: sqlite3.Connection, doc: dict) -> Optional[int]:
    """Insert document; returns row id, or None if duplicate by content_hash."""
    try:
        cur = conn.execute(
            """
            INSERT INTO documents (
                source_name, source_type, source_url, title, author,
                raw_text, raw_html, language, published_at, retrieved_at, content_hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                doc["source_name"],
                doc["source_type"],
                doc["source_url"],
                doc.get("title"),
                doc.get("author"),
                doc.get("raw_text"),
                doc.get("raw_html"),
                doc.get("language"),
                doc.get("published_at"),
                doc["retrieved_at"],
                doc["content_hash"],
            ),
        )
        return cur.lastrowid
    except sqlite3.IntegrityError:
        return None


def insert_entities(conn: sqlite3.Connection, document_id: int, entities: Iterable[dict]) -> int:
    count = 0
    now = utcnow_iso()
    for ent in entities:
        try:
            conn.execute(
                """
                INSERT INTO entities (document_id, entity_type, entity_value, context, first_seen)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    document_id,
                    ent["entity_type"],
                    ent["entity_value"],
                    ent.get("context"),
                    now,
                ),
            )
            count += 1
        except sqlite3.IntegrityError:
            continue
    return count


def upsert_watchlist_entry(conn: sqlite3.Connection, entry: dict) -> int:
    conn.execute(
        """
        INSERT INTO watchlist (type, value, description, severity, enabled)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(type, value) DO UPDATE SET
            description = excluded.description,
            severity = excluded.severity,
            enabled = excluded.enabled
        """,
        (
            entry["type"].lower(),
            entry["value"],
            entry.get("description"),
            entry.get("severity", "medium").lower(),
            int(entry.get("enabled", True)),
        ),
    )
    row = conn.execute(
        "SELECT id FROM watchlist WHERE type = ? AND value = ?",
        (entry["type"].lower(), entry["value"]),
    ).fetchone()
    return row["id"]


def list_watchlist(
    conn: sqlite3.Connection,
    *,
    type_filter: Optional[str] = None,
    search: Optional[str] = None,
    enabled_only: bool = False,
):
    """List watchlist entries with optional filters.

    Returns rows as plain dicts so the dashboard can stuff them into a
    DataFrame without sqlite3.Row coupling.
    """
    sql = (
        "SELECT id, type, value, description, severity, enabled "
        "FROM watchlist WHERE 1=1"
    )
    params: list = []
    if type_filter:
        sql += " AND type = ?"
        params.append(type_filter.lower())
    if search:
        sql += " AND (value LIKE ? OR description LIKE ?)"
        like = f"%{search}%"
        params.extend([like, like])
    if enabled_only:
        sql += " AND enabled = 1"
    sql += " ORDER BY type, value"
    return [dict(r) for r in conn.execute(sql, tuple(params)).fetchall()]


def get_watchlist_entry(conn: sqlite3.Connection, entry_id: int):
    row = conn.execute(
        "SELECT id, type, value, description, severity, enabled "
        "FROM watchlist WHERE id = ?",
        (int(entry_id),),
    ).fetchone()
    return dict(row) if row else None


def update_watchlist_entry(
    conn: sqlite3.Connection,
    entry_id: int,
    *,
    description: Optional[str] = None,
    severity: Optional[str] = None,
    enabled: Optional[bool] = None,
) -> Optional[dict]:
    """Update mutable fields on a watchlist entry. Returns the updated row,
    or None if the id doesn't exist.

    `type` and `value` are intentionally NOT mutable here — they form the
    UNIQUE identity of the row, and changing them is "delete and re-add"
    in semantic terms.
    """
    existing = get_watchlist_entry(conn, entry_id)
    if existing is None:
        return None

    changes = {}
    if description is not None and description != existing["description"]:
        changes["description"] = description
    if severity is not None:
        sev = severity.lower()
        if sev != existing["severity"]:
            changes["severity"] = sev
    if enabled is not None:
        flag = 1 if enabled else 0
        if flag != existing["enabled"]:
            changes["enabled"] = flag

    if not changes:
        return existing

    set_clause = ", ".join(f"{k} = ?" for k in changes)
    params = list(changes.values()) + [int(entry_id)]
    conn.execute(f"UPDATE watchlist SET {set_clause} WHERE id = ?", params)
    return get_watchlist_entry(conn, entry_id)


def delete_watchlist_entry(conn: sqlite3.Connection, entry_id: int) -> bool:
    """Returns True if a row was deleted, False if the id didn't exist."""
    cur = conn.execute("DELETE FROM watchlist WHERE id = ?", (int(entry_id),))
    return cur.rowcount > 0


def insert_match(
    conn: sqlite3.Connection,
    document_id: int,
    watchlist_id: int,
    matched_value: str,
    match_type: str,
    context: Optional[str],
    severity: str,
) -> Optional[int]:
    try:
        cur = conn.execute(
            """
            INSERT INTO matches (
                document_id, watchlist_id, matched_value, match_type,
                context, severity, status, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 'new', ?)
            """,
            (
                document_id,
                watchlist_id,
                matched_value,
                match_type,
                context,
                severity,
                utcnow_iso(),
            ),
        )
        return cur.lastrowid
    except sqlite3.IntegrityError:
        return None


def record_alert(
    conn: sqlite3.Connection, match_id: int, channel: str, success: bool, error: Optional[str]
) -> None:
    conn.execute(
        """
        INSERT OR REPLACE INTO alerts (match_id, channel, sent_at, success, error)
        VALUES (?, ?, ?, ?, ?)
        """,
        (match_id, channel, utcnow_iso(), int(success), error),
    )


# --- Enrichments ----------------------------------------------------------
import json  # noqa: E402


def get_enrichment(
    conn: sqlite3.Connection, entity_type: str, entity_value: str, provider: str
):
    return conn.execute(
        """
        SELECT id, entity_type, entity_value, provider, enriched_at, success,
               result_json, error
        FROM enrichments
        WHERE entity_type = ? AND entity_value = ? AND provider = ?
        """,
        (entity_type, entity_value, provider),
    ).fetchone()


def upsert_enrichment(
    conn: sqlite3.Connection,
    entity_type: str,
    entity_value: str,
    provider: str,
    success: bool,
    result: Optional[dict],
    error: Optional[str] = None,
) -> int:
    payload = json.dumps(result) if result is not None else None
    conn.execute(
        """
        INSERT INTO enrichments (
            entity_type, entity_value, provider, enriched_at, success,
            result_json, error
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(entity_type, entity_value, provider) DO UPDATE SET
            enriched_at = excluded.enriched_at,
            success = excluded.success,
            result_json = excluded.result_json,
            error = excluded.error
        """,
        (entity_type, entity_value, provider, utcnow_iso(), int(success), payload, error),
    )
    row = conn.execute(
        "SELECT id FROM enrichments WHERE entity_type = ? AND entity_value = ? AND provider = ?",
        (entity_type, entity_value, provider),
    ).fetchone()
    return row["id"]


def list_enrichments(conn: sqlite3.Connection, entity_type: str, entity_value: str):
    return conn.execute(
        """
        SELECT id, provider, enriched_at, success, result_json, error
        FROM enrichments
        WHERE entity_type = ? AND entity_value = ?
        ORDER BY enriched_at DESC
        """,
        (entity_type, entity_value),
    ).fetchall()


# --- onion discovery candidates ----------------------------------------
_ONION_CANDIDATE_COLS = (
    "id, url, host, title, first_source, sources_json, times_seen, "
    "status, notes, reviewed_by, reviewed_at, discovered_at, last_seen_at"
)
_VALID_CANDIDATE_STATUSES = {"pending", "approved", "rejected"}


def upsert_onion_candidate(
    conn: sqlite3.Connection,
    *,
    url: str,
    host: str,
    title: Optional[str],
    source_name: str,
) -> dict:
    """Insert a new candidate or refresh an existing one.

    On re-discovery we update last_seen_at, bump times_seen, and merge the
    source_name into sources_json — but we DO NOT change status. A rejected
    candidate stays rejected forever (or until the operator manually flips
    it). That's the safety property: once you've said no, the tool won't
    keep nagging.
    """
    now = utcnow_iso()
    existing = conn.execute(
        f"SELECT {_ONION_CANDIDATE_COLS} FROM onion_candidates WHERE url = ?",
        (url,),
    ).fetchone()
    if existing is None:
        conn.execute(
            """
            INSERT INTO onion_candidates
                (url, host, title, first_source, sources_json, times_seen,
                 status, discovered_at, last_seen_at)
            VALUES (?, ?, ?, ?, ?, 1, 'pending', ?, ?)
            """,
            (url, host, title, source_name, json.dumps([source_name]), now, now),
        )
        return get_onion_candidate_by_url(conn, url)

    try:
        sources = json.loads(existing["sources_json"] or "[]")
    except (TypeError, json.JSONDecodeError):
        sources = []
    if source_name not in sources:
        sources.append(source_name)
    new_title = title or existing["title"]
    conn.execute(
        """
        UPDATE onion_candidates
        SET times_seen = times_seen + 1,
            last_seen_at = ?,
            sources_json = ?,
            title = ?
        WHERE url = ?
        """,
        (now, json.dumps(sources), new_title, url),
    )
    return get_onion_candidate_by_url(conn, url)


def get_onion_candidate(conn: sqlite3.Connection, candidate_id: int) -> Optional[dict]:
    row = conn.execute(
        f"SELECT {_ONION_CANDIDATE_COLS} FROM onion_candidates WHERE id = ?",
        (int(candidate_id),),
    ).fetchone()
    return dict(row) if row else None


def get_onion_candidate_by_url(conn: sqlite3.Connection, url: str) -> Optional[dict]:
    row = conn.execute(
        f"SELECT {_ONION_CANDIDATE_COLS} FROM onion_candidates WHERE url = ?",
        (url,),
    ).fetchone()
    return dict(row) if row else None


def list_onion_candidates(
    conn: sqlite3.Connection,
    *,
    status: Optional[str] = None,
    search: Optional[str] = None,
):
    sql = f"SELECT {_ONION_CANDIDATE_COLS} FROM onion_candidates WHERE 1=1"
    params: list = []
    if status:
        sql += " AND status = ?"
        params.append(status.lower())
    if search:
        sql += " AND (url LIKE ? OR title LIKE ?)"
        like = f"%{search}%"
        params.extend([like, like])
    sql += " ORDER BY last_seen_at DESC, id DESC"
    return [dict(r) for r in conn.execute(sql, tuple(params)).fetchall()]


def set_onion_candidate_status(
    conn: sqlite3.Connection,
    candidate_id: int,
    status: str,
    *,
    reviewed_by: Optional[str] = None,
    notes: Optional[str] = None,
) -> Optional[dict]:
    s = status.lower()
    if s not in _VALID_CANDIDATE_STATUSES:
        raise ValueError(
            f"invalid status {status!r}; expected one of {sorted(_VALID_CANDIDATE_STATUSES)}"
        )
    existing = get_onion_candidate(conn, candidate_id)
    if existing is None:
        return None
    conn.execute(
        """
        UPDATE onion_candidates
        SET status = ?, reviewed_by = ?, reviewed_at = ?, notes = ?
        WHERE id = ?
        """,
        (s, reviewed_by, utcnow_iso(), notes, int(candidate_id)),
    )
    return get_onion_candidate(conn, candidate_id)


# --- scrub runs + findings ---------------------------------------------
def create_scrub_run(
    conn: sqlite3.Connection,
    *,
    target_type: str,
    target_value: str,
    actor: Optional[str] = None,
) -> int:
    cur = conn.execute(
        """
        INSERT INTO scrub_runs (target_type, target_value, started_at, actor)
        VALUES (?, ?, ?, ?)
        """,
        (target_type, target_value, utcnow_iso(), actor),
    )
    return int(cur.lastrowid)


def add_scrub_finding(
    conn: sqlite3.Connection,
    run_id: int,
    *,
    provider: str,
    kind: str,
    title: str,
    severity: str = "info",
    detail: Optional[str] = None,
    url: Optional[str] = None,
    data: Optional[dict] = None,
) -> int:
    cur = conn.execute(
        """
        INSERT INTO scrub_findings
            (run_id, provider, kind, title, detail, severity, url, data_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            int(run_id), provider, kind, title, detail, severity, url,
            json.dumps(data, default=str) if data is not None else None,
            utcnow_iso(),
        ),
    )
    return int(cur.lastrowid)


def finalize_scrub_run(
    conn: sqlite3.Connection,
    run_id: int,
    *,
    providers_run: list,
    findings_count: int,
    highest_severity: Optional[str],
) -> None:
    conn.execute(
        """
        UPDATE scrub_runs
        SET finished_at = ?, providers_run = ?, findings_count = ?, highest_severity = ?
        WHERE id = ?
        """,
        (
            utcnow_iso(), json.dumps(providers_run), int(findings_count),
            highest_severity, int(run_id),
        ),
    )


def get_scrub_run(conn: sqlite3.Connection, run_id: int) -> Optional[dict]:
    row = conn.execute(
        "SELECT * FROM scrub_runs WHERE id = ?", (int(run_id),)
    ).fetchone()
    return dict(row) if row else None


def list_scrub_runs(conn: sqlite3.Connection, limit: int = 50) -> list:
    rows = conn.execute(
        "SELECT * FROM scrub_runs ORDER BY started_at DESC, id DESC LIMIT ?",
        (int(limit),),
    ).fetchall()
    return [dict(r) for r in rows]


def get_scrub_findings(conn: sqlite3.Connection, run_id: int) -> list:
    rows = conn.execute(
        "SELECT * FROM scrub_findings WHERE run_id = ? ORDER BY id",
        (int(run_id),),
    ).fetchall()
    return [dict(r) for r in rows]
