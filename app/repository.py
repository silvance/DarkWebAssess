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
