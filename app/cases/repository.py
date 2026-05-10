"""Case management repository: CRUD over cases / evidence / notes / events.

Conventions
- Statuses: open, reviewing, waiting, confirmed, false_positive, escalated, closed
- Severity: low, medium, high, critical (matches scoring bands)
- Evidence is polymorphic via a canonical `ref` string:
    match:42, document:7, entity:domain:example.com, summary:9, enrichment:11
  Free-form text evidence has ref=None.
"""
import json
import sqlite3
from typing import Any, Iterable, List, Optional

from app.normalizer import utcnow_iso

VALID_STATUSES = (
    "open",
    "reviewing",
    "waiting",
    "confirmed",
    "false_positive",
    "escalated",
    "closed",
)

VALID_SEVERITIES = ("low", "medium", "high", "critical")
VALID_KINDS = ("match", "document", "entity", "enrichment", "summary", "text")

# Length caps on user-supplied free-form strings. Picked generously enough
# that legitimate use is never blocked, but small enough that pathological
# input can't blow up the dashboard or the markdown exporter.
MAX_TITLE_LEN = 256
MAX_LABEL_LEN = 256
MAX_SUMMARY_LEN = 8_000
MAX_NOTE_LEN = 16_000
MAX_EVIDENCE_BODY_LEN = 32_000


def _bounded(value: Optional[str], limit: int, *, field: str) -> Optional[str]:
    """Reject strings longer than `limit`. None / empty pass through."""
    if value is None:
        return None
    if len(value) > limit:
        raise ValueError(f"{field} exceeds maximum length of {limit} characters")
    return value


# --- helpers --------------------------------------------------------------
def _record_event(
    conn: sqlite3.Connection,
    case_id: int,
    event_type: str,
    *,
    actor: Optional[str] = None,
    payload: Optional[dict] = None,
) -> int:
    cur = conn.execute(
        """
        INSERT INTO case_events (case_id, event_type, actor, payload_json, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            int(case_id),
            event_type,
            actor,
            json.dumps(payload, default=str) if payload is not None else None,
            utcnow_iso(),
        ),
    )
    return int(cur.lastrowid)


def _bump_updated(conn: sqlite3.Connection, case_id: int) -> None:
    conn.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (utcnow_iso(), int(case_id)))


# --- cases ----------------------------------------------------------------
def create_case(
    conn: sqlite3.Connection,
    *,
    title: str,
    severity: str = "medium",
    owner: Optional[str] = None,
    summary: Optional[str] = None,
    status: str = "open",
) -> int:
    if status not in VALID_STATUSES:
        raise ValueError(f"Invalid status: {status}")
    if severity not in VALID_SEVERITIES:
        raise ValueError(f"Invalid severity: {severity}")
    if not title or not title.strip():
        raise ValueError("Case title cannot be empty")
    title = _bounded(title, MAX_TITLE_LEN, field="title")
    summary = _bounded(summary, MAX_SUMMARY_LEN, field="summary")
    now = utcnow_iso()
    cur = conn.execute(
        """
        INSERT INTO cases (title, summary, status, severity, owner, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (title, summary, status, severity, owner, now, now),
    )
    case_id = int(cur.lastrowid)
    _record_event(
        conn,
        case_id,
        "created",
        actor=owner,
        payload={"title": title, "severity": severity, "status": status},
    )
    return case_id


def get_case(conn: sqlite3.Connection, case_id: int) -> Optional[dict]:
    row = conn.execute("SELECT * FROM cases WHERE id = ?", (int(case_id),)).fetchone()
    return dict(row) if row else None


def list_cases(
    conn: sqlite3.Connection,
    *,
    status: Optional[str] = None,
    limit: int = 200,
) -> List[dict]:
    sql = "SELECT * FROM cases"
    params: list = []
    if status:
        sql += " WHERE status = ?"
        params.append(status)
    sql += " ORDER BY updated_at DESC LIMIT ?"
    params.append(int(limit))
    return [dict(r) for r in conn.execute(sql, tuple(params)).fetchall()]


def update_case_status(
    conn: sqlite3.Connection,
    case_id: int,
    new_status: str,
    *,
    actor: Optional[str] = None,
) -> None:
    if new_status not in VALID_STATUSES:
        raise ValueError(f"Invalid status: {new_status}")
    case = get_case(conn, case_id)
    if not case:
        raise LookupError(f"Case {case_id} not found")
    if case["status"] == new_status:
        return
    closed_at = utcnow_iso() if new_status == "closed" else None
    conn.execute(
        "UPDATE cases SET status = ?, updated_at = ?, closed_at = ? WHERE id = ?",
        (new_status, utcnow_iso(), closed_at, int(case_id)),
    )
    _record_event(
        conn,
        case_id,
        "status_changed",
        actor=actor,
        payload={"from": case["status"], "to": new_status},
    )


def update_case_field(
    conn: sqlite3.Connection,
    case_id: int,
    field: str,
    value: Any,
    *,
    actor: Optional[str] = None,
) -> None:
    if field not in ("title", "summary", "owner", "severity"):
        raise ValueError(f"Field {field!r} is not directly editable")
    if field == "severity" and value not in VALID_SEVERITIES:
        raise ValueError(f"Invalid severity: {value}")
    if field == "title":
        if not value or not str(value).strip():
            raise ValueError("Case title cannot be empty")
        _bounded(value, MAX_TITLE_LEN, field="title")
    elif field == "summary":
        _bounded(value, MAX_SUMMARY_LEN, field="summary")
    case = get_case(conn, case_id)
    if not case:
        raise LookupError(f"Case {case_id} not found")
    conn.execute(
        f"UPDATE cases SET {field} = ?, updated_at = ? WHERE id = ?",
        (value, utcnow_iso(), int(case_id)),
    )
    _record_event(
        conn,
        case_id,
        f"{field}_changed",
        actor=actor,
        payload={"from": case[field], "to": value},
    )


# --- notes ----------------------------------------------------------------
def add_note(
    conn: sqlite3.Connection,
    case_id: int,
    body: str,
    *,
    author: Optional[str] = None,
) -> int:
    if not body or not body.strip():
        raise ValueError("Note body cannot be empty")
    body = _bounded(body, MAX_NOTE_LEN, field="note body")
    cur = conn.execute(
        "INSERT INTO case_notes (case_id, author, body, created_at) VALUES (?, ?, ?, ?)",
        (int(case_id), author, body.strip(), utcnow_iso()),
    )
    note_id = int(cur.lastrowid)
    _bump_updated(conn, case_id)
    _record_event(
        conn,
        case_id,
        "note_added",
        actor=author,
        payload={"note_id": note_id, "preview": body.strip()[:140]},
    )
    return note_id


def list_notes(conn: sqlite3.Connection, case_id: int) -> List[dict]:
    return [
        dict(r)
        for r in conn.execute(
            "SELECT id, author, body, created_at FROM case_notes WHERE case_id = ? ORDER BY created_at ASC",
            (int(case_id),),
        ).fetchall()
    ]


# --- evidence -------------------------------------------------------------
def attach_evidence(
    conn: sqlite3.Connection,
    case_id: int,
    kind: str,
    *,
    ref: Optional[str] = None,
    label: Optional[str] = None,
    body: Optional[str] = None,
    actor: Optional[str] = None,
) -> Optional[int]:
    """Attach evidence to a case. Returns new evidence id, or None if a
    duplicate (same kind+ref already attached). Free-form text evidence
    (ref=None) always inserts."""
    if kind not in VALID_KINDS:
        raise ValueError(f"Invalid evidence kind: {kind}")
    if kind == "text" and (not body or not body.strip()):
        raise ValueError("Text evidence requires a body")
    if kind != "text" and not ref:
        raise ValueError(f"Evidence kind {kind!r} requires a ref")
    label = _bounded(label, MAX_LABEL_LEN, field="label")
    body = _bounded(body, MAX_EVIDENCE_BODY_LEN, field="evidence body")

    try:
        cur = conn.execute(
            """
            INSERT INTO case_evidence (case_id, kind, ref, label, body, added_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (int(case_id), kind, ref, label, body, utcnow_iso()),
        )
    except sqlite3.IntegrityError:
        return None
    ev_id = int(cur.lastrowid)
    _bump_updated(conn, case_id)
    _record_event(
        conn,
        case_id,
        "evidence_added",
        actor=actor,
        payload={"evidence_id": ev_id, "kind": kind, "ref": ref, "label": label},
    )
    return ev_id


def list_evidence(
    conn: sqlite3.Connection,
    case_id: int,
    *,
    kind: Optional[str] = None,
) -> List[dict]:
    sql = "SELECT * FROM case_evidence WHERE case_id = ?"
    params: list = [int(case_id)]
    if kind:
        sql += " AND kind = ?"
        params.append(kind)
    sql += " ORDER BY added_at ASC, id ASC"
    return [dict(r) for r in conn.execute(sql, tuple(params)).fetchall()]


def remove_evidence(conn: sqlite3.Connection, evidence_id: int) -> bool:
    row = conn.execute(
        "SELECT case_id, kind, ref, label FROM case_evidence WHERE id = ?",
        (int(evidence_id),),
    ).fetchone()
    if not row:
        return False
    conn.execute("DELETE FROM case_evidence WHERE id = ?", (int(evidence_id),))
    _bump_updated(conn, row["case_id"])
    _record_event(
        conn,
        row["case_id"],
        "evidence_removed",
        payload={"evidence_id": int(evidence_id), "kind": row["kind"], "ref": row["ref"]},
    )
    return True


# --- timeline -------------------------------------------------------------
def list_events(conn: sqlite3.Connection, case_id: int) -> List[dict]:
    rows = conn.execute(
        "SELECT id, event_type, actor, payload_json, created_at FROM case_events "
        "WHERE case_id = ? ORDER BY created_at ASC, id ASC",
        (int(case_id),),
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["payload"] = json.loads(d.pop("payload_json") or "null")
        except (TypeError, ValueError):
            d["payload"] = None
        out.append(d)
    return out


# --- create-from-match convenience ---------------------------------------
def create_case_from_match(
    conn: sqlite3.Connection,
    match_id: int,
    *,
    title: Optional[str] = None,
    owner: Optional[str] = None,
) -> Optional[int]:
    row = conn.execute(
        """
        SELECT m.id AS match_id, m.matched_value, m.match_type, m.severity,
               m.score, m.score_reasons, m.context, d.id AS document_id,
               d.title AS doc_title, d.source_name, d.source_url
        FROM matches m JOIN documents d ON d.id = m.document_id
        WHERE m.id = ?
        """,
        (int(match_id),),
    ).fetchone()
    if not row:
        return None

    case_title = title or f"{row['matched_value']} ({row['source_name']})"
    summary_lines = [
        f"Seeded from match #{row['match_id']}.",
        f"Matched {row['match_type']} `{row['matched_value']}` in *{row['source_name']}*.",
    ]
    if row["doc_title"]:
        summary_lines.append(f"Source title: {row['doc_title']}")
    case_id = create_case(
        conn,
        title=case_title,
        severity=row["severity"] or "medium",
        owner=owner,
        summary="\n".join(summary_lines),
    )

    attach_evidence(
        conn,
        case_id,
        "match",
        ref=f"match:{row['match_id']}",
        label=f"{row['match_type']} {row['matched_value']}",
        actor=owner,
    )
    attach_evidence(
        conn,
        case_id,
        "document",
        ref=f"document:{row['document_id']}",
        label=row["doc_title"] or row["source_url"],
        actor=owner,
    )
    if row["matched_value"] and row["match_type"]:
        # Best-effort entity link — derive type from the match_type prefix
        ent_type = row["match_type"].replace("exact_", "").replace("subdomain", "domain")
        attach_evidence(
            conn,
            case_id,
            "entity",
            ref=f"entity:{ent_type}:{row['matched_value']}",
            label=f"{ent_type}={row['matched_value']}",
            actor=owner,
        )
    summary_row = conn.execute(
        "SELECT id, model FROM llm_summaries WHERE match_id = ? ORDER BY created_at DESC LIMIT 1",
        (int(match_id),),
    ).fetchone()
    if summary_row:
        attach_evidence(
            conn,
            case_id,
            "summary",
            ref=f"summary:{summary_row['id']}",
            label=f"Analyst summary ({summary_row['model']})",
            actor=owner,
        )

    return case_id


# --- aggregate detail -----------------------------------------------------
def get_case_detail(conn: sqlite3.Connection, case_id: int) -> Optional[dict]:
    case = get_case(conn, case_id)
    if not case:
        return None
    case["evidence"] = list_evidence(conn, case_id)
    case["notes"] = list_notes(conn, case_id)
    case["events"] = list_events(conn, case_id)
    return case
