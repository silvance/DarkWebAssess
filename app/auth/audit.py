"""Audit logging — records security-relevant actions to `audit_log`.

Use `record_audit(conn, action="...", actor="alice", ...)` from anywhere
that handles a user-driven action: login attempts, user/role changes,
match/case status flips, summary regen, backups, etc.

The function is best-effort: failures are swallowed (with a warning) so an
audit failure can never take down the calling action. Tests assert the
happy path.
"""
import json
import logging
import sqlite3
from typing import Optional

from app.normalizer import utcnow_iso

log = logging.getLogger(__name__)


def record_audit(
    conn: sqlite3.Connection,
    *,
    action: str,
    actor: Optional[str] = None,
    actor_role: Optional[str] = None,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    payload: Optional[dict] = None,
    ip_address: Optional[str] = None,
) -> Optional[int]:
    try:
        cur = conn.execute(
            """
            INSERT INTO audit_log (
                actor, actor_role, action, target_type, target_id,
                payload_json, ip_address, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                actor,
                actor_role,
                action,
                target_type,
                str(target_id) if target_id is not None else None,
                json.dumps(payload, default=str) if payload is not None else None,
                ip_address,
                utcnow_iso(),
            ),
        )
        return int(cur.lastrowid)
    except Exception as exc:  # noqa: BLE001
        log.warning("audit log insert failed: %s", exc)
        return None


def list_audit(
    conn: sqlite3.Connection,
    *,
    action: Optional[str] = None,
    actor: Optional[str] = None,
    limit: int = 200,
):
    sql = "SELECT * FROM audit_log WHERE 1=1"
    params: list = []
    if action:
        sql += " AND action = ?"
        params.append(action)
    if actor:
        sql += " AND actor = ?"
        params.append(actor)
    sql += " ORDER BY created_at DESC LIMIT ?"
    params.append(int(limit))
    return [dict(r) for r in conn.execute(sql, tuple(params)).fetchall()]
