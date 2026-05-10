"""User CRUD + role helpers + login workflow."""
import sqlite3
from typing import List, Optional

from app.auth.audit import record_audit
from app.auth.passwords import hash_password, verify_password
from app.config import AUTH_ROLES
from app.normalizer import utcnow_iso

ROLE_LEVELS = {"viewer": 1, "analyst": 2, "admin": 3}


def has_role(user_role: Optional[str], required: str) -> bool:
    return ROLE_LEVELS.get((user_role or "").lower(), 0) >= ROLE_LEVELS.get(required, 0)


def _validate_role(role: str) -> None:
    if role not in AUTH_ROLES:
        raise ValueError(f"Invalid role: {role!r}. Allowed: {AUTH_ROLES}")


def count_users(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"] or 0)


def list_users(conn: sqlite3.Connection) -> List[dict]:
    rows = conn.execute(
        "SELECT id, username, role, full_name, enabled, created_at, last_login_at "
        "FROM users ORDER BY username"
    ).fetchall()
    return [dict(r) for r in rows]


def get_user(conn: sqlite3.Connection, username: str) -> Optional[dict]:
    row = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    return dict(row) if row else None


def create_user(
    conn: sqlite3.Connection,
    username: str,
    password: str,
    *,
    role: str = "analyst",
    full_name: Optional[str] = None,
    actor: Optional[str] = "cli",
) -> int:
    _validate_role(role)
    if not username or not username.strip():
        raise ValueError("Username cannot be empty")
    if get_user(conn, username):
        raise ValueError(f"User {username!r} already exists")
    conn.execute(
        """
        INSERT INTO users (username, password_hash, role, full_name, enabled, created_at)
        VALUES (?, ?, ?, ?, 1, ?)
        """,
        (username.strip(), hash_password(password), role, full_name, utcnow_iso()),
    )
    row = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    record_audit(
        conn, action="user_created", actor=actor,
        target_type="user", target_id=username,
        payload={"role": role, "enabled": True},
    )
    return int(row["id"])


def set_password(
    conn: sqlite3.Connection,
    username: str,
    new_password: str,
    *,
    actor: Optional[str] = "cli",
) -> bool:
    if not get_user(conn, username):
        return False
    conn.execute(
        "UPDATE users SET password_hash = ?, failed_logins = 0 WHERE username = ?",
        (hash_password(new_password), username),
    )
    record_audit(
        conn, action="user_password_changed", actor=actor,
        target_type="user", target_id=username,
    )
    return True


def set_role(
    conn: sqlite3.Connection,
    username: str,
    new_role: str,
    *,
    actor: Optional[str] = "cli",
) -> bool:
    _validate_role(new_role)
    user = get_user(conn, username)
    if not user:
        return False
    if user["role"] == new_role:
        return True
    conn.execute("UPDATE users SET role = ? WHERE username = ?", (new_role, username))
    record_audit(
        conn, action="user_role_changed", actor=actor,
        target_type="user", target_id=username,
        payload={"from": user["role"], "to": new_role},
    )
    return True


def set_enabled(
    conn: sqlite3.Connection,
    username: str,
    enabled: bool,
    *,
    actor: Optional[str] = "cli",
) -> bool:
    user = get_user(conn, username)
    if not user:
        return False
    conn.execute(
        "UPDATE users SET enabled = ? WHERE username = ?",
        (1 if enabled else 0, username),
    )
    record_audit(
        conn,
        action="user_enabled" if enabled else "user_disabled",
        actor=actor,
        target_type="user",
        target_id=username,
    )
    return True


def delete_user(
    conn: sqlite3.Connection,
    username: str,
    *,
    actor: Optional[str] = "cli",
) -> bool:
    if not get_user(conn, username):
        return False
    conn.execute("DELETE FROM users WHERE username = ?", (username,))
    record_audit(
        conn, action="user_deleted", actor=actor,
        target_type="user", target_id=username,
    )
    return True


def authenticate(
    conn: sqlite3.Connection,
    username: str,
    password: str,
    *,
    ip: Optional[str] = None,
) -> Optional[dict]:
    """Verify credentials. Returns the user dict on success, None on failure.

    Both success and failure are recorded in the audit log; failures also
    increment `failed_logins`. Disabled accounts return None even if the
    password is correct (and the audit row uses action=login_disabled)."""
    user = get_user(conn, username)
    if not user or not verify_password(password, user["password_hash"]):
        record_audit(
            conn, action="login_failed", actor=username, ip_address=ip,
            payload={"reason": "bad_credentials"},
        )
        if user:
            conn.execute(
                "UPDATE users SET failed_logins = failed_logins + 1 WHERE id = ?",
                (user["id"],),
            )
        return None
    if not user["enabled"]:
        record_audit(
            conn, action="login_disabled", actor=username, actor_role=user["role"],
            ip_address=ip,
        )
        return None
    conn.execute(
        "UPDATE users SET last_login_at = ?, failed_logins = 0 WHERE id = ?",
        (utcnow_iso(), user["id"]),
    )
    record_audit(
        conn, action="login_success", actor=username, actor_role=user["role"],
        ip_address=ip,
    )
    return get_user(conn, username)
