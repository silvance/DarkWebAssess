import os
import sqlite3
import tempfile

import pytest

from app.auth.audit import list_audit, record_audit
from app.auth.passwords import hash_password, verify_password
from app.auth.users import (
    authenticate,
    count_users,
    create_user,
    delete_user,
    get_user,
    has_role,
    list_users,
    set_enabled,
    set_password,
    set_role,
)
from app.database import get_connection, init_db


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


# --- passwords ----------------------------------------------------------
def test_hash_round_trip():
    h = hash_password("hunter2-correct-horse")
    assert verify_password("hunter2-correct-horse", h) is True
    assert verify_password("wrong", h) is False


def test_hash_rejects_empty():
    with pytest.raises(ValueError):
        hash_password("")


def test_verify_handles_garbage():
    assert verify_password("x", "not-a-bcrypt-hash") is False
    assert verify_password("", "any") is False


# --- has_role -----------------------------------------------------------
def test_role_hierarchy():
    assert has_role("admin", "viewer") is True
    assert has_role("admin", "admin") is True
    assert has_role("analyst", "admin") is False
    assert has_role("viewer", "analyst") is False
    assert has_role(None, "viewer") is False
    assert has_role("ADMIN", "admin") is True  # case-insensitive


# --- user CRUD ----------------------------------------------------------
def test_create_and_authenticate(conn):
    uid = create_user(conn, "alice", "s3cret-pass!", role="admin", actor="cli")
    assert uid > 0
    assert count_users(conn) == 1
    user = authenticate(conn, "alice", "s3cret-pass!")
    assert user is not None and user["role"] == "admin"
    assert user["last_login_at"] is not None


def test_authenticate_records_audit_on_failure(conn):
    create_user(conn, "alice", "good-password", role="analyst", actor="cli")
    assert authenticate(conn, "alice", "wrong") is None
    rows = list_audit(conn)
    actions = [r["action"] for r in rows]
    assert "login_failed" in actions
    user_after = get_user(conn, "alice")
    assert user_after["failed_logins"] == 1


def test_authenticate_disabled_user_is_blocked(conn):
    create_user(conn, "alice", "pw-correct-horse-battery", actor="cli")
    set_enabled(conn, "alice", False, actor="cli")
    assert authenticate(conn, "alice", "pw-correct-horse-battery") is None
    actions = {r["action"] for r in list_audit(conn)}
    assert "login_disabled" in actions


def test_create_rejects_dupes_and_bad_role(conn):
    create_user(conn, "alice", "pw-correct-horse-battery", actor="cli")
    with pytest.raises(ValueError):
        create_user(conn, "alice", "anything", actor="cli")
    with pytest.raises(ValueError):
        create_user(conn, "bob", "pw-correct-horse-battery", role="god", actor="cli")


def test_set_role_change_recorded(conn):
    create_user(conn, "alice", "pw-correct-horse-battery", role="analyst", actor="cli")
    assert set_role(conn, "alice", "viewer", actor="cli") is True
    assert get_user(conn, "alice")["role"] == "viewer"
    audit_actions = [r["action"] for r in list_audit(conn)]
    assert "user_role_changed" in audit_actions


def test_set_role_idempotent(conn):
    create_user(conn, "alice", "pw-correct-horse-battery", role="viewer", actor="cli")
    pre = len(list_audit(conn, action="user_role_changed"))
    set_role(conn, "alice", "viewer", actor="cli")
    assert len(list_audit(conn, action="user_role_changed")) == pre


def test_set_password_resets_failed_logins(conn):
    create_user(conn, "alice", "pw-correct-horse-battery", actor="cli")
    authenticate(conn, "alice", "wrong")
    assert get_user(conn, "alice")["failed_logins"] == 1
    set_password(conn, "alice", "new-correct-horse-pw", actor="cli")
    assert get_user(conn, "alice")["failed_logins"] == 0
    assert authenticate(conn, "alice", "new-correct-horse-pw") is not None


def test_delete_user(conn):
    create_user(conn, "alice", "pw-correct-horse-battery", actor="cli")
    assert delete_user(conn, "alice", actor="cli") is True
    assert get_user(conn, "alice") is None
    assert delete_user(conn, "alice", actor="cli") is False


def test_list_users_excludes_password_hash(conn):
    create_user(conn, "alice", "pw-correct-horse-battery", actor="cli")
    rows = list_users(conn)
    assert rows and "password_hash" not in rows[0]


# --- audit ---------------------------------------------------------------
def test_record_audit_writes_row(conn):
    rid = record_audit(
        conn,
        actor="alice",
        actor_role="admin",
        action="match_status_changed",
        target_type="match",
        target_id="42",
        payload={"from": "new", "to": "confirmed"},
        ip_address="10.0.0.1",
    )
    assert rid is not None
    rows = list_audit(conn, action="match_status_changed")
    assert len(rows) == 1
    assert rows[0]["actor"] == "alice"
    assert "confirmed" in rows[0]["payload_json"]
