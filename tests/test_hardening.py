"""Regression tests for the hardening pass.

Covers:
- Library-level password minimum length (CLI + dashboard could each forget it,
  but the library can't).
- Brute-force lockout on `authenticate()`.
- Pydantic validation of YAML config files.
- Length caps on case fields / evidence / notes.
- HTML report escapes quotes.
"""
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml as _yaml

from app.auth.passwords import WeakPasswordError, hash_password
from app.auth.users import authenticate, create_user, get_user
from app.cases.repository import (
    MAX_NOTE_LEN,
    MAX_TITLE_LEN,
    add_note,
    attach_evidence,
    create_case,
)
from app.config_models import load_sources, load_suppression, load_watchlist
from app.database import get_connection, init_db
from app.reports.base import Report, ReportSection
from app.reports.renderers import render_html


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


# --- password length -----------------------------------------------------
def test_hash_password_rejects_short():
    with pytest.raises(WeakPasswordError):
        hash_password("short")


def test_create_user_rejects_short(conn):
    with pytest.raises(WeakPasswordError):
        create_user(conn, "alice", "short", actor="cli")


# --- lockout -------------------------------------------------------------
def test_lockout_kicks_in_after_threshold(conn, monkeypatch):
    monkeypatch.setattr("app.config.AUTH_LOCKOUT_THRESHOLD", 3)
    monkeypatch.setattr("app.config.AUTH_LOCKOUT_MINUTES", 15)
    # Re-import the module's reference too — `from ... import` captures.
    monkeypatch.setattr("app.auth.users.AUTH_LOCKOUT_THRESHOLD", 3)
    monkeypatch.setattr("app.auth.users.AUTH_LOCKOUT_MINUTES", 15)

    create_user(conn, "alice", "a-strong-password", actor="cli")

    for _ in range(3):
        assert authenticate(conn, "alice", "wrong") is None
    # 4th attempt — even with the correct password — should be locked.
    assert authenticate(conn, "alice", "a-strong-password") is None
    audit_actions = [
        r["action"]
        for r in conn.execute(
            "SELECT action FROM audit_log ORDER BY id"
        ).fetchall()
    ]
    assert "login_locked" in audit_actions


def test_lockout_clears_after_cooldown(conn, monkeypatch):
    monkeypatch.setattr("app.config.AUTH_LOCKOUT_THRESHOLD", 2)
    monkeypatch.setattr("app.auth.users.AUTH_LOCKOUT_THRESHOLD", 2)
    # Set cooldown to 1 minute and back-date the failure timestamp by 10 minutes.
    monkeypatch.setattr("app.config.AUTH_LOCKOUT_MINUTES", 1)
    monkeypatch.setattr("app.auth.users.AUTH_LOCKOUT_MINUTES", 1)

    create_user(conn, "alice", "a-strong-password", actor="cli")
    authenticate(conn, "alice", "wrong")
    authenticate(conn, "alice", "wrong")
    # Move last_failed_at into the past so the cooldown has expired.
    old_ts = (datetime.now(timezone.utc) - timedelta(minutes=10)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    conn.execute("UPDATE users SET last_failed_at = ? WHERE username = ?",
                 (old_ts, "alice"))
    # Correct password should now succeed.
    assert authenticate(conn, "alice", "a-strong-password") is not None


def test_successful_login_clears_failed_logins(conn):
    create_user(conn, "alice", "a-strong-password", actor="cli")
    authenticate(conn, "alice", "wrong")
    authenticate(conn, "alice", "wrong")
    assert get_user(conn, "alice")["failed_logins"] == 2
    authenticate(conn, "alice", "a-strong-password")
    assert get_user(conn, "alice")["failed_logins"] == 0


# --- YAML validation -----------------------------------------------------
def test_sources_validation_rejects_unknown_severity(tmp_path: Path):
    p = tmp_path / "sources.yaml"
    p.write_text(_yaml.safe_dump({
        "sources": [
            {"name": "X", "type": "rss", "url": "https://x/y"},
            {"name": "Y", "type": "ftp", "url": "ftp://nope"},  # bad type
        ]
    }))
    with pytest.raises(Exception):  # pydantic.ValidationError
        load_sources(str(p))


def test_sources_validation_rejects_non_http_url(tmp_path: Path):
    p = tmp_path / "sources.yaml"
    p.write_text(_yaml.safe_dump({
        "sources": [{"name": "X", "type": "rss", "url": "javascript:alert(1)"}]
    }))
    with pytest.raises(Exception):
        load_sources(str(p))


def test_watchlist_validation_rejects_bad_severity(tmp_path: Path):
    p = tmp_path / "watchlist.yaml"
    p.write_text(_yaml.safe_dump({
        "watchlist": [{"type": "domain", "value": "x.com", "severity": "huge"}]
    }))
    with pytest.raises(Exception):
        load_watchlist(str(p))


def test_watchlist_validation_rejects_unknown_type(tmp_path: Path):
    p = tmp_path / "watchlist.yaml"
    p.write_text(_yaml.safe_dump({
        "watchlist": [{"type": "subdomain_thingy", "value": "x.com"}]
    }))
    with pytest.raises(Exception):
        load_watchlist(str(p))


def test_suppression_validation_accepts_minimal(tmp_path: Path):
    p = tmp_path / "supp.yaml"
    p.write_text(_yaml.safe_dump({
        "suppress": [{"type": "domain", "value": "github.com"}]
    }))
    cfg = load_suppression(str(p))
    assert len(cfg.suppress) == 1


# --- length caps on case fields -----------------------------------------
def test_case_title_too_long_rejected(conn):
    with pytest.raises(ValueError):
        create_case(conn, title="x" * (MAX_TITLE_LEN + 1))


def test_note_body_too_long_rejected(conn):
    cid = create_case(conn, title="t")
    with pytest.raises(ValueError):
        add_note(conn, cid, "x" * (MAX_NOTE_LEN + 1))


def test_text_evidence_body_required(conn):
    cid = create_case(conn, title="t")
    with pytest.raises(ValueError):
        attach_evidence(conn, cid, "text", body="")


# --- HTML report escaping -----------------------------------------------
def test_html_report_escapes_quotes_and_brackets():
    r = Report(
        name="x", title='<script>"alert"</script>',
        description="d & d",
        generated_at="2026-05-10T00:00:00Z",
        sections=[
            ReportSection(title='hostile "title"', columns=["v"], rows=[{"v": "<b>"}])
        ],
    )
    out = render_html(r)
    assert "<script>" not in out
    assert "&lt;script&gt;" in out
    assert "&quot;alert&quot;" in out  # quote=True is doing its job
