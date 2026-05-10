"""Tests for the new watchlist repository helpers used by the dashboard
editor: list filters, partial updates, and delete."""
import os
import tempfile

import pytest

from app.database import get_connection, init_db
from app.repository import (
    delete_watchlist_entry,
    get_watchlist_entry,
    list_watchlist,
    update_watchlist_entry,
    upsert_watchlist_entry,
)


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


def _seed(conn):
    return [
        upsert_watchlist_entry(conn, {"type": "domain", "value": "example.com",
                                      "description": "primary",
                                      "severity": "high", "enabled": True}),
        upsert_watchlist_entry(conn, {"type": "email", "value": "alice@example.com",
                                      "description": "alice mail",
                                      "severity": "medium", "enabled": False}),
        upsert_watchlist_entry(conn, {"type": "cve", "value": "CVE-2024-3400",
                                      "description": "PAN-OS",
                                      "severity": "critical", "enabled": True}),
    ]


# --- list_watchlist filters ---------------------------------------------
def test_list_watchlist_returns_all_by_default(conn):
    _seed(conn)
    assert len(list_watchlist(conn)) == 3


def test_list_watchlist_filters_by_type(conn):
    _seed(conn)
    rows = list_watchlist(conn, type_filter="email")
    assert len(rows) == 1
    assert rows[0]["value"] == "alice@example.com"


def test_list_watchlist_search_matches_value_and_description(conn):
    _seed(conn)
    by_value = list_watchlist(conn, search="example.com")
    assert {r["value"] for r in by_value} == {"example.com", "alice@example.com"}
    by_desc = list_watchlist(conn, search="PAN-OS")
    assert len(by_desc) == 1 and by_desc[0]["value"] == "CVE-2024-3400"


def test_list_watchlist_enabled_only(conn):
    _seed(conn)
    rows = list_watchlist(conn, enabled_only=True)
    values = {r["value"] for r in rows}
    assert "alice@example.com" not in values  # disabled
    assert "example.com" in values
    assert "CVE-2024-3400" in values


def test_list_watchlist_type_filter_is_case_insensitive(conn):
    _seed(conn)
    assert len(list_watchlist(conn, type_filter="EMAIL")) == 1


# --- get_watchlist_entry -------------------------------------------------
def test_get_watchlist_entry_returns_dict(conn):
    ids = _seed(conn)
    entry = get_watchlist_entry(conn, ids[0])
    assert entry["type"] == "domain"
    assert entry["value"] == "example.com"


def test_get_watchlist_entry_returns_none_for_unknown(conn):
    _seed(conn)
    assert get_watchlist_entry(conn, 9999) is None


# --- update_watchlist_entry ---------------------------------------------
def test_update_changes_only_specified_fields(conn):
    ids = _seed(conn)
    target = ids[1]  # alice email, severity=medium, enabled=False
    updated = update_watchlist_entry(conn, target, severity="critical")
    assert updated["severity"] == "critical"
    assert updated["enabled"] == 0  # unchanged
    assert updated["description"] == "alice mail"  # unchanged


def test_update_can_toggle_enabled(conn):
    ids = _seed(conn)
    updated = update_watchlist_entry(conn, ids[1], enabled=True)
    assert updated["enabled"] == 1


def test_update_can_change_description(conn):
    ids = _seed(conn)
    updated = update_watchlist_entry(conn, ids[0], description="my main domain")
    assert updated["description"] == "my main domain"


def test_update_normalizes_severity_case(conn):
    ids = _seed(conn)
    updated = update_watchlist_entry(conn, ids[0], severity="HIGH")
    assert updated["severity"] == "high"


def test_update_returns_none_for_unknown_id(conn):
    _seed(conn)
    assert update_watchlist_entry(conn, 9999, enabled=True) is None


def test_update_no_op_when_nothing_changed(conn):
    ids = _seed(conn)
    before = get_watchlist_entry(conn, ids[0])
    after = update_watchlist_entry(
        conn, ids[0],
        severity=before["severity"],
        enabled=bool(before["enabled"]),
    )
    assert after == before


# --- delete_watchlist_entry ---------------------------------------------
def test_delete_returns_true_and_removes(conn):
    ids = _seed(conn)
    assert delete_watchlist_entry(conn, ids[0]) is True
    assert get_watchlist_entry(conn, ids[0]) is None
    assert len(list_watchlist(conn)) == 2


def test_delete_returns_false_for_unknown(conn):
    _seed(conn)
    assert delete_watchlist_entry(conn, 9999) is False
