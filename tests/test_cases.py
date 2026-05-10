import os
import tempfile

import pytest

from app.cases.exporter import export_markdown
from app.cases.repository import (
    add_note,
    attach_evidence,
    create_case,
    create_case_from_match,
    get_case_detail,
    list_cases,
    list_events,
    list_evidence,
    list_notes,
    remove_evidence,
    update_case_field,
    update_case_status,
)
from app.database import get_connection, init_db
from app.repository import (
    insert_document,
    insert_match,
    upsert_enrichment,
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


def _seed_match(conn) -> int:
    doc_id = insert_document(
        conn,
        {
            "source_name": "Test Feed",
            "source_type": "rss",
            "source_url": "https://example.com/post",
            "title": "Example post",
            "raw_text": "example.com appears here",
            "raw_html": None,
            "language": "en",
            "published_at": "2026-05-09T12:00:00Z",
            "retrieved_at": "2026-05-10T00:00:00Z",
            "content_hash": "h-cases",
        },
    )
    wid = upsert_watchlist_entry(
        conn,
        {"type": "domain", "value": "example.com", "severity": "high", "enabled": True},
    )
    return insert_match(
        conn,
        document_id=doc_id,
        watchlist_id=wid,
        matched_value="example.com",
        match_type="exact_domain",
        context="ctx",
        severity="high",
    )


# --- create + lifecycle --------------------------------------------------
def test_create_case_records_creation_event(conn):
    cid = create_case(conn, title="Test", severity="medium", owner="alice")
    assert cid > 0
    detail = get_case_detail(conn, cid)
    assert detail["title"] == "Test"
    assert detail["status"] == "open"
    assert any(ev["event_type"] == "created" for ev in detail["events"])


def test_create_case_rejects_invalid_status_and_severity(conn):
    with pytest.raises(ValueError):
        create_case(conn, title="x", status="bogus")
    with pytest.raises(ValueError):
        create_case(conn, title="x", severity="huge")


def test_status_transition_records_event_and_closed_at(conn):
    cid = create_case(conn, title="Test", severity="high")
    update_case_status(conn, cid, "reviewing", actor="alice")
    update_case_status(conn, cid, "closed", actor="alice")
    detail = get_case_detail(conn, cid)
    assert detail["status"] == "closed"
    assert detail["closed_at"] is not None
    transitions = [
        ev["payload"] for ev in detail["events"] if ev["event_type"] == "status_changed"
    ]
    assert {"from": "open", "to": "reviewing"} in transitions
    assert {"from": "reviewing", "to": "closed"} in transitions


def test_status_idempotent_when_unchanged(conn):
    cid = create_case(conn, title="Test")
    before = len(list_events(conn, cid))
    update_case_status(conn, cid, "open")
    after = len(list_events(conn, cid))
    assert before == after  # no extra event emitted


def test_update_case_field_and_severity_validation(conn):
    cid = create_case(conn, title="Test")
    update_case_field(conn, cid, "owner", "alice")
    update_case_field(conn, cid, "severity", "critical")
    case = get_case_detail(conn, cid)
    assert case["owner"] == "alice"
    assert case["severity"] == "critical"
    with pytest.raises(ValueError):
        update_case_field(conn, cid, "severity", "huge")
    with pytest.raises(ValueError):
        update_case_field(conn, cid, "status", "open")  # must use update_case_status


def test_list_cases_filters_by_status(conn):
    a = create_case(conn, title="A")
    b = create_case(conn, title="B")
    update_case_status(conn, b, "closed")
    open_only = [c["id"] for c in list_cases(conn, status="open")]
    closed_only = [c["id"] for c in list_cases(conn, status="closed")]
    assert a in open_only
    assert b in closed_only


# --- notes ---------------------------------------------------------------
def test_add_note_records_event_and_appears_in_listing(conn):
    cid = create_case(conn, title="Test")
    nid = add_note(conn, cid, "first note", author="alice")
    notes = list_notes(conn, cid)
    assert len(notes) == 1 and notes[0]["id"] == nid
    events = [ev for ev in list_events(conn, cid) if ev["event_type"] == "note_added"]
    assert events and events[0]["payload"]["note_id"] == nid


def test_add_note_rejects_empty_body(conn):
    cid = create_case(conn, title="Test")
    with pytest.raises(ValueError):
        add_note(conn, cid, "   ")


# --- evidence ------------------------------------------------------------
def test_attach_match_evidence_dedupes(conn):
    cid = create_case(conn, title="Test")
    first = attach_evidence(conn, cid, "match", ref="match:1", label="m1")
    second = attach_evidence(conn, cid, "match", ref="match:1", label="m1")
    assert first is not None
    assert second is None  # duplicate

    items = list_evidence(conn, cid, kind="match")
    assert len(items) == 1


def test_attach_text_allows_multiple_without_ref(conn):
    cid = create_case(conn, title="Test")
    a = attach_evidence(conn, cid, "text", body="first")
    b = attach_evidence(conn, cid, "text", body="second")
    assert a and b and a != b
    assert len(list_evidence(conn, cid, kind="text")) == 2


def test_attach_validation(conn):
    cid = create_case(conn, title="Test")
    with pytest.raises(ValueError):
        attach_evidence(conn, cid, "match")  # ref required for non-text
    with pytest.raises(ValueError):
        attach_evidence(conn, cid, "text", body="")  # body required for text
    with pytest.raises(ValueError):
        attach_evidence(conn, cid, "bogus", ref="x:1")


def test_remove_evidence(conn):
    cid = create_case(conn, title="Test")
    eid = attach_evidence(conn, cid, "match", ref="match:42")
    assert remove_evidence(conn, eid) is True
    assert remove_evidence(conn, eid) is False
    assert list_evidence(conn, cid) == []


# --- create-from-match ---------------------------------------------------
def test_create_case_from_match_seeds_evidence(conn):
    match_id = _seed_match(conn)
    cid = create_case_from_match(conn, match_id, owner="alice")
    assert cid is not None
    detail = get_case_detail(conn, cid)
    kinds = sorted(ev["kind"] for ev in detail["evidence"])
    assert "match" in kinds and "document" in kinds and "entity" in kinds
    refs = [ev["ref"] for ev in detail["evidence"]]
    assert f"match:{match_id}" in refs
    assert any(r.startswith("entity:domain:") for r in refs)


def test_create_case_from_unknown_match_returns_none(conn):
    assert create_case_from_match(conn, 9999) is None


def test_create_case_from_match_inherits_severity(conn):
    match_id = _seed_match(conn)  # severity=high in fixture
    cid = create_case_from_match(conn, match_id)
    assert get_case_detail(conn, cid)["severity"] == "high"


# --- markdown export -----------------------------------------------------
def test_export_markdown_contains_core_sections(conn):
    match_id = _seed_match(conn)
    upsert_enrichment(
        conn,
        "domain",
        "example.com",
        "urlhaus",
        success=True,
        result={"verdict": "malicious", "url_count": 4},
    )
    cid = create_case_from_match(conn, match_id)
    attach_evidence(
        conn,
        cid,
        "enrichment",
        ref=f"enrichment:{conn.execute('SELECT id FROM enrichments LIMIT 1').fetchone()['id']}",
        label="urlhaus",
    )
    add_note(conn, cid, "Looks tied to a recent leak claim.", author="alice")
    update_case_status(conn, cid, "reviewing")
    md = export_markdown(conn, cid)
    assert md is not None
    assert "Case #" in md
    assert "Linked matches" in md
    assert "example.com" in md
    assert "Looks tied to a recent leak" in md
    assert "Timeline" in md
    assert "status_changed" in md or "status" in md
    assert "urlhaus" in md


def test_export_markdown_unknown_case(conn):
    assert export_markdown(conn, 9999) is None
