import json
import os
import tempfile

import pytest

from app.database import get_connection, init_db
from app.repository import (
    insert_document,
    insert_entities,
    insert_match,
    upsert_source,
    upsert_watchlist_entry,
)
from app.reports.base import parse_window, window_bounds
from app.reports.renderers import render_html, render_json, render_markdown, render
from app.reports.runner import (
    generate_report,
    get_saved,
    list_saved,
    list_templates,
    save_report,
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


def _seed_basic(conn) -> dict:
    upsert_source(
        conn, {"name": "Test Feed", "type": "rss", "url": "https://x/y", "enabled": True}
    )
    doc_id = insert_document(
        conn,
        {
            "source_name": "Test Feed",
            "source_type": "rss",
            "source_url": "https://x/y",
            "title": "Critical advisory",
            "raw_text": "example.com appears here CVE-2024-3400",
            "raw_html": None,
            "language": "en",
            "published_at": "2026-05-09T12:00:00Z",
            "retrieved_at": "2026-05-10T00:00:00Z",
            "content_hash": "h-rep",
        },
    )
    insert_entities(
        conn,
        doc_id,
        [
            {"entity_type": "domain", "entity_value": "example.com", "context": ""},
            {"entity_type": "cve", "entity_value": "CVE-2024-3400", "context": ""},
        ],
    )
    wid = upsert_watchlist_entry(
        conn,
        {"type": "domain", "value": "example.com", "severity": "high",
         "enabled": True, "description": "primary"},
    )
    mid = insert_match(
        conn,
        document_id=doc_id,
        watchlist_id=wid,
        matched_value="example.com",
        match_type="exact_domain",
        context="ctx",
        severity="high",
    )
    return {"doc_id": doc_id, "watchlist_id": wid, "match_id": mid}


# --- window parsing -----------------------------------------------------
def test_parse_window_basic_units():
    assert parse_window("24h").total_seconds() == 24 * 3600
    assert parse_window("7d").days == 7
    assert parse_window("30m").total_seconds() == 30 * 60
    assert parse_window(None) is None


def test_parse_window_rejects_garbage():
    with pytest.raises(ValueError):
        parse_window("nope")


def test_window_bounds_returns_iso_strings():
    start, end = window_bounds("24h")
    assert start and start.endswith("Z")
    assert end and end.endswith("Z")


def test_window_bounds_no_window_only_end():
    start, end = window_bounds(None)
    assert start is None
    assert end and end.endswith("Z")


# --- registry ------------------------------------------------------------
def test_list_templates_includes_core_set():
    names = {n for n, _ in list_templates()}
    assert {"daily_summary", "weekly_watchlist", "source_health", "executive"} <= names


def test_unknown_template_raises(conn):
    with pytest.raises(KeyError):
        generate_report(conn, "no_such_report")


# --- daily_summary -------------------------------------------------------
def test_daily_summary_includes_match_we_seeded(conn):
    _seed_basic(conn)
    r = generate_report(conn, "daily_summary", window="7d")
    assert r.name == "daily_summary"
    section_titles = [s.title for s in r.sections]
    assert "Top open matches by score" in section_titles
    top = next(s for s in r.sections if s.title == "Top open matches by score")
    values = [row["matched_value"] for row in top.rows]
    assert "example.com" in values


# --- weekly_watchlist ----------------------------------------------------
def test_weekly_watchlist_counts_hits_per_entry(conn):
    seeded = _seed_basic(conn)
    r = generate_report(conn, "weekly_watchlist", window="30d")
    entries = next(s for s in r.sections if s.title == "Watchlist entries with hits")
    rows = [row for row in entries.rows if row["watchlist_value"] == "example.com"]
    assert rows and rows[0]["hits"] >= 1


# --- source_health -------------------------------------------------------
def test_source_health_lists_seeded_source(conn):
    _seed_basic(conn)
    r = generate_report(conn, "source_health", window="7d")
    src_section = next(s for s in r.sections if s.title == "Sources")
    names = [row["name"] for row in src_section.rows]
    assert "Test Feed" in names


# --- executive ----------------------------------------------------------
def test_executive_metrics_present(conn):
    _seed_basic(conn)
    r = generate_report(conn, "executive", window="30d")
    metrics = next(s for s in r.sections if s.title == "Headline metrics")
    keys = {row["metric"] for row in metrics.rows}
    assert "matches_total" in keys
    assert "docs_total" in keys
    assert "open_high_critical" in keys


# --- renderers ----------------------------------------------------------
def test_render_markdown_has_title_and_window(conn):
    _seed_basic(conn)
    r = generate_report(conn, "daily_summary", window="7d")
    md = render_markdown(r)
    assert md.startswith("# Daily threat summary")
    assert "Window:" in md or "Generated:" in md
    assert "## Top open matches by score" in md


def test_render_html_is_well_formed(conn):
    _seed_basic(conn)
    r = generate_report(conn, "daily_summary", window="7d")
    html_body = render_html(r)
    assert html_body.startswith("<!doctype html>")
    assert "<table>" in html_body
    assert "Daily threat summary" in html_body


def test_render_json_round_trips(conn):
    _seed_basic(conn)
    r = generate_report(conn, "daily_summary", window="7d")
    js = render_json(r)
    parsed = json.loads(js)
    assert parsed["name"] == "daily_summary"
    assert any(s["title"] == "Top open matches by score" for s in parsed["sections"])


def test_render_dispatch_unknown_format_raises(conn):
    _seed_basic(conn)
    r = generate_report(conn, "daily_summary", window="7d")
    with pytest.raises(ValueError):
        render(r, "pdf")


# --- persistence --------------------------------------------------------
def test_save_and_load_report(conn):
    _seed_basic(conn)
    report = generate_report(conn, "daily_summary", window="24h")
    rid = save_report(conn, report)
    saved = get_saved(conn, rid)
    assert saved is not None
    assert saved["name"] == "daily_summary"
    assert "<h1>" in saved["body_html"]
    listed = list_saved(conn, name="daily_summary")
    assert any(r["id"] == rid for r in listed)
