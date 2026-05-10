import json
import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

from app.database import get_connection, init_db
from app.matching.scoring import (
    SCORE_BANDS,
    ScoreResult,
    score_and_persist,
    score_match,
    score_to_severity,
)
from app.repository import (
    insert_document,
    insert_entities,
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


def _doc(conn, source_name="Test Source", days_old=0, source_url="https://x/y", title="t"):
    pub = (datetime.now(timezone.utc) - timedelta(days=days_old)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return insert_document(
        conn,
        {
            "source_name": source_name,
            "source_type": "rss",
            "source_url": source_url,
            "title": title,
            "raw_text": "x",
            "raw_html": None,
            "language": None,
            "published_at": pub,
            "retrieved_at": pub,
            "content_hash": f"hash-{source_name}-{days_old}-{title}-{source_url}",
        },
    )


def _watchlist(conn, **kw):
    entry = {"type": "domain", "value": "example.com", "severity": "medium", "enabled": True}
    entry.update(kw)
    return upsert_watchlist_entry(conn, entry)


def _match(conn, doc_id, watchlist_id, **kw):
    payload = {
        "matched_value": "example.com",
        "match_type": "exact_domain",
        "context": "ctx",
        "severity": "medium",
    }
    payload.update(kw)
    return insert_match(
        conn,
        document_id=doc_id,
        watchlist_id=watchlist_id,
        matched_value=payload["matched_value"],
        match_type=payload["match_type"],
        context=payload["context"],
        severity=payload["severity"],
    )


# --- score_to_severity ---------------------------------------------------
def test_score_band_mapping():
    assert score_to_severity(0) == "low"
    assert score_to_severity(25) == "low"
    assert score_to_severity(26) == "medium"
    assert score_to_severity(50) == "medium"
    assert score_to_severity(51) == "high"
    assert score_to_severity(75) == "high"
    assert score_to_severity(76) == "critical"
    assert score_to_severity(100) == "critical"


# --- Base + match-type --------------------------------------------------
def test_high_severity_exact_domain_lands_in_high_band(conn):
    doc_id = _doc(conn, days_old=10)
    wid = _watchlist(conn, severity="high")
    mid = _match(conn, doc_id, wid, severity="high")
    res, _ = score_and_persist(conn, mid)
    assert res.severity in ("high", "critical")
    # 55 (high) + 15 (exact) = 70 minimum, no other boosts in this fixture.
    assert res.score >= 70


def test_keyword_match_loses_specificity_points(conn):
    doc_id = _doc(conn, days_old=30)
    wid = _watchlist(conn, type="keyword", value="ransomware", severity="medium")
    mid = _match(conn, doc_id, wid, matched_value="ransomware", match_type="keyword", severity="medium")
    res, _ = score_and_persist(conn, mid)
    # 30 (medium) - 5 (keyword) = 25; recency neutral at 30 days.
    assert res.score == 25
    assert any("keyword" in r for r in res.reasons)


# --- Recency ------------------------------------------------------------
def test_very_recent_boost(conn):
    doc_id = _doc(conn, days_old=0)
    wid = _watchlist(conn, severity="medium")
    mid = _match(conn, doc_id, wid)
    res, _ = score_and_persist(conn, mid)
    # 30 base + 15 exact + 10 <24h = 55
    assert any("very recent" in r for r in res.reasons)
    assert res.score >= 55


def test_old_post_penalty(conn):
    doc_id = _doc(conn, days_old=180)
    wid = _watchlist(conn, severity="medium")
    mid = _match(conn, doc_id, wid)
    res, _ = score_and_persist(conn, mid)
    assert any("old" in r for r in res.reasons)


# --- Source reliability -------------------------------------------------
def test_known_source_boost(conn):
    doc_id = _doc(conn, source_name="CISA Cybersecurity Advisories", days_old=30)
    wid = _watchlist(conn, severity="medium")
    mid = _match(conn, doc_id, wid)
    res, _ = score_and_persist(conn, mid)
    assert any("high-reliability" in r for r in res.reasons)


# --- CVE enrichment -----------------------------------------------------
def test_cve_in_kev_and_high_epss(conn):
    doc_id = _doc(conn, days_old=2)
    wid = _watchlist(conn, type="cve", value="CVE-2024-3400", severity="high")
    mid = _match(
        conn,
        doc_id,
        wid,
        matched_value="CVE-2024-3400",
        match_type="exact_cve",
        severity="high",
    )
    upsert_enrichment(
        conn,
        "cve",
        "CVE-2024-3400",
        "cisa_kev",
        success=True,
        result={"in_kev": True, "known_ransomware_use": "Known"},
    )
    upsert_enrichment(
        conn, "cve", "CVE-2024-3400", "epss", success=True, result={"epss": 0.96, "percentile": 0.99}
    )
    res, _ = score_and_persist(conn, mid)
    assert res.score == 100  # capped
    assert any("CISA KEV" in r for r in res.reasons)
    assert any("EPSS" in r for r in res.reasons)


# --- IP enrichment ------------------------------------------------------
def test_ip_abuseipdb_high_confidence(conn):
    doc_id = _doc(conn, days_old=10)
    wid = _watchlist(conn, type="ip", value="1.2.3.4", severity="medium")
    mid = _match(
        conn, doc_id, wid, matched_value="1.2.3.4", match_type="exact_ip", severity="medium"
    )
    upsert_enrichment(
        conn, "ip", "1.2.3.4", "abuseipdb", success=True, result={"abuse_confidence": 90}
    )
    res, _ = score_and_persist(conn, mid)
    assert any("AbuseIPDB" in r for r in res.reasons)


# --- VT / URLhaus on domain ---------------------------------------------
def test_domain_urlhaus_and_vt(conn):
    doc_id = _doc(conn, days_old=5)
    wid = _watchlist(conn, severity="medium")
    mid = _match(conn, doc_id, wid)
    upsert_enrichment(
        conn, "domain", "example.com", "urlhaus", success=True, result={"verdict": "malicious"}
    )
    upsert_enrichment(
        conn, "domain", "example.com", "virustotal", success=True, result={"malicious": 8}
    )
    res, _ = score_and_persist(conn, mid)
    assert any("URLhaus" in r for r in res.reasons)
    assert any("VT" in r for r in res.reasons)


# --- Co-occurrence ------------------------------------------------------
def test_cooccurring_hash_boosts_domain_match(conn):
    doc_id = _doc(conn, days_old=10)
    insert_entities(
        conn,
        doc_id,
        [
            {"entity_type": "sha256", "entity_value": "a" * 64, "context": ""},
            {"entity_type": "domain", "entity_value": "example.com", "context": ""},
        ],
    )
    wid = _watchlist(conn, severity="medium")
    mid = _match(conn, doc_id, wid)
    res, _ = score_and_persist(conn, mid)
    assert any("file hash" in r for r in res.reasons)


# --- Multi-source corroboration -----------------------------------------
def test_multi_source_corroboration(conn):
    wid = _watchlist(conn, severity="medium")
    for src in ("Krebs on Security", "BleepingComputer", "The Hacker News"):
        d = _doc(conn, source_name=src, days_old=30, source_url=f"https://{src}/x")
        _match(conn, d, wid)
    # Score the most recently inserted match.
    last_id = conn.execute("SELECT MAX(id) AS m FROM matches").fetchone()["m"]
    res, _ = score_and_persist(conn, last_id)
    assert any("3 sources" in r for r in res.reasons)


# --- False-positive feedback -------------------------------------------
def test_false_positive_feedback_penalty(conn):
    wid = _watchlist(conn, severity="high")
    d1 = _doc(conn, days_old=10, source_url="https://a/1")
    d2 = _doc(conn, days_old=10, source_url="https://b/2")
    fp_id = _match(conn, d1, wid, severity="high")
    conn.execute("UPDATE matches SET status = 'false_positive' WHERE id = ?", (fp_id,))
    conn.commit()

    fresh_id = _match(conn, d2, wid, severity="high")
    res, _ = score_and_persist(conn, fresh_id)
    assert any("false-positive" in r for r in res.reasons)


# --- Persistence --------------------------------------------------------
def test_score_persisted_to_match_row(conn):
    doc_id = _doc(conn, days_old=0)
    wid = _watchlist(conn, severity="high")
    mid = _match(conn, doc_id, wid, severity="high")
    score_and_persist(conn, mid)
    row = conn.execute(
        "SELECT score, score_reasons, score_updated_at, severity FROM matches WHERE id = ?",
        (mid,),
    ).fetchone()
    assert row["score"] is not None
    assert row["score_updated_at"] is not None
    reasons = json.loads(row["score_reasons"])
    assert isinstance(reasons, list) and reasons
