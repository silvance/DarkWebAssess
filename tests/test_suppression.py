import os
import tempfile
from pathlib import Path

import pytest

from app.database import get_connection, init_db
from app.matching import suppression as supp
from app.matching.scoring import score_and_persist
from app.repository import insert_document, insert_match, upsert_watchlist_entry


@pytest.fixture
def rules_path(tmp_path: Path, monkeypatch):
    p = tmp_path / "suppression.yaml"
    p.write_text(
        """
suppress:
  - type: domain
    value: github.com
    reason: code-hosting reference
  - type: keyword
    value: ransomware
    sources:
      - SANS Internet Storm Center
    reason: too generic on this source
""".strip()
    )
    monkeypatch.setattr(supp, "SUPPRESSION_PATH", str(p))
    supp.reload_rules()
    yield p
    supp.reload_rules()


@pytest.fixture
def conn():
    fd, db = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(db)
    c = get_connection(db)
    try:
        yield c
    finally:
        c.close()
        os.unlink(db)


def test_domain_rule_suppresses_regardless_of_source(rules_path):
    assert supp.suppression_reason("exact_domain", "github.com", "Some Source") is not None
    assert supp.suppression_reason("subdomain", "github.com", "Some Source") is not None


def test_value_must_match(rules_path):
    assert supp.suppression_reason("exact_domain", "evil.example.com", "Some Source") is None


def test_keyword_rule_only_for_listed_source(rules_path):
    assert supp.suppression_reason("keyword", "ransomware", "SANS Internet Storm Center") is not None
    assert supp.suppression_reason("keyword", "ransomware", "Krebs on Security") is None


def test_suppressed_match_score_capped(rules_path, conn):
    doc_id = insert_document(
        conn,
        {
            "source_name": "Some Source",
            "source_type": "rss",
            "source_url": "https://x/y",
            "title": "t",
            "raw_text": "github.com appears here",
            "raw_html": None,
            "language": None,
            "published_at": "2026-05-10T00:00:00Z",
            "retrieved_at": "2026-05-10T00:00:00Z",
            "content_hash": "h-supp-1",
        },
    )
    wid = upsert_watchlist_entry(
        conn,
        {"type": "domain", "value": "github.com", "severity": "high", "enabled": True},
    )
    mid = insert_match(
        conn,
        document_id=doc_id,
        watchlist_id=wid,
        matched_value="github.com",
        match_type="exact_domain",
        context="",
        severity="high",
    )
    res, _ = score_and_persist(conn, mid)
    assert res.score <= 5
    assert any("suppressed" in r for r in res.reasons)
