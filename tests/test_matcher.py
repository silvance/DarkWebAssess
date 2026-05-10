import os
import tempfile

import pytest

from app.database import get_connection, init_db
from app.extractors.entities import extract_all
from app.matching.watchlist_matcher import match_document
from app.repository import upsert_watchlist_entry


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


def test_exact_domain_match(conn):
    upsert_watchlist_entry(
        conn,
        {"type": "domain", "value": "example.com", "severity": "high", "enabled": True},
    )
    text = "An attacker registered example.com to host the loader."
    ents = extract_all(text)
    matches = match_document(conn, document_id=1, title="Test", text=text, entities=ents)
    types = {(m["match_type"], m["matched_value"]) for m in matches}
    assert ("exact_domain", "example.com") in types


def test_subdomain_match(conn):
    upsert_watchlist_entry(
        conn,
        {"type": "domain", "value": "example.com", "severity": "high", "enabled": True},
    )
    text = "C2 lives at bad.evil.example.com today."
    ents = extract_all(text)
    matches = match_document(conn, document_id=1, title="", text=text, entities=ents)
    assert any(
        m["match_type"] == "subdomain" and m["matched_value"] == "bad.evil.example.com"
        for m in matches
    )


def test_cve_match(conn):
    upsert_watchlist_entry(
        conn,
        {"type": "cve", "value": "CVE-2024-3400", "severity": "critical", "enabled": True},
    )
    text = "Patch CVE-2024-3400 immediately."
    ents = extract_all(text)
    matches = match_document(conn, document_id=1, title="", text=text, entities=ents)
    assert any(m["match_type"] == "exact_cve" for m in matches)


def test_keyword_match_in_title(conn):
    upsert_watchlist_entry(
        conn,
        {"type": "keyword", "value": "ransomware", "severity": "low", "enabled": True},
    )
    matches = match_document(
        conn,
        document_id=1,
        title="New ransomware leak site",
        text="other text",
        entities=[],
    )
    assert any(m["match_type"] == "keyword" and m["matched_value"] == "ransomware" for m in matches)


def test_disabled_watchlist_entry_ignored(conn):
    upsert_watchlist_entry(
        conn,
        {"type": "domain", "value": "example.com", "severity": "high", "enabled": False},
    )
    text = "example.com appears here"
    ents = extract_all(text)
    matches = match_document(conn, document_id=1, title="", text=text, entities=ents)
    assert matches == []


def test_email_exact_match_case_insensitive(conn):
    upsert_watchlist_entry(
        conn,
        {"type": "email", "value": "Alice@Example.com", "severity": "medium", "enabled": True},
    )
    text = "leaked: alice@example.com"
    ents = extract_all(text)
    matches = match_document(conn, document_id=1, title="", text=text, entities=ents)
    assert any(m["match_type"] == "exact_email" for m in matches)
