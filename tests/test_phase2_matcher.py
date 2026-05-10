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


def test_onion_match(conn):
    addr = "c" * 56 + ".onion"
    upsert_watchlist_entry(
        conn,
        {"type": "onion", "value": addr, "severity": "high", "enabled": True},
    )
    text = f"leak posted at {addr} today"
    ents = extract_all(text)
    matches = match_document(conn, document_id=1, title="", text=text, entities=ents)
    assert any(m["match_type"] == "exact_onion" and m["matched_value"] == addr for m in matches)


def test_wallet_eth_match(conn):
    eth = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
    upsert_watchlist_entry(
        conn,
        {"type": "wallet", "value": eth, "severity": "medium", "enabled": True},
    )
    text = f"attacker wallet {eth}"
    ents = extract_all(text)
    matches = match_document(conn, document_id=1, title="", text=text, entities=ents)
    assert any(m["match_type"] == "exact_eth" for m in matches)


def test_handle_match_with_or_without_at(conn):
    upsert_watchlist_entry(
        conn,
        {"type": "handle", "value": "leak_actor", "severity": "medium", "enabled": True},
    )
    text = "follow @leak_actor for updates"
    ents = extract_all(text)
    matches = match_document(conn, document_id=1, title="", text=text, entities=ents)
    assert any(m["match_type"] == "exact_handle" for m in matches)


def test_malware_match(conn):
    upsert_watchlist_entry(
        conn,
        {"type": "malware", "value": "LockBit", "severity": "high", "enabled": True},
    )
    text = "the LockBit gang leaked another victim today"
    ents = extract_all(text)
    matches = match_document(conn, document_id=1, title="", text=text, entities=ents)
    assert any(m["match_type"] == "exact_malware" for m in matches)


def test_actor_match(conn):
    upsert_watchlist_entry(
        conn,
        {"type": "actor", "value": "Volt Typhoon", "severity": "critical", "enabled": True},
    )
    text = "Volt Typhoon resurfaced this week"
    ents = extract_all(text)
    matches = match_document(conn, document_id=1, title="", text=text, entities=ents)
    assert any(m["match_type"] == "exact_actor" for m in matches)
