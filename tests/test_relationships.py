import os
import tempfile

import pytest

from app.database import get_connection, init_db
from app.graph.relationships import (
    build_graphviz,
    entity_summary,
    list_entity_types,
    neighbors,
    related_documents,
)
from app.repository import insert_document, insert_entities


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
    """Three documents, hand-picked overlap.

    doc1: example.com, CVE-2024-3400, LockBit
    doc2: example.com, CVE-2024-3400, evil.com
    doc3: example.com, evil.com, ATT&CK ref
    """
    docs = [
        ("h-1", [
            ("domain", "example.com"),
            ("cve", "CVE-2024-3400"),
            ("malware", "LockBit"),
        ]),
        ("h-2", [
            ("domain", "example.com"),
            ("cve", "CVE-2024-3400"),
            ("domain", "evil.com"),
        ]),
        ("h-3", [
            ("domain", "example.com"),
            ("domain", "evil.com"),
            ("actor", "Volt Typhoon"),
        ]),
    ]
    for h, entities in docs:
        doc_id = insert_document(conn, {
            "source_name": "Test Feed",
            "source_type": "rss",
            "source_url": f"https://x/{h}",
            "title": h,
            "raw_text": "x",
            "raw_html": None,
            "language": "en",
            "published_at": "2026-05-09T12:00:00Z",
            "retrieved_at": f"2026-05-10T00:00:0{int(h[-1])}Z",
            "content_hash": h,
        })
        insert_entities(conn, doc_id, [
            {"entity_type": t, "entity_value": v, "context": ""} for t, v in entities
        ])


# --- summary -----------------------------------------------------------
def test_entity_summary_counts_distinct_documents(conn):
    _seed(conn)
    s = entity_summary(conn, "domain", "example.com")
    assert s["sightings"] == 3
    s2 = entity_summary(conn, "cve", "CVE-2024-3400")
    assert s2["sightings"] == 2


def test_entity_summary_returns_none_for_unknown(conn):
    _seed(conn)
    assert entity_summary(conn, "domain", "nonexistent.example") is None


# --- neighbors ---------------------------------------------------------
def test_neighbors_ordered_by_shared_docs(conn):
    _seed(conn)
    rows = neighbors(conn, "domain", "example.com")
    # Expect: CVE shares 2 docs, evil.com shares 2 docs, LockBit + Volt Typhoon share 1 each.
    counts = {(r["neighbor_type"], r["neighbor_value"]): r["shared_docs"] for r in rows}
    assert counts[("cve", "CVE-2024-3400")] == 2
    assert counts[("domain", "evil.com")] == 2
    assert counts[("malware", "LockBit")] == 1
    assert counts[("actor", "Volt Typhoon")] == 1


def test_neighbors_respects_neighbor_types(conn):
    _seed(conn)
    rows = neighbors(conn, "domain", "example.com", neighbor_types=["cve"])
    assert len(rows) == 1
    assert rows[0]["neighbor_type"] == "cve"


def test_neighbors_respects_min_shared(conn):
    _seed(conn)
    rows = neighbors(conn, "domain", "example.com", min_shared=2)
    types = {(r["neighbor_type"], r["neighbor_value"]) for r in rows}
    assert ("cve", "CVE-2024-3400") in types
    assert ("malware", "LockBit") not in types  # only 1 shared doc


def test_neighbors_excludes_self(conn):
    _seed(conn)
    rows = neighbors(conn, "domain", "example.com")
    for r in rows:
        assert not (r["neighbor_type"] == "domain" and r["neighbor_value"] == "example.com")


def test_neighbors_empty_for_unknown_entity(conn):
    _seed(conn)
    assert neighbors(conn, "domain", "no-such-thing.example") == []


# --- related documents -------------------------------------------------
def test_related_documents_lists_each_doc_once(conn):
    _seed(conn)
    docs = related_documents(conn, "domain", "example.com")
    assert len(docs) == 3
    # Most recent first — h-3 has retrieved_at ending in 03Z.
    assert docs[0]["title"] == "h-3"


# --- entity types listing ---------------------------------------------
def test_list_entity_types_distinct_sorted(conn):
    _seed(conn)
    types = list_entity_types(conn)
    assert "actor" in types and "cve" in types and "domain" in types and "malware" in types
    # Sorted alphabetically.
    assert types == sorted(types)


# --- graphviz rendering -----------------------------------------------
def test_build_graphviz_includes_all_neighbors():
    rows = [
        {"neighbor_type": "cve", "neighbor_value": "CVE-2024-3400", "shared_docs": 2, "last_seen": "x"},
        {"neighbor_type": "actor", "neighbor_value": "Volt Typhoon", "shared_docs": 1, "last_seen": "y"},
    ]
    dot = build_graphviz("domain", "example.com", rows)
    assert dot.startswith("digraph")
    assert "example.com" in dot
    assert "CVE-2024-3400" in dot
    assert "Volt Typhoon" in dot
    # edges labeled with shared-doc counts
    assert 'label="2"' in dot
    assert 'label="1"' in dot


def test_build_graphviz_escapes_quotes():
    rows = [
        {
            "neighbor_type": "actor",
            "neighbor_value": 'has"quote',
            "shared_docs": 1,
            "last_seen": None,
        }
    ]
    dot = build_graphviz("domain", 'evil"ish', rows)
    # Both center label and neighbor label have escaped quotes.
    assert '\\"' in dot
    # Should still parse as valid DOT — we don't run graphviz here, just sanity check.
    assert dot.count("digraph") == 1


def test_build_graphviz_caps_at_max_nodes():
    rows = [
        {"neighbor_type": "cve", "neighbor_value": f"CVE-2024-{i}", "shared_docs": 1, "last_seen": "x"}
        for i in range(50)
    ]
    dot = build_graphviz("domain", "x.com", rows, max_nodes=5)
    # Only 5 neighbor edges should be present.
    assert dot.count(" -> ") == 5
