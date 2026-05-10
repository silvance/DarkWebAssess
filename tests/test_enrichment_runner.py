import json
import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

from app.database import get_connection, init_db
from app.enrichment.base import EnrichmentProvider
from app.enrichment.runner import enrich_entity, iter_distinct_entities
from app.repository import insert_document, insert_entities, upsert_enrichment


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


class StubProvider(EnrichmentProvider):
    name = "stub"
    supported_types = ("cve",)

    def __init__(self, payload=None, raises=None, configured=True):
        self.payload = payload or {"hello": "world"}
        self.raises = raises
        self.calls = 0
        self._configured = configured

    def is_configured(self):
        return self._configured

    def enrich(self, entity_type, entity_value):
        self.calls += 1
        if self.raises:
            raise self.raises
        return {**self.payload, "value": entity_value}


def test_runner_records_success(conn):
    p = StubProvider()
    outcomes = enrich_entity(conn, "cve", "CVE-2024-3400", providers=[p])
    assert len(outcomes) == 1 and outcomes[0].success and not outcomes[0].cached
    row = conn.execute(
        "SELECT * FROM enrichments WHERE provider='stub' AND entity_value='CVE-2024-3400'"
    ).fetchone()
    assert row["success"] == 1
    assert json.loads(row["result_json"])["value"] == "CVE-2024-3400"


def test_runner_records_error(conn):
    p = StubProvider(raises=RuntimeError("boom"))
    outcomes = enrich_entity(conn, "cve", "CVE-2024-3400", providers=[p])
    assert outcomes[0].success is False
    row = conn.execute(
        "SELECT * FROM enrichments WHERE provider='stub'"
    ).fetchone()
    assert row["success"] == 0
    assert "boom" in (row["error"] or "")


def test_runner_uses_cache_when_fresh(conn):
    p = StubProvider()
    # First call writes a row.
    enrich_entity(conn, "cve", "CVE-2024-3400", providers=[p])
    assert p.calls == 1
    # Second call should hit cache.
    outcomes = enrich_entity(conn, "cve", "CVE-2024-3400", providers=[p])
    assert outcomes[0].cached is True
    assert p.calls == 1


def test_runner_force_bypasses_cache(conn):
    p = StubProvider()
    enrich_entity(conn, "cve", "CVE-2024-3400", providers=[p])
    enrich_entity(conn, "cve", "CVE-2024-3400", providers=[p], force=True)
    assert p.calls == 2


def test_runner_skips_unconfigured(conn):
    p = StubProvider(configured=False)
    outcomes = enrich_entity(conn, "cve", "CVE-2024-3400", providers=[p])
    assert outcomes == []
    assert p.calls == 0


def test_runner_skips_unsupported_type(conn):
    p = StubProvider()
    outcomes = enrich_entity(conn, "domain", "example.com", providers=[p])
    assert outcomes == []
    assert p.calls == 0


def test_runner_refreshes_stale_entries(conn):
    p = StubProvider()
    # Simulate an old enrichment row (10 days ago).
    old = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute(
        "INSERT INTO enrichments (entity_type, entity_value, provider, enriched_at, success, result_json) "
        "VALUES (?, ?, ?, ?, 1, ?)",
        ("cve", "CVE-2024-3400", "stub", old, json.dumps({"old": True})),
    )
    conn.commit()
    enrich_entity(conn, "cve", "CVE-2024-3400", providers=[p], max_age_hours=24)
    assert p.calls == 1


def test_iter_distinct_entities(conn):
    doc_id = insert_document(
        conn,
        {
            "source_name": "t",
            "source_type": "rss",
            "source_url": "http://x",
            "title": "t",
            "raw_text": "x",
            "raw_html": None,
            "language": None,
            "published_at": None,
            "retrieved_at": "2026-05-10T00:00:00Z",
            "content_hash": "abc",
        },
    )
    insert_entities(
        conn,
        doc_id,
        [
            {"entity_type": "cve", "entity_value": "CVE-2024-3400", "context": ""},
            {"entity_type": "domain", "entity_value": "example.com", "context": ""},
            {"entity_type": "cve", "entity_value": "CVE-2024-3400", "context": ""},
        ],
    )
    conn.commit()
    cves = iter_distinct_entities(conn, entity_types=["cve"])
    assert cves == [("cve", "CVE-2024-3400")]
    all_entities = iter_distinct_entities(conn)
    assert ("domain", "example.com") in all_entities
