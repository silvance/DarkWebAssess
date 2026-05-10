"""Coordinate enrichment provider runs and persist results."""
import json
import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, List, Optional

from app.config import ENRICHMENT_MAX_AGE_HOURS
from app.enrichment.abuseipdb import AbuseIpdbProvider
from app.enrichment.base import EnrichmentProvider
from app.enrichment.cisa_kev import CisaKevProvider
from app.enrichment.epss import EpssProvider
from app.enrichment.malware_bazaar import MalwareBazaarProvider
from app.enrichment.urlhaus import UrlhausProvider
from app.enrichment.virustotal import VirusTotalProvider
from app.repository import get_enrichment, upsert_enrichment

log = logging.getLogger(__name__)


def default_providers() -> List[EnrichmentProvider]:
    return [
        CisaKevProvider(),
        EpssProvider(),
        UrlhausProvider(),
        MalwareBazaarProvider(),
        VirusTotalProvider(),
        AbuseIpdbProvider(),
    ]


@dataclass
class EnrichmentOutcome:
    provider: str
    success: bool
    cached: bool = False
    error: Optional[str] = None


def _is_fresh(enriched_at: str, max_age_hours: int) -> bool:
    try:
        ts = datetime.strptime(enriched_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return False
    return datetime.now(timezone.utc) - ts < timedelta(hours=max_age_hours)


def enrich_entity(
    conn: sqlite3.Connection,
    entity_type: str,
    entity_value: str,
    providers: Optional[Iterable[EnrichmentProvider]] = None,
    max_age_hours: int = ENRICHMENT_MAX_AGE_HOURS,
    force: bool = False,
) -> List[EnrichmentOutcome]:
    """Run all applicable providers for one entity. Cache-aware unless force=True."""
    providers = list(providers) if providers is not None else default_providers()
    results: List[EnrichmentOutcome] = []

    for p in providers:
        if not p.supports(entity_type):
            continue
        if not p.is_configured():
            log.info("%s: skipping (not configured)", p.name)
            continue

        if not force:
            existing = get_enrichment(conn, entity_type, entity_value, p.name)
            if existing and existing["success"] and _is_fresh(existing["enriched_at"], max_age_hours):
                results.append(EnrichmentOutcome(p.name, True, cached=True))
                continue

        try:
            payload = p.enrich(entity_type, entity_value)
            upsert_enrichment(conn, entity_type, entity_value, p.name, True, payload)
            results.append(EnrichmentOutcome(p.name, True))
        except Exception as exc:  # noqa: BLE001
            log.warning("%s failed for %s/%s: %s", p.name, entity_type, entity_value, exc)
            upsert_enrichment(conn, entity_type, entity_value, p.name, False, None, error=str(exc))
            results.append(EnrichmentOutcome(p.name, False, error=str(exc)))
    conn.commit()
    return results


def iter_distinct_entities(
    conn: sqlite3.Connection,
    entity_types: Optional[Iterable[str]] = None,
    limit: Optional[int] = None,
) -> List[tuple]:
    """Distinct (entity_type, entity_value) pairs across all collected docs."""
    sql = "SELECT DISTINCT entity_type, entity_value FROM entities"
    params: list = []
    if entity_types:
        types = list(entity_types)
        placeholders = ",".join("?" * len(types))
        sql += f" WHERE entity_type IN ({placeholders})"
        params.extend(types)
    sql += " ORDER BY entity_type, entity_value"
    if limit:
        sql += " LIMIT ?"
        params.append(int(limit))
    rows = conn.execute(sql, tuple(params)).fetchall()
    return [(r["entity_type"], r["entity_value"]) for r in rows]


def parse_result(row) -> dict:
    """Helper for callers reading enrichments back out of the DB."""
    if not row or not row["result_json"]:
        return {}
    try:
        return json.loads(row["result_json"])
    except (TypeError, ValueError):
        return {}
