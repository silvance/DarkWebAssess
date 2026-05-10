"""End-to-end pipeline functions — used by both the CLI and the scheduler.

Lifted out of `app.main` so the CLI handlers stay thin and the scheduler
job entry points can call exactly the same code path the analyst would
trigger by hand. This module owns the orchestration; each stage's logic
still lives in its respective package (collectors / extractors / matching
/ enrichment / alerts).
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Iterable, List, Optional

from app.alerts.telegram import format_alert_message, is_configured, send_telegram
from app.collectors.rss_collector import collect_rss
from app.config import (
    ALERT_MIN_SEVERITY,
    ALERT_MIN_SCORE,
    ENRICH_BATCH_LIMIT,
    SEVERITY_ORDER,
    SOURCE_BACKOFF_BASE_MINUTES,
    SOURCE_BACKOFF_MAX_EXPONENT,
    SOURCES_PATH,
)
from app.config_models import load_sources
from app.database import db_cursor
from app.enrichment.runner import default_providers, enrich_entity, iter_distinct_entities
from app.extractors.entities import extract_all
from app.matching.scoring import score_and_persist
from app.matching.watchlist_matcher import match_document
from app.repository import (
    insert_document,
    insert_entities,
    insert_match,
    mark_source_error,
    mark_source_success,
    record_alert,
    upsert_source,
)

log = logging.getLogger(__name__)


# --- alert gating --------------------------------------------------------
def severity_ge_min(severity: str) -> bool:
    return SEVERITY_ORDER.get((severity or "").lower(), 0) >= SEVERITY_ORDER.get(
        ALERT_MIN_SEVERITY, 3
    )


def should_alert(severity: str, score: Optional[int]) -> bool:
    """Alert iff the severity gate passes AND, if a score floor is set,
    the score is at or above it."""
    if not severity_ge_min(severity):
        return False
    if ALERT_MIN_SCORE > 0 and (score is None or score < ALERT_MIN_SCORE):
        return False
    return True


# --- per-source backoff --------------------------------------------------
def backoff_until(
    error_count: int, last_checked_at: Optional[str]
) -> Optional[datetime]:
    """The wall-clock time before which we should not retry a source.
    None = no backoff in effect."""
    if not error_count or not last_checked_at:
        return None
    exp = min(int(error_count), SOURCE_BACKOFF_MAX_EXPONENT)
    minutes = SOURCE_BACKOFF_BASE_MINUTES * (2 ** exp)
    try:
        last = datetime.strptime(last_checked_at, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except (TypeError, ValueError):
        return None
    return last + timedelta(minutes=minutes)


# --- per-document processing --------------------------------------------
def process_document(conn, doc: dict) -> dict:
    """Insert document, extract entities, run matches, score, send alerts.

    Returns a per-doc stats dict. Idempotent w.r.t. duplicate documents
    (deduped via content_hash).
    """
    stats = {"new": 0, "duplicate": 0, "entities": 0, "matches": 0, "alerts": 0}
    doc_id = insert_document(conn, doc)
    if doc_id is None:
        stats["duplicate"] = 1
        return stats
    stats["new"] = 1

    entities = extract_all(doc.get("raw_text") or "")
    stats["entities"] = insert_entities(conn, doc_id, entities)

    matches = match_document(
        conn,
        doc_id,
        title=doc.get("title"),
        text=doc.get("raw_text"),
        entities=entities,
    )
    for m in matches:
        match_id = insert_match(
            conn,
            document_id=doc_id,
            watchlist_id=m["watchlist_id"],
            matched_value=m["matched_value"],
            match_type=m["match_type"],
            context=m.get("context"),
            severity=m.get("severity", "medium"),
        )
        if match_id is None:
            continue
        stats["matches"] += 1

        scored = score_and_persist(conn, match_id)
        effective_severity = scored[0].severity if scored else m.get("severity", "medium")
        score_value = scored[0].score if scored else None

        if should_alert(effective_severity, score_value) and is_configured():
            alert_match = dict(m)
            alert_match["severity"] = effective_severity
            alert_match["score"] = score_value
            alert_match["reasons"] = scored[0].reasons if scored else []
            text = format_alert_message(alert_match, doc)
            ok, err = send_telegram(text)
            record_alert(conn, match_id, "telegram", ok, err)
            if ok:
                stats["alerts"] += 1
    return stats


# --- cycle orchestrators -------------------------------------------------
def _enabled(sources: Iterable) -> Iterable:
    for src in sources:
        if getattr(src, "enabled", True):
            yield src


def run_collection_cycle(only: Optional[List[str]] = None) -> dict:
    """One full collection cycle. Returns a stats dict; safe to call from
    the CLI or the scheduler. Per-source exponential backoff is applied."""
    cfg = load_sources(SOURCES_PATH)
    only_set = set(only) if only else None
    totals = {
        "new": 0,
        "duplicate": 0,
        "entities": 0,
        "matches": 0,
        "alerts": 0,
        "errors": 0,
        "skipped": 0,
    }

    with db_cursor() as conn:
        for src in cfg.sources:
            upsert_source(conn, src.model_dump())

        now = datetime.now(timezone.utc)
        for src in _enabled(cfg.sources):
            if only_set and src.name not in only_set:
                continue
            if src.type != "rss":
                log.warning("Skipping unsupported source type %s", src.type)
                continue

            db_row = conn.execute(
                "SELECT error_count, last_checked_at FROM sources WHERE name = ?",
                (src.name,),
            ).fetchone()
            until = backoff_until(
                db_row["error_count"] if db_row else 0,
                db_row["last_checked_at"] if db_row else None,
            )
            if until and now < until:
                log.info("Skipping %s due to backoff until %s", src.name, until.isoformat())
                totals["skipped"] += 1
                continue

            log.info("Collecting %s (%s)", src.name, src.url)
            try:
                docs = list(collect_rss(src.model_dump()))
            except Exception as exc:  # noqa: BLE001
                log.exception("Collection failed for %s", src.name)
                mark_source_error(conn, src.name, str(exc))
                totals["errors"] += 1
                continue

            for doc in docs:
                s = process_document(conn, doc)
                for k in totals:
                    if k in s:
                        totals[k] += s[k]
            mark_source_success(conn, src.name)

    return totals


def run_enrichment_cycle(
    entity_type: Optional[str] = None,
    entity_value: Optional[str] = None,
    limit: Optional[int] = None,
    force: bool = False,
) -> dict:
    """One enrichment cycle. Returns a stats dict including target count."""
    providers = default_providers()
    configured = [p for p in providers if p.is_configured()]
    if not configured:
        return {
            "targets": 0, "hits": 0, "cached": 0, "errors": 0, "skipped": 0,
            "configured": 0,
        }

    if entity_value and entity_type:
        targets = [(entity_type, entity_value)]
    else:
        with db_cursor() as conn:
            types = [entity_type] if entity_type else None
            targets = iter_distinct_entities(conn, entity_types=types, limit=limit)

    totals = {
        "targets": len(targets), "hits": 0, "cached": 0, "errors": 0, "skipped": 0,
        "configured": len(configured),
    }
    with db_cursor() as conn:
        for etype, evalue in targets:
            outcomes = enrich_entity(
                conn, etype, evalue, providers=configured, force=force
            )
            if not outcomes:
                totals["skipped"] += 1
                continue
            for o in outcomes:
                if o.cached:
                    totals["cached"] += 1
                elif o.success:
                    totals["hits"] += 1
                else:
                    totals["errors"] += 1
    return totals
