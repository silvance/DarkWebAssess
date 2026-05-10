"""CLI orchestrator for the threat intelligence MVP.

Subcommands:
    init-db         Create the SQLite schema.
    sync-config     Load sources.yaml and watchlist.yaml into the DB.
    collect         Fetch enabled sources, normalize, store new documents,
                    extract entities, run watchlist matching, send alerts.
    extract         Re-run entity extraction over already-stored documents.
    match           Re-run watchlist matching over already-stored documents.
    alert-test      Send a test Telegram alert.
"""
import argparse
import logging
import sys
from datetime import datetime, timedelta, timezone
from typing import Iterable, List, Optional

import yaml

from app.alerts.telegram import format_alert_message, is_configured, send_telegram
from app.config import (
    ALERT_MIN_SEVERITY,
    ENRICH_BATCH_LIMIT,
    SEVERITY_ORDER,
    SOURCE_BACKOFF_BASE_MINUTES,
    SOURCE_BACKOFF_MAX_EXPONENT,
    SOURCES_PATH,
    WATCHLIST_PATH,
)
from app.collectors.rss_collector import collect_rss
from app.database import db_cursor, init_db
from app.enrichment.runner import (
    default_providers,
    enrich_entity,
    iter_distinct_entities,
)
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
    upsert_watchlist_entry,
)

log = logging.getLogger("threatintel")


# --- Config loading ---------------------------------------------------------
def load_yaml(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def cmd_init_db(_args):
    init_db()
    print("Database initialized.")


def cmd_sync_config(_args):
    sources = load_yaml(SOURCES_PATH).get("sources", []) or []
    watchlist = load_yaml(WATCHLIST_PATH).get("watchlist", []) or []
    with db_cursor() as conn:
        for src in sources:
            upsert_source(conn, src)
        for entry in watchlist:
            upsert_watchlist_entry(conn, entry)
    print(f"Synced {len(sources)} sources and {len(watchlist)} watchlist entries.")


def _severity_ge_min(severity: str) -> bool:
    return SEVERITY_ORDER.get(severity.lower(), 0) >= SEVERITY_ORDER.get(
        ALERT_MIN_SEVERITY, 3
    )


def _should_alert(severity: str, score) -> bool:
    """Alert iff severity meets the floor AND, if a score threshold is set,
    the score meets it too."""
    if not _severity_ge_min(severity):
        return False
    from app.config import ALERT_MIN_SCORE  # imported lazily to allow env override

    if ALERT_MIN_SCORE > 0 and (score is None or score < ALERT_MIN_SCORE):
        return False
    return True


def _process_document(conn, doc: dict) -> dict:
    """Insert document, extract entities, run matches, send alerts.

    Returns a small per-doc stats dict.
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

        # Score the match; severity is updated to reflect priority.
        scored = score_and_persist(conn, match_id)
        effective_severity = scored[0].severity if scored else m.get("severity", "medium")
        score_value = scored[0].score if scored else None

        if _should_alert(effective_severity, score_value) and is_configured():
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


def _iter_enabled_sources(sources: Iterable[dict]):
    for src in sources:
        if src.get("enabled", True):
            yield src


def _backoff_until(error_count: int, last_checked_at: Optional[str]) -> Optional[datetime]:
    """Exponential backoff cap, returns the wall-clock time before which we
    should not retry this source. None means no backoff in effect."""
    if not error_count or not last_checked_at:
        return None
    exp = min(int(error_count), SOURCE_BACKOFF_MAX_EXPONENT)
    minutes = SOURCE_BACKOFF_BASE_MINUTES * (2 ** exp)
    try:
        last = datetime.strptime(last_checked_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None
    return last + timedelta(minutes=minutes)


def run_collection_cycle(only: Optional[List[str]] = None) -> dict:
    """One full collection cycle. Returns a stats dict; safe to call from
    the CLI or the scheduler."""
    sources = load_yaml(SOURCES_PATH).get("sources", []) or []
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
        # Make sure sources are registered for health tracking.
        for src in sources:
            upsert_source(conn, src)

        now = datetime.now(timezone.utc)
        for src in _iter_enabled_sources(sources):
            if only_set and src["name"] not in only_set:
                continue
            if src["type"] != "rss":
                log.warning("Skipping unsupported source type %s", src["type"])
                continue

            db_row = conn.execute(
                "SELECT error_count, last_checked_at FROM sources WHERE name = ?",
                (src["name"],),
            ).fetchone()
            until = _backoff_until(db_row["error_count"], db_row["last_checked_at"]) if db_row else None
            if until and now < until:
                log.info("Skipping %s due to backoff until %s", src["name"], until.isoformat())
                totals["skipped"] += 1
                continue

            log.info("Collecting %s (%s)", src["name"], src["url"])
            try:
                docs = list(collect_rss(src))
            except Exception as exc:  # noqa: BLE001
                log.exception("Collection failed for %s", src["name"])
                mark_source_error(conn, src["name"], str(exc))
                totals["errors"] += 1
                continue

            for doc in docs:
                s = _process_document(conn, doc)
                for k in totals:
                    if k in s:
                        totals[k] += s[k]
            mark_source_success(conn, src["name"])

    return totals


def cmd_collect(args):
    totals = run_collection_cycle(only=args.only)
    print(
        "Collection done. "
        f"new={totals['new']} dup={totals['duplicate']} "
        f"entities={totals['entities']} matches={totals['matches']} "
        f"alerts={totals['alerts']} errors={totals['errors']} "
        f"skipped={totals['skipped']}"
    )


def cmd_extract(_args):
    """Re-run extraction across stored documents that have no entities."""
    with db_cursor() as conn:
        docs = conn.execute(
            """
            SELECT d.id, d.raw_text
            FROM documents d
            LEFT JOIN entities e ON e.document_id = d.id
            WHERE e.id IS NULL
            """
        ).fetchall()
        total = 0
        for row in docs:
            ents = extract_all(row["raw_text"] or "")
            total += insert_entities(conn, row["id"], ents)
    print(f"Extracted {total} entities across {len(docs)} documents.")


def cmd_match(_args):
    """Re-run watchlist matching across all stored documents."""
    total = 0
    with db_cursor() as conn:
        rows = conn.execute(
            "SELECT id, source_name, source_type, source_url, title, raw_text, retrieved_at FROM documents"
        ).fetchall()
        for r in rows:
            ents = conn.execute(
                "SELECT entity_type, entity_value, context FROM entities WHERE document_id = ?",
                (r["id"],),
            ).fetchall()
            ents_dicts = [dict(e) for e in ents]
            for m in match_document(conn, r["id"], r["title"], r["raw_text"], ents_dicts):
                mid = insert_match(
                    conn,
                    document_id=r["id"],
                    watchlist_id=m["watchlist_id"],
                    matched_value=m["matched_value"],
                    match_type=m["match_type"],
                    context=m.get("context"),
                    severity=m.get("severity", "medium"),
                )
                if mid is not None:
                    score_and_persist(conn, mid)
                    total += 1
    print(f"Created {total} new matches.")


def cmd_score(args):
    """(Re)score matches. By default, only matches without a score yet."""
    where = "" if args.rescore_all else "WHERE score IS NULL"
    with db_cursor() as conn:
        ids = [
            r["id"]
            for r in conn.execute(f"SELECT id FROM matches {where} ORDER BY id").fetchall()
        ]
        for mid in ids:
            score_and_persist(conn, mid)
    print(f"Scored {len(ids)} matches.")


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
        return {"targets": 0, "hits": 0, "cached": 0, "errors": 0, "skipped": 0, "configured": 0}

    if entity_value and entity_type:
        targets = [(entity_type, entity_value)]
    else:
        with db_cursor() as conn:
            types = [entity_type] if entity_type else None
            targets = iter_distinct_entities(conn, entity_types=types, limit=limit)

    totals = {"targets": len(targets), "hits": 0, "cached": 0, "errors": 0, "skipped": 0,
              "configured": len(configured)}
    with db_cursor() as conn:
        for etype, evalue in targets:
            outcomes = enrich_entity(conn, etype, evalue, providers=configured, force=force)
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


def cmd_enrich(args):
    providers = default_providers()
    configured = [p for p in providers if p.is_configured()]
    skipped = [p.name for p in providers if not p.is_configured()]
    if skipped:
        log.info("Skipping unconfigured providers: %s", ", ".join(skipped))
    if not configured:
        print("No enrichment providers are configured.")
        return

    totals = run_enrichment_cycle(
        entity_type=args.type, entity_value=args.value, limit=args.limit, force=args.force
    )
    if totals["targets"] == 0:
        print("No entities to enrich.")
        return
    print(
        "Enrichment done. "
        f"targets={totals['targets']} hits={totals['hits']} cached={totals['cached']} "
        f"errors={totals['errors']} skipped={totals['skipped']}"
    )


def cmd_alert_test(_args):
    if not is_configured():
        print("Telegram not configured. Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID.")
        sys.exit(1)
    ok, err = send_telegram("Test alert from mini-threat-intel.")
    print("OK" if ok else f"FAILED: {err}")


def cmd_scheduler(args):
    from app.jobs.scheduler import run_scheduler

    try:
        run_scheduler(run_now=args.run_now)
    except (KeyboardInterrupt, SystemExit):
        log.info("Scheduler stopped.")


def cmd_search(args):
    from app.search import search_documents

    with db_cursor() as conn:
        rows = search_documents(
            conn,
            args.query,
            source_name=args.source,
            since=args.since,
            until=args.until,
            limit=args.limit,
        )
    if not rows:
        print("No results.")
        return
    for r in rows:
        print(f"[{r['retrieved_at']}] {r['source_name']}: {r['title'] or '(no title)'}")
        print(f"  {r['source_url']}")
        if r.get("snippet"):
            print(f"  {r['snippet']}")
        print()


def cmd_reindex(_args):
    from app.search import reindex as fts_reindex

    with db_cursor() as conn:
        n = fts_reindex(conn)
    print(f"FTS index rebuilt over {n} documents.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="threatintel", description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init-db", help="Create the SQLite schema.").set_defaults(func=cmd_init_db)
    sub.add_parser("sync-config", help="Load sources.yaml and watchlist.yaml into the DB.").set_defaults(
        func=cmd_sync_config
    )

    pc = sub.add_parser("collect", help="Run collection across enabled sources.")
    pc.add_argument("--only", nargs="*", help="Restrict to these source names.")
    pc.set_defaults(func=cmd_collect)

    sub.add_parser("extract", help="Re-run extraction over stored docs.").set_defaults(func=cmd_extract)
    sub.add_parser("match", help="Re-run watchlist matching over stored docs.").set_defaults(func=cmd_match)

    ps = sub.add_parser("score", help="(Re)score matches.")
    ps.add_argument(
        "--rescore-all",
        action="store_true",
        help="Recompute scores for every match, not just unscored ones.",
    )
    ps.set_defaults(func=cmd_score)

    pe = sub.add_parser("enrich", help="Run enrichment providers over stored entities.")
    pe.add_argument("--type", help="Restrict to one entity type (cve, domain, ip, url, md5, sha1, sha256).")
    pe.add_argument("--value", help="Enrich a single entity value (requires --type).")
    pe.add_argument("--limit", type=int, help="Cap the number of entities processed.")
    pe.add_argument("--force", action="store_true", help="Bypass cache freshness check.")
    pe.set_defaults(func=cmd_enrich)

    sub.add_parser("alert-test", help="Send a test Telegram alert.").set_defaults(func=cmd_alert_test)

    psched = sub.add_parser("scheduler", help="Run collect/enrich/source-health on intervals.")
    psched.add_argument("--run-now", action="store_true", help="Trigger every job immediately on start.")
    psched.set_defaults(func=cmd_scheduler)

    psr = sub.add_parser("search", help="Full-text search over collected documents.")
    psr.add_argument("query", help="Search query (FTS5 syntax accepted).")
    psr.add_argument("--source", help="Restrict to a single source name.")
    psr.add_argument("--since", help="Only documents retrieved at/after this ISO timestamp.")
    psr.add_argument("--until", help="Only documents retrieved at/before this ISO timestamp.")
    psr.add_argument("--limit", type=int, default=20)
    psr.set_defaults(func=cmd_search)

    sub.add_parser("reindex", help="Rebuild the FTS index from documents.").set_defaults(
        func=cmd_reindex
    )

    return p


def main(argv=None):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    parser = build_parser()
    args = parser.parse_args(argv)
    # Ensure DB exists for any subcommand other than init-db.
    if args.command != "init-db":
        init_db()
    args.func(args)


if __name__ == "__main__":
    main()
