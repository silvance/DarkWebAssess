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
from typing import Iterable

import yaml

from app.alerts.telegram import format_alert_message, is_configured, send_telegram
from app.config import (
    ALERT_MIN_SEVERITY,
    SEVERITY_ORDER,
    SOURCES_PATH,
    WATCHLIST_PATH,
)
from app.collectors.rss_collector import collect_rss
from app.database import db_cursor, init_db
from app.extractors.entities import extract_all
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

        if _severity_ge_min(m.get("severity", "medium")) and is_configured():
            text = format_alert_message(m, doc)
            ok, err = send_telegram(text)
            record_alert(conn, match_id, "telegram", ok, err)
            if ok:
                stats["alerts"] += 1
    return stats


def _iter_enabled_sources(sources: Iterable[dict]):
    for src in sources:
        if src.get("enabled", True):
            yield src


def cmd_collect(args):
    sources = load_yaml(SOURCES_PATH).get("sources", []) or []
    only = set(args.only) if args.only else None
    totals = {"new": 0, "duplicate": 0, "entities": 0, "matches": 0, "alerts": 0, "errors": 0}

    with db_cursor() as conn:
        # Make sure sources are registered for health tracking.
        for src in sources:
            upsert_source(conn, src)

        for src in _iter_enabled_sources(sources):
            if only and src["name"] not in only:
                continue
            if src["type"] != "rss":
                log.warning("Skipping unsupported source type %s", src["type"])
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

    print(
        "Collection done. "
        f"new={totals['new']} dup={totals['duplicate']} "
        f"entities={totals['entities']} matches={totals['matches']} "
        f"alerts={totals['alerts']} errors={totals['errors']}"
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
                    total += 1
    print(f"Created {total} new matches.")


def cmd_alert_test(_args):
    if not is_configured():
        print("Telegram not configured. Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID.")
        sys.exit(1)
    ok, err = send_telegram("Test alert from mini-threat-intel.")
    print("OK" if ok else f"FAILED: {err}")


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
    sub.add_parser("alert-test", help="Send a test Telegram alert.").set_defaults(func=cmd_alert_test)

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
