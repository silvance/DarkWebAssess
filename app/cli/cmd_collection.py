"""init-db / sync-config / collect / extract / match commands."""
import sys

from app.cli._helpers import load_sources_validated, load_watchlist_validated
from app.database import db_cursor, init_db
from app.extractors.entities import extract_all
from app.matching.scoring import score_and_persist
from app.matching.watchlist_matcher import match_document
from app.pipeline import run_collection_cycle
from app.repository import (
    insert_entities, insert_match, upsert_source, upsert_watchlist_entry,
)


def register(sub):
    sub.add_parser("init-db", help="Create the SQLite schema.").set_defaults(func=cmd_init_db)
    sub.add_parser(
        "sync-config", help="Load sources.yaml and watchlist.yaml into the DB."
    ).set_defaults(func=cmd_sync_config)

    pc = sub.add_parser("collect", help="Run collection across enabled sources.")
    pc.add_argument("--only", nargs="*", help="Restrict to these source names.")
    pc.set_defaults(func=cmd_collect)

    sub.add_parser("extract", help="Re-run extraction over stored docs.").set_defaults(
        func=cmd_extract
    )
    sub.add_parser("match", help="Re-run watchlist matching over stored docs.").set_defaults(
        func=cmd_match
    )


def cmd_init_db(_args):
    init_db()
    print("Database initialized.")


def cmd_sync_config(_args):
    from pydantic import ValidationError

    try:
        sources = load_sources_validated()
        watchlist = load_watchlist_validated()
    except ValidationError as exc:
        print(f"Config validation failed:\n{exc}")
        sys.exit(1)
    with db_cursor() as conn:
        for src in sources:
            upsert_source(conn, src)
        for entry in watchlist:
            upsert_watchlist_entry(conn, entry)
    print(f"Synced {len(sources)} sources and {len(watchlist)} watchlist entries.")


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
            "SELECT id, source_name, source_type, source_url, title, raw_text, retrieved_at "
            "FROM documents"
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
