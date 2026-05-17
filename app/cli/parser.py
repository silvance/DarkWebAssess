"""Top-level argparse assembler. Each subcommand module registers itself."""
import argparse
import logging

from app import __version__
from app.cli import (
    cmd_alerts,
    cmd_backup,
    cmd_cases,
    cmd_collection,
    cmd_discover,
    cmd_enrich,
    cmd_network,
    cmd_pivot,
    cmd_reports,
    cmd_scheduler,
    cmd_score,
    cmd_search,
    cmd_summarize,
    cmd_tor,
    cmd_users,
)
from app.database import init_db

DESCRIPTION = """CLI orchestrator for the threat intelligence MVP.

Subcommands:
    init-db        Create the SQLite schema.
    sync-config    Load sources.yaml and watchlist.yaml into the DB.
    collect        Fetch enabled sources, normalize, store new documents,
                   extract entities, run watchlist matching, send alerts.
    extract        Re-run entity extraction over already-stored documents.
    match          Re-run watchlist matching over already-stored documents.
    score          (Re)score matches.
    enrich         Run enrichment providers over stored entities.
    summarize      Generate analyst summaries via the Claude API.
    case ...       Manage cases / investigations.
    report ...     Generate and manage reports.
    user ...       Manage dashboard users.
    backup         Online-backup the SQLite DB.
    restore        Restore the SQLite DB from a backup file.
    scheduler      Run collect/enrich/source-health on intervals.
    search         Full-text search over collected documents.
    reindex        Rebuild the FTS index from documents.
    alert-test     Send a test Telegram alert.
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="threatintel",
        description=DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"mini-threat-intel {__version__}",
    )
    sub = p.add_subparsers(dest="command", required=True)

    cmd_collection.register(sub)
    cmd_score.register(sub)
    cmd_enrich.register(sub)
    cmd_alerts.register(sub)
    cmd_scheduler.register(sub)
    cmd_search.register(sub)
    cmd_summarize.register(sub)
    cmd_cases.register(sub)
    cmd_reports.register(sub)
    cmd_users.register(sub)
    cmd_backup.register(sub)
    cmd_pivot.register(sub)
    cmd_tor.register(sub)
    cmd_discover.register(sub)
    cmd_network.register(sub)

    return p


def main(argv=None):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "init-db":
        init_db()
    args.func(args)
