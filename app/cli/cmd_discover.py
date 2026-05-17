"""`discover` subcommand — run onion-discovery and triage candidates.

Sub-subcommands:
    dwa discover run         — fetch the configured directories, write candidates
    dwa discover list        — show pending (or any-status) candidates
    dwa discover show <id>   — full detail on one candidate
    dwa discover approve <id> — mark approved + print the sources.yaml snippet
    dwa discover reject <id> — mark rejected (won't be re-suggested)
"""
from __future__ import annotations

import json
import logging
import sys

from app.config import ONION_DIRECTORIES_PATH

log = logging.getLogger(__name__)


def register(sub) -> None:
    p = sub.add_parser(
        "discover",
        help="Discover candidate onion URLs from trusted aggregator pages.",
    )
    sp = p.add_subparsers(dest="discover_cmd", required=True)

    p_run = sp.add_parser("run", help="Run one discovery cycle.")
    p_run.add_argument(
        "--directory",
        help="Only fetch this directory by name (default: all enabled).",
    )
    p_run.set_defaults(func=_cmd_run)

    p_list = sp.add_parser("list", help="List candidates.")
    p_list.add_argument(
        "--status",
        choices=["pending", "approved", "rejected", "all"],
        default="pending",
    )
    p_list.add_argument("--search", help="Filter by substring of URL or title.")
    p_list.set_defaults(func=_cmd_list)

    p_show = sp.add_parser("show", help="Show full detail on one candidate.")
    p_show.add_argument("candidate_id", type=int)
    p_show.set_defaults(func=_cmd_show)

    p_approve = sp.add_parser(
        "approve",
        help="Mark a candidate approved and print the sources.yaml snippet.",
    )
    p_approve.add_argument("candidate_id", type=int)
    p_approve.add_argument("--reviewer", default=None, help="Username doing the review.")
    p_approve.add_argument("--notes", default=None)
    p_approve.set_defaults(func=_cmd_approve)

    p_reject = sp.add_parser("reject", help="Mark a candidate rejected.")
    p_reject.add_argument("candidate_id", type=int)
    p_reject.add_argument("--reviewer", default=None)
    p_reject.add_argument("--reason", dest="notes", default=None)
    p_reject.set_defaults(func=_cmd_reject)


def _cmd_run(args) -> None:
    from app.config_models import load_onion_directories
    from app.collectors.onion_discovery import discover_from_directories
    from app.database import get_connection
    from app.repository import upsert_onion_candidate

    cfg = load_onion_directories(ONION_DIRECTORIES_PATH)
    directories = cfg.directories
    if args.directory:
        directories = [d for d in directories if d.name == args.directory]
        if not directories:
            print(f"[discover] no directory named {args.directory!r}", file=sys.stderr)
            sys.exit(2)
    enabled = [d for d in directories if d.enabled]
    if not enabled:
        print(
            f"[discover] no enabled directories in {ONION_DIRECTORIES_PATH}. "
            "Edit the file and set `enabled: true` on the ones you trust.",
        )
        return
    print(f"[discover] fetching {len(enabled)} director{'y' if len(enabled) == 1 else 'ies'} ...")
    found = discover_from_directories(enabled)
    new = 0
    refreshed = 0
    with get_connection() as conn:
        for cand in found:
            row = upsert_onion_candidate(
                conn,
                url=cand.url,
                host=cand.host,
                title=cand.title,
                source_name=cand.source_name,
            )
            if row["times_seen"] == 1:
                new += 1
            else:
                refreshed += 1
        conn.commit()
    print(
        f"[discover] done. {len(found)} URLs extracted "
        f"({new} new, {refreshed} re-seen). Review with `dwa discover list`."
    )


def _cmd_list(args) -> None:
    from app.database import get_connection
    from app.repository import list_onion_candidates

    status = None if args.status == "all" else args.status
    with get_connection() as conn:
        rows = list_onion_candidates(conn, status=status, search=args.search)
    if not rows:
        print(f"[discover] no candidates with status={args.status}.")
        return
    print(f"{'ID':>4}  {'STATUS':<9}  {'SEEN':>4}  URL")
    print("-" * 80)
    for r in rows:
        url = r["url"]
        if len(url) > 60:
            url = url[:57] + "..."
        print(f"{r['id']:>4}  {r['status']:<9}  {r['times_seen']:>4}  {url}")
    print()
    print(f"{len(rows)} candidates. `dwa discover show <id>` for details.")


def _cmd_show(args) -> None:
    from app.database import get_connection
    from app.repository import get_onion_candidate

    with get_connection() as conn:
        row = get_onion_candidate(conn, args.candidate_id)
    if not row:
        print(f"[discover] no candidate with id={args.candidate_id}.", file=sys.stderr)
        sys.exit(2)
    sources = []
    try:
        sources = json.loads(row.get("sources_json") or "[]")
    except json.JSONDecodeError:
        pass
    print(f"Candidate #{row['id']}")
    print(f"  URL:           {row['url']}")
    print(f"  Host:          {row['host']}")
    print(f"  Title:         {row['title'] or '(none)'}")
    print(f"  Status:        {row['status']}")
    print(f"  Times seen:    {row['times_seen']}")
    print(f"  Discovered at: {row['discovered_at']}")
    print(f"  Last seen at:  {row['last_seen_at']}")
    print(f"  First source:  {row['first_source']}")
    print(f"  All sources:   {', '.join(sources) if sources else '(none)'}")
    if row.get("reviewed_at"):
        print(f"  Reviewed at:   {row['reviewed_at']}  by {row.get('reviewed_by') or '(unknown)'}")
    if row.get("notes"):
        print(f"  Notes:         {row['notes']}")


def _cmd_approve(args) -> None:
    from app.database import get_connection
    from app.repository import set_onion_candidate_status

    with get_connection() as conn:
        row = set_onion_candidate_status(
            conn, args.candidate_id, "approved",
            reviewed_by=args.reviewer, notes=args.notes,
        )
        conn.commit()
    if row is None:
        print(f"[discover] no candidate with id={args.candidate_id}.", file=sys.stderr)
        sys.exit(2)
    print(f"[discover] candidate #{row['id']} marked approved.")
    title = row.get("title") or row["host"]
    safe_name = (title[:60] if title else f"onion-{row['id']}").strip().replace('"', "'")
    snippet = (
        f"\n# Add this entry to sources.yaml, then run: dwa sync-config\n"
        f"  - name: \"{safe_name}\"\n"
        f"    type: onion\n"
        f"    url: \"{row['url']}\"\n"
        f"    enabled: true\n"
    )
    print(snippet)


def _cmd_reject(args) -> None:
    from app.database import get_connection
    from app.repository import set_onion_candidate_status

    with get_connection() as conn:
        row = set_onion_candidate_status(
            conn, args.candidate_id, "rejected",
            reviewed_by=args.reviewer, notes=args.notes,
        )
        conn.commit()
    if row is None:
        print(f"[discover] no candidate with id={args.candidate_id}.", file=sys.stderr)
        sys.exit(2)
    print(
        f"[discover] candidate #{row['id']} marked rejected. "
        "It will not be re-suggested even if a directory lists it again."
    )
