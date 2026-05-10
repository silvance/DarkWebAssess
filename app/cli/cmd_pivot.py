"""Pivot from an entity to its co-occurrence neighbors."""
import sys

from app.database import db_cursor


def register(sub):
    pp = sub.add_parser(
        "pivot",
        help="Show entities that co-occur with a given entity (relationship pivot).",
    )
    pp.add_argument(
        "entity",
        help="Entity in the form type:value, e.g. domain:example.com or cve:CVE-2024-3400",
    )
    pp.add_argument(
        "--neighbor-type",
        action="append",
        help="Restrict to one or more neighbor types. Repeat to allow multiple.",
    )
    pp.add_argument("--limit", type=int, default=25, help="Max neighbors (default 25).")
    pp.add_argument(
        "--min-shared",
        type=int,
        default=1,
        help="Drop neighbors that share fewer than this many documents.",
    )
    pp.set_defaults(func=cmd_pivot)


def cmd_pivot(args):
    from app.graph.relationships import (
        entity_summary,
        neighbors,
        related_documents,
    )

    if ":" not in args.entity:
        print("entity must be in the form type:value (e.g. domain:example.com)")
        sys.exit(1)
    etype, evalue = args.entity.split(":", 1)
    etype = etype.strip()
    evalue = evalue.strip()
    if not etype or not evalue:
        print("entity must be in the form type:value")
        sys.exit(1)

    with db_cursor() as conn:
        summary = entity_summary(conn, etype, evalue)
        if not summary:
            print(f"Unknown entity: {etype}:{evalue}")
            sys.exit(1)
        rows = neighbors(
            conn,
            etype,
            evalue,
            neighbor_types=args.neighbor_type or None,
            limit=args.limit,
            min_shared=args.min_shared,
        )
        docs = related_documents(conn, etype, evalue, limit=10)

    print(f"{etype}: {evalue}")
    print(
        f"  sightings={summary['sightings']}  "
        f"first={summary['first_seen']}  last={summary['last_seen']}"
    )
    if rows:
        print(f"\nNeighbors (top {len(rows)}):")
        print(f"  {'docs':>4}  {'type':<10} value")
        for r in rows:
            print(
                f"  {r['shared_docs']:>4}  {r['neighbor_type']:<10} {r['neighbor_value']}"
            )
    else:
        print("\n(no neighbors found)")

    if docs:
        print(f"\nRelated documents (top {len(docs)}):")
        for d in docs:
            print(f"  [{d['retrieved_at']}] {d['source_name']}: {d['title'] or d['source_url']}")
