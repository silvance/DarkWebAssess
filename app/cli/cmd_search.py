"""search / reindex commands."""
from app.database import db_cursor


def register(sub):
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


def cmd_search(args):
    from app.search import search_documents

    with db_cursor() as conn:
        rows = search_documents(
            conn, args.query,
            source_name=args.source, since=args.since, until=args.until, limit=args.limit,
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
