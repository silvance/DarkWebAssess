"""`demo-seed` / `demo-clear` — populate or remove sample data.

Lets a new operator explore a fully-populated dashboard before wiring up
real sources. All demo content is fictional and runs through the real
pipeline, so what you see is produced by the actual extractors + scorer.
"""
from __future__ import annotations


def register(sub) -> None:
    p_seed = sub.add_parser(
        "demo-seed",
        help="Populate the DB with fictional sample data to explore the UI.",
    )
    p_seed.set_defaults(func=_cmd_seed)

    p_clear = sub.add_parser(
        "demo-clear",
        help="Remove everything `demo-seed` added (leaves your data alone).",
    )
    p_clear.set_defaults(func=_cmd_clear)


def _cmd_seed(_args) -> None:
    from app.database import get_connection
    from app.demo import seed_demo

    with get_connection() as conn:
        stats = seed_demo(conn)
    print(
        "[demo] seeded: "
        f"{stats['watchlist']} watchlist rules, "
        f"{stats['documents_new']} documents "
        f"({stats['documents_dup']} already present), "
        f"{stats['entities']} entities, {stats['matches']} matches."
    )
    print("[demo] open the dashboard and check Overview → Matches.")
    print("[demo] run `dwa demo-clear` to remove it all when you're done.")


def _cmd_clear(_args) -> None:
    from app.database import get_connection
    from app.demo import clear_demo

    with get_connection() as conn:
        stats = clear_demo(conn)
    print(
        f"[demo] removed: {stats['documents']} documents, "
        f"{stats['watchlist']} watchlist rules."
    )
