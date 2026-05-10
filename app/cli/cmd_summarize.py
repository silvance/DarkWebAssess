"""LLM analyst-summary command."""
import logging

from app.database import db_cursor

log = logging.getLogger(__name__)


def register(sub):
    pz = sub.add_parser("summarize", help="Generate analyst summaries via the Claude API.")
    grp = pz.add_mutually_exclusive_group()
    grp.add_argument("--match-id", type=int, help="Summarize a single match by ID.")
    grp.add_argument(
        "--top", type=int,
        help="Summarize the top-N highest-scored open matches that lack a summary.",
    )
    grp.add_argument(
        "--all-new", action="store_true",
        help="Summarize every match that has no summary yet.",
    )
    pz.add_argument("--model", help="Override LLM_MODEL for this run.")
    pz.add_argument("--force", action="store_true",
                    help="Regenerate even if a summary already exists.")
    pz.set_defaults(func=cmd_summarize)


def cmd_summarize(args):
    from app.llm.summarizer import SummarizerNotConfigured, summarize_match

    with db_cursor() as conn:
        if args.match_id:
            ids = [int(args.match_id)]
        elif args.top:
            ids = [
                r["id"]
                for r in conn.execute(
                    """
                    SELECT m.id
                    FROM matches m
                    LEFT JOIN llm_summaries s ON s.match_id = m.id
                    WHERE s.id IS NULL AND m.status IN ('new', 'reviewing')
                    ORDER BY COALESCE(m.score, -1) DESC, m.created_at DESC
                    LIMIT ?
                    """,
                    (int(args.top),),
                ).fetchall()
            ]
        elif args.all_new:
            ids = [
                r["id"]
                for r in conn.execute(
                    """
                    SELECT m.id FROM matches m
                    LEFT JOIN llm_summaries s ON s.match_id = m.id
                    WHERE s.id IS NULL
                    ORDER BY m.created_at DESC
                    """
                ).fetchall()
            ]
        else:
            print("Specify --match-id N, --top N, or --all-new.")
            return

        if not ids:
            print("Nothing to summarize.")
            return

        ok = 0
        skipped = 0
        for mid in ids:
            try:
                rec = summarize_match(conn, mid, model=args.model, force=args.force)
            except SummarizerNotConfigured as exc:
                print(f"Cannot summarize: {exc}")
                return
            except Exception as exc:  # noqa: BLE001
                log.exception("Summarization failed for match %s", mid)
                print(f"  match {mid}: ERROR {exc}")
                continue
            if rec is None:
                skipped += 1
                print(f"  match {mid}: skipped (already summarized; pass --force to regenerate)")
            else:
                ok += 1
                print(
                    f"  match {mid}: ok confidence={rec.summary.confidence} "
                    f"in_toks={rec.input_tokens} out_toks={rec.output_tokens} "
                    f"cache_read={rec.cache_read_input_tokens}"
                )
    print(f"Summarized {ok}, skipped {skipped} of {len(ids)} matches.")
