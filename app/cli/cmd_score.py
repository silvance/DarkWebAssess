"""(re)score matches command."""
from app.database import db_cursor
from app.matching.scoring import score_and_persist


def register(sub):
    ps = sub.add_parser("score", help="(Re)score matches.")
    ps.add_argument(
        "--rescore-all",
        action="store_true",
        help="Recompute scores for every match, not just unscored ones.",
    )
    ps.set_defaults(func=cmd_score)


def cmd_score(args):
    where = "" if args.rescore_all else "WHERE score IS NULL"
    with db_cursor() as conn:
        ids = [
            r["id"]
            for r in conn.execute(f"SELECT id FROM matches {where} ORDER BY id").fetchall()
        ]
        for mid in ids:
            score_and_persist(conn, mid)
    print(f"Scored {len(ids)} matches.")
