"""Case management commands."""
from app.database import db_cursor


def register(sub):
    pc = sub.add_parser("case", help="Manage cases / investigations.")
    cs = pc.add_subparsers(dest="case_command", required=True)

    cc = cs.add_parser("create", help="Create a new case.")
    cc.add_argument("--from-match", type=int,
                    help="Seed from a match (auto-attaches doc, summary, entity).")
    cc.add_argument("--title")
    cc.add_argument("--severity", choices=["low", "medium", "high", "critical"],
                    default="medium")
    cc.add_argument("--owner")
    cc.add_argument("--summary")
    cc.set_defaults(func=cmd_case_create)

    cl = cs.add_parser("list", help="List cases.")
    cl.add_argument("--status", help="Filter by status.")
    cl.add_argument("--limit", type=int, default=50)
    cl.set_defaults(func=cmd_case_list)

    csh = cs.add_parser("show", help="Show case detail.")
    csh.add_argument("case_id", type=int)
    csh.set_defaults(func=cmd_case_show)

    cn = cs.add_parser("note", help="Add a note to a case.")
    cn.add_argument("case_id", type=int)
    cn.add_argument("--body", required=True)
    cn.add_argument("--author")
    cn.set_defaults(func=cmd_case_note)

    ca = cs.add_parser("attach", help="Attach evidence to a case.")
    ca.add_argument("case_id", type=int)
    grp = ca.add_mutually_exclusive_group(required=True)
    grp.add_argument("--match", type=int)
    grp.add_argument("--document", type=int)
    grp.add_argument("--entity", help="format type:value (e.g. domain:example.com)")
    grp.add_argument("--enrichment", type=int)
    grp.add_argument("--summary", type=int, help="llm_summaries.id")
    grp.add_argument("--text", help="free-form text content")
    ca.add_argument("--label")
    ca.add_argument("--actor")
    ca.set_defaults(func=cmd_case_attach)

    cst = cs.add_parser("status", help="Change a case's status.")
    cst.add_argument("case_id", type=int)
    cst.add_argument("--to", required=True, choices=[
        "open", "reviewing", "waiting", "confirmed", "false_positive", "escalated", "closed",
    ])
    cst.add_argument("--actor")
    cst.set_defaults(func=cmd_case_status)

    ce = cs.add_parser("export", help="Export a case as markdown.")
    ce.add_argument("case_id", type=int)
    ce.add_argument("--output", help="Write to this path (otherwise stdout).")
    ce.set_defaults(func=cmd_case_export)


def cmd_case_create(args):
    from app.cases.repository import create_case, create_case_from_match

    with db_cursor() as conn:
        if args.from_match:
            cid = create_case_from_match(
                conn, args.from_match, title=args.title, owner=args.owner
            )
            if cid is None:
                print(f"Match {args.from_match} not found.")
                return
        else:
            if not args.title:
                print("--title is required (unless --from-match is given).")
                return
            cid = create_case(
                conn, title=args.title, severity=args.severity,
                owner=args.owner, summary=args.summary,
            )
    print(f"Created case #{cid}")


def cmd_case_list(args):
    from app.cases.repository import list_cases

    with db_cursor() as conn:
        rows = list_cases(conn, status=args.status, limit=args.limit)
    if not rows:
        print("No cases.")
        return
    for r in rows:
        print(
            f"#{r['id']:<4} [{r['status']:<14}] {r['severity']:<8} "
            f"{r['updated_at']}  {r['title']}"
        )


def cmd_case_show(args):
    from app.cases.repository import get_case_detail

    with db_cursor() as conn:
        case = get_case_detail(conn, args.case_id)
    if not case:
        print(f"Case {args.case_id} not found.")
        return
    print(f"Case #{case['id']}: {case['title']}")
    print(f"  status={case['status']}  severity={case['severity']}  "
          f"owner={case['owner'] or '-'}")
    print(f"  created={case['created_at']}  updated={case['updated_at']}")
    if case.get("summary"):
        print("  summary:")
        for line in case["summary"].splitlines():
            print(f"    {line}")
    print(f"  evidence ({len(case['evidence'])}):")
    for ev in case["evidence"]:
        print(f"    [{ev['kind']}] {ev['ref'] or '-'}  {ev['label'] or ''}")
    print(f"  notes ({len(case['notes'])}):")
    for n in case["notes"]:
        print(f"    [{n['created_at']}] {n['author'] or '-'}: {n['body'][:120]}")


def cmd_case_note(args):
    from app.cases.repository import add_note

    with db_cursor() as conn:
        nid = add_note(conn, args.case_id, args.body, author=args.author)
    print(f"Added note #{nid} to case #{args.case_id}")


def cmd_case_attach(args):
    from app.cases.repository import attach_evidence

    if args.match is not None:
        kind, ref, label = "match", f"match:{args.match}", args.label or f"match {args.match}"
    elif args.document is not None:
        kind, ref, label = "document", f"document:{args.document}", args.label or f"document {args.document}"
    elif args.entity is not None:
        if ":" not in args.entity:
            print("--entity must be in format type:value")
            return
        kind, ref, label = "entity", f"entity:{args.entity}", args.label or args.entity
    elif args.enrichment is not None:
        kind, ref, label = "enrichment", f"enrichment:{args.enrichment}", args.label
    elif args.summary is not None:
        kind, ref, label = "summary", f"summary:{args.summary}", args.label or f"summary {args.summary}"
    else:
        kind, ref, label = "text", None, args.label or "note"

    body = args.text if args.text else None
    with db_cursor() as conn:
        eid = attach_evidence(
            conn, args.case_id, kind, ref=ref, label=label, body=body, actor=args.actor
        )
    if eid is None:
        print(f"Already attached to case #{args.case_id} (skipped).")
    else:
        print(f"Attached evidence #{eid} ({kind}) to case #{args.case_id}")


def cmd_case_status(args):
    from app.cases.repository import update_case_status

    with db_cursor() as conn:
        update_case_status(conn, args.case_id, args.to, actor=args.actor)
    print(f"Case #{args.case_id} → {args.to}")


def cmd_case_export(args):
    from app.cases.exporter import export_markdown

    with db_cursor() as conn:
        md = export_markdown(conn, args.case_id)
    if md is None:
        print(f"Case {args.case_id} not found.")
        return
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"Wrote {args.output}")
    else:
        print(md)
