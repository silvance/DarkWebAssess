"""Report management commands."""
from app.database import db_cursor


def register(sub):
    pr = sub.add_parser("report", help="Generate and manage reports.")
    rs = pr.add_subparsers(dest="report_command", required=True)

    rl = rs.add_parser("list", help="List available templates and saved reports.")
    rl.add_argument("--saved", action="store_true",
                    help="List saved reports instead of templates.")
    rl.add_argument("--name", help="Filter saved reports by template name.")
    rl.add_argument("--limit", type=int, default=20)
    rl.set_defaults(func=cmd_report_list)

    rg = rs.add_parser("generate", help="Generate a report by template name.")
    rg.add_argument("name", help="Template name (run `report list` to see options).")
    rg.add_argument("--window", help="Window override, e.g. 24h, 7d, 30d.")
    rg.add_argument("--format", default="md", choices=["md", "markdown", "html", "json"])
    rg.add_argument("--output", help="Write to this path (otherwise stdout).")
    rg.add_argument("--save", action="store_true", help="Persist the report to the DB.")
    rg.set_defaults(func=cmd_report_generate)

    rsh = rs.add_parser("show", help="Print a saved report.")
    rsh.add_argument("report_id", type=int)
    rsh.add_argument("--format", default="md", choices=["md", "markdown", "html", "json"])
    rsh.add_argument("--output", help="Write to this path (otherwise stdout).")
    rsh.set_defaults(func=cmd_report_show)


def cmd_report_list(args):
    from app.reports.runner import list_saved, list_templates

    if args.saved:
        with db_cursor() as conn:
            rows = list_saved(conn, name=args.name, limit=args.limit)
        if not rows:
            print("No saved reports.")
            return
        for r in rows:
            print(f"#{r['id']:<4} {r['name']:<22} {r['generated_at']}  {r['title'] or ''}")
        return

    print("Available report templates:")
    for name, doc in list_templates():
        print(f"  {name:<22} {doc}")


def cmd_report_generate(args):
    from app.reports.renderers import render
    from app.reports.runner import generate_report, save_report

    with db_cursor() as conn:
        try:
            report = generate_report(conn, args.name, window=args.window)
        except KeyError as exc:
            print(exc)
            return
        if args.save:
            rid = save_report(conn, report)
            print(f"Saved report #{rid}")
        rendered = render(report, args.format)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(rendered)
        print(f"Wrote {args.output}")
    else:
        print(rendered)


def cmd_report_show(args):
    from app.reports.runner import get_saved

    with db_cursor() as conn:
        row = get_saved(conn, args.report_id)
    if not row:
        print(f"Report #{args.report_id} not found.")
        return
    fmt = args.format.lower()
    body = (
        row["body_markdown"] if fmt in ("md", "markdown")
        else row["body_html"] if fmt == "html"
        else row["body_json"]
    )
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(body)
        print(f"Wrote {args.output}")
    else:
        print(body)
