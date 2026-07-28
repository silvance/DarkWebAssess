"""`scrub` — check what's publicly exposed about an identifier you control.

Self-monitoring, not targeting: this is the OSINT-hygiene equivalent of
pulling your own credit report. Point it at your own email / username /
domain and it runs the available scrub providers (local cross-reference,
Gravatar, Have I Been Pwned, …) and prints a consolidated exposure report.

Examples:
    dwa scrub you@example.com
    dwa scrub yourhandle --type username
    dwa scrub yourcompany.example --format md --output exposure.md
"""
from __future__ import annotations

import sys


def register(sub) -> None:
    p = sub.add_parser(
        "scrub",
        help="Self-monitoring exposure check for an email / username / domain.",
    )
    p.add_argument("target", help="The identifier to check (yours).")
    p.add_argument(
        "--type", choices=["auto", "email", "username", "domain"], default="auto",
        help="Target type (default: auto-detect).",
    )
    p.add_argument(
        "--format", choices=["text", "md", "json"], default="text",
        help="Report format (default: text).",
    )
    p.add_argument("--output", help="Write the report to this file instead of stdout.")
    p.add_argument(
        "--no-save", action="store_true",
        help="Don't persist the run to the database.",
    )
    p.set_defaults(func=_run)


def _run(args) -> None:
    from app.database import get_connection
    from app.scrub.base import Target
    from app.scrub.report import render_json, render_markdown, render_text
    from app.scrub.runner import detect_type, run_scrub

    ttype = detect_type(args.target) if args.type == "auto" else args.type
    target = Target(type=ttype, value=args.target)

    with get_connection() as conn:
        report = run_scrub(conn, target, persist=not args.no_save)

    if args.format == "md":
        text = render_markdown(report)
    elif args.format == "json":
        text = render_json(report)
    else:
        text = render_text(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print(f"[scrub] wrote report to {args.output}", file=sys.stderr)
    else:
        print(text)

    # Exit non-zero when high-severity exposure is found, so the command is
    # scriptable (`dwa scrub me@x.co || alert-someone`).
    if report.highest_severity == "high":
        sys.exit(1)
