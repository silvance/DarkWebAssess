"""`export` — export watchlist-match indicators for other TI tools.

Formats:
  csv   — flat table, every indicator type, opens in any spreadsheet
  stix  — STIX 2.1 bundle (Indicator / Vulnerability / Malware / ThreatActor)
  misp  — MISP Event JSON, importable via "Import from MISP JSON"

Examples:
    dwa export --format csv --since 7d --output iocs.csv
    dwa export --format stix --min-severity high
    dwa export --format misp --output event.json
"""
from __future__ import annotations

import sys


def register(sub) -> None:
    p = sub.add_parser(
        "export",
        help="Export match indicators as CSV / STIX 2.1 / MISP JSON.",
    )
    p.add_argument("--format", choices=["csv", "stix", "misp"], default="csv")
    p.add_argument("--since", help="Only matches newer than this (e.g. 7d, 24h, 30m).")
    p.add_argument(
        "--min-severity", choices=["low", "medium", "high", "critical"],
        help="Only indicators at or above this severity.",
    )
    p.add_argument("--limit", type=int, default=5000, help="Max indicators (default 5000).")
    p.add_argument("--output", help="Write to this file instead of stdout.")
    p.add_argument("--info", default="", help="MISP event title (misp format only).")
    p.set_defaults(func=_run)


def _run(args) -> None:
    from app.database import get_connection
    from app.export.csv_export import render_csv
    from app.export.misp_export import build_event, render_misp
    from app.export.query import fetch_indicators
    from app.export.stix_export import build_bundle, render_stix

    with get_connection() as conn:
        try:
            indicators = fetch_indicators(
                conn, since=args.since, min_severity=args.min_severity,
                limit=args.limit,
            )
        except ValueError as exc:
            print(f"[export] {exc}", file=sys.stderr)
            sys.exit(2)

    skipped = 0
    if args.format == "csv":
        text = render_csv(indicators)
    elif args.format == "stix":
        _bundle, skipped = build_bundle(indicators)
        text = render_stix(indicators)
    else:  # misp
        _event, skipped = build_event(indicators, info=args.info)
        text = render_misp(indicators, info=args.info)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text if text.endswith("\n") else text + "\n")
        dest = args.output
    else:
        print(text)
        dest = "stdout"

    note = f"[export] {len(indicators)} indicator(s) → {args.format} → {dest}"
    if skipped:
        note += f" ({skipped} skipped: no {args.format} mapping)"
    print(note, file=sys.stderr)
