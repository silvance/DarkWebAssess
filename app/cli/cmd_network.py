"""`network-check` subcommand — verify the egress IP before letting the
tool make outbound requests.

Exit codes:
  0  egress IP is inside the configured allowlist (or no allowlist set)
  1  egress IP is OUTSIDE the allowlist
  2  egress lookup itself failed (network down, blocked, etc.)
"""
from __future__ import annotations

import sys


def register(sub) -> None:
    p = sub.add_parser(
        "network-check",
        help="Verify the egress IP against EXPECTED_EGRESS_PREFIXES.",
    )
    p.add_argument(
        "--prefixes",
        default=None,
        help="Override EXPECTED_EGRESS_PREFIXES (comma-separated CIDRs).",
    )
    p.add_argument(
        "--url",
        default=None,
        help="Override the IP-echo URL (default $EGRESS_CHECK_URL or api.ipify.org).",
    )
    p.set_defaults(func=_run)


def _run(args) -> None:
    from app.network.egress import check_egress

    result = check_egress(expected_prefixes=args.prefixes, url=args.url)
    if result.ip is None:
        print(f"[network-check] FAILED: {result.reason}", file=sys.stderr)
        sys.exit(2)
    print(f"[network-check] egress IP: {result.ip}")
    if result.expected_prefixes:
        print(f"[network-check] allowlist:  {', '.join(result.expected_prefixes)}")
    else:
        print("[network-check] allowlist:  (none configured)")
    print(f"[network-check] result:     {result.reason}")
    if not result.ok:
        sys.exit(1)
