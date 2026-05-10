"""tor-check command — verifies the Tor SOCKS proxy is reachable.

Hits the Tor Project's check service (`https://check.torproject.org/api/ip`)
through the configured SOCKS5h proxy and reports whether the response says
we're running on Tor. Helps an operator diagnose "I added an onion source
but nothing collected" by isolating Tor connectivity from collector logic.
"""
import sys


def register(sub):
    pt = sub.add_parser(
        "tor-check",
        help="Smoke-test Tor connectivity (uses TOR_SOCKS_HOST / TOR_SOCKS_PORT).",
    )
    pt.add_argument(
        "--url",
        default="https://check.torproject.org/api/ip",
        help="Override the URL hit through the Tor proxy. Default: torproject's check service.",
    )
    pt.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Per-request timeout in seconds (default 30).",
    )
    pt.set_defaults(func=cmd_tor_check)


def cmd_tor_check(args):
    from app.collectors.onion_collector import build_tor_session
    from app.config import TOR_SOCKS_HOST, TOR_SOCKS_PORT

    print(f"Connecting via socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT} ...")
    try:
        session = build_tor_session()
        resp = session.get(args.url, timeout=args.timeout)
        resp.raise_for_status()
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL: {exc}")
        print(
            "Hint: make sure a Tor daemon is running and listening on the "
            "configured SOCKS port. On Linux: `sudo systemctl start tor`. "
            "Via Docker: `docker compose --profile tor up -d`."
        )
        sys.exit(1)

    body = resp.text.strip()
    print(f"HTTP {resp.status_code}")
    print(body[:400])
    # The torproject check endpoint returns JSON like {"IsTor": true, "IP": "..."}.
    if "IsTor" in body and "true" in body.lower():
        print("OK: traffic is routed through Tor.")
    else:
        print(
            "WARNING: response does not look like a Tor exit. Double-check "
            "that the SOCKS proxy you're pointed at is actually a Tor proxy."
        )
