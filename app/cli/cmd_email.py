"""`email-test` — verify SMTP delivery configuration.

Sends a short test message to SMTP_TO so you can confirm host / auth / TLS
are right before relying on report delivery.
"""
from __future__ import annotations

import sys


def register(sub) -> None:
    p = sub.add_parser("email-test", help="Send a test email to verify SMTP config.")
    p.add_argument("--to", help="Override recipient(s) (comma-separated).")
    p.set_defaults(func=_run)


def _run(args) -> None:
    from app.delivery.email import is_configured, send_email, unconfigured_reason

    if not is_configured() and not args.to:
        print(f"[email] not configured: {unconfigured_reason()}", file=sys.stderr)
        print("[email] set SMTP_HOST / SMTP_FROM / SMTP_TO (see .env.example).",
              file=sys.stderr)
        sys.exit(2)

    ok, err = send_email(
        "DarkWebAssess test email",
        "This is a test message from `dwa email-test`. SMTP delivery works.",
        to=args.to,
    )
    if ok:
        print("[email] OK — test message sent.")
    else:
        print(f"[email] FAILED — {err}", file=sys.stderr)
        sys.exit(1)
