"""alert-test command."""
import sys

from app.alerts.telegram import is_configured, send_telegram


def register(sub):
    sub.add_parser("alert-test", help="Send a test Telegram alert.").set_defaults(
        func=cmd_alert_test
    )


def cmd_alert_test(_args):
    if not is_configured():
        print("Telegram not configured. Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID.")
        sys.exit(1)
    ok, err = send_telegram("Test alert from mini-threat-intel.")
    print("OK" if ok else f"FAILED: {err}")
