"""SMTP email delivery — stdlib only (no new dependencies).

Sends reports / digests to a configured recipient list. Mirrors the
Telegram alert module's shape: `is_configured()` + a `send_email(...)`
that returns `(ok, error)` and never raises on a delivery failure.

Config (all env, all optional):
  SMTP_HOST / SMTP_PORT (587) / SMTP_USER / SMTP_PASSWORD
  SMTP_FROM / SMTP_TO (comma-separated)
  SMTP_USE_TLS (1 = STARTTLS, default) / SMTP_USE_SSL (0 = implicit TLS)
  SMTP_TIMEOUT (30)
"""
from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from typing import List, Optional, Tuple

from app import config

log = logging.getLogger(__name__)


def _recipients(to: Optional[str] = None) -> List[str]:
    raw = to if to is not None else config.SMTP_TO
    return [addr.strip() for addr in (raw or "").split(",") if addr.strip()]


def is_configured() -> bool:
    """True when host, from, and at least one recipient are set."""
    return bool(config.SMTP_HOST and config.SMTP_FROM and _recipients())


def unconfigured_reason() -> str:
    missing = []
    if not config.SMTP_HOST:
        missing.append("SMTP_HOST")
    if not config.SMTP_FROM:
        missing.append("SMTP_FROM")
    if not _recipients():
        missing.append("SMTP_TO")
    return "missing " + ", ".join(missing) if missing else "configured"


def build_message(
    subject: str,
    body_text: str,
    *,
    body_html: Optional[str] = None,
    to: Optional[List[str]] = None,
) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = config.SMTP_FROM
    msg["To"] = ", ".join(to if to is not None else _recipients())
    msg.set_content(body_text)
    if body_html:
        msg.add_alternative(body_html, subtype="html")
    return msg


def send_email(
    subject: str,
    body_text: str,
    *,
    body_html: Optional[str] = None,
    to: Optional[str] = None,
) -> Tuple[bool, Optional[str]]:
    """Send an email. Returns (ok, error). Never raises."""
    if not config.SMTP_HOST or not config.SMTP_FROM:
        return False, "smtp not configured (" + unconfigured_reason() + ")"
    recipients = _recipients(to)
    if not recipients:
        return False, "no recipients (set SMTP_TO or pass --to)"

    msg = build_message(subject, body_text, body_html=body_html, to=recipients)

    try:
        if config.SMTP_USE_SSL:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(
                config.SMTP_HOST, config.SMTP_PORT,
                timeout=config.SMTP_TIMEOUT, context=context,
            ) as server:
                _auth_and_send(server, msg, recipients)
        else:
            with smtplib.SMTP(
                config.SMTP_HOST, config.SMTP_PORT, timeout=config.SMTP_TIMEOUT,
            ) as server:
                if config.SMTP_USE_TLS:
                    server.starttls(context=ssl.create_default_context())
                _auth_and_send(server, msg, recipients)
        return True, None
    except Exception as exc:  # noqa: BLE001
        log.warning("email send failed: %s", exc)
        return False, f"{exc.__class__.__name__}: {exc}"


def _auth_and_send(server: smtplib.SMTP, msg: EmailMessage, recipients: List[str]) -> None:
    if config.SMTP_USER:
        server.login(config.SMTP_USER, config.SMTP_PASSWORD)
    server.send_message(msg, from_addr=config.SMTP_FROM, to_addrs=recipients)
