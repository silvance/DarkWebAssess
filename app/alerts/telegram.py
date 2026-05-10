import logging
from typing import Optional

import requests

from app.config import HTTP_TIMEOUT, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID

log = logging.getLogger(__name__)


def is_configured() -> bool:
    return bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)


def format_alert_message(match: dict, document: dict) -> str:
    severity = match.get("severity", "medium").upper()
    score = match.get("score")
    reasons = match.get("reasons") or []
    score_line = f"Score: {score}\n" if score is not None else ""
    reasons_block = ""
    if reasons:
        bullet = "\n".join(f"  - {r}" for r in reasons[:6])
        reasons_block = f"\nWhy:\n{bullet}\n"
    return (
        f"\U0001F6A8 New Threat Intel Match — {severity}\n\n"
        f"Matched: {match.get('matched_value')}\n"
        f"Type: {match.get('match_type')}\n"
        f"{score_line}"
        f"Source: {document.get('source_name')}\n"
        f"Title: {document.get('title') or '(no title)'}\n"
        f"URL: {document.get('source_url')}\n"
        f"Collected: {document.get('retrieved_at')}\n"
        f"{reasons_block}\n"
        f"Context: {match.get('context') or '(no context)'}"
    )


def send_telegram(text: str) -> tuple[bool, Optional[str]]:
    if not is_configured():
        return False, "telegram not configured"
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        resp = requests.post(
            url,
            json={"chat_id": TELEGRAM_CHAT_ID, "text": text, "disable_web_page_preview": True},
            timeout=HTTP_TIMEOUT,
        )
        if resp.status_code != 200:
            return False, f"http {resp.status_code}: {resp.text[:200]}"
        return True, None
    except requests.RequestException as exc:
        return False, str(exc)
