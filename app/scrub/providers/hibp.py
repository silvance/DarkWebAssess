"""Have I Been Pwned breach check.

Queries the HIBP breach API for an email and turns each breach into a
finding. Breaches that exposed passwords (or are flagged sensitive) are
raised to high severity — those are the ones that actually put you at
credential-stuffing risk.

Requires a paid HIBP API key (`HIBP_API_KEY`). Self-skips when unset so
users without a key still get the other scrub providers.

Ref: https://haveibeenpwned.com/API/v3
"""
from __future__ import annotations

from typing import List, Optional

import requests

from app.config import HIBP_API_KEY, SCRUB_HTTP_TIMEOUT, USER_AGENT
from app.scrub.base import Finding, ScrubProvider, Target

_BREACH_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"

# Data classes that indicate credential exposure → high severity.
_CREDENTIAL_CLASSES = {
    "Passwords", "Password hints", "Security questions and answers",
    "Auth tokens", "Partial credit card data", "Bank account numbers",
}


class HibpProvider(ScrubProvider):
    name = "hibp"
    supported_types = ("email",)

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key if api_key is not None else HIBP_API_KEY

    def is_available(self) -> bool:
        return bool(self.api_key)

    def unavailable_reason(self) -> str:
        return "HIBP_API_KEY not set (paid key required)"

    def scrub(self, target: Target) -> List[Finding]:
        resp = requests.get(
            _BREACH_URL.format(account=target.normalized()),
            params={"truncateResponse": "false"},
            headers={
                "hibp-api-key": self.api_key,
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
            },
            timeout=SCRUB_HTTP_TIMEOUT,
        )
        # 404 = not found in any breach (the good outcome).
        if resp.status_code == 404:
            return []
        resp.raise_for_status()

        breaches = resp.json() or []
        findings: List[Finding] = []
        for b in breaches:
            data_classes = b.get("DataClasses") or []
            exposed_creds = bool(set(data_classes) & _CREDENTIAL_CLASSES)
            sensitive = bool(b.get("IsSensitive"))
            if exposed_creds or sensitive:
                severity = "high"
            elif data_classes:
                severity = "medium"
            else:
                severity = "low"
            name = b.get("Name") or "Unknown"
            findings.append(Finding(
                kind="breach",
                title=f"Found in breach: {b.get('Title') or name}",
                severity=severity,
                detail=(
                    f"Breach date {b.get('BreachDate') or '?'}. "
                    f"Exposed: {', '.join(data_classes) or 'unknown'}."
                    + (" Flagged sensitive." if sensitive else "")
                ),
                url=f"https://haveibeenpwned.com/breach/{name}",
                data={
                    "name": name,
                    "breach_date": b.get("BreachDate"),
                    "pwn_count": b.get("PwnCount"),
                    "data_classes": data_classes,
                    "is_sensitive": sensitive,
                    "is_verified": b.get("IsVerified"),
                },
            ))
        return findings
