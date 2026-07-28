"""Gravatar exposure check.

An email's MD5 hash is a public lookup key for Gravatar. If a Gravatar
exists, the avatar image (and often a public profile with linked social
accounts, location, and display name) is retrievable by anyone who knows
the email. This is a common, quiet source of personal exposure — a good
first thing to know about your own address.

No API key required. Two requests:
  1. HEAD/GET the avatar with `d=404` — a 200 means a Gravatar exists.
  2. GET the `.json` profile — may expose display name, accounts, URLs.
"""
from __future__ import annotations

import hashlib
from typing import List

import requests

from app.config import SCRUB_HTTP_TIMEOUT, USER_AGENT
from app.scrub.base import Finding, ScrubProvider, Target

_AVATAR_URL = "https://www.gravatar.com/avatar/{hash}?d=404"
_PROFILE_URL = "https://www.gravatar.com/{hash}.json"


def _email_hash(email: str) -> str:
    return hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()


class GravatarProvider(ScrubProvider):
    name = "gravatar"
    supported_types = ("email",)

    def scrub(self, target: Target) -> List[Finding]:
        h = _email_hash(target.normalized())
        headers = {"User-Agent": USER_AGENT}

        resp = requests.get(
            _AVATAR_URL.format(hash=h),
            headers=headers,
            timeout=SCRUB_HTTP_TIMEOUT,
            allow_redirects=True,
        )
        if resp.status_code == 404:
            # No Gravatar for this email — that's the "clean" outcome.
            return []
        if resp.status_code != 200:
            resp.raise_for_status()

        findings: List[Finding] = [
            Finding(
                kind="avatar",
                title="Email has a public Gravatar",
                severity="low",
                detail=(
                    "Anyone who knows this email can retrieve its Gravatar "
                    "image via the public MD5 lookup. Consider whether the "
                    "avatar reveals more than you intend."
                ),
                url=f"https://www.gravatar.com/avatar/{h}",
                data={"md5": h},
            )
        ]

        # Best-effort profile fetch. Not all Gravatars have a public profile.
        try:
            pr = requests.get(
                _PROFILE_URL.format(hash=h),
                headers=headers,
                timeout=SCRUB_HTTP_TIMEOUT,
            )
            if pr.status_code == 200 and pr.headers.get("Content-Type", "").startswith("application/json"):
                entry = ((pr.json() or {}).get("entry") or [{}])[0]
                display = entry.get("displayName") or entry.get("preferredUsername")
                accounts = [
                    a.get("url") or a.get("shortname")
                    for a in (entry.get("accounts") or [])
                ]
                urls = [u.get("value") for u in (entry.get("urls") or [])]
                location = entry.get("currentLocation")
                exposed = {
                    "display_name": display,
                    "accounts": [a for a in accounts if a],
                    "urls": [u for u in urls if u],
                    "location": location or None,
                }
                # A public profile with linked accounts is a bigger deal than
                # a bare avatar.
                has_links = bool(exposed["accounts"] or exposed["urls"])
                findings.append(Finding(
                    kind="profile",
                    title="Email has a public Gravatar profile",
                    severity="medium" if has_links else "low",
                    detail=(
                        "The Gravatar profile is public and may reveal a "
                        "display name, location, and linked social accounts."
                    ),
                    url=entry.get("profileUrl") or f"https://www.gravatar.com/{h}",
                    data=exposed,
                ))
        except (requests.RequestException, ValueError):
            # Profile fetch is best-effort; the avatar finding still stands.
            pass

        return findings
