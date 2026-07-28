"""Native username enumeration (Sherlock-style).

Given a username you control, check a curated list of sites to see where a
public profile with that handle exists. The site definitions ship bundled
with the release (`app/scrub/data/username_sites.json`), so this works out
of the box with no external tools and no API keys.

Detection is best-effort and honest about uncertainty:
  - status_code : present on 200, absent on the site's absent status
                  (default 404), otherwise UNKNOWN.
  - message     : on 200, absent when a known "not found" string appears in
                  the body, else present; non-200 -> UNKNOWN.

A site that rate-limits, blocks, or errors is reported as UNKNOWN — never a
false "absent". Each confirmed profile becomes one low-severity finding;
the value is the aggregate map of where your handle is exposed.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import List, Optional

import requests

from app.config import (
    SCRUB_HTTP_TIMEOUT,
    SCRUB_REQUEST_DELAY,
    SCRUB_USER_AGENT,
    SCRUB_USERNAME_MAX_SITES,
    SCRUB_USERNAME_SITES_PATH,
)
from app.scrub.base import Finding, ScrubProvider, Target

log = logging.getLogger(__name__)

# Bundled site list lives next to this package's data dir. Path(__file__)
# resolves correctly under PyInstaller's _MEIPASS because the spec bundles
# the JSON to app/scrub/data/.
_BUNDLED_SITES = Path(__file__).resolve().parent.parent / "data" / "username_sites.json"


def load_sites(path: Optional[str] = None) -> List[dict]:
    """Load the site definitions. Operator override via
    SCRUB_USERNAME_SITES_PATH (or the `path` arg) falls back to bundled."""
    src = path or SCRUB_USERNAME_SITES_PATH or str(_BUNDLED_SITES)
    with open(src, "r", encoding="utf-8") as f:
        data = json.load(f)
    return [s for s in (data.get("sites") or []) if s.get("url") and s.get("name")]


def check_site(
    site: dict,
    username: str,
    *,
    session: Optional[requests.Session] = None,
    timeout: Optional[int] = None,
) -> str:
    """Return 'present', 'absent', or 'unknown' for one site.

    Never raises — a network/parse failure maps to 'unknown'.
    """
    timeout = timeout or SCRUB_HTTP_TIMEOUT
    getter = session.get if session is not None else requests.get
    url = site["url"].format(username=username)
    try:
        resp = getter(
            url,
            headers={"User-Agent": SCRUB_USER_AGENT, "Accept": "*/*"},
            timeout=timeout,
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        log.debug("username check %s errored: %s", site["name"], exc)
        return "unknown"

    detect = site.get("detect", "status_code")
    if detect == "status_code":
        absent_status = int(site.get("absent_status", 404))
        if resp.status_code == 200:
            return "present"
        if resp.status_code == absent_status:
            return "absent"
        return "unknown"
    if detect == "message":
        if resp.status_code != 200:
            # Some sites 404 for absent even in message mode.
            if resp.status_code == int(site.get("absent_status", 404)):
                return "absent"
            return "unknown"
        absent_text = site.get("absent_text") or ""
        if absent_text and absent_text in resp.text:
            return "absent"
        return "present"
    return "unknown"


class UsernameEnumProvider(ScrubProvider):
    name = "username_enum"
    supported_types = ("username",)

    def __init__(
        self,
        sites: Optional[List[dict]] = None,
        *,
        delay: Optional[float] = None,
        max_sites: Optional[int] = None,
    ):
        self._sites = sites
        self.delay = SCRUB_REQUEST_DELAY if delay is None else delay
        self.max_sites = SCRUB_USERNAME_MAX_SITES if max_sites is None else max_sites

    def _load(self) -> List[dict]:
        if self._sites is not None:
            return self._sites
        try:
            return load_sites()
        except (OSError, ValueError) as exc:
            log.warning("username_enum: could not load site list: %s", exc)
            return []

    def scrub(self, target: Target) -> List[Finding]:
        username = target.normalized()
        sites = self._load()
        if self.max_sites and self.max_sites > 0:
            sites = sites[: self.max_sites]

        session = requests.Session()
        findings: List[Finding] = []
        checked = 0
        unknown = 0
        for i, site in enumerate(sites):
            if self.delay and i > 0:
                time.sleep(self.delay)
            result = check_site(site, username, session=session)
            checked += 1
            if result == "present":
                url = site["url"].format(username=username)
                findings.append(Finding(
                    kind="account",
                    title=f"Public profile on {site['name']}",
                    severity="low",
                    detail=(
                        f"A profile with the handle '{username}' exists on "
                        f"{site['name']} ({site.get('category', 'site')})."
                    ),
                    url=url,
                    data={"site": site["name"], "category": site.get("category")},
                ))
            elif result == "unknown":
                unknown += 1

        # A summary finding so the operator knows the coverage (how many
        # sites checked, how many were inconclusive). Info severity.
        findings.append(Finding(
            kind="summary",
            title=(
                f"Checked {checked} site(s): "
                f"{len([f for f in findings if f.kind == 'account'])} profile(s) found, "
                f"{unknown} inconclusive"
            ),
            severity="info",
            detail=(
                "Inconclusive sites rate-limited, blocked, or returned an "
                "unexpected status — treat them as 'unknown', not 'clear'."
            ) if unknown else None,
            data={"checked": checked, "unknown": unknown},
        ))
        return findings
