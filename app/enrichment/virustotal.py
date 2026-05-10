"""VirusTotal v3 enrichment.

Supports domain, IP, file hash, and URL lookups. Requires an API key
(`VIRUSTOTAL_API_KEY`); provider self-skips otherwise. Returns the
`last_analysis_stats` summary plus reputation.
"""
import base64
from typing import Optional

import requests

from app.config import HTTP_TIMEOUT, USER_AGENT, VIRUSTOTAL_API_KEY
from app.enrichment.base import EnrichmentProvider

VT_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalProvider(EnrichmentProvider):
    name = "virustotal"
    supported_types = ("domain", "ip", "md5", "sha1", "sha256", "url")

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key if api_key is not None else VIRUSTOTAL_API_KEY

    def is_configured(self) -> bool:
        return bool(self.api_key)

    @staticmethod
    def _path(entity_type: str, entity_value: str) -> str:
        if entity_type == "domain":
            return f"/domains/{entity_value}"
        if entity_type == "ip":
            return f"/ip_addresses/{entity_value}"
        if entity_type in ("md5", "sha1", "sha256"):
            return f"/files/{entity_value}"
        if entity_type == "url":
            url_id = base64.urlsafe_b64encode(entity_value.encode("utf-8")).rstrip(b"=").decode()
            return f"/urls/{url_id}"
        raise NotImplementedError(entity_type)

    def enrich(self, entity_type: str, entity_value: str) -> dict:
        path = self._path(entity_type, entity_value)
        resp = requests.get(
            f"{VT_BASE}{path}",
            headers={"x-apikey": self.api_key, "User-Agent": USER_AGENT},
            timeout=HTTP_TIMEOUT,
        )
        if resp.status_code == 404:
            return {"verdict": "unknown", "found": False}
        resp.raise_for_status()
        attrs = (resp.json().get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        return {
            "found": True,
            "verdict": "malicious" if malicious > 0 else ("suspicious" if suspicious > 0 else "clean"),
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": int(stats.get("harmless") or 0),
            "undetected": int(stats.get("undetected") or 0),
            "reputation": attrs.get("reputation"),
            "last_analysis_date": attrs.get("last_analysis_date"),
        }
