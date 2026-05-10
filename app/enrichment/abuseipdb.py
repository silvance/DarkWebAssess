"""AbuseIPDB IP reputation enrichment."""
from typing import Optional

import requests

from app.config import ABUSEIPDB_API_KEY, HTTP_TIMEOUT, USER_AGENT
from app.enrichment.base import EnrichmentProvider

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIpdbProvider(EnrichmentProvider):
    name = "abuseipdb"
    supported_types = ("ip",)

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key if api_key is not None else ABUSEIPDB_API_KEY

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def enrich(self, entity_type: str, entity_value: str) -> dict:
        if entity_type != "ip":
            raise NotImplementedError(f"{self.name} does not support {entity_type}")
        resp = requests.get(
            ABUSEIPDB_URL,
            params={"ipAddress": entity_value, "maxAgeInDays": 90, "verbose": ""},
            headers={
                "Key": self.api_key,
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            },
            timeout=HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        data = (resp.json() or {}).get("data") or {}
        score = int(data.get("abuseConfidenceScore") or 0)
        return {
            "abuse_confidence": score,
            "verdict": "malicious" if score >= 75 else ("suspicious" if score >= 25 else "clean"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "total_reports": data.get("totalReports"),
            "last_reported_at": data.get("lastReportedAt"),
            "is_tor": data.get("isTor"),
            "usage_type": data.get("usageType"),
        }
