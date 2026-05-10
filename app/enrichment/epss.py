"""FIRST.org EPSS (exploit prediction scoring) enrichment for CVEs.

Public API, no auth.
"""
import requests

from app.config import HTTP_TIMEOUT, USER_AGENT
from app.enrichment.base import EnrichmentProvider

EPSS_URL = "https://api.first.org/data/v1/epss"


class EpssProvider(EnrichmentProvider):
    name = "epss"
    supported_types = ("cve",)

    def enrich(self, entity_type: str, entity_value: str) -> dict:
        if entity_type != "cve":
            raise NotImplementedError(f"{self.name} does not support {entity_type}")
        resp = requests.get(
            EPSS_URL,
            params={"cve": entity_value.upper()},
            headers={"User-Agent": USER_AGENT},
            timeout=HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json().get("data", []) or []
        if not data:
            return {"epss": None, "percentile": None, "date": None}
        row = data[0]
        return {
            "epss": float(row.get("epss")) if row.get("epss") is not None else None,
            "percentile": float(row.get("percentile")) if row.get("percentile") is not None else None,
            "date": row.get("date"),
        }
