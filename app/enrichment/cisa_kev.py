"""CISA Known Exploited Vulnerabilities catalog enrichment.

Downloads the public catalog once, caches it on disk, and looks up CVE IDs.
No authentication required.
"""
import json
import time
from pathlib import Path
from typing import Optional

import requests

from app.config import DATA_DIR, HTTP_TIMEOUT, USER_AGENT
from app.enrichment.base import EnrichmentProvider

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_CACHE = Path(DATA_DIR) / "cisa_kev.json"
DEFAULT_MAX_AGE_SECONDS = 24 * 3600


class CisaKevProvider(EnrichmentProvider):
    name = "cisa_kev"
    supported_types = ("cve",)

    def __init__(self, cache_path: Optional[Path] = None, max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS):
        self.cache_path = Path(cache_path) if cache_path else DEFAULT_CACHE
        self.max_age_seconds = max_age_seconds
        self._index: Optional[dict] = None

    def _load_catalog(self) -> dict:
        if self.cache_path.exists():
            age = time.time() - self.cache_path.stat().st_mtime
            if age < self.max_age_seconds:
                return json.loads(self.cache_path.read_text(encoding="utf-8"))
        resp = requests.get(KEV_URL, headers={"User-Agent": USER_AGENT}, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(resp.text, encoding="utf-8")
        return resp.json()

    def _index_catalog(self) -> dict:
        if self._index is not None:
            return self._index
        cat = self._load_catalog()
        self._index = {
            v.get("cveID", "").upper(): v for v in cat.get("vulnerabilities", []) if v.get("cveID")
        }
        return self._index

    def enrich(self, entity_type: str, entity_value: str) -> dict:
        if entity_type != "cve":
            raise NotImplementedError(f"{self.name} does not support {entity_type}")
        index = self._index_catalog()
        v = index.get(entity_value.upper())
        if not v:
            return {"in_kev": False}
        return {
            "in_kev": True,
            "vendor_project": v.get("vendorProject"),
            "product": v.get("product"),
            "vulnerability_name": v.get("vulnerabilityName"),
            "date_added": v.get("dateAdded"),
            "due_date": v.get("dueDate"),
            "known_ransomware_use": v.get("knownRansomwareCampaignUse"),
            "short_description": v.get("shortDescription"),
        }
