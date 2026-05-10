"""URLhaus (abuse.ch) enrichment for URLs, hosts, and payload hashes.

abuse.ch enforces an Auth-Key header on its public APIs; provider self-skips
if `ABUSECH_AUTH_KEY` is not set.
"""
import requests

from app.config import ABUSECH_AUTH_KEY, HTTP_TIMEOUT, USER_AGENT
from app.enrichment.base import EnrichmentProvider

URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_HOST = "https://urlhaus-api.abuse.ch/v1/host/"
URLHAUS_PAYLOAD = "https://urlhaus-api.abuse.ch/v1/payload/"


class UrlhausProvider(EnrichmentProvider):
    name = "urlhaus"
    supported_types = ("url", "domain", "ip", "md5", "sha256")

    def __init__(self, auth_key: str = ""):
        self.auth_key = auth_key or ABUSECH_AUTH_KEY

    def is_configured(self) -> bool:
        return bool(self.auth_key)

    def _headers(self) -> dict:
        return {
            "User-Agent": USER_AGENT,
            "Auth-Key": self.auth_key,
            "Accept": "application/json",
        }

    def enrich(self, entity_type: str, entity_value: str) -> dict:
        if entity_type == "url":
            url, payload = URLHAUS_URL, {"url": entity_value}
        elif entity_type in ("domain", "ip"):
            url, payload = URLHAUS_HOST, {"host": entity_value}
        elif entity_type in ("md5", "sha256"):
            field = "md5_hash" if entity_type == "md5" else "sha256_hash"
            url, payload = URLHAUS_PAYLOAD, {field: entity_value}
        else:
            raise NotImplementedError(f"{self.name} does not support {entity_type}")

        resp = requests.post(url, data=payload, headers=self._headers(), timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        body = resp.json()
        status = body.get("query_status")
        if status != "ok":
            return {"verdict": "unknown", "query_status": status}

        # Return a small, normalized summary; keep the raw body too.
        summary = {"query_status": "ok"}
        if entity_type == "url":
            summary.update(
                {
                    "verdict": "malicious",
                    "threat": body.get("threat"),
                    "tags": body.get("tags") or [],
                    "url_status": body.get("url_status"),
                    "date_added": body.get("date_added"),
                }
            )
        elif entity_type in ("domain", "ip"):
            summary.update(
                {
                    "verdict": "malicious" if body.get("url_count") else "unknown",
                    "url_count": body.get("url_count"),
                    "blacklists": body.get("blacklists"),
                    "host": body.get("host"),
                }
            )
        else:
            summary.update(
                {
                    "verdict": "malicious",
                    "file_type": body.get("file_type"),
                    "signature": body.get("signature"),
                    "tags": body.get("tags") or [],
                    "first_seen": body.get("firstseen"),
                }
            )
        return summary
