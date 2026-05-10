import json
from pathlib import Path

import pytest

from app.enrichment.abuseipdb import AbuseIpdbProvider
from app.enrichment.cisa_kev import CisaKevProvider
from app.enrichment.epss import EpssProvider
from app.enrichment.malware_bazaar import MalwareBazaarProvider
from app.enrichment.urlhaus import UrlhausProvider
from app.enrichment.virustotal import VirusTotalProvider


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=None):
        self.status_code = status_code
        self._payload = payload
        self.text = text if text is not None else json.dumps(payload or {})

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


# --- CISA KEV --------------------------------------------------------------
def test_cisa_kev_hit_with_disk_cache(tmp_path: Path, monkeypatch):
    cache = tmp_path / "kev.json"
    cache.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2024-3400",
                        "vendorProject": "Palo Alto",
                        "product": "PAN-OS",
                        "vulnerabilityName": "GlobalProtect command injection",
                        "dateAdded": "2024-04-12",
                        "dueDate": "2024-04-19",
                        "knownRansomwareCampaignUse": "Unknown",
                        "shortDescription": "Test",
                    }
                ]
            }
        )
    )
    p = CisaKevProvider(cache_path=cache, max_age_seconds=10_000)
    out = p.enrich("cve", "cve-2024-3400")
    assert out["in_kev"] is True
    assert out["product"] == "PAN-OS"


def test_cisa_kev_miss(tmp_path: Path):
    cache = tmp_path / "kev.json"
    cache.write_text(json.dumps({"vulnerabilities": []}))
    p = CisaKevProvider(cache_path=cache, max_age_seconds=10_000)
    assert p.enrich("cve", "CVE-1999-9999") == {"in_kev": False}


# --- EPSS ------------------------------------------------------------------
def test_epss_hit(monkeypatch):
    p = EpssProvider()

    def fake_get(url, params=None, headers=None, timeout=None):
        assert "first.org" in url
        assert params["cve"] == "CVE-2024-3400"
        return FakeResponse(
            payload={
                "data": [
                    {"cve": "CVE-2024-3400", "epss": "0.97", "percentile": "0.99", "date": "2024-05-01"}
                ]
            }
        )

    monkeypatch.setattr("app.enrichment.epss.requests.get", fake_get)
    out = p.enrich("cve", "CVE-2024-3400")
    assert out == {"epss": 0.97, "percentile": 0.99, "date": "2024-05-01"}


def test_epss_no_data(monkeypatch):
    p = EpssProvider()
    monkeypatch.setattr(
        "app.enrichment.epss.requests.get",
        lambda *a, **k: FakeResponse(payload={"data": []}),
    )
    out = p.enrich("cve", "CVE-1999-9999")
    assert out == {"epss": None, "percentile": None, "date": None}


# --- URLhaus ---------------------------------------------------------------
def test_urlhaus_skipped_without_key():
    assert UrlhausProvider(auth_key="").is_configured() is False


def test_urlhaus_url_hit(monkeypatch):
    p = UrlhausProvider(auth_key="dummy")

    def fake_post(url, data=None, headers=None, timeout=None):
        assert headers["Auth-Key"] == "dummy"
        assert "url" in data
        return FakeResponse(
            payload={
                "query_status": "ok",
                "threat": "malware_download",
                "tags": ["loader"],
                "url_status": "online",
                "date_added": "2026-05-09",
            }
        )

    monkeypatch.setattr("app.enrichment.urlhaus.requests.post", fake_post)
    out = p.enrich("url", "https://evil.example.com/x")
    assert out["verdict"] == "malicious"
    assert "loader" in out["tags"]


def test_urlhaus_host_unknown(monkeypatch):
    p = UrlhausProvider(auth_key="dummy")
    monkeypatch.setattr(
        "app.enrichment.urlhaus.requests.post",
        lambda *a, **k: FakeResponse(payload={"query_status": "no_results"}),
    )
    out = p.enrich("domain", "example.com")
    assert out["verdict"] == "unknown"


# --- MalwareBazaar ---------------------------------------------------------
def test_malware_bazaar_skipped_without_key():
    assert MalwareBazaarProvider(auth_key="").is_configured() is False


def test_malware_bazaar_hit(monkeypatch):
    p = MalwareBazaarProvider(auth_key="dummy")

    def fake_post(url, data=None, headers=None, timeout=None):
        return FakeResponse(
            payload={
                "query_status": "ok",
                "data": [
                    {
                        "signature": "Emotet",
                        "file_type": "exe",
                        "tags": ["emotet", "loader"],
                        "first_seen": "2026-05-01",
                        "reporter": "abuse.ch",
                    }
                ],
            }
        )

    monkeypatch.setattr("app.enrichment.malware_bazaar.requests.post", fake_post)
    out = p.enrich("sha256", "a" * 64)
    assert out["verdict"] == "malicious"
    assert out["signature"] == "Emotet"


# --- VirusTotal ------------------------------------------------------------
def test_virustotal_skipped_without_key():
    assert VirusTotalProvider(api_key="").is_configured() is False


def test_virustotal_domain(monkeypatch):
    p = VirusTotalProvider(api_key="dummy")

    def fake_get(url, headers=None, timeout=None):
        assert "/domains/example.com" in url
        assert headers["x-apikey"] == "dummy"
        return FakeResponse(
            payload={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 3, "suspicious": 1, "harmless": 50, "undetected": 10},
                        "reputation": -5,
                        "last_analysis_date": 1715200000,
                    }
                }
            }
        )

    monkeypatch.setattr("app.enrichment.virustotal.requests.get", fake_get)
    out = p.enrich("domain", "example.com")
    assert out["verdict"] == "malicious"
    assert out["malicious"] == 3


def test_virustotal_404(monkeypatch):
    p = VirusTotalProvider(api_key="dummy")
    monkeypatch.setattr(
        "app.enrichment.virustotal.requests.get",
        lambda *a, **k: FakeResponse(status_code=404, payload={}),
    )
    assert p.enrich("ip", "1.2.3.4") == {"verdict": "unknown", "found": False}


# --- AbuseIPDB -------------------------------------------------------------
def test_abuseipdb_skipped_without_key():
    assert AbuseIpdbProvider(api_key="").is_configured() is False


def test_abuseipdb_score_bands(monkeypatch):
    p = AbuseIpdbProvider(api_key="dummy")
    captured = {}

    def fake_get(url, params=None, headers=None, timeout=None):
        captured["headers"] = headers
        return FakeResponse(
            payload={
                "data": {
                    "abuseConfidenceScore": 80,
                    "countryCode": "RU",
                    "isp": "ExampleISP",
                    "domain": "example.com",
                    "totalReports": 42,
                    "lastReportedAt": "2026-05-09T12:00:00+00:00",
                    "isTor": False,
                    "usageType": "Data Center",
                }
            }
        )

    monkeypatch.setattr("app.enrichment.abuseipdb.requests.get", fake_get)
    out = p.enrich("ip", "1.2.3.4")
    assert out["abuse_confidence"] == 80
    assert out["verdict"] == "malicious"
    assert captured["headers"]["Key"] == "dummy"
