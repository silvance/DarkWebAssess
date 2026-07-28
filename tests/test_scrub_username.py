"""Tests for native username enumeration (Sherlock-style).

All network is mocked. We assert detection semantics (present / absent /
unknown), the never-a-false-absent property, the bundled site list loads,
and the provider aggregates findings + a coverage summary.
"""
from __future__ import annotations

import json

import pytest

from app.scrub.base import Target
from app.scrub.providers import username_enum as ue
from app.scrub.providers.username_enum import (
    UsernameEnumProvider,
    check_site,
    load_sites,
)


class _Resp:
    def __init__(self, status=200, text=""):
        self.status_code = status
        self.text = text


# --- bundled site list --------------------------------------------------
def test_bundled_site_list_loads_and_is_wellformed():
    sites = load_sites()
    assert len(sites) >= 20
    for s in sites:
        assert "{username}" in s["url"]
        assert s["detect"] in ("status_code", "message")
        if s["detect"] == "message":
            assert s.get("absent_text")


def test_bundled_json_parses_directly():
    with open(ue._BUNDLED_SITES, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["_meta"]["schema_version"] == 1
    assert isinstance(data["sites"], list)


def test_load_sites_honors_path_override(tmp_path):
    custom = tmp_path / "sites.json"
    custom.write_text(json.dumps({
        "sites": [{"name": "X", "url": "https://x.example/{username}", "detect": "status_code"}]
    }))
    sites = load_sites(str(custom))
    assert len(sites) == 1
    assert sites[0]["name"] == "X"


# --- check_site detection ----------------------------------------------
def test_check_status_code_present(monkeypatch):
    monkeypatch.setattr(ue.requests, "get", lambda *a, **k: _Resp(200))
    site = {"name": "S", "url": "https://s/{username}", "detect": "status_code"}
    assert check_site(site, "alice") == "present"


def test_check_status_code_absent(monkeypatch):
    monkeypatch.setattr(ue.requests, "get", lambda *a, **k: _Resp(404))
    site = {"name": "S", "url": "https://s/{username}", "detect": "status_code"}
    assert check_site(site, "alice") == "absent"


def test_check_status_code_other_is_unknown(monkeypatch):
    # 403/429/500 must be 'unknown', never a false 'absent'.
    for code in (403, 429, 500, 503):
        monkeypatch.setattr(ue.requests, "get", lambda *a, **k: _Resp(code))
        site = {"name": "S", "url": "https://s/{username}", "detect": "status_code"}
        assert check_site(site, "alice") == "unknown", code


def test_check_custom_absent_status(monkeypatch):
    monkeypatch.setattr(ue.requests, "get", lambda *a, **k: _Resp(410))
    site = {"name": "S", "url": "https://s/{username}", "detect": "status_code", "absent_status": 410}
    assert check_site(site, "alice") == "absent"


def test_check_message_present_and_absent(monkeypatch):
    site = {"name": "HN", "url": "https://hn/{username}", "detect": "message",
            "absent_text": "No such user."}
    monkeypatch.setattr(ue.requests, "get", lambda *a, **k: _Resp(200, "welcome alice"))
    assert check_site(site, "alice") == "present"
    monkeypatch.setattr(ue.requests, "get", lambda *a, **k: _Resp(200, "No such user."))
    assert check_site(site, "alice") == "absent"


def test_check_network_error_is_unknown(monkeypatch):
    import requests
    def boom(*a, **k):
        raise requests.ConnectionError("down")
    monkeypatch.setattr(ue.requests, "get", boom)
    site = {"name": "S", "url": "https://s/{username}", "detect": "status_code"}
    assert check_site(site, "alice") == "unknown"


# --- provider aggregation ----------------------------------------------
def _sites():
    return [
        {"name": "Present1", "url": "https://p1/{username}", "detect": "status_code"},
        {"name": "Present2", "url": "https://p2/{username}", "detect": "status_code"},
        {"name": "Absent", "url": "https://a/{username}", "detect": "status_code"},
        {"name": "Blocked", "url": "https://b/{username}", "detect": "status_code"},
    ]


def test_provider_aggregates_accounts_and_summary(monkeypatch):
    def fake_get(url, **k):
        if url.startswith("https://p1") or url.startswith("https://p2"):
            return _Resp(200)
        if url.startswith("https://a"):
            return _Resp(404)
        return _Resp(429)  # blocked -> unknown
    monkeypatch.setattr(ue.requests, "Session", lambda: type("S", (), {"get": staticmethod(fake_get)})())

    provider = UsernameEnumProvider(sites=_sites(), delay=0)
    findings = provider.scrub(Target("username", "alice"))

    accounts = [f for f in findings if f.kind == "account"]
    summaries = [f for f in findings if f.kind == "summary"]
    assert {f.data["site"] for f in accounts} == {"Present1", "Present2"}
    assert all(f.severity == "low" for f in accounts)
    assert len(summaries) == 1
    assert summaries[0].data == {"checked": 4, "unknown": 1}


def test_provider_only_supports_username():
    p = UsernameEnumProvider(sites=_sites(), delay=0)
    assert p.supports("username") is True
    assert p.supports("email") is False


def test_provider_max_sites_caps_checks(monkeypatch):
    monkeypatch.setattr(ue.requests, "Session",
                        lambda: type("S", (), {"get": staticmethod(lambda url, **k: _Resp(404))})())
    provider = UsernameEnumProvider(sites=_sites(), delay=0, max_sites=2)
    findings = provider.scrub(Target("username", "alice"))
    summary = [f for f in findings if f.kind == "summary"][0]
    assert summary.data["checked"] == 2


def test_provider_missing_site_file_degrades(monkeypatch):
    # If the bundled file can't load, provider returns just a summary of 0.
    monkeypatch.setattr(ue, "load_sites", lambda *a, **k: (_ for _ in ()).throw(OSError("gone")))
    provider = UsernameEnumProvider()  # sites=None -> triggers _load()
    findings = provider.scrub(Target("username", "alice"))
    accounts = [f for f in findings if f.kind == "account"]
    assert accounts == []
