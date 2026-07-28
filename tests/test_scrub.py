"""Tests for the self-monitoring scrub feature.

Network providers (gravatar, hibp) are tested with `requests.get`
monkeypatched — we assert the parsing/severity logic, never make a real
call. The local cross-reference provider + runner persistence run against
a real temp SQLite DB.
"""
from __future__ import annotations

import os
import tempfile
from types import SimpleNamespace

import pytest

from app.database import get_connection, init_db
from app.repository import (
    get_scrub_findings,
    get_scrub_run,
    insert_document,
    insert_entities,
    insert_match,
    list_scrub_runs,
    upsert_watchlist_entry,
)
from app.scrub import runner as runner_mod
from app.scrub.base import Finding, Target, max_severity
from app.scrub.providers.gravatar import GravatarProvider, _email_hash
from app.scrub.providers.hibp import HibpProvider
from app.scrub.providers.local_xref import LocalXrefProvider
from app.scrub.report import render_json, render_markdown, render_text
from app.scrub.runner import ScrubReport, detect_type, run_scrub


# --- helpers ------------------------------------------------------------
class _Resp:
    def __init__(self, status=200, json_data=None, ctype="application/json"):
        self.status_code = status
        self._json = json_data if json_data is not None else {}
        self.headers = {"Content-Type": ctype}

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(f"HTTP {self.status_code}")


@pytest.fixture
def conn():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    c = get_connection(path)
    try:
        yield c
    finally:
        c.close()
        os.unlink(path)


# --- type detection -----------------------------------------------------
def test_detect_type_email():
    assert detect_type("alice@example.com") == "email"


def test_detect_type_domain():
    assert detect_type("example.com") == "domain"
    assert detect_type("sub.example.co.uk") == "domain"


def test_detect_type_username_fallback():
    assert detect_type("alice_smith") == "username"
    assert detect_type("j.doe99") == "username"  # no TLD-looking suffix... actually has none


def test_target_normalizes_email_lowercase():
    assert Target("email", "  Alice@Example.COM ").normalized() == "alice@example.com"
    # Usernames keep case.
    assert Target("username", " AliceSmith ").normalized() == "AliceSmith"


def test_max_severity():
    assert max_severity(["info", "high", "low"]) == "high"
    assert max_severity(["low", "medium"]) == "medium"
    assert max_severity([]) is None
    assert max_severity(["bogus"]) is None


# --- Gravatar provider --------------------------------------------------
def test_gravatar_no_avatar_returns_empty(monkeypatch):
    monkeypatch.setattr(
        "app.scrub.providers.gravatar.requests.get",
        lambda *a, **k: _Resp(status=404),
    )
    out = GravatarProvider().scrub(Target("email", "nobody@example.com"))
    assert out == []


def test_gravatar_avatar_only(monkeypatch):
    calls = {"n": 0}

    def fake_get(url, **k):
        calls["n"] += 1
        if "/avatar/" in url:
            return _Resp(status=200, ctype="image/png")
        # profile fetch → 404
        return _Resp(status=404, ctype="text/plain")

    monkeypatch.setattr("app.scrub.providers.gravatar.requests.get", fake_get)
    out = GravatarProvider().scrub(Target("email", "someone@example.com"))
    kinds = {f.kind for f in out}
    assert kinds == {"avatar"}
    assert out[0].severity == "low"


def test_gravatar_with_public_profile_and_links(monkeypatch):
    profile = {
        "entry": [{
            "displayName": "Alice",
            "profileUrl": "https://gravatar.com/alice",
            "accounts": [{"url": "https://twitter.com/alice"}],
            "urls": [{"value": "https://alice.blog"}],
            "currentLocation": "Somewhere",
        }]
    }

    def fake_get(url, **k):
        if "/avatar/" in url:
            return _Resp(status=200, ctype="image/png")
        return _Resp(status=200, json_data=profile, ctype="application/json")

    monkeypatch.setattr("app.scrub.providers.gravatar.requests.get", fake_get)
    out = GravatarProvider().scrub(Target("email", "alice@example.com"))
    kinds = {f.kind for f in out}
    assert kinds == {"avatar", "profile"}
    prof = [f for f in out if f.kind == "profile"][0]
    # Public profile with linked accounts → medium.
    assert prof.severity == "medium"
    assert prof.data["display_name"] == "Alice"
    assert "https://twitter.com/alice" in prof.data["accounts"]


def test_email_hash_is_md5_of_normalized():
    import hashlib
    h = hashlib.md5(b"alice@example.com").hexdigest()
    assert _email_hash("  Alice@Example.COM ") == h


# --- HIBP provider ------------------------------------------------------
def test_hibp_self_skips_without_key():
    p = HibpProvider(api_key="")
    assert p.is_available() is False


def test_hibp_404_means_no_breach(monkeypatch):
    monkeypatch.setattr(
        "app.scrub.providers.hibp.requests.get",
        lambda *a, **k: _Resp(status=404),
    )
    out = HibpProvider(api_key="k").scrub(Target("email", "clean@example.com"))
    assert out == []


def test_hibp_password_breach_is_high(monkeypatch):
    breaches = [{
        "Name": "BigCorp", "Title": "BigCorp",
        "BreachDate": "2019-01-01",
        "DataClasses": ["Email addresses", "Passwords"],
        "PwnCount": 1000000, "IsSensitive": False, "IsVerified": True,
    }]
    monkeypatch.setattr(
        "app.scrub.providers.hibp.requests.get",
        lambda *a, **k: _Resp(status=200, json_data=breaches),
    )
    out = HibpProvider(api_key="k").scrub(Target("email", "x@example.com"))
    assert len(out) == 1
    assert out[0].kind == "breach"
    assert out[0].severity == "high"  # passwords exposed


def test_hibp_non_credential_breach_is_medium(monkeypatch):
    breaches = [{
        "Name": "Forum", "Title": "Forum",
        "BreachDate": "2020-01-01",
        "DataClasses": ["Email addresses", "Usernames"],
        "IsSensitive": False,
    }]
    monkeypatch.setattr(
        "app.scrub.providers.hibp.requests.get",
        lambda *a, **k: _Resp(status=200, json_data=breaches),
    )
    out = HibpProvider(api_key="k").scrub(Target("email", "x@example.com"))
    assert out[0].severity == "medium"


def test_hibp_sensitive_breach_is_high(monkeypatch):
    breaches = [{
        "Name": "Sensitive", "Title": "Sensitive Site",
        "BreachDate": "2021-01-01",
        "DataClasses": ["Email addresses"],
        "IsSensitive": True,
    }]
    monkeypatch.setattr(
        "app.scrub.providers.hibp.requests.get",
        lambda *a, **k: _Resp(status=200, json_data=breaches),
    )
    out = HibpProvider(api_key="k").scrub(Target("email", "x@example.com"))
    assert out[0].severity == "high"


# --- Local cross-reference ---------------------------------------------
def _seed_match(conn, email="jsmith@acme.example"):
    wl_id = upsert_watchlist_entry(conn, {
        "type": "email", "value": email, "description": "test",
        "severity": "high", "enabled": True,
    })
    doc_id = insert_document(conn, {
        "source_name": "TestFeed", "source_type": "rss",
        "source_url": "https://t.example/1", "title": "leak",
        "raw_text": f"contact {email} for details",
        "retrieved_at": "2026-01-01T00:00:00Z",
        "content_hash": "hash-local-xref-1",
    })
    insert_entities(conn, doc_id, [
        {"entity_type": "email", "entity_value": email, "context": f"reach {email} now"},
    ])
    insert_match(
        conn, document_id=doc_id, watchlist_id=wl_id,
        matched_value=email, match_type="exact_email",
        context="ctx", severity="high",
    )
    conn.commit()
    return doc_id


def test_local_xref_finds_watchlist_match(conn):
    _seed_match(conn, "jsmith@acme.example")
    out = LocalXrefProvider(conn).scrub(Target("email", "jsmith@acme.example"))
    kinds = [f.kind for f in out]
    assert "mention" in kinds
    # The watchlist match is the high-severity finding.
    assert any(f.severity == "high" for f in out)


def test_local_xref_empty_when_no_data(conn):
    out = LocalXrefProvider(conn).scrub(Target("email", "ghost@nowhere.example"))
    assert out == []


def test_local_xref_case_insensitive(conn):
    _seed_match(conn, "jsmith@acme.example")
    out = LocalXrefProvider(conn).scrub(Target("email", "JSmith@ACME.example"))
    assert len(out) > 0


# --- Runner + persistence ----------------------------------------------
def test_run_scrub_persists_run_and_findings(conn):
    _seed_match(conn, "jsmith@acme.example")
    # Only the offline local_xref provider (no network).
    report = run_scrub(
        conn, Target("email", "jsmith@acme.example"),
        providers=[LocalXrefProvider(conn)], persist=True, delay=0,
    )
    assert report.run_id is not None
    assert report.highest_severity == "high"

    stored = get_scrub_run(conn, report.run_id)
    assert stored["target_value"] == "jsmith@acme.example"
    assert stored["findings_count"] == len(report.findings)
    assert stored["highest_severity"] == "high"
    assert stored["finished_at"] is not None

    findings = get_scrub_findings(conn, report.run_id)
    assert len(findings) == len(report.findings)


def test_run_scrub_no_save(conn):
    _seed_match(conn, "jsmith@acme.example")
    report = run_scrub(
        conn, Target("email", "jsmith@acme.example"),
        providers=[LocalXrefProvider(conn)], persist=False, delay=0,
    )
    assert report.run_id is None
    assert list_scrub_runs(conn) == []


def test_run_scrub_skips_unavailable_provider(conn):
    report = run_scrub(
        conn, Target("email", "x@example.com"),
        providers=[HibpProvider(api_key="")], persist=True, delay=0,
    )
    # One provider run, marked skipped, no findings.
    pr = report.provider_runs[0]
    assert pr.ran is False
    assert "HIBP_API_KEY" in pr.skipped_reason
    assert report.findings == []


def test_run_scrub_isolates_provider_error(conn):
    class Boom(LocalXrefProvider):
        name = "boom"
        def scrub(self, target):
            raise RuntimeError("kaboom")

    _seed_match(conn, "jsmith@acme.example")
    report = run_scrub(
        conn, Target("email", "jsmith@acme.example"),
        providers=[Boom(conn), LocalXrefProvider(conn)], persist=True, delay=0,
    )
    # Boom errored but local_xref still ran and produced findings.
    by_name = {pr.provider: pr for pr in report.provider_runs}
    assert by_name["boom"].error is not None
    assert len(by_name["local_xref"].findings) > 0


def test_run_scrub_respects_target_type_support(conn):
    # HIBP only supports email; a username target should skip it entirely
    # (not even counted as a provider run).
    report = run_scrub(
        conn, Target("username", "alice"),
        providers=[HibpProvider(api_key="k")], persist=False, delay=0,
    )
    assert report.provider_runs == []


# --- Report rendering ---------------------------------------------------
def _report_with_findings():
    return ScrubReport(
        run_id=1,
        target=Target("email", "a@b.co"),
        provider_runs=[
            runner_mod.ProviderRun(
                provider="local_xref", ran=True,
                findings=[Finding(kind="mention", title="Seen in feed", severity="high")],
            ),
            runner_mod.ProviderRun(
                provider="hibp", ran=False, skipped_reason="no key",
            ),
        ],
    )


def test_render_text_includes_summary_and_findings():
    txt = render_text(_report_with_findings())
    assert "a@b.co" in txt
    assert "highest severity: high" in txt
    assert "Seen in feed" in txt
    assert "hibp: skipped" in txt


def test_render_markdown_has_table_and_headings():
    md = render_markdown(_report_with_findings())
    assert "# Scrub report" in md
    assert "| Provider | Result |" in md
    assert "Seen in feed" in md


def test_render_json_roundtrips():
    import json
    js = render_json(_report_with_findings())
    parsed = json.loads(js)
    assert parsed["target"]["value"] == "a@b.co"
    assert parsed["highest_severity"] == "high"
    assert parsed["findings_count"] == 1


def test_render_text_no_findings():
    empty = ScrubReport(
        run_id=1, target=Target("email", "clean@x.co"),
        provider_runs=[runner_mod.ProviderRun(provider="gravatar", ran=True, findings=[])],
    )
    txt = render_text(empty)
    assert "No exposure found" in txt
