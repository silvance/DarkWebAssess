"""Tests for `dwa doctor`.

Each individual check is exercised in isolation so the test suite
catches regressions in the diagnostic without depending on the rest of
the project's state. The driver itself (`_run_all_checks`) is tested
end-to-end: with everything default we expect zero FAILs.
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile

import pytest

from app.cli import cmd_doctor


# --- Python version ---------------------------------------------------
def test_python_version_passes_on_supported(monkeypatch):
    # The test process is running on a supported Python by definition.
    r = cmd_doctor._check_python_version()
    assert r.status == "OK"
    assert "Python" in r.detail


# --- Database ---------------------------------------------------------
def test_database_missing_is_fail(monkeypatch, tmp_path):
    # Use a path inside tmp_path so the test never accidentally creates
    # state that other tests inherit (and so we get a real "missing" path
    # the first time).
    missing = tmp_path / "subdir-that-doesnt-exist" / "x.db"
    monkeypatch.setattr("app.config.DATABASE_PATH", str(missing))
    r = cmd_doctor._check_database()
    assert r.status == "FAIL"
    assert "does not exist" in r.detail
    assert "init-db" in (r.hint or "")


def test_database_ok_on_freshly_initialized(monkeypatch):
    from app.database import init_db
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        init_db(path)
        monkeypatch.setattr("app.config.DATABASE_PATH", path)
        import app.database as db_mod
        monkeypatch.setattr(db_mod, "DATABASE_PATH", path)
        r = cmd_doctor._check_database()
        assert r.status == "OK"
        assert "documents" in r.detail
    finally:
        os.unlink(path)


# --- YAML config loaders ---------------------------------------------
def test_check_yaml_missing_file_is_warn(tmp_path):
    r = cmd_doctor._check_yaml(
        "sources.yaml", str(tmp_path / "missing.yaml"), "load_sources",
    )
    assert r.status == "WARN"
    assert "not found" in r.detail


def test_check_yaml_invalid_yaml_is_fail(tmp_path):
    bad = tmp_path / "sources.yaml"
    bad.write_text("sources:\n  - this: is not a valid SourceEntry\n")
    r = cmd_doctor._check_yaml("sources.yaml", str(bad), "load_sources")
    assert r.status == "FAIL"
    assert "→" not in r.detail or "Fix the YAML" in (r.hint or "")


def test_check_yaml_valid_file_counts_entries(tmp_path):
    good = tmp_path / "watchlist.yaml"
    good.write_text(
        "watchlist:\n"
        "  - {type: email, value: a@b.co, enabled: true}\n"
        "  - {type: email, value: c@d.co, enabled: false}\n"
    )
    r = cmd_doctor._check_yaml("watchlist.yaml", str(good), "load_watchlist")
    assert r.status == "OK"
    assert "2 entries" in r.detail
    assert "1 enabled" in r.detail


# --- Egress preflight ------------------------------------------------
def test_egress_off_without_allowlist_is_info(monkeypatch):
    monkeypatch.delenv("STRICT_EGRESS", raising=False)
    monkeypatch.delenv("EXPECTED_EGRESS_PREFIXES", raising=False)
    r = cmd_doctor._check_egress(skip_network=True)
    assert r.status == "INFO"
    assert "STRICT_EGRESS off" in r.detail


def test_egress_strict_without_allowlist_is_fail(monkeypatch):
    """Fail-closed semantics: STRICT_EGRESS=1 with no allowlist is the
    config that the preflight refuses to start under. Doctor calls it
    out explicitly so the operator sees the misconfiguration before
    running collect / scheduler."""
    monkeypatch.setenv("STRICT_EGRESS", "1")
    monkeypatch.setenv("EXPECTED_EGRESS_PREFIXES", "")
    r = cmd_doctor._check_egress(skip_network=True)
    assert r.status == "FAIL"
    assert "fail-closed" in r.detail


def test_egress_advisory_allowlist_without_strict_is_info(monkeypatch):
    monkeypatch.delenv("STRICT_EGRESS", raising=False)
    monkeypatch.setenv("EXPECTED_EGRESS_PREFIXES", "10.0.0.0/8")
    r = cmd_doctor._check_egress(skip_network=True)
    assert r.status == "INFO"
    assert "advisory" in r.detail


def test_egress_skip_network_when_strict_and_allowlist_set(monkeypatch):
    monkeypatch.setenv("STRICT_EGRESS", "1")
    monkeypatch.setenv("EXPECTED_EGRESS_PREFIXES", "10.0.0.0/8")
    r = cmd_doctor._check_egress(skip_network=True)
    assert r.status == "INFO"
    assert "skipped" in r.detail.lower()


# --- Provider keys ---------------------------------------------------
def test_provider_keys_all_unset_are_info(monkeypatch):
    for env in ("ANTHROPIC_API_KEY", "VIRUSTOTAL_API_KEY",
                "ABUSEIPDB_API_KEY", "ABUSECH_AUTH_KEY"):
        monkeypatch.delenv(env, raising=False)
    rows = cmd_doctor._check_provider_keys()
    assert all(r.status == "INFO" for r in rows)
    assert len(rows) == 4


def test_provider_keys_set_one_reports_ok(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "secret")
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    rows = cmd_doctor._check_provider_keys()
    statuses = {r.name: r.status for r in rows}
    assert statuses["VirusTotal key"] == "OK"
    assert statuses["Anthropic LLM key"] == "INFO"
    assert statuses["AbuseIPDB key"] == "INFO"


# --- Telegram --------------------------------------------------------
def test_telegram_both_unset_is_info(monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
    r = cmd_doctor._check_telegram()
    assert r.status == "INFO"


def test_telegram_half_configured_is_warn(monkeypatch):
    """Token set but chat id missing is the common foot-gun: alerts
    silently never fire. The check turns that into a visible WARN."""
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "12345:abc")
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
    r = cmd_doctor._check_telegram()
    assert r.status == "WARN"
    assert "half-configured" in (r.hint or "").lower() or "won't fire" in (r.hint or "").lower() or "fire" in (r.hint or "")


def test_telegram_both_set_is_ok(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "12345:abc")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "67890")
    r = cmd_doctor._check_telegram()
    assert r.status == "OK"


# --- Driver / end-to-end -------------------------------------------
def test_run_all_checks_returns_results_list(monkeypatch):
    results = cmd_doctor._run_all_checks(skip_network=True)
    assert len(results) > 5
    statuses = {r.status for r in results}
    assert statuses.issubset({"OK", "INFO", "WARN", "FAIL"})


def test_run_command_exits_nonzero_when_any_check_fails(monkeypatch, capsys):
    """The `dwa doctor` exit code is what makes the command scriptable:
    you can wire it into a pre-deploy gate (`dwa doctor && dwa
    scheduler`). Verify a FAIL anywhere → exit 1."""
    monkeypatch.setenv("STRICT_EGRESS", "1")
    monkeypatch.setenv("EXPECTED_EGRESS_PREFIXES", "")  # triggers FAIL
    args = argparse.Namespace(no_network=True)
    with pytest.raises(SystemExit) as exc:
        cmd_doctor._run(args)
    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "[FAIL]" in out
    # The forced STRICT_EGRESS+no-allowlist fail must be present in the
    # summary — other checks may or may not fail depending on env state.
    assert "fail" in out  # the summary always prints "N fail"


def test_run_command_exits_zero_on_clean_state(monkeypatch, capsys, tmp_path):
    """Clean configuration: every check should land in {OK, INFO} and
    the command should NOT raise SystemExit."""
    # Clear all the optional-but-tracked env so nothing trips WARN/FAIL.
    for env in (
        "STRICT_EGRESS", "EXPECTED_EGRESS_PREFIXES",
        "ANTHROPIC_API_KEY", "VIRUSTOTAL_API_KEY",
        "ABUSEIPDB_API_KEY", "ABUSECH_AUTH_KEY",
        "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID",
    ):
        monkeypatch.delenv(env, raising=False)
    # Point DATABASE_PATH at a fresh initialized DB so the database check
    # doesn't fail due to leftover state from prior tests.
    from app.database import init_db
    db_path = str(tmp_path / "doctor.db")
    init_db(db_path)
    monkeypatch.setenv("DATABASE_PATH", db_path)
    import app.config
    monkeypatch.setattr(app.config, "DATABASE_PATH", db_path)
    import app.database as db_mod
    monkeypatch.setattr(db_mod, "DATABASE_PATH", db_path)

    args = argparse.Namespace(no_network=True)
    # Must NOT raise SystemExit on clean state.
    cmd_doctor._run(args)
    out = capsys.readouterr().out
    assert "0 fail" in out
