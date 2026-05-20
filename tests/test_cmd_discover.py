"""Tests for the `discover` CLI subcommand (`app/cli/cmd_discover.py`).

Coverage:

- _cmd_run dispatch:
  - no enabled directories → prints the "no enabled directories" message,
    exits 0 (not an error)
  - --directory referring to an unknown name → exit 2
  - happy path: candidates persisted, new/refreshed counts printed
- _cmd_list: empty + populated
- _cmd_show: known id + unknown id (exit 2)
- _cmd_approve: writes a `discover_approved` audit row, prints the
  sources.yaml snippet, unknown id → exit 2
- _cmd_reject: writes a `discover_rejected` audit row, unknown id → exit 2

The network side (HTTP fetch + HTML parse) is monkeypatched at the
`discover_from_directories` seam so these tests are fully offline. The
`record_audit` write goes through the real `audit_log` table — we read
back from it to assert audit semantics.
"""
from __future__ import annotations

import argparse
import os
import tempfile
from types import SimpleNamespace

import pytest

from app.cli import cmd_discover
from app.collectors.onion_discovery import DiscoveredOnion
from app.database import get_connection, init_db
from app.repository import set_onion_candidate_status, upsert_onion_candidate


@pytest.fixture
def db_env(monkeypatch):
    """Spin up a fresh SQLite DB per test and route the CLI's
    `get_connection()` calls at it via DATABASE_PATH."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    monkeypatch.setenv("DATABASE_PATH", path)
    # `app.database` reads DATABASE_PATH lazily through _resolve_db_path,
    # which falls back to the module global. Set both to be safe.
    import app.database as db_mod
    monkeypatch.setattr(db_mod, "DATABASE_PATH", path, raising=True)
    # Don't run the egress preflight in tests (no internet in CI sandbox).
    monkeypatch.delenv("STRICT_EGRESS", raising=False)
    try:
        yield path
    finally:
        os.unlink(path)


def _seed_candidates(path: str, *items: dict) -> list[dict]:
    """Insert candidates directly via the repository for setup. Returns
    the list of stored rows."""
    out = []
    with get_connection(path) as conn:
        for it in items:
            out.append(upsert_onion_candidate(
                conn,
                url=it["url"],
                host=it.get("host") or it["url"].split("//", 1)[1].split("/", 1)[0],
                title=it.get("title"),
                source_name=it.get("source_name", "test-index"),
            ))
        conn.commit()
    return out


def _audit_rows(path: str, action: str | None = None) -> list[dict]:
    with get_connection(path) as conn:
        if action:
            rows = conn.execute(
                "SELECT * FROM audit_log WHERE action = ? ORDER BY id",
                (action,),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
        return [dict(r) for r in rows]


# --- _cmd_run -----------------------------------------------------------
def test_cmd_run_no_enabled_directories_prints_help_and_returns(
    db_env, monkeypatch, capsys
):
    """`onion_directories.yaml` ships with everything disabled — verify
    the user gets a useful nudge rather than an opaque success."""
    import app.config_models as cm

    monkeypatch.setattr(
        cm, "load_onion_directories",
        lambda _path: SimpleNamespace(directories=[
            SimpleNamespace(name="ahmia", enabled=False),
        ]),
    )
    args = argparse.Namespace(directory=None)
    cmd_discover._cmd_run(args)
    captured = capsys.readouterr()
    assert "no enabled directories" in captured.out
    assert _audit_rows(db_env) == []


def test_cmd_run_unknown_directory_filter_exits_2(db_env, monkeypatch, capsys):
    import app.config_models as cm
    monkeypatch.setattr(
        cm, "load_onion_directories",
        lambda _path: SimpleNamespace(directories=[
            SimpleNamespace(name="ahmia", enabled=True),
        ]),
    )
    args = argparse.Namespace(directory="not-a-real-directory")
    with pytest.raises(SystemExit) as exc:
        cmd_discover._cmd_run(args)
    assert exc.value.code == 2
    assert "no directory named" in capsys.readouterr().err


def test_cmd_run_persists_candidates_and_prints_summary(db_env, monkeypatch, capsys):
    """Happy path: enabled directory, discovery yields candidates,
    they're upserted and the new/refreshed counts are printed."""
    import app.config_models as cm
    import app.cli.cmd_discover as cmd_mod

    monkeypatch.setattr(
        cm, "load_onion_directories",
        lambda _path: SimpleNamespace(directories=[
            SimpleNamespace(name="ahmia", enabled=True, transport="clearweb"),
        ]),
    )
    # Replace the network-touching collector. Two candidates: one totally
    # new, one already-seen so the refreshed-count branch fires.
    _seed_candidates(db_env, {
        "url": "http://" + ("a" * 16) + ".onion/", "title": "old"
    })
    fake = [
        DiscoveredOnion(
            url="http://" + ("a" * 16) + ".onion/",  # already seen
            host=("a" * 16) + ".onion",
            title="old", source_name="ahmia",
        ),
        DiscoveredOnion(
            url="http://" + ("b" * 56) + ".onion/",  # new
            host=("b" * 56) + ".onion",
            title="brand new", source_name="ahmia",
        ),
    ]
    monkeypatch.setattr(cmd_mod, "discover_from_directories",
                        lambda _dirs: fake, raising=False)
    # Some test environments don't import discover_from_directories at
    # module load (it's a local import). Patch the source module too.
    import app.collectors.onion_discovery as od
    monkeypatch.setattr(od, "discover_from_directories", lambda _dirs: fake)

    args = argparse.Namespace(directory=None)
    cmd_discover._cmd_run(args)

    out = capsys.readouterr().out
    assert "2 URLs extracted" in out
    assert "1 new" in out
    assert "1 re-seen" in out


# --- _cmd_list ----------------------------------------------------------
def test_cmd_list_empty_db_prints_friendly_message(db_env, capsys):
    args = argparse.Namespace(status="pending", search=None)
    cmd_discover._cmd_list(args)
    out = capsys.readouterr().out
    assert "no candidates with status=pending" in out


def test_cmd_list_populated_prints_table(db_env, capsys):
    _seed_candidates(db_env,
        {"url": "http://" + ("c" * 16) + ".onion/"},
        {"url": "http://" + ("d" * 16) + ".onion/"},
    )
    args = argparse.Namespace(status="pending", search=None)
    cmd_discover._cmd_list(args)
    out = capsys.readouterr().out
    assert "2 candidates" in out
    assert "pending" in out


# --- _cmd_show ----------------------------------------------------------
def test_cmd_show_unknown_id_exits_2(db_env, capsys):
    args = argparse.Namespace(candidate_id=9999)
    with pytest.raises(SystemExit) as exc:
        cmd_discover._cmd_show(args)
    assert exc.value.code == 2
    assert "no candidate with id=9999" in capsys.readouterr().err


def test_cmd_show_known_id_prints_metadata(db_env, capsys):
    seeded = _seed_candidates(db_env, {
        "url": "http://" + ("e" * 16) + ".onion/", "title": "Some Index"
    })
    args = argparse.Namespace(candidate_id=seeded[0]["id"])
    cmd_discover._cmd_show(args)
    out = capsys.readouterr().out
    assert f"Candidate #{seeded[0]['id']}" in out
    assert "Some Index" in out
    assert "pending" in out


# --- _cmd_approve -------------------------------------------------------
def test_cmd_approve_unknown_id_exits_2(db_env, capsys):
    args = argparse.Namespace(candidate_id=9999, reviewer=None, notes=None)
    with pytest.raises(SystemExit) as exc:
        cmd_discover._cmd_approve(args)
    assert exc.value.code == 2


def test_cmd_approve_writes_audit_row_and_prints_snippet(db_env, capsys):
    seeded = _seed_candidates(db_env, {
        "url": "http://" + ("f" * 16) + ".onion/",
        "title": "TargetSite",
    })
    args = argparse.Namespace(
        candidate_id=seeded[0]["id"],
        reviewer="alice",
        notes="ransomware-leak index",
    )
    cmd_discover._cmd_approve(args)
    out = capsys.readouterr().out
    # Snippet is what the operator pastes into sources.yaml.
    assert "type: onion" in out
    assert "enabled: true" in out
    assert "TargetSite" in out  # name reflected in snippet

    # Audit row exists with the expected fields.
    audit = _audit_rows(db_env, action="discover_approved")
    assert len(audit) == 1
    row = audit[0]
    assert row["actor"] == "alice"
    assert row["actor_role"] == "cli"
    assert row["target_type"] == "onion_candidate"
    assert row["target_id"] == str(seeded[0]["id"])
    # Payload is JSON-encoded; key bits round-trip.
    import json
    payload = json.loads(row["payload_json"])
    assert payload["host"] == ("f" * 16) + ".onion"
    assert payload["notes"] == "ransomware-leak index"


# --- _cmd_reject --------------------------------------------------------
def test_cmd_reject_unknown_id_exits_2(db_env, capsys):
    args = argparse.Namespace(candidate_id=9999, reviewer=None, notes=None)
    with pytest.raises(SystemExit) as exc:
        cmd_discover._cmd_reject(args)
    assert exc.value.code == 2


def test_cmd_reject_writes_audit_row(db_env, capsys):
    seeded = _seed_candidates(db_env, {
        "url": "http://" + ("g" * 16) + ".onion/",
    })
    args = argparse.Namespace(
        candidate_id=seeded[0]["id"],
        reviewer="alice",
        notes="csam-host",
    )
    cmd_discover._cmd_reject(args)
    out = capsys.readouterr().out
    assert "marked rejected" in out

    audit = _audit_rows(db_env, action="discover_rejected")
    assert len(audit) == 1
    assert audit[0]["actor"] == "alice"
    assert audit[0]["actor_role"] == "cli"
    import json
    payload = json.loads(audit[0]["payload_json"])
    assert payload["notes"] == "csam-host"


def test_reject_then_rediscovery_preserves_rejected_status(db_env, capsys):
    """End-to-end pin: after `reject`, a fresh discover-run that finds
    the same URL must NOT flip status back to pending. The CLI is just
    the user-facing surface for the durable-rejection contract we
    already test at the repo layer; this test wires the two together."""
    seeded = _seed_candidates(db_env, {
        "url": "http://" + ("h" * 16) + ".onion/",
    })
    args = argparse.Namespace(
        candidate_id=seeded[0]["id"], reviewer="alice", notes="bad",
    )
    cmd_discover._cmd_reject(args)
    capsys.readouterr()
    # Re-upsert the same URL (simulating a fresh discover-run finding it
    # in another directory).
    with get_connection(db_env) as conn:
        refreshed = upsert_onion_candidate(
            conn,
            url="http://" + ("h" * 16) + ".onion/",
            host=("h" * 16) + ".onion",
            title=None, source_name="other-index",
        )
        conn.commit()
    assert refreshed["status"] == "rejected"
    assert refreshed["times_seen"] == 2
