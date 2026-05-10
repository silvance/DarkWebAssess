import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

from app import database as dbm
from app import main as app_main
from app.database import get_connection, init_db
from app.jobs import runner as job_runner


@pytest.fixture
def temp_db(monkeypatch):
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    monkeypatch.setattr(dbm, "DATABASE_PATH", path)
    yield path
    os.unlink(path)


def test_record_run_success(temp_db):
    out = job_runner.record_run("unit_test", lambda: {"hello": "world"})
    assert out == {"hello": "world"}
    with get_connection(temp_db) as conn:
        rows = conn.execute("SELECT * FROM job_runs WHERE job_name = ?", ("unit_test",)).fetchall()
    assert len(rows) == 1
    assert rows[0]["success"] == 1
    assert rows[0]["finished_at"] is not None
    assert rows[0]["duration_seconds"] is not None


def test_record_run_failure_persists_and_reraises(temp_db):
    def boom():
        raise RuntimeError("kaboom")

    with pytest.raises(RuntimeError):
        job_runner.record_run("unit_fail", boom)

    with get_connection(temp_db) as conn:
        row = conn.execute("SELECT * FROM job_runs WHERE job_name = ?", ("unit_fail",)).fetchone()
    assert row["success"] == 0
    assert "kaboom" in (row["message"] or "")


# --- Source backoff -------------------------------------------------------
def _utc_iso(offset_minutes: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=offset_minutes)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def test_backoff_zero_errors_no_skip():
    assert app_main._backoff_until(0, _utc_iso(-1)) is None


def test_backoff_grows_with_errors():
    # 1 error → 5 * 2^1 = 10 minutes after the last attempt.
    until = app_main._backoff_until(1, _utc_iso(-5))  # 5 minutes ago
    assert until is not None
    # 5m ago + 10m backoff = 5m in the future.
    assert until > datetime.now(timezone.utc)


def test_backoff_is_capped():
    until_small = app_main._backoff_until(3, _utc_iso(0))
    until_huge = app_main._backoff_until(99, _utc_iso(0))
    # 99 errors should be capped at exponent 6 → 5 * 2^6 = 320 minutes.
    assert until_huge is not None and until_small is not None
    assert (until_huge - until_small).total_seconds() <= 320 * 60
