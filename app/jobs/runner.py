"""Job runner: wraps callables with start/finish bookkeeping in `job_runs`."""
import json
import logging
import time
from typing import Any, Callable, Optional

import requests

from app.collectors.rss_collector import collect_rss
from app.config import (
    ENRICH_BATCH_LIMIT,
    HTTP_TIMEOUT,
    SOURCES_PATH,
    USER_AGENT,
)
from app.database import db_cursor
from app.normalizer import utcnow_iso
from app.repository import mark_source_error, mark_source_success

log = logging.getLogger(__name__)


def _start_run(job_name: str) -> int:
    with db_cursor() as conn:
        cur = conn.execute(
            "INSERT INTO job_runs (job_name, started_at) VALUES (?, ?)",
            (job_name, utcnow_iso()),
        )
        return cur.lastrowid


def _finish_run(run_id: int, success: bool, message: Optional[str], duration: float) -> None:
    with db_cursor() as conn:
        conn.execute(
            """
            UPDATE job_runs
            SET finished_at = ?, success = ?, message = ?, duration_seconds = ?
            WHERE id = ?
            """,
            (utcnow_iso(), int(success), message, float(duration), int(run_id)),
        )


def record_run(job_name: str, fn: Callable[[], Any]) -> Any:
    """Run `fn`, persist a row to `job_runs`, and return whatever fn returned.

    Exceptions are recorded and re-raised so the scheduler logs them too.
    """
    run_id = _start_run(job_name)
    t0 = time.time()
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        _finish_run(run_id, False, str(exc), time.time() - t0)
        raise
    msg: Optional[str]
    if isinstance(result, str):
        msg = result
    elif result is None:
        msg = None
    else:
        try:
            msg = json.dumps(result, default=str)
        except (TypeError, ValueError):
            msg = repr(result)
    _finish_run(run_id, True, msg, time.time() - t0)
    return result


# --- Job entry points -----------------------------------------------------
def job_collect():
    # Local import to avoid a circular import at module load time.
    from app.main import run_collection_cycle

    return run_collection_cycle()


def job_enrich():
    from app.main import run_enrichment_cycle

    return run_enrichment_cycle(limit=ENRICH_BATCH_LIMIT)


def job_daily_report():
    """Generate and persist the daily_summary report."""
    from app.reports.runner import generate_report, save_report

    with db_cursor() as conn:
        report = generate_report(conn, "daily_summary", window="24h")
        save_report(conn, report)
    return {"name": "daily_summary"}


def job_source_health():
    """HEAD each enabled source URL and update its health row.

    A successful HEAD just records last_checked_at; a failure increments
    error_count and triggers backoff. We don't try to actually parse the
    feed here — that's the collector's job.
    """
    import yaml

    with open(SOURCES_PATH, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    sources = cfg.get("sources", []) or []
    headers = {"User-Agent": USER_AGENT}
    counts = {"ok": 0, "errors": 0}
    with db_cursor() as conn:
        for src in sources:
            if not src.get("enabled", True):
                continue
            try:
                resp = requests.head(src["url"], headers=headers, timeout=HTTP_TIMEOUT, allow_redirects=True)
                # Some servers reject HEAD; fall back to a light GET on 4xx.
                if resp.status_code >= 400 and resp.status_code != 405:
                    resp = requests.get(src["url"], headers=headers, timeout=HTTP_TIMEOUT, stream=True)
                resp.raise_for_status()
                mark_source_success(conn, src["name"])
                counts["ok"] += 1
            except Exception as exc:  # noqa: BLE001
                mark_source_error(conn, src["name"], str(exc))
                counts["errors"] += 1
    return counts
