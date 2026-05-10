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
    from app.pipeline import run_collection_cycle

    return run_collection_cycle()


def job_enrich():
    from app.pipeline import run_enrichment_cycle

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
    feed here — that's the collector's job. Onion sources are HEAD-checked
    over the Tor SOCKS proxy so we never accidentally probe a .onion via
    the clearweb."""
    from app.collectors.onion_collector import build_tor_session
    from app.config import ONION_REQUEST_TIMEOUT
    from app.config_models import load_sources

    cfg = load_sources(SOURCES_PATH)
    counts = {"ok": 0, "errors": 0}
    with db_cursor() as conn:
        for src in cfg.sources:
            if not src.enabled:
                continue
            try:
                if src.type == "onion":
                    session = build_tor_session()
                    timeout = ONION_REQUEST_TIMEOUT
                else:
                    session = requests
                    timeout = HTTP_TIMEOUT
                headers = {"User-Agent": USER_AGENT} if src.type != "onion" else None
                resp = session.head(
                    src.url, headers=headers, timeout=timeout, allow_redirects=True,
                )
                # Some servers reject HEAD; fall back to a light GET on 4xx
                # (other than 405 Method Not Allowed which means HEAD itself
                # was rejected and there's no point retrying with it).
                if resp.status_code >= 400 and resp.status_code != 405:
                    resp = session.get(
                        src.url, headers=headers, timeout=timeout, stream=True,
                    )
                resp.raise_for_status()
                mark_source_success(conn, src.name)
                counts["ok"] += 1
            except Exception as exc:  # noqa: BLE001
                mark_source_error(conn, src.name, str(exc))
                counts["errors"] += 1
    return counts
