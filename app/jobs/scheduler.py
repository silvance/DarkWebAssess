"""APScheduler wiring for the threat-intel pipeline.

Run interactively via:
    python -m app.main scheduler [--run-now]

The scheduler stays in the foreground; ctrl-C stops it.
"""
import logging
from datetime import datetime, timezone

from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.interval import IntervalTrigger

from app.config import (
    COLLECT_INTERVAL_MINUTES,
    ENRICH_INTERVAL_MINUTES,
    SOURCE_HEALTH_INTERVAL_HOURS,
)
from app.jobs.runner import job_collect, job_enrich, job_source_health, record_run

log = logging.getLogger(__name__)


def _wrap(name, fn):
    def runner():
        try:
            record_run(name, fn)
        except Exception:  # noqa: BLE001
            log.exception("Job %s raised", name)
    runner.__name__ = name
    return runner


def build_scheduler() -> BlockingScheduler:
    sched = BlockingScheduler(timezone="UTC")
    sched.add_job(
        _wrap("collect", job_collect),
        IntervalTrigger(minutes=COLLECT_INTERVAL_MINUTES),
        id="collect",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    sched.add_job(
        _wrap("enrich", job_enrich),
        IntervalTrigger(minutes=ENRICH_INTERVAL_MINUTES),
        id="enrich",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    sched.add_job(
        _wrap("source_health", job_source_health),
        IntervalTrigger(hours=SOURCE_HEALTH_INTERVAL_HOURS),
        id="source_health",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    return sched


def run_scheduler(run_now: bool = False) -> None:
    sched = build_scheduler()
    if run_now:
        for job in sched.get_jobs():
            job.modify(next_run_time=datetime.now(timezone.utc))
    log.info(
        "Scheduler started. collect=%dm enrich=%dm source_health=%dh. Ctrl-C to stop.",
        COLLECT_INTERVAL_MINUTES,
        ENRICH_INTERVAL_MINUTES,
        SOURCE_HEALTH_INTERVAL_HOURS,
    )
    sched.start()
