"""Scheduler command."""
import logging

log = logging.getLogger(__name__)


def register(sub):
    psched = sub.add_parser(
        "scheduler", help="Run collect/enrich/source-health on intervals."
    )
    psched.add_argument(
        "--run-now", action="store_true", help="Trigger every job immediately on start."
    )
    psched.set_defaults(func=cmd_scheduler)


def cmd_scheduler(args):
    from app.jobs.scheduler import run_scheduler
    from app.network.egress import preflight_or_exit

    preflight_or_exit()
    try:
        run_scheduler(run_now=args.run_now)
    except (KeyboardInterrupt, SystemExit):
        log.info("Scheduler stopped.")
