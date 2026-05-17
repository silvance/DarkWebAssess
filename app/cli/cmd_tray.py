"""`tray` subcommand — launches the system-tray UI."""
from __future__ import annotations


def register(sub) -> None:
    p = sub.add_parser(
        "tray",
        help="Launch the system-tray launcher (Windows / Linux / macOS).",
    )
    p.set_defaults(func=_run)


def _run(args) -> int:
    from app.ui.tray import run_tray
    run_tray()
    return 0
