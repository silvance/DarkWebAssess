"""Thin CLI entry point — defers to `app.cli.parser` for the actual work.

The real subcommand modules live under `app.cli/`. This shim exists so the
familiar `python -m app.main <subcommand>` invocations keep working without
any caller-side changes.
"""
from app.cli.parser import main

if __name__ == "__main__":
    main()
