"""CLI package — one module per command group.

Each `cmd_*.py` module exposes a `register(sub)` callable that adds its
subparsers to the top-level argparse tree, plus the `cmd_*` handler
functions argparse dispatches to.

`app.cli.parser` imports every module's `register` and assembles the
full parser; `app.main` is a thin shim that delegates to it so the
existing `python -m app.main <subcommand>` invocations keep working.
"""
