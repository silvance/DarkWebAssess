"""Unified entry point — used both as a development helper and as the main
script bundled into the PyInstaller-built executable.

Behavior
- `mini-threat-intel.exe` (no args)         → launches the Streamlit dashboard
- `mini-threat-intel.exe dashboard`         → same
- `mini-threat-intel.exe tray`              → system-tray launcher (Windows)
- `mini-threat-intel.exe collect|score|...` → forwards to the regular CLI
                                              defined in `app.main`

The dashboard launcher uses Streamlit's programmatic bootstrap so it works
both from a normal install and from a frozen build (where the script path
lives under sys._MEIPASS).
"""
import os
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path


def _is_frozen() -> bool:
    return getattr(sys, "frozen", False)


def _streamlit_script_path() -> Path:
    if _is_frozen():
        base = Path(getattr(sys, "_MEIPASS", os.path.dirname(sys.executable)))
    else:
        base = Path(__file__).resolve().parent.parent
    return base / "app" / "ui" / "streamlit_app.py"


def _resource_dir() -> Path:
    """Directory that holds bundled YAML configs (sources, watchlist, etc.)."""
    if _is_frozen():
        return Path(getattr(sys, "_MEIPASS", os.path.dirname(sys.executable)))
    return Path(__file__).resolve().parent.parent


def _resolve_data_dir() -> Path:
    """Pick a writable data directory.

    Precedence:
      1. $DWA_DATA_DIR (set by the installer to %APPDATA%\\DarkWebAssess)
      2. cwd/data (portable / dev mode)
    """
    override = os.environ.get("DWA_DATA_DIR")
    if override:
        d = Path(override)
    else:
        d = Path(os.getcwd()) / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _ensure_runtime_paths() -> None:
    """When frozen, point YAML config + DB at user-writable directories."""
    if not _is_frozen():
        # In dev mode we still honour DWA_DATA_DIR if set, so the installer
        # smoke-test path works from a checkout too.
        if os.environ.get("DWA_DATA_DIR") and "DATABASE_PATH" not in os.environ:
            os.environ["DATABASE_PATH"] = str(_resolve_data_dir() / "threatintel.db")
        return
    # YAML configs are bundled read-only inside the exe; expose them via env so
    # config.py picks them up.
    res = _resource_dir()
    os.environ.setdefault("SOURCES_PATH", str(res / "sources.yaml"))
    os.environ.setdefault("WATCHLIST_PATH", str(res / "watchlist.yaml"))
    os.environ.setdefault("SUPPRESSION_PATH", str(res / "suppression.yaml"))
    os.environ.setdefault("ONION_DIRECTORIES_PATH", str(res / "onion_directories.yaml"))

    if "DATABASE_PATH" not in os.environ:
        os.environ["DATABASE_PATH"] = str(_resolve_data_dir() / "threatintel.db")


def _open_browser_when_ready(port: int, host: str = "127.0.0.1", timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    url = f"http://localhost:{port}/"
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.3)
    else:
        return
    try:
        webbrowser.open(url, new=2)
    except Exception:  # noqa: BLE001
        pass


def _first_run_bootstrap() -> None:
    """On first launch (empty DB), create the schema and load the bundled
    watchlist/sources so a freshly-downloaded build shows real content
    instead of a blank dashboard. No-op once the DB has any sources or
    watchlist rules, so it never overrides an established install. Best
    effort — never blocks the dashboard from launching.
    """
    try:
        from app.database import db_cursor, init_db
        init_db()
        with db_cursor() as conn:
            has_sources = conn.execute("SELECT COUNT(*) FROM sources").fetchone()[0]
            has_watchlist = conn.execute("SELECT COUNT(*) FROM watchlist").fetchone()[0]
        if has_sources or has_watchlist:
            return
        from app.cli._helpers import (
            load_sources_validated,
            load_watchlist_validated,
        )
        from app.repository import upsert_source, upsert_watchlist_entry

        sources = load_sources_validated()
        watchlist = load_watchlist_validated()
        with db_cursor() as conn:
            for src in sources:
                upsert_source(conn, src)
            for entry in watchlist:
                upsert_watchlist_entry(conn, entry)
        print(
            f"[first-run] loaded {len(sources)} sources + {len(watchlist)} "
            "watchlist entries from bundled config.",
            flush=True,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"[first-run] bootstrap skipped: {exc}", file=sys.stderr, flush=True)


def _run_dashboard(port: int, open_browser: bool = True) -> None:
    """Launch Streamlit in-process (works from a frozen build)."""
    _first_run_bootstrap()
    # In a PyInstaller bundle Streamlit mis-detects "development mode" as ON,
    # and it then refuses to honor --server.port ("server.port does not work
    # when global.developmentMode is true"). Force development mode OFF so the
    # frozen dashboard launches on the chosen port.
    os.environ["STREAMLIT_GLOBAL_DEVELOPMENT_MODE"] = "false"
    if open_browser:
        threading.Thread(
            target=_open_browser_when_ready, args=(port,), daemon=True
        ).start()
    script = str(_streamlit_script_path())
    sys.argv = ["streamlit", "run", script, "--server.port", str(port),
                "--server.headless", "true"]
    from streamlit.web import cli as st_cli
    sys.exit(st_cli.main())


def main(argv=None) -> None:
    _ensure_runtime_paths()
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] == "dashboard":
        port = int(os.getenv("STREAMLIT_PORT", "8501"))
        open_browser = "--no-browser" not in args
        _run_dashboard(port, open_browser=open_browser)
        return
    if args[0] == "tray":
        from app.ui.tray import run_tray
        run_tray()
        return
    # Anything else: dispatch to the regular CLI defined in app.main
    from app.main import main as cli_main
    cli_main(args)


if __name__ == "__main__":
    main()
