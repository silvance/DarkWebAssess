"""Unified entry point — used both as a development helper and as the main
script bundled into the PyInstaller-built executable.

Behavior
- `mini-threat-intel.exe` (no args)         → launches the Streamlit dashboard
- `mini-threat-intel.exe dashboard`         → same
- `mini-threat-intel.exe collect|score|...` → forwards to the regular CLI
                                              defined in `app.main`

The dashboard launcher uses Streamlit's programmatic bootstrap so it works
both from a normal install and from a frozen build (where the script path
lives under sys._MEIPASS).
"""
import os
import sys
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


def _ensure_runtime_paths() -> None:
    """When frozen, point YAML config + DB at user-writable directories."""
    if not _is_frozen():
        return
    # YAML configs are bundled read-only inside the exe; expose them via env so
    # config.py picks them up.
    res = _resource_dir()
    os.environ.setdefault("SOURCES_PATH", str(res / "sources.yaml"))
    os.environ.setdefault("WATCHLIST_PATH", str(res / "watchlist.yaml"))
    os.environ.setdefault("SUPPRESSION_PATH", str(res / "suppression.yaml"))

    # The DB and any caches must live somewhere writable. Default to a
    # per-user data dir alongside the exe (cwd is fine for a portable build).
    if "DATABASE_PATH" not in os.environ:
        data_dir = Path(os.getcwd()) / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        os.environ["DATABASE_PATH"] = str(data_dir / "threatintel.db")


def _run_dashboard(port: int) -> None:
    """Launch Streamlit in-process (works from a frozen build)."""
    script = str(_streamlit_script_path())
    # Streamlit's CLI rewrites argv; replicate the supported pattern.
    sys.argv = ["streamlit", "run", script, "--server.port", str(port),
                "--server.headless", "true"]
    from streamlit.web import cli as st_cli
    sys.exit(st_cli.main())


def main(argv=None) -> None:
    _ensure_runtime_paths()
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] == "dashboard":
        port = int(os.getenv("STREAMLIT_PORT", "8501"))
        _run_dashboard(port)
        return
    # Anything else: dispatch to the regular CLI defined in app.main
    from app.main import main as cli_main
    cli_main(args)


if __name__ == "__main__":
    main()
