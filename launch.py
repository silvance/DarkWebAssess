#!/usr/bin/env python3
"""One-shot launcher for the mini threat-intel platform.

Run me first. I'll:
    1. git pull the latest changes (if you're in a git checkout)
    2. create a local virtualenv at .venv/ if it doesn't exist
    3. install / refresh dependencies from requirements.txt (skipped if
       requirements.txt hasn't changed since the last successful install)
    4. init the SQLite schema and sync sources.yaml + watchlist.yaml
    5. launch the chosen target (default: the Streamlit dashboard)

Usage:
    python launch.py [target] [options]
    ./launch.py [target] [options]      # POSIX, after `chmod +x launch.py`
    ./run.sh [target] [options]         # POSIX wrapper
    run.bat [target] [options]          # Windows wrapper

Targets:
    dashboard   (default) launch the Streamlit dashboard at http://localhost:8501
    collect     run one collection cycle and exit
    scheduler   run the background scheduler in the foreground
    setup       bootstrap (git pull + venv + deps + init) then exit
    update      alias for setup

Common options:
    --no-pull          Skip the git pull step
    --no-install       Skip the dependency install/update step
    --no-init          Skip init-db and sync-config
    --port N           Override the Streamlit port (default 8501)
    --python PATH      Use this Python interpreter to create the venv
"""
import argparse
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"
REQS = ROOT / "requirements.txt"
INSTALLED_MARKER = VENV / ".installed-hash"
MIN_PY = (3, 10)


def info(msg: str) -> None:
    print(f"[launch] {msg}", flush=True)


def warn(msg: str) -> None:
    print(f"[launch] WARN {msg}", file=sys.stderr, flush=True)


def fail(msg: str, code: int = 1) -> "None":
    print(f"[launch] ERROR {msg}", file=sys.stderr, flush=True)
    sys.exit(code)


def check_python() -> None:
    if sys.version_info < MIN_PY:
        fail(
            f"Python {MIN_PY[0]}.{MIN_PY[1]}+ is required to run this launcher. "
            f"Detected {sys.version.split()[0]}. Install a newer Python and try again."
        )


def is_frozen() -> bool:
    """True when running inside a PyInstaller-built executable."""
    return getattr(sys, "frozen", False)


def venv_python() -> Path:
    if os.name == "nt":
        return VENV / "Scripts" / "python.exe"
    return VENV / "bin" / "python"


def ensure_venv(python_exe: str) -> None:
    if VENV.exists() and venv_python().exists():
        return
    info(f"Creating virtualenv at {VENV.relative_to(ROOT)}/ ...")
    try:
        subprocess.check_call([python_exe, "-m", "venv", str(VENV)])
    except subprocess.CalledProcessError as exc:
        fail(
            f"Could not create the venv with {python_exe!r}: {exc}. "
            "On Debian/Ubuntu you may need: sudo apt install python3-venv."
        )


def reqs_hash() -> str:
    if not REQS.exists():
        return ""
    return hashlib.sha256(REQS.read_bytes()).hexdigest()


def install_requirements(force: bool = False) -> None:
    if not REQS.exists():
        warn("requirements.txt missing; skipping dependency install.")
        return
    current_hash = reqs_hash()
    if not force and INSTALLED_MARKER.exists():
        try:
            cached = INSTALLED_MARKER.read_text().strip()
        except OSError:
            cached = ""
        if cached == current_hash:
            info("Dependencies already up to date.")
            return

    info("Installing / updating dependencies (this may take a minute) ...")
    py = str(venv_python())
    try:
        subprocess.check_call([py, "-m", "pip", "install", "--quiet", "--upgrade", "pip"])
        subprocess.check_call([py, "-m", "pip", "install", "--quiet", "-r", str(REQS)])
    except subprocess.CalledProcessError as exc:
        fail(f"pip install failed (exit {exc.returncode}). Try `--no-install` to skip.")
    INSTALLED_MARKER.write_text(current_hash)
    info("Dependencies installed.")


def git_pull() -> None:
    if not (ROOT / ".git").exists():
        info("Not a git checkout; skipping pull.")
        return
    if shutil.which("git") is None:
        warn("git not on PATH; skipping pull.")
        return
    try:
        remotes = subprocess.run(
            ["git", "remote"],
            cwd=str(ROOT),
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except subprocess.CalledProcessError:
        warn("could not read git remotes; skipping pull.")
        return
    if not remotes:
        info("No git remote configured; skipping pull.")
        return
    info("Pulling latest changes ...")
    try:
        result = subprocess.run(["git", "pull", "--ff-only"], cwd=str(ROOT), check=False)
    except Exception as exc:  # noqa: BLE001
        warn(f"git pull failed (continuing): {exc}")
        return
    if result.returncode != 0:
        warn("git pull returned non-zero (you may have local edits or no network); continuing.")


def run_app(args: List[str], *, exec_replace: bool = True) -> None:
    """Run `python -m app.main <args...>` inside the venv."""
    cmd = [str(venv_python()), "-m", "app.main", *args]
    if exec_replace and os.name != "nt":
        os.execvp(cmd[0], cmd)
    else:
        result = subprocess.run(cmd, cwd=str(ROOT))
        sys.exit(result.returncode)


def maybe_init_db(skip: bool) -> None:
    if skip:
        return
    info("Initializing database ...")
    py = str(venv_python())
    try:
        subprocess.check_call([py, "-m", "app.main", "init-db"], cwd=str(ROOT))
    except subprocess.CalledProcessError as exc:
        fail(f"init-db failed (exit {exc.returncode}).")
    info("Syncing sources.yaml + watchlist.yaml ...")
    try:
        subprocess.check_call([py, "-m", "app.main", "sync-config"], cwd=str(ROOT))
    except subprocess.CalledProcessError as exc:
        warn(f"sync-config returned non-zero (continuing): exit {exc.returncode}")


def launch_dashboard(port: int) -> None:
    info(f"Launching Streamlit dashboard on http://localhost:{port}")
    info("Ctrl-C to stop.")
    cmd = [
        str(venv_python()),
        "-m",
        "streamlit",
        "run",
        str(ROOT / "app" / "ui" / "streamlit_app.py"),
        "--server.port",
        str(port),
    ]
    if os.name == "nt":
        result = subprocess.run(cmd, cwd=str(ROOT))
        sys.exit(result.returncode)
    os.execvp(cmd[0], cmd)


def launch_collect() -> None:
    info("Running one collection cycle ...")
    run_app(["collect"])


def launch_scheduler() -> None:
    info("Starting the scheduler in the foreground (Ctrl-C to stop) ...")
    run_app(["scheduler"])


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="dashboard",
        choices=["dashboard", "collect", "scheduler", "setup", "update"],
        help="What to launch after bootstrap (default: dashboard).",
    )
    parser.add_argument("--no-pull", action="store_true", help="Skip git pull.")
    parser.add_argument("--no-install", action="store_true", help="Skip dependency install/update.")
    parser.add_argument("--no-init", action="store_true", help="Skip init-db / sync-config.")
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("STREAMLIT_PORT", "8501")),
        help="Streamlit port (default 8501).",
    )
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="Python interpreter to use when creating the venv (default: current).",
    )
    parser.add_argument(
        "--reinstall",
        action="store_true",
        help="Force a dependency reinstall even if requirements.txt is unchanged.",
    )
    args = parser.parse_args(argv)

    check_python()
    info(f"Working directory: {ROOT}")

    frozen = is_frozen()
    if frozen:
        info("Running inside a frozen build — skipping git pull and dependency install.")

    if not args.no_pull and not frozen:
        git_pull()

    if not frozen:
        ensure_venv(args.python)
        if not args.no_install:
            install_requirements(force=args.reinstall)

    maybe_init_db(args.no_init)

    if args.target in ("setup", "update"):
        info("Setup complete. Run `./run.sh` (or `python launch.py`) to start the dashboard.")
        return
    if args.target == "dashboard":
        launch_dashboard(args.port)
    elif args.target == "collect":
        launch_collect()
    elif args.target == "scheduler":
        launch_scheduler()


if __name__ == "__main__":
    main()
