"""System-tray launcher for Windows (and any platform pystray supports).

Menu items:
    Open Dashboard        — start the Streamlit server (if not already running)
                            and open the browser to it
    Run Collection Now    — fire one `collect` cycle in the background
    Open Data Folder      — Explorer / Finder / xdg-open on the data directory
    About                 — version + paths
    Quit                  — terminate the dashboard subprocess and exit

Pystray + Pillow are the only extra deps. If they're missing we print a
helpful message rather than crashing.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Optional


def _info(msg: str) -> None:
    print(f"[tray] {msg}", flush=True)


def _warn(msg: str) -> None:
    print(f"[tray] WARN {msg}", file=sys.stderr, flush=True)


def _port() -> int:
    return int(os.getenv("STREAMLIT_PORT", "8501"))


def _data_dir() -> Path:
    override = os.environ.get("DWA_DATA_DIR")
    if override:
        return Path(override)
    return Path(os.getcwd()) / "data"


def _port_listening(port: int, host: str = "127.0.0.1") -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.4):
            return True
    except OSError:
        return False


def _spawn_dashboard() -> subprocess.Popen:
    """Re-invoke ourselves to spin up the Streamlit dashboard.

    Works for both the frozen .exe (sys.executable IS the bundled exe) and
    dev mode (sys.executable is the venv python; we run `-m app.entry`).
    """
    if getattr(sys, "frozen", False):
        cmd = [sys.executable, "dashboard", "--no-browser"]
    else:
        cmd = [sys.executable, "-m", "app.entry", "dashboard", "--no-browser"]
    # Inherit env (DWA_DATA_DIR, DATABASE_PATH, STREAMLIT_PORT) so the child
    # writes to the same data dir as the tray.
    kwargs = {}
    if os.name == "nt":
        # Detach from the tray's console window so closing the tray doesn't
        # propagate Ctrl-C and the child gets its own group.
        CREATE_NO_WINDOW = 0x08000000
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        kwargs["creationflags"] = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
    return subprocess.Popen(cmd, **kwargs)


def _open_path(path: Path) -> None:
    p = str(path)
    try:
        if os.name == "nt":
            os.startfile(p)  # noqa: S606 — intentional, opens Explorer
        elif sys.platform == "darwin":
            subprocess.Popen(["open", p])
        else:
            subprocess.Popen(["xdg-open", p])
    except Exception as exc:  # noqa: BLE001
        _warn(f"could not open {p}: {exc}")


def _wait_until_listening(port: int, timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _port_listening(port):
            return True
        time.sleep(0.3)
    return False


def _make_icon_image():
    from PIL import Image, ImageDraw

    img = Image.new("RGB", (64, 64), color=(13, 27, 42))
    d = ImageDraw.Draw(img)
    # Cyan square outline + "DW" monogram, distinguishable at 16x16.
    d.rectangle((6, 6, 57, 57), outline=(0, 212, 255), width=3)
    d.line((18, 22, 18, 44), fill=(0, 212, 255), width=4)
    d.line((18, 22, 28, 44), fill=(0, 212, 255), width=4)
    d.line((28, 44, 38, 22), fill=(0, 212, 255), width=4)
    d.rectangle((42, 22, 50, 44), outline=(0, 212, 255), width=3)
    return img


class _TrayState:
    def __init__(self) -> None:
        self.dashboard_proc: Optional[subprocess.Popen] = None
        self.lock = threading.Lock()

    def ensure_dashboard(self) -> None:
        with self.lock:
            if self.dashboard_proc and self.dashboard_proc.poll() is None:
                return
            if _port_listening(_port()):
                # Something else is on the port (maybe an externally-started
                # streamlit). Don't fight it — just open the browser.
                return
            _info("Starting dashboard ...")
            self.dashboard_proc = _spawn_dashboard()

    def stop(self) -> None:
        with self.lock:
            if self.dashboard_proc and self.dashboard_proc.poll() is None:
                _info("Stopping dashboard ...")
                try:
                    self.dashboard_proc.terminate()
                    try:
                        self.dashboard_proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self.dashboard_proc.kill()
                except Exception as exc:  # noqa: BLE001
                    _warn(f"could not stop dashboard cleanly: {exc}")


def run_tray() -> None:
    try:
        import pystray
        from pystray import Menu, MenuItem
    except ImportError:
        _warn(
            "pystray is not installed. Install it with `pip install pystray pillow` "
            "or use the bundled .exe build."
        )
        sys.exit(2)

    state = _TrayState()
    port = _port()

    def on_open_dashboard(icon, item):
        def _go():
            state.ensure_dashboard()
            if _wait_until_listening(port):
                webbrowser.open(f"http://localhost:{port}/", new=2)
            else:
                _warn(f"dashboard did not start on port {port} within 30s")
        threading.Thread(target=_go, daemon=True).start()

    def on_collect_now(icon, item):
        def _go():
            _info("Running one collection cycle ...")
            if getattr(sys, "frozen", False):
                cmd = [sys.executable, "collect"]
            else:
                cmd = [sys.executable, "-m", "app.main", "collect"]
            try:
                subprocess.Popen(cmd)
            except Exception as exc:  # noqa: BLE001
                _warn(f"collect failed to start: {exc}")
        threading.Thread(target=_go, daemon=True).start()

    def on_open_data(icon, item):
        _open_path(_data_dir())

    def on_about(icon, item):
        from app import __version__
        about = (
            f"DarkWebAssess v{__version__}\n"
            f"Data dir: {_data_dir()}\n"
            f"Dashboard: http://localhost:{port}/"
        )
        # pystray notify is best-effort cross-platform.
        try:
            icon.notify(about, "DarkWebAssess")
        except Exception:  # noqa: BLE001
            _info(about)

    def on_quit(icon, item):
        state.stop()
        icon.stop()

    image = _make_icon_image()
    menu = Menu(
        MenuItem("Open Dashboard", on_open_dashboard, default=True),
        MenuItem("Run Collection Now", on_collect_now),
        MenuItem("Open Data Folder", on_open_data),
        Menu.SEPARATOR,
        MenuItem("About", on_about),
        MenuItem("Quit", on_quit),
    )
    icon = pystray.Icon("DarkWebAssess", image, "DarkWebAssess", menu)
    _info("Tray icon started. Right-click for menu, double-click to open dashboard.")
    icon.run()
