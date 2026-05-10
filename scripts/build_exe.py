#!/usr/bin/env python3
"""Convenience wrapper around PyInstaller for building a frozen executable.

Usage:
    pip install -r requirements-build.txt
    python scripts/build_exe.py

Output:
    dist/mini-threat-intel/                # bundle directory
    dist/mini-threat-intel/mini-threat-intel(.exe)
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "mini-threat-intel.spec"
BUILD_DIR = ROOT / "build"
DIST_DIR = ROOT / "dist"


def _check_pyinstaller():
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        sys.exit(
            "PyInstaller is not installed. Run:\n"
            "    pip install -r requirements-build.txt"
        )


def main():
    _check_pyinstaller()
    if not SPEC.exists():
        sys.exit(f"Spec file not found: {SPEC}")

    # Wipe previous outputs so the build is reproducible.
    for d in (BUILD_DIR, DIST_DIR):
        if d.exists():
            print(f"[build] removing {d}")
            shutil.rmtree(d)

    cmd = [sys.executable, "-m", "PyInstaller", "--clean", "--noconfirm", str(SPEC)]
    print("[build] running:", " ".join(cmd))
    rc = subprocess.call(cmd, cwd=str(ROOT))
    if rc != 0:
        sys.exit(rc)

    target = DIST_DIR / "mini-threat-intel"
    if os.name == "nt":
        target = target / "mini-threat-intel.exe"
    else:
        target = target / "mini-threat-intel"
    print(f"[build] done. Executable: {target}")
    print("[build] copy/zip the entire dist/mini-threat-intel/ folder to ship.")


if __name__ == "__main__":
    main()
