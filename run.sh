#!/usr/bin/env bash
# One-shot launcher (POSIX wrapper). See launch.py for full options.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if command -v python3 >/dev/null 2>&1; then
    PY=python3
elif command -v python >/dev/null 2>&1; then
    PY=python
else
    echo "Python 3.10+ is required but no python interpreter was found on PATH." >&2
    echo "Install Python from https://www.python.org/downloads/ and try again." >&2
    exit 1
fi

exec "$PY" "$DIR/launch.py" "$@"
