#!/usr/bin/env bash
set -euo pipefail

export PYTHONPATH="${PYTHONPATH:-}:$(pwd)/src"

if [[ -x ".venv/bin/python" ]]; then
  PYTHON_BIN=".venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
else
  echo "Error: No python interpreter found (tried .venv/bin/python, python3, python)" >&2
  exit 1
fi

if [[ "$(uname -s)" == "Linux" ]]; then
  if ! "${PYTHON_BIN}" - <<'PY'
import ctypes
import ctypes.util
import sys

candidates = [
    "libxcb-cursor.so.0",
    ctypes.util.find_library("xcb-cursor"),
    ctypes.util.find_library("xcb_cursor"),
]

for name in candidates:
    if not name:
        continue
    try:
        ctypes.CDLL(name)
    except OSError:
        continue
    sys.exit(0)

sys.exit(1)
PY
  then
    if command -v ldconfig >/dev/null 2>&1; then
      echo "Debug (ldconfig -p | grep libxcb-cursor):" >&2
      ldconfig -p 2>/dev/null | grep "libxcb-cursor" >&2 || true
    fi
    cat >&2 <<'EOF'
Error: Missing system library libxcb-cursor.so.0 required by Qt xcb platform plugin.
Install on Ubuntu/Debian:
  sudo apt update
  sudo apt install -y libxcb-cursor0
Then re-run ./scripts/dev_run.sh
EOF
    exit 1
  fi
fi

"${PYTHON_BIN}" -m v2link_client.main
