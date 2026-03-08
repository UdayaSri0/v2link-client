#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${ROOT_DIR}/.venv"
VENV_PYTHON="${VENV_DIR}/bin/python"
REQUIREMENTS_FILE="${ROOT_DIR}/requirements.txt"

export PYTHONPATH="${ROOT_DIR}/src${PYTHONPATH:+:${PYTHONPATH}}"

if [[ ! -x "${VENV_PYTHON}" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    BOOTSTRAP_PYTHON="python3"
  elif command -v python >/dev/null 2>&1; then
    BOOTSTRAP_PYTHON="python"
  else
    echo "Error: No python interpreter found (tried python3, python)" >&2
    exit 1
  fi

  echo "Creating virtual environment at ${VENV_DIR}..."
  "${BOOTSTRAP_PYTHON}" -m venv "${VENV_DIR}"
fi

PYTHON_BIN="${VENV_PYTHON}"

if [[ ! -f "${REQUIREMENTS_FILE}" ]]; then
  echo "Error: requirements file not found at ${REQUIREMENTS_FILE}" >&2
  exit 1
fi

if ! "${PYTHON_BIN}" - <<'PY'
from importlib.util import find_spec
import sys

required = ("PyQt6", "platformdirs", "pydantic")
missing = [name for name in required if find_spec(name) is None]
sys.exit(0 if not missing else 1)
PY
then
  echo "Installing Python dependencies into ${VENV_DIR}..."
  if ! "${PYTHON_BIN}" -m pip --version >/dev/null 2>&1; then
    "${PYTHON_BIN}" -m ensurepip --upgrade
  fi
  "${PYTHON_BIN}" -m pip install --upgrade pip
  "${PYTHON_BIN}" -m pip install -r "${REQUIREMENTS_FILE}"
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
