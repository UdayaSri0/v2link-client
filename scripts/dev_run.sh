#!/usr/bin/env bash
set -euo pipefail

export PYTHONPATH="${PYTHONPATH:-}:$(pwd)/src"

if [[ "$(uname -s)" == "Linux" ]]; then
  if ! ldconfig -p 2>/dev/null | grep -q "libxcb-cursor.so.0"; then
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

"${PYTHON_BIN}" -m v2link_client.main
