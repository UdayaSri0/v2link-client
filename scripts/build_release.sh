#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"

resolve_version() {
  if [[ -n "${VERSION:-}" ]]; then
    echo "${VERSION#v}"
    return
  fi

  if [[ -x "${ROOT_DIR}/.venv/bin/python" ]]; then
    PYTHON_BIN="${ROOT_DIR}/.venv/bin/python"
  elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
  else
    PYTHON_BIN="python"
  fi

  ROOT_DIR_ENV="${ROOT_DIR}" "${PYTHON_BIN}" - <<'PY'
import os
from pathlib import Path
import tomllib

pyproject = Path(os.environ["ROOT_DIR_ENV"]) / "pyproject.toml"
data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
print(str(data["project"]["version"]).strip())
PY
}

VERSION_NAME="$(resolve_version)"
if [[ -z "${VERSION_NAME}" ]]; then
  echo "Error: failed to resolve project version." >&2
  exit 1
fi

export VERSION="${VERSION_NAME}"
echo "Building release artifacts for v${VERSION_NAME}..."

"${ROOT_DIR}/scripts/build_pyinstaller.sh"
"${ROOT_DIR}/scripts/build_appimage.sh"
"${ROOT_DIR}/scripts/build_deb.sh"

if ! compgen -G "${DIST_DIR}/*.AppImage" >/dev/null; then
  echo "Error: no AppImage artifact found in ${DIST_DIR}" >&2
  exit 1
fi

if ! compgen -G "${DIST_DIR}/*.deb" >/dev/null; then
  echo "Error: no .deb artifact found in ${DIST_DIR}" >&2
  exit 1
fi

cd "${DIST_DIR}"
sha256sum ./*.AppImage ./*.deb > SHA256SUMS

echo "Release artifacts:"
ls -1 "${DIST_DIR}"
