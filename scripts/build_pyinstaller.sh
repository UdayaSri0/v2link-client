#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_NAME="v2link-client"
ENTRYPOINT="${ROOT_DIR}/src/v2link_client/main.py"
DIST_DIR="${ROOT_DIR}/dist"
WORK_DIR="${ROOT_DIR}/build/pyinstaller"
SPEC_DIR="${ROOT_DIR}/build"

if [[ -x "${ROOT_DIR}/.venv/bin/python" ]]; then
  PYTHON_BIN="${ROOT_DIR}/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
else
  echo "Error: python interpreter not found." >&2
  exit 1
fi

if [[ ! -f "${ENTRYPOINT}" ]]; then
  echo "Error: entrypoint not found at ${ENTRYPOINT}" >&2
  exit 1
fi

if ! "${PYTHON_BIN}" -c "import PyInstaller" >/dev/null 2>&1; then
  echo "Installing PyInstaller..."
  "${PYTHON_BIN}" -m pip install --upgrade pyinstaller
fi

mkdir -p "${DIST_DIR}" "${WORK_DIR}" "${SPEC_DIR}"
rm -rf "${DIST_DIR:?}/${APP_NAME}" "${WORK_DIR:?}"/*

echo "Building ${APP_NAME} with ${PYTHON_BIN}..."
PYTHONPATH="${ROOT_DIR}/src${PYTHONPATH:+:${PYTHONPATH}}" \
  "${PYTHON_BIN}" -m PyInstaller \
  --noconfirm \
  --clean \
  --windowed \
  --onedir \
  --name "${APP_NAME}" \
  --paths "${ROOT_DIR}/src" \
  --distpath "${DIST_DIR}" \
  --workpath "${WORK_DIR}" \
  --specpath "${SPEC_DIR}" \
  "${ENTRYPOINT}"

OUTPUT_BIN="${DIST_DIR}/${APP_NAME}/${APP_NAME}"
if [[ ! -x "${OUTPUT_BIN}" ]]; then
  echo "Error: expected binary not found at ${OUTPUT_BIN}" >&2
  exit 1
fi

echo "PyInstaller output ready: ${DIST_DIR}/${APP_NAME}"
