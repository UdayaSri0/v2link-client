#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"

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
