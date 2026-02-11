#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"

"${ROOT_DIR}/scripts/build_pyinstaller.sh"
"${ROOT_DIR}/scripts/build_appimage.sh"

cd "${DIST_DIR}"
sha256sum ./*.AppImage > SHA256SUMS

echo "Release artifacts:"
ls -1 "${DIST_DIR}"
