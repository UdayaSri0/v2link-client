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

mkdir -p "${DIST_DIR}"
rm -f "${DIST_DIR}"/*.AppImage "${DIST_DIR}"/*.deb "${DIST_DIR}/SHA256SUMS"

"${ROOT_DIR}/scripts/fetch_xray_core.sh"
"${ROOT_DIR}/scripts/build_pyinstaller.sh"
"${ROOT_DIR}/scripts/build_appimage.sh"
"${ROOT_DIR}/scripts/build_netmon.sh"
"${ROOT_DIR}/scripts/build_deb.sh"

if ! compgen -G "${DIST_DIR}/*.AppImage" >/dev/null; then
  echo "Error: no AppImage artifact found in ${DIST_DIR}" >&2
  exit 1
fi

if ! compgen -G "${DIST_DIR}/*.deb" >/dev/null; then
  echo "Error: no .deb artifact found in ${DIST_DIR}" >&2
  exit 1
fi

if [[ ! -x "${ROOT_DIR}/build/AppDir/usr/bin/xray/xray" ]]; then
  echo "Error: AppImage layout missing bundled Xray binary." >&2
  exit 1
fi
if [[ ! -f "${ROOT_DIR}/build/AppDir/usr/bin/xray/geoip.dat" || ! -f "${ROOT_DIR}/build/AppDir/usr/bin/xray/geosite.dat" ]]; then
  echo "Error: AppImage layout missing bundled Xray geo assets." >&2
  exit 1
fi
if find "${ROOT_DIR}/build/AppDir" \
  \( -name 'v2link-netmon' -o -name 'v2link-netmon.service' \) -print -quit | grep -q .; then
  echo "Error: AppImage layout contains privileged v2link-netmon service assets." >&2
  exit 1
fi

DEB_TREE="$(find "${ROOT_DIR}/build/deb" -maxdepth 1 -type d -name 'v2link-client_*' | sort | tail -n 1)"
if [[ -z "${DEB_TREE}" ]]; then
  echo "Error: Debian package tree not found." >&2
  exit 1
fi
if [[ ! -x "${DEB_TREE}/opt/v2link-client/xray/xray" ]]; then
  echo "Error: .deb layout missing bundled Xray binary." >&2
  exit 1
fi
if [[ ! -f "${DEB_TREE}/opt/v2link-client/xray/geoip.dat" || ! -f "${DEB_TREE}/opt/v2link-client/xray/geosite.dat" ]]; then
  echo "Error: .deb layout missing bundled Xray geo assets." >&2
  exit 1
fi
if [[ ! -x "${DEB_TREE}/usr/lib/v2link-client/v2link-netmon" ]]; then
  echo "Error: .deb layout missing v2link-netmon helper." >&2
  exit 1
fi
for required_file in \
  "${DEB_TREE}/lib/systemd/system/v2link-netmon.service" \
  "${DEB_TREE}/DEBIAN/postinst" \
  "${DEB_TREE}/DEBIAN/prerm" \
  "${DEB_TREE}/DEBIAN/postrm"; do
  if [[ ! -f "${required_file}" ]]; then
    echo "Error: .deb layout missing required netmon package asset: ${required_file}" >&2
    exit 1
  fi
done

cd "${DIST_DIR}"
sha256sum ./*.AppImage ./*.deb > SHA256SUMS
cd "${ROOT_DIR}"
"${ROOT_DIR}/scripts/verify_release_artifacts.sh"

echo "Release artifacts:"
ls -1 "${DIST_DIR}"
