#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

fail() {
  echo "Error: $*" >&2
  exit 1
}

require_file() {
  [[ -f "$1" ]] || fail "required file missing: $1"
}

PROJECT_VERSION="$(ROOT_DIR_ENV="${ROOT_DIR}" python3 - <<'PY'
import os, tomllib
from pathlib import Path
data = tomllib.loads((Path(os.environ["ROOT_DIR_ENV"]) / "pyproject.toml").read_text(encoding="utf-8"))
print(data["project"]["version"])
PY
)"
XRAY_VERSION="$(ROOT_DIR_ENV="${ROOT_DIR}" python3 - <<'PY'
import json, os
from pathlib import Path
print(json.loads((Path(os.environ["ROOT_DIR_ENV"]) / "packaging/xray-release.json").read_text(encoding="utf-8"))["version"])
PY
)"

mapfile -t APPIMAGES < <(find "${DIST_DIR}" -maxdepth 1 -type f -name "v2link-client-${PROJECT_VERSION}-linux-*.AppImage" -print)
mapfile -t DEBS < <(find "${DIST_DIR}" -maxdepth 1 -type f -name "v2link-client_${PROJECT_VERSION}_*.deb" -print)
[[ "${#APPIMAGES[@]}" -eq 1 ]] || fail "expected exactly one x86-64 AppImage for ${PROJECT_VERSION}"
[[ "${#DEBS[@]}" -eq 1 ]] || fail "expected exactly one amd64 Debian package for ${PROJECT_VERSION}"
require_file "${DIST_DIR}/SHA256SUMS"
(cd "${DIST_DIR}" && sha256sum -c SHA256SUMS)

APPIMAGE="${APPIMAGES[0]}"
DEB="${DEBS[0]}"
[[ "$(basename "${APPIMAGE}")" == *"-linux-x86_64.AppImage" ]] || fail "unexpected AppImage architecture name"
[[ "$(basename "${DEB}")" == *"_amd64.deb" ]] || fail "unexpected Debian architecture name"

APP_EXTRACT="${TMP_DIR}/appimage"
mkdir -p "${APP_EXTRACT}"
(cd "${APP_EXTRACT}" && APPIMAGE_EXTRACT_AND_RUN=1 "${APPIMAGE}" --appimage-extract >/dev/null)
APP_XRAY="${APP_EXTRACT}/squashfs-root/usr/bin/xray/xray"
APP_ASSETS="$(dirname "${APP_XRAY}")"
for item in xray geoip.dat geosite.dat LICENSE VERSION; do
  require_file "${APP_ASSETS}/${item}"
done
[[ -x "${APP_XRAY}" ]] || fail "AppImage Xray is not executable"
# shellcheck disable=SC2016 # These assertions intentionally match literal launcher variables.
grep -Fq 'V2LINK_BUNDLED_XRAY_DIR="${APPDIR}/usr/bin/xray"' "${APP_EXTRACT}/squashfs-root/AppRun"
# shellcheck disable=SC2016 # These assertions intentionally match literal launcher variables.
grep -Fq 'XRAY_LOCATION_ASSET="${APPDIR}/usr/bin/xray"' "${APP_EXTRACT}/squashfs-root/AppRun"
APP_VERSION_OUTPUT="$(XRAY_LOCATION_ASSET="${APP_ASSETS}" "${APP_XRAY}" version)"
[[ "${APP_VERSION_OUTPUT}" == *"Xray ${XRAY_VERSION#v}"* ]] || fail "AppImage Xray version mismatch"
[[ "$(<"${APP_ASSETS}/VERSION")" == "${XRAY_VERSION}" ]] || fail "AppImage VERSION mismatch"

CONFIG="${TMP_DIR}/minimal-xray.json"
printf '%s\n' '{"log":{"loglevel":"none"},"inbounds":[],"outbounds":[{"protocol":"freedom","settings":{}}]}' >"${CONFIG}"
XRAY_LOCATION_ASSET="${APP_ASSETS}" "${APP_XRAY}" run -test -c "${CONFIG}" >/dev/null

DEB_ROOT="${TMP_DIR}/deb"
mkdir -p "${DEB_ROOT}"
dpkg-deb -x "${DEB}" "${DEB_ROOT}"
DEB_ASSETS="${DEB_ROOT}/opt/v2link-client/xray"
DEB_XRAY="${DEB_ASSETS}/xray"
for item in xray geoip.dat geosite.dat LICENSE VERSION; do
  require_file "${DEB_ASSETS}/${item}"
done
require_file "${DEB_ROOT}/usr/share/doc/v2link-client/THIRD_PARTY_NOTICES.md"
[[ -x "${DEB_XRAY}" ]] || fail "Debian Xray is not executable"
grep -Fq 'V2LINK_BUNDLED_XRAY_DIR="/opt/v2link-client/xray"' "${DEB_ROOT}/usr/bin/v2link-client"
grep -Fq 'XRAY_LOCATION_ASSET="/opt/v2link-client/xray"' "${DEB_ROOT}/usr/bin/v2link-client"
DEB_VERSION_OUTPUT="$(XRAY_LOCATION_ASSET="${DEB_ASSETS}" "${DEB_XRAY}" version)"
[[ "${DEB_VERSION_OUTPUT}" == *"Xray ${XRAY_VERSION#v}"* ]] || fail "Debian Xray version mismatch"
[[ "$(<"${DEB_ASSETS}/VERSION")" == "${XRAY_VERSION}" ]] || fail "Debian VERSION mismatch"
XRAY_LOCATION_ASSET="${DEB_ASSETS}" "${DEB_XRAY}" run -test -c "${CONFIG}" >/dev/null
[[ "$(dpkg-deb -f "${DEB}" Architecture)" == "amd64" ]] || fail "Debian package is not amd64"
file "${DEB_XRAY}" | grep -Eq 'x86-64|x86_64' || fail "Debian Xray is not x86-64"

echo "Verified AppImage: $(basename "${APPIMAGE}")"
echo "Verified Debian package: $(basename "${DEB}")"
echo "Bundled Xray-core: ${XRAY_VERSION}"
