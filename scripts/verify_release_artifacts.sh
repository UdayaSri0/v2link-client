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

require_mode() {
  local expected="$1" path="$2"
  [[ "$(stat -c '%a' "${path}")" == "${expected}" ]] || \
    fail "unexpected mode for ${path}: expected ${expected}"
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

APPIMAGE="${APPIMAGES[0]}"
DEB="${DEBS[0]}"
[[ "$(basename "${APPIMAGE}")" == *"-linux-x86_64.AppImage" ]] || fail "unexpected AppImage architecture name"
[[ "$(basename "${DEB}")" == *"_amd64.deb" ]] || fail "unexpected Debian architecture name"
for artifact in "${APPIMAGE}" "${DEB}"; do
  artifact_name="$(basename "${artifact}")"
  grep -Eq "^[[:xdigit:]]{64} [ *]${artifact_name}$" "${DIST_DIR}/SHA256SUMS" || \
    fail "SHA256SUMS lacks current artifact: ${artifact_name}"
  (cd "${DIST_DIR}" && grep -E "^[[:xdigit:]]{64} [ *]${artifact_name}$" SHA256SUMS | sha256sum -c -)
done

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
if find "${APP_EXTRACT}/squashfs-root" \
  \( -name 'v2link-netmon' -o -name 'v2link-netmon.service' \) -print -quit | grep -q .; then
  fail "AppImage unexpectedly contains privileged v2link-netmon service assets"
fi

DEB_ROOT="${TMP_DIR}/deb"
mkdir -p "${DEB_ROOT}"
dpkg-deb -x "${DEB}" "${DEB_ROOT}"
DEB_CONTROL="${TMP_DIR}/deb-control"
mkdir -p "${DEB_CONTROL}"
dpkg-deb -e "${DEB}" "${DEB_CONTROL}"
DEB_ASSETS="${DEB_ROOT}/opt/v2link-client/xray"
DEB_XRAY="${DEB_ASSETS}/xray"
DEB_HELPER="${DEB_ROOT}/usr/lib/v2link-client/v2link-netmon"
DEB_UNIT="${DEB_ROOT}/lib/systemd/system/v2link-netmon.service"
for item in xray geoip.dat geosite.dat LICENSE VERSION; do
  require_file "${DEB_ASSETS}/${item}"
done
require_file "${DEB_ROOT}/usr/share/doc/v2link-client/THIRD_PARTY_NOTICES.md"
require_file "${DEB_HELPER}"
require_file "${DEB_UNIT}"
for script in postinst prerm postrm; do
  require_file "${DEB_CONTROL}/${script}"
  require_mode 755 "${DEB_CONTROL}/${script}"
  bash -n "${DEB_CONTROL}/${script}"
done
require_mode 755 "${DEB_HELPER}"
require_mode 644 "${DEB_UNIT}"
[[ -x "${DEB_XRAY}" ]] || fail "Debian Xray is not executable"
grep -Fq 'V2LINK_BUNDLED_XRAY_DIR="/opt/v2link-client/xray"' "${DEB_ROOT}/usr/bin/v2link-client"
grep -Fq 'XRAY_LOCATION_ASSET="/opt/v2link-client/xray"' "${DEB_ROOT}/usr/bin/v2link-client"
DEB_VERSION_OUTPUT="$(XRAY_LOCATION_ASSET="${DEB_ASSETS}" "${DEB_XRAY}" version)"
[[ "${DEB_VERSION_OUTPUT}" == *"Xray ${XRAY_VERSION#v}"* ]] || fail "Debian Xray version mismatch"
[[ "$(<"${DEB_ASSETS}/VERSION")" == "${XRAY_VERSION}" ]] || fail "Debian VERSION mismatch"
XRAY_LOCATION_ASSET="${DEB_ASSETS}" "${DEB_XRAY}" run -test -c "${CONFIG}" >/dev/null
[[ "$(dpkg-deb -f "${DEB}" Architecture)" == "amd64" ]] || fail "Debian package is not amd64"
[[ "$(dpkg-deb -f "${DEB}" Version)" == "${PROJECT_VERSION}" ]] || fail "Debian package version mismatch"
DEB_DEPENDS="$(dpkg-deb -f "${DEB}" Depends)"
[[ ", ${DEB_DEPENDS}, " == *", adduser, "* ]] || fail "Debian package lacks adduser dependency"
[[ ", ${DEB_DEPENDS}, " == *", init-system-helpers, "* ]] || fail "Debian package lacks init-system-helpers dependency"
file "${DEB_XRAY}" | grep -Eq 'x86-64|x86_64' || fail "Debian Xray is not x86-64"
file "${DEB_HELPER}" | grep -Eq 'x86-64|x86_64' || fail "Debian helper is not x86-64"

if dpkg-deb -c "${DEB}" | awk '{print $2}' | grep -Ev '^root/root$' >/dev/null; then
  fail "Debian archive contains entries not owned by root:root"
fi

grep -Fq 'User=v2link-netmon' "${DEB_UNIT}" || fail "netmon unit lacks dedicated user"
grep -Fq 'Group=v2link-netmon' "${DEB_UNIT}" || fail "netmon unit lacks dedicated group"
grep -Fq 'ExecStart=/usr/lib/v2link-client/v2link-netmon' "${DEB_UNIT}" || \
  fail "netmon unit has an unexpected helper path"
if grep -Eq 'CAP_SYS_ADMIN|CAP_BPF|CAP_PERFMON|CAP_NET_ADMIN' "${DEB_UNIT}"; then
  fail "netmon unit contains broad capabilities for the placeholder backend"
fi
if command -v systemd-analyze >/dev/null 2>&1; then
  # Verify against the extracted executable without requiring the package to be
  # installed on the CI host. All other unit directives remain unchanged.
  VERIFICATION_UNIT="${TMP_DIR}/v2link-netmon.service"
  sed "s|^ExecStart=/usr/lib/v2link-client/v2link-netmon$|ExecStart=${DEB_HELPER}|" \
    "${DEB_UNIT}" >"${VERIFICATION_UNIT}"
  systemd-analyze verify "${VERIFICATION_UNIT}" >/dev/null
else
  echo "Note: systemd-analyze unavailable; skipped unit verification." >&2
fi

echo "Verified AppImage: $(basename "${APPIMAGE}")"
echo "Verified Debian package: $(basename "${DEB}")"
echo "Bundled Xray-core: ${XRAY_VERSION}"
