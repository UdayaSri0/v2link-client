#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_NAME="v2link-client"
DIST_DIR="${ROOT_DIR}/dist"
APPDIR="${ROOT_DIR}/build/AppDir"
PYINSTALLER_DIR="${DIST_DIR}/${APP_NAME}"
DESKTOP_SRC="${ROOT_DIR}/packaging/app.desktop"
ICON_SRC="${ROOT_DIR}/packaging/icon.png"
TOOLS_DIR="${ROOT_DIR}/tools"
APPIMAGETOOL_VERSION="12"
APPIMAGETOOL_SHA256_X86_64="d918b4df547b388ef253f3c9e7f6529ca81a885395c31f619d9aaf7030499a13"
APPIMAGETOOL_SHA256_AARCH64="c9d058310a4e04b9fbbd81340fff2b5fb44943a630b31881e321719f271bd41a"

if [[ ! -d "${PYINSTALLER_DIR}" ]]; then
  "${ROOT_DIR}/scripts/build_pyinstaller.sh"
fi

if [[ ! -f "${DESKTOP_SRC}" ]]; then
  echo "Error: missing desktop entry at ${DESKTOP_SRC}" >&2
  exit 1
fi

if [[ ! -f "${ICON_SRC}" ]]; then
  echo "Error: missing icon file at ${ICON_SRC}" >&2
  exit 1
fi

normalize_arch() {
  case "$(uname -m)" in
    x86_64 | amd64) echo "x86_64" ;;
    aarch64 | arm64) echo "aarch64" ;;
    *)
      echo "Error: unsupported architecture $(uname -m)" >&2
      exit 1
      ;;
  esac
}

detect_version() {
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

data = tomllib.loads((Path(os.environ["ROOT_DIR_ENV"]) / "pyproject.toml").read_text(encoding="utf-8"))
print(data["project"]["version"])
PY
}

resolve_appimagetool() {
  if [[ -n "${APPIMAGETOOL:-}" && -x "${APPIMAGETOOL}" ]]; then
    echo "${APPIMAGETOOL}"
    return
  fi

  if command -v appimagetool >/dev/null 2>&1; then
    command -v appimagetool
    return
  fi

  local arch
  arch="$(normalize_arch)"
  local url expected_sha
  case "${arch}" in
    x86_64)
      url="https://github.com/AppImage/AppImageKit/releases/download/${APPIMAGETOOL_VERSION}/appimagetool-x86_64.AppImage"
      expected_sha="${APPIMAGETOOL_SHA256_X86_64}"
      ;;
    aarch64)
      url="https://github.com/AppImage/AppImageKit/releases/download/${APPIMAGETOOL_VERSION}/appimagetool-aarch64.AppImage"
      expected_sha="${APPIMAGETOOL_SHA256_AARCH64}"
      ;;
    *) echo "Error: unsupported architecture ${arch}" >&2; exit 1 ;;
  esac

  mkdir -p "${TOOLS_DIR}"
  local target="${TOOLS_DIR}/appimagetool-${APPIMAGETOOL_VERSION}-${arch}.AppImage"
  if [[ ! -f "${target}" ]] || ! printf '%s  %s\n' "${expected_sha}" "${target}" | sha256sum -c - >/dev/null 2>&1; then
    echo "Downloading appimagetool..." >&2
    local temporary="${target}.download"
    curl --fail --location --silent --show-error --retry 4 --retry-all-errors "${url}" -o "${temporary}"
    printf '%s  %s\n' "${expected_sha}" "${temporary}" | sha256sum -c - >&2
    mv "${temporary}" "${target}"
  fi
  chmod 0755 "${target}"

  echo "${target}"
}

ARCH_NAME="${ARCH:-$(normalize_arch)}"
VERSION_NAME="$(detect_version)"
APPIMAGE_TOOL_BIN="$(resolve_appimagetool)"
OUTPUT_FILE="${DIST_DIR}/${APP_NAME}-${VERSION_NAME}-linux-${ARCH_NAME}.AppImage"
XRAY_VENDOR_DIR="${ROOT_DIR}/vendor/xray/${ARCH_NAME}"

ensure_bundled_xray() {
  if [[ ! -x "${XRAY_VENDOR_DIR}/xray" || ! -f "${XRAY_VENDOR_DIR}/geoip.dat" || ! -f "${XRAY_VENDOR_DIR}/geosite.dat" ]]; then
    ARCH="${ARCH_NAME}" "${ROOT_DIR}/scripts/fetch_xray_core.sh"
  fi
  for required_file in xray geoip.dat geosite.dat LICENSE VERSION; do
    if [[ ! -e "${XRAY_VENDOR_DIR}/${required_file}" ]]; then
      echo "Error: bundled Xray file missing: ${XRAY_VENDOR_DIR}/${required_file}" >&2
      exit 1
    fi
  done
}

ensure_bundled_xray

rm -rf "${APPDIR}"
mkdir -p "${APPDIR}/usr/bin" "${APPDIR}/usr/bin/xray"
cp -a "${PYINSTALLER_DIR}/." "${APPDIR}/usr/bin/"
cp "${XRAY_VENDOR_DIR}/xray" "${APPDIR}/usr/bin/xray/xray"
cp "${XRAY_VENDOR_DIR}/geoip.dat" "${APPDIR}/usr/bin/xray/geoip.dat"
cp "${XRAY_VENDOR_DIR}/geosite.dat" "${APPDIR}/usr/bin/xray/geosite.dat"
cp "${XRAY_VENDOR_DIR}/LICENSE" "${APPDIR}/usr/bin/xray/LICENSE"
cp "${XRAY_VENDOR_DIR}/VERSION" "${APPDIR}/usr/bin/xray/VERSION"
cp "${DESKTOP_SRC}" "${APPDIR}/${APP_NAME}.desktop"
cp "${ICON_SRC}" "${APPDIR}/${APP_NAME}.png"
chmod 0755 "${APPDIR}/usr/bin/xray/xray"

cat >"${APPDIR}/AppRun" <<EOF
#!/usr/bin/env bash
set -euo pipefail
APPDIR="\$(cd "\$(dirname "\$0")" && pwd)"
export V2LINK_CLIENT_VERSION="${VERSION_NAME}"
export V2LINK_BUNDLED_XRAY_DIR="\${APPDIR}/usr/bin/xray"
export XRAY_LOCATION_ASSET="\${APPDIR}/usr/bin/xray"
exec "\${APPDIR}/usr/bin/v2link-client" "\$@"
EOF
chmod +x "${APPDIR}/AppRun"

for required_file in xray geoip.dat geosite.dat LICENSE VERSION; do
  if [[ ! -e "${APPDIR}/usr/bin/xray/${required_file}" ]]; then
    echo "Error: AppDir missing bundled Xray file: ${required_file}" >&2
    exit 1
  fi
done

# AppImages remain unprivileged. A netmon helper must be installed separately.
if find "${APPDIR}" \( -name 'v2link-netmon' -o -name 'v2link-netmon.service' \) -print -quit | grep -q .; then
  echo "Error: AppDir must not contain privileged v2link-netmon service assets." >&2
  exit 1
fi

rm -f "${OUTPUT_FILE}"
echo "Building AppImage with ${APPIMAGE_TOOL_BIN}..."
ARCH="${ARCH_NAME}" VERSION="${VERSION_NAME}" APPIMAGE_EXTRACT_AND_RUN=1 \
  "${APPIMAGE_TOOL_BIN}" "${APPDIR}" "${OUTPUT_FILE}"
chmod +x "${OUTPUT_FILE}"

echo "AppImage ready: ${OUTPUT_FILE}"
