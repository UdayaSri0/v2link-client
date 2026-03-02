#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_NAME="v2link-client"
DIST_DIR="${ROOT_DIR}/dist"
PYINSTALLER_DIR="${DIST_DIR}/${APP_NAME}"
BUILD_DIR="${ROOT_DIR}/build/deb"
DEB_TEMPLATE_DIR="${ROOT_DIR}/packaging/deb"
CONTROL_TEMPLATE="${DEB_TEMPLATE_DIR}/control.in"
WRAPPER_TEMPLATE="${DEB_TEMPLATE_DIR}/v2link-client-wrapper.in"
DESKTOP_SRC="${DEB_TEMPLATE_DIR}/v2link-client.desktop"
ICON_SRC="${ROOT_DIR}/packaging/icon.png"
DEPENDS="libegl1, libgl1, libxkbcommon-x11-0, libdbus-1-3, libxcb-cursor0"

if [[ ! -d "${PYINSTALLER_DIR}" ]]; then
  "${ROOT_DIR}/scripts/build_pyinstaller.sh"
fi

for required_file in \
  "${CONTROL_TEMPLATE}" \
  "${WRAPPER_TEMPLATE}" \
  "${DESKTOP_SRC}" \
  "${ICON_SRC}" \
  "${DEB_TEMPLATE_DIR}/postinst" \
  "${DEB_TEMPLATE_DIR}/postrm"; do
  if [[ ! -f "${required_file}" ]]; then
    echo "Error: required file not found: ${required_file}" >&2
    exit 1
  fi
done

if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "Error: dpkg-deb is required to build .deb packages." >&2
  exit 1
fi

normalize_arch() {
  local raw_arch="${ARCH:-$(uname -m)}"
  case "${raw_arch}" in
    x86_64 | amd64) echo "amd64" ;;
    aarch64 | arm64) echo "arm64" ;;
    *)
      echo "Error: unsupported architecture ${raw_arch}" >&2
      exit 1
      ;;
  esac
}

detect_version() {
  if [[ -n "${VERSION:-}" ]]; then
    echo "${VERSION#v}"
    return
  fi

  if git -C "${ROOT_DIR}" describe --tags --exact-match >/dev/null 2>&1; then
    git -C "${ROOT_DIR}" describe --tags --exact-match | sed 's/^v//'
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
print(data["project"]["version"])
PY
}

sanitize_deb_version() {
  local version="$1"
  version="${version#v}"
  version="${version//_/+}"
  version="$(echo "${version}" | sed 's/[^0-9A-Za-z.+:~-]/+/g')"
  version="$(echo "${version}" | sed 's/^+*//; s/+*$//')"
  if [[ -z "${version}" ]]; then
    echo "Error: resolved Debian version is empty." >&2
    exit 1
  fi
  echo "${version}"
}

ARCH_NAME="$(normalize_arch)"
VERSION_NAME="$(sanitize_deb_version "$(detect_version)")"
PKG_DIR="${BUILD_DIR}/${APP_NAME}_${VERSION_NAME}_${ARCH_NAME}"
DEBIAN_DIR="${PKG_DIR}/DEBIAN"
OPT_DIR="${PKG_DIR}/opt/${APP_NAME}"
BIN_DIR="${PKG_DIR}/usr/bin"
APPS_DIR="${PKG_DIR}/usr/share/applications"
ICON_DIR="${PKG_DIR}/usr/share/icons/hicolor/256x256/apps"
OUTPUT_DEB="${DIST_DIR}/${APP_NAME}_${VERSION_NAME}_${ARCH_NAME}.deb"

rm -rf "${PKG_DIR}"
mkdir -p "${DEBIAN_DIR}" "${OPT_DIR}" "${BIN_DIR}" "${APPS_DIR}" "${ICON_DIR}"

cp -a "${PYINSTALLER_DIR}/." "${OPT_DIR}/"
cp "${DESKTOP_SRC}" "${APPS_DIR}/${APP_NAME}.desktop"
cp "${ICON_SRC}" "${ICON_DIR}/${APP_NAME}.png"

sed \
  -e "s|@VERSION@|${VERSION_NAME}|g" \
  "${WRAPPER_TEMPLATE}" >"${BIN_DIR}/${APP_NAME}"

sed \
  -e "s|@PACKAGE@|${APP_NAME}|g" \
  -e "s|@VERSION@|${VERSION_NAME}|g" \
  -e "s|@ARCH@|${ARCH_NAME}|g" \
  -e "s|@DEPENDS@|${DEPENDS}|g" \
  "${CONTROL_TEMPLATE}" >"${DEBIAN_DIR}/control"

cp "${DEB_TEMPLATE_DIR}/postinst" "${DEBIAN_DIR}/postinst"
cp "${DEB_TEMPLATE_DIR}/postrm" "${DEBIAN_DIR}/postrm"

chmod 0755 "${BIN_DIR}/${APP_NAME}" "${DEBIAN_DIR}/postinst" "${DEBIAN_DIR}/postrm"
chmod 0755 "${OPT_DIR}/${APP_NAME}" || true

rm -f "${OUTPUT_DEB}"
dpkg-deb --build --root-owner-group "${PKG_DIR}" "${OUTPUT_DEB}" >/dev/null

if [[ ! -f "${OUTPUT_DEB}" ]]; then
  echo "Error: expected .deb not produced at ${OUTPUT_DEB}" >&2
  exit 1
fi

echo ".deb ready: ${OUTPUT_DEB}"
