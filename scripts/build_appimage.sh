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

  "${PYTHON_BIN}" - <<'PY'
from pathlib import Path
import tomllib

data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
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
  local url
  case "${arch}" in
    x86_64) url="https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage" ;;
    aarch64) url="https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-aarch64.AppImage" ;;
    *) echo "Error: unsupported architecture ${arch}" >&2; exit 1 ;;
  esac

  mkdir -p "${TOOLS_DIR}"
  local target="${TOOLS_DIR}/appimagetool-${arch}.AppImage"
  if [[ ! -x "${target}" ]]; then
    echo "Downloading appimagetool..." >&2
    curl -fsSL "${url}" -o "${target}"
    chmod +x "${target}"
  fi

  echo "${target}"
}

ARCH_NAME="${ARCH:-$(normalize_arch)}"
VERSION_NAME="$(detect_version)"
APPIMAGE_TOOL_BIN="$(resolve_appimagetool)"
OUTPUT_FILE="${DIST_DIR}/${APP_NAME}-${VERSION_NAME}-linux-${ARCH_NAME}.AppImage"

rm -rf "${APPDIR}"
mkdir -p "${APPDIR}/usr/bin"
cp -a "${PYINSTALLER_DIR}/." "${APPDIR}/usr/bin/"
cp "${DESKTOP_SRC}" "${APPDIR}/${APP_NAME}.desktop"
cp "${ICON_SRC}" "${APPDIR}/${APP_NAME}.png"

cat >"${APPDIR}/AppRun" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
APPDIR="$(cd "$(dirname "$0")" && pwd)"
exec "${APPDIR}/usr/bin/v2link-client" "$@"
EOF
chmod +x "${APPDIR}/AppRun"

rm -f "${OUTPUT_FILE}"
echo "Building AppImage with ${APPIMAGE_TOOL_BIN}..."
ARCH="${ARCH_NAME}" VERSION="${VERSION_NAME}" APPIMAGE_EXTRACT_AND_RUN=1 \
  "${APPIMAGE_TOOL_BIN}" "${APPDIR}" "${OUTPUT_FILE}"
chmod +x "${OUTPUT_FILE}"

echo "AppImage ready: ${OUTPUT_FILE}"
