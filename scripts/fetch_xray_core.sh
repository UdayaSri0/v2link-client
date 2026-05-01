#!/usr/bin/env bash
set -euo pipefail

XRAY_VERSION="v26.3.27"
XRAY_SHA256_X86_64="23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae"
XRAY_SHA256_AARCH64="4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR_ROOT="${ROOT_DIR}/vendor/xray"

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Error: $1 is required to fetch Xray-core." >&2
    exit 1
  fi
}

normalize_arch() {
  local raw_arch="${ARCH:-$(uname -m)}"
  case "${raw_arch}" in
    x86_64 | amd64) echo "x86_64" ;;
    aarch64 | arm64) echo "aarch64" ;;
    *)
      echo "Error: unsupported architecture ${raw_arch}" >&2
      exit 1
      ;;
  esac
}

asset_for_arch() {
  case "$1" in
    x86_64) echo "Xray-linux-64.zip" ;;
    aarch64) echo "Xray-linux-arm64-v8a.zip" ;;
    *) echo "Error: unsupported architecture $1" >&2; exit 1 ;;
  esac
}

sha_for_arch() {
  case "$1" in
    x86_64) echo "${XRAY_SHA256_X86_64}" ;;
    aarch64) echo "${XRAY_SHA256_AARCH64}" ;;
    *) echo "Error: unsupported architecture $1" >&2; exit 1 ;;
  esac
}

verify_sha_is_set() {
  local sha="$1"
  local arch="$2"
  if [[ -z "${sha}" || "${sha}" == *"PLACEHOLDER"* || "${sha}" == "..." ]]; then
    echo "Error: SHA256 for Xray ${arch} is not set." >&2
    echo "Set XRAY_SHA256_${arch^^} to the official digest before release." >&2
    exit 1
  fi
}

copy_required_file() {
  local src="$1"
  local dest="$2"
  local label="$3"
  if [[ ! -f "${src}" ]]; then
    echo "Error: Xray archive structure changed; missing ${label} at ${src}" >&2
    exit 1
  fi
  cp "${src}" "${dest}"
}

require_tool curl
require_tool unzip
require_tool sha256sum

ARCH_NAME="$(normalize_arch)"
ASSET_NAME="$(asset_for_arch "${ARCH_NAME}")"
EXPECTED_SHA="$(sha_for_arch "${ARCH_NAME}")"
verify_sha_is_set "${EXPECTED_SHA}" "${ARCH_NAME}"

URL="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/${ASSET_NAME}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

ARCHIVE="${TMP_DIR}/${ASSET_NAME}"
EXTRACT_DIR="${TMP_DIR}/extract"
TARGET_DIR="${VENDOR_ROOT}/${ARCH_NAME}"

echo "Fetching Xray-core ${XRAY_VERSION} for ${ARCH_NAME} from official GitHub Releases..."
curl -fL "${URL}" -o "${ARCHIVE}"
printf '%s  %s\n' "${EXPECTED_SHA}" "${ARCHIVE}" | sha256sum -c -

mkdir -p "${EXTRACT_DIR}"
unzip -q "${ARCHIVE}" -d "${EXTRACT_DIR}"

rm -rf "${TARGET_DIR}"
mkdir -p "${TARGET_DIR}"

copy_required_file "${EXTRACT_DIR}/xray" "${TARGET_DIR}/xray" "xray"
copy_required_file "${EXTRACT_DIR}/geoip.dat" "${TARGET_DIR}/geoip.dat" "geoip.dat"
copy_required_file "${EXTRACT_DIR}/geosite.dat" "${TARGET_DIR}/geosite.dat" "geosite.dat"

if [[ -f "${EXTRACT_DIR}/LICENSE" ]]; then
  cp "${EXTRACT_DIR}/LICENSE" "${TARGET_DIR}/LICENSE"
elif [[ -f "${EXTRACT_DIR}/LICENSE.txt" ]]; then
  cp "${EXTRACT_DIR}/LICENSE.txt" "${TARGET_DIR}/LICENSE"
else
  echo "Error: Xray archive structure changed; missing LICENSE" >&2
  exit 1
fi

if [[ -f "${EXTRACT_DIR}/README.md" ]]; then
  cp "${EXTRACT_DIR}/README.md" "${TARGET_DIR}/README.md"
fi

printf '%s\n' "${XRAY_VERSION}" >"${TARGET_DIR}/VERSION"
chmod 0755 "${TARGET_DIR}/xray"
chmod 0644 "${TARGET_DIR}/geoip.dat" "${TARGET_DIR}/geosite.dat" "${TARGET_DIR}/LICENSE" "${TARGET_DIR}/VERSION"

echo "Bundled Xray-core ready: ${TARGET_DIR}"
