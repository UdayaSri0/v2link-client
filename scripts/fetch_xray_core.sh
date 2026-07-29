#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR_ROOT="${ROOT_DIR}/vendor/xray"
MANIFEST="${ROOT_DIR}/packaging/xray-release.json"
VERIFY_ONLY=0

if [[ "${1:-}" == "--verify-existing" ]]; then
  VERIFY_ONLY=1
  shift
fi
if [[ "$#" -ne 0 ]]; then
  echo "Usage: $0 [--verify-existing]" >&2
  exit 2
fi

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
  manifest_value "$1" filename
}

sha_for_arch() {
  manifest_value "$1" sha256
}

manifest_value() {
  local arch="$1"
  local field="$2"
  MANIFEST_PATH="${MANIFEST}" MANIFEST_ARCH="${arch}" MANIFEST_FIELD="${field}" python3 - <<'PY'
import json, os
from pathlib import Path
data = json.loads(Path(os.environ["MANIFEST_PATH"]).read_text(encoding="utf-8"))
print(data["assets"][os.environ["MANIFEST_ARCH"]][os.environ["MANIFEST_FIELD"]])
PY
}

verify_sha_is_set() {
  local sha="$1"
  local arch="$2"
  if [[ ! "${sha}" =~ ^[0-9a-fA-F]{64}$ || "${sha}" =~ ^(0{64}|f{64})$ ]]; then
    echo "Error: SHA256 for Xray ${arch} is not set." >&2
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

require_tool sha256sum
require_tool python3

if [[ ! -s "${MANIFEST}" ]]; then
  echo "Error: Xray release manifest missing: ${MANIFEST}" >&2
  exit 1
fi

ARCH_NAME="$(normalize_arch)"
XRAY_VERSION="$(MANIFEST_PATH="${MANIFEST}" python3 - <<'PY'
import json, os
from pathlib import Path
print(json.loads(Path(os.environ["MANIFEST_PATH"]).read_text(encoding="utf-8"))["version"])
PY
)"
ASSET_NAME="$(asset_for_arch "${ARCH_NAME}")"
EXPECTED_SHA="$(sha_for_arch "${ARCH_NAME}")"
verify_sha_is_set "${EXPECTED_SHA}" "${ARCH_NAME}"

URL="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/${ASSET_NAME}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

ARCHIVE="${TMP_DIR}/${ASSET_NAME}"
EXTRACT_DIR="${TMP_DIR}/extract"
TARGET_DIR="${VENDOR_ROOT}/${ARCH_NAME}"

verify_directory() {
  local directory="$1"
  local required_file
  for required_file in xray geoip.dat geosite.dat LICENSE VERSION; do
    if [[ ! -f "${directory}/${required_file}" ]]; then
      echo "Error: bundled Xray file missing: ${directory}/${required_file}" >&2
      return 1
    fi
  done
  if [[ ! -x "${directory}/xray" ]]; then
    echo "Error: bundled Xray is not executable: ${directory}/xray" >&2
    return 1
  fi
  local recorded_version reported_version
  recorded_version="$(tr -d '[:space:]' <"${directory}/VERSION")"
  if [[ "${recorded_version}" != "${XRAY_VERSION}" ]]; then
    echo "Error: VERSION records ${recorded_version:-nothing}, expected ${XRAY_VERSION}" >&2
    return 1
  fi
  reported_version="$("${directory}/xray" version 2>&1)" || {
    echo "Error: bundled Xray version command failed." >&2
    return 1
  }
  if [[ ! "${reported_version}" =~ Xray[[:space:]]+${XRAY_VERSION#v}([^0-9.]|$) ]]; then
    echo "Error: bundled Xray reports an unexpected version: ${reported_version%%$'\n'*}" >&2
    return 1
  fi
}

if [[ "${VERIFY_ONLY}" -eq 1 ]]; then
  verify_directory "${TARGET_DIR}"
  echo "Bundled Xray-core verified: ${TARGET_DIR}"
  exit 0
fi

require_tool curl
require_tool unzip
echo "Fetching Xray-core ${XRAY_VERSION} for ${ARCH_NAME} from official GitHub Releases..."
curl --fail --location --silent --show-error --retry 4 --retry-delay 2 \
  --retry-all-errors "${URL}" -o "${ARCHIVE}"
printf '%s  %s\n' "${EXPECTED_SHA}" "${ARCHIVE}" | sha256sum -c -

mkdir -p "${EXTRACT_DIR}"
unzip -q "${ARCHIVE}" -d "${EXTRACT_DIR}"

STAGED_DIR="${TMP_DIR}/vendor-ready"
mkdir -p "${STAGED_DIR}"

copy_required_file "${EXTRACT_DIR}/xray" "${STAGED_DIR}/xray" "xray"
copy_required_file "${EXTRACT_DIR}/geoip.dat" "${STAGED_DIR}/geoip.dat" "geoip.dat"
copy_required_file "${EXTRACT_DIR}/geosite.dat" "${STAGED_DIR}/geosite.dat" "geosite.dat"

if [[ -f "${EXTRACT_DIR}/LICENSE" ]]; then
  cp "${EXTRACT_DIR}/LICENSE" "${STAGED_DIR}/LICENSE"
elif [[ -f "${EXTRACT_DIR}/LICENSE.txt" ]]; then
  cp "${EXTRACT_DIR}/LICENSE.txt" "${STAGED_DIR}/LICENSE"
else
  echo "Error: Xray archive structure changed; missing LICENSE" >&2
  exit 1
fi

if [[ -f "${EXTRACT_DIR}/README.md" ]]; then
  cp "${EXTRACT_DIR}/README.md" "${STAGED_DIR}/README.md"
fi

printf '%s\n' "${XRAY_VERSION}" >"${STAGED_DIR}/VERSION"
chmod 0755 "${STAGED_DIR}/xray"
chmod 0644 "${STAGED_DIR}/geoip.dat" "${STAGED_DIR}/geosite.dat" "${STAGED_DIR}/LICENSE" "${STAGED_DIR}/VERSION"
verify_directory "${STAGED_DIR}"

mkdir -p "${VENDOR_ROOT}"
BACKUP_DIR="${TMP_DIR}/previous"
if [[ -e "${TARGET_DIR}" ]]; then
  mv "${TARGET_DIR}" "${BACKUP_DIR}"
fi
if ! mv "${STAGED_DIR}" "${TARGET_DIR}"; then
  if [[ -e "${BACKUP_DIR}" ]]; then
    mv "${BACKUP_DIR}" "${TARGET_DIR}"
  fi
  exit 1
fi

echo "Bundled Xray-core ready: ${TARGET_DIR}"
