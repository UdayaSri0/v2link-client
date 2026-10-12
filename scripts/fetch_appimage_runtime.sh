#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCH_NAME="${ARCH:-$(uname -m)}"
case "${ARCH_NAME}" in
  x86_64 | aarch64) ;;
  *) echo "Error: unsupported runtime architecture ${ARCH_NAME}" >&2; exit 1 ;;
esac
read -r ASSET_ID EXPECTED_SHA < <(python3 - "${ROOT_DIR}/packaging/appimage-runtime.json" "${ARCH_NAME}" <<'PY'
import json, sys
asset = json.load(open(sys.argv[1], encoding="utf-8"))["assets"][sys.argv[2]]
print(asset["id"], asset["sha256"])
PY
)
mkdir -p "${ROOT_DIR}/tools"
TARGET="${ROOT_DIR}/tools/runtime-${ARCH_NAME}"
# Immutable asset ID plus a pinned SHA: never accept a moving continuous build.
if ! printf '%s  %s\n' "${EXPECTED_SHA}" "${TARGET}" | sha256sum -c - >/dev/null 2>&1; then
  TEMPORARY="${TARGET}.download"
  trap 'rm -f "${TEMPORARY}"' EXIT
  curl --fail --location --silent --show-error --retry 4 --retry-all-errors \
    -H 'Accept: application/octet-stream' \
    "https://api.github.com/repos/AppImage/type2-runtime/releases/assets/${ASSET_ID}" -o "${TEMPORARY}"
  printf '%s  %s\n' "${EXPECTED_SHA}" "${TEMPORARY}" | sha256sum -c - >&2
  mv "${TEMPORARY}" "${TARGET}"
fi
if readelf -l "${TARGET}" | grep -q INTERP || readelf -d "${TARGET}" | grep -q NEEDED; then
  echo "Error: AppImage runtime must be statically linked" >&2
  exit 1
fi
file "${TARGET}" | grep -Eq "${ARCH_NAME/x86_64/x86-64}" || {
  echo "Error: runtime architecture mismatch" >&2; exit 1;
}
chmod 0755 "${TARGET}"
echo "${TARGET}"
