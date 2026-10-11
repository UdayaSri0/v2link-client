#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="$(realpath "${1:?Usage: test_appimage_clean.sh APPIMAGE}")"
for version in 22.04 24.04; do
  log_dir="${ROOT_DIR}/build/smoke-${version}"
  mkdir -p "${log_dir}"
  # Only the temporary diagnostics directory is writable by the test UID.
  chmod 0777 "${log_dir}"
  docker build --build-arg "UBUNTU_VERSION=${version}" \
    -f "${ROOT_DIR}/packaging/appimage-smoke.Dockerfile" \
    -t "v2link-appimage-smoke:${version}" "${ROOT_DIR}"
  docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
    --mount "type=bind,src=${IMAGE},dst=/artifacts/app.AppImage,readonly" \
    --mount "type=bind,src=${log_dir},dst=/logs" \
    "v2link-appimage-smoke:${version}"
done
