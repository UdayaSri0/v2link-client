#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NETMON_DIR="${ROOT_DIR}/netmon"
OUT_DIR="${ROOT_DIR}/dist/netmon"

if ! command -v cargo >/dev/null 2>&1; then
  echo "Error: cargo is required to build v2link-netmon." >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"
cargo build --manifest-path "${NETMON_DIR}/Cargo.toml" --release -p v2link-netmon
cp "${NETMON_DIR}/target/release/v2link-netmon" "${OUT_DIR}/v2link-netmon"
chmod 0755 "${OUT_DIR}/v2link-netmon"

echo "v2link-netmon ready: ${OUT_DIR}/v2link-netmon"
