#!/usr/bin/env bash
set -euo pipefail

# Build a signed APT repository using reprepro from .deb artifacts.
# The repository output is suitable for GitHub Pages hosting.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
REPO_DIR="${ROOT_DIR}/public/apt"
CODENAME="stable"
COMPONENT="main"
APT_PUBLIC_KEY="${ROOT_DIR}/apt/public.key"

usage() {
  cat <<'EOF'
Usage: scripts/apt_repo_build.sh [options]

Options:
  --dist-dir <path>    Directory containing .deb artifacts (default: ./dist)
  --repo-dir <path>    Output APT repo directory (default: ./public/apt)
  --codename <name>    Debian codename/suite (default: stable)
  --component <name>   Debian component (default: main)
  -h, --help           Show this help

Environment:
  APT_GPG_KEY_ID       Required signing key fingerprint/key ID unless APT_SKIP_SIGN=1
  APT_SKIP_SIGN        Set to 1 to skip signing (local/dev only)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dist-dir)
      DIST_DIR="$2"
      shift 2
      ;;
    --repo-dir)
      REPO_DIR="$2"
      shift 2
      ;;
    --codename)
      CODENAME="$2"
      shift 2
      ;;
    --component)
      COMPONENT="$2"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "Error: unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if ! command -v reprepro >/dev/null 2>&1; then
  echo "Error: reprepro is required to build the APT repository." >&2
  exit 1
fi

if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "Error: dpkg-deb is required to inspect package metadata." >&2
  exit 1
fi

if [[ ! -f "${APT_PUBLIC_KEY}" ]]; then
  echo "Error: missing public repository key at ${APT_PUBLIC_KEY}" >&2
  exit 1
fi

mapfile -t DEB_FILES < <(find "${DIST_DIR}" -type f -name "*.deb" | sort)
if [[ "${#DEB_FILES[@]}" -eq 0 ]]; then
  echo "Error: no .deb artifacts found under ${DIST_DIR}" >&2
  exit 1
fi

if [[ "${APT_SKIP_SIGN:-0}" != "1" && -z "${APT_GPG_KEY_ID:-}" ]]; then
  echo "Error: APT_GPG_KEY_ID is required for signing." >&2
  exit 1
fi

rm -rf "${REPO_DIR}"
mkdir -p "${REPO_DIR}/conf"

{
  echo "Origin: v2link-client"
  echo "Label: v2link-client"
  echo "Suite: ${CODENAME}"
  echo "Codename: ${CODENAME}"
  echo "Architectures: amd64 arm64 source"
  echo "Components: ${COMPONENT}"
  echo "Description: v2link-client APT repository"
  if [[ "${APT_SKIP_SIGN:-0}" != "1" ]]; then
    echo "SignWith: ${APT_GPG_KEY_ID}"
  fi
} >"${REPO_DIR}/conf/distributions"

for deb in "${DEB_FILES[@]}"; do
  reprepro --basedir "${REPO_DIR}" includedeb "${CODENAME}" "${deb}"
done

cp "${APT_PUBLIC_KEY}" "${REPO_DIR}/public.key"

if [[ ! -f "${REPO_DIR}/dists/${CODENAME}/${COMPONENT}/binary-amd64/Packages.gz" ]]; then
  echo "Error: missing Packages.gz for amd64 index." >&2
  exit 1
fi

if [[ "${APT_SKIP_SIGN:-0}" != "1" ]]; then
  if [[ ! -f "${REPO_DIR}/dists/${CODENAME}/InRelease" ]]; then
    echo "Error: missing signed InRelease metadata." >&2
    exit 1
  fi
  if [[ ! -f "${REPO_DIR}/dists/${CODENAME}/Release.gpg" ]]; then
    echo "Error: missing detached Release.gpg signature." >&2
    exit 1
  fi
fi

echo "APT repository ready at ${REPO_DIR}"
