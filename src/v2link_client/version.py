"""Version helpers for runtime and packaging."""

from __future__ import annotations

import os
import re
import sys
from functools import lru_cache
from importlib import metadata
from pathlib import Path
import tomllib

PACKAGE_NAME = "v2link-client"
DEFAULT_VERSION = "0.0.0"
_PREFIX_RE = re.compile(r"^[vV]\s*")


def _normalize_version(value: str) -> str:
    """Normalize release version strings for display/comparison."""
    normalized = _PREFIX_RE.sub("", value.strip()).replace(" ", "")
    match = re.match(r"([0-9]+(?:\.[0-9]+)*)", normalized)
    if not match:
        return DEFAULT_VERSION
    semver = match.group(1).strip(".")
    return semver or DEFAULT_VERSION


def _read_pyproject_version() -> str | None:
    """Read the authoritative version from source or bundled project metadata."""
    candidates = [Path(__file__).resolve().parents[2] / "pyproject.toml"]
    frozen_root = getattr(sys, "_MEIPASS", None)
    if frozen_root:
        candidates.insert(0, Path(frozen_root) / "pyproject.toml")

    for pyproject_path in candidates:
        if not pyproject_path.is_file():
            continue
        try:
            data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            continue
        version = str(data.get("project", {}).get("version", "")).strip()
        if version:
            return version
    return None


def get_project_version() -> str:
    """Return the version declared in local pyproject.toml when available."""
    version = _read_pyproject_version()
    if not version:
        return DEFAULT_VERSION
    return version


@lru_cache(maxsize=1)
def get_version() -> str:
    """
    Return the project version from a single source of truth.

    Priority:
    1) Build/runtime override env var
    2) Local pyproject (dev mode/source tree)
    3) Installed package metadata
    4) Default fallback
    """
    env_version = (os.getenv("V2LINK_CLIENT_VERSION") or os.getenv("VERSION") or "").strip()
    if env_version:
        return env_version

    dev_version = _read_pyproject_version()
    if dev_version:
        return dev_version

    try:
        installed = metadata.version(PACKAGE_NAME).strip()
        if installed:
            return installed
    except metadata.PackageNotFoundError:
        pass

    return DEFAULT_VERSION


def get_semver() -> str:
    """Return normalized semantic-style version (no leading 'v' / spaces)."""
    return _normalize_version(get_version())
