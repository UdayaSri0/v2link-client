"""Check GitHub releases for newer versions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import logging
import re
from typing import Any
from urllib import error as urllib_error
from urllib import request as urllib_request

from packaging.version import InvalidVersion, Version

from v2link_client.core.errors import AppError

logger = logging.getLogger(__name__)

GITHUB_REPO = "UdayaSri0/v2link-client"
LATEST_RELEASE_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
RELEASES_PAGE_URL = f"https://github.com/{GITHUB_REPO}/releases"
_VERSION_PREFIX_RE = re.compile(r"^[vV]\s*")


class UpdateCheckError(AppError):
    """Raised when release check fails."""


@dataclass(frozen=True, slots=True)
class ReleaseAsset:
    name: str
    download_url: str


@dataclass(frozen=True, slots=True)
class UpdateCheckResult:
    current_version: str
    latest_tag: str
    latest_version: str
    update_available: bool
    release_url: str
    notes: str | None
    appimage_asset: ReleaseAsset | None
    deb_asset: ReleaseAsset | None
    preferred_download_url: str


def normalize_version(value: str) -> str:
    text = _VERSION_PREFIX_RE.sub("", (value or "").strip())
    if not text:
        return "0"
    return text


def parse_version(value: str) -> Version:
    normalized = normalize_version(value)
    try:
        return Version(normalized)
    except InvalidVersion:
        match = re.search(r"([0-9]+(?:\.[0-9]+)*)", normalized)
        if match:
            try:
                return Version(match.group(1))
            except InvalidVersion:
                pass
        return Version("0")


def is_update_available(current_version: str, latest_tag: str) -> bool:
    return parse_version(latest_tag) > parse_version(current_version)


def _short_notes(body: str, *, max_lines: int = 6, max_chars: int = 500) -> str | None:
    text = (body or "").strip()
    if not text:
        return None
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return None
    clipped = "\n".join(lines[:max_lines]).strip()
    if len(clipped) > max_chars:
        clipped = f"{clipped[: max_chars - 1].rstrip()}…"
    return clipped or None


def _pick_assets(assets_raw: Any) -> tuple[ReleaseAsset | None, ReleaseAsset | None]:
    appimage_asset: ReleaseAsset | None = None
    deb_asset: ReleaseAsset | None = None
    if not isinstance(assets_raw, list):
        return appimage_asset, deb_asset

    for item in assets_raw:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        url = str(item.get("browser_download_url", "")).strip()
        if not name or not url:
            continue
        name_lower = name.lower()
        if appimage_asset is None and name_lower.endswith(".appimage"):
            appimage_asset = ReleaseAsset(name=name, download_url=url)
        if deb_asset is None and name_lower.endswith(".deb"):
            deb_asset = ReleaseAsset(name=name, download_url=url)
    return appimage_asset, deb_asset


def parse_release_payload(payload: Any, *, current_version: str) -> UpdateCheckResult:
    if not isinstance(payload, dict):
        raise UpdateCheckError(
            "Invalid response payload from GitHub releases API",
            user_message="Could not parse update information from GitHub.",
        )

    tag_name = str(payload.get("tag_name", "")).strip()
    if not tag_name:
        raise UpdateCheckError(
            "GitHub releases response missing tag_name",
            user_message="Latest release information is incomplete (missing version tag).",
        )

    latest_version = normalize_version(tag_name)
    release_url = str(payload.get("html_url", "")).strip() or RELEASES_PAGE_URL
    notes = _short_notes(str(payload.get("body", "")))
    appimage_asset, deb_asset = _pick_assets(payload.get("assets"))

    preferred_download_url = release_url
    if appimage_asset is not None:
        preferred_download_url = appimage_asset.download_url
    elif deb_asset is not None:
        preferred_download_url = deb_asset.download_url

    update_available = is_update_available(current_version=current_version, latest_tag=tag_name)

    logger.info(
        "Parsed latest release: current=%s latest=%s update_available=%s appimage=%s deb=%s",
        normalize_version(current_version),
        latest_version,
        update_available,
        appimage_asset.name if appimage_asset else None,
        deb_asset.name if deb_asset else None,
    )

    return UpdateCheckResult(
        current_version=normalize_version(current_version),
        latest_tag=tag_name,
        latest_version=latest_version,
        update_available=update_available,
        release_url=release_url,
        notes=notes,
        appimage_asset=appimage_asset,
        deb_asset=deb_asset,
        preferred_download_url=preferred_download_url,
    )


def check_for_updates(current_version: str, *, timeout_s: float = 8.0) -> UpdateCheckResult:
    logger.info(
        "Checking GitHub releases for updates: current=%s url=%s",
        normalize_version(current_version),
        LATEST_RELEASE_API_URL,
    )
    req = urllib_request.Request(
        LATEST_RELEASE_API_URL,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": f"v2link-client/{normalize_version(current_version)}",
        },
        method="GET",
    )

    try:
        with urllib_request.urlopen(req, timeout=timeout_s) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except urllib_error.HTTPError as exc:
        detail = exc.reason or f"HTTP {exc.code}"
        if exc.code == 403:
            remaining = (exc.headers or {}).get("X-RateLimit-Remaining", "")
            reset_at = (exc.headers or {}).get("X-RateLimit-Reset", "")
            if str(remaining).strip() == "0":
                reset_hint = ""
                try:
                    if reset_at:
                        when = datetime.fromtimestamp(int(reset_at), tz=timezone.utc)
                        reset_hint = f" Try again after {when.strftime('%Y-%m-%d %H:%M UTC')}."
                except Exception:
                    reset_hint = ""
                raise UpdateCheckError(
                    f"GitHub API rate limit reached: {detail}",
                    user_message=f"GitHub API rate limit reached.{reset_hint}",
                ) from exc
        raise UpdateCheckError(
            f"Update check failed with HTTP {exc.code}: {detail}",
            user_message=f"Update check failed (HTTP {exc.code}: {detail}).",
        ) from exc
    except urllib_error.URLError as exc:
        raise UpdateCheckError(
            f"Update check network error: {exc}",
            user_message="Could not connect to GitHub to check for updates.",
        ) from exc
    except TimeoutError as exc:
        raise UpdateCheckError(
            f"Update check timed out: {exc}",
            user_message="Timed out while checking for updates.",
        ) from exc

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise UpdateCheckError(
            f"Failed to decode GitHub release response: {exc}",
            user_message="Received invalid update data from GitHub.",
        ) from exc

    return parse_release_payload(payload, current_version=current_version)
