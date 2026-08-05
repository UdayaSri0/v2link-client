"""Locate and validate Xray-core for source, packaged, and custom installs."""

from __future__ import annotations

from dataclasses import dataclass, replace
import os
from pathlib import Path
import platform
import subprocess
import sys
from typing import Iterable, Literal

from v2link_client.core.logging_setup import sanitize_sensitive_text
from v2link_client.core.system_subprocess import build_xray_subprocess_env, system_which
from v2link_client.core.xray_settings import load_xray_settings

XraySource = Literal["user-configured", "bundled", "system-path"]
MISSING_XRAY_MESSAGE = (
    "Xray-core was not found. This build may be incomplete. Please install the official "
    "v2link-client AppImage/.deb package, or configure a custom Xray path."
)


@dataclass(frozen=True, slots=True)
class XrayBinary:
    path: str | None
    source: XraySource
    version: str | None
    valid: bool
    error: str | None = None
    architecture: str | None = None
    geoip_found: bool = False
    geosite_found: bool = False
    asset_dir: str | None = None
    version_manifest: str | None = None
    version_manifest_status: str = "unavailable"
    warning: str | None = None

    @property
    def name(self) -> str:
        return "xray"


def _normalize_arch(raw_arch: str | None = None) -> str:
    arch = (raw_arch or platform.machine() or "").lower()
    if arch in {"x86_64", "amd64"}:
        return "x86_64"
    if arch in {"aarch64", "arm64"}:
        return "aarch64"
    return arch


def _dedupe(paths: Iterable[Path]) -> list[Path]:
    seen: set[str] = set()
    result: list[Path] = []
    for path in paths:
        try:
            key = str(path.expanduser().resolve(strict=False))
        except OSError:
            key = str(path)
        if key in seen:
            continue
        seen.add(key)
        result.append(path)
    return result


def _candidate_from_env_dir(value: str | None) -> list[Path]:
    if not value:
        return []
    path = Path(value).expanduser()
    if path.is_file():
        return [path]
    return [path / "xray", path]


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _executable_dir() -> Path:
    return Path(sys.executable).resolve().parent


def _meipass_dir() -> Path | None:
    raw = getattr(sys, "_MEIPASS", None)
    if not raw:
        return None
    return Path(str(raw)).resolve()


def get_bundled_xray_candidates() -> list[Path]:
    """Return possible bundled Xray binary paths, ordered by packaging priority."""

    appdir = os.environ.get("APPDIR")
    arch = _normalize_arch()
    exe_dir = _executable_dir()
    root = _project_root()
    cwd = Path.cwd()

    candidates: list[Path] = []
    candidates.extend(_candidate_from_env_dir(os.environ.get("V2LINK_BUNDLED_XRAY_DIR")))
    candidates.extend(_candidate_from_env_dir(os.environ.get("XRAY_LOCATION_ASSET")))

    candidates.extend(
        [
            Path("/opt/v2link-client/xray/xray"),
            Path("/opt/v2link-client/bin/xray"),
            exe_dir / "xray" / "xray",
            exe_dir / "bin" / "xray",
        ]
    )

    if appdir:
        appdir_path = Path(appdir)
        candidates.extend(
            [
                appdir_path / "usr" / "bin" / "xray" / "xray",
                appdir_path / "usr" / "bin" / "bin" / "xray",
            ]
        )

    meipass = _meipass_dir()
    if meipass is not None:
        candidates.extend(
            [
                meipass / "xray" / "xray",
                meipass / "bin" / "xray",
                meipass / "usr" / "bin" / "xray" / "xray",
                meipass / "usr" / "bin" / "bin" / "xray",
            ]
        )

    for base in (cwd, root):
        candidates.append(base / "vendor" / "xray" / arch / "xray")

    return _dedupe(candidates)


def _parse_version(output: str) -> str | None:
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.lower().startswith("xray "):
            parts = line.split()
            if len(parts) >= 2:
                version = parts[1].strip()
                return version if version.startswith("v") else f"v{version}"
            return line
    return None


def validate_xray_binary(
    path: str | Path | None,
    *,
    source: XraySource = "user-configured",
    timeout_s: float = 2.0,
) -> XrayBinary:
    if path is None or not str(path).strip():
        return XrayBinary(path=None, source=source, version=None, valid=False, error="No Xray path configured.")

    candidate = Path(path).expanduser()
    display_path = str(candidate)
    if not candidate.exists():
        return XrayBinary(display_path, source, None, False, "Xray binary does not exist.")
    if not candidate.is_file():
        return XrayBinary(display_path, source, None, False, "Xray path is not a file.")
    if not os.access(candidate, os.X_OK):
        return XrayBinary(display_path, source, None, False, "Xray binary is not executable.")

    base = candidate.parent
    geoip_found = (base / "geoip.dat").is_file()
    geosite_found = (base / "geosite.dat").is_file()
    manifest_path = base / "VERSION"
    manifest_version = (
        manifest_path.read_text(encoding="utf-8").strip()
        if manifest_path.is_file()
        else None
    )
    env, _info = build_xray_subprocess_env(candidate)
    try:
        result = subprocess.run(
            [str(candidate), "version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return XrayBinary(display_path, source, None, False, "Timed out while checking Xray version.")
    except OSError as exc:
        detail = (
            "Xray executable has the wrong architecture."
            if getattr(exc, "errno", None) == 8
            else sanitize_sensitive_text(f"Could not run Xray: {exc}")
        )
        return XrayBinary(display_path, source, None, False, detail)

    output = "\n".join(part for part in (result.stdout, result.stderr) if part)
    version = _parse_version(output)
    if result.returncode != 0:
        detail = sanitize_sensitive_text(output.strip()) or f"exit code {result.returncode}"
        return XrayBinary(display_path, source, version, False, f"Xray version check failed: {detail}")
    if version is None:
        detail = sanitize_sensitive_text(output.strip()) or "no version output"
        return XrayBinary(display_path, source, None, False, f"Selected file does not look like Xray-core: {detail}")

    manifest_status = "unavailable"
    if manifest_version:
        manifest_status = "match" if manifest_version == version else "mismatch"
    if manifest_status == "mismatch":
        return XrayBinary(
            display_path, source, version, False,
            f"Xray version {version} does not match VERSION record {manifest_version}.",
            _normalize_arch(), geoip_found, geosite_found, str(base),
            manifest_version, manifest_status,
        )

    return XrayBinary(
        str(candidate.resolve(strict=False)), source, version, True, None,
        _normalize_arch(), geoip_found, geosite_found, str(base),
        manifest_version, manifest_status,
    )


def get_system_xray_candidate() -> XrayBinary:
    path = system_which("xray")
    if not path:
        return XrayBinary(None, "system-path", None, False, "xray was not found in PATH.")
    return validate_xray_binary(path, source="system-path")


def find_xray_binary() -> XrayBinary:
    settings = load_xray_settings()
    errors: list[str] = []

    if settings.use_custom_binary:
        custom = validate_xray_binary(settings.custom_binary_path, source="user-configured")
        if custom.valid:
            return custom
        errors.append(f"custom: {custom.error or 'invalid'}")

    for candidate in get_bundled_xray_candidates():
        bundled = validate_xray_binary(candidate, source="bundled")
        if bundled.valid:
            if errors:
                return replace(
                    bundled,
                    warning="The custom Xray path is invalid. v2link-client is using the bundled Xray-core instead.",
                )
            return bundled
        if candidate.exists():
            errors.append(f"bundled {candidate}: {bundled.error or 'invalid'}")

    system = get_system_xray_candidate()
    if system.valid:
        if errors:
            return replace(
                system,
                warning="The custom Xray path is invalid. v2link-client is using Xray-core from the system PATH instead.",
            )
        return system
    errors.append(f"system PATH: {system.error or 'missing'}")

    detail = "; ".join(errors) if errors else MISSING_XRAY_MESSAGE
    return XrayBinary(None, "system-path", None, False, f"{MISSING_XRAY_MESSAGE} ({detail})")


def xray_asset_status(binary: XrayBinary | None) -> dict[str, object]:
    if binary is None or not binary.path:
        return {
            "geoip_path": None,
            "geoip_found": False,
            "geosite_path": None,
            "geosite_found": False,
            "bundled_incomplete": False,
            "asset_dir": None,
            "version_manifest": None,
            "version_manifest_status": "unavailable",
        }
    base = Path(binary.path).parent
    geoip = base / "geoip.dat"
    geosite = base / "geosite.dat"
    return {
        "geoip_path": str(geoip),
        "geoip_found": geoip.is_file(),
        "geosite_path": str(geosite),
        "geosite_found": geosite.is_file(),
        "bundled_incomplete": binary.source == "bundled" and not (geoip.is_file() and geosite.is_file()),
        "asset_dir": str(base),
        "version_manifest": binary.version_manifest,
        "version_manifest_status": binary.version_manifest_status,
    }
