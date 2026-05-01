"""Persist optional Xray-core binary preferences."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from v2link_client.core.storage import get_config_dir, load_json, save_json

XRAY_SETTINGS_FILE = "xray_settings.json"


@dataclass(frozen=True, slots=True)
class XraySettings:
    use_custom_binary: bool = False
    custom_binary_path: str | None = None


def get_xray_settings_path() -> Path:
    return get_config_dir() / XRAY_SETTINGS_FILE


def load_xray_settings(path: Path | None = None) -> XraySettings:
    data = load_json(path or get_xray_settings_path(), {})
    if not isinstance(data, dict):
        data = {}
    custom_path = data.get("custom_binary_path")
    if not isinstance(custom_path, str) or not custom_path.strip():
        custom_path = None
    return XraySettings(
        use_custom_binary=bool(data.get("use_custom_binary", False)),
        custom_binary_path=custom_path.strip() if custom_path else None,
    )


def save_xray_settings(settings: XraySettings, path: Path | None = None) -> None:
    save_json(
        path or get_xray_settings_path(),
        {
            "use_custom_binary": bool(settings.use_custom_binary),
            "custom_binary_path": settings.custom_binary_path or "",
        },
    )
