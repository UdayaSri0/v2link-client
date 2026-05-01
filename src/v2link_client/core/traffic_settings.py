"""Traffic Monitor settings persistence."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from v2link_client.core.storage import get_config_dir, load_json, save_json

TRAFFIC_SETTINGS_FILE = "traffic_settings.json"
RETENTION_OPTIONS = {7, 30, 90}
DEFAULT_DAILY_RETENTION_DAYS = 365


@dataclass(frozen=True, slots=True)
class TrafficSettings:
    proxy_history_enabled: bool = True
    app_tracking_enabled: bool = False
    show_experimental_warning: bool = True
    detailed_retention_days: int = 30
    daily_retention_days: int = DEFAULT_DAILY_RETENTION_DAYS
    netmon_provider: str = "socket"


def get_traffic_settings_path() -> Path:
    return get_config_dir() / TRAFFIC_SETTINGS_FILE


def load_traffic_settings(path: Path | None = None) -> TrafficSettings:
    settings_path = path or get_traffic_settings_path()
    payload = load_json(settings_path, {})
    if not isinstance(payload, dict):
        payload = {}

    detailed_retention_days = _retention_value(payload.get("detailed_retention_days"))
    daily_retention_days = _positive_int(
        payload.get("daily_retention_days"),
        DEFAULT_DAILY_RETENTION_DAYS,
    )
    provider = str(payload.get("netmon_provider", "socket") or "socket").strip().lower()
    if provider not in {"disabled", "mock", "socket"}:
        provider = "socket"

    return TrafficSettings(
        proxy_history_enabled=bool(payload.get("proxy_history_enabled", True)),
        app_tracking_enabled=bool(payload.get("app_tracking_enabled", False)),
        show_experimental_warning=bool(payload.get("show_experimental_warning", True)),
        detailed_retention_days=detailed_retention_days,
        daily_retention_days=daily_retention_days,
        netmon_provider=provider,
    )


def save_traffic_settings(settings: TrafficSettings, path: Path | None = None) -> None:
    settings_path = path or get_traffic_settings_path()
    save_json(settings_path, asdict(settings))


def _retention_value(value: Any) -> int:
    parsed = _positive_int(value, 30)
    if parsed in RETENTION_OPTIONS:
        return parsed
    return 30


def _positive_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default
