from __future__ import annotations

from v2link_client.core.traffic_settings import (
    TrafficSettings,
    load_traffic_settings,
    save_traffic_settings,
)


def test_traffic_settings_defaults_when_missing(tmp_path) -> None:
    settings = load_traffic_settings(tmp_path / "traffic_settings.json")

    assert settings.proxy_history_enabled is True
    assert settings.app_tracking_enabled is False
    assert settings.show_experimental_warning is True
    assert settings.detailed_retention_days == 30
    assert settings.daily_retention_days == 365
    assert settings.netmon_provider == "socket"


def test_traffic_settings_load_save(tmp_path) -> None:
    path = tmp_path / "traffic_settings.json"
    expected = TrafficSettings(
        proxy_history_enabled=False,
        app_tracking_enabled=True,
        show_experimental_warning=False,
        detailed_retention_days=90,
        daily_retention_days=365,
        netmon_provider="disabled",
    )

    save_traffic_settings(expected, path)
    loaded = load_traffic_settings(path)

    assert loaded == expected


def test_legacy_mock_provider_is_disabled_in_production_settings(tmp_path) -> None:
    path = tmp_path / "traffic_settings.json"
    path.write_text(
        '{"app_tracking_enabled": true, "netmon_provider": "mock"}',
        encoding="utf-8",
    )

    settings = load_traffic_settings(path)

    assert settings.app_tracking_enabled is True
    assert settings.netmon_provider == "disabled"


def test_traffic_settings_sanitizes_invalid_values(tmp_path) -> None:
    path = tmp_path / "traffic_settings.json"
    path.write_text(
        '{"detailed_retention_days": 999, "daily_retention_days": -1, "netmon_provider": "root"}',
        encoding="utf-8",
    )

    settings = load_traffic_settings(path)

    assert settings.detailed_retention_days == 30
    assert settings.daily_retention_days == 365
    assert settings.netmon_provider == "socket"
