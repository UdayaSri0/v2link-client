from __future__ import annotations

from v2link_client.core.netmon_client import NetmonClient


def test_disabled_netmon_client_returns_clean_status() -> None:
    client = NetmonClient()

    status = client.get_status()

    assert status.installed is False
    assert status.running is False
    assert status.permission_ok is False
    assert status.message == "Per-application tracking helper is not installed yet."
    assert client.get_live_apps() == []
    assert client.get_today_app_usage() == []
    assert client.get_history(days=7) == []


def test_mock_netmon_client_returns_data() -> None:
    client = NetmonClient(provider="mock")

    status = client.start_tracking()
    apps = client.get_live_apps()
    today = client.get_today_app_usage()
    history = client.get_history(days=3)

    assert status.installed is True
    assert status.running is True
    assert status.permission_ok is True
    assert apps
    assert today
    assert history
    assert all(app.source == "mock" for app in apps)
    assert {app.confidence for app in apps} <= {"high", "medium", "low", "unknown", "exact"}
