from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

from v2link_client.core.xray_api import TrafficStats
from v2link_client.ui.main_window import MainWindow


class _ShutdownHarness:
    _shutdown_application = MainWindow._shutdown_application

    def __init__(self) -> None:
        self._closing = False
        self._shutdown_complete = False
        timers = [Mock() for _ in range(7)]
        (
            self._status_timer,
            self._stats_timer,
            self._traffic_persistence_timer,
            self._overview_timer,
            self._diagnostics_timer,
            self._health_timer,
            self._proxy_audit_timer,
        ) = timers
        self._stats_token = 1
        self._health_token = 1
        self._proxy_audit_token = 1
        self._stats_active_token = 1
        self._proxy_audit_active_token = 1
        self._stats_in_flight = True
        self._health_in_flight = True
        self._proxy_audit_running = True
        self._save_profile_preferences = Mock()
        self._last_known_stats = Mock(return_value=TrafficStats(10, 20))
        self._end_traffic_session = Mock()
        self.traffic_monitor_widget = SimpleNamespace(shutdown=Mock())
        self.diagnostics_widget = SimpleNamespace(shutdown=Mock())
        self._process = SimpleNamespace(stop=Mock())
        self._restore_system_proxy = Mock()
        self._thread_pool = SimpleNamespace(clear=Mock(), waitForDone=Mock(return_value=True))
        self._traffic_storage_worker = SimpleNamespace(shutdown=Mock(return_value=True))


def test_shutdown_is_ordered_and_idempotent(monkeypatch) -> None:
    import v2link_client.ui.main_window as main_window

    cancel = Mock(return_value=1)
    monkeypatch.setattr(main_window, "cancel_active_stats_queries", cancel)
    window = _ShutdownHarness()

    window._shutdown_application()
    window._shutdown_application()

    assert window._closing is True
    assert window._shutdown_complete is True
    for timer in (
        window._status_timer,
        window._stats_timer,
        window._traffic_persistence_timer,
        window._overview_timer,
        window._diagnostics_timer,
        window._health_timer,
        window._proxy_audit_timer,
    ):
        timer.stop.assert_called_once_with()
    window._end_traffic_session.assert_called_once_with(
        final_stats=TrafficStats(uplink_bytes=10, downlink_bytes=20)
    )
    window._process.stop.assert_called_once_with(timeout_s=3.0)
    window._restore_system_proxy.assert_called_once_with()
    cancel.assert_called_once_with(timeout_s=1.0)
    window._traffic_storage_worker.shutdown.assert_called_once_with(
        drain=True,
        timeout_s=main_window.TRAFFIC_FINAL_FLUSH_TIMEOUT_S,
    )
    assert window._stats_active_token is None
    assert window._proxy_audit_active_token is None


def test_late_health_result_is_ignored_while_closing() -> None:
    window = SimpleNamespace(
        _closing=True,
        _health_token=2,
        _health_in_flight=True,
        _last_health_result=None,
        _set_health_state=Mock(),
    )

    MainWindow._on_health_result(window, (2, object()))

    window._set_health_state.assert_not_called()
    assert window._health_in_flight is True
