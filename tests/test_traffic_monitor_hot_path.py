from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import Mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

_QT_APP = None


def _app():
    global _QT_APP
    from PyQt6.QtWidgets import QApplication

    _QT_APP = QApplication.instance() or _QT_APP or QApplication([])
    return _QT_APP


def _stats(up: int = 100, down: int = 200):
    from v2link_client.core.xray_api import TrafficStats

    return TrafficStats(uplink_bytes=up, downlink_bytes=down)


class _RunningProcess:
    binary = SimpleNamespace(path="/tmp/xray")

    def is_running(self) -> bool:
        return True


class _CapturingPool:
    def __init__(self) -> None:
        self.workers = []

    def start(self, worker) -> None:
        self.workers.append(worker)


class _StatsHarness:
    from v2link_client.ui.main_window import MainWindow as _MainWindow

    _kick_stats_poll = _MainWindow._kick_stats_poll
    _on_stats_worker_finished = _MainWindow._on_stats_worker_finished
    _on_stats_result = _MainWindow._on_stats_result
    _on_stats_error = _MainWindow._on_stats_error
    _now_iso_seconds = _MainWindow._now_iso_seconds

    def __init__(self) -> None:
        self._closing = False
        self._api_port = 10085
        self._process = _RunningProcess()
        self._thread_pool = _CapturingPool()
        self._stats_in_flight = False
        self._stats_token = 7
        self._stats_active_token = None
        self._stats_skipped_polls = 0
        self._stats_query_started_at = None
        self._last_stats_query_duration_ms = None
        self._last_stats_failure_log_at = None
        self._last_stats_failure_message = None
        self._last_slow_stats_callback_warning_at = None
        self._stats_available = False
        self._last_stats_query_result = None
        self._last_stats_query_time = None
        self._last_stats_at = None
        self._last_uplink = None
        self._last_downlink = None
        self._last_traffic_activity_at = None
        self._record_traffic_sample = Mock(return_value=None)
        self._update_traffic_monitor_diagnostics = Mock()
        self.traffic_label = Mock()
        self.speed_label = Mock()
        self.traffic_monitor_widget = SimpleNamespace(
            update_live_metrics=Mock(),
            refresh=Mock(),
            refresh_history=Mock(),
            refresh_applications=Mock(),
            refresh_profiles=Mock(),
        )


def test_live_sample_does_not_trigger_complete_or_section_refreshes(tmp_path) -> None:
    from v2link_client.core.traffic_settings import TrafficSettings
    from v2link_client.core.traffic_store import TrafficStore
    from v2link_client.ui.main_window import MainWindow

    store = TrafficStore(tmp_path / "traffic.sqlite3")
    session_id = store.start_proxy_session(
        None, "Unsaved", "fingerprint", _stats(0, 0), "127.0.0.1:10085", 1080, 8080
    )
    monitor = SimpleNamespace(
        update_live_sample=Mock(),
        refresh=Mock(),
        refresh_history=Mock(),
        refresh_applications=Mock(),
        refresh_profiles=Mock(),
    )
    window = SimpleNamespace(
        _traffic_settings=TrafficSettings(),
        _traffic_store=store,
        _traffic_session_id=session_id,
        _last_traffic_store_error=None,
        _last_traffic_sample=None,
        traffic_monitor_widget=monitor,
        _refresh_traffic_monitor=Mock(),
    )

    sample = MainWindow._record_traffic_sample(window, _stats())

    assert sample is not None
    monitor.update_live_sample.assert_called_once_with(sample)
    monitor.refresh.assert_not_called()
    monitor.refresh_history.assert_not_called()
    monitor.refresh_applications.assert_not_called()
    monitor.refresh_profiles.assert_not_called()
    window._refresh_traffic_monitor.assert_not_called()


def test_second_stats_poll_is_skipped_while_query_is_running(monkeypatch) -> None:
    import v2link_client.ui.main_window as main_window

    harness = _StatsHarness()
    monkeypatch.setattr(main_window, "get_outbound_traffic", Mock(return_value=_stats()))

    harness._kick_stats_poll()
    harness._kick_stats_poll()

    assert len(harness._thread_pool.workers) == 1
    assert harness._stats_in_flight is True
    assert harness._stats_skipped_polls == 1


def test_stats_query_state_resets_after_success(monkeypatch) -> None:
    import v2link_client.ui.main_window as main_window

    harness = _StatsHarness()
    query = Mock(return_value=_stats())
    monkeypatch.setattr(main_window, "get_outbound_traffic", query)
    harness._kick_stats_poll()
    payload = harness._thread_pool.workers[0].fn()

    harness._on_stats_result(payload)

    query.assert_called_once_with(
        "/tmp/xray",
        server="127.0.0.1:10085",
        timeout_s=main_window.STATS_QUERY_TIMEOUT_S,
    )
    assert harness._stats_in_flight is False
    assert harness._stats_active_token is None
    assert harness._stats_available is True
    harness.traffic_label.setText.assert_called_once()
    harness.traffic_monitor_widget.refresh.assert_not_called()
    harness.traffic_monitor_widget.refresh_history.assert_not_called()
    harness.traffic_monitor_widget.refresh_applications.assert_not_called()
    harness.traffic_monitor_widget.refresh_profiles.assert_not_called()


def test_stats_query_state_resets_after_failure_and_timeout() -> None:
    from v2link_client.core.xray_api import XrayApiError

    harness = _StatsHarness()
    harness._stats_in_flight = True
    harness._stats_active_token = harness._stats_token

    harness._on_stats_error(harness._stats_token, "query failed", 12.0)

    assert harness._stats_in_flight is False
    assert harness._stats_active_token is None

    harness._stats_in_flight = True
    harness._stats_active_token = harness._stats_token
    timeout = XrayApiError("timed out", user_message="Xray API timed out")
    harness._on_stats_worker_finished((harness._stats_token, 1.0, 3000.0, timeout))

    assert harness._stats_in_flight is False
    assert harness._stats_active_token is None


def test_closing_window_does_not_start_stats_query() -> None:
    harness = _StatsHarness()
    harness._closing = True

    harness._kick_stats_poll()

    assert harness._thread_pool.workers == []


def test_stale_stats_result_does_not_clear_current_request() -> None:
    harness = _StatsHarness()
    harness._stats_token = 8
    harness._stats_in_flight = True
    harness._stats_active_token = 8

    harness._on_stats_result((7, 1.0, 10.0, _stats()))

    assert harness._stats_in_flight is True
    assert harness._stats_active_token == 8
    harness._record_traffic_sample.assert_not_called()


def test_tab_activation_refreshes_only_relevant_section(tmp_path) -> None:
    app = _app()
    from v2link_client.core.traffic_store import TrafficStore
    from v2link_client.ui.traffic_monitor_widget import TrafficMonitorWidget

    widget = TrafficMonitorWidget(TrafficStore(tmp_path / "traffic.sqlite3"))
    widget.refresh_overview = Mock()
    widget.refresh_applications = Mock()
    widget.refresh_profiles = Mock()
    widget.refresh_history = Mock()
    widget.refresh_diagnostics = Mock()
    widget.show()
    app.processEvents()

    widget.tabs.setCurrentIndex(3)

    widget.refresh_history.assert_called_once_with()
    widget.refresh_overview.assert_not_called()
    widget.refresh_applications.assert_not_called()
    widget.refresh_profiles.assert_not_called()
    widget.refresh_diagnostics.assert_not_called()
    widget.close()


def test_invisible_tab_activation_does_not_refresh(tmp_path) -> None:
    _app()
    from v2link_client.core.traffic_store import TrafficStore
    from v2link_client.ui.traffic_monitor_widget import TrafficMonitorWidget

    widget = TrafficMonitorWidget(TrafficStore(tmp_path / "traffic.sqlite3"))
    widget.refresh_applications = Mock()
    widget.hide()

    widget.tabs.setCurrentIndex(1)

    widget.refresh_applications.assert_not_called()
    widget.close()
