from __future__ import annotations

import os
from datetime import datetime
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

_QT_APP = None


def test_traffic_monitor_widget_imports() -> None:
    from v2link_client.ui.traffic_monitor_widget import TrafficMonitorWidget

    assert TrafficMonitorWidget.__name__ == "TrafficMonitorWidget"


def _app():
    global _QT_APP
    from PyQt6.QtWidgets import QApplication

    _QT_APP = QApplication.instance() or _QT_APP or QApplication([])
    return _QT_APP


def _stats(up: int, down: int):
    from v2link_client.core.xray_api import TrafficStats

    return TrafficStats(uplink_bytes=up, downlink_bytes=down)


def test_history_tab_selecting_date_and_session_updates_details(tmp_path, monkeypatch) -> None:
    _app()
    import v2link_client.core.traffic_store as traffic_store
    from PyQt6.QtCore import QDate
    from v2link_client.core.traffic_store import TrafficStore
    from v2link_client.ui.traffic_monitor_widget import TrafficMonitorWidget

    monkeypatch.setattr(
        traffic_store,
        "_now",
        lambda: datetime(2026, 5, 1, 20, 0, 0),
    )
    store = TrafficStore(tmp_path / "traffic.sqlite3")
    session_id = store.start_proxy_session(
        "profile-1", "Home", "fingerprint", _stats(0, 0), "127.0.0.1:10085", 1080, 8080
    )
    store.record_proxy_sample(
        session_id,
        _stats(100, 200),
        now=datetime(2026, 5, 1, 20, 1, 0),
    )
    store.end_proxy_session(session_id)

    widget = TrafficMonitorWidget(store)
    widget.range_selector.setCurrentIndex(widget.range_selector.findData("custom"))
    widget.history_start_date.setDate(QDate.fromString("2026-05-01", "yyyy-MM-dd"))
    widget.history_end_date.setDate(QDate.fromString("2026-05-01", "yyyy-MM-dd"))
    widget.refresh()

    assert widget.history_table.rowCount() == 1
    widget.history_table.selectRow(0)
    assert widget.sessions_table.rowCount() == 1
    widget.sessions_table.selectRow(0)
    deadline = time.monotonic() + 3.0
    while widget.session_detail_labels["profile"].text() == "none" and time.monotonic() < deadline:
        _app().processEvents()
        time.sleep(0.005)
    assert widget.session_detail_labels["profile"].text() == "Home"
    assert widget.session_detail_labels["download"].text() == "200 B"
    widget.close()


def test_history_tab_missing_data_does_not_crash(tmp_path) -> None:
    _app()
    from v2link_client.core.traffic_store import TrafficStore
    from v2link_client.ui.traffic_monitor_widget import TrafficMonitorWidget

    widget = TrafficMonitorWidget(TrafficStore(tmp_path / "traffic.sqlite3"))
    widget.refresh()

    assert widget.history_table.rowCount() == 0
    assert widget.sessions_table.rowCount() == 0
    assert widget.session_detail_labels["profile"].text() == "none"
    widget.close()


def test_history_tab_builds_in_compact_and_workspace_modes(tmp_path) -> None:
    _app()
    from PyQt6.QtCore import Qt
    from v2link_client.core.traffic_store import TrafficStore
    from v2link_client.ui.traffic_monitor_widget import TrafficMonitorWidget

    widget = TrafficMonitorWidget(TrafficStore(tmp_path / "traffic.sqlite3"))
    widget.resize(900, 700)
    widget._apply_responsive_layout()
    assert widget._layout_mode == "compact"
    assert widget.daily_chart.maximumHeight() <= 200

    widget.toggle_workspace_mode()
    assert widget._layout_mode == "workspace"
    assert widget.history_main_splitter.orientation() == Qt.Orientation.Horizontal
    widget.exit_workspace_mode()
    widget.close()


def test_scroll_safe_tabs_and_helper_empty_state(tmp_path) -> None:
    _app()
    from PyQt6.QtWidgets import QScrollArea
    from v2link_client.core.traffic_store import TrafficStore
    from v2link_client.ui.traffic_monitor_widget import TrafficMonitorWidget

    widget = TrafficMonitorWidget(TrafficStore(tmp_path / "traffic.sqlite3"))
    assert isinstance(widget.tabs.widget(0), QScrollArea)
    assert isinstance(widget.tabs.widget(1), QScrollArea)
    assert isinstance(widget.tabs.widget(3), QScrollArea)
    assert isinstance(widget.tabs.widget(4), QScrollArea)
    assert isinstance(widget.tabs.widget(5), QScrollArea)
    assert not widget.app_search_row.isVisible()
    assert widget.app_helper_card.minimumSizeHint().height() < 180
    widget.close()


def test_layout_state_save_restore_does_not_crash(tmp_path) -> None:
    _app()
    from PyQt6.QtCore import Qt
    from v2link_client.core.traffic_store import TrafficStore
    from v2link_client.ui.traffic_monitor_widget import TrafficMonitorWidget

    widget = TrafficMonitorWidget(TrafficStore(tmp_path / "traffic.sqlite3"))
    widget.tabs.setCurrentIndex(3)
    widget.toggle_workspace_mode()
    state = widget._save_layout_state()
    restored = TrafficMonitorWidget(TrafficStore(tmp_path / "traffic2.sqlite3"))
    restored._restore_layout_state(state)
    assert restored.tabs.currentIndex() == 3
    assert restored.history_main_splitter.orientation() == Qt.Orientation.Horizontal
    widget.close()
    restored.close()


def test_long_profile_names_do_not_crash_table_rendering(tmp_path) -> None:
    _app()
    from v2link_client.core.traffic_store import TrafficStore
    from v2link_client.ui.traffic_monitor_widget import TrafficMonitorWidget

    store = TrafficStore(tmp_path / "traffic.sqlite3")
    long_name = "profile-" + "very-long-name-" * 20
    session_id = store.start_proxy_session("profile-1", long_name, "fingerprint", _stats(0, 0), None, 1080, 8080)
    store.record_proxy_sample(session_id, _stats(1024, 4096))
    store.end_proxy_session(session_id)

    widget = TrafficMonitorWidget(store)
    widget.refresh()
    assert widget.profiles_table.rowCount() == 1
    item = widget.profiles_table.item(0, 0)
    assert item is not None
    assert item.toolTip() == long_name
    widget.close()


def test_main_window_geometry_save_restore_does_not_crash(tmp_path, monkeypatch) -> None:
    _app()
    import v2link_client.core.profile_store as profile_store
    import v2link_client.core.traffic_settings as traffic_settings
    import v2link_client.core.traffic_store as traffic_store
    import v2link_client.ui.main_window as main_window
    from v2link_client.core.xray_locator import XrayBinary

    config_dir = tmp_path / "config"
    state_dir = tmp_path / "state"
    data_dir = tmp_path / "data"
    monkeypatch.setattr(main_window, "get_config_dir", lambda: config_dir)
    monkeypatch.setattr(main_window, "get_state_dir", lambda: state_dir)
    monkeypatch.setattr(profile_store, "get_config_dir", lambda: config_dir)
    monkeypatch.setattr(traffic_settings, "get_config_dir", lambda: config_dir)
    monkeypatch.setattr(traffic_store, "get_data_dir", lambda: data_dir)
    monkeypatch.setattr(
        main_window,
        "locate_xray_binary",
        lambda: XrayBinary(path="/tmp/xray", source="bundled", version="Xray 26.4.25", valid=True),
    )

    class FakeSystemProxyManager:
        backend = "fake"

        def is_supported(self) -> bool:
            return True

        def restore_if_needed(self) -> bool:
            return False

        def repair_stale_loopback_proxy(self) -> bool:
            return False

    monkeypatch.setattr(main_window, "SystemProxyManager", FakeSystemProxyManager)

    window = main_window.MainWindow()
    window.resize(1040, 700)
    window.traffic_monitor_widget.tabs.setCurrentIndex(3)
    window._save_profile_preferences()
    window.close()

    restored = main_window.MainWindow()
    assert restored.size().width() >= 640
    assert restored.traffic_monitor_widget.tabs.currentIndex() == 3
    restored.close()
