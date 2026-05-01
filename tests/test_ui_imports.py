from __future__ import annotations


def test_traffic_monitor_widget_imports() -> None:
    from v2link_client.ui.traffic_monitor_widget import TrafficMonitorWidget

    assert TrafficMonitorWidget.__name__ == "TrafficMonitorWidget"
