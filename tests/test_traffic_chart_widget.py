from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from v2link_client.core.traffic_store import DailyUsageBreakdown, ProxyTrafficSample
from v2link_client.ui.traffic_chart_widget import (
    MAX_SESSION_CHART_POINTS,
    SESSION_CHART_MARKER_LIMIT,
    TrafficLineChartWidget,
    downsample_session_chart_points,
    prepare_daily_chart_data,
    prepare_session_cumulative_chart_data,
    prepare_session_speed_chart_data,
)
import pytest

_QT_APP = None


def _app():
    global _QT_APP
    from PyQt6.QtWidgets import QApplication

    _QT_APP = QApplication.instance() or _QT_APP or QApplication([])
    return _QT_APP


def _sample(timestamp: str, up_delta: int, down_delta: int) -> ProxyTrafficSample:
    return ProxyTrafficSample(
        session_id="session-1",
        timestamp=timestamp,
        uplink_bytes=up_delta,
        downlink_bytes=down_delta,
        uplink_delta_bytes=up_delta,
        downlink_delta_bytes=down_delta,
        upload_bps=float(up_delta),
        download_bps=float(down_delta),
    )


def test_daily_chart_data_with_one_day() -> None:
    rows = [
        DailyUsageBreakdown(
            date="2026-05-01",
            download_bytes=2048,
            upload_bytes=1024,
            total_bytes=3072,
            session_count=1,
            first_session_at=None,
            last_session_at=None,
        )
    ]

    points = prepare_daily_chart_data(rows)

    assert len(points) == 1
    assert points[0].label == "05-01"
    assert points[0].total_bytes == 3072


def test_daily_chart_data_with_multiple_days_and_empty() -> None:
    rows = [
        DailyUsageBreakdown("2026-05-01", 1, 2, 3, 1, None, None),
        DailyUsageBreakdown("2026-05-02", 4, 5, 9, 2, None, None),
    ]

    assert [point.total_bytes for point in prepare_daily_chart_data(rows)] == [3, 9]
    assert prepare_daily_chart_data([]) == []


def test_daily_chart_data_handles_small_and_large_values() -> None:
    rows = [
        DailyUsageBreakdown("2026-05-01", 1, 1, 2, 1, None, None),
        DailyUsageBreakdown("2026-05-02", 5 * 1024**3, 2 * 1024**3, 7 * 1024**3, 1, None, None),
    ]

    points = prepare_daily_chart_data(rows)

    assert points[0].total_bytes == 2
    assert points[1].download_bytes == 5 * 1024**3


def test_session_chart_speed_and_cumulative_data() -> None:
    samples = [
        _sample("2026-05-01T20:00:01+00:00", 100, 200),
        _sample("2026-05-01T20:00:02+00:00", 50, 75),
    ]

    speed = prepare_session_speed_chart_data(samples)
    cumulative = prepare_session_cumulative_chart_data(samples)

    assert speed[0].download_value == 200
    assert speed[1].upload_value == 50
    assert cumulative[0].download_value == 200
    assert cumulative[1].download_value == 275
    assert cumulative[1].upload_value == 150


@pytest.mark.parametrize("count", [0, 1, 100, MAX_SESSION_CHART_POINTS])
def test_downsampling_keeps_data_at_or_below_limit(count: int) -> None:
    points = prepare_session_speed_chart_data(
        _sample(f"2026-05-01T20:{idx // 60:02d}:{idx % 60:02d}+00:00", idx, idx * 2)
        for idx in range(count)
    )

    assert len(points) == count


@pytest.mark.parametrize("count", [MAX_SESSION_CHART_POINTS + 1, 10_000, 100_000])
def test_downsampling_bounds_large_series_and_preserves_endpoints(count: int) -> None:
    source = [
        _sample(f"2026-05-{1 + idx // 86400:02d}T{(idx // 3600) % 24:02d}:{(idx // 60) % 60:02d}:{idx % 60:02d}+00:00", idx, idx * 2)
        for idx in range(count)
    ]

    points = prepare_session_speed_chart_data(source)

    assert len(points) <= MAX_SESSION_CHART_POINTS
    assert points[0].label == prepare_session_speed_chart_data(source[:1])[0].label
    assert points[-1].label == prepare_session_speed_chart_data(source[-1:])[0].label
    values = [point.upload_value for point in points]
    assert values == sorted(values)


def test_downsampling_preserves_upload_and_download_peaks_in_order() -> None:
    from v2link_client.ui.traffic_chart_widget import SessionChartPoint

    points = [SessionChartPoint(str(idx).zfill(5), float(idx), float(idx)) for idx in range(10_000)]
    points[2_500] = SessionChartPoint("02500", 1_000_000.0, 1.0)
    points[7_500] = SessionChartPoint("07500", 1.0, 2_000_000.0)

    sampled = downsample_session_chart_points(points, maximum_points=600)

    assert len(sampled) <= 600
    assert max(point.download_value for point in sampled) == 1_000_000.0
    assert max(point.upload_value for point in sampled) == 2_000_000.0
    assert [point.label for point in sampled] == sorted(point.label for point in sampled)


def test_line_chart_suppresses_markers_for_large_series() -> None:
    from v2link_client.ui.traffic_chart_widget import SessionChartPoint

    _app()
    widget = TrafficLineChartWidget()
    widget.set_data(SessionChartPoint(str(idx), float(idx), float(idx)) for idx in range(SESSION_CHART_MARKER_LIMIT + 1))

    assert widget.markers_enabled is False
    assert len(widget.points) <= MAX_SESSION_CHART_POINTS
    widget.close()
