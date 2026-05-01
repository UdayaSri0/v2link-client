from __future__ import annotations

from v2link_client.core.traffic_store import DailyUsageBreakdown, ProxyTrafficSample
from v2link_client.ui.traffic_chart_widget import (
    prepare_daily_chart_data,
    prepare_session_cumulative_chart_data,
    prepare_session_speed_chart_data,
)


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
