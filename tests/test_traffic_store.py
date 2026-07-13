from __future__ import annotations

from datetime import datetime, timezone
import sqlite3

import v2link_client.core.traffic_store as traffic_store
from v2link_client.core.traffic_store import AppIdentity, TrafficStore
from v2link_client.core.xray_api import TrafficStats


def _stats(up: int, down: int) -> TrafficStats:
    return TrafficStats(uplink_bytes=up, downlink_bytes=down)


def test_traffic_store_schema_creation(tmp_path) -> None:
    path = tmp_path / "traffic.sqlite3"
    TrafficStore(path)

    with sqlite3.connect(path) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert "schema_migrations" in tables
        assert "proxy_sessions" in tables
        assert "proxy_samples" in tables
        assert "daily_proxy_usage" in tables
        assert "profile_usage_totals" in tables
        assert "apps" in tables
        assert "app_traffic_samples" in tables
        assert "daily_app_usage" in tables
        assert "app_tracking_events" in tables
        version = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
        assert version == traffic_store.SCHEMA_VERSION


def test_session_start_and_end(tmp_path) -> None:
    store = TrafficStore(tmp_path / "traffic.sqlite3")
    session_id = store.start_proxy_session(
        "profile-1", "Home", "fingerprint", _stats(10, 20), "127.0.0.1:10085", 1080, 8080
    )
    store.end_proxy_session(session_id)

    with sqlite3.connect(store.db_path) as conn:
        row = conn.execute(
            "SELECT profile_id, profile_name, start_uplink_bytes, ended_at FROM proxy_sessions"
        ).fetchone()
    assert row[0] == "profile-1"
    assert row[1] == "Home"
    assert row[2] == 10
    assert row[3] is not None


def test_sample_delta_calculation(tmp_path) -> None:
    store = TrafficStore(tmp_path / "traffic.sqlite3")
    session_id = store.start_proxy_session(
        "profile-1", "Home", "fingerprint", _stats(100, 200), "127.0.0.1:10085", 1080, 8080
    )
    sample = store.record_proxy_sample(
        session_id,
        _stats(250, 500),
        now=datetime(2026, 5, 1, 10, 0, 1, tzinfo=timezone.utc),
    )

    assert sample.uplink_delta_bytes == 150
    assert sample.downlink_delta_bytes == 300
    assert sample.upload_bps > 0
    assert sample.download_bps > 0


def test_counter_reset_handling(tmp_path) -> None:
    store = TrafficStore(tmp_path / "traffic.sqlite3")
    session_id = store.start_proxy_session(
        "profile-1", "Home", "fingerprint", _stats(500, 700), "127.0.0.1:10085", 1080, 8080
    )
    sample = store.record_proxy_sample(session_id, _stats(10, 20))

    assert sample.uplink_delta_bytes == 0
    assert sample.downlink_delta_bytes == 0
    assert sample.warning is not None
    with sqlite3.connect(store.db_path) as conn:
        notes = conn.execute("SELECT notes FROM proxy_sessions WHERE id = ?", (session_id,)).fetchone()[0]
    assert "counter reset/decreased" in notes


def test_daily_aggregation(tmp_path) -> None:
    store = TrafficStore(tmp_path / "traffic.sqlite3")
    session_id = store.start_proxy_session(
        None, "Unsaved profile", "fingerprint", _stats(0, 0), "127.0.0.1:10085", 1080, 8080
    )
    store.record_proxy_sample(
        session_id,
        _stats(100, 200),
        now=datetime(2026, 5, 1, 10, 0, 0, tzinfo=timezone.utc),
    )
    store.record_proxy_sample(
        session_id,
        _stats(150, 260),
        now=datetime(2026, 5, 1, 10, 0, 1, tzinfo=timezone.utc),
    )

    rows = store.get_daily_usage(days=365)
    row = next(item for item in rows if item.date == "2026-05-01")
    assert row.profile_id is None
    assert row.uplink_bytes == 150
    assert row.downlink_bytes == 260


def test_month_summary_uses_local_month(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        traffic_store,
        "_now",
        lambda: datetime(2026, 5, 15, 12, 0, 0, tzinfo=timezone.utc).astimezone(),
    )
    store = TrafficStore(tmp_path / "traffic.sqlite3")
    may_session = store.start_proxy_session(
        None, "Unsaved profile", "may", _stats(0, 0), "127.0.0.1:10085", 1080, 8080
    )
    store.record_proxy_sample(
        may_session,
        _stats(100, 200),
        now=datetime(2026, 5, 1, 10, 0, 0, tzinfo=timezone.utc),
    )
    april_session = store.start_proxy_session(
        None, "Unsaved profile", "april", _stats(0, 0), "127.0.0.1:10085", 1080, 8080
    )
    store.record_proxy_sample(
        april_session,
        _stats(300, 400),
        now=datetime(2026, 4, 30, 10, 0, 0, tzinfo=timezone.utc),
    )

    summary = store.get_month_summary()

    assert summary.uplink_bytes == 100
    assert summary.downlink_bytes == 200


def test_profile_total_aggregation(tmp_path) -> None:
    store = TrafficStore(tmp_path / "traffic.sqlite3")
    session_id = store.start_proxy_session(
        "profile-1", "Home", "fingerprint", _stats(0, 0), "127.0.0.1:10085", 1080, 8080
    )
    store.record_proxy_sample(session_id, _stats(100, 200))
    store.record_proxy_sample(session_id, _stats(175, 230))

    profiles = store.get_profile_summaries()
    assert len(profiles) == 1
    assert profiles[0].profile_id == "profile-1"
    assert profiles[0].profile_name == "Home"
    assert profiles[0].uplink_bytes == 175
    assert profiles[0].downlink_bytes == 230


def test_csv_export(tmp_path) -> None:
    store = TrafficStore(tmp_path / "traffic.sqlite3")
    session_id = store.start_proxy_session(
        "profile-1", "Home", "fingerprint", _stats(0, 0), "127.0.0.1:10085", 1080, 8080
    )
    store.record_proxy_sample(session_id, _stats(100, 200))

    export_path = tmp_path / "traffic.csv"
    store.export_csv(export_path, range_days=365)

    text = export_path.read_text(encoding="utf-8")
    assert "date,profile_id,connection_fingerprint,uplink_bytes,downlink_bytes,total_bytes" in text
    assert "profile-1" in text
    assert ",100,200,300" in text


def test_no_db_corruption_on_repeated_writes(tmp_path) -> None:
    store = TrafficStore(tmp_path / "traffic.sqlite3")
    session_id = store.start_proxy_session(
        "profile-1", "Home", "fingerprint", _stats(0, 0), "127.0.0.1:10085", 1080, 8080
    )

    for idx in range(100):
        store.record_proxy_sample(session_id, _stats(idx + 1, (idx + 1) * 2))

    with sqlite3.connect(store.db_path) as conn:
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        count = conn.execute("SELECT COUNT(*) FROM proxy_samples").fetchone()[0]
    assert integrity == "ok"
    assert count == 100


def test_app_usage_aggregation(tmp_path) -> None:
    store = TrafficStore(tmp_path / "traffic.sqlite3")
    identity = AppIdentity(
        id="app-1",
        name="Browser",
        executable_path="/usr/bin/browser",
        uid=1000,
        trusted_identity=True,
    )
    store.record_app_sample(
        identity,
        rx_bytes=1000,
        tx_bytes=250,
        source="mock",
        confidence="high",
        now=datetime(2026, 5, 1, 10, 0, 0, tzinfo=timezone.utc),
    )
    store.record_app_sample(
        identity,
        rx_bytes=1500,
        tx_bytes=400,
        source="mock",
        confidence="high",
        now=datetime(2026, 5, 1, 10, 0, 1, tzinfo=timezone.utc),
    )

    rows = store.get_app_history(days=365)
    row = next(item for item in rows if item.app_id == "app-1")
    assert row.app_name == "Browser"
    assert row.rx_bytes == 1500
    assert row.tx_bytes == 400
    assert row.confidence == "high"
    assert store.app_tables_present()


def test_clear_history_requires_explicit_call(tmp_path) -> None:
    store = TrafficStore(tmp_path / "traffic.sqlite3")
    session_id = store.start_proxy_session(
        "profile-1", "Home", "fingerprint", _stats(0, 0), "127.0.0.1:10085", 1080, 8080
    )
    store.record_proxy_sample(session_id, _stats(100, 200))
    identity = AppIdentity(id="app-1", name="Browser", executable_path="/usr/bin/browser")
    store.record_app_sample(identity, rx_bytes=50, tx_bytes=25, source="mock")

    assert store.get_daily_usage(days=365)
    assert store.get_app_history(days=365)

    reopened = TrafficStore(store.db_path)
    assert reopened.get_daily_usage(days=365)
    assert reopened.get_app_history(days=365)

    reopened.clear_history(include_app_tracking=True)
    assert reopened.get_daily_usage(days=365) == []
    assert reopened.get_app_history(days=365) == []


def test_session_history_by_date_and_range(tmp_path, monkeypatch) -> None:
    store = TrafficStore(tmp_path / "traffic.sqlite3")
    monkeypatch.setattr(
        traffic_store,
        "_now",
        lambda: datetime(2026, 5, 1, 20, 0, 0),
    )
    session_one = store.start_proxy_session(
        "profile-1", "Home", "fingerprint-1", _stats(0, 0), "127.0.0.1:10085", 1080, 8080
    )
    store.record_proxy_sample(
        session_one,
        _stats(100, 200),
        now=datetime(2026, 5, 1, 20, 10, 0),
    )
    monkeypatch.setattr(
        traffic_store,
        "_now",
        lambda: datetime(2026, 5, 1, 20, 30, 0),
    )
    store.end_proxy_session(session_one)

    monkeypatch.setattr(
        traffic_store,
        "_now",
        lambda: datetime(2026, 5, 2, 8, 0, 0),
    )
    session_two = store.start_proxy_session(
        None, "Unsaved profile", "fingerprint-2", _stats(0, 0), "127.0.0.1:10085", 1081, 8081
    )
    store.record_proxy_sample(
        session_two,
        _stats(50, 75),
        now=datetime(2026, 5, 2, 8, 5, 0),
    )

    may_first = store.get_sessions_for_date("2026-05-01")
    ranged = store.get_sessions_for_range("2026-05-01", "2026-05-02")

    assert [row.session_id for row in may_first] == [session_one]
    assert [row.session_id for row in ranged] == [session_one, session_two]
    assert may_first[0].duration_seconds == 1800
    assert may_first[0].download_bytes == 200
    assert may_first[0].upload_bytes == 100
    assert may_first[0].total_bytes == 300
    assert may_first[0].status == "completed"


def test_active_and_crashed_session_status(tmp_path, monkeypatch) -> None:
    store = TrafficStore(tmp_path / "traffic.sqlite3")
    monkeypatch.setattr(
        traffic_store,
        "_now",
        lambda: datetime(2026, 5, 1, 20, 0, 0),
    )
    session_id = store.start_proxy_session(
        "profile-1", "Home", "fingerprint", _stats(0, 0), "127.0.0.1:10085", 1080, 8080
    )
    store.record_proxy_sample(
        session_id,
        _stats(100, 200),
        now=datetime(2026, 5, 1, 20, 1, 0),
    )
    monkeypatch.setattr(
        traffic_store,
        "_now",
        lambda: datetime(2026, 5, 1, 20, 5, 0),
    )

    active = store.get_session_detail(session_id)
    reopened = TrafficStore(store.db_path)
    crashed = reopened.get_session_detail(session_id)

    assert active.status == "active"
    assert active.duration_seconds == 300
    assert crashed.status == "crashed"
    assert crashed.duration_seconds == 60


def test_unknown_unfinished_session_without_samples(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        traffic_store,
        "_now",
        lambda: datetime(2026, 5, 1, 20, 0, 0),
    )
    store = TrafficStore(tmp_path / "traffic.sqlite3")
    session_id = store.start_proxy_session(
        "profile-1", "Home", "fingerprint", _stats(0, 0), "127.0.0.1:10085", 1080, 8080
    )
    reopened = TrafficStore(store.db_path)

    detail = reopened.get_session_detail(session_id)

    assert detail.status == "unknown"
    assert detail.duration_seconds == 0
    assert detail.sample_count == 0


def test_hourly_usage_and_daily_breakdown(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        traffic_store,
        "_now",
        lambda: datetime(2026, 5, 1, 8, 0, 0),
    )
    store = TrafficStore(tmp_path / "traffic.sqlite3")
    session_id = store.start_proxy_session(
        "profile-1", "Home", "fingerprint", _stats(0, 0), "127.0.0.1:10085", 1080, 8080
    )
    store.record_proxy_sample(
        session_id,
        _stats(100, 200),
        now=datetime(2026, 5, 1, 8, 0, 0),
    )
    store.record_proxy_sample(
        session_id,
        _stats(150, 260),
        now=datetime(2026, 5, 1, 9, 0, 0),
    )

    hourly = store.get_hourly_usage_for_date("2026-05-01")
    monkeypatch.setattr(
        traffic_store,
        "_now",
        lambda: datetime(2026, 5, 2, 12, 0, 0),
    )
    daily = store.get_daily_usage_breakdown(days=2)

    assert len(hourly) == 24
    assert hourly[8].upload_bytes == 100
    assert hourly[8].download_bytes == 200
    assert hourly[9].upload_bytes == 50
    assert hourly[9].download_bytes == 60
    may_first = next(row for row in daily if row.date == "2026-05-01")
    assert may_first.session_count == 1
    assert may_first.upload_bytes == 150
    assert may_first.download_bytes == 260


def test_session_samples_and_csv_exports(tmp_path, monkeypatch) -> None:
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
    store.record_proxy_sample(
        session_id,
        _stats(125, 250),
        now=datetime(2026, 5, 1, 20, 2, 0),
    )

    assert len(store.get_session_samples(session_id)) == 2

    daily_path = tmp_path / "daily.csv"
    sessions_path = tmp_path / "sessions.csv"
    samples_path = tmp_path / "samples.csv"
    store.export_daily_summary_csv(daily_path, start_date="2026-05-01", end_date="2026-05-01")
    store.export_session_summary_csv(sessions_path, start_date="2026-05-01", end_date="2026-05-01")
    store.export_session_samples_csv(samples_path, session_id=session_id)

    assert "date,download_bytes,upload_bytes,total_bytes,session_count" in daily_path.read_text(encoding="utf-8")
    assert "session_id,date,started_at,ended_at,duration_seconds" in sessions_path.read_text(encoding="utf-8")
    assert session_id in sessions_path.read_text(encoding="utf-8")
    assert "timestamp,uplink_bytes,downlink_bytes,uplink_delta_bytes" in samples_path.read_text(encoding="utf-8")
    assert "20:02:00" in samples_path.read_text(encoding="utf-8")


def test_retention_cleanup_deletes_old_samples_but_keeps_summaries(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        traffic_store,
        "_now",
        lambda: datetime(2026, 5, 10, 12, 0, 0),
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

    deleted = store.cleanup_old_samples(7)

    assert deleted == 1
    assert store.get_session_samples(session_id) == []
    assert store.get_sessions_for_date("2026-05-10")
    assert store.get_daily_usage_breakdown_for_range("2026-05-01", "2026-05-10")
