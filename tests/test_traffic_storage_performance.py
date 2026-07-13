from __future__ import annotations

import csv
from datetime import datetime, timedelta, timezone
import sqlite3
import threading

from v2link_client.core.traffic_store import TrafficStore
from v2link_client.core.traffic_storage_worker import TrafficStorageWorker
from v2link_client.core.xray_api import TrafficStats
from v2link_client.ui.traffic_chart_widget import MAX_SESSION_CHART_POINTS


def _stats(up: int, down: int) -> TrafficStats:
    return TrafficStats(uplink_bytes=up, downlink_bytes=down)


def _session(store: TrafficStore) -> str:
    return store.start_proxy_session("profile-1", "Profile", "fp", _stats(0, 0), None, 1080, 8080)


def _bulk_samples(store: TrafficStore, session_id: str, count: int) -> None:
    with sqlite3.connect(store.db_path) as conn:
        conn.executemany(
            """
            INSERT INTO proxy_samples (
                session_id, timestamp, uplink_bytes, downlink_bytes,
                uplink_delta_bytes, downlink_delta_bytes, upload_bps, download_bps
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                (
                    session_id,
                    f"2026-05-01T{(idx // 3600) % 24:02d}:{(idx // 60) % 60:02d}:{idx % 60:02d}+00:00",
                    idx,
                    idx * 2,
                    1,
                    2,
                    float(idx),
                    float(idx * 2),
                )
                for idx in range(count)
            ),
        )


def test_automatic_chart_query_is_bounded_and_keeps_endpoints(tmp_path) -> None:
    store = TrafficStore(tmp_path / "traffic.sqlite3")
    session_id = _session(store)
    _bulk_samples(store, session_id, 10_000)

    rows = store.get_session_chart_samples(session_id, maximum_points=MAX_SESSION_CHART_POINTS)

    assert 2 <= len(rows) <= MAX_SESSION_CHART_POINTS
    assert rows[0].uplink_bytes == 0
    assert rows[-1].uplink_bytes == 9_999
    assert [row.timestamp for row in rows] == sorted(row.timestamp for row in rows)
    assert store.get_session_sample_count(session_id) == 10_000


def test_complete_sample_export_remains_unbounded(tmp_path) -> None:
    store = TrafficStore(tmp_path / "traffic.sqlite3")
    session_id = _session(store)
    _bulk_samples(store, session_id, 10_000)
    target = tmp_path / "samples.csv"

    store.export_session_samples_csv(target, session_id=session_id)

    with target.open(newline="", encoding="utf-8") as handle:
        assert sum(1 for _row in csv.reader(handle)) == 10_001


def test_storage_worker_batches_cumulative_counters_and_finalizes(tmp_path) -> None:
    store = TrafficStore(tmp_path / "traffic.sqlite3")
    session_id = _session(store)
    worker = TrafficStorageWorker(store, queue_limit=4)

    assert worker.submit_sample(session_id, _stats(100, 200)) is True
    assert worker.submit_sample(session_id, _stats(300, 500)) is True
    final = worker.end_session(session_id, _stats(350, 650), timeout_s=5.0)
    worker.shutdown(drain=True, timeout_s=5.0)

    assert final is True
    detail = store.get_session_detail(session_id)
    assert detail.upload_bytes == 350
    assert detail.download_bytes == 650
    assert detail.status == "completed"
    today = store.get_today_summary()
    assert (today.uplink_bytes, today.downlink_bytes) == (350, 650)
    profile = store.get_profile_summaries(limit=1)[0]
    assert (profile.uplink_bytes, profile.downlink_bytes) == (350, 650)


def test_storage_worker_reuses_one_thread_owned_connection(tmp_path, monkeypatch) -> None:
    store = TrafficStore(tmp_path / "traffic.sqlite3")
    session_id = _session(store)
    original = store._open_connection
    opened = 0

    def counted():
        nonlocal opened
        opened += 1
        return original()

    monkeypatch.setattr(store, "_open_connection", counted)
    worker = TrafficStorageWorker(store)
    assert worker.submit_sample(session_id, _stats(100, 200))
    assert worker.submit_sample(session_id, _stats(300, 500))
    assert worker.wait_until_idle(timeout_s=5.0)
    worker.shutdown()

    assert opened == 1


def test_storage_worker_handles_counter_reset_and_short_session(tmp_path) -> None:
    store = TrafficStore(tmp_path / "traffic.sqlite3")
    session_id = _session(store)
    worker = TrafficStorageWorker(store)
    assert worker.submit_sample(session_id, _stats(100, 200))
    assert worker.end_session(session_id, _stats(10, 20), timeout_s=5.0)
    worker.shutdown()

    detail = store.get_session_detail(session_id)
    assert detail.upload_bytes == 100
    assert detail.download_bytes == 200
    assert "counter reset" in (detail.notes or "")


def test_storage_worker_recovers_after_write_failure(tmp_path, monkeypatch) -> None:
    store = TrafficStore(tmp_path / "traffic.sqlite3")
    session_id = _session(store)
    original = store.record_proxy_sample
    calls = 0

    def flaky(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise sqlite3.OperationalError("database busy")
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "record_proxy_sample", flaky)
    worker = TrafficStorageWorker(store)
    assert worker.submit_sample(session_id, _stats(100, 200))
    assert worker.wait_until_idle(timeout_s=5.0)
    assert worker.last_error is not None
    assert worker.submit_sample(session_id, _stats(300, 500))
    assert worker.wait_until_idle(timeout_s=5.0)
    worker.shutdown()

    assert worker.last_error is None
    detail = store.get_session_detail(session_id)
    assert detail.upload_bytes == 300
    assert detail.download_bytes == 500


def test_storage_worker_queue_is_bounded_and_shutdown_drains(tmp_path, monkeypatch) -> None:
    store = TrafficStore(tmp_path / "traffic.sqlite3")
    session_id = _session(store)
    release = threading.Event()
    entered = threading.Event()
    original = store.record_proxy_sample

    def blocked(*args, **kwargs):
        entered.set()
        release.wait(5.0)
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "record_proxy_sample", blocked)
    worker = TrafficStorageWorker(store, queue_limit=2)
    assert worker.submit_sample(session_id, _stats(1, 1))
    assert entered.wait(2.0)
    accepted = [worker.submit_sample(session_id, _stats(idx, idx)) for idx in range(2, 8)]
    assert accepted.count(True) <= 2
    assert worker.queue_size <= 2
    release.set()
    worker.shutdown(drain=True, timeout_s=5.0)
    assert worker.is_alive is False


def test_retention_runs_at_most_daily_and_preserves_summaries(tmp_path) -> None:
    store = TrafficStore(tmp_path / "traffic.sqlite3")
    session_id = _session(store)
    old = datetime.now(timezone.utc) - timedelta(days=40)
    store.record_proxy_sample(session_id, _stats(100, 200), now=old)

    first = store.run_retention_cleanup_if_due(30)
    second = store.run_retention_cleanup_if_due(30)

    assert first.ran is True
    assert first.rows_removed == 1
    assert second.ran is False
    assert store.get_session_detail(session_id).session_id == session_id


def test_existing_v2_database_migrates_without_losing_data(tmp_path) -> None:
    path = tmp_path / "traffic.sqlite3"
    store = TrafficStore(path)
    session_id = _session(store)
    store.record_proxy_sample(session_id, _stats(100, 200))
    with sqlite3.connect(path) as conn:
        conn.execute("DELETE FROM schema_migrations WHERE version > 2")
        conn.execute("DROP TABLE traffic_maintenance")

    reopened = TrafficStore(path)

    assert reopened.get_session_samples(session_id)[-1].downlink_bytes == 200
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] >= 3
