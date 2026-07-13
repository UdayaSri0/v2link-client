"""Persistent proxy and application traffic history backed by SQLite."""

from __future__ import annotations

import csv
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any, Iterator
from uuid import uuid4

from v2link_client.core.storage import get_data_dir
from v2link_client.core.xray_api import TrafficStats

TRAFFIC_DB_FILENAME = "traffic.sqlite3"
SCHEMA_VERSION = 3
DEFAULT_SESSION_QUERY_LIMIT = 1000

CONFIDENCE_LEVELS = {"exact", "high", "medium", "low", "unknown"}
TRAFFIC_SOURCES = {"xray", "netmon-ebpf", "netmon-proc", "netmon-systemd", "mock"}


@dataclass(frozen=True, slots=True)
class ProxyTrafficSample:
    session_id: str
    timestamp: str
    uplink_bytes: int
    downlink_bytes: int
    uplink_delta_bytes: int
    downlink_delta_bytes: int
    upload_bps: float
    download_bps: float
    session_uplink_bytes: int = 0
    session_downlink_bytes: int = 0
    warning: str | None = None


@dataclass(frozen=True, slots=True)
class TrafficUsageSummary:
    uplink_bytes: int
    downlink_bytes: int


@dataclass(frozen=True, slots=True)
class ProfileTrafficSummary:
    profile_id: str
    profile_name: str | None
    connection_fingerprint: str | None
    uplink_bytes: int
    downlink_bytes: int
    first_seen: str
    last_seen: str


@dataclass(frozen=True, slots=True)
class DailyTrafficUsage:
    date: str
    profile_id: str | None
    connection_fingerprint: str | None
    uplink_bytes: int
    downlink_bytes: int


@dataclass(frozen=True, slots=True)
class ProxySessionSummary:
    session_id: str
    profile_id: str | None
    profile_name: str | None
    connection_fingerprint: str | None
    started_at: str
    ended_at: str | None
    duration_seconds: int
    download_bytes: int
    upload_bytes: int
    total_bytes: int
    average_download_bps: float
    average_upload_bps: float
    status: str


@dataclass(frozen=True, slots=True)
class ProxySessionDetail:
    session_id: str
    profile_id: str | None
    profile_name: str | None
    connection_fingerprint: str | None
    started_at: str
    ended_at: str | None
    duration_seconds: int
    download_bytes: int
    upload_bytes: int
    total_bytes: int
    average_download_bps: float
    average_upload_bps: float
    status: str
    xray_api_server: str | None
    socks_port: int | None
    http_port: int | None
    sample_count: int
    first_sample_at: str | None
    last_sample_at: str | None
    peak_download_bps: float
    peak_upload_bps: float
    notes: str | None


@dataclass(frozen=True, slots=True)
class HourlyUsage:
    hour: int
    download_bytes: int
    upload_bytes: int
    total_bytes: int


@dataclass(frozen=True, slots=True)
class DailyUsageBreakdown:
    date: str
    download_bytes: int
    upload_bytes: int
    total_bytes: int
    session_count: int
    first_session_at: str | None
    last_session_at: str | None


@dataclass(frozen=True, slots=True)
class TrafficHistoryDiagnostics:
    session_count: int
    sample_count: int
    oldest_session_at: str | None
    newest_session_at: str | None
    unfinished_session_count: int
    db_file_size_bytes: int


@dataclass(frozen=True, slots=True)
class RetentionCleanupResult:
    ran: bool
    rows_removed: int
    duration_ms: float
    completed_at: str | None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class AppIdentity:
    id: str
    name: str
    executable_path: str
    desktop_id: str | None = None
    icon_name: str | None = None
    pid: int | None = None
    uid: int | None = None
    trusted_identity: bool = False


@dataclass(frozen=True, slots=True)
class AppTrafficSample:
    app_id: str
    timestamp: str
    rx_bytes: int
    tx_bytes: int
    rx_delta_bytes: int
    tx_delta_bytes: int
    download_bps: float
    upload_bps: float
    source: str
    confidence: str
    app_name: str | None = None
    executable_path: str | None = None
    pid: int | None = None
    uid: int | None = None


@dataclass(frozen=True, slots=True)
class AppUsageSummary:
    app_id: str
    app_name: str
    executable_path: str
    rx_bytes: int
    tx_bytes: int
    download_bps: float = 0.0
    upload_bps: float = 0.0
    last_seen: str | None = None
    confidence: str = "unknown"
    source: str = "mock"
    pid: int | None = None
    uid: int | None = None


def get_traffic_db_path() -> Path:
    return get_data_dir() / TRAFFIC_DB_FILENAME


def _now() -> datetime:
    return datetime.now().astimezone()


def _to_iso(value: datetime | None = None) -> str:
    return (value or _now()).astimezone().isoformat()


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _next_month_start(month_prefix: str) -> str:
    year_text, month_text = month_prefix.split("-", maxsplit=1)
    year = int(year_text)
    month = int(month_text)
    if month == 12:
        return f"{year + 1:04d}-01-01"
    return f"{year:04d}-{month + 1:02d}-01"


def _timestamp_range(start_date: str, end_date: str) -> tuple[str, str]:
    start = datetime.fromisoformat(str(start_date)[:10]).date()
    end = datetime.fromisoformat(str(end_date)[:10]).date()
    if end < start:
        start, end = end, start
    return f"{start.isoformat()}T00:00:00", f"{(end + timedelta(days=1)).isoformat()}T00:00:00"


def _stats_pair(stats: TrafficStats | dict[str, Any] | None) -> tuple[int, int]:
    if stats is None:
        return 0, 0
    if isinstance(stats, TrafficStats):
        return max(0, int(stats.uplink_bytes)), max(0, int(stats.downlink_bytes))
    try:
        up = int(stats.get("uplink_bytes", 0))  # type: ignore[union-attr]
        down = int(stats.get("downlink_bytes", 0))  # type: ignore[union-attr]
    except (AttributeError, TypeError, ValueError):
        return 0, 0
    return max(0, up), max(0, down)


def _clean_confidence(value: str | None) -> str:
    cleaned = (value or "unknown").strip().lower()
    return cleaned if cleaned in CONFIDENCE_LEVELS else "unknown"


def _clean_source(value: str | None) -> str:
    cleaned = (value or "mock").strip().lower()
    return cleaned if cleaned in TRAFFIC_SOURCES else "mock"


class TrafficStore:
    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or get_traffic_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._active_proxy_session_id: str | None = None
        self._thread_state = threading.local()
        self._migrate()

    def start_proxy_session(
        self,
        profile_id: str | None,
        profile_name: str | None,
        connection_fingerprint: str | None,
        initial_stats: TrafficStats | dict[str, Any] | None,
        api_server: str | None,
        socks_port: int | None,
        http_port: int | None,
    ) -> str:
        session_id = str(uuid4())
        started_at = _to_iso()
        up, down = _stats_pair(initial_stats)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO proxy_sessions (
                    id, profile_id, profile_name, connection_fingerprint, started_at,
                    start_uplink_bytes, start_downlink_bytes, last_uplink_bytes,
                    last_downlink_bytes, xray_api_server, socks_port, http_port
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    profile_id,
                    profile_name,
                    connection_fingerprint,
                    started_at,
                    up,
                    down,
                    up,
                    down,
                    api_server,
                    socks_port,
                    http_port,
                ),
            )
        self._active_proxy_session_id = session_id
        return session_id

    def record_proxy_sample(
        self,
        session_id: str,
        stats: TrafficStats | dict[str, Any],
        now: datetime | None = None,
    ) -> ProxyTrafficSample:
        timestamp = _to_iso(now)
        current_up, current_down = _stats_pair(stats)

        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT profile_id, profile_name, connection_fingerprint, started_at,
                       last_uplink_bytes, last_downlink_bytes, total_uplink_bytes,
                       total_downlink_bytes, notes
                FROM proxy_sessions
                WHERE id = ?
                """,
                (session_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"Traffic session not found: {session_id}")

            previous_sample = conn.execute(
                """
                SELECT timestamp
                FROM proxy_samples
                WHERE session_id = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (session_id,),
            ).fetchone()
            previous_timestamp = (
                str(previous_sample["timestamp"]) if previous_sample is not None else str(row["started_at"])
            )

            last_up = int(row["last_uplink_bytes"])
            last_down = int(row["last_downlink_bytes"])
            raw_up_delta = current_up - last_up
            raw_down_delta = current_down - last_down
            warnings: list[str] = []
            up_delta = raw_up_delta
            down_delta = raw_down_delta
            if raw_up_delta < 0:
                up_delta = 0
                warnings.append(
                    f"{timestamp}: uplink counter reset/decreased ({last_up} -> {current_up})"
                )
            if raw_down_delta < 0:
                down_delta = 0
                warnings.append(
                    f"{timestamp}: downlink counter reset/decreased ({last_down} -> {current_down})"
                )

            try:
                dt = max(0.001, (_parse_iso(timestamp) - _parse_iso(previous_timestamp)).total_seconds())
            except ValueError:
                dt = 1.0
            upload_bps = float(up_delta) / dt
            download_bps = float(down_delta) / dt

            conn.execute(
                """
                INSERT INTO proxy_samples (
                    session_id, timestamp, uplink_bytes, downlink_bytes,
                    uplink_delta_bytes, downlink_delta_bytes, upload_bps, download_bps
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    timestamp,
                    current_up,
                    current_down,
                    up_delta,
                    down_delta,
                    upload_bps,
                    download_bps,
                ),
            )

            notes = str(row["notes"] or "")
            if warnings:
                notes = "\n".join(part for part in [notes, *warnings] if part)

            total_up = int(row["total_uplink_bytes"]) + up_delta
            total_down = int(row["total_downlink_bytes"]) + down_delta
            conn.execute(
                """
                UPDATE proxy_sessions
                SET last_uplink_bytes = ?,
                    last_downlink_bytes = ?,
                    total_uplink_bytes = ?,
                    total_downlink_bytes = ?,
                    notes = ?
                WHERE id = ?
                """,
                (current_up, current_down, total_up, total_down, notes or None, session_id),
            )

            usage_date = timestamp[:10]
            profile_id = row["profile_id"]
            profile_name = row["profile_name"]
            fingerprint = row["connection_fingerprint"]
            self._add_daily_usage(
                conn,
                date=usage_date,
                profile_id=profile_id,
                connection_fingerprint=fingerprint,
                uplink_delta=up_delta,
                downlink_delta=down_delta,
            )
            if profile_id:
                self._add_profile_usage(
                    conn,
                    profile_id=str(profile_id),
                    profile_name=str(profile_name) if profile_name else None,
                    connection_fingerprint=str(fingerprint) if fingerprint else None,
                    uplink_delta=up_delta,
                    downlink_delta=down_delta,
                    timestamp=timestamp,
                )

        return ProxyTrafficSample(
            session_id=session_id,
            timestamp=timestamp,
            uplink_bytes=current_up,
            downlink_bytes=current_down,
            uplink_delta_bytes=up_delta,
            downlink_delta_bytes=down_delta,
            upload_bps=upload_bps,
            download_bps=download_bps,
            session_uplink_bytes=total_up,
            session_downlink_bytes=total_down,
            warning="; ".join(warnings) if warnings else None,
        )

    def end_proxy_session(
        self,
        session_id: str,
        final_stats: TrafficStats | dict[str, Any] | None = None,
    ) -> None:
        if final_stats is not None:
            self.record_proxy_sample(session_id, final_stats)
        ended_at = _to_iso()
        with self._connect() as conn:
            conn.execute(
                "UPDATE proxy_sessions SET ended_at = ? WHERE id = ? AND ended_at IS NULL",
                (ended_at, session_id),
            )
        if self._active_proxy_session_id == session_id:
            self._active_proxy_session_id = None

    def get_today_summary(self) -> TrafficUsageSummary:
        today = _now().date().isoformat()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT COALESCE(SUM(uplink_bytes), 0) AS uplink_bytes,
                       COALESCE(SUM(downlink_bytes), 0) AS downlink_bytes
                FROM daily_proxy_usage
                WHERE date = ?
                """,
                (today,),
            ).fetchone()
        return TrafficUsageSummary(
            uplink_bytes=int(row["uplink_bytes"] if row else 0),
            downlink_bytes=int(row["downlink_bytes"] if row else 0),
        )

    def get_month_summary(self) -> TrafficUsageSummary:
        month_prefix = _now().date().isoformat()[:7]
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT COALESCE(SUM(uplink_bytes), 0) AS uplink_bytes,
                       COALESCE(SUM(downlink_bytes), 0) AS downlink_bytes
                FROM daily_proxy_usage
                WHERE date >= ? AND date < ?
                """,
                (f"{month_prefix}-01", _next_month_start(month_prefix)),
            ).fetchone()
        return TrafficUsageSummary(
            uplink_bytes=int(row["uplink_bytes"] if row else 0),
            downlink_bytes=int(row["downlink_bytes"] if row else 0),
        )

    def get_profile_summaries(self, limit: int = 20) -> list[ProfileTrafficSummary]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT profile_id, profile_name, connection_fingerprint,
                       uplink_bytes, downlink_bytes, first_seen, last_seen
                FROM profile_usage_totals
                ORDER BY (uplink_bytes + downlink_bytes) DESC, last_seen DESC
                LIMIT ?
                """,
                (max(1, int(limit)),),
            ).fetchall()
        return [
            ProfileTrafficSummary(
                profile_id=str(row["profile_id"]),
                profile_name=row["profile_name"],
                connection_fingerprint=row["connection_fingerprint"],
                uplink_bytes=int(row["uplink_bytes"]),
                downlink_bytes=int(row["downlink_bytes"]),
                first_seen=str(row["first_seen"]),
                last_seen=str(row["last_seen"]),
            )
            for row in rows
        ]

    def get_daily_usage(
        self,
        days: int = 30,
        profile_id: str | None = None,
    ) -> list[DailyTrafficUsage]:
        days = max(1, int(days))
        start_date = (_now().date() - timedelta(days=days - 1)).isoformat()
        params: list[Any] = [start_date]
        where = "date >= ?"
        if profile_id is not None:
            where += " AND profile_id = ?"
            params.append(profile_id)

        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT date, profile_id, connection_fingerprint,
                       SUM(uplink_bytes) AS uplink_bytes,
                       SUM(downlink_bytes) AS downlink_bytes
                FROM daily_proxy_usage
                WHERE {where}
                GROUP BY date, profile_id, connection_fingerprint
                ORDER BY date ASC
                """,
                tuple(params),
            ).fetchall()
        return [
            DailyTrafficUsage(
                date=str(row["date"]),
                profile_id=row["profile_id"],
                connection_fingerprint=row["connection_fingerprint"],
                uplink_bytes=int(row["uplink_bytes"] or 0),
                downlink_bytes=int(row["downlink_bytes"] or 0),
            )
            for row in rows
        ]

    def get_sessions_for_date(self, date: str) -> list[ProxySessionSummary]:
        return self.get_sessions_for_range(date, date)

    def get_sessions_for_range(
        self,
        start_date: str,
        end_date: str,
        *,
        limit: int | None = DEFAULT_SESSION_QUERY_LIMIT,
    ) -> list[ProxySessionSummary]:
        start, end_exclusive = _timestamp_range(start_date, end_date)
        limit_sql = ""
        params: list[Any] = [start, end_exclusive]
        if limit is not None:
            limit_sql = "LIMIT ?"
            params.append(max(1, int(limit)))
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT s.*,
                       CASE WHEN EXISTS (
                           SELECT 1 FROM proxy_samples ps
                           WHERE ps.session_id = s.id LIMIT 1
                       ) THEN 1 ELSE 0 END AS sample_count,
                       NULL AS first_sample_at,
                       (
                           SELECT ps.timestamp FROM proxy_samples ps
                           WHERE ps.session_id = s.id
                           ORDER BY ps.id DESC LIMIT 1
                       ) AS last_sample_at
                FROM proxy_sessions s
                WHERE s.started_at >= ?
                  AND s.started_at < ?
                ORDER BY s.started_at ASC
                {limit_sql}
                """,
                tuple(params),
            ).fetchall()
        return [self._session_summary_from_row(row) for row in rows]

    def get_recent_sessions(self, *, days: int = 30, limit: int = 5) -> list[ProxySessionSummary]:
        start = (_now().date() - timedelta(days=max(1, int(days)) - 1)).isoformat()
        start_timestamp, _end = _timestamp_range(start, _now().date().isoformat())
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT s.*, 0 AS sample_count, NULL AS first_sample_at, NULL AS last_sample_at
                FROM proxy_sessions s
                WHERE s.started_at >= ?
                ORDER BY s.started_at DESC
                LIMIT ?
                """,
                (start_timestamp, max(1, int(limit))),
            ).fetchall()
        summaries = [self._session_summary_from_row(row) for row in rows]
        summaries.reverse()
        return summaries

    def get_session_detail(self, session_id: str) -> ProxySessionDetail:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT s.*,
                       COUNT(ps.id) AS sample_count,
                       MIN(ps.timestamp) AS first_sample_at,
                       MAX(ps.timestamp) AS last_sample_at,
                       COALESCE(MAX(ps.download_bps), 0) AS peak_download_bps,
                       COALESCE(MAX(ps.upload_bps), 0) AS peak_upload_bps
                FROM proxy_sessions s
                LEFT JOIN proxy_samples ps ON ps.session_id = s.id
                WHERE s.id = ?
                GROUP BY s.id
                """,
                (session_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"Traffic session not found: {session_id}")
        summary = self._session_summary_from_row(row)
        return ProxySessionDetail(
            session_id=summary.session_id,
            profile_id=summary.profile_id,
            profile_name=summary.profile_name,
            connection_fingerprint=summary.connection_fingerprint,
            started_at=summary.started_at,
            ended_at=summary.ended_at,
            duration_seconds=summary.duration_seconds,
            download_bytes=summary.download_bytes,
            upload_bytes=summary.upload_bytes,
            total_bytes=summary.total_bytes,
            average_download_bps=summary.average_download_bps,
            average_upload_bps=summary.average_upload_bps,
            status=summary.status,
            xray_api_server=row["xray_api_server"],
            socks_port=int(row["socks_port"]) if row["socks_port"] is not None else None,
            http_port=int(row["http_port"]) if row["http_port"] is not None else None,
            sample_count=int(row["sample_count"] or 0),
            first_sample_at=str(row["first_sample_at"]) if row["first_sample_at"] is not None else None,
            last_sample_at=str(row["last_sample_at"]) if row["last_sample_at"] is not None else None,
            peak_download_bps=max(0.0, float(row["peak_download_bps"] or 0.0)),
            peak_upload_bps=max(0.0, float(row["peak_upload_bps"] or 0.0)),
            notes=str(row["notes"]) if row["notes"] else None,
        )

    def get_session_samples(
        self,
        session_id: str,
        limit: int | None = None,
    ) -> list[ProxyTrafficSample]:
        params: list[Any] = [session_id]
        limit_sql = ""
        if limit is not None:
            limit_sql = "LIMIT ?"
            params.append(max(1, int(limit)))
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT session_id, timestamp, uplink_bytes, downlink_bytes,
                       uplink_delta_bytes, downlink_delta_bytes, upload_bps, download_bps
                FROM proxy_samples
                WHERE session_id = ?
                ORDER BY id ASC
                {limit_sql}
                """,
                tuple(params),
            ).fetchall()
        return [self._proxy_sample_from_row(row) for row in rows]

    def get_session_sample_count(self, session_id: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS sample_count FROM proxy_samples WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        return int(row["sample_count"] or 0) if row else 0

    def get_recent_session_samples(
        self,
        session_id: str,
        *,
        limit: int,
    ) -> list[ProxyTrafficSample]:
        return self.get_recent_samples(session_id=session_id, limit=limit)

    def get_session_chart_samples(
        self,
        session_id: str,
        *,
        maximum_points: int,
    ) -> list[ProxyTrafficSample]:
        """Return peak-preserving time buckets without returning an unbounded row set."""
        limit = max(2, int(maximum_points))
        with self._connect() as conn:
            count_row = conn.execute(
                "SELECT COUNT(*) AS sample_count FROM proxy_samples WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            sample_count = int(count_row["sample_count"] or 0) if count_row else 0
            if sample_count <= limit:
                rows = conn.execute(
                    """
                    SELECT session_id, timestamp, uplink_bytes, downlink_bytes,
                           uplink_delta_bytes, downlink_delta_bytes, upload_bps, download_bps,
                           SUM(uplink_delta_bytes) OVER (ORDER BY id) AS session_uplink_bytes,
                           SUM(downlink_delta_bytes) OVER (ORDER BY id) AS session_downlink_bytes
                    FROM proxy_samples
                    WHERE session_id = ?
                    ORDER BY id ASC
                    LIMIT ?
                    """,
                    (session_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    WITH numbered AS (
                        SELECT id, session_id, timestamp, uplink_bytes, downlink_bytes,
                               uplink_delta_bytes, downlink_delta_bytes, upload_bps, download_bps,
                               ROW_NUMBER() OVER (ORDER BY id) AS row_number,
                               COUNT(*) OVER () AS total_rows,
                               SUM(uplink_delta_bytes) OVER (ORDER BY id) AS session_uplink_bytes,
                               SUM(downlink_delta_bytes) OVER (ORDER BY id) AS session_downlink_bytes
                        FROM proxy_samples
                        WHERE session_id = ?
                    ), bucketed AS (
                        SELECT *,
                               CAST(((row_number - 1) * (? - 1)) / MAX(1, total_rows - 1) AS INTEGER) AS bucket
                        FROM numbered
                    ), ranked AS (
                        SELECT *,
                               ROW_NUMBER() OVER (
                                   PARTITION BY bucket
                                   ORDER BY MAX(download_bps, upload_bps) DESC, row_number ASC
                               ) AS bucket_rank
                        FROM bucketed
                    )
                    SELECT session_id, timestamp, uplink_bytes, downlink_bytes,
                           uplink_delta_bytes, downlink_delta_bytes, upload_bps, download_bps,
                           session_uplink_bytes, session_downlink_bytes
                    FROM ranked
                    WHERE row_number = 1
                       OR row_number = total_rows
                       OR (bucket > 0 AND bucket < ? - 1 AND bucket_rank = 1)
                    ORDER BY id ASC
                    LIMIT ?
                    """,
                    (session_id, limit, limit, limit),
                ).fetchall()
        return [self._proxy_sample_from_row(row) for row in rows]

    def get_hourly_usage_for_date(self, date: str) -> list[HourlyUsage]:
        usage = {hour: [0, 0] for hour in range(24)}
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT CAST(substr(timestamp, 12, 2) AS INTEGER) AS hour,
                       COALESCE(SUM(downlink_delta_bytes), 0) AS download_bytes,
                       COALESCE(SUM(uplink_delta_bytes), 0) AS upload_bytes
                FROM proxy_samples
                WHERE substr(timestamp, 1, 10) = ?
                GROUP BY hour
                ORDER BY hour ASC
                """,
                (str(date)[:10],),
            ).fetchall()
        for row in rows:
            hour = int(row["hour"] or 0)
            if 0 <= hour <= 23:
                usage[hour] = [
                    max(0, int(row["download_bytes"] or 0)),
                    max(0, int(row["upload_bytes"] or 0)),
                ]
        return [
            HourlyUsage(
                hour=hour,
                download_bytes=values[0],
                upload_bytes=values[1],
                total_bytes=values[0] + values[1],
            )
            for hour, values in sorted(usage.items())
        ]

    def get_daily_usage_breakdown(self, days: int = 30) -> list[DailyUsageBreakdown]:
        days = max(1, int(days))
        start_date = (_now().date() - timedelta(days=days - 1)).isoformat()
        return self.get_daily_usage_breakdown_for_range(start_date, _now().date().isoformat())

    def get_daily_usage_breakdown_for_range(
        self,
        start_date: str,
        end_date: str,
    ) -> list[DailyUsageBreakdown]:
        start = str(start_date)[:10]
        end = str(end_date)[:10]
        if end < start:
            start, end = end, start
        start_timestamp, end_exclusive = _timestamp_range(start, end)
        daily: dict[str, dict[str, Any]] = {}
        with self._connect() as conn:
            usage_rows = conn.execute(
                """
                SELECT date,
                       COALESCE(SUM(downlink_bytes), 0) AS download_bytes,
                       COALESCE(SUM(uplink_bytes), 0) AS upload_bytes
                FROM daily_proxy_usage
                WHERE date >= ? AND date <= ?
                GROUP BY date
                """,
                (start, end),
            ).fetchall()
            session_rows = conn.execute(
                """
                SELECT substr(started_at, 1, 10) AS date,
                       COUNT(*) AS session_count,
                       MIN(started_at) AS first_session_at,
                       MAX(COALESCE(ended_at, started_at)) AS last_session_at
                FROM proxy_sessions
                WHERE started_at >= ?
                  AND started_at < ?
                GROUP BY date
                """,
                (start_timestamp, end_exclusive),
            ).fetchall()
        for row in usage_rows:
            date = str(row["date"])
            daily[date] = {
                "download_bytes": max(0, int(row["download_bytes"] or 0)),
                "upload_bytes": max(0, int(row["upload_bytes"] or 0)),
                "session_count": 0,
                "first_session_at": None,
                "last_session_at": None,
            }
        for row in session_rows:
            date = str(row["date"])
            entry = daily.setdefault(
                date,
                {
                    "download_bytes": 0,
                    "upload_bytes": 0,
                    "session_count": 0,
                    "first_session_at": None,
                    "last_session_at": None,
                },
            )
            entry["session_count"] = max(0, int(row["session_count"] or 0))
            entry["first_session_at"] = str(row["first_session_at"]) if row["first_session_at"] else None
            entry["last_session_at"] = str(row["last_session_at"]) if row["last_session_at"] else None
        return [
            DailyUsageBreakdown(
                date=date,
                download_bytes=int(values["download_bytes"]),
                upload_bytes=int(values["upload_bytes"]),
                total_bytes=int(values["download_bytes"]) + int(values["upload_bytes"]),
                session_count=int(values["session_count"]),
                first_session_at=values["first_session_at"],
                last_session_at=values["last_session_at"],
            )
            for date, values in sorted(daily.items())
        ]

    def get_recent_samples(
        self,
        session_id: str | None = None,
        limit: int = 300,
    ) -> list[ProxyTrafficSample]:
        params: list[Any] = []
        where = ""
        if session_id is not None:
            where = "WHERE session_id = ?"
            params.append(session_id)
        params.append(max(1, int(limit)))
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT session_id, timestamp, uplink_bytes, downlink_bytes,
                       uplink_delta_bytes, downlink_delta_bytes, upload_bps, download_bps
                FROM proxy_samples
                {where}
                ORDER BY id DESC
                LIMIT ?
                """,
                tuple(params),
            ).fetchall()
        rows.reverse()
        return [self._proxy_sample_from_row(row) for row in rows]

    def export_csv(self, path: str | Path, range_days: int = 30) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        rows = self.get_daily_usage(days=range_days)
        with destination.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                [
                    "date",
                    "profile_id",
                    "connection_fingerprint",
                    "uplink_bytes",
                    "downlink_bytes",
                    "total_bytes",
                ]
            )
            for row in rows:
                writer.writerow(
                    [
                        row.date,
                        row.profile_id or "",
                        row.connection_fingerprint or "",
                        row.uplink_bytes,
                        row.downlink_bytes,
                        row.uplink_bytes + row.downlink_bytes,
                    ]
                )

    def export_daily_summary_csv(
        self,
        path: str | Path,
        *,
        start_date: str,
        end_date: str,
    ) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        rows = self.get_daily_usage_breakdown_for_range(start_date, end_date)
        with destination.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                [
                    "date",
                    "download_bytes",
                    "upload_bytes",
                    "total_bytes",
                    "session_count",
                    "first_session_at",
                    "last_session_at",
                ]
            )
            for row in rows:
                writer.writerow(
                    [
                        row.date,
                        row.download_bytes,
                        row.upload_bytes,
                        row.total_bytes,
                        row.session_count,
                        row.first_session_at or "",
                        row.last_session_at or "",
                    ]
                )

    def export_session_summary_csv(
        self,
        path: str | Path,
        *,
        start_date: str,
        end_date: str,
    ) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        rows = self.get_sessions_for_range(start_date, end_date, limit=None)
        with destination.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                [
                    "session_id",
                    "date",
                    "started_at",
                    "ended_at",
                    "duration_seconds",
                    "profile_id",
                    "profile_name",
                    "download_bytes",
                    "upload_bytes",
                    "total_bytes",
                    "average_download_bps",
                    "average_upload_bps",
                    "status",
                ]
            )
            for row in rows:
                writer.writerow(
                    [
                        row.session_id,
                        row.started_at[:10],
                        row.started_at,
                        row.ended_at or "",
                        row.duration_seconds,
                        row.profile_id or "",
                        row.profile_name or "",
                        row.download_bytes,
                        row.upload_bytes,
                        row.total_bytes,
                        f"{row.average_download_bps:.3f}",
                        f"{row.average_upload_bps:.3f}",
                        row.status,
                    ]
                )

    def export_session_samples_csv(self, path: str | Path, *, session_id: str) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn, destination.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                [
                    "timestamp",
                    "uplink_bytes",
                    "downlink_bytes",
                    "uplink_delta_bytes",
                    "downlink_delta_bytes",
                    "upload_bps",
                    "download_bps",
                ]
            )
            rows = conn.execute(
                """
                SELECT session_id, timestamp, uplink_bytes, downlink_bytes,
                       uplink_delta_bytes, downlink_delta_bytes, upload_bps, download_bps
                FROM proxy_samples
                WHERE session_id = ?
                ORDER BY id ASC
                """,
                (session_id,),
            )
            for raw_row in rows:
                row = self._proxy_sample_from_row(raw_row)
                writer.writerow(
                    [
                        row.timestamp,
                        row.uplink_bytes,
                        row.downlink_bytes,
                        row.uplink_delta_bytes,
                        row.downlink_delta_bytes,
                        f"{row.upload_bps:.3f}",
                        f"{row.download_bps:.3f}",
                    ]
                )

    def export_app_csv(self, path: str | Path, range_days: int = 30) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        rows = self.get_app_history(days=range_days)
        with destination.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                [
                    "date",
                    "app_id",
                    "application",
                    "executable_path",
                    "rx_bytes",
                    "tx_bytes",
                    "total_bytes",
                ]
            )
            for row in rows:
                writer.writerow(
                    [
                        row.last_seen or "",
                        row.app_id,
                        row.app_name,
                        row.executable_path,
                        row.rx_bytes,
                        row.tx_bytes,
                        row.rx_bytes + row.tx_bytes,
                    ]
                )

    def cleanup_old_samples(self, retention_days: int) -> int:
        days = int(retention_days)
        if days <= 0:
            return 0
        cutoff = _to_iso(_now() - timedelta(days=days))
        with self._connect() as conn:
            result = conn.execute("DELETE FROM proxy_samples WHERE timestamp < ?", (cutoff,))
            return int(result.rowcount or 0)

    def run_retention_cleanup_if_due(
        self,
        retention_days: int,
        *,
        minimum_interval: timedelta = timedelta(days=1),
        force: bool = False,
    ) -> RetentionCleanupResult:
        started = time.monotonic()
        now = _now()
        with self._connect() as conn:
            previous = conn.execute(
                "SELECT last_run_at FROM traffic_maintenance WHERE name = 'sample_retention'"
            ).fetchone()
            previous_at = None
            if previous and previous["last_run_at"]:
                try:
                    previous_at = _parse_iso(str(previous["last_run_at"]))
                except ValueError:
                    previous_at = None
            if not force and previous_at is not None and now - previous_at < minimum_interval:
                return RetentionCleanupResult(False, 0, 0.0, _to_iso(previous_at), None)

            rows_removed = 0
            error: str | None = None
            try:
                days = int(retention_days)
                if days > 0:
                    cutoff = _to_iso(now - timedelta(days=days))
                    result = conn.execute(
                        "DELETE FROM proxy_samples WHERE timestamp < ?",
                        (cutoff,),
                    )
                    rows_removed = int(result.rowcount or 0)
            except Exception as exc:
                error = str(exc)
            duration_ms = (time.monotonic() - started) * 1000.0
            completed_at = _to_iso(now)
            conn.execute(
                """
                INSERT INTO traffic_maintenance(name, last_run_at, duration_ms, rows_removed, last_error)
                VALUES ('sample_retention', ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    last_run_at = excluded.last_run_at,
                    duration_ms = excluded.duration_ms,
                    rows_removed = excluded.rows_removed,
                    last_error = excluded.last_error
                """,
                (completed_at, duration_ms, rows_removed, error),
            )
        return RetentionCleanupResult(True, rows_removed, duration_ms, completed_at, error)

    def get_history_diagnostics(self) -> TrafficHistoryDiagnostics:
        with self._connect() as conn:
            sessions = conn.execute(
                """
                SELECT COUNT(*) AS session_count,
                       MIN(started_at) AS oldest_session_at,
                       MAX(started_at) AS newest_session_at,
                       SUM(CASE WHEN ended_at IS NULL THEN 1 ELSE 0 END) AS unfinished_session_count
                FROM proxy_sessions
                """
            ).fetchone()
            samples = conn.execute("SELECT COUNT(*) AS sample_count FROM proxy_samples").fetchone()
        return TrafficHistoryDiagnostics(
            session_count=int(sessions["session_count"] or 0) if sessions else 0,
            sample_count=int(samples["sample_count"] or 0) if samples else 0,
            oldest_session_at=str(sessions["oldest_session_at"]) if sessions and sessions["oldest_session_at"] else None,
            newest_session_at=str(sessions["newest_session_at"]) if sessions and sessions["newest_session_at"] else None,
            unfinished_session_count=int(sessions["unfinished_session_count"] or 0) if sessions else 0,
            db_file_size_bytes=self.db_path.stat().st_size if self.db_path.exists() else 0,
        )

    def upsert_app(self, identity: AppIdentity, *, now: datetime | None = None) -> str:
        timestamp = _to_iso(now)
        app_id = identity.id.strip()
        if not app_id:
            raise ValueError("app id is required")
        name = identity.name.strip() or "Unknown application"
        executable_path = identity.executable_path.strip()
        if not executable_path:
            raise ValueError("executable path is required")

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO apps (
                    id, name, executable_path, desktop_id, icon_name, uid,
                    first_seen, last_seen, trusted_identity
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    executable_path = excluded.executable_path,
                    desktop_id = excluded.desktop_id,
                    icon_name = excluded.icon_name,
                    uid = excluded.uid,
                    last_seen = excluded.last_seen,
                    trusted_identity = excluded.trusted_identity
                """,
                (
                    app_id,
                    name,
                    executable_path,
                    identity.desktop_id,
                    identity.icon_name,
                    identity.uid,
                    timestamp,
                    timestamp,
                    1 if identity.trusted_identity else 0,
                ),
            )
        return app_id

    def record_app_sample(
        self,
        identity: AppIdentity,
        *,
        rx_bytes: int,
        tx_bytes: int,
        source: str,
        confidence: str = "unknown",
        now: datetime | None = None,
    ) -> AppTrafficSample:
        timestamp = _to_iso(now)
        app_id = self.upsert_app(identity, now=now)
        current_rx = max(0, int(rx_bytes))
        current_tx = max(0, int(tx_bytes))
        source = _clean_source(source)
        confidence = _clean_confidence(confidence)

        with self._connect() as conn:
            previous = conn.execute(
                """
                SELECT timestamp, rx_bytes, tx_bytes
                FROM app_traffic_samples
                WHERE app_id = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (app_id,),
            ).fetchone()
            if previous is None:
                previous_timestamp = timestamp
                rx_delta = current_rx
                tx_delta = current_tx
            else:
                previous_timestamp = str(previous["timestamp"])
                rx_delta = max(0, current_rx - int(previous["rx_bytes"]))
                tx_delta = max(0, current_tx - int(previous["tx_bytes"]))

            try:
                dt = max(0.001, (_parse_iso(timestamp) - _parse_iso(previous_timestamp)).total_seconds())
            except ValueError:
                dt = 1.0
            download_bps = float(rx_delta) / dt
            upload_bps = float(tx_delta) / dt

            conn.execute(
                """
                INSERT INTO app_traffic_samples (
                    app_id, timestamp, rx_bytes, tx_bytes, rx_delta_bytes, tx_delta_bytes,
                    download_bps, upload_bps, source, confidence
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    app_id,
                    timestamp,
                    current_rx,
                    current_tx,
                    rx_delta,
                    tx_delta,
                    download_bps,
                    upload_bps,
                    source,
                    confidence,
                ),
            )
            conn.execute("UPDATE apps SET last_seen = ? WHERE id = ?", (timestamp, app_id))
            self._add_daily_app_usage(
                conn,
                date=timestamp[:10],
                app_id=app_id,
                rx_delta=rx_delta,
                tx_delta=tx_delta,
            )

        return AppTrafficSample(
            app_id=app_id,
            timestamp=timestamp,
            rx_bytes=current_rx,
            tx_bytes=current_tx,
            rx_delta_bytes=rx_delta,
            tx_delta_bytes=tx_delta,
            download_bps=download_bps,
            upload_bps=upload_bps,
            source=source,
            confidence=confidence,
            app_name=identity.name,
            executable_path=identity.executable_path,
            pid=identity.pid,
            uid=identity.uid,
        )

    def get_today_app_usage(self) -> list[AppUsageSummary]:
        today = _now().date().isoformat()
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT a.id AS app_id, a.name, a.executable_path, a.uid, a.last_seen,
                       u.rx_bytes, u.tx_bytes,
                       COALESCE(s.download_bps, 0) AS download_bps,
                       COALESCE(s.upload_bps, 0) AS upload_bps,
                       COALESCE(s.confidence, 'unknown') AS confidence,
                       COALESCE(s.source, 'mock') AS source
                FROM daily_app_usage u
                JOIN apps a ON a.id = u.app_id
                LEFT JOIN app_traffic_samples s ON s.id = (
                    SELECT id FROM app_traffic_samples
                    WHERE app_id = a.id
                    ORDER BY id DESC
                    LIMIT 1
                )
                WHERE u.date = ?
                ORDER BY (u.rx_bytes + u.tx_bytes) DESC, a.name ASC
                """,
                (today,),
            ).fetchall()
        return [self._app_summary_from_row(row, last_seen_key="last_seen") for row in rows]

    def get_app_history(self, days: int = 30) -> list[AppUsageSummary]:
        days = max(1, int(days))
        start_date = (_now().date() - timedelta(days=days - 1)).isoformat()
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT a.id AS app_id, a.name, a.executable_path, a.uid,
                       u.date AS usage_date, u.rx_bytes, u.tx_bytes,
                       COALESCE(s.download_bps, 0) AS download_bps,
                       COALESCE(s.upload_bps, 0) AS upload_bps,
                       COALESCE(s.confidence, 'unknown') AS confidence,
                       COALESCE(s.source, 'mock') AS source
                FROM daily_app_usage u
                JOIN apps a ON a.id = u.app_id
                LEFT JOIN app_traffic_samples s ON s.id = (
                    SELECT id FROM app_traffic_samples
                    WHERE app_id = a.id
                    ORDER BY id DESC
                    LIMIT 1
                )
                WHERE u.date >= ?
                ORDER BY u.date ASC, (u.rx_bytes + u.tx_bytes) DESC
                """,
                (start_date,),
            ).fetchall()
        return [self._app_summary_from_row(row, last_seen_key="usage_date") for row in rows]

    def log_app_tracking_event(
        self,
        level: str,
        message: str,
        detail: str | None = None,
        *,
        now: datetime | None = None,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO app_tracking_events(timestamp, level, message, detail)
                VALUES (?, ?, ?, ?)
                """,
                (_to_iso(now), level.strip().lower() or "info", message.strip(), detail),
            )

    def app_tables_present(self) -> bool:
        required = {"apps", "app_traffic_samples", "daily_app_usage", "app_tracking_events"}
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        return required.issubset({str(row["name"]) for row in rows})

    def clear_history(self, *, include_app_tracking: bool = True) -> None:
        """Explicitly clear stored traffic history.

        This is intentionally only called by direct user action/tests.
        """
        with self._connect() as conn:
            conn.execute("DELETE FROM proxy_samples")
            conn.execute("DELETE FROM proxy_sessions")
            conn.execute("DELETE FROM daily_proxy_usage")
            conn.execute("DELETE FROM profile_usage_totals")
            if include_app_tracking:
                conn.execute("DELETE FROM app_traffic_samples")
                conn.execute("DELETE FROM daily_app_usage")
                conn.execute("DELETE FROM app_tracking_events")
                conn.execute("DELETE FROM apps")

    def _open_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA busy_timeout = 3000")
        conn.execute("PRAGMA wal_autocheckpoint = 1000")
        return conn

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        persistent = getattr(self._thread_state, "connection", None)
        if isinstance(persistent, sqlite3.Connection):
            with persistent:
                yield persistent
            return
        conn = self._open_connection()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    @contextmanager
    def persistent_thread_connection(self) -> Iterator[None]:
        """Reuse one SQLite connection only within the calling worker thread."""
        if getattr(self._thread_state, "connection", None) is not None:
            yield
            return
        conn = self._open_connection()
        self._thread_state.connection = conn
        try:
            yield
        finally:
            del self._thread_state.connection
            conn.close()

    def _migrate(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                )
                """
            )
            current = conn.execute(
                "SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations"
            ).fetchone()
            version = int(current["version"] if current else 0)
            if version < 1:
                self._apply_schema_v1(conn)
                conn.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                    (1, _to_iso()),
                )
                version = 1
            if version < 2:
                self._apply_schema_v2(conn)
                conn.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                    (2, _to_iso()),
                )
                version = 2
            if version < 3:
                self._apply_schema_v3(conn)
                conn.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                    (3, _to_iso()),
                )

    def _apply_schema_v1(self, conn: sqlite3.Connection) -> None:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS proxy_sessions (
                id TEXT PRIMARY KEY,
                profile_id TEXT NULL,
                profile_name TEXT NULL,
                connection_fingerprint TEXT NULL,
                started_at TEXT NOT NULL,
                ended_at TEXT NULL,
                start_uplink_bytes INTEGER NOT NULL DEFAULT 0,
                start_downlink_bytes INTEGER NOT NULL DEFAULT 0,
                last_uplink_bytes INTEGER NOT NULL DEFAULT 0,
                last_downlink_bytes INTEGER NOT NULL DEFAULT 0,
                total_uplink_bytes INTEGER NOT NULL DEFAULT 0,
                total_downlink_bytes INTEGER NOT NULL DEFAULT 0,
                xray_api_server TEXT NULL,
                socks_port INTEGER NULL,
                http_port INTEGER NULL,
                notes TEXT NULL
            );

            CREATE TABLE IF NOT EXISTS proxy_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                uplink_bytes INTEGER NOT NULL,
                downlink_bytes INTEGER NOT NULL,
                uplink_delta_bytes INTEGER NOT NULL,
                downlink_delta_bytes INTEGER NOT NULL,
                upload_bps REAL NOT NULL DEFAULT 0,
                download_bps REAL NOT NULL DEFAULT 0,
                FOREIGN KEY(session_id) REFERENCES proxy_sessions(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS daily_proxy_usage (
                date TEXT NOT NULL,
                profile_id TEXT NULL,
                connection_fingerprint TEXT NULL,
                uplink_bytes INTEGER NOT NULL DEFAULT 0,
                downlink_bytes INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(date, profile_id, connection_fingerprint)
            );

            CREATE TABLE IF NOT EXISTS profile_usage_totals (
                profile_id TEXT PRIMARY KEY,
                profile_name TEXT NULL,
                connection_fingerprint TEXT NULL,
                uplink_bytes INTEGER NOT NULL DEFAULT 0,
                downlink_bytes INTEGER NOT NULL DEFAULT 0,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_proxy_sessions_profile_id
                ON proxy_sessions(profile_id);
            CREATE INDEX IF NOT EXISTS idx_proxy_sessions_started_at
                ON proxy_sessions(started_at);
            CREATE INDEX IF NOT EXISTS idx_proxy_samples_session_id
                ON proxy_samples(session_id);
            CREATE INDEX IF NOT EXISTS idx_proxy_samples_timestamp
                ON proxy_samples(timestamp);
            CREATE INDEX IF NOT EXISTS idx_daily_proxy_usage_date
                ON daily_proxy_usage(date);
            CREATE INDEX IF NOT EXISTS idx_daily_proxy_usage_profile_id
                ON daily_proxy_usage(profile_id);
            CREATE INDEX IF NOT EXISTS idx_profile_usage_totals_last_seen
                ON profile_usage_totals(last_seen);
            """
        )

    def _apply_schema_v2(self, conn: sqlite3.Connection) -> None:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS apps (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                executable_path TEXT NOT NULL,
                desktop_id TEXT NULL,
                icon_name TEXT NULL,
                uid INTEGER NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                trusted_identity INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS app_traffic_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                app_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                rx_bytes INTEGER NOT NULL DEFAULT 0,
                tx_bytes INTEGER NOT NULL DEFAULT 0,
                rx_delta_bytes INTEGER NOT NULL DEFAULT 0,
                tx_delta_bytes INTEGER NOT NULL DEFAULT 0,
                download_bps REAL NOT NULL DEFAULT 0,
                upload_bps REAL NOT NULL DEFAULT 0,
                source TEXT NOT NULL,
                confidence TEXT NOT NULL DEFAULT 'unknown',
                FOREIGN KEY(app_id) REFERENCES apps(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS daily_app_usage (
                date TEXT NOT NULL,
                app_id TEXT NOT NULL,
                rx_bytes INTEGER NOT NULL DEFAULT 0,
                tx_bytes INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(date, app_id),
                FOREIGN KEY(app_id) REFERENCES apps(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS app_tracking_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                level TEXT NOT NULL,
                message TEXT NOT NULL,
                detail TEXT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_apps_name
                ON apps(name);
            CREATE INDEX IF NOT EXISTS idx_apps_executable_path
                ON apps(executable_path);
            CREATE INDEX IF NOT EXISTS idx_app_traffic_samples_app_id
                ON app_traffic_samples(app_id);
            CREATE INDEX IF NOT EXISTS idx_app_traffic_samples_timestamp
                ON app_traffic_samples(timestamp);
            CREATE INDEX IF NOT EXISTS idx_daily_app_usage_date
                ON daily_app_usage(date);
            CREATE INDEX IF NOT EXISTS idx_daily_app_usage_app_id
                ON daily_app_usage(app_id);
            CREATE INDEX IF NOT EXISTS idx_app_tracking_events_timestamp
                ON app_tracking_events(timestamp);
            """
        )

    def _apply_schema_v3(self, conn: sqlite3.Connection) -> None:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS traffic_maintenance (
                name TEXT PRIMARY KEY,
                last_run_at TEXT NULL,
                duration_ms REAL NOT NULL DEFAULT 0,
                rows_removed INTEGER NOT NULL DEFAULT 0,
                last_error TEXT NULL
            );
            """
        )

    def _add_daily_usage(
        self,
        conn: sqlite3.Connection,
        *,
        date: str,
        profile_id: str | None,
        connection_fingerprint: str | None,
        uplink_delta: int,
        downlink_delta: int,
    ) -> None:
        result = conn.execute(
            """
            UPDATE daily_proxy_usage
            SET uplink_bytes = uplink_bytes + ?,
                downlink_bytes = downlink_bytes + ?
            WHERE date = ?
              AND (profile_id = ? OR (profile_id IS NULL AND ? IS NULL))
              AND (
                connection_fingerprint = ?
                OR (connection_fingerprint IS NULL AND ? IS NULL)
              )
            """,
            (
                uplink_delta,
                downlink_delta,
                date,
                profile_id,
                profile_id,
                connection_fingerprint,
                connection_fingerprint,
            ),
        )
        if result.rowcount:
            return
        conn.execute(
            """
            INSERT INTO daily_proxy_usage (
                date, profile_id, connection_fingerprint, uplink_bytes, downlink_bytes
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (date, profile_id, connection_fingerprint, uplink_delta, downlink_delta),
        )

    def _add_profile_usage(
        self,
        conn: sqlite3.Connection,
        *,
        profile_id: str,
        profile_name: str | None,
        connection_fingerprint: str | None,
        uplink_delta: int,
        downlink_delta: int,
        timestamp: str,
    ) -> None:
        conn.execute(
            """
            INSERT INTO profile_usage_totals (
                profile_id, profile_name, connection_fingerprint,
                uplink_bytes, downlink_bytes, first_seen, last_seen
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(profile_id) DO UPDATE SET
                profile_name = excluded.profile_name,
                connection_fingerprint = excluded.connection_fingerprint,
                uplink_bytes = profile_usage_totals.uplink_bytes + excluded.uplink_bytes,
                downlink_bytes = profile_usage_totals.downlink_bytes + excluded.downlink_bytes,
                last_seen = excluded.last_seen
            """,
            (
                profile_id,
                profile_name,
                connection_fingerprint,
                uplink_delta,
                downlink_delta,
                timestamp,
                timestamp,
            ),
        )

    def _add_daily_app_usage(
        self,
        conn: sqlite3.Connection,
        *,
        date: str,
        app_id: str,
        rx_delta: int,
        tx_delta: int,
    ) -> None:
        conn.execute(
            """
            INSERT INTO daily_app_usage(date, app_id, rx_bytes, tx_bytes)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(date, app_id) DO UPDATE SET
                rx_bytes = daily_app_usage.rx_bytes + excluded.rx_bytes,
                tx_bytes = daily_app_usage.tx_bytes + excluded.tx_bytes
            """,
            (date, app_id, rx_delta, tx_delta),
        )

    def _proxy_sample_from_row(self, row: sqlite3.Row) -> ProxyTrafficSample:
        keys = row.keys()
        return ProxyTrafficSample(
            session_id=str(row["session_id"]),
            timestamp=str(row["timestamp"]),
            uplink_bytes=max(0, int(row["uplink_bytes"] or 0)),
            downlink_bytes=max(0, int(row["downlink_bytes"] or 0)),
            uplink_delta_bytes=max(0, int(row["uplink_delta_bytes"] or 0)),
            downlink_delta_bytes=max(0, int(row["downlink_delta_bytes"] or 0)),
            upload_bps=max(0.0, float(row["upload_bps"] or 0.0)),
            download_bps=max(0.0, float(row["download_bps"] or 0.0)),
            session_uplink_bytes=(
                max(0, int(row["session_uplink_bytes"] or 0))
                if "session_uplink_bytes" in keys
                else 0
            ),
            session_downlink_bytes=(
                max(0, int(row["session_downlink_bytes"] or 0))
                if "session_downlink_bytes" in keys
                else 0
            ),
        )

    def _session_summary_from_row(self, row: sqlite3.Row) -> ProxySessionSummary:
        session_id = str(row["id"])
        started_at = str(row["started_at"])
        ended_at = str(row["ended_at"]) if row["ended_at"] else None
        first_sample_at = str(row["first_sample_at"]) if "first_sample_at" in row.keys() and row["first_sample_at"] else None
        last_sample_at = str(row["last_sample_at"]) if "last_sample_at" in row.keys() and row["last_sample_at"] else None
        sample_count = int(row["sample_count"] or 0) if "sample_count" in row.keys() else 0
        status = self._session_status(session_id, ended_at=ended_at, sample_count=sample_count)
        duration = self._session_duration_seconds(
            started_at=started_at,
            ended_at=ended_at,
            last_sample_at=last_sample_at,
            status=status,
        )
        upload = max(0, int(row["total_uplink_bytes"] or 0))
        download = max(0, int(row["total_downlink_bytes"] or 0))
        denominator = max(1, duration)
        return ProxySessionSummary(
            session_id=session_id,
            profile_id=str(row["profile_id"]) if row["profile_id"] else None,
            profile_name=str(row["profile_name"]) if row["profile_name"] else None,
            connection_fingerprint=str(row["connection_fingerprint"]) if row["connection_fingerprint"] else None,
            started_at=started_at,
            ended_at=ended_at,
            duration_seconds=duration,
            download_bytes=download,
            upload_bytes=upload,
            total_bytes=download + upload,
            average_download_bps=float(download) / denominator,
            average_upload_bps=float(upload) / denominator,
            status=status,
        )

    def _session_status(self, session_id: str, *, ended_at: str | None, sample_count: int) -> str:
        if ended_at:
            return "completed"
        if self._active_proxy_session_id == session_id:
            return "active"
        return "crashed" if sample_count > 0 else "unknown"

    def _session_duration_seconds(
        self,
        *,
        started_at: str,
        ended_at: str | None,
        last_sample_at: str | None,
        status: str,
    ) -> int:
        try:
            start = _parse_iso(started_at)
        except ValueError:
            return 0
        end_text = ended_at
        if end_text is None and status == "active":
            end = _now()
        elif end_text is None:
            end = _parse_iso(last_sample_at) if last_sample_at else start
        else:
            try:
                end = _parse_iso(end_text)
            except ValueError:
                end = start
        if (start.tzinfo is None) != (end.tzinfo is None):
            if start.tzinfo is not None:
                start = start.astimezone().replace(tzinfo=None)
            if end.tzinfo is not None:
                end = end.astimezone().replace(tzinfo=None)
        return max(0, int((end - start).total_seconds()))

    def _app_summary_from_row(
        self,
        row: sqlite3.Row,
        *,
        last_seen_key: str,
    ) -> AppUsageSummary:
        return AppUsageSummary(
            app_id=str(row["app_id"]),
            app_name=str(row["name"]),
            executable_path=str(row["executable_path"]),
            rx_bytes=int(row["rx_bytes"] or 0),
            tx_bytes=int(row["tx_bytes"] or 0),
            download_bps=float(row["download_bps"] or 0.0),
            upload_bps=float(row["upload_bps"] or 0.0),
            last_seen=str(row[last_seen_key]) if row[last_seen_key] is not None else None,
            confidence=_clean_confidence(str(row["confidence"] or "unknown")),
            source=_clean_source(str(row["source"] or "mock")),
            uid=int(row["uid"]) if row["uid"] is not None else None,
        )
