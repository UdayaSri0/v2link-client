"""Persistent proxy and application traffic history backed by SQLite."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
import sqlite3
from typing import Any
from uuid import uuid4

from v2link_client.core.storage import get_data_dir
from v2link_client.core.xray_api import TrafficStats

TRAFFIC_DB_FILENAME = "traffic.sqlite3"
SCHEMA_VERSION = 2

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
        return [
            ProxyTrafficSample(
                session_id=str(row["session_id"]),
                timestamp=str(row["timestamp"]),
                uplink_bytes=int(row["uplink_bytes"]),
                downlink_bytes=int(row["downlink_bytes"]),
                uplink_delta_bytes=int(row["uplink_delta_bytes"]),
                downlink_delta_bytes=int(row["downlink_delta_bytes"]),
                upload_bps=float(row["upload_bps"]),
                download_bps=float(row["download_bps"]),
            )
            for row in rows
        ]

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

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA busy_timeout = 3000")
        return conn

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
