"""Bounded single-writer queue for traffic persistence and maintenance."""

from __future__ import annotations

from dataclasses import dataclass, field
from queue import Full, Queue
import threading
import time
from typing import Any

from v2link_client.core.logging_setup import sanitize_sensitive_text
from v2link_client.core.traffic_store import RetentionCleanupResult, TrafficStore
from v2link_client.core.xray_api import TrafficStats

DEFAULT_TRAFFIC_STORAGE_QUEUE_LIMIT = 8


@dataclass(slots=True)
class _StorageCommand:
    kind: str
    session_id: str | None = None
    stats: TrafficStats | None = None
    retention_days: int = 0
    force: bool = False
    finished: threading.Event | None = None
    result: dict[str, Any] = field(default_factory=dict)


class TrafficStorageWorker:
    """Serialize SQLite writes away from Qt with a bounded, drainable queue."""

    def __init__(self, store: TrafficStore, *, queue_limit: int = DEFAULT_TRAFFIC_STORAGE_QUEUE_LIMIT) -> None:
        self._store = store
        self._queue: Queue[_StorageCommand] = Queue(maxsize=max(1, int(queue_limit)))
        self._lock = threading.Lock()
        self._last_error: str | None = None
        self._last_persisted: dict[str, TrafficStats] = {}
        self._last_submitted: dict[str, TrafficStats] = {}
        self._last_cleanup: RetentionCleanupResult | None = None
        self._dropped_requests = 0
        self._write_count = 0
        self._write_duration_total_ms = 0.0
        self._last_write_duration_ms: float | None = None
        self._write_failures = 0
        self._accepting = True
        self._shutdown_lock = threading.Lock()
        self._thread = threading.Thread(target=self._run, name="v2link-traffic-storage", daemon=True)
        self._thread.start()

    @property
    def queue_size(self) -> int:
        return self._queue.qsize()

    @property
    def is_alive(self) -> bool:
        return self._thread.is_alive()

    @property
    def last_error(self) -> str | None:
        with self._lock:
            return self._last_error

    @property
    def last_cleanup(self) -> RetentionCleanupResult | None:
        with self._lock:
            return self._last_cleanup

    @property
    def dropped_requests(self) -> int:
        with self._lock:
            return self._dropped_requests

    @property
    def write_metrics(self) -> dict[str, int | float | None]:
        with self._lock:
            average = (
                self._write_duration_total_ms / self._write_count
                if self._write_count
                else None
            )
            return {
                "last_ms": self._last_write_duration_ms,
                "average_ms": average,
                "failures": self._write_failures,
                "count": self._write_count,
            }

    def last_persisted_stats(self, session_id: str) -> TrafficStats | None:
        with self._lock:
            return self._last_persisted.get(session_id)

    def submit_sample(self, session_id: str, stats: TrafficStats) -> bool:
        if not self._accepting:
            return False
        with self._lock:
            if self._last_submitted.get(session_id) == stats and self._last_error is None:
                return True
        accepted = self._submit(_StorageCommand("sample", session_id=session_id, stats=stats))
        if accepted:
            with self._lock:
                self._last_submitted[session_id] = stats
        return accepted

    def submit_cleanup(self, retention_days: int, *, force: bool = False) -> bool:
        if not self._accepting:
            return False
        return self._submit(
            _StorageCommand("cleanup", retention_days=int(retention_days), force=force)
        )

    def end_session(
        self,
        session_id: str,
        final_stats: TrafficStats | None,
        *,
        timeout_s: float,
    ) -> bool:
        if not self._accepting:
            return False
        finished = threading.Event()
        command = _StorageCommand(
            "end",
            session_id=session_id,
            stats=final_stats,
            finished=finished,
        )
        try:
            self._queue.put(command, timeout=max(0.1, float(timeout_s)))
        except Full:
            with self._lock:
                self._dropped_requests += 1
            return False
        if not finished.wait(max(0.1, float(timeout_s))):
            return False
        return bool(command.result.get("ok"))

    def wait_until_idle(self, *, timeout_s: float) -> bool:
        deadline = time.monotonic() + max(0.0, float(timeout_s))
        while time.monotonic() < deadline:
            if self._queue.unfinished_tasks == 0:
                return True
            time.sleep(0.005)
        return self._queue.unfinished_tasks == 0

    def shutdown(self, *, drain: bool = True, timeout_s: float = 5.0) -> bool:
        with self._shutdown_lock:
            if not self._thread.is_alive():
                return True
            timeout = max(0.1, float(timeout_s))
            deadline = time.monotonic() + timeout
            self._accepting = False
            if drain:
                self.wait_until_idle(timeout_s=max(0.0, deadline - time.monotonic()))
            command = _StorageCommand("stop")
            remaining = max(0.0, deadline - time.monotonic())
            try:
                if remaining > 0:
                    self._queue.put(command, timeout=remaining)
                else:
                    self._queue.put_nowait(command)
            except Full:
                return False
            self._thread.join(max(0.0, deadline - time.monotonic()))
            return not self._thread.is_alive()

    def _submit(self, command: _StorageCommand) -> bool:
        try:
            self._queue.put_nowait(command)
        except Full:
            with self._lock:
                self._dropped_requests += 1
            return False
        return True

    def _run(self) -> None:
        with self._store.persistent_thread_connection():
            self._run_commands()

    def _run_commands(self) -> None:
        while True:
            command = self._queue.get()
            started_at = time.monotonic()
            try:
                if command.kind == "stop":
                    return
                if command.kind == "sample" and command.session_id and command.stats:
                    self._store.record_proxy_sample(command.session_id, command.stats)
                    with self._lock:
                        self._last_persisted[command.session_id] = command.stats
                        self._last_error = None
                    command.result["ok"] = True
                elif command.kind == "end" and command.session_id:
                    self._store.end_proxy_session(command.session_id, final_stats=command.stats)
                    with self._lock:
                        if command.stats is not None:
                            self._last_persisted[command.session_id] = command.stats
                        self._last_error = None
                    command.result["ok"] = True
                elif command.kind == "cleanup":
                    result = self._store.run_retention_cleanup_if_due(
                        command.retention_days,
                        force=command.force,
                    )
                    with self._lock:
                        self._last_cleanup = result
                        self._last_error = (
                            sanitize_sensitive_text(result.error)
                            if result.error is not None
                            else None
                        )
                    command.result["ok"] = result.error is None
            except Exception as exc:  # persistence must recover on the next cumulative sample
                with self._lock:
                    self._last_error = sanitize_sensitive_text(str(exc))
                    self._write_failures += 1
                    if command.session_id is not None:
                        self._last_submitted.pop(command.session_id, None)
                command.result["ok"] = False
            finally:
                if command.kind in {"sample", "end", "cleanup"}:
                    duration_ms = (time.monotonic() - started_at) * 1000.0
                    with self._lock:
                        self._last_write_duration_ms = duration_ms
                        self._write_duration_total_ms += duration_ms
                        self._write_count += 1
                if command.finished is not None:
                    command.finished.set()
                self._queue.task_done()
