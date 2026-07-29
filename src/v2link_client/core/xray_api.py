"""Interact with Xray's local API (via the `xray api ...` CLI).

We intentionally shell out to the `xray` binary instead of implementing gRPC
clients. This keeps the app dependency-free and matches how users validate
their setup manually.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import logging
import re
import subprocess
import threading
from typing import Final

from v2link_client.core.errors import AppError, BinaryMissingError, PermissionDeniedError
from v2link_client.core.system_subprocess import build_xray_subprocess_env
from v2link_client.core.owned_process import terminate_owned_process


_STAT_RE: Final[re.Pattern[str]] = re.compile(r'name:\\s*\"(?P<name>[^\"]+)\"\\s+value:\\s*(?P<value>\\d+)')
logger = logging.getLogger(__name__)

_stats_process_lock = threading.Lock()
_stats_processes: dict[int, subprocess.Popen[str]] = {}
_stats_query_slot = threading.Lock()


class XrayApiError(AppError):
    pass


@dataclass(frozen=True, slots=True)
class TrafficStats:
    uplink_bytes: int
    downlink_bytes: int


def statsquery(
    xray_path: str,
    *,
    server: str,
    pattern: str | None = None,
    timeout_s: float = 3.0,
    reset: bool = False,
) -> dict[str, int]:
    if not _stats_query_slot.acquire(blocking=False):
        raise XrayApiError(
            "another xray stats query is already active",
            user_message="An Xray stats query is already in progress.",
        )
    try:
        return _statsquery_owned(
            xray_path,
            server=server,
            pattern=pattern,
            timeout_s=timeout_s,
            reset=reset,
        )
    finally:
        _stats_query_slot.release()


def _statsquery_owned(
    xray_path: str,
    *,
    server: str,
    pattern: str | None,
    timeout_s: float,
    reset: bool,
) -> dict[str, int]:
    cmd: list[str] = [
        xray_path,
        "api",
        "statsquery",
        "--server",
        server,
        "-timeout",
        str(int(max(1.0, float(timeout_s)))),
    ]
    if pattern:
        cmd += ["-pattern", pattern]
    if reset:
        cmd += ["-reset"]

    env, env_info = build_xray_subprocess_env(xray_path)
    logger.debug(
        "Running xray api command: %s [env_mode=%s removed_env=%s]",
        cmd,
        env_info.mode,
        ",".join(env_info.removed_keys) or "none",
    )
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            start_new_session=True,
        )
        with _stats_process_lock:
            _stats_processes[proc.pid] = proc
        try:
            stdout, stderr = proc.communicate(timeout=timeout_s + 1.0)
        except subprocess.TimeoutExpired as exc:
            terminate_owned_process(proc, timeout_s=1.0)
            raise XrayApiError(
                f"xray api statsquery timed out after {timeout_s:.1f}s",
                user_message="Xray API timed out while fetching stats.",
            ) from exc
        finally:
            with _stats_process_lock:
                _stats_processes.pop(proc.pid, None)
    except FileNotFoundError as exc:
        raise BinaryMissingError(
            f"xray binary missing: {xray_path}",
            user_message=(
                "Xray-core was not found. This build may be incomplete. Please install the official "
                "v2link-client AppImage/.deb package, or configure a custom Xray path."
            ),
        ) from exc
    except PermissionError as exc:
        raise PermissionDeniedError(
            f"xray binary is not executable: {xray_path}",
            user_message=f"Xray binary is not executable: {xray_path}",
        ) from exc
    if proc.returncode != 0:
        detail = (stderr or "").strip() or (stdout or "").strip() or "unknown error"
        raise XrayApiError(
            f"xray api statsquery failed: {detail}",
            user_message=f"Xray API stats query failed: {detail}",
        )

    # Newer Xray prints JSON, older versions may print text.
    raw_out = (stdout or "").strip()
    if raw_out:
        try:
            payload = json.loads(raw_out)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict):
            stats: dict[str, int] = {}
            items = payload.get("stat")
            if isinstance(items, list):
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    name = item.get("name")
                    if not isinstance(name, str) or not name:
                        continue
                    value = item.get("value", 0)
                    try:
                        stats[name] = int(value)
                    except (TypeError, ValueError):
                        stats[name] = 0
            return stats

    stats: dict[str, int] = {}
    for line in raw_out.splitlines():
        match = _STAT_RE.search(line)
        if not match:
            continue
        name = match.group("name")
        try:
            value = int(match.group("value"))
        except ValueError:
            continue
        stats[name] = value

    return stats


def get_outbound_traffic(
    xray_path: str,
    *,
    server: str,
    outbound_tag: str = "proxy",
    timeout_s: float = 3.0,
) -> TrafficStats:
    pattern = f"outbound>>>{outbound_tag}>>>traffic>>>"
    stats = statsquery(xray_path, server=server, pattern=pattern, timeout_s=timeout_s)
    up = stats.get(f"outbound>>>{outbound_tag}>>>traffic>>>uplink", 0)
    down = stats.get(f"outbound>>>{outbound_tag}>>>traffic>>>downlink", 0)
    return TrafficStats(uplink_bytes=up, downlink_bytes=down)


def active_stats_query_pid() -> int | None:
    with _stats_process_lock:
        for pid, proc in _stats_processes.items():
            if proc.poll() is None:
                return int(pid)
    return None


def cancel_active_stats_queries(*, timeout_s: float = 1.0) -> int:
    """Terminate and reap only stats-query children started by this process."""
    with _stats_process_lock:
        processes = list(_stats_processes.values())
    for proc in processes:
        terminate_owned_process(proc, timeout_s=timeout_s)
        with _stats_process_lock:
            _stats_processes.pop(proc.pid, None)
    return len(processes)
