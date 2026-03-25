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
from typing import Final

from v2link_client.core.errors import AppError, BinaryMissingError
from v2link_client.core.system_subprocess import build_host_subprocess_env


_STAT_RE: Final[re.Pattern[str]] = re.compile(r'name:\\s*\"(?P<name>[^\"]+)\"\\s+value:\\s*(?P<value>\\d+)')
logger = logging.getLogger(__name__)


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

    env, env_info = build_host_subprocess_env()
    logger.info(
        "Running xray api command: %s [env_mode=%s removed_env=%s]",
        cmd,
        env_info.mode,
        ",".join(env_info.removed_keys) or "none",
    )
    try:
        result = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_s + 1.0,
            env=env,
        )
    except FileNotFoundError as exc:
        raise BinaryMissingError(
            f"xray binary missing: {xray_path}",
            user_message="Xray-core binary not found. Install `xray` or add it to PATH.",
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise XrayApiError(
            f"xray api statsquery timed out: {exc}",
            user_message="Xray API timed out while fetching stats.",
        ) from exc

    if result.returncode != 0:
        detail = (result.stderr or "").strip() or (result.stdout or "").strip() or "unknown error"
        raise XrayApiError(
            f"xray api statsquery failed: {detail}",
            user_message=f"Xray API stats query failed: {detail}",
        )

    # Newer Xray prints JSON, older versions may print text.
    raw_out = (result.stdout or "").strip()
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
