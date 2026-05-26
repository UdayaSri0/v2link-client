"""Diagnostics collection."""

from __future__ import annotations

from dataclasses import dataclass
import os
import platform
import shlex
import sqlite3
import subprocess
import sys
from typing import Any

from v2link_client import __version__
from v2link_client.core.proxy_manager import SNAPSHOT_FILE, get_backend_warning_history
from v2link_client.core.storage import get_logs_dir, get_state_dir
from v2link_client.core.traffic_store import get_traffic_db_path
from v2link_client.core.system_subprocess import (
    build_host_subprocess_env,
    get_host_subprocess_env_info,
    system_which,
)

@dataclass(frozen=True, slots=True)
class CommandReport:
    ok: bool
    output: str
    stderr: str
    returncode: int | None
    command: str
    env_mode: str
    removed_env_keys: tuple[str, ...]


def _tool_available(name: str) -> bool:
    return system_which(name) is not None


def _format_cmd(cmd: list[str]) -> str:
    try:
        return shlex.join(cmd)
    except Exception:
        return str(cmd)


def _run_command(cmd: list[str], *, timeout_s: float = 3.0) -> CommandReport:
    env, env_info = build_host_subprocess_env()
    command_text = _format_cmd(cmd)
    try:
        result = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CommandReport(
            ok=False,
            output=str(exc),
            stderr="",
            returncode=None,
            command=command_text,
            env_mode=env_info.mode,
            removed_env_keys=env_info.removed_keys,
        )

    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()
    if result.returncode != 0:
        detail = stderr or stdout or "unknown error"
        return CommandReport(
            ok=False,
            output=detail,
            stderr=stderr,
            returncode=result.returncode,
            command=command_text,
            env_mode=env_info.mode,
            removed_env_keys=env_info.removed_keys,
        )
    return CommandReport(
        ok=True,
        output=stdout,
        stderr=stderr,
        returncode=result.returncode,
        command=command_text,
        env_mode=env_info.mode,
        removed_env_keys=env_info.removed_keys,
    )


def _format_proxy_status(status: Any) -> str:
    if not isinstance(status, dict):
        return "n/a"
    mode = str(status.get("mode", "") or "?")
    http_enabled = bool(status.get("http_enabled", False))
    http_host = str(status.get("http_host", "") or "")
    http_port = status.get("http_port", "")
    socks_host = str(status.get("socks_host", "") or "")
    socks_port = status.get("socks_port", "")
    return (
        f"mode={mode}, "
        f"http_enabled={str(http_enabled).lower()}, "
        f"http={http_host}:{http_port}, "
        f"socks={socks_host}:{socks_port}"
    )


def _append_runtime_state(lines: list[str], state: Any) -> None:
    if not isinstance(state, dict):
        return

    system_proxy = state.get("system_proxy")
    xray = state.get("xray")
    traffic = state.get("traffic")
    if not isinstance(system_proxy, dict) and not isinstance(xray, dict) and not isinstance(traffic, dict):
        return

    lines.append("Runtime Proxy State")

    if isinstance(system_proxy, dict):
        lines.append(f"- System proxy backend: {system_proxy.get('backend') or 'unknown'}")
        lines.append(
            f"- System proxy preference: "
            f"{'on' if bool(system_proxy.get('enabled_preference')) else 'off'}"
        )
        lines.append(
            f"- System proxy applied by this session: "
            f"{'yes' if bool(system_proxy.get('applied_by_session')) else 'no'}"
        )
        lines.append(f"- Desired GNOME proxy: {_format_proxy_status(system_proxy.get('desired'))}")
        lines.append(f"- Actual GNOME proxy: {_format_proxy_status(system_proxy.get('actual'))}")
        matches_desired = system_proxy.get("matches_desired")
        if isinstance(matches_desired, bool):
            lines.append(f"- Desired vs actual match: {'yes' if matches_desired else 'no'}")
        mismatches = system_proxy.get("mismatches")
        if isinstance(mismatches, list) and mismatches:
            lines.append(f"- Drift details: {'; '.join(str(item) for item in mismatches)}")
        last_reapply_at = system_proxy.get("last_auto_reapply_at")
        last_reapply_reason = system_proxy.get("last_auto_reapply_reason")
        if last_reapply_at:
            lines.append(
                f"- Last auto-reapply: {last_reapply_at} "
                f"({last_reapply_reason or 'reason not captured'})"
            )
        else:
            lines.append("- Last auto-reapply: none")
        last_audit_error = system_proxy.get("last_audit_error")
        if last_audit_error:
            lines.append(f"- Last proxy audit error: {last_audit_error}")

    if isinstance(xray, dict):
        status = str(xray.get("status") or ("found" if xray.get("valid") else "missing"))
        source = str(xray.get("source") or "unknown")
        source_label = {
            "user-configured": "user configured",
            "bundled": "bundled",
            "system-path": "system PATH",
        }.get(source, source)
        lines.append(f"- Xray status: {status}")
        lines.append(f"- Xray source: {source_label}")
        lines.append(f"- Xray running: {'yes' if bool(xray.get('running')) else 'no'}")
        resolved_path = xray.get("resolved_path") or xray.get("binary_path")
        if resolved_path:
            lines.append(f"- Xray path: {resolved_path}")
        if xray.get("version"):
            lines.append(f"- Xray version: {xray.get('version')}")
        if xray.get("error"):
            lines.append(f"- Xray error: {xray.get('error')}")
        geoip_found = bool(xray.get("geoip_found"))
        geosite_found = bool(xray.get("geosite_found"))
        lines.append(
            f"- Geo files found: geoip.dat={'yes' if geoip_found else 'no'} "
            f"geosite.dat={'yes' if geosite_found else 'no'}"
        )
        if xray.get("geoip_path"):
            lines.append(f"- geoip.dat path: {xray.get('geoip_path')}")
        if xray.get("geosite_path"):
            lines.append(f"- geosite.dat path: {xray.get('geosite_path')}")
        if bool(xray.get("bundled_incomplete")) or bool(xray.get("bundled_missing_in_packaged_build")):
            lines.append("- Warning: Bundled Xray is missing. This build is incomplete.")
        if source == "system-path" and status == "found":
            lines.append("- Note: Using system Xray from PATH.")
        lines.append(
            f"- Xray stats API configured: "
            f"{'yes' if bool(xray.get('stats_api_configured')) else 'no'}"
        )
        if xray.get("stats_api_server"):
            lines.append(f"- Xray stats API server: {xray.get('stats_api_server')}")
        if xray.get("last_stats_query_time"):
            lines.append(f"- Last stats query time: {xray.get('last_stats_query_time')}")
        if xray.get("last_stats_query_result"):
            lines.append(f"- Last stats query result: {xray.get('last_stats_query_result')}")
        lines.append(
            f"- Xray proxy listeners reachable: "
            f"http={str(bool(xray.get('http_listener_reachable'))).lower()} "
            f"socks={str(bool(xray.get('socks_listener_reachable'))).lower()}"
        )
        lines.append(
            f"- Recent traffic flowing through Xray: "
            f"{str(bool(xray.get('recent_traffic_flowing'))).lower()}"
        )
        health_state = str(xray.get("health_state", "") or "").lower()
        health_detail = str(xray.get("health_detail", "") or "")
        if health_state:
            lines.append(f"- Health check: {health_state} ({health_detail or 'n/a'})")
        health_url = xray.get("health_checked_url")
        if health_url:
            lines.append(
                "- Proxied HTTP/HTTPS probe: "
                f"url={health_url} status={xray.get('health_status_code')} "
                f"latency_ms={xray.get('health_latency_ms')} error={xray.get('health_error') or 'none'}"
            )

        proxy_matches = False
        if isinstance(system_proxy, dict):
            proxy_matches = bool(system_proxy.get("matches_desired") is True)
        listeners_ok = bool(xray.get("http_listener_reachable")) and bool(
            xray.get("socks_listener_reachable")
        )
        if proxy_matches and listeners_ok:
            lines.append(
                "- Hint: If some apps still bypass the tunnel, they may ignore GNOME system proxy and "
                "need app-specific proxy settings."
            )

    if isinstance(traffic, dict):
        lines.append("")
        lines.append("Traffic Monitor")
        lines.append(
            f"- Proxy/profile history tracking: "
            f"{'enabled' if bool(traffic.get('proxy_history_enabled')) else 'disabled'}"
        )
        lines.append(
            f"- App tracking setting: "
            f"{'enabled' if bool(traffic.get('app_tracking_enabled')) else 'disabled'}"
        )
        lines.append(f"- Detailed sample retention: {traffic.get('detailed_retention_days') or 'n/a'} days")
        lines.append(f"- Daily total retention: {traffic.get('daily_retention_days') or 'n/a'} days")
        lines.append(f"- Current proxy session ID: {traffic.get('current_session_id') or 'none'}")
        lines.append(f"- Last traffic sample time: {traffic.get('last_sample_time') or 'none'}")
        lines.append(f"- Last traffic store error: {traffic.get('last_store_error') or 'none'}")
        lines.append(
            f"- DB app tables present: "
            f"{'yes' if bool(traffic.get('app_tables_present')) else 'no'}"
        )
        netmon = traffic.get("netmon")
        if isinstance(netmon, dict):
            lines.append(
                "- App helper: "
                f"provider={netmon.get('provider') or 'unknown'} "
                f"installed={'yes' if bool(netmon.get('installed')) else 'no'} "
                f"running={'yes' if bool(netmon.get('running')) else 'no'}"
            )
            lines.append(f"- App helper socket/API: {netmon.get('api_url') or netmon.get('socket_path') or 'n/a'}")
            lines.append(
                f"- App helper permission: "
                f"{'ok' if bool(netmon.get('permission_ok')) else 'not available'}"
            )
            lines.append(f"- App helper last response: {netmon.get('last_response') or 'none'}")
            lines.append(f"- App helper last error: {netmon.get('last_error') or 'none'}")
            lines.append(f"- Kernel support: {netmon.get('kernel_support') or 'unknown/not checked yet'}")

    lines.append("")


def _append_traffic_storage(lines: list[str]) -> None:
    db_path = get_traffic_db_path()
    parent = db_path.parent
    lines.append(f"- Traffic DB: {db_path}")
    lines.append(f"- Traffic DB exists: {'yes' if db_path.exists() else 'no'}")
    lines.append(f"- Traffic DB parent exists: {'yes' if parent.exists() else 'no'}")
    lines.append(f"- Traffic DB readable: {'yes' if db_path.exists() and os.access(db_path, os.R_OK) else 'no'}")
    writable = os.access(db_path, os.W_OK) if db_path.exists() else os.access(parent, os.W_OK)
    lines.append(f"- Traffic DB writable: {'yes' if writable else 'no'}")
    lines.append(f"- Traffic DB app tables present: {'yes' if _db_app_tables_present(db_path) else 'no'}")


def _db_app_tables_present(db_path) -> bool:  # noqa: ANN001
    if not db_path.exists():
        return False
    try:
        with sqlite3.connect(db_path) as conn:
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
    except sqlite3.Error:
        return False
    required = {"apps", "app_traffic_samples", "daily_app_usage", "app_tracking_events"}
    return required.issubset({str(row[0]) for row in rows})


def collect_diagnostics(state: Any | None = None) -> str:
    lines: list[str] = []
    lines.append("v2link-client diagnostics")
    lines.append("")

    lines.append("System")
    lines.append(f"- OS: {platform.system()} {platform.release()}")
    lines.append(f"- Kernel: {platform.version()}")
    lines.append(f"- Arch: {platform.machine()}")
    lines.append(f"- Python: {sys.version.split()[0]}")
    lines.append("")

    env_info = get_host_subprocess_env_info()
    lines.append("Runtime")
    lines.append(f"- App version: v{__version__}")
    lines.append(f"- Mode: {env_info.runtime_kind}")
    lines.append(f"- Executable: {env_info.executable_path}")
    lines.append(f"- Host subprocess env: {env_info.mode}")
    lines.append(
        "- Sanitized child env keys present now: "
        f"{', '.join(env_info.removed_keys) if env_info.removed_keys else 'none'}"
    )
    lines.append("")

    lines.append("Desktop Environment")
    lines.append(f"- XDG_CURRENT_DESKTOP: {os.environ.get('XDG_CURRENT_DESKTOP', '')}")
    lines.append(f"- DESKTOP_SESSION: {os.environ.get('DESKTOP_SESSION', '')}")
    lines.append("")

    lines.append("Tools")
    lines.append(f"- gsettings: {'yes' if _tool_available('gsettings') else 'no'}")
    lines.append(f"- nmcli: {'yes' if _tool_available('nmcli') else 'no'}")
    lines.append(f"- kwriteconfig5: {'yes' if _tool_available('kwriteconfig5') else 'no'}")
    lines.append("")

    lines.append("Paths")
    lines.append(f"- Logs: {get_logs_dir()}")
    snapshot_path = get_state_dir() / SNAPSHOT_FILE
    lines.append(
        f"- System proxy snapshot: {'present' if snapshot_path.exists() else 'absent'} ({snapshot_path})"
    )
    _append_traffic_storage(lines)
    lines.append("")

    lines.append("Proxy Backend Warnings")
    backend_warnings = get_backend_warning_history(limit=10)
    if backend_warnings:
        for warning in backend_warnings:
            lines.append(f"- {warning}")
    else:
        lines.append("- none")
    lines.append("")

    lines.append("System Proxy (gsettings)")
    if _tool_available("gsettings"):
        report = _run_command(["gsettings", "list-recursively", "org.gnome.system.proxy"])
        lines.append(f"- Command: {report.command}")
        lines.append(f"- Env mode: {report.env_mode}")
        lines.append(
            "- Removed env keys: "
            f"{', '.join(report.removed_env_keys) if report.removed_env_keys else 'none'}"
        )
        lines.append(f"- Exit code: {report.returncode if report.returncode is not None else 'n/a'}")
        if report.ok:
            for raw_line in report.output.splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                schema, key, value = (line.split(maxsplit=2) + ["", ""])[:3]
                if schema and key:
                    lines.append(f"- {schema}:{key} = {value}")
                else:
                    lines.append(f"- {line}")
            if report.stderr:
                lines.append(f"- Warning: {report.stderr}")
        else:
            lines.append(f"- Error reading gsettings: {report.output}")
    else:
        lines.append("- gsettings unavailable")
    lines.append("")

    _append_runtime_state(lines, state)

    return "\n".join(lines)
