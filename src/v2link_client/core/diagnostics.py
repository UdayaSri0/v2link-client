"""Diagnostics collection."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from typing import Any

from v2link_client.core.proxy_manager import SNAPSHOT_FILE, get_backend_warning_history
from v2link_client.core.storage import get_logs_dir, get_state_dir


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def _run_command(cmd: list[str], *, timeout_s: float = 3.0) -> tuple[bool, str, str]:
    try:
        result = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc), ""

    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()
    if result.returncode != 0:
        detail = stderr or stdout or "unknown error"
        return False, detail, stderr
    return True, stdout, stderr


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
    if not isinstance(system_proxy, dict) and not isinstance(xray, dict):
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
        lines.append(f"- Xray running: {'yes' if bool(xray.get('running')) else 'no'}")
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

    lines.append("")


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
        ok, output, stderr = _run_command(["gsettings", "list-recursively", "org.gnome.system.proxy"])
        if ok:
            for raw_line in output.splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                schema, key, value = (line.split(maxsplit=2) + ["", ""])[:3]
                if schema and key:
                    lines.append(f"- {schema}:{key} = {value}")
                else:
                    lines.append(f"- {line}")
            if stderr:
                lines.append(f"- Warning: {stderr}")
        else:
            lines.append(f"- Error reading gsettings: {output}")
    else:
        lines.append("- gsettings unavailable")
    lines.append("")

    _append_runtime_state(lines, state)

    return "\n".join(lines)
