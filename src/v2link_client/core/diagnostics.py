"""Diagnostics collection."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from typing import Any

from v2link_client.core.proxy_manager import SNAPSHOT_FILE
from v2link_client.core.storage import get_logs_dir, get_state_dir


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def _run_command(cmd: list[str], *, timeout_s: float = 3.0) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    if result.returncode != 0:
        detail = (result.stderr or "").strip() or (result.stdout or "").strip() or "unknown error"
        return False, detail
    return True, (result.stdout or "").strip()


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

    lines.append("System Proxy (gsettings)")
    if _tool_available("gsettings"):
        ok, output = _run_command(["gsettings", "list-recursively", "org.gnome.system.proxy"])
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
        else:
            lines.append(f"- Error reading gsettings: {output}")
    else:
        lines.append("- gsettings unavailable")
    lines.append("")

    if state is not None:
        lines.append("State")
        lines.append(f"- Raw: {state}")
        lines.append("")

    return "\n".join(lines)
