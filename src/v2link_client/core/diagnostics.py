"""Diagnostics collection."""

from __future__ import annotations

import os
import platform
import shutil
import sys
from typing import Any

from v2link_client.core.storage import get_logs_dir


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


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
    lines.append("")

    if state is not None:
        lines.append("State")
        lines.append(f"- Raw: {state}")
        lines.append("")

    return "\n".join(lines)
