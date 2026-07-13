"""Helpers for terminating process groups created by this application."""

from __future__ import annotations

import os
import signal
import subprocess
from typing import Any


def terminate_owned_process(proc: Any, *, timeout_s: float) -> int | None:
    """Reap an app-owned process, escalating only its private process group."""
    if proc is None:
        return None
    timeout = max(0.1, float(timeout_s))
    _signal_owned_group(proc, signal.SIGTERM)
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        _signal_owned_group(proc, signal.SIGKILL)
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            # A real SIGKILL cannot be ignored. This branch mainly protects
            # shutdown from broken/mocked process implementations.
            return proc.poll()
    # The group leader can exit before one of its descendants. The PGID stays
    # reserved while descendants live, so one final group check prevents an
    # orphan that ignored TERM without ever targeting an unrelated group.
    if _owned_group_exists(proc):
        _signal_owned_group(proc, signal.SIGKILL)
    return proc.poll()


def _signal_owned_group(proc: Any, sig: signal.Signals) -> None:
    pid = getattr(proc, "pid", None)
    if isinstance(pid, int) and pid > 0 and os.name == "posix":
        try:
            os.killpg(pid, sig)
            return
        except ProcessLookupError:
            return
        except OSError:
            pass
    try:
        if sig == signal.SIGKILL:
            proc.kill()
        else:
            proc.terminate()
    except ProcessLookupError:
        return


def _owned_group_exists(proc: Any) -> bool:
    pid = getattr(proc, "pid", None)
    if not isinstance(pid, int) or pid <= 0 or os.name != "posix":
        return False
    try:
        os.killpg(pid, 0)
    except (ProcessLookupError, PermissionError):
        return False
    return True
