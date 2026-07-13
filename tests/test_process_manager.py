from __future__ import annotations

import os
from pathlib import Path
import shutil
import socket
import time

import pytest

from v2link_client.core.errors import PortInUseError
from v2link_client.core.process_manager import (
    XrayProcessManager,
    _append_bounded,
    ensure_port_available,
    find_xray_binary,
    validate_xray_config,
)
from v2link_client.core.storage import save_json
from v2link_client.core.xray_locator import XrayBinary


def test_ensure_port_available_detects_in_use_port() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        host, port = sock.getsockname()
        with pytest.raises(PortInUseError):
            ensure_port_available(host, port)


def test_validate_xray_config_smoke(tmp_path) -> None:
    if not shutil.which("xray"):
        pytest.skip("xray not installed")

    cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": 10809,
                "protocol": "socks",
                "settings": {"auth": "noauth"},
            }
        ],
        "outbounds": [{"protocol": "freedom", "settings": {}}],
    }
    cfg_path = tmp_path / "xray.json"
    save_json(cfg_path, cfg)

    xray = find_xray_binary()
    validate_xray_config(xray, cfg_path)


def _script(path: Path, body: str) -> Path:
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _process_gone(pid: int) -> bool:
    stat = Path(f"/proc/{pid}/stat")
    if not stat.exists():
        return True
    try:
        return stat.read_text(encoding="utf-8").split()[2] == "Z"
    except (OSError, IndexError):
        return True


@pytest.mark.parametrize("ignore_term", [False, True])
def test_xray_manager_stops_owned_process_group(
    tmp_path, monkeypatch, ignore_term: bool
) -> None:
    child_file = tmp_path / "child.pid"
    script = _script(
        tmp_path / "xray",
        ("trap '' TERM\n" if ignore_term else "")
        + f"sleep 60 &\necho $! > {child_file}\nwait",
    )
    monkeypatch.setattr("v2link_client.core.process_manager.get_logs_dir", lambda: tmp_path)
    manager = XrayProcessManager(
        XrayBinary(str(script), "user-configured", "test", True, None)
    )
    manager.start(tmp_path / "config.json")
    deadline = time.monotonic() + 2.0
    while not child_file.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    child_pid = int(child_file.read_text(encoding="utf-8"))

    manager.stop(timeout_s=0.2)

    assert manager.pid is None
    deadline = time.monotonic() + 2.0
    while not _process_gone(child_pid) and time.monotonic() < deadline:
        time.sleep(0.01)
    assert _process_gone(child_pid)
    manager.stop(timeout_s=0.2)  # repeated stop is safe


def test_xray_stdout_rotation_is_bounded(tmp_path, monkeypatch) -> None:
    import v2link_client.core.process_manager as process_manager

    monkeypatch.setattr(process_manager, "XRAY_STDOUT_MAX_BYTES", 64)
    path = tmp_path / "xray_stdout.log"
    _append_bounded(path, b"a" * 48)
    _append_bounded(path, b"b" * 48)

    assert path.stat().st_size <= 64
    assert (tmp_path / "xray_stdout.log.1").stat().st_size <= 64


def test_xray_manager_kills_child_after_group_leader_exits(tmp_path, monkeypatch) -> None:
    child_file = tmp_path / "orphan.pid"
    script = _script(
        tmp_path / "xray",
        f"sh -c 'trap \"\" TERM; sleep 60' &\necho $! > {child_file}\nsleep 0.1",
    )
    monkeypatch.setattr("v2link_client.core.process_manager.get_logs_dir", lambda: tmp_path)
    manager = XrayProcessManager(
        XrayBinary(str(script), "user-configured", "test", True, None)
    )
    manager.start(tmp_path / "config.json")
    deadline = time.monotonic() + 2.0
    while manager.is_running() and time.monotonic() < deadline:
        time.sleep(0.01)
    child_pid = int(child_file.read_text(encoding="utf-8"))

    manager.stop(timeout_s=0.2)

    deadline = time.monotonic() + 2.0
    while not _process_gone(child_pid) and time.monotonic() < deadline:
        time.sleep(0.01)
    assert _process_gone(child_pid)
