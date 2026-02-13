from __future__ import annotations

import json
import subprocess

import pytest

import v2link_client.core.proxy_manager as pm
from v2link_client.core.errors import ProxyApplyError
from v2link_client.core.proxy_manager import SystemProxyConfig, SystemProxyManager


def _default_gsettings_state() -> dict[tuple[str, str], str]:
    return {
        ("org.gnome.system.proxy", "mode"): "'none'",
        ("org.gnome.system.proxy", "autoconfig-url"): "''",
        ("org.gnome.system.proxy", "ignore-hosts"): "['localhost']",
        ("org.gnome.system.proxy", "use-same-proxy"): "false",
        ("org.gnome.system.proxy.ftp", "host"): "''",
        ("org.gnome.system.proxy.ftp", "port"): "0",
        ("org.gnome.system.proxy.http", "enabled"): "false",
        ("org.gnome.system.proxy.http", "host"): "''",
        ("org.gnome.system.proxy.http", "port"): "0",
        ("org.gnome.system.proxy.http", "authentication-user"): "''",
        ("org.gnome.system.proxy.http", "authentication-password"): "''",
        ("org.gnome.system.proxy.http", "use-authentication"): "false",
        ("org.gnome.system.proxy.https", "host"): "''",
        ("org.gnome.system.proxy.https", "port"): "0",
        ("org.gnome.system.proxy.socks", "host"): "''",
        ("org.gnome.system.proxy.socks", "port"): "0",
    }


def _fake_run_factory(
    state: dict[tuple[str, str], str],
    calls: list[list[str]],
):
    def fake_run(cmd, check, capture_output, text, timeout):  # noqa: ANN001
        calls.append(list(cmd))
        if cmd[:3] == ["gsettings", "list-keys", "org.gnome.system.proxy"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="mode\nignore-hosts\n", stderr="")

        if cmd[:2] == ["gsettings", "get"]:
            key = (cmd[2], cmd[3])
            if key not in state:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="missing key")
            return subprocess.CompletedProcess(cmd, 0, stdout=f"{state[key]}\n", stderr="")

        if cmd[:2] == ["gsettings", "set"]:
            state[(cmd[2], cmd[3])] = cmd[4]
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        raise AssertionError(f"Unexpected command: {cmd}")

    return fake_run


def _set_commands(calls: list[list[str]]) -> list[list[str]]:
    return [c for c in calls if c[:2] == ["gsettings", "set"]]


def test_system_proxy_apply_unsupported_backend(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(pm.shutil, "which", lambda _name: None)
    mgr = SystemProxyManager(state_dir=tmp_path)
    with pytest.raises(ProxyApplyError):
        mgr.apply(
            SystemProxyConfig(
                http_host="127.0.0.1",
                http_port=8080,
                socks_host="127.0.0.1",
                socks_port=1080,
                bypass_hosts=["localhost"],
            )
        )


def test_restore_mode_none_uses_canonical_no_proxy(tmp_path, monkeypatch) -> None:
    calls: list[list[str]] = []
    state = _default_gsettings_state()
    state[("org.gnome.system.proxy", "ignore-hosts")] = "['corp.local']"
    state[("org.gnome.system.proxy", "use-same-proxy")] = "true"
    state[("org.gnome.system.proxy.http", "port")] = "8080"

    monkeypatch.setattr(pm.shutil, "which", lambda _name: "/usr/bin/gsettings")
    monkeypatch.setattr(pm.subprocess, "run", _fake_run_factory(state, calls))

    mgr = SystemProxyManager(state_dir=tmp_path)
    mgr.apply(
        SystemProxyConfig(
            http_host="127.0.0.1",
            http_port=8080,
            socks_host="127.0.0.1",
            socks_port=1080,
            bypass_hosts=["localhost", "127.0.0.0/8", "::1"],
        )
    )
    snap_path = tmp_path / pm.SNAPSHOT_FILE
    assert snap_path.exists()

    calls.clear()
    mgr.restore()
    assert not snap_path.exists()

    assert state[("org.gnome.system.proxy", "mode")] == "'none'"
    assert state[("org.gnome.system.proxy.http", "host")] == "''"
    assert state[("org.gnome.system.proxy.http", "port")] == "0"
    assert state[("org.gnome.system.proxy.https", "port")] == "0"
    assert state[("org.gnome.system.proxy.socks", "port")] == "0"
    assert state[("org.gnome.system.proxy.ftp", "port")] == "0"
    assert state[("org.gnome.system.proxy", "use-same-proxy")] == "false"
    assert "corp.local" in state[("org.gnome.system.proxy", "ignore-hosts")]
    assert "127.0.0.0/8" in state[("org.gnome.system.proxy", "ignore-hosts")]
    assert "::1" in state[("org.gnome.system.proxy", "ignore-hosts")]

    restore_sets = _set_commands(calls)
    assert restore_sets[-1] == ["gsettings", "set", "org.gnome.system.proxy", "mode", "'none'"]


def test_restore_mode_manual_preserves_snapshot(tmp_path, monkeypatch) -> None:
    calls: list[list[str]] = []
    state = _default_gsettings_state()

    monkeypatch.setattr(pm.shutil, "which", lambda _name: "/usr/bin/gsettings")
    monkeypatch.setattr(pm.subprocess, "run", _fake_run_factory(state, calls))

    mgr = SystemProxyManager(state_dir=tmp_path)
    snap_path = tmp_path / pm.SNAPSHOT_FILE
    payload = {
        "backend": "gsettings",
        "snapshot": {
            "org.gnome.system.proxy:mode": "'manual'",
            "org.gnome.system.proxy:ignore-hosts": "['localhost', 'corp.local']",
            "org.gnome.system.proxy:use-same-proxy": "true",
            "org.gnome.system.proxy.http:enabled": "true",
            "org.gnome.system.proxy.http:host": "'proxy.corp'",
            "org.gnome.system.proxy.http:port": "3128",
            "org.gnome.system.proxy.https:host": "'proxy.corp'",
            "org.gnome.system.proxy.https:port": "3128",
            "org.gnome.system.proxy.socks:host": "'proxy.corp'",
            "org.gnome.system.proxy.socks:port": "1080",
        },
    }
    snap_path.write_text(json.dumps(payload), encoding="utf-8")

    mgr.restore()
    assert not snap_path.exists()
    assert state[("org.gnome.system.proxy", "mode")] == "'manual'"
    assert state[("org.gnome.system.proxy.http", "host")] == "'proxy.corp'"
    assert state[("org.gnome.system.proxy.http", "port")] == "3128"

    restore_sets = _set_commands(calls)
    assert restore_sets[-1] == ["gsettings", "set", "org.gnome.system.proxy", "mode", "'manual'"]


def test_restore_backward_compatible_with_old_snapshot_keys(tmp_path, monkeypatch) -> None:
    calls: list[list[str]] = []
    state = _default_gsettings_state()

    monkeypatch.setattr(pm.shutil, "which", lambda _name: "/usr/bin/gsettings")
    monkeypatch.setattr(pm.subprocess, "run", _fake_run_factory(state, calls))

    mgr = SystemProxyManager(state_dir=tmp_path)
    snap_path = tmp_path / pm.SNAPSHOT_FILE
    old_payload = {
        "backend": "gsettings",
        "snapshot": {
            "org.gnome.system.proxy:mode": "'manual'",
            "org.gnome.system.proxy:ignore-hosts": "['localhost']",
            "org.gnome.system.proxy:use-same-proxy": "true",
            "org.gnome.system.proxy.http:enabled": "true",
            "org.gnome.system.proxy.http:host": "'127.0.0.1'",
            "org.gnome.system.proxy.http:port": "8080",
            "org.gnome.system.proxy.https:host": "'127.0.0.1'",
            "org.gnome.system.proxy.https:port": "8080",
            "org.gnome.system.proxy.socks:host": "'127.0.0.1'",
            "org.gnome.system.proxy.socks:port": "1080",
        },
    }
    snap_path.write_text(json.dumps(old_payload), encoding="utf-8")

    mgr.restore()
    assert not snap_path.exists()
    assert state[("org.gnome.system.proxy", "mode")] == "'manual'"


def test_repair_stale_loopback_proxy_repairs(tmp_path, monkeypatch) -> None:
    calls: list[list[str]] = []
    state = _default_gsettings_state()
    state[("org.gnome.system.proxy", "mode")] = "'manual'"
    state[("org.gnome.system.proxy", "use-same-proxy")] = "true"
    state[("org.gnome.system.proxy", "ignore-hosts")] = "['localhost']"
    state[("org.gnome.system.proxy.http", "host")] = "'127.0.0.1'"
    state[("org.gnome.system.proxy.http", "port")] = "8080"
    state[("org.gnome.system.proxy.http", "enabled")] = "true"
    state[("org.gnome.system.proxy.https", "host")] = "'127.0.0.1'"
    state[("org.gnome.system.proxy.https", "port")] = "8080"

    monkeypatch.setattr(pm.shutil, "which", lambda _name: "/usr/bin/gsettings")
    monkeypatch.setattr(pm.subprocess, "run", _fake_run_factory(state, calls))

    def fake_create_connection(*_args, **_kwargs):  # noqa: ANN001
        raise OSError()

    monkeypatch.setattr(pm.socket, "create_connection", fake_create_connection)

    mgr = SystemProxyManager(state_dir=tmp_path)
    assert mgr.repair_stale_loopback_proxy() is True
    assert state[("org.gnome.system.proxy", "mode")] == "'none'"
    assert state[("org.gnome.system.proxy.http", "port")] == "0"


def test_repair_stale_loopback_proxy_noop_when_proxy_is_reachable(tmp_path, monkeypatch) -> None:
    calls: list[list[str]] = []
    state = _default_gsettings_state()
    state[("org.gnome.system.proxy", "mode")] = "'manual'"
    state[("org.gnome.system.proxy", "use-same-proxy")] = "true"
    state[("org.gnome.system.proxy.http", "host")] = "'127.0.0.1'"
    state[("org.gnome.system.proxy.http", "port")] = "8080"

    monkeypatch.setattr(pm.shutil, "which", lambda _name: "/usr/bin/gsettings")
    monkeypatch.setattr(pm.subprocess, "run", _fake_run_factory(state, calls))

    class DummySocket:
        def close(self) -> None:
            return None

    monkeypatch.setattr(pm.socket, "create_connection", lambda *args, **kwargs: DummySocket())

    mgr = SystemProxyManager(state_dir=tmp_path)
    assert mgr.repair_stale_loopback_proxy() is False
    assert state[("org.gnome.system.proxy", "mode")] == "'manual'"
