from __future__ import annotations

import json
import subprocess
import time

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


@pytest.fixture(autouse=True)
def _disable_gio_backend(monkeypatch) -> None:
    monkeypatch.setattr(pm, "_gio_available", lambda: False)
    pm._GSETTINGS_KEY_CACHE.clear()
    pm._BACKEND_WARNING_HISTORY.clear()


def _fake_run_factory(
    state: dict[tuple[str, str], str],
    calls: list[list[str]],
    *,
    ignore_manual_mode_set: bool = False,
):
    def fake_run(cmd, check, capture_output, text, timeout, env):  # noqa: ANN001
        assert "LD_LIBRARY_PATH" not in env
        calls.append(list(cmd))

        if cmd[:2] == ["gsettings", "list-keys"] and len(cmd) == 3:
            schema = cmd[2]
            keys = sorted({k for (s, k) in state if s == schema})
            if not keys:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="missing schema")
            return subprocess.CompletedProcess(cmd, 0, stdout="\n".join(keys) + "\n", stderr="")

        if cmd[:2] == ["gsettings", "get"]:
            key = (cmd[2], cmd[3])
            if key not in state:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="missing key")
            return subprocess.CompletedProcess(cmd, 0, stdout=f"{state[key]}\n", stderr="")

        if cmd[:2] == ["gsettings", "set"]:
            schema, key, value = cmd[2], cmd[3], cmd[4]
            if ignore_manual_mode_set and schema == "org.gnome.system.proxy" and key == "mode" and value == "'manual'":
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            state[(schema, key)] = value
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        raise AssertionError(f"Unexpected command: {cmd}")

    return fake_run


def _set_commands(calls: list[list[str]]) -> list[list[str]]:
    return [c for c in calls if c[:2] == ["gsettings", "set"]]


def test_system_proxy_apply_unsupported_backend(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(pm, "system_which", lambda _name: None)
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


def test_apply_verification_detects_mode_mismatch(tmp_path, monkeypatch) -> None:
    calls: list[list[str]] = []
    state = _default_gsettings_state()

    monkeypatch.setattr(pm, "system_which", lambda _name: "/usr/bin/gsettings")
    monkeypatch.setattr(
        pm.subprocess,
        "run",
        _fake_run_factory(state, calls, ignore_manual_mode_set=True),
    )

    mgr = SystemProxyManager(state_dir=tmp_path)
    with pytest.raises(ProxyApplyError) as exc_info:
        mgr.apply(
            SystemProxyConfig(
                http_host="127.0.0.1",
                http_port=8080,
                socks_host="127.0.0.1",
                socks_port=1080,
                bypass_hosts=["localhost", "127.0.0.0/8", "::1"],
            )
        )

    assert "not applied correctly" in exc_info.value.user_message


def test_restore_mode_none_restores_exact_snapshot_state(tmp_path, monkeypatch) -> None:
    calls: list[list[str]] = []
    state = _default_gsettings_state()
    state[("org.gnome.system.proxy", "ignore-hosts")] = "['corp.local']"
    state[("org.gnome.system.proxy", "use-same-proxy")] = "true"
    state[("org.gnome.system.proxy.http", "port")] = "8080"
    initial_state = dict(state)

    monkeypatch.setattr(pm, "system_which", lambda _name: "/usr/bin/gsettings")
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

    assert state[("org.gnome.system.proxy", "mode")] == initial_state[("org.gnome.system.proxy", "mode")]
    assert state[("org.gnome.system.proxy.http", "host")] == initial_state[("org.gnome.system.proxy.http", "host")]
    assert state[("org.gnome.system.proxy.http", "port")] == initial_state[("org.gnome.system.proxy.http", "port")]
    assert state[("org.gnome.system.proxy", "use-same-proxy")] == initial_state[("org.gnome.system.proxy", "use-same-proxy")]
    assert state[("org.gnome.system.proxy", "ignore-hosts")] == initial_state[("org.gnome.system.proxy", "ignore-hosts")]

    restore_sets = _set_commands(calls)
    assert restore_sets[-1] == ["gsettings", "set", "org.gnome.system.proxy", "mode", "'none'"]


def test_restore_mode_manual_preserves_snapshot(tmp_path, monkeypatch) -> None:
    calls: list[list[str]] = []
    state = _default_gsettings_state()

    monkeypatch.setattr(pm, "system_which", lambda _name: "/usr/bin/gsettings")
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

    monkeypatch.setattr(pm, "system_which", lambda _name: "/usr/bin/gsettings")
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


def test_restore_missing_snapshot_falls_back_to_no_proxy(tmp_path, monkeypatch) -> None:
    calls: list[list[str]] = []
    state = _default_gsettings_state()
    state[("org.gnome.system.proxy", "mode")] = "'manual'"
    state[("org.gnome.system.proxy.http", "enabled")] = "true"
    state[("org.gnome.system.proxy.http", "host")] = "'127.0.0.1'"
    state[("org.gnome.system.proxy.http", "port")] = "8080"

    monkeypatch.setattr(pm, "system_which", lambda _name: "/usr/bin/gsettings")
    monkeypatch.setattr(pm.subprocess, "run", _fake_run_factory(state, calls))

    mgr = SystemProxyManager(state_dir=tmp_path)
    status = mgr.restore()

    assert status.mode == "none"
    assert state[("org.gnome.system.proxy", "mode")] == "'none'"
    assert state[("org.gnome.system.proxy.http", "port")] == "0"


def test_restore_corrupt_snapshot_falls_back_to_no_proxy(tmp_path, monkeypatch) -> None:
    calls: list[list[str]] = []
    state = _default_gsettings_state()
    state[("org.gnome.system.proxy", "mode")] = "'manual'"

    monkeypatch.setattr(pm, "system_which", lambda _name: "/usr/bin/gsettings")
    monkeypatch.setattr(pm.subprocess, "run", _fake_run_factory(state, calls))

    snap_path = tmp_path / pm.SNAPSHOT_FILE
    snap_path.parent.mkdir(parents=True, exist_ok=True)
    snap_path.write_text("{not-json", encoding="utf-8")

    mgr = SystemProxyManager(state_dir=tmp_path)
    status = mgr.restore()

    assert status.mode == "none"
    assert state[("org.gnome.system.proxy", "mode")] == "'none'"
    assert not snap_path.exists()


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

    monkeypatch.setattr(pm, "system_which", lambda _name: "/usr/bin/gsettings")
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

    monkeypatch.setattr(pm, "system_which", lambda _name: "/usr/bin/gsettings")
    monkeypatch.setattr(pm.subprocess, "run", _fake_run_factory(state, calls))

    class DummySocket:
        def close(self) -> None:
            return None

    monkeypatch.setattr(pm.socket, "create_connection", lambda *args, **kwargs: DummySocket())

    mgr = SystemProxyManager(state_dir=tmp_path)
    assert mgr.repair_stale_loopback_proxy() is False
    assert state[("org.gnome.system.proxy", "mode")] == "'manual'"


def test_apply_success_sets_manual_proxy_and_snapshot(tmp_path, monkeypatch) -> None:
    calls: list[list[str]] = []
    state = _default_gsettings_state()

    monkeypatch.setattr(pm, "system_which", lambda _name: "/usr/bin/gsettings")
    monkeypatch.setattr(pm.subprocess, "run", _fake_run_factory(state, calls))

    mgr = SystemProxyManager(state_dir=tmp_path)
    status = mgr.apply(
        SystemProxyConfig(
            http_host="127.0.0.1",
            http_port=8080,
            socks_host="127.0.0.1",
            socks_port=1080,
            bypass_hosts=["localhost", "127.0.0.0/8", "::1"],
        )
    )

    assert status.mode == "manual"
    assert status.http_enabled is True
    assert status.http_host == "127.0.0.1"
    assert status.http_port == 8080
    assert status.socks_host == "127.0.0.1"
    assert status.socks_port == 1080
    assert mgr.snapshot_path.exists()


def test_restore_if_needed_recovers_snapshot_from_previous_session(tmp_path, monkeypatch) -> None:
    calls: list[list[str]] = []
    state = _default_gsettings_state()

    monkeypatch.setattr(pm, "system_which", lambda _name: "/usr/bin/gsettings")
    monkeypatch.setattr(pm.subprocess, "run", _fake_run_factory(state, calls))

    first = SystemProxyManager(state_dir=tmp_path, session_id="session-a")
    first.apply(
        SystemProxyConfig(
            http_host="127.0.0.1",
            http_port=8080,
            socks_host="127.0.0.1",
            socks_port=1080,
            bypass_hosts=["localhost", "127.0.0.0/8", "::1"],
        )
    )
    assert first.snapshot_path.exists()

    second = SystemProxyManager(state_dir=tmp_path, session_id="session-b")
    restored = second.restore_if_needed()

    assert restored is True
    assert second.snapshot_path.exists() is False
    assert state[("org.gnome.system.proxy", "mode")] == "'none'"


def test_audit_runtime_detects_drift_and_reapplies(tmp_path, monkeypatch) -> None:
    calls: list[list[str]] = []
    state = _default_gsettings_state()

    monkeypatch.setattr(pm, "system_which", lambda _name: "/usr/bin/gsettings")
    monkeypatch.setattr(pm.subprocess, "run", _fake_run_factory(state, calls))

    cfg = SystemProxyConfig(
        http_host="127.0.0.1",
        http_port=8080,
        socks_host="127.0.0.1",
        socks_port=1080,
        bypass_hosts=["localhost", "127.0.0.0/8", "::1"],
    )
    mgr = SystemProxyManager(state_dir=tmp_path)
    mgr.apply(cfg)

    # Simulate runtime drift from an external settings change.
    state[("org.gnome.system.proxy", "mode")] = "'none'"

    audit = mgr.audit_runtime(cfg, reconcile=False)
    assert audit.matches_desired is False
    assert audit.reapplied is False
    assert any("mode expected='manual'" in item for item in audit.mismatches)

    reconciled = mgr.audit_runtime(cfg, reconcile=True)
    assert reconciled.matches_desired is True
    assert reconciled.reapplied is True
    assert reconciled.mismatches == ()
    assert state[("org.gnome.system.proxy", "mode")] == "'manual'"


def test_backend_warning_history_records_rc0_stderr_warning(monkeypatch) -> None:
    pm._BACKEND_WARNING_HISTORY.clear()

    monkeypatch.setattr(pm, "system_which", lambda _name: "/usr/bin/gsettings")

    def fake_run(cmd, check, capture_output, text, timeout, env):  # noqa: ANN001
        assert "LD_LIBRARY_PATH" not in env
        if cmd[:2] == ["gsettings", "list-keys"]:
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout="mode\nignore-hosts\n",
                stderr="libdconfsettings.so: undefined symbol: g_assertion_message_cmpnum",
            )
        raise AssertionError(f"Unexpected command: {cmd}")

    monkeypatch.setattr(pm.subprocess, "run", fake_run)

    assert pm._gsettings_available() is True
    warnings = pm.get_backend_warning_history(limit=10)
    assert warnings
    assert "undefined symbol" in warnings[-1].lower()


def test_restore_if_needed_skips_snapshot_owned_by_live_other_pid(tmp_path, monkeypatch) -> None:
    calls: list[list[str]] = []
    state = _default_gsettings_state()

    monkeypatch.setattr(pm, "system_which", lambda _name: "/usr/bin/gsettings")
    monkeypatch.setattr(pm.subprocess, "run", _fake_run_factory(state, calls))

    sleeper = subprocess.Popen(["sleep", "30"])
    try:
        payload = {
            "version": pm.SNAPSHOT_VERSION,
            "backend": "gsettings",
            "session_id": "live-owner",
            "owner_pid": sleeper.pid,
            "owner_created_at": int(time.time()),
            "snapshot": {
                "org.gnome.system.proxy": {
                    "mode": "manual",
                }
            },
        }
        snap_path = tmp_path / pm.SNAPSHOT_FILE
        snap_path.write_text(json.dumps(payload), encoding="utf-8")

        mgr = SystemProxyManager(state_dir=tmp_path, session_id="new-session")
        restored = mgr.restore_if_needed()

        assert restored is False
        assert snap_path.exists()
    finally:
        sleeper.terminate()
        sleeper.wait(timeout=5)


def test_restore_if_owned_skips_snapshot_from_other_session(tmp_path, monkeypatch) -> None:
    calls: list[list[str]] = []
    state = _default_gsettings_state()

    monkeypatch.setattr(pm, "system_which", lambda _name: "/usr/bin/gsettings")
    monkeypatch.setattr(pm.subprocess, "run", _fake_run_factory(state, calls))

    snap_path = tmp_path / pm.SNAPSHOT_FILE
    payload = {
        "version": pm.SNAPSHOT_VERSION,
        "backend": "gsettings",
        "session_id": "other-session",
        "owner_pid": 424242,
        "snapshot": {
            "org.gnome.system.proxy": {
                "mode": "none",
            }
        },
    }
    snap_path.write_text(json.dumps(payload), encoding="utf-8")

    mgr = SystemProxyManager(state_dir=tmp_path, session_id="this-session")
    status = mgr.restore_if_owned()

    assert status is None
    assert snap_path.exists()
