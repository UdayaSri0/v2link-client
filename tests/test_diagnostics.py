from __future__ import annotations

import subprocess

import v2link_client.core.diagnostics as diag
from v2link_client.core.proxy_manager import SNAPSHOT_FILE


def test_collect_diagnostics_includes_gsettings_proxy_state(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(diag, "_tool_available", lambda name: name == "gsettings")
    monkeypatch.setattr(diag, "get_state_dir", lambda: tmp_path)
    monkeypatch.setattr(diag, "get_backend_warning_history", lambda limit=10: [])
    (tmp_path / SNAPSHOT_FILE).write_text("{}", encoding="utf-8")

    def fake_run(cmd, check, capture_output, text, timeout, env):  # noqa: ANN001
        assert "LD_LIBRARY_PATH" not in env
        if cmd == ["gsettings", "list-recursively", "org.gnome.system.proxy"]:
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout=(
                    "org.gnome.system.proxy mode 'none'\n"
                    "org.gnome.system.proxy.http host ''\n"
                    "org.gnome.system.proxy.http port 0\n"
                ),
                stderr="",
            )
        raise AssertionError(f"Unexpected command: {cmd}")

    monkeypatch.setattr(diag.subprocess, "run", fake_run)

    report = diag.collect_diagnostics()
    assert "Runtime" in report
    assert "- Host subprocess env: clean-host" in report
    assert "System Proxy (gsettings)" in report
    assert "Proxy Backend Warnings" in report
    assert "System proxy snapshot: present" in report
    assert "- Command: gsettings list-recursively org.gnome.system.proxy" in report
    assert "- Env mode: clean-host" in report
    assert "- org.gnome.system.proxy:mode = 'none'" in report
    assert "- org.gnome.system.proxy.http:port = 0" in report


def test_collect_diagnostics_handles_missing_gsettings(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(diag, "_tool_available", lambda _name: False)
    monkeypatch.setattr(diag, "get_state_dir", lambda: tmp_path)
    monkeypatch.setattr(diag, "get_backend_warning_history", lambda limit=10: [])

    report = diag.collect_diagnostics()
    assert "System Proxy (gsettings)" in report
    assert "- gsettings unavailable" in report
    assert "System proxy snapshot: absent" in report


def test_collect_diagnostics_surfaces_gsettings_stderr_warning(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(diag, "_tool_available", lambda name: name == "gsettings")
    monkeypatch.setattr(diag, "get_state_dir", lambda: tmp_path)
    monkeypatch.setattr(diag, "get_backend_warning_history", lambda limit=10: [])

    def fake_run(cmd, check, capture_output, text, timeout, env):  # noqa: ANN001
        assert "LD_LIBRARY_PATH" not in env
        if cmd == ["gsettings", "list-recursively", "org.gnome.system.proxy"]:
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout="org.gnome.system.proxy mode 'manual'\n",
                stderr="libgvfsdbus.so failed to load",
            )
        raise AssertionError(f"Unexpected command: {cmd}")

    monkeypatch.setattr(diag.subprocess, "run", fake_run)

    report = diag.collect_diagnostics()
    assert "- Warning: libgvfsdbus.so failed to load" in report


def test_collect_diagnostics_includes_runtime_proxy_state(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(diag, "_tool_available", lambda _name: False)
    monkeypatch.setattr(diag, "get_state_dir", lambda: tmp_path)
    monkeypatch.setattr(
        diag,
        "get_backend_warning_history",
        lambda limit=10: ["gsettings get ...: libdconfsettings.so undefined symbol"],
    )

    state = {
        "system_proxy": {
            "backend": "gsettings",
            "enabled_preference": True,
            "applied_by_session": True,
            "desired": {
                "mode": "manual",
                "http_enabled": True,
                "http_host": "127.0.0.1",
                "http_port": 8080,
                "socks_host": "127.0.0.1",
                "socks_port": 1080,
            },
            "actual": {
                "mode": "none",
                "http_enabled": False,
                "http_host": "",
                "http_port": 0,
                "socks_host": "",
                "socks_port": 0,
            },
            "matches_desired": False,
            "mismatches": ["mode expected='manual' got='none'"],
            "last_auto_reapply_at": "2026-03-08 08:01:02",
            "last_auto_reapply_reason": "mode drift",
            "last_audit_error": "temporary failure",
        },
        "xray": {
            "running": True,
            "status": "found",
            "source": "system-path",
            "resolved_path": "/usr/bin/xray",
            "version": "v26.4.25",
            "geoip_found": False,
            "geosite_found": False,
            "health_state": "online",
            "health_detail": "55 ms",
            "health_checked_url": "https://www.gstatic.com/generate_204",
            "health_status_code": 204,
            "health_latency_ms": 55,
            "health_error": None,
            "http_listener_reachable": True,
            "socks_listener_reachable": True,
            "recent_traffic_flowing": False,
        },
    }

    report = diag.collect_diagnostics(state=state)
    assert "Runtime Proxy State" in report
    assert "- System proxy backend: gsettings" in report
    assert "- Desired vs actual match: no" in report
    assert "- Drift details: mode expected='manual' got='none'" in report
    assert "- Last proxy audit error: temporary failure" in report
    assert "- Xray status: found" in report
    assert "- Xray source: system PATH" in report
    assert "- Xray path: /usr/bin/xray" in report
    assert "- Xray version: v26.4.25" in report
    assert "- Note: Using system Xray from PATH." in report
    assert "Proxied HTTP/HTTPS probe" in report
    assert "libdconfsettings.so undefined symbol" in report


def test_collect_diagnostics_adds_bypass_hint_when_proxy_matches(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(diag, "_tool_available", lambda _name: False)
    monkeypatch.setattr(diag, "get_state_dir", lambda: tmp_path)
    monkeypatch.setattr(diag, "get_backend_warning_history", lambda limit=10: [])

    state = {
        "system_proxy": {
            "backend": "gsettings",
            "enabled_preference": True,
            "applied_by_session": True,
            "matches_desired": True,
            "desired": {
                "mode": "manual",
                "http_enabled": True,
                "http_host": "127.0.0.1",
                "http_port": 8080,
                "socks_host": "127.0.0.1",
                "socks_port": 1080,
            },
            "actual": {
                "mode": "manual",
                "http_enabled": True,
                "http_host": "127.0.0.1",
                "http_port": 8080,
                "socks_host": "127.0.0.1",
                "socks_port": 1080,
            },
            "mismatches": [],
        },
        "xray": {
            "running": True,
            "health_state": "online",
            "health_detail": "ok",
            "http_listener_reachable": True,
            "socks_listener_reachable": True,
            "recent_traffic_flowing": False,
        },
    }

    report = diag.collect_diagnostics(state=state)
    assert "- Hint: If some apps still bypass the tunnel" in report
