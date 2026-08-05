from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
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
    assert "- App version: v" in report
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


def test_cached_performance_diagnostics_omit_sensitive_identifiers(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(diag, "_tool_available", lambda _name: False)
    monkeypatch.setattr(diag, "get_state_dir", lambda: tmp_path)
    monkeypatch.setattr(diag, "get_backend_warning_history", lambda limit=10: [])
    state = {
        "traffic": {
            "current_session_active": True,
            "session_count": 3,
            "sample_count": 90,
            "current_session_sample_count": 4,
            "database_size_bytes": 4096,
            "wal_size_bytes": 128,
        },
        "performance": {
            "stats_interval_ms": 2000,
            "stats_started": 4,
            "stats_completed": 4,
            "stats_skipped": 1,
            "stats_failures": 0,
            "chart_source_rows": 900,
            "chart_rendered_points": 900,
        },
    }

    report = diag.collect_diagnostics(state)

    assert "Cached Performance Diagnostics" in report
    assert "interval_ms=2000" in report
    assert "source=900 rendered=900" in report
    assert "Current proxy session active: yes" in report
    assert "session-id-secret" not in report
    assert "credential" not in report.lower()


def test_build_report_has_stable_metadata_and_does_not_mutate_state(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(diag, "_tool_available", lambda _name: False)
    monkeypatch.setattr(diag, "get_state_dir", lambda: tmp_path)
    monkeypatch.setattr(diag, "get_logs_dir", lambda: tmp_path / "logs")
    monkeypatch.setattr(diag, "get_backend_warning_history", lambda limit=10: [])
    generated_at = datetime(2026, 8, 5, 12, 34, 56, tzinfo=timezone.utc)
    state = {
        "xray": {
            "status": "found",
            "version": "26.3.27",
            "health_state": "offline",
            "error": "profile vless://fixture@example.invalid:443",
        }
    }
    original = deepcopy(state)

    report = diag.build_diagnostics_report(state, generated_at=generated_at)

    assert report.startswith("v2link-client diagnostics\nReport schema version: 2")
    assert "Generated: 2026-08-05T12:34:56+00:00" in report
    assert "Sensitive values are redacted by default." in report
    assert "Xray version: 26.3.27" in report
    assert "vless://<redacted>" in report
    assert "fixture@example.invalid" not in report
    assert state == original


def test_diagnostics_sanitizes_all_raw_command_and_runtime_channels(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(diag, "_tool_available", lambda name: name == "gsettings")
    monkeypatch.setattr(diag, "get_state_dir", lambda: tmp_path)
    monkeypatch.setattr(diag, "get_logs_dir", lambda: tmp_path / "logs")
    monkeypatch.setattr(
        diag,
        "get_backend_warning_history",
        lambda limit=10: [
            "failure for fixture.user@example.invalid token=fixture-warning-token"
        ],
    )

    def fake_run(cmd, check, capture_output, text, timeout, env):  # noqa: ANN001
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout=(
                "org.gnome.system.proxy mode 'manual'\n"
                "org.gnome.system.proxy.http authentication-user 'fixture-user'\n"
                "org.gnome.system.proxy.http authentication-password 'fixture-pass'\n"
            ),
            stderr="warning Bearer fixture-bearer-token",
        )

    monkeypatch.setattr(diag.subprocess, "run", fake_run)
    state = {
        "system_proxy": {
            "backend": "gsettings",
            "last_audit_error": "password=fixture-audit-pass",
        },
        "xray": {
            "status": "found",
            "error": "https://subscription.invalid/fetch?token=fixture-url-token",
            "warning": "identity 01234567-89ab-cdef-0123-456789abcdef",
        },
        "traffic": {
            "diagnostics_error": "cookie=fixture-cookie",
            "netmon": {
                "installation_state": "installed",
                "daemon_state": "connection-refused",
                "backend_state": "not-implemented",
                "reason_code": "backend-not-implemented",
                "last_response": "authorization=fixture-helper-auth",
                "last_error": "user fixture.helper@example.invalid",
            },
        },
    }

    report = diag.build_diagnostics_report(state)

    for secret in (
        "fixture.user",
        "fixture-warning-token",
        "fixture-user",
        "fixture-pass",
        "fixture-bearer-token",
        "fixture-audit-pass",
        "fixture-url-token",
        "01234567-89ab",
        "fixture-cookie",
        "fixture-helper-auth",
        "fixture.helper",
    ):
        assert secret not in report
    assert "connection-refused" in report
    assert "backend-not-implemented" in report
    assert "org.gnome.system.proxy.http:authentication-password" in report


def test_command_report_is_sanitized_before_return(monkeypatch) -> None:
    def fake_run(cmd, check, capture_output, text, timeout, env):  # noqa: ANN001
        return subprocess.CompletedProcess(
            cmd,
            1,
            stdout="",
            stderr="Authorization: Bearer fixture-command-secret",
        )

    monkeypatch.setattr(diag.subprocess, "run", fake_run)

    report = diag._run_command(["synthetic-tool"])

    assert not report.ok
    assert "fixture-command-secret" not in report.output
    assert "fixture-command-secret" not in report.stderr
    assert "Authorization" in report.output


def test_recent_error_is_included_once_and_sanitized(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(diag, "_tool_available", lambda _name: False)
    monkeypatch.setattr(diag, "get_state_dir", lambda: tmp_path)
    monkeypatch.setattr(diag, "get_logs_dir", lambda: tmp_path / "logs")
    monkeypatch.setattr(diag, "get_backend_warning_history", lambda limit=10: [])
    state = {
        "recent_error": {
            "timestamp": "2026-08-05T10:00:00+00:00",
            "source": "Xray startup",
            "severity": "error",
            "reason_code": "invalid-config",
            "summary": "Core startup failed",
            "details": "vless://fixture@example.invalid:443?token=fixture-token",
        }
    }

    report = diag.build_diagnostics_report(state)

    assert report.count("Recent Error") == 1
    assert "Reason code: invalid-config" in report
    assert "vless://<redacted>" in report
    assert "fixture-token" not in report
