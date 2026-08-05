from __future__ import annotations

import json
import socket
import subprocess
import threading

import pytest

import v2link_client.core.netmon_client as netmon
from v2link_client.core.netmon_client import NetmonClient


def test_disabled_netmon_client_returns_clean_status() -> None:
    client = NetmonClient(provider="disabled")

    status = client.get_status()

    assert status.installed is False
    assert status.running is False
    assert status.permission_ok is False
    assert status.daemon_state == "disabled"
    assert status.reason_code == "tracking-disabled"
    assert client.get_live_apps() == []
    assert client.get_today_app_usage() == []
    assert client.get_history(days=7) == []


def test_mock_netmon_client_returns_data() -> None:
    client = NetmonClient(provider="mock")

    status = client.start_tracking()
    apps = client.get_live_apps()
    today = client.get_today_app_usage()
    history = client.get_history(days=3)

    assert status.installed is True
    assert status.running is True
    assert status.permission_ok is True
    assert apps
    assert today
    assert history
    assert all(app.source == "mock" for app in apps)
    assert {app.confidence for app in apps} <= {"high", "medium", "low", "unknown", "exact"}


def test_socket_netmon_client_parses_daemon_responses(tmp_path) -> None:
    socket_path = tmp_path / "netmon.sock"
    ready = threading.Event()

    def server() -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as srv:
            srv.bind(str(socket_path))
            srv.listen(2)
            ready.set()
            for _ in range(2):
                conn, _ = srv.accept()
                with conn:
                    request = conn.recv(4096).decode("ascii")
                    if "GET /status " in request:
                        payload = {
                            "installed": True,
                            "running": True,
                            "backend": "ebpf",
                            "permission_ok": True,
                            "kernel_supported": True,
                            "started_at": "2026-05-01T00:00:00Z",
                            "message": "v2link-netmon running",
                            "socket_path": str(socket_path),
                        }
                    else:
                        payload = {
                            "timestamp": "2026-05-01T00:00:01Z",
                            "apps": [
                                {
                                    "identity": {
                                        "app_id": "app-firefox",
                                        "name": "Firefox",
                                        "executable_path": "/usr/lib/firefox/firefox",
                                        "uid": 1000,
                                        "pid": 1234,
                                    },
                                    "rx_bytes": 123456,
                                    "tx_bytes": 45678,
                                    "download_bps": 1024.0,
                                    "upload_bps": 512.0,
                                    "confidence": "high",
                                    "source": "netmon-ebpf",
                                    "last_seen": "2026-05-01T00:00:01Z",
                                }
                            ],
                        }
                    body = json.dumps(payload).encode("utf-8")
                    conn.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                        + str(len(body)).encode("ascii")
                        + b"\r\n\r\n"
                        + body
                    )

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    assert ready.wait(timeout=2)

    client = NetmonClient(provider="socket", socket_path=str(socket_path))
    status = client.get_status()
    apps = client.get_live_apps()

    assert status.installed is True
    assert status.running is True
    assert status.backend == "ebpf"
    assert status.kernel_supported is True
    assert len(apps) == 1
    assert apps[0].app_name == "Firefox"
    assert apps[0].rx_bytes == 123456
    assert apps[0].source == "netmon-ebpf"


def _evidence(*, installed: bool = True, service_state: str | None = "inactive"):
    return netmon._InstallationEvidence(
        installed=installed,
        installation_state="installed" if installed else "not-installed",
        helper_binary_path="/usr/lib/v2link-client/v2link-netmon",
        service_unit_path="/lib/systemd/system/v2link-netmon.service",
        service_state=service_state,
    )


@pytest.mark.parametrize(
    ("code", "daemon_state"),
    [
        ("permission-denied", "permission-denied"),
        ("connection-refused", "connection-refused"),
        ("timeout", "timeout"),
        ("invalid-response", "invalid-response"),
    ],
)
def test_socket_failures_remain_distinct(monkeypatch, code, daemon_state) -> None:
    client = NetmonClient(provider="socket")
    monkeypatch.setattr(client, "_installation_evidence", lambda: _evidence())

    def fail(_path):
        raise netmon.NetmonUnavailableError(code, "synthetic local failure")

    monkeypatch.setattr(client, "_request_json", fail)
    status = client.get_status()
    assert status.installed is True
    assert status.running is False
    assert status.operational is False
    assert status.daemon_state == daemon_state
    assert status.reason_code == code


def test_missing_socket_preserves_installed_filesystem_evidence(monkeypatch) -> None:
    client = NetmonClient(provider="socket")
    monkeypatch.setattr(client, "_installation_evidence", lambda: _evidence())
    monkeypatch.setattr(
        client, "_request_json",
        lambda _path: (_ for _ in ()).throw(netmon.NetmonUnavailableError("socket-missing", "missing")),
    )
    status = client.get_status()
    assert status.installed is True
    assert status.installation_state == "installed"
    assert status.daemon_state == "inactive"
    assert status.reason_code == "socket-missing"


def test_failed_service_is_distinct_from_an_inactive_service(monkeypatch) -> None:
    client = NetmonClient(provider="socket")
    monkeypatch.setattr(
        client, "_installation_evidence", lambda: _evidence(service_state="failed")
    )
    monkeypatch.setattr(
        client, "_request_json",
        lambda _path: (_ for _ in ()).throw(
            netmon.NetmonUnavailableError("socket-missing", "missing")
        ),
    )

    status = client.get_status()

    assert status.installed is True
    assert status.daemon_state == "failed"
    assert status.service_state == "failed"
    assert status.reason_code == "service-failed"


def test_genuine_helper_absence_is_not_installed(monkeypatch) -> None:
    client = NetmonClient(provider="socket")
    monkeypatch.setattr(client, "_installation_evidence", lambda: _evidence(installed=False, service_state=None))
    monkeypatch.setattr(
        client, "_request_json",
        lambda _path: (_ for _ in ()).throw(netmon.NetmonUnavailableError("socket-missing", "missing")),
    )
    status = client.get_status()
    assert status.installed is False
    assert status.reason_code == "helper-not-installed"


def test_appimage_disabled_provider_requires_external_helper() -> None:
    status = NetmonClient(provider="disabled", runtime_kind="appimage").get_status()
    assert status.installation_state == "external-helper-required"
    assert status.reason_code == "external-helper-required"
    assert status.operational is False


def test_appimage_socket_provider_without_helper_requires_external_helper(monkeypatch) -> None:
    client = NetmonClient(
        provider="socket", runtime_kind="appimage",
        helper_binary_path="/synthetic/missing/helper",
        service_unit_paths=("/synthetic/missing/unit",),
    )
    monkeypatch.setattr(
        client, "_request_json",
        lambda _path: (_ for _ in ()).throw(netmon.NetmonUnavailableError("socket-missing", "missing")),
    )
    status = client.get_status()
    assert status.installation_state == "external-helper-required"
    assert status.reason_code == "external-helper-required"


@pytest.mark.parametrize(
    ("payload", "backend_state", "operational"),
    [
        ({"running": True, "backend": "ebpf", "kernel_supported": True}, "unknown", False),
        ({"api_version": 2, "backend": "ebpf-unavailable", "reason_code": "backend-not-implemented", "operational": False}, "not-implemented", False),
        ({"api_version": 2, "backend": "ebpf", "reason_code": "kernel-unsupported", "operational": False, "kernel_supported": False}, "kernel-unsupported", False),
        ({"api_version": 2, "backend": "ebpf", "reason_code": "backend-initialization-failed", "operational": False}, "initialization-failed", False),
    ],
)
def test_old_and_new_status_payloads(monkeypatch, payload, backend_state, operational) -> None:
    client = NetmonClient(provider="socket")
    monkeypatch.setattr(client, "_installation_evidence", lambda: _evidence())
    monkeypatch.setattr(client, "_request_json", lambda _path: payload)
    status = client.get_status()
    assert status.running is True
    assert status.backend_state == backend_state
    assert status.operational is operational


def test_invalid_field_types_degrade_safely(monkeypatch) -> None:
    client = NetmonClient(provider="socket")
    monkeypatch.setattr(client, "_installation_evidence", lambda: _evidence())
    monkeypatch.setattr(client, "_request_json", lambda _path: {"backend": [], "operational": "yes", "kernel_supported": "yes"})
    status = client.get_status()
    assert status.backend == "unknown"
    assert status.backend_state == "unknown"
    assert status.operational is False
    assert status.kernel_supported is None


def test_sensitive_daemon_error_is_sanitized(monkeypatch) -> None:
    client = NetmonClient(provider="socket")
    monkeypatch.setattr(client, "_installation_evidence", lambda: _evidence())
    monkeypatch.setattr(client, "_request_json", lambda _path: {
        "api_version": 2, "backend": "ebpf", "backend_state": "initialization-failed",
        "last_error": "failed for user@example.invalid with 01234567-89ab-cdef-0123-456789abcdef",
    })
    status = client.get_status()
    assert status.last_error is not None
    assert "user@example.invalid" not in status.last_error
    assert "01234567-89ab" not in status.last_error


def test_sensitive_daemon_message_and_reported_path_are_not_exposed(monkeypatch) -> None:
    client = NetmonClient(provider="socket", socket_path="/run/v2link-client/netmon.sock")
    monkeypatch.setattr(client, "_installation_evidence", lambda: _evidence())
    monkeypatch.setattr(client, "_request_json", lambda _path: {
        "api_version": 2,
        "backend": "ebpf-unavailable",
        "backend_state": "not-implemented",
        "operational": False,
        "message": "failed for user@example.invalid",
        "socket_path": "/home/private-user/secret.sock",
    })

    status = client.get_status()

    assert "user@example.invalid" not in status.message
    assert status.socket_path == "/run/v2link-client/netmon.sock"


def test_non_operational_v2_response_cannot_supply_app_rows(monkeypatch) -> None:
    client = NetmonClient(provider="socket")
    monkeypatch.setattr(client, "_request_json", lambda _path: {
        "status": {
            "api_version": 2,
            "backend": "ebpf-unavailable",
            "backend_state": "not-implemented",
            "operational": False,
        },
        "apps": [{
            "app_id": "fabricated",
            "name": "Fabricated",
            "executable_path": "/usr/bin/fabricated",
            "rx_bytes": 1,
        }],
    })

    assert client.get_live_apps() == []


def test_installation_probe_cache_and_refresh(monkeypatch, tmp_path) -> None:
    helper = tmp_path / "v2link-netmon"
    unit = tmp_path / "v2link-netmon.service"
    helper.write_text("fixture")
    helper.chmod(0o755)
    unit.write_text("fixture")
    calls = 0
    client = NetmonClient(
        provider="socket", helper_binary_path=str(helper), service_unit_paths=(str(unit),),
        probe_ttl_seconds=60,
    )

    def service_state():
        nonlocal calls
        calls += 1
        return "inactive"

    monkeypatch.setattr(client, "_probe_service_state", service_state)
    assert client._installation_evidence().installed is True
    assert client._installation_evidence().installed is True
    assert calls == 1
    client.refresh_installation_state()
    assert client._installation_evidence().installed is True
    assert calls == 2


def test_systemctl_unavailable_preserves_filesystem_evidence(monkeypatch, tmp_path) -> None:
    helper = tmp_path / "v2link-netmon"
    unit = tmp_path / "v2link-netmon.service"
    helper.write_text("fixture")
    helper.chmod(0o755)
    unit.write_text("fixture")
    monkeypatch.setattr(netmon, "system_which", lambda _name: None)
    evidence = NetmonClient(
        helper_binary_path=str(helper), service_unit_paths=(str(unit),)
    )._installation_evidence()
    assert evidence.installed is True
    assert evidence.service_state == "unknown"


def test_systemd_bus_failure_preserves_filesystem_evidence(monkeypatch, tmp_path) -> None:
    helper = tmp_path / "v2link-netmon"
    unit = tmp_path / "v2link-netmon.service"
    helper.write_text("fixture")
    helper.chmod(0o755)
    unit.write_text("fixture")
    monkeypatch.setattr(netmon, "system_which", lambda _name: "/usr/bin/systemctl")
    monkeypatch.setattr(
        netmon.subprocess, "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="Failed to connect to bus"
        ),
    )
    evidence = NetmonClient(
        helper_binary_path=str(helper), service_unit_paths=(str(unit),)
    )._installation_evidence()
    assert evidence.installed is True
    assert evidence.service_state == "unknown"
