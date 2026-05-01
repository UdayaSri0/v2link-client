from __future__ import annotations

import json
import socket
import threading

from v2link_client.core.netmon_client import NetmonClient


def test_disabled_netmon_client_returns_clean_status() -> None:
    client = NetmonClient()

    status = client.get_status()

    assert status.installed is False
    assert status.running is False
    assert status.permission_ok is False
    assert status.message == "Per-application tracking helper is not installed yet."
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
