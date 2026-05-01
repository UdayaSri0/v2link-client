"""Client abstraction for the optional v2link-netmon helper service."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
import json
import socket
from urllib.parse import urlencode

from v2link_client.core.traffic_store import AppIdentity, AppUsageSummary, _now, _to_iso

DEFAULT_SOCKET_PATH = "/run/v2link-client/netmon.sock"


class NetmonUnavailableError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class NetmonStatus:
    installed: bool
    running: bool
    permission_ok: bool
    message: str
    socket_path: str | None = DEFAULT_SOCKET_PATH
    api_url: str | None = None
    last_response: str | None = None
    kernel_support: str = "not checked yet"
    provider: str = "disabled"
    backend: str = "unavailable"
    kernel_supported: bool | None = None
    last_error: str | None = None


class NetmonClient:
    def __init__(
        self,
        *,
        provider: str = "socket",
        socket_path: str | None = DEFAULT_SOCKET_PATH,
        api_url: str | None = None,
    ) -> None:
        self.provider = provider.strip().lower() or "disabled"
        self.socket_path = socket_path
        self.api_url = api_url
        self._tracking = False
        self._last_response: str | None = None

    def get_status(self) -> NetmonStatus:
        if self.provider == "mock":
            return NetmonStatus(
                installed=True,
                running=self._tracking,
                permission_ok=True,
                message="Mock per-application tracking provider is active for development.",
                socket_path=self.socket_path,
                api_url=self.api_url,
                last_response=self._last_response or "mock status ok",
                kernel_support="mock",
                provider="mock",
                backend="mock",
                kernel_supported=True,
                last_error=None,
            )
        if self.provider == "socket":
            try:
                payload = self._request_json("/status")
            except NetmonUnavailableError as exc:
                self._last_response = str(exc)
                return _unavailable_status(
                    socket_path=self.socket_path,
                    api_url=self.api_url,
                    last_response=self._last_response,
                )
            self._last_response = "status ok"
            return _status_from_payload(
                payload,
                socket_path=self.socket_path,
                api_url=self.api_url,
                last_response=self._last_response,
            )
        return NetmonStatus(
            installed=False,
            running=False,
            permission_ok=False,
            message="Per-application tracking helper is not installed yet.",
            socket_path=self.socket_path,
            api_url=self.api_url,
            last_response=self._last_response,
            kernel_support="not checked yet",
            provider="disabled",
        )

    def get_live_apps(self) -> list[AppUsageSummary]:
        if self.provider == "socket":
            return self._apps_from_endpoint("/live")
        if self.provider != "mock":
            self._last_response = "helper unavailable"
            return []
        self._last_response = "mock live apps returned"
        return _mock_apps(live=True)

    def get_today_app_usage(self) -> list[AppUsageSummary]:
        if self.provider == "socket":
            return self._apps_from_endpoint("/apps/today")
        if self.provider != "mock":
            self._last_response = "helper unavailable"
            return []
        self._last_response = "mock today usage returned"
        return _mock_apps(live=False)

    def get_history(self, days: int = 30) -> list[AppUsageSummary]:
        if self.provider == "socket":
            query = urlencode({"days": max(1, int(days))})
            return self._apps_from_endpoint(f"/apps/history?{query}")
        if self.provider != "mock":
            self._last_response = "helper unavailable"
            return []
        days = max(1, int(days))
        today = _now().date()
        rows: list[AppUsageSummary] = []
        for offset in range(min(days, 7)):
            date = (today - timedelta(days=offset)).isoformat()
            for app in _mock_apps(live=False):
                rows.append(
                    AppUsageSummary(
                        app_id=app.app_id,
                        app_name=app.app_name,
                        executable_path=app.executable_path,
                        rx_bytes=max(0, app.rx_bytes - offset * 12_000),
                        tx_bytes=max(0, app.tx_bytes - offset * 4_000),
                        download_bps=0.0,
                        upload_bps=0.0,
                        last_seen=date,
                        confidence=app.confidence,
                        source=app.source,
                        pid=app.pid,
                        uid=app.uid,
                    )
                )
        self._last_response = "mock history returned"
        return rows

    def start_tracking(self) -> NetmonStatus:
        if self.provider == "socket":
            self._last_response = "using socket helper"
            return self.get_status()
        if self.provider != "mock":
            self._last_response = "start ignored: helper unavailable"
            return self.get_status()
        self._tracking = True
        self._last_response = "mock tracking started"
        return self.get_status()

    def stop_tracking(self) -> NetmonStatus:
        if self.provider == "mock":
            self._tracking = False
            self._last_response = "mock tracking stopped"
        else:
            self._last_response = "stop ignored: helper unavailable"
        return self.get_status()

    def _apps_from_endpoint(self, path: str) -> list[AppUsageSummary]:
        try:
            payload = self._request_json(path)
        except NetmonUnavailableError as exc:
            self._last_response = str(exc)
            return []
        self._last_response = f"{path} ok"
        raw_apps = payload.get("apps", []) if isinstance(payload, dict) else []
        if not isinstance(raw_apps, list):
            return []
        apps: list[AppUsageSummary] = []
        for item in raw_apps:
            if isinstance(item, dict):
                parsed = _app_from_payload(item)
                if parsed is not None:
                    apps.append(parsed)
        return apps

    def _request_json(self, path: str) -> dict:
        if not self.socket_path:
            raise NetmonUnavailableError("Per-application tracking helper socket is not configured.")
        request = f"GET {path} HTTP/1.1\r\nHost: v2link-netmon\r\nConnection: close\r\n\r\n"
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(1.5)
                sock.connect(self.socket_path)
                sock.sendall(request.encode("ascii"))
                chunks: list[bytes] = []
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
        except FileNotFoundError as exc:
            raise NetmonUnavailableError(
                "Per-application tracking helper is not installed yet."
            ) from exc
        except PermissionError as exc:
            raise NetmonUnavailableError(
                "Permission denied connecting to v2link-netmon helper socket."
            ) from exc
        except OSError as exc:
            raise NetmonUnavailableError(f"v2link-netmon helper unavailable: {exc}") from exc

        response = b"".join(chunks)
        _, _, body = response.partition(b"\r\n\r\n")
        if not body:
            raise NetmonUnavailableError("v2link-netmon helper returned an empty response.")
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise NetmonUnavailableError("v2link-netmon helper returned invalid JSON.") from exc
        if not isinstance(payload, dict):
            raise NetmonUnavailableError("v2link-netmon helper returned an invalid response.")
        return payload


def _mock_apps(*, live: bool) -> list[AppUsageSummary]:
    timestamp = _to_iso()
    return [
        AppUsageSummary(
            app_id="mock-firefox",
            app_name="Firefox",
            executable_path="/usr/lib/firefox/firefox",
            rx_bytes=82_500_000,
            tx_bytes=7_200_000,
            download_bps=180_000.0 if live else 0.0,
            upload_bps=24_000.0 if live else 0.0,
            last_seen=timestamp,
            confidence="high",
            source="mock",
            pid=4242 if live else None,
            uid=1000,
        ),
        AppUsageSummary(
            app_id="mock-code",
            app_name="Visual Studio Code",
            executable_path="/usr/share/code/code",
            rx_bytes=21_000_000,
            tx_bytes=3_100_000,
            download_bps=42_000.0 if live else 0.0,
            upload_bps=8_000.0 if live else 0.0,
            last_seen=timestamp,
            confidence="medium",
            source="mock",
            pid=5151 if live else None,
            uid=1000,
        ),
    ]


def mock_identity(summary: AppUsageSummary) -> AppIdentity:
    return AppIdentity(
        id=summary.app_id,
        name=summary.app_name,
        executable_path=summary.executable_path,
        pid=summary.pid,
        uid=summary.uid,
        trusted_identity=summary.confidence in {"exact", "high"},
    )


def _unavailable_status(
    *,
    socket_path: str | None,
    api_url: str | None,
    last_response: str | None,
) -> NetmonStatus:
    return NetmonStatus(
        installed=False,
        running=False,
        permission_ok=False,
        message="Per-application tracking helper is not installed yet.",
        socket_path=socket_path,
        api_url=api_url,
        last_response=last_response,
        kernel_support="not checked yet",
        provider="socket",
        backend="unavailable",
        kernel_supported=None,
        last_error=last_response,
    )


def _status_from_payload(
    payload: dict,
    *,
    socket_path: str | None,
    api_url: str | None,
    last_response: str | None,
) -> NetmonStatus:
    return NetmonStatus(
        installed=bool(payload.get("installed", True)),
        running=bool(payload.get("running", False)),
        permission_ok=bool(payload.get("permission_ok", False)),
        message=str(payload.get("message") or "v2link-netmon status unavailable"),
        socket_path=str(payload.get("socket_path") or socket_path or ""),
        api_url=api_url,
        last_response=last_response,
        kernel_support=(
            "supported"
            if bool(payload.get("kernel_supported", False))
            else "unsupported or not available"
        ),
        provider="socket",
        backend=str(payload.get("backend") or "unknown"),
        kernel_supported=bool(payload.get("kernel_supported", False)),
        last_error=(
            str(payload.get("last_error"))
            if payload.get("last_error") not in {None, ""}
            else None
        ),
    )


def _app_from_payload(payload: dict) -> AppUsageSummary | None:
    identity = payload.get("identity")
    if not isinstance(identity, dict):
        identity = payload
    app_id = str(identity.get("app_id") or payload.get("app_id") or "").strip()
    name = str(identity.get("name") or payload.get("name") or "").strip()
    executable_path = str(
        identity.get("executable_path") or payload.get("executable_path") or ""
    ).strip()
    if not app_id or not name or not executable_path:
        return None
    return AppUsageSummary(
        app_id=app_id,
        app_name=name,
        executable_path=executable_path,
        rx_bytes=_int_value(payload.get("rx_bytes")),
        tx_bytes=_int_value(payload.get("tx_bytes")),
        download_bps=float(payload.get("download_bps") or 0.0),
        upload_bps=float(payload.get("upload_bps") or 0.0),
        last_seen=str(payload.get("last_seen") or payload.get("timestamp") or ""),
        confidence=str(payload.get("confidence") or "unknown"),
        source=str(payload.get("source") or "netmon-ebpf"),
        pid=_optional_int(identity.get("pid") or payload.get("pid")),
        uid=_optional_int(identity.get("uid") or payload.get("uid")),
    )


def _int_value(value: object) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _optional_int(value: object) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
