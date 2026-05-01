"""Client abstraction for the optional v2link-netmon helper service.

The real privileged helper is intentionally not implemented in this phase.
This module gives the GUI a stable API and safe disabled/mock providers.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from v2link_client.core.traffic_store import AppIdentity, AppUsageSummary, _now, _to_iso

DEFAULT_SOCKET_PATH = "/run/v2link-netmon/v2link-netmon.sock"


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


class NetmonClient:
    def __init__(
        self,
        *,
        provider: str = "disabled",
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
        if self.provider != "mock":
            self._last_response = "helper unavailable"
            return []
        self._last_response = "mock live apps returned"
        return _mock_apps(live=True)

    def get_today_app_usage(self) -> list[AppUsageSummary]:
        if self.provider != "mock":
            self._last_response = "helper unavailable"
            return []
        self._last_response = "mock today usage returned"
        return _mock_apps(live=False)

    def get_history(self, days: int = 30) -> list[AppUsageSummary]:
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
