"""Client abstraction for the optional v2link-netmon helper service."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import socket
import subprocess
import time
from urllib.parse import urlencode

from v2link_client.core.logging_setup import sanitize_sensitive_text
from v2link_client.core.system_subprocess import (
    build_host_subprocess_env,
    detect_runtime_kind,
    system_which,
)
from v2link_client.core.traffic_store import AppUsageSummary

DEFAULT_SOCKET_PATH = "/run/v2link-client/netmon.sock"
DEFAULT_HELPER_BINARY_PATH = "/usr/lib/v2link-client/v2link-netmon"
DEFAULT_SERVICE_UNIT_PATH = "/lib/systemd/system/v2link-netmon.service"
ALTERNATE_SERVICE_UNIT_PATH = "/usr/lib/systemd/system/v2link-netmon.service"
INSTALLATION_PROBE_TTL_SECONDS = 5.0
MAX_RESPONSE_BYTES = 1024 * 1024


class NetmonUnavailableError(RuntimeError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


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
    operational: bool = False
    installation_state: str = "unknown"
    daemon_state: str = "unknown"
    backend_state: str = "unknown"
    reason_code: str = "unknown"
    remediation: str | None = None
    helper_binary_path: str | None = DEFAULT_HELPER_BINARY_PATH
    service_unit_path: str | None = DEFAULT_SERVICE_UNIT_PATH
    service_state: str | None = None
    counters_available: bool = False


@dataclass(frozen=True, slots=True)
class _InstallationEvidence:
    installed: bool
    installation_state: str
    helper_binary_path: str
    service_unit_path: str
    service_state: str | None


class NetmonClient:
    def __init__(
        self,
        *,
        provider: str = "socket",
        socket_path: str | None = DEFAULT_SOCKET_PATH,
        api_url: str | None = None,
        helper_binary_path: str = DEFAULT_HELPER_BINARY_PATH,
        service_unit_paths: tuple[str, ...] = (
            DEFAULT_SERVICE_UNIT_PATH,
            ALTERNATE_SERVICE_UNIT_PATH,
        ),
        probe_ttl_seconds: float = INSTALLATION_PROBE_TTL_SECONDS,
        runtime_kind: str | None = None,
    ) -> None:
        requested_provider = provider.strip().lower() or "disabled"
        self.provider = (
            requested_provider
            if requested_provider in {"disabled", "socket"}
            else "disabled"
        )
        self.socket_path = socket_path
        self.api_url = api_url
        self._last_response: str | None = None
        self.helper_binary_path = helper_binary_path
        self.service_unit_paths = service_unit_paths
        self.probe_ttl_seconds = max(0.0, float(probe_ttl_seconds))
        self.runtime_kind = runtime_kind or detect_runtime_kind()
        self._probe_cache: tuple[float, _InstallationEvidence] | None = None

    def refresh_installation_state(self) -> None:
        """Invalidate cached filesystem/systemd evidence without changing the host."""
        self._probe_cache = None

    def get_status(self) -> NetmonStatus:
        if self.provider == "socket":
            evidence = self._installation_evidence()
            try:
                payload = self._request_json("/status")
            except NetmonUnavailableError as exc:
                self._last_response = sanitize_sensitive_text(str(exc))
                return _unavailable_status(
                    socket_path=self.socket_path,
                    api_url=self.api_url,
                    last_response=self._last_response,
                    evidence=evidence,
                    reason_code=exc.reason_code,
                )
            self._last_response = "status ok"
            return _status_from_payload(
                payload,
                socket_path=self.socket_path,
                api_url=self.api_url,
                last_response=self._last_response,
                evidence=evidence,
            )
        if self.runtime_kind == "appimage":
            return NetmonStatus(
                installed=False, running=False, operational=False, permission_ok=False,
                message="Per-application tracking requires the separately installed v2link-netmon system helper.",
                remediation="Install and configure the optional Debian system helper; proxy operation is unaffected.",
                socket_path=self.socket_path, api_url=self.api_url, provider="disabled",
                installation_state="external-helper-required", daemon_state="disabled",
                backend_state="unavailable", reason_code="external-helper-required",
                helper_binary_path=self.helper_binary_path,
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
            operational=False,
            installation_state="unknown",
            daemon_state="disabled",
            backend_state="unavailable",
            reason_code="tracking-disabled",
            remediation="Enable per-application tracking in settings to query the optional helper.",
            helper_binary_path=self.helper_binary_path,
        )

    def _installation_evidence(self) -> _InstallationEvidence:
        now = time.monotonic()
        if self._probe_cache and now - self._probe_cache[0] < self.probe_ttl_seconds:
            return self._probe_cache[1]
        binary = Path(self.helper_binary_path)
        selected_unit = next((Path(item) for item in self.service_unit_paths if Path(item).is_file()), None)
        binary_present = binary.is_file() and os.access(binary, os.X_OK)
        installed = binary_present or selected_unit is not None
        installation_state = (
            "installed" if installed else
            "external-helper-required" if self.runtime_kind == "appimage" else
            "not-installed"
        )
        service_state = self._probe_service_state() if selected_unit is not None else None
        evidence = _InstallationEvidence(
            installed=installed,
            installation_state=installation_state,
            helper_binary_path=str(binary),
            service_unit_path=str(selected_unit or Path(self.service_unit_paths[0])),
            service_state=service_state,
        )
        self._probe_cache = (now, evidence)
        return evidence

    def _probe_service_state(self) -> str | None:
        systemctl = system_which("systemctl")
        if not systemctl:
            return "unknown"
        env, _ = build_host_subprocess_env()
        try:
            result = subprocess.run(
                [systemctl, "is-active", "v2link-netmon.service"],
                check=False, capture_output=True, text=True, timeout=0.5, env=env,
            )
        except (OSError, subprocess.TimeoutExpired):
            return "unknown"
        value = (result.stdout or "").strip().lower()
        return value if value in {"active", "inactive", "failed", "activating", "deactivating"} else "unknown"

    def get_live_apps(self) -> list[AppUsageSummary]:
        if self.provider == "socket":
            return self._apps_from_endpoint("/live")
        self._last_response = "helper unavailable"
        return []

    def get_today_app_usage(self) -> list[AppUsageSummary]:
        if self.provider == "socket":
            return self._apps_from_endpoint("/apps/today")
        self._last_response = "helper unavailable"
        return []

    def get_history(self, days: int = 30) -> list[AppUsageSummary]:
        if self.provider == "socket":
            query = urlencode({"days": max(1, int(days))})
            return self._apps_from_endpoint(f"/apps/history?{query}")
        self._last_response = "helper unavailable"
        return []

    def start_tracking(self) -> NetmonStatus:
        if self.provider == "socket":
            self._last_response = "using socket helper"
            return self.get_status()
        self._last_response = "start ignored: helper unavailable"
        return self.get_status()

    def stop_tracking(self) -> NetmonStatus:
        self._last_response = "stop ignored: helper unavailable"
        return self.get_status()

    def _apps_from_endpoint(self, path: str) -> list[AppUsageSummary]:
        try:
            payload = self._request_json(path)
        except NetmonUnavailableError as exc:
            self._last_response = str(exc)
            return []
        self._last_response = f"{path} ok"
        status_payload = payload.get("status") if isinstance(payload, dict) else None
        # Fail closed: application rows are trustworthy only when the same
        # response explicitly confirms a real operational counter backend.
        if not isinstance(status_payload, dict):
            return []
        backend = _string_field(status_payload, "backend", "unknown")
        backend_state = _backend_state(status_payload, backend)
        if not (
            backend_state == "operational"
            and _bool_field(status_payload, "operational", default=False)
            and _bool_field(status_payload, "counters_available", default=False)
        ):
            return []
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
            raise NetmonUnavailableError("socket-not-configured", "Per-application tracking helper socket is not configured.")
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
                    if sum(map(len, chunks)) > MAX_RESPONSE_BYTES:
                        raise NetmonUnavailableError(
                            "invalid-response",
                            "v2link-netmon helper returned an oversized response.",
                        )
        except FileNotFoundError as exc:
            raise NetmonUnavailableError("socket-missing", "The v2link-netmon helper socket is missing.") from exc
        except PermissionError as exc:
            raise NetmonUnavailableError("permission-denied", "Permission denied connecting to the v2link-netmon helper socket.") from exc
        except socket.timeout as exc:
            raise NetmonUnavailableError("timeout", "The v2link-netmon helper response timed out.") from exc
        except ConnectionRefusedError as exc:
            raise NetmonUnavailableError("connection-refused", "The v2link-netmon helper refused the connection.") from exc
        except OSError as exc:
            raise NetmonUnavailableError("socket-error", "The v2link-netmon helper socket could not be reached.") from exc

        response = b"".join(chunks)
        headers, separator, body = response.partition(b"\r\n\r\n")
        if not separator or not headers.startswith(b"HTTP/1.1 200 "):
            raise NetmonUnavailableError(
                "invalid-response", "v2link-netmon helper returned an invalid HTTP response."
            )
        if not body:
            raise NetmonUnavailableError("invalid-response", "v2link-netmon helper returned an empty response.")
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise NetmonUnavailableError("invalid-response", "v2link-netmon helper returned invalid JSON.") from exc
        if not isinstance(payload, dict):
            raise NetmonUnavailableError("invalid-response", "v2link-netmon helper returned an invalid response.")
        return payload


def _unavailable_status(
    *,
    socket_path: str | None,
    api_url: str | None,
    last_response: str | None,
    evidence: _InstallationEvidence,
    reason_code: str,
) -> NetmonStatus:
    daemon_state = {
        "socket-missing": "inactive" if evidence.service_state == "inactive" else "socket-missing",
        "permission-denied": "permission-denied",
        "connection-refused": "connection-refused",
        "timeout": "timeout",
        "invalid-response": "invalid-response",
        "socket-error": "failed",
    }.get(reason_code, "unknown")
    if reason_code == "socket-missing" and evidence.service_state == "failed":
        daemon_state = "failed"
    messages = {
        "permission-denied": "The helper is installed, but access to its socket was denied.",
        "connection-refused": "The helper socket exists, but the daemon refused the connection.",
        "timeout": "The helper did not respond before the local timeout.",
        "invalid-response": "The helper returned an invalid status response.",
        "socket-missing": (
            "The helper is installed, but its service is inactive or its socket is missing."
            if evidence.installed else "The optional v2link-netmon helper is not installed."
        ),
    }
    remediation = {
        "permission-denied": "Ask an administrator to grant helper-group access, then log out and back in.",
        "connection-refused": "Inspect v2link-netmon.service status; no service action is taken automatically.",
        "timeout": "Inspect v2link-netmon.service logs and try again.",
        "invalid-response": "Check that the installed helper version is compatible with this application.",
        "socket-missing": (
            "Ask an administrator to enable and start v2link-netmon.service."
            if evidence.installed else "Install the optional Debian v2link-netmon system helper."
        ),
    }
    if evidence.installation_state == "external-helper-required":
        messages["socket-missing"] = (
            "Per-application tracking requires the separately installed v2link-netmon system helper."
        )
        remediation["socket-missing"] = (
            "Install and configure the optional system helper; AppImage proxy operation is unaffected."
        )
    if daemon_state == "failed":
        messages["socket-missing"] = "The helper is installed, but its service is in a failed state."
        remediation["socket-missing"] = "Inspect v2link-netmon.service status and logs."
    return NetmonStatus(
        installed=evidence.installed,
        running=False,
        permission_ok=False,
        message=messages.get(reason_code, "The v2link-netmon helper is unavailable."),
        socket_path=socket_path,
        api_url=api_url,
        last_response=last_response,
        kernel_support="not checked yet",
        provider="socket",
        backend="unavailable",
        kernel_supported=None,
        last_error=last_response,
        operational=False,
        installation_state=evidence.installation_state,
        daemon_state=daemon_state,
        backend_state="unknown",
        reason_code=(
            "external-helper-required"
            if evidence.installation_state == "external-helper-required"
            else "helper-not-installed" if not evidence.installed
            else "service-failed" if daemon_state == "failed"
            else reason_code
        ),
        remediation=remediation.get(reason_code, "Inspect v2link-netmon.service status."),
        helper_binary_path=evidence.helper_binary_path,
        service_unit_path=evidence.service_unit_path,
        service_state=evidence.service_state,
    )


def _status_from_payload(
    payload: dict,
    *,
    socket_path: str | None,
    api_url: str | None,
    last_response: str | None,
    evidence: _InstallationEvidence,
) -> NetmonStatus:
    backend = _string_field(payload, "backend", "unknown")
    reported_backend_state = _backend_state(payload, backend)
    counters_available = _bool_field(payload, "counters_available", default=False)
    # Fail closed: a legacy or malformed response without an explicit boolean
    # cannot claim that production counters are available.
    operational = (
        reported_backend_state == "operational"
        and _bool_field(payload, "operational", default=False)
        and counters_available
    )
    backend_state = (
        "unavailable"
        if reported_backend_state == "operational" and not operational
        else reported_backend_state
    )
    kernel_supported = _optional_bool(payload.get("kernel_supported"))
    reason_code = _string_field(
        payload, "reason_code", "operational" if operational else backend_state
    )
    if not operational and reason_code == "operational":
        reason_code = "counters-unavailable"
    raw_error = payload.get("last_error") or payload.get("backend_error")
    safe_error = sanitize_sensitive_text(str(raw_error)) if raw_error not in {None, ""} else None
    return NetmonStatus(
        installed=True,
        running=True,
        permission_ok=_bool_field(payload, "permission_ok", default=True),
        message=sanitize_sensitive_text(
            _string_field(payload, "message", _backend_message(backend_state))
        ),
        # The configured local endpoint is authoritative. Do not expose a
        # daemon-supplied filesystem path in diagnostics or UI state.
        socket_path=socket_path,
        api_url=api_url,
        last_response=last_response,
        kernel_support=(
            "supported" if kernel_supported is True else "unsupported" if kernel_supported is False else "unknown"
        ),
        provider="socket",
        backend=backend,
        kernel_supported=kernel_supported,
        last_error=safe_error,
        operational=operational,
        installation_state="installed",
        daemon_state="reachable",
        backend_state=backend_state,
        reason_code=reason_code,
        remediation=_backend_remediation(backend_state),
        helper_binary_path=evidence.helper_binary_path,
        service_unit_path=evidence.service_unit_path,
        service_state=evidence.service_state or "active",
        counters_available=counters_available,
    )


def _bool_field(payload: dict, key: str, *, default: bool) -> bool:
    value = payload.get(key, default)
    return value if isinstance(value, bool) else default


def _optional_bool(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def _string_field(payload: dict, key: str, default: str) -> str:
    value = payload.get(key)
    return value.strip() if isinstance(value, str) and value.strip() else default


def _backend_state(payload: dict, backend: str) -> str:
    explicit = payload.get("backend_state")
    if isinstance(explicit, str) and explicit in {
        "unavailable", "not-implemented", "kernel-unsupported",
        "initialization-failed", "operational", "unknown",
    }:
        return explicit
    reason = _string_field(payload, "reason_code", "")
    if reason == "backend-not-implemented" or backend in {"ebpf-unavailable", "placeholder"}:
        return "not-implemented"
    if reason == "kernel-unsupported":
        return "kernel-unsupported"
    if reason == "backend-initialization-failed":
        return "initialization-failed"
    return "unknown"


def _backend_message(state: str) -> str:
    return {
        "not-implemented": "The helper daemon is running, but per-application attribution is not implemented in this release.",
        "kernel-unsupported": "The helper daemon is running, but this kernel does not support its backend.",
        "initialization-failed": "The helper daemon is running, but its backend failed to initialize.",
        "operational": "Per-application tracking is operational.",
    }.get(state, "The helper daemon is reachable, but backend status is unknown.")


def _backend_remediation(state: str) -> str | None:
    return {
        "not-implemented": "Use aggregate Xray traffic data; production per-application attribution is unavailable in this release.",
        "kernel-unsupported": "Use a supported kernel or keep per-application tracking disabled.",
        "initialization-failed": "Inspect v2link-netmon.service logs for the sanitized backend error.",
    }.get(state)


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
