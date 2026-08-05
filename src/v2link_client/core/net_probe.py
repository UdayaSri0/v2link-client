"""Network probes (ping-like checks) for remote servers."""

from __future__ import annotations

from dataclasses import dataclass
import socket
import ssl
import time


@dataclass(frozen=True, slots=True)
class ServerPingResult:
    tcp_ms: int | None
    tls_sni_ms: int | None
    tls_host_ms: int | None
    error: str | None


def ping_server(
    host: str,
    port: int,
    *,
    security: str = "none",
    sni: str | None = None,
    timeout_s: float = 3.0,
) -> ServerPingResult:
    host = (host or "").strip()
    if not host or not isinstance(port, int) or port <= 0:
        return ServerPingResult(
            tcp_ms=None,
            tls_sni_ms=None,
            tls_host_ms=None,
            error="Missing host/port",
        )

    tcp_ms: int | None = None
    try:
        started = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout_s):
            tcp_ms = int((time.monotonic() - started) * 1000)
    except OSError as exc:
        return ServerPingResult(
            tcp_ms=None,
            tls_sni_ms=None,
            tls_host_ms=None,
            error=str(exc),
        )

    if (security or "").strip().lower() != "tls":
        return ServerPingResult(
            tcp_ms=tcp_ms,
            tls_sni_ms=None,
            tls_host_ms=None,
            error=None,
        )

    def _tls_handshake(server_name: str) -> tuple[int | None, str | None]:
        context = ssl.create_default_context()

        started_tls = time.monotonic()
        try:
            with socket.create_connection((host, port), timeout=timeout_s) as sock:
                sock.settimeout(timeout_s)
                with context.wrap_socket(sock, server_hostname=server_name) as ssock:
                    ssock.do_handshake()
            return int((time.monotonic() - started_tls) * 1000), None
        except Exception as exc:  # noqa: BLE001 - we want the user-visible error text
            return None, str(exc)

    tls_sni_ms: int | None = None
    tls_host_ms: int | None = None
    errors: list[str] = []

    server_sni = (sni or "").strip() or host
    ms, err = _tls_handshake(server_sni)
    tls_sni_ms = ms
    if err:
        errors.append(f"TLS({server_sni}): {err}")

    if server_sni != host:
        ms2, err2 = _tls_handshake(host)
        tls_host_ms = ms2
        if err2:
            errors.append(f"TLS({host}): {err2}")

    return ServerPingResult(
        tcp_ms=tcp_ms,
        tls_sni_ms=tls_sni_ms,
        tls_host_ms=tls_host_ms,
        error="; ".join(errors) if errors else None,
    )
