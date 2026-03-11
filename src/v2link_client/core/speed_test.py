"""Simple speed test through the local HTTP proxy inbound.

This is not meant to replace full-featured speed test tools; it's a quick,
dependency-free check for throughput and basic tunnel health.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import time
import urllib.request

from v2link_client.version import get_semver


DEFAULT_USER_AGENT = f"Mozilla/5.0 (X11; Linux x86_64) v2link-client/{get_semver()}"
DEFAULT_DOWNLOAD_BYTES = 10 * 1024 * 1024
DEFAULT_UPLOAD_BYTES = 5 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class SpeedTestResult:
    download_bps: float | None
    upload_bps: float | None
    download_bytes: int
    upload_bytes: int
    download_time_s: float | None
    upload_time_s: float | None
    error: str | None


def run_speed_test_via_http_proxy(
    proxy_host: str,
    proxy_port: int,
    *,
    download_bytes: int = DEFAULT_DOWNLOAD_BYTES,
    upload_bytes: int = DEFAULT_UPLOAD_BYTES,
    timeout_s: float = 25.0,
) -> SpeedTestResult:
    proxy_host = (proxy_host or "").strip()
    if not proxy_host or not isinstance(proxy_port, int) or proxy_port <= 0:
        return SpeedTestResult(
            download_bps=None,
            upload_bps=None,
            download_bytes=0,
            upload_bytes=0,
            download_time_s=None,
            upload_time_s=None,
            error="Missing proxy host/port",
        )

    proxy_url = f"http://{proxy_host}:{proxy_port}"
    handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    opener = urllib.request.build_opener(handler)

    dl_url = f"https://speed.cloudflare.com/__down?bytes={int(max(1, download_bytes))}"
    ul_url = "https://speed.cloudflare.com/__up"

    headers = {"User-Agent": DEFAULT_USER_AGENT}

    dl_time_s: float | None = None
    ul_time_s: float | None = None
    dl_bps: float | None = None
    ul_bps: float | None = None

    try:
        # Download
        req = urllib.request.Request(dl_url, headers=headers, method="GET")
        started = time.monotonic()
        read_total = 0
        with opener.open(req, timeout=timeout_s) as resp:
            while True:
                chunk = resp.read(64 * 1024)
                if not chunk:
                    break
                read_total += len(chunk)
        dl_time_s = max(0.001, time.monotonic() - started)
        dl_bps = read_total / dl_time_s

        # Upload
        payload = os.urandom(int(max(1, upload_bytes)))
        req2 = urllib.request.Request(
            ul_url,
            data=payload,
            method="POST",
            headers={**headers, "Content-Type": "application/octet-stream"},
        )
        started2 = time.monotonic()
        with opener.open(req2, timeout=timeout_s) as resp2:
            # Read a byte so the request fully completes.
            try:
                resp2.read(1)
            except Exception:
                pass
        ul_time_s = max(0.001, time.monotonic() - started2)
        ul_bps = len(payload) / ul_time_s

        return SpeedTestResult(
            download_bps=dl_bps,
            upload_bps=ul_bps,
            download_bytes=read_total,
            upload_bytes=len(payload),
            download_time_s=dl_time_s,
            upload_time_s=ul_time_s,
            error=None,
        )
    except Exception as exc:  # noqa: BLE001 - user facing
        return SpeedTestResult(
            download_bps=dl_bps,
            upload_bps=ul_bps,
            download_bytes=0,
            upload_bytes=0,
            download_time_s=dl_time_s,
            upload_time_s=ul_time_s,
            error=str(exc),
        )
