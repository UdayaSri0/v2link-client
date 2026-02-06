"""Connectivity checks for the running core.

We treat the core as "online" when an HTTPS request succeeds *through* the local
HTTP proxy inbound. This validates both:
- the local core is reachable, and
- the outbound tunnel can reach the internet.
"""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Literal
from typing import Sequence
import urllib.error
import urllib.request


DEFAULT_HTTP_TEST_URLS: tuple[str, ...] = (
    # Plain HTTP first so we can surface clear proxy status codes (e.g. 503)
    # instead of only TLS handshake errors.
    "http://www.gstatic.com/generate_204",
    "http://example.com/",
)

DEFAULT_HTTPS_TEST_URLS: tuple[str, ...] = (
    "https://www.gstatic.com/generate_204",
    "https://1.1.1.1/cdn-cgi/trace",
)


@dataclass(frozen=True, slots=True)
class ProxyHealthResult:
    state: Literal["online", "degraded", "offline"]
    checked_url: str | None
    status_code: int | None
    latency_ms: int | None
    error: str | None


def check_http_proxy(
    proxy_host: str,
    proxy_port: int,
    *,
    http_urls: Sequence[str] = DEFAULT_HTTP_TEST_URLS,
    https_urls: Sequence[str] = DEFAULT_HTTPS_TEST_URLS,
    timeout_s: float = 4.0,
) -> ProxyHealthResult:
    proxy_url = f"http://{proxy_host}:{proxy_port}"
    handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    opener = urllib.request.build_opener(handler)

    http_result = _try_urls(opener, http_urls, timeout_s)
    if http_result.state != "online":
        return http_result

    https_result = _try_urls(opener, https_urls, timeout_s)
    if https_result.state == "online":
        return https_result

    return ProxyHealthResult(
        state="degraded",
        checked_url=https_result.checked_url,
        status_code=https_result.status_code,
        latency_ms=https_result.latency_ms,
        error=f"HTTP ok, HTTPS failed: {https_result.error or 'unknown error'}",
    )


def _try_urls(
    opener,
    urls: Sequence[str],
    timeout_s: float,
) -> ProxyHealthResult:
    best_failure: ProxyHealthResult | None = None
    for url in urls:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "v2link-client/0.1"},
            method="GET",
        )
        started = time.monotonic()
        try:
            with opener.open(request, timeout=timeout_s) as response:
                status = getattr(response, "status", None)
                # Read a byte so the request fully completes for endpoints with a body.
                try:
                    response.read(1)
                except Exception:
                    # Some responses may not be readable; ignore as long as the
                    # connection/proxying succeeded.
                    pass
        except urllib.error.HTTPError as exc:
            latency_ms = int((time.monotonic() - started) * 1000)
            failure = ProxyHealthResult(
                state="offline",
                checked_url=url,
                status_code=int(getattr(exc, "code", 0)) or None,
                latency_ms=latency_ms,
                error=f"HTTP {exc.code} {exc.reason}",
            )
            best_failure = _prefer_failure(best_failure, failure)
            continue
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            latency_ms = int((time.monotonic() - started) * 1000)
            failure = ProxyHealthResult(
                state="offline",
                checked_url=url,
                status_code=None,
                latency_ms=latency_ms,
                error=str(exc),
            )
            best_failure = _prefer_failure(best_failure, failure)
            continue

        latency_ms = int((time.monotonic() - started) * 1000)
        ok = status is None or 200 <= int(status) < 400
        if ok:
            return ProxyHealthResult(
                state="online",
                checked_url=url,
                status_code=int(status) if status is not None else None,
                latency_ms=latency_ms,
                error=None,
            )

        failure = ProxyHealthResult(
            state="offline",
            checked_url=url,
            status_code=int(status) if status is not None else None,
            latency_ms=latency_ms,
            error=f"HTTP {status}",
        )
        best_failure = _prefer_failure(best_failure, failure)

    if best_failure is not None:
        return best_failure

    return ProxyHealthResult(
        state="offline",
        checked_url=urls[-1] if urls else None,
        status_code=None,
        latency_ms=None,
        error="Unknown error",
    )


def _prefer_failure(
    current: ProxyHealthResult | None, candidate: ProxyHealthResult
) -> ProxyHealthResult:
    if current is None:
        return candidate
    if current.status_code is None and candidate.status_code is not None:
        return candidate
    if current.error is None and candidate.error is not None:
        return candidate
    return current
