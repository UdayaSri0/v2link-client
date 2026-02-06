from __future__ import annotations

import types

import pytest

from v2link_client.core.health_check import ProxyHealthResult, check_http_proxy


class _FakeResponse:
    def __init__(self, status: int) -> None:
        self.status = status

    def read(self, _: int = -1) -> bytes:
        return b""

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


def test_health_check_success(monkeypatch) -> None:
    def fake_build_opener(_handler):
        return types.SimpleNamespace(open=lambda _req, timeout: _FakeResponse(204))

    monkeypatch.setattr("urllib.request.build_opener", fake_build_opener)

    result = check_http_proxy(
        "127.0.0.1",
        8080,
        http_urls=("http://example.com",),
        https_urls=("https://example.com",),
    )
    assert isinstance(result, ProxyHealthResult)
    assert result.state == "online"
    assert result.status_code == 204
    assert result.checked_url == "https://example.com"
    assert result.error is None


def test_health_check_tries_fallback_urls(monkeypatch) -> None:
    calls: list[str] = []

    def fake_open(req, timeout):
        calls.append(req.full_url)
        if req.full_url.endswith("a"):
            raise OSError("boom")
        return _FakeResponse(200)

    def fake_build_opener(_handler):
        return types.SimpleNamespace(open=fake_open)

    monkeypatch.setattr("urllib.request.build_opener", fake_build_opener)

    result = check_http_proxy(
        "127.0.0.1",
        8080,
        http_urls=("http://t/a", "http://t/b"),
        https_urls=("https://t/c",),
    )
    assert result.state == "online"
    assert calls == ["http://t/a", "http://t/b", "https://t/c"]


def test_health_check_failure(monkeypatch) -> None:
    def fake_build_opener(_handler):
        def _open(_req, timeout):
            raise OSError("connection refused")

        return types.SimpleNamespace(open=_open)

    monkeypatch.setattr("urllib.request.build_opener", fake_build_opener)

    result = check_http_proxy(
        "127.0.0.1", 8080, http_urls=("http://example.com",), https_urls=("https://example.com",)
    )
    assert result.state == "offline"
    assert "refused" in (result.error or "").lower()


def test_health_check_degraded_http_ok_https_fail(monkeypatch) -> None:
    def fake_open(req, timeout):
        if req.full_url.startswith("https://"):
            raise OSError("tls failed")
        return _FakeResponse(204)

    def fake_build_opener(_handler):
        return types.SimpleNamespace(open=fake_open)

    monkeypatch.setattr("urllib.request.build_opener", fake_build_opener)

    result = check_http_proxy(
        "127.0.0.1",
        8080,
        http_urls=("http://example.com",),
        https_urls=("https://example.com",),
    )
    assert result.state == "degraded"
    assert "HTTP ok" in (result.error or "")
