from __future__ import annotations

import ssl

import v2link_client.core.net_probe as net_probe


class _FakeSocket:
    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def settimeout(self, _timeout: float) -> None:
        return None


class _FakeTlsSocket(_FakeSocket):
    def do_handshake(self) -> None:
        return None


class _FakeTlsContext:
    def __init__(self) -> None:
        self.check_hostname = True
        self.verify_mode = ssl.CERT_REQUIRED

    def wrap_socket(self, _socket, *, server_hostname: str):
        assert server_hostname == "server.invalid"
        assert self.check_hostname is True
        assert self.verify_mode == ssl.CERT_REQUIRED
        return _FakeTlsSocket()


def test_tls_probe_always_retains_secure_certificate_verification(monkeypatch) -> None:
    context = _FakeTlsContext()
    monkeypatch.setattr(
        net_probe.socket,
        "create_connection",
        lambda *_args, **_kwargs: _FakeSocket(),
    )
    monkeypatch.setattr(net_probe.ssl, "create_default_context", lambda: context)

    result = net_probe.ping_server(
        "server.invalid",
        443,
        security="tls",
        sni="server.invalid",
    )

    assert result.error is None
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
