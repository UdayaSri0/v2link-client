from __future__ import annotations

import pytest

from v2link_client.core.config_builder import (
    DEFAULT_HTTP_PORT,
    DEFAULT_LISTEN,
    DEFAULT_SOCKS_PORT,
    build_xray_config,
)
from v2link_client.core.errors import ConfigBuildError
from v2link_client.core.link_parser import parse_link


def test_build_xray_config_for_vless_tls(tmp_path) -> None:
    parsed = parse_link(
        "vless://b345f204-4df1-4d31-8243-dae7845099ad@prime.example.com:443"
        "?security=tls&allowInsecure=0&encryption=none&type=tcp&sni=aka.ms&fp=chrome"
    )
    cfg = build_xray_config(parsed, logs_dir=tmp_path)

    assert cfg["inbounds"][0]["listen"] == DEFAULT_LISTEN
    assert cfg["inbounds"][0]["port"] == DEFAULT_SOCKS_PORT
    assert cfg["inbounds"][1]["port"] == DEFAULT_HTTP_PORT

    outbound = cfg["outbounds"][0]
    assert outbound["protocol"] == "vless"
    vnext = outbound["settings"]["vnext"][0]
    assert vnext["address"] == "prime.example.com"
    assert vnext["port"] == 443
    assert vnext["users"][0]["id"] == "b345f204-4df1-4d31-8243-dae7845099ad"

    stream = outbound["streamSettings"]
    assert stream["network"] == "tcp"
    assert stream["security"] == "tls"
    assert stream["tlsSettings"]["serverName"] == "aka.ms"
    assert stream["tlsSettings"]["allowInsecure"] is False
    assert stream["tlsSettings"]["fingerprint"] == "chrome"
    assert stream["tlsSettings"]["verifyPeerCertByName"] == "aka.ms,prime.example.com"


def test_build_xray_config_rejects_grpc_without_service_name(tmp_path) -> None:
    parsed = parse_link(
        "vless://b345f204-4df1-4d31-8243-dae7845099ad@prime.example.com:443"
        "?security=tls&type=grpc"
    )
    with pytest.raises(ConfigBuildError):
        build_xray_config(parsed, logs_dir=tmp_path)


def test_build_xray_config_supports_ws(tmp_path) -> None:
    parsed = parse_link(
        "vless://b345f204-4df1-4d31-8243-dae7845099ad@prime.example.com:443"
        "?security=tls&type=ws&path=%2Fwebsocket&host=cdn.example.com"
    )
    cfg = build_xray_config(parsed, logs_dir=tmp_path)
    stream = cfg["outbounds"][0]["streamSettings"]
    assert stream["network"] == "ws"
    assert stream["wsSettings"]["path"] == "/websocket"
    assert stream["wsSettings"]["headers"]["Host"] == "cdn.example.com"


def test_build_xray_config_includes_stats_api_when_api_port_set(tmp_path) -> None:
    parsed = parse_link(
        "vless://b345f204-4df1-4d31-8243-dae7845099ad@prime.example.com:443"
        "?security=tls&allowInsecure=0&encryption=none&type=tcp&sni=aka.ms&fp=chrome"
    )
    cfg = build_xray_config(parsed, logs_dir=tmp_path, api_port=12345)

    assert cfg["api"]["tag"] == "api"
    assert "StatsService" in cfg["api"]["services"]
    assert cfg["routing"]["rules"][0]["inboundTag"] == ["api"]
    assert cfg["routing"]["rules"][0]["outboundTag"] == "api"
    assert cfg["policy"]["system"]["statsOutboundUplink"] is True
    assert cfg["policy"]["system"]["statsOutboundDownlink"] is True

    api_inbound = next(i for i in cfg["inbounds"] if i["tag"] == "api")
    assert api_inbound["listen"] == DEFAULT_LISTEN
    assert api_inbound["port"] == 12345
