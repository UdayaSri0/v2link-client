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

    assert cfg["log"] == {"loglevel": "warning"}
    assert "access" not in cfg["log"]
    assert "error" not in cfg["log"]

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
    assert "allowInsecure" not in stream["tlsSettings"]
    assert stream["tlsSettings"]["fingerprint"] == "chrome"
    assert stream["tlsSettings"]["verifyPeerCertByName"] == "aka.ms,prime.example.com"


def _contains_key(value, key: str) -> bool:
    if isinstance(value, dict):
        return key in value or any(_contains_key(item, key) for item in value.values())
    if isinstance(value, list):
        return any(_contains_key(item, key) for item in value)
    return False


@pytest.mark.parametrize("legacy", ["0", "false", "1", "true"])
def test_legacy_allow_insecure_is_never_generated(tmp_path, legacy: str) -> None:
    parsed = parse_link(
        "vless://11111111-1111-1111-1111-111111111111@example.invalid:443"
        f"?security=tls&type=tcp&allowInsecure={legacy}"
    )
    cfg = build_xray_config(parsed, logs_dir=tmp_path)
    assert not _contains_key(cfg, "allowInsecure")


def test_explicit_modern_tls_fields_take_precedence(tmp_path) -> None:
    pin_a = "ab" * 32
    pin_b = "cd" * 32
    parsed = parse_link(
        "vless://11111111-1111-1111-1111-111111111111@example.invalid:443"
        "?security=tls&type=tcp&sni=sni.example.invalid"
        f"&pcs={pin_a},{pin_b}&vcn=verify.example.invalid,backup.example.invalid"
    )
    first = build_xray_config(parsed, logs_dir=tmp_path)
    second = build_xray_config(parsed, logs_dir=tmp_path)
    tls = first["outbounds"][0]["streamSettings"]["tlsSettings"]

    assert tls["serverName"] == "sni.example.invalid"
    assert tls["pinnedPeerCertSha256"] == f"{pin_a},{pin_b}"
    assert tls["verifyPeerCertByName"] == "verify.example.invalid,backup.example.invalid"
    assert first == second


def test_tls_without_sni_uses_host_without_empty_modern_fields(tmp_path) -> None:
    parsed = parse_link(
        "vless://11111111-1111-1111-1111-111111111111@example.invalid:443"
        "?security=tls&type=tcp&fp=chrome&alpn=h2,http%2F1.1"
    )
    tls = build_xray_config(parsed, logs_dir=tmp_path)["outbounds"][0]["streamSettings"]["tlsSettings"]
    assert tls["serverName"] == "example.invalid"
    assert tls["fingerprint"] == "chrome"
    assert tls["alpn"] == ["h2", "http/1.1"]
    assert "pinnedPeerCertSha256" not in tls
    assert "verifyPeerCertByName" not in tls


def test_detailed_xray_logging_is_opt_in_and_keeps_access_disabled(tmp_path) -> None:
    parsed = parse_link(
        "vless://11111111-1111-1111-1111-111111111111@example.com:443"
        "?security=tls&type=tcp"
    )

    cfg = build_xray_config(parsed, logs_dir=tmp_path, detailed_logging=True)

    assert cfg["log"] == {"loglevel": "debug"}


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
