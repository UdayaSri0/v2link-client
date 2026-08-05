from __future__ import annotations

import pytest

from v2link_client.core.errors import InvalidLinkError, UnsupportedSchemeError
from v2link_client.core.link_parser import VlessLink, parse_link


USER_ID = "11111111-1111-4111-8111-111111111111"
PIN_A = "01" * 32
PIN_B = "aB" * 32


def _link(query: str = "security=tls") -> str:
    return f"vless://{USER_ID}@server.invalid:443?{query}"


def test_parse_vless_basic() -> None:
    link = (
        f"vless://{USER_ID}@server.invalid:443"
        "?security=tls&allowInsecure=0&encryption=none&type=tcp&sni=edge.invalid&fp=chrome&headerType=none"
        "#Synthetic%20profile"
    )
    parsed = parse_link(link)
    assert isinstance(parsed, VlessLink)
    assert parsed.user_id == USER_ID
    assert parsed.host == "server.invalid"
    assert parsed.port == 443
    assert parsed.security == "tls"
    assert parsed.legacy_allow_insecure is False
    assert parsed.transport == "tcp"
    assert parsed.sni == "edge.invalid"
    assert parsed.fingerprint == "chrome"
    assert parsed.name == "Synthetic profile"


def test_parse_vless_rejects_invalid_uuid() -> None:
    link = "vless://not-a-uuid@server.invalid:443?security=tls"
    with pytest.raises(InvalidLinkError):
        parse_link(link)


def test_parse_rejects_unsupported_scheme() -> None:
    with pytest.raises(UnsupportedSchemeError):
        parse_link("http://example.invalid")


def test_parse_rejects_unimplemented_scheme() -> None:
    with pytest.raises(UnsupportedSchemeError):
        parse_link("vmess://abcd")


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("security=tls", None),
        ("security=tls&allowInsecure=0", False),
        ("security=tls&allowInsecure=false", False),
        ("security=tls&allowInsecure=1", True),
        ("security=tls&allowInsecure=true", True),
        ("security=tls&AlLoWiNsEcUrE=TRUE", True),
    ],
)
def test_parse_vless_preserves_legacy_allow_insecure_state(
    query: str, expected: bool | None
) -> None:
    parsed = parse_link(_link(query))
    assert parsed.legacy_allow_insecure is expected


def test_parse_vless_normalizes_certificate_pins() -> None:
    colon_pin = ":".join(PIN_A[index : index + 2] for index in range(0, 64, 2))
    parsed = parse_link(
        _link(
            f"security=tls&PCS={colon_pin},{PIN_B},{PIN_A}"
            f"&pinnedPeerCertSha256={PIN_B.lower()}"
        )
    )
    assert parsed.pinned_peer_cert_sha256 == (PIN_A, PIN_B.lower())


def test_parse_vless_preserves_first_seen_order_across_pin_aliases() -> None:
    pin_c = "cd" * 32
    parsed = parse_link(
        _link(
            f"security=tls&pinnedPeerCertSha256={PIN_B}"
            f"&pcs={PIN_A}&pinnedPeerCertSha256={pin_c}"
        )
    )

    assert parsed.pinned_peer_cert_sha256 == (PIN_B.lower(), PIN_A, pin_c)


@pytest.mark.parametrize(
    "value",
    [
        "ab" * 31,
        "ab" * 33,
        "gg" * 32,
        ("ab" * 16) + ":" + ("cd" * 16),
        f"{PIN_A},",
        "," + PIN_A,
    ],
)
def test_parse_vless_rejects_malformed_certificate_pins(value: str) -> None:
    with pytest.raises(InvalidLinkError) as caught:
        parse_link(_link(f"security=tls&pcs={value}"))
    assert value not in str(caught.value)


def test_parse_vless_parses_and_deduplicates_verification_names() -> None:
    parsed = parse_link(
        _link(
            "security=tls&VCN=edge.invalid,alt.invalid,edge.invalid"
            "&verifyPeerCertByName=third.invalid"
        )
    )
    assert parsed.verify_peer_cert_by_name == (
        "edge.invalid",
        "alt.invalid",
        "third.invalid",
    )


@pytest.mark.parametrize("value", ["edge.invalid,", ",edge.invalid", "edge%0A.invalid"])
def test_parse_vless_rejects_malformed_verification_names(value: str) -> None:
    with pytest.raises(InvalidLinkError) as caught:
        parse_link(_link(f"security=tls&vcn={value}"))
    assert "server.invalid" not in str(caught.value)


def test_parse_vless_rejects_overlong_verification_name_without_echoing_it() -> None:
    value = "a" * 254
    with pytest.raises(InvalidLinkError) as caught:
        parse_link(_link(f"security=tls&vcn={value}"))
    assert value not in str(caught.value)


def test_parse_vless_rejects_excessive_modern_tls_values() -> None:
    pins = ",".join(f"{index:064x}" for index in range(17))
    names = ",".join(f"name-{index}.invalid" for index in range(33))
    with pytest.raises(InvalidLinkError, match="pin count"):
        parse_link(_link(f"security=tls&pcs={pins}"))
    with pytest.raises(InvalidLinkError, match="name count"):
        parse_link(_link(f"security=tls&vcn={names}"))

    duplicate_pins = ",".join([PIN_A] * 17)
    duplicate_names = ",".join(["edge.invalid"] * 33)
    with pytest.raises(InvalidLinkError, match="pin count"):
        parse_link(_link(f"security=tls&pcs={duplicate_pins}"))
    with pytest.raises(InvalidLinkError, match="name count"):
        parse_link(_link(f"security=tls&vcn={duplicate_names}"))


def test_parse_vless_rejects_oversized_modern_tls_input() -> None:
    value = "a" * 4097
    with pytest.raises(InvalidLinkError) as caught:
        parse_link(_link(f"security=tls&vcn={value}"))
    assert value not in str(caught.value)


def test_parse_vless_combines_modern_fields_with_legacy_true() -> None:
    parsed = parse_link(
        _link(
            f"security=tls&allowInsecure=1&pcs={PIN_A}"
            "&vcn=certificate-name.invalid"
        )
    )
    assert parsed.legacy_allow_insecure is True
    assert parsed.pinned_peer_cert_sha256 == (PIN_A,)
    assert parsed.verify_peer_cert_by_name == ("certificate-name.invalid",)
