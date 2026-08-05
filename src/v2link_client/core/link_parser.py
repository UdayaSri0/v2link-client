"""Parse V2Ray-style links.

This module currently focuses on `vless://` links because they're common in
V2Ray/Xray ecosystems and are the minimal requirement to start the core.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
import uuid
from typing import Literal
from urllib.parse import parse_qsl, unquote, urlparse

from v2link_client.core.errors import InvalidLinkError, UnsupportedSchemeError

SUPPORTED_SCHEMES: set[str] = {"vmess", "vless", "trojan", "ss"}
MAX_TLS_QUERY_VALUE_LENGTH = 4096
MAX_CERTIFICATE_PINS = 16
MAX_VERIFICATION_NAMES = 32
MAX_VERIFICATION_NAME_LENGTH = 253


@dataclass(frozen=True, slots=True)
class VlessLink:
    scheme: Literal["vless"]
    name: str | None
    user_id: str
    host: str
    port: int
    encryption: str
    security: str
    transport: str
    sni: str | None
    fingerprint: str | None
    legacy_allow_insecure: bool | None
    header_type: str | None
    path: str | None
    ws_host: str | None
    grpc_service_name: str | None
    flow: str | None
    alpn: list[str] | None
    pinned_peer_cert_sha256: tuple[str, ...] | None
    verify_peer_cert_by_name: tuple[str, ...] | None

    def display_name(self) -> str:
        return self.name or f"{self.host}:{self.port}"


ParsedLink = VlessLink


def _first(query: dict[str, list[str]], key: str) -> str | None:
    values = query.get(key)
    if not values:
        return None
    value = values[0].strip()
    return value or None


def _parse_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    return None


def _parse_certificate_pins(values: list[str]) -> tuple[str, ...] | None:
    if not values:
        return None
    if sum(len(value) for value in values) > MAX_TLS_QUERY_VALUE_LENGTH:
        raise InvalidLinkError(
            "Certificate pin input exceeds the supported limit",
            user_message="The profile's certificate pin data is too long.",
        )

    result: list[str] = []
    seen: set[str] = set()
    entry_count = 0
    for value in values:
        for item in value.split(","):
            entry_count += 1
            if entry_count > MAX_CERTIFICATE_PINS:
                raise InvalidLinkError(
                    "Certificate pin count exceeds the supported limit",
                    user_message="The profile contains too many certificate pins.",
                )
            candidate = item.strip()
            if not candidate:
                raise InvalidLinkError(
                    "Certificate pin list contains an empty entry",
                    user_message="The profile contains an empty certificate pin.",
                )
            colon_hex = r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){31}"
            if ":" in candidate and re.fullmatch(colon_hex, candidate) is None:
                raise InvalidLinkError(
                    "Certificate pin has invalid colon-separated hexadecimal syntax",
                    user_message="A certificate pin has an invalid hexadecimal format.",
                )
            candidate = candidate.replace(":", "")
            if len(candidate) != 64:
                raise InvalidLinkError(
                    "Certificate pin has an invalid SHA-256 length",
                    user_message="A certificate pin must be a 32-byte SHA-256 value.",
                )
            try:
                bytes.fromhex(candidate)
            except ValueError as exc:
                raise InvalidLinkError(
                    "Certificate pin contains non-hexadecimal characters",
                    user_message="A certificate pin must contain only hexadecimal characters.",
                ) from exc
            normalized = candidate.lower()
            if normalized not in seen:
                seen.add(normalized)
                result.append(normalized)
    return tuple(result)


def _parse_verification_names(values: list[str]) -> tuple[str, ...] | None:
    if not values:
        return None
    if sum(len(value) for value in values) > MAX_TLS_QUERY_VALUE_LENGTH:
        raise InvalidLinkError(
            "Certificate verification-name input exceeds the supported limit",
            user_message="The profile's certificate verification-name data is too long.",
        )

    result: list[str] = []
    seen: set[str] = set()
    entry_count = 0
    for value in values:
        for item in value.split(","):
            entry_count += 1
            if entry_count > MAX_VERIFICATION_NAMES:
                raise InvalidLinkError(
                    "Certificate verification-name count exceeds the supported limit",
                    user_message="The profile contains too many certificate verification names.",
                )
            candidate = item.strip()
            if not candidate:
                raise InvalidLinkError(
                    "Certificate verification-name list contains an empty entry",
                    user_message="The profile contains an empty certificate verification name.",
                )
            if len(candidate) > MAX_VERIFICATION_NAME_LENGTH:
                raise InvalidLinkError(
                    "Certificate verification name exceeds the supported limit",
                    user_message="A certificate verification name is too long.",
                )
            if any(ord(character) < 32 or ord(character) == 127 for character in candidate):
                raise InvalidLinkError(
                    "Certificate verification name contains a control character",
                    user_message="A certificate verification name contains an invalid character.",
                )
            if candidate not in seen:
                seen.add(candidate)
                result.append(candidate)
    return tuple(result)


def parse_link(raw: str) -> ParsedLink:
    raw = (raw or "").strip()
    if not raw:
        raise InvalidLinkError("Empty link", user_message="Paste a vless:// link first.")

    parsed = urlparse(raw)
    scheme = (parsed.scheme or "").lower()
    if scheme not in SUPPORTED_SCHEMES:
        raise UnsupportedSchemeError(
            f"Unsupported scheme: {scheme!r}",
            user_message=f"Unsupported link scheme: {scheme or '<missing>'}://",
        )

    if scheme != "vless":
        raise UnsupportedSchemeError(
            f"Scheme not implemented: {scheme}",
            user_message="Only vless:// links are supported in this build.",
        )

    return _parse_vless(raw)


def _parse_vless(raw: str) -> VlessLink:
    parsed = urlparse(raw)

    user_id = parsed.username or ""
    host = parsed.hostname or ""
    port = parsed.port
    if not user_id or not host or port is None:
        raise InvalidLinkError(
            "Malformed vless link",
            user_message="VLESS link must include user id, host, and port.",
        )

    try:
        uuid.UUID(user_id)
    except ValueError as exc:
        raise InvalidLinkError(
            "Invalid VLESS user id",
            user_message="VLESS user id must be a UUID.",
        ) from exc

    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query: dict[str, list[str]] = {}
    for key, value in query_pairs:
        query.setdefault(key.lower(), []).append(value)

    encryption = _first(query, "encryption") or "none"
    security = _first(query, "security") or "none"
    transport = _first(query, "type") or _first(query, "transport") or "tcp"

    legacy_allow_insecure = _parse_bool(_first(query, "allowinsecure"))
    pinned_peer_cert_sha256 = _parse_certificate_pins(
        [
            value
            for key, value in query_pairs
            if key.lower() in {"pcs", "pinnedpeercertsha256"}
        ]
    )
    verify_peer_cert_by_name = _parse_verification_names(
        [
            value
            for key, value in query_pairs
            if key.lower() in {"vcn", "verifypeercertbyname"}
        ]
    )

    sni = _first(query, "sni") or _first(query, "servername")
    fingerprint = _first(query, "fp") or _first(query, "fingerprint")
    header_type = _first(query, "headertype")
    path = _first(query, "path")
    ws_host = _first(query, "host")
    grpc_service_name = _first(query, "servicename")
    flow = _first(query, "flow")

    alpn_raw = _first(query, "alpn")
    alpn = None
    if alpn_raw:
        alpn = [part.strip() for part in alpn_raw.split(",") if part.strip()]
        if not alpn:
            alpn = None

    name = unquote(parsed.fragment) if parsed.fragment else None

    transport = transport.lower()
    if transport not in {"tcp", "ws", "grpc"}:
        raise InvalidLinkError(
            f"Unsupported transport: {transport}",
            user_message=f"Unsupported VLESS transport: {transport}",
        )

    security = security.lower()
    if security not in {"none", "tls"}:
        raise InvalidLinkError(
            f"Unsupported security: {security}",
            user_message=f"Unsupported VLESS security: {security}",
        )

    return VlessLink(
        scheme="vless",
        name=name,
        user_id=user_id,
        host=host,
        port=port,
        encryption=encryption,
        security=security,
        transport=transport,
        sni=sni,
        fingerprint=fingerprint,
        legacy_allow_insecure=legacy_allow_insecure,
        header_type=header_type,
        path=path,
        ws_host=ws_host,
        grpc_service_name=grpc_service_name,
        flow=flow,
        alpn=alpn,
        pinned_peer_cert_sha256=pinned_peer_cert_sha256,
        verify_peer_cert_by_name=verify_peer_cert_by_name,
    )
