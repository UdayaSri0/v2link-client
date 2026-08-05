from __future__ import annotations

import json
from pathlib import Path

import pytest

from v2link_client.core.config_builder import build_xray_config
from v2link_client.core.link_parser import parse_link
from v2link_client.core.process_manager import validate_xray_config
from v2link_client.core.xray_locator import get_bundled_xray_candidates, validate_xray_binary


def _contains_key(value, key: str) -> bool:
    if isinstance(value, dict):
        return key in value or any(_contains_key(child, key) for child in value.values())
    if isinstance(value, list):
        return any(_contains_key(child, key) for child in value)
    return False


def _available_bundled_xray():
    for candidate in get_bundled_xray_candidates():
        result = validate_xray_binary(candidate, source="bundled")
        if result.valid and result.path:
            return result
    pytest.skip("bundled Xray binary is unavailable for this architecture")


@pytest.mark.parametrize(
    "modern_query",
    [
        "",
        f"&pcs={'ab' * 32}",
        f"&pcs={'cd' * 32}&vcn=verify.example.invalid",
    ],
    ids=["legacy-only", "certificate-pin", "certificate-pin-and-name"],
)
def test_bundled_xray_accepts_migrated_tls_config(tmp_path: Path, modern_query: str) -> None:
    raw = (
        "vless://11111111-1111-1111-1111-111111111111@example.invalid:443"
        "?encryption=none&security=tls&type=tcp&allowInsecure=1"
        f"{modern_query}"
    )
    config = build_xray_config(parse_link(raw), logs_dir=tmp_path)
    assert not _contains_key(config, "allowInsecure")

    config_path = tmp_path / "xray.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    validate_xray_config(_available_bundled_xray(), config_path)
