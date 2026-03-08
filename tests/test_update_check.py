from __future__ import annotations

import pytest

from v2link_client.core.update_check import (
    UpdateCheckError,
    is_update_available,
    normalize_version,
    parse_release_payload,
)


def test_normalize_version_strips_v_prefix_and_spaces() -> None:
    assert normalize_version(" v0.1.9.0.0 ") == "0.1.9.0.0"
    assert normalize_version("V 1.2.3") == "1.2.3"


def test_is_update_available_handles_dotted_versions() -> None:
    assert is_update_available("0.1.9.0.0", "v0.1.10.0.0") is True
    assert is_update_available("0.1.9.0.0", "v0.1.9.0.0") is False
    assert is_update_available("0.1.10.0.0", "v0.1.9.9.9") is False


def test_parse_release_payload_extracts_assets_and_notes() -> None:
    payload = {
        "tag_name": "v0.1.10.0.0",
        "html_url": "https://github.com/UdayaSri0/v2link-client/releases/tag/v0.1.10.0.0",
        "body": "\n".join(
            [
                "Release highlights",
                "",
                "- Fix system proxy drift",
                "- Improve diagnostics",
                "- Add update checker",
            ]
        ),
        "assets": [
            {
                "name": "v2link-client-0.1.10.0.0-x86_64.AppImage",
                "browser_download_url": "https://example.com/v2link-client.AppImage",
            },
            {
                "name": "v2link-client_0.1.10.0.0_amd64.deb",
                "browser_download_url": "https://example.com/v2link-client.deb",
            },
        ],
    }

    result = parse_release_payload(payload, current_version="0.1.9.0.0")
    assert result.update_available is True
    assert result.latest_version == "0.1.10.0.0"
    assert result.appimage_asset is not None
    assert result.appimage_asset.download_url.endswith(".AppImage")
    assert result.deb_asset is not None
    assert result.deb_asset.download_url.endswith(".deb")
    assert result.notes is not None
    assert "Release highlights" in result.notes


def test_parse_release_payload_requires_tag_name() -> None:
    with pytest.raises(UpdateCheckError):
        parse_release_payload({}, current_version="0.1.9.0.0")
