from __future__ import annotations

import sys

from v2link_client.app_assets import get_app_icon_path


def test_get_app_icon_path_prefers_meipass_when_frozen(tmp_path, monkeypatch) -> None:
    bundle_root = tmp_path / "_internal"
    bundle_root.mkdir()
    icon_path = bundle_root / "icon.png"
    icon_path.write_bytes(b"png")

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(bundle_root), raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "v2link-client"), raising=False)

    assert get_app_icon_path() == icon_path
