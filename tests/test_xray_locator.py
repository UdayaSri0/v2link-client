from __future__ import annotations

import os
from pathlib import Path

import v2link_client.core.xray_locator as locator
from v2link_client.core.xray_settings import XraySettings


def _fake_xray(path: Path, *, output: str = "Xray 26.4.25") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!/usr/bin/env bash\nprintf '%s\\n' '{output}'\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def test_xray_locator_finds_dev_bundled_xray(tmp_path, monkeypatch) -> None:
    fake = _fake_xray(tmp_path / "vendor" / "xray" / "x86_64" / "xray")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(locator.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(locator, "load_xray_settings", lambda: XraySettings())
    monkeypatch.setattr(locator, "system_which", lambda _name: None)
    monkeypatch.setenv("V2LINK_BUNDLED_XRAY_DIR", str(fake.parent))

    result = locator.find_xray_binary()

    assert result.valid is True
    assert result.source == "bundled"
    assert result.path == str(fake)
    assert result.version == "v26.4.25"


def test_xray_locator_falls_back_to_path(tmp_path, monkeypatch) -> None:
    fake = _fake_xray(tmp_path / "bin" / "xray")
    monkeypatch.setattr(locator, "get_bundled_xray_candidates", lambda: [])
    monkeypatch.setattr(locator, "load_xray_settings", lambda: XraySettings())
    monkeypatch.setattr(locator, "system_which", lambda _name: str(fake))

    result = locator.find_xray_binary()

    assert result.valid is True
    assert result.source == "system-path"
    assert result.path == str(fake)


def test_xray_locator_handles_missing_binary(monkeypatch) -> None:
    monkeypatch.setattr(locator, "get_bundled_xray_candidates", lambda: [])
    monkeypatch.setattr(locator, "load_xray_settings", lambda: XraySettings())
    monkeypatch.setattr(locator, "system_which", lambda _name: None)

    result = locator.find_xray_binary()

    assert result.valid is False
    assert result.path is None
    assert "Xray-core was not found" in (result.error or "")


def test_xray_locator_invalid_custom_path(monkeypatch, tmp_path) -> None:
    missing = tmp_path / "missing-xray"
    monkeypatch.setattr(locator, "get_bundled_xray_candidates", lambda: [])
    monkeypatch.setattr(
        locator,
        "load_xray_settings",
        lambda: XraySettings(use_custom_binary=True, custom_binary_path=str(missing)),
    )
    monkeypatch.setattr(locator, "system_which", lambda _name: None)

    result = locator.find_xray_binary()

    assert result.valid is False
    assert "custom:" in (result.error or "")


def test_xray_locator_valid_custom_path(monkeypatch, tmp_path) -> None:
    fake = _fake_xray(tmp_path / "custom" / "xray")
    monkeypatch.setattr(locator, "get_bundled_xray_candidates", lambda: [])
    monkeypatch.setattr(
        locator,
        "load_xray_settings",
        lambda: XraySettings(use_custom_binary=True, custom_binary_path=str(fake)),
    )
    monkeypatch.setattr(locator, "system_which", lambda _name: None)

    result = locator.find_xray_binary()

    assert result.valid is True
    assert result.source == "user-configured"
    assert result.version == "v26.4.25"


def test_xray_locator_uses_environment_bundled_dir(monkeypatch, tmp_path) -> None:
    fake = _fake_xray(tmp_path / "appdir" / "usr" / "bin" / "xray" / "xray")
    monkeypatch.setenv("V2LINK_BUNDLED_XRAY_DIR", str(fake.parent))
    monkeypatch.setattr(locator, "load_xray_settings", lambda: XraySettings())
    monkeypatch.setattr(locator, "system_which", lambda _name: None)

    candidates = locator.get_bundled_xray_candidates()
    result = locator.find_xray_binary()

    assert candidates[0] == fake
    assert result.valid is True
    assert result.source == "bundled"
    assert result.path == str(fake)


def test_validate_xray_binary_rejects_non_executable(tmp_path) -> None:
    path = tmp_path / "xray"
    path.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    path.chmod(0o644)

    result = locator.validate_xray_binary(path)

    assert result.valid is False
    assert "not executable" in (result.error or "")


def test_xray_asset_status_reports_geo_files(tmp_path) -> None:
    fake = _fake_xray(tmp_path / "xray" / "xray")
    (tmp_path / "xray" / "geoip.dat").write_text("geoip", encoding="utf-8")
    (tmp_path / "xray" / "geosite.dat").write_text("geosite", encoding="utf-8")
    binary = locator.XrayBinary(str(fake), "bundled", "v26.4.25", True, None)

    status = locator.xray_asset_status(binary)

    assert status["geoip_found"] is True
    assert status["geosite_found"] is True
    assert status["bundled_incomplete"] is False


def test_source_candidates_do_not_include_other_architecture(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(locator, "_project_root", lambda: tmp_path)
    monkeypatch.setattr(locator.platform, "machine", lambda: "x86_64")
    monkeypatch.delenv("V2LINK_BUNDLED_XRAY_DIR", raising=False)
    monkeypatch.delenv("XRAY_LOCATION_ASSET", raising=False)

    candidates = locator.get_bundled_xray_candidates()

    assert tmp_path / "vendor" / "xray" / "x86_64" / "xray" in candidates
    assert tmp_path / "vendor" / "xray" / "aarch64" / "xray" not in candidates


def test_invalid_custom_path_falls_back_to_bundled(tmp_path, monkeypatch) -> None:
    bundled = _fake_xray(tmp_path / "bundle" / "xray")
    monkeypatch.setattr(
        locator,
        "load_xray_settings",
        lambda: XraySettings(use_custom_binary=True, custom_binary_path=str(tmp_path / "missing")),
    )
    monkeypatch.setattr(locator, "get_bundled_xray_candidates", lambda: [bundled])
    monkeypatch.setattr(locator, "system_which", lambda _name: None)

    result = locator.find_xray_binary()

    assert result.valid is True
    assert result.source == "bundled"
    assert "custom Xray path is invalid" in (result.warning or "")


def test_version_manifest_mismatch_is_rejected(tmp_path) -> None:
    fake = _fake_xray(tmp_path / "bundle" / "xray", output="Xray 26.3.27")
    (fake.parent / "VERSION").write_text("v99.0.0\n", encoding="utf-8")

    result = locator.validate_xray_binary(fake, source="bundled")

    assert result.valid is False
    assert result.version_manifest_status == "mismatch"
    assert "does not match" in (result.error or "")


def test_version_check_receives_asset_environment(tmp_path) -> None:
    marker = tmp_path / "asset-dir.txt"
    fake = tmp_path / "path with spaces" / "xray"
    fake.parent.mkdir(parents=True)
    fake.write_text(
        f"#!/bin/sh\nprintf '%s' \"$XRAY_LOCATION_ASSET\" > '{marker}'\nprintf 'Xray 26.3.27\\n'\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)

    result = locator.validate_xray_binary(fake)

    assert result.valid is True
    assert marker.read_text(encoding="utf-8") == str(fake.parent.resolve())
