from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_project_version_is_release_target() -> None:
    import tomllib

    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["version"] == "0.2.2"


def test_fetch_xray_script_pins_official_release_and_sha() -> None:
    import json

    script = (ROOT / "scripts" / "fetch_xray_core.sh").read_text(encoding="utf-8")
    manifest = json.loads(
        (ROOT / "packaging" / "xray-release.json").read_text(encoding="utf-8")
    )
    assert "https://github.com/XTLS/Xray-core/releases/download" in script
    assert manifest["version"] == "v26.3.27"
    assert len(manifest["assets"]["x86_64"]["sha256"]) == 64
    assert len(manifest["assets"]["aarch64"]["sha256"]) == 64
    assert "sha256sum -c -" in script
    assert "--verify-existing" in script
    assert "--retry-all-errors" in script
    assert "verify_directory" in script


def test_build_scripts_contain_xray_copy_checks() -> None:
    appimage = (ROOT / "scripts" / "build_appimage.sh").read_text(encoding="utf-8")
    deb = (ROOT / "scripts" / "build_deb.sh").read_text(encoding="utf-8")
    release = (ROOT / "scripts" / "build_release.sh").read_text(encoding="utf-8")

    assert "scripts/fetch_xray_core.sh" in appimage
    assert "APPDIR}/usr/bin/xray/xray" in appimage
    assert "V2LINK_BUNDLED_XRAY_DIR" in appimage
    assert "XRAY_LOCATION_ASSET" in appimage

    assert "scripts/fetch_xray_core.sh" in deb
    assert "OPT_DIR}/xray/xray" in deb
    assert "geoip.dat" in deb
    assert "geosite.dat" in deb

    assert "scripts/fetch_xray_core.sh" in release
    assert "build_netmon.sh" in release
    assert "AppImage layout missing bundled Xray" in release
    assert ".deb layout missing bundled Xray" in release
    assert "verify_release_artifacts.sh" in release


def test_runtime_diagnostic_script_is_private_and_read_only() -> None:
    script_path = ROOT / "scripts" / "diagnose_runtime_performance.sh"
    script = script_path.read_text(encoding="utf-8")

    assert script_path.stat().st_mode & 0o111
    assert "sqlite3 -readonly" in script
    assert "command arguments" in script
    assert "kill " not in script
    assert "systemctl stop" not in script


def test_build_scripts_use_release_artifact_naming() -> None:
    appimage = (ROOT / "scripts" / "build_appimage.sh").read_text(encoding="utf-8")
    deb = (ROOT / "scripts" / "build_deb.sh").read_text(encoding="utf-8")
    release = (ROOT / "scripts" / "build_release.sh").read_text(encoding="utf-8")

    assert '${APP_NAME}-${VERSION_NAME}-linux-${ARCH_NAME}.AppImage' in appimage
    assert '${APP_NAME}_${VERSION_NAME}_${ARCH_NAME}.deb' in deb
    assert "sha256sum ./*.AppImage ./*.deb > SHA256SUMS" in release


def test_appimagetool_is_versioned_and_checksum_verified() -> None:
    script = (ROOT / "scripts" / "build_appimage.sh").read_text(encoding="utf-8")
    assert "releases/download/continuous" not in script
    assert "APPIMAGETOOL_VERSION=" in script
    assert "APPIMAGETOOL_SHA256_X86_64=" in script
    assert "sha256sum -c -" in script


def test_release_verifier_inspects_extracted_artifacts() -> None:
    script = (ROOT / "scripts" / "verify_release_artifacts.sh").read_text(encoding="utf-8")
    assert "--appimage-extract" in script
    assert "dpkg-deb -x" in script
    assert "run -test" in script
    assert "THIRD_PARTY_NOTICES.md" in script
