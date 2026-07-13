from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_project_version_is_release_target() -> None:
    import tomllib

    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["version"] == "0.2.0"


def test_fetch_xray_script_pins_official_release_and_sha() -> None:
    script = (ROOT / "scripts" / "fetch_xray_core.sh").read_text(encoding="utf-8")
    assert "https://github.com/XTLS/Xray-core/releases/download" in script
    assert "XRAY_VERSION=\"v26.3.27\"" in script
    assert "XRAY_SHA256_X86_64=\"23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae\"" in script
    assert "XRAY_SHA256_AARCH64=\"4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c\"" in script
    assert "sha256sum -c -" in script


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
