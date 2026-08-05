from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_project_version_is_release_target() -> None:
    import tomllib
    from v2link_client.version import get_project_version

    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["version"] == "0.2.4"
    assert get_project_version() == data["project"]["version"]


def test_release_documentation_matches_project_version() -> None:
    import tomllib

    version = tomllib.loads(
        (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]["version"]
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    release_notes = (ROOT / "docs" / "releases" / f"v{version}.md").read_text(
        encoding="utf-8"
    )

    assert f"## [{version}] - 2026-08-05" in changelog
    assert release_notes.startswith(f"# v2link-client v{version}\n")


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


def test_pyinstaller_bundles_authoritative_version_metadata() -> None:
    script = (ROOT / "scripts" / "build_pyinstaller.sh").read_text(encoding="utf-8")

    assert '--add-data "${ROOT_DIR}/pyproject.toml:."' in script


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
    assert "sha256sum *.AppImage *.deb > SHA256SUMS" in release


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
    assert "dpkg-deb -e" in script
    assert "v2link-netmon.service" in script
    assert "DEB_HELPER" in script
    assert "postinst prerm postrm" in script
    assert "root:root" in script
    assert "systemd-analyze verify" in script
    assert "SHA256SUMS lacks current artifact" in script
    assert "AppImage application runtime version mismatch" in script
    assert "Debian application runtime version mismatch" in script


def test_debian_build_stages_complete_netmon_lifecycle() -> None:
    script = (ROOT / "scripts" / "build_deb.sh").read_text(encoding="utf-8")

    for maintainer_script in ("postinst", "prerm", "postrm"):
        assert f'"${{DEB_TEMPLATE_DIR}}/{maintainer_script}"' in script
        assert f'"${{DEBIAN_DIR}}/{maintainer_script}"' in script
    assert "dpkg-deb --build --root-owner-group" in script
    assert 'DEPENDS="adduser, init-system-helpers,' in script
    assert 'chmod 0755 "${LIB_DIR}/v2link-netmon"' in script
    assert 'chmod 0644 "${SYSTEMD_DIR}/v2link-netmon.service"' in script


def test_debian_maintainer_scripts_preserve_opt_in_lifecycle() -> None:
    postinst = (ROOT / "packaging" / "deb" / "postinst").read_text(encoding="utf-8")
    prerm = (ROOT / "packaging" / "deb" / "prerm").read_text(encoding="utf-8")
    postrm = (ROOT / "packaging" / "deb" / "postrm").read_text(encoding="utf-8")

    assert 'addgroup --system "${SERVICE_GROUP}"' in postinst
    assert "adduser --system" in postinst
    assert "--no-create-home" in postinst
    assert "--shell /usr/sbin/nologin" in postinst
    assert "existing ${SERVICE_USER} account is incompatible" in postinst
    assert 'service_uid="$(id -u "${SERVICE_USER}")"' in postinst
    assert 'getent shadow "${SERVICE_USER}"' in postinst
    assert 'deb-systemd-invoke try-restart "${SERVICE}"' in postinst
    assert '\nsystemctl enable' not in postinst
    assert '\nsystemctl start' not in postinst
    assert 'deb-systemd-invoke stop "${SERVICE}"' in prerm
    assert '[[ -d /run/systemd/system ]]' in postinst
    assert '[[ -d /run/systemd/system ]]' in prerm
    assert 'deb-systemd-helper purge "${SERVICE}"' in postrm
    assert "SERVICE_USER" not in postrm


def test_appimage_build_and_verifier_exclude_privileged_helper() -> None:
    build = (ROOT / "scripts" / "build_appimage.sh").read_text(encoding="utf-8")
    verify = (ROOT / "scripts" / "verify_release_artifacts.sh").read_text(
        encoding="utf-8"
    )

    for script in (build, verify):
        assert "v2link-netmon.service" in script
        assert "privileged v2link-netmon service assets" in script
    assert "pkexec" not in build
    assert "sudo" not in build


def test_release_workflow_runs_netmon_python_and_rust_quality_checks() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )

    assert "tests/test_netmon_client.py" in workflow
    assert "tests/test_diagnostics.py" in workflow
    assert "tests/test_build_scripts.py" in workflow
    assert "cargo fmt --manifest-path netmon/Cargo.toml --all -- --check" in workflow
    assert "cargo test --manifest-path netmon/Cargo.toml --workspace --locked" in workflow
    assert "cargo clippy --manifest-path netmon/Cargo.toml" in workflow
    assert "--workspace --all-targets --locked -- -D warnings" in workflow


def test_packaged_entrypoint_reaches_diagnostic_privacy_ui() -> None:
    main_window = (ROOT / "src/v2link_client/ui/main_window.py").read_text(encoding="utf-8")
    diagnostics = (ROOT / "src/v2link_client/ui/diagnostics_widget.py").read_text(
        encoding="utf-8"
    )
    profile_dialogs = (ROOT / "src/v2link_client/ui/profile_dialogs.py").read_text(
        encoding="utf-8"
    )
    workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

    assert "from v2link_client.ui.diagnostics_widget import DiagnosticsWidget" in main_window
    assert "from v2link_client.core.latest_error import LatestErrorStore" in main_window
    assert "from v2link_client.ui.safe_text_actions import" in diagnostics
    assert 'QPushButton("Copy latest error")' in diagnostics
    assert 'QPushButton("Save diagnostics report")' in diagnostics
    assert 'QPushButton("Copy validation error")' in profile_dialogs
    for test_name in (
        "tests/test_logging_setup.py",
        "tests/test_diagnostics_clipboard_ui.py",
        "tests/test_latest_error_ui_integration.py",
    ):
        assert test_name in workflow
