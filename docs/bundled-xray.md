# Bundled Xray-core

Official v2link-client AppImage, `.deb`, and APT releases include Xray-core so users can install and run the app in one go. A separate system `xray` install is only a fallback or an advanced custom choice.

## Resolution Order

v2link-client resolves Xray-core in this order:

1. Custom Xray path configured in **Xray Settings**, if valid.
2. Bundled Xray inside the installed application.
3. System `xray` from `PATH`.

If none is usable, the GUI reports:

```text
Xray-core was not found. This build may be incomplete. Please install the official v2link-client AppImage/.deb package, or configure a custom Xray path.
```

## Installed Locations

AppImage layout:

```text
AppDir/usr/bin/xray/xray
AppDir/usr/bin/xray/geoip.dat
AppDir/usr/bin/xray/geosite.dat
AppDir/usr/bin/xray/LICENSE
AppDir/usr/bin/xray/VERSION
```

Debian/APT layout:

```text
/opt/v2link-client/xray/xray
/opt/v2link-client/xray/geoip.dat
/opt/v2link-client/xray/geosite.dat
/opt/v2link-client/xray/LICENSE
/opt/v2link-client/xray/VERSION
```

Source/development vendor layout:

```text
vendor/xray/x86_64/xray
vendor/xray/aarch64/xray
```

## Custom Xray Path

Use **Xray Settings** in the app to choose a custom binary. The app validates the file by running:

```bash
xray version
```

The setting is stored at:

```text
$XDG_CONFIG_HOME/v2link-client/xray_settings.json
```

Use **Reset to bundled/default** to return to the bundled binary first, then system `PATH` fallback.

## Verify Version

The active Xray source, path, version, and geo asset status are shown in **Diagnostics** and **About**.

Package-level checks:

```bash
/opt/v2link-client/xray/xray version
squashfs-root/usr/bin/xray/xray version
```

## Maintainer Update Flow

Xray is fetched from official Xray-core GitHub Releases only:

```text
https://github.com/XTLS/Xray-core/releases
```

To update the pinned release:

1. Edit `packaging/xray-release.json`.
2. Set the pinned stable `version`.
3. Set the official archive filename and SHA-256 for each architecture.
4. Run `./scripts/fetch_xray_core.sh` on each release architecture or with `ARCH=x86_64` / `ARCH=aarch64`.
5. Run `./scripts/build_release.sh`.

The fetch script fails if checksums are placeholders or if the archive structure no longer contains `xray`, `geoip.dat`, `geosite.dat`, and `LICENSE`.

Official v0.2.2 binary artifacts target x86-64. The aarch64 mapping and runtime
discovery remain available for source development, but ARM64 packages must not be
published until they are built and verified in native ARM64 CI.

## Licensing

Xray-core is a third-party project. v2link-client bundles the Xray-core license file inside release artifacts and records attribution in `docs/THIRD_PARTY_NOTICES.md`.

## Traffic Monitor Helper

Bundled Xray is enough for proxy/profile traffic tracking through Xray's Stats API. Per-application tracking still requires the optional `v2link-netmon` helper service.

AppImage cannot safely install or enable a systemd service automatically. Debian/APT packages install the helper and service file, but users opt in explicitly:

```bash
sudo systemctl enable --now v2link-netmon
```
