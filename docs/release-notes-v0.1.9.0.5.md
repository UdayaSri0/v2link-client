# v2link-client v0.1.9.0.5

This release focuses on packaged Linux runtime reliability, especially for Debian-installed builds where proxy and system-integration commands needed a cleaner host environment.

## Highlights

- Fixed Debian-installed runs where packaged proxy/VPN traffic handling could fail because child processes inherited bundled runtime library/plugin paths.
- Added a clean host subprocess path for system tools such as `gsettings` and `xray`.
- Expanded diagnostics to make packaged-runtime troubleshooting much easier.
- Updated the shipped application icon so source runs, AppImage builds, and Debian packages use the same artwork.

## What's New

- Packaged builds now launch host-system commands with a sanitized native environment instead of forwarding PyInstaller runtime paths into child processes.
- Diagnostics now report runtime packaging mode, executable path, clean-host subprocess mode, `gsettings` command details, and proxied HTTP/HTTPS probe results.
- Runtime packaging now bundles and applies the provided application icon consistently across launchers and windows.

## Packaging

- AppImage artifact: `v2link-client-0.1.9.0.5-linux-<x86_64|aarch64>.AppImage`
- Debian artifact: `v2link-client_0.1.9.0.5_<amd64|arm64>.deb`
- Checksums: `SHA256SUMS`

## Fixes

- Fixed Debian-installed runs so system-proxy snapshot create/restore and GNOME proxy application behave more like source-run execution.
- Fixed Xray validation, startup, and traffic-stat commands to use the same clean host subprocess environment as other system integration calls.
- Replaced the placeholder package icon with the provided application artwork.

## Notes

- Canonical project version source remains `pyproject.toml`, and packaging scripts now propagate the same version metadata through release artifacts and runtime reporting.
- The GitHub release workflow still fails early if the pushed tag version does not match `pyproject.toml`.

## Full Changelog

See `CHANGELOG.md` for the detailed project history.
