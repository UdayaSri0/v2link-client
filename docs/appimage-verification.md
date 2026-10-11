# AppImage catalog repair verification

Prepared on 2026-10-11 for review in
[draft PR #31](https://github.com/UdayaSri0/v2link-client/pull/31).
The repair was verified before preparing version 0.2.5. Main, release tags,
GitHub Releases, APT publication and upstream catalog PR #8261 were not modified.

## Confirmed root cause

The [catalog run](https://github.com/AppImage/appimage.github.io/actions/runs/36638643416)
found the bundled Qt XCB plugin but its dynamic loader could not resolve
`libxcb-icccm.so.4`. It then reported failure to initialize the XCB platform and
GUI exit within 11 seconds. This was a missing native dependency, rather than a
missing plugin file or an application requirement to run as root.

`readelf -d` confirms `libqxcb.so` and `libQt6XcbQpa.so.6` require ICCCM, cursor,
util, image, keysyms, render-util, shape, randr, render, shm, sync, xfixes, xkb and
XKB common/X11 libraries. The original build copied PyInstaller output directly
into AppDir and did not reject unresolved native dependencies. PyInstaller can
warn and continue when these libraries are absent from the build host.
The original verifier's `--version` path does not instantiate QApplication and
therefore cannot establish that the Qt platform plugin initializes.

Evidence from a local pre-repair collection:

```text
WARNING: could not resolve 'libxcb-cursor.so.0', dependency of '.../libqxcb.so'
libxcb-cursor.so.0 => not found
```

The first new CI audit also correctly stopped on a missing build-host
`libxcb-shape.so.0`; the complete build prerequisites were then declared.

## Changes and their purpose

| Files | Purpose |
|---|---|
| `scripts/prepare_appdir.py`, `tests/test_appdir_dependencies.py` | Read real DT_NEEDED entries, complete the native closure, reject missing dependencies and unsafe host libraries, audit loader resolution and glibc requirements. Tests compile real ELF fixtures and exercise both successful collection and fail-closed behavior. |
| `scripts/build_appimage.sh` | Preserve the PyInstaller/PyQt6 layout, invoke the audit, supply the static runtime explicitly, install AppStream/desktop metadata and notices, and use standard artifact names. |
| `scripts/fetch_appimage_runtime.sh`, `packaging/appimage-runtime.json`, `packaging/licenses/appimage-runtime.txt` | Pin the official runtime by immutable asset ID and SHA256, verify architecture, reject an ELF interpreter or dynamic dependencies, retain source provenance and license notice. |
| `scripts/smoke_appimage.py`, `scripts/test_appimage_clean.sh`, `packaging/appimage-smoke.Dockerfile`, `.dockerignore` | Test actual mapped XCB windows in clean Ubuntu images, require 30-second process survival, keep diagnostics, manage Xvfb readiness directly, and bound container/test timeouts. |
| `.github/workflows/ci.yml`, `.github/workflows/release.yml` | Provision native dependencies only in the builder and require clean GUI/ABI checks before accepting or uploading verified artifacts. Preserve release confirmation, default-branch controls, APT signing and publishing dependencies. |
| `scripts/build_deb.sh`, `scripts/verify_release_artifacts.sh` | Declare complete Debian XCB dependencies and the glibc 2.35 minimum; verify naming, static runtime, metadata, ELF closure and the existing Xray/helper security checks. |
| `packaging/io.github.UdayaSri0.v2link-client.metainfo.xml`, `docs/THIRD_PARTY_NOTICES.md` | Provide AppStream metadata and notices for the runtime/native support libraries. |
| `pyproject.toml`, `CHANGELOG.md`, `README.md`, `tests/test_build_scripts.py`, `tests/test_version.py`, `tests/test_latest_error.py` | Prepare consistent candidate version metadata, naming assertions, dated changelog, compatibility guidance and version examples. Historical release documentation keeps its original version/names. |
| `docs/appimage-packaging.md`, `docs/development.md`, `docs/maintainer-release.md`, `docs/releases/v0.2.5.md` | Document build prerequisites, deployment decisions, validation gates, limitations and proposed release notes. |

`build_pyinstaller.sh` and `build_release.sh` were inspected. Their Qt collection
and architecture-independent checksum generation are retained. No second Qt
deployment stack or system-directory copying was introduced. linuxdeploy was
evaluated but not added because system Qt discovery could conflict with PyQt6.

## Native dependencies and compatibility

The private payload now guarantees the required `libxcb-icccm.so.4`,
`libxcb-cursor.so.0`, `libxcb-image.so.0`, `libxcb-keysyms.so.1`,
`libxcb-render-util.so.0`, `libxcb-util.so.1`, `libxcb-xkb.so.1`,
`libxkbcommon.so.0`, `libxkbcommon-x11.so.0` and related shape/randr/shm/sync/
render/xfixes modules. The audit additionally collected
`libwayland-cursor.so.0` and `libwayland-egl.so.1` in the verified CI build.

The verified CI payload removed bundled `libX11.so.6` and `libX11-xcb.so.1`.
The collection policy also excludes glibc, the dynamic linker, core libxcb and
host graphics driver interfaces. No glibc is copied. Qt's wheel libraries and
their private PyInstaller search directory are preserved; AppRun does not add
global LD_LIBRARY_PATH or Qt plugin overrides. Some advisory AppImage blacklist
entries, including C++ and font libraries, remain private with their dependency
chain to avoid introducing a different ABI set into the PyQt6 installation.

The official runtime is statically linked with musl. Its pinned x86-64 SHA256 is
`156f4bdbde9c52d01814600013e0a273f0118dc2de98975f3c8c63427ec79074`;
source commit: `8f39b89e2ac31e1640b3d3f7e9a5108e6ce805fa`.
The existing pinned AppImageKit 12 assembler accepts it via `--runtime-file`.
This removes host libfuse2/runtime-glibc dependencies while retaining type-2
SquashFS compatibility. The application payload still needs host glibc.

The Ubuntu 22.04-built payload requires **GLIBC_2.35**. Ubuntu 22.04 / Linux
Mint 21 is the supported baseline; older distributions are outside support.
The catalog's glibc warning is advisory on that baseline. Missing ELF libraries
and failed GUI startup are release blockers. A locally built Ubuntu 24.04
development payload required GLIBC_2.38 and correctly failed the 2.35 ceiling;
it is not the candidate to distribute.

## Actual verification

The [successful repair CI run](https://github.com/UdayaSri0/v2link-client/actions/runs/38125128867)
tested commit `2b59f33451a6d3421b746182323b9310862b5b28` before candidate
version preparation. The version 0.2.5 preparation repeats these same mandatory
gates; use [PR #31 checks](https://github.com/UdayaSri0/v2link-client/pull/31/checks)
for the final candidate run and downloadable artifact set.

| Environment / check | Actual result |
|---|---|
| Ubuntu 22.04 builder | 209 ELF files audited; required native libraries resolved; maximum GLIBC_2.35. |
| Clean Ubuntu 22.04, Xvfb, UID 65534 | Visible XCB window, 30-second process survival, Qt plugin initialization and extracted ELF/Xray checks passed. |
| Clean Ubuntu 24.04, Xvfb, UID 65534 | The same Ubuntu 22.04-built AppImage passed the same checks. |
| Clean fixture integrity | ICCCM, cursor, image, keysyms, render-util, util and XKB-X11 utility packages explicitly absent. Only normal display/graphics/font dependencies and test tooling were installed. |
| GUI privilege/isolation | All capabilities dropped, no new privileges and no container network; GUI remained unprivileged. |
| Full Python suite | 331 passed, 1 skipped. The skipped legacy check requires a separately installed system Xray. |
| Bundled Xray TLS integration | 3 passed; generated legacy/pin/name TLS configurations accepted by bundled Xray v26.3.27. |
| Rust workspace | 9 unit tests passed; formatting and Clippy with warnings denied passed. |
| Packaging/security | ShellCheck, shell syntax, AppImage/Debian extraction, exact names/checksums, bundled Xray identity/configuration, Debian modes/ownership, service verification and privileged-helper exclusion passed. |
| Local Ubuntu 24.04 development build | Real XCB window and 30-second survival passed, 152 ELF files audited. The final smoke harness was also exercised locally. |

Clean GUI logs included:

```text
Starting AppImage smoke test as UID 65534: /artifacts/app.AppImage
Extracted ELF dependency audit passed
PASS: visible XCB window; process survived 30s; bundled Xray and ELF audit passed
```

Qt diagnostics use `QT_DEBUG_PLUGINS=1`. The smoke test requires a successful
`libqxcb.so` load, rejects plugin/shared-library errors, and retains the mapped
window tree and Xvfb logs. An early `xvfb-run` harness stall was replaced by
directly managed Xvfb with bounded readiness; the resulting isolated tests
passed. No dependency test or security test was bypassed.

## Limitations and catalog readiness

- Clean tests exercise XCB through extraction-and-run. Direct kernel FUSE
  mounting, native Wayland and physical GPU/display integration were not tested.
- Live provider/VPN connectivity was not exercised without provider credentials.
  Existing profile/connection logic is unchanged; its Python tests and bundled
  Xray configuration integration passed.
- Some blacklist suggestions remain advisory. AppStream XML/package structure
  was checked; a full external AppStream lint run was not performed locally.
- The local sandbox denies Unix sockets/chroot/ptrace and initially produced a
  Unix-socket test failure plus inconsistent process-ID checks. GitHub's full
  suite passed in its normal runner. Graphify query/update was attempted but the
  graphify command is unavailable in this workspace.
- Official ARM64 artifacts still await native CI, as before.

The repaired build is suitable for candidate verification and catalog retesting
after approved publication. Retesting the catalog while its URL still resolves
to the public v0.2.4 asset would test the old broken artifact. Publishing,
tagging, merging, editing the upstream catalog PR and issuing `/retest` remain
separate approval steps.

## Suggested commit

```text
fix(packaging): make AppImages launch with bundled Qt/XCB dependencies

Complete and audit the native ELF dependency closure, pin a verified static
type-2 runtime, and add AppStream metadata. Require real XCB GUI smoke tests on
clean Ubuntu 22.04 and 24.04 before release artifacts are accepted. Prepare the
verified v0.2.5 candidate with standard names while preserving Debian/APT
signing, TLS and helper security controls.
```

Proposed release notes: [v0.2.5](releases/v0.2.5.md).
Candidate names are `v2link-client-0.2.5-x86_64.AppImage`,
`v2link-client_0.2.5_amd64.deb` and `SHA256SUMS`.
