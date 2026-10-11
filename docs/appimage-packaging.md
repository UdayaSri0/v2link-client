# AppImage packaging and validation

Build official artifacts on Ubuntu 22.04. The supported payload baseline is
glibc 2.35 (Ubuntu 22.04 / Linux Mint 21); a static runtime does not remove the
Python/Qt payload's glibc requirements. Older distributions are not supported.
Ubuntu 24.04 is also a required clean GUI test target. Builds made on newer
systems are development artifacts until the ELF baseline check passes.

Install native dependencies in the **build environment**, before PyInstaller:

```sh
sudo apt install binutils libgl1 libegl1 libdbus-1-3 libxkbcommon-x11-0 \
  libxcb-cursor0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 \
  libxcb-render-util0 libxcb-xkb1 libwayland-cursor0 libwayland-egl1
```

`prepare_appdir.py` reads every ELF object's DT_NEEDED entries, completes the
native dependency closure from the build host, then runs a loader audit.
Missing build dependencies are errors, rather than PyInstaller warnings that
silently produce an incomplete release. Qt comes only from the PyQt6 wheel;
the script refuses to fill a missing Qt library from the system Qt installation.
The PyInstaller bootloader supplies its private `_internal` loader directory.
AppRun does not set global Qt/loader paths. Build-only extracted sysroots may
be supplied with `V2LINK_NATIVE_LIBRARY_DIRS` (colon-separated directories).

glibc, the dynamic linker, graphics driver libraries, and core X11/XCB driver
interfaces remain on the host. Qt's XCB utility libraries are private. Some
AppImage excludelist suggestions remain intentionally bundled (libstdc++, font
rendering and related dependencies) to meet Qt's ABI requirements. Those lint
warnings are advisory; unresolved ELF libraries, incompatible symbol versions,
missing metadata and failed GUI startup block verification. No system library
directory is copied wholesale.

The existing checksum-pinned AppImageKit 12 tool is used solely to assemble
SquashFS. `fetch_appimage_runtime.sh` fetches the official musl-static type-2
runtime by immutable GitHub asset ID, checks a pinned SHA256, verifies its
architecture and rejects PT_INTERP/DT_NEEDED. Provenance is recorded in
`packaging/appimage-runtime.json`. Tool overrides still receive this explicitly
verified runtime via `--runtime-file`. No moving runtime download is accepted.
The runtime removes the dependency on host libfuse2 and host glibc for the
runtime itself. Normal mounting still needs kernel FUSE access; on systems
without it use `APPIMAGE_EXTRACT_AND_RUN=1 ./v2link-client-*.AppImage`.

AppStream metadata is installed under `usr/share/metainfo`, with the desktop
entry both at AppDir root and under `usr/share/applications`. Debian dependency
declarations also include the XCB utilities. Debian/APT signing and the optional
netmon helper's opt-in service lifecycle remain unchanged.

After building:

```sh
python3 scripts/prepare_appdir.py build/AppDir --check --max-glibc 2.35
./scripts/verify_release_artifacts.sh
./scripts/test_appimage_clean.sh dist/v2link-client-<version>-x86_64.AppImage
```

The clean Docker tests install only display/test tooling and normal desktop
graphics/font dependencies, explicitly check that the missing XCB utility
packages are absent, then run as UID 65534 with all capabilities removed and no
network. Xvfb plus `QT_QPA_PLATFORM=xcb` and `QT_DEBUG_PLUGINS=1` must show a
mapped application window and a GUI process alive after 30 seconds. The test
also audits all extracted ELF objects and tests the bundled Xray configuration.
Logs are retained under `build/smoke-22.04` and `build/smoke-24.04`. Both CI and
release workflows require these checks before uploading verified artifacts.

linuxdeploy/its Qt plugin is not used: adding a second Qt discovery/deployment
pass would risk mixing system Qt with PyQt6. The existing PyInstaller layout
plus dependency closure and clean GUI tests addresses the demonstrated defect.
For future changes, evaluate linuxdeploy only if it can consume the exact wheel
Qt tree and preserve the same audits and private loader behavior.

GUI startup does not establish VPN server reachability. The Python profile,
connection, TLS, logging and security tests plus Rust tests remain mandatory;
clean GUI checks supplement rather than replace them. Native Wayland and direct
FUSE mounting require separate desktop checks if unavailable in the test host.
