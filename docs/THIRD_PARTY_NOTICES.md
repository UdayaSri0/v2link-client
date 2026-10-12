# Third-Party Notices

## Xray-core

v2link-client official Linux release artifacts bundle Xray-core for normal proxy operation.

- Project: https://github.com/XTLS/Xray-core
- Bundled version: v26.3.27 (canonical record: `packaging/xray-release.json`)
- License: included in packaged output at `xray/LICENSE`

This notice does not replace the bundled Xray-core license file and does not change the v2link-client license.

## AppImage runtime and native Qt support libraries

The AppImage embeds the official static type-2 runtime from
https://github.com/AppImage/type2-runtime. Its exact source commit and binary
checksums are recorded in `packaging/appimage-runtime.json`. The upstream license
and embedded-library notice are included at
`usr/share/doc/v2link-client/appimage-runtime.txt` in the AppImage.

Qt/PyQt6 remain the versions installed from the Python requirements. Required
XCB utilities, XKB support, and Wayland support libraries are collected from the
build distribution by ELF dependency, rather than from another Qt installation.
Available Ubuntu copyright notices for these packages are included under
`usr/share/doc/v2link-client/native-licenses/` in the AppImage; Ubuntu package
sources are available from https://archive.ubuntu.com/ubuntu/pool/.
