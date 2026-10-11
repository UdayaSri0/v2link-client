#!/usr/bin/env python3
"""Complete/audit trusted PyInstaller ELF payloads without a second Qt install.

Only DT_NEEDED libraries are copied, by SONAME, from the build environment.
PyInstaller already puts _internal on its process-local loader path. Qt's own
RUNPATH is retained. Nothing is added to the user's global environment.
"""
from __future__ import annotations

import argparse
import fnmatch
import os
from pathlib import Path
import re
import shutil
import subprocess

# Host ABI/driver libraries: never copy these into the application. Remaining
# AppImage excludelist suggestions are advisory; e.g. libstdc++ is intentionally
# private because Qt wheels may need a newer GLIBCXX than the host provides.
HOST_LIBRARIES = (
    "ld-linux*", "libc.so.*", "libm.so.*", "libmvec.so.*", "libdl.so.*",
    "libpthread.so.*", "librt.so.*", "libresolv.so.*", "libutil.so.*",
    "libanl.so.*", "libBrokenLocale.so.*", "libnss_*.so.*", "libthread_db.so.*",
    "libGL.so.*", "libEGL.so.*", "libGLX.so.*", "libGLdispatch.so.*",
    "libOpenGL.so.*", "libglapi.so.*", "libdrm*.so.*", "libgbm.so.*",
    "libvulkan.so.*", "libX11.so.*", "libX11-xcb.so.*", "libxcb.so.*",
    "libxcb-dri*.so.*", "libwayland-client.so.*",
)


def host_library(name: str) -> bool:
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in HOST_LIBRARIES)


def elf_files(root: Path) -> list[Path]:
    result = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            with path.open("rb") as stream:
                if stream.read(4) == b"\x7fELF":
                    result.append(path)
    return result


def needed(path: Path) -> list[str]:
    output = subprocess.check_output(["readelf", "-d", str(path)], text=True)
    return re.findall(r"\(NEEDED\).*\[([^]]+)\]", output)


def system_libraries() -> dict[str, Path]:
    result = {}
    output = subprocess.check_output(["ldconfig", "-p"], text=True)
    for name, path in re.findall(r"^\s*(\S+)\s+\([^\n]+\) => (\S+)$", output, re.M):
        result.setdefault(name, Path(path))
    # Explicit build-only search directories support extracted sysroots. They
    # never become application runtime environment variables.
    for directory in reversed(os.environ.get("V2LINK_NATIVE_LIBRARY_DIRS", "").split(os.pathsep)):
        if directory:
            for path in Path(directory).glob("*.so*"):
                result[path.name] = path
    return result


def prepare(root: Path, check: bool = False, max_glibc: str | None = None) -> None:
    internal = root / "usr/bin/_internal"
    if not internal.is_dir():
        raise RuntimeError(f"missing PyInstaller library directory: {internal}")
    plugin = internal / "PyQt6/Qt6/plugins/platforms/libqxcb.so"
    if not plugin.is_file():
        raise RuntimeError("missing Qt XCB platform plugin")
    removed = []
    for path in sorted(internal.rglob("*")):
        if (path.is_file() or path.is_symlink()) and host_library(path.name):
            if check:
                raise RuntimeError(f"unsafe bundled host library: {path}")
            path.unlink()
            removed.append(path.name)
    system = system_libraries()
    queue = elf_files(root)
    bundled = {p.name: p for p in internal.rglob("*") if p.is_file()}
    seen: set[Path] = set()
    added = []
    while queue:
        path = queue.pop()
        if path.resolve() in seen:
            continue
        seen.add(path.resolve())
        for name in needed(path):
            if host_library(name):
                continue
            if name in bundled:
                continue
            source = system.get(name)
            if source is None or not source.is_file():
                raise RuntimeError(f"{path.relative_to(root)} requires missing {name}; install it in the BUILD environment")
            if check:
                raise RuntimeError(f"unbundled native dependency: {name} required by {path.relative_to(root)}")
            if name.startswith("libQt"):
                raise RuntimeError(f"refusing to mix system Qt with PyQt6: {name}")
            target = internal / name
            shutil.copy2(source.resolve(), target)
            bundled[name] = target
            queue.append(target)
            added.append(name)
    # ldd checks the actual loader resolution, including symbol versions and
    # required host libraries. Only run it on our trusted, locally built files.
    env = dict(os.environ, LD_LIBRARY_PATH=str(internal), LC_ALL="C")
    errors = []
    glibc_versions = []
    for path in elf_files(root):
        versions = subprocess.check_output(["readelf", "--version-info", str(path)], text=True)
        glibc_versions += re.findall(r"Name: GLIBC_(\d+\.\d+(?:\.\d+)?)", versions)
        proc = subprocess.run(["ldd", str(path)], env=env, text=True, capture_output=True)
        output = proc.stdout + proc.stderr
        if "not found" in output:
            errors.append(f"{path.relative_to(root)}:\n{output}")
    if errors:
        raise RuntimeError("unresolved ELF dependencies:\n" + "\n".join(errors))
    maximum = max(glibc_versions, key=lambda v: tuple(map(int, v.split("."))), default="0.0")
    print("Removed host ABI/driver libraries:", ", ".join(sorted(set(removed))) or "none")
    print("Added DT_NEEDED libraries:", ", ".join(sorted(added)) or "none")
    print(f"Payload requires GLIBC_{maximum}; static AppImage runtime is independent")
    if max_glibc and tuple(map(int, maximum.split("."))) > tuple(map(int, max_glibc.split("."))):
        raise RuntimeError(f"payload GLIBC_{maximum} exceeds supported baseline GLIBC_{max_glibc}; build on Ubuntu 22.04")
    print(f"Verified {len(seen)} ELF files; Qt XCB dependencies resolved")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("appdir", type=Path)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--max-glibc")
    args = parser.parse_args()
    try:
        prepare(args.appdir.resolve(), args.check, args.max_glibc)
    except (RuntimeError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"Error: {exc}\n")
