"""Exercise real ELF dependency closure and fail-closed packaging."""
import importlib.util
from pathlib import Path
import shutil
import subprocess

import pytest


spec = importlib.util.spec_from_file_location(
    "prepare_appdir", Path(__file__).resolve().parents[1] / "scripts/prepare_appdir.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


@pytest.fixture
def payload(tmp_path, monkeypatch):
    if not all(shutil.which(tool) for tool in ("gcc", "readelf", "ldd", "ldconfig")):
        pytest.skip("ELF toolchain required")
    native = tmp_path / "native"
    native.mkdir()
    (native / "dep.c").write_text("int test_dependency(void) { return 42; }")
    subprocess.run(["gcc", "-shared", "-fPIC", "-Wl,-soname,libtestdep.so.1",
                    str(native / "dep.c"), "-o", str(native / "libtestdep.so.1")], check=True)
    root = tmp_path / "AppDir"
    internal = root / "usr/bin/_internal"
    plugin = internal / "PyQt6/Qt6/plugins/platforms/libqxcb.so"
    plugin.parent.mkdir(parents=True)
    (native / "plugin.c").write_text("extern int test_dependency(void); int plugin(void) { return test_dependency(); }")
    subprocess.run(["gcc", "-shared", "-fPIC", str(native / "plugin.c"),
                    "-L" + str(native), "-l:libtestdep.so.1", "-o", str(plugin)], check=True)
    monkeypatch.setenv("V2LINK_NATIVE_LIBRARY_DIRS", str(native))
    return root, internal, native


def test_copies_needed_library_and_audits_real_loader(payload):
    root, internal, _ = payload
    module.prepare(root)
    assert (internal / "libtestdep.so.1").is_file()
    module.prepare(root, check=True)


def test_missing_build_dependency_blocks_packaging(payload):
    root, _, native = payload
    (native / "libtestdep.so.1").unlink()
    with pytest.raises(RuntimeError, match="requires missing libtestdep.so.1"):
        module.prepare(root)


def test_audit_does_not_accept_dependency_only_on_build_host(payload):
    root, _, _ = payload
    with pytest.raises(RuntimeError, match="unbundled native dependency"):
        module.prepare(root, check=True)


def test_host_libraries_removed_and_check_refuses_them(payload):
    root, internal, _ = payload
    (internal / "libc.so.6").write_bytes(b"do not bundle glibc")
    with pytest.raises(RuntimeError, match="unsafe bundled host library"):
        module.prepare(root, check=True)
    module.prepare(root)
    assert not (internal / "libc.so.6").exists()


def test_xcb_utilities_are_private_but_glibc_and_drivers_are_host():
    for name in ("libxcb-icccm.so.4", "libxcb-cursor.so.0", "libxcb-image.so.0",
                 "libxcb-keysyms.so.1", "libxcb-render-util.so.0", "libxcb-xkb.so.1",
                 "libxkbcommon-x11.so.0"):
        assert not module.host_library(name)
    for name in ("libc.so.6", "ld-linux-x86-64.so.2", "libGL.so.1", "libEGL.so.1"):
        assert module.host_library(name)
