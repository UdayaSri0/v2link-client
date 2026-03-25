from __future__ import annotations

from v2link_client.core.system_subprocess import build_host_subprocess_env


def test_build_host_subprocess_env_strips_packaged_runtime_vars() -> None:
    base_env = {
        "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
        "DISPLAY": ":1",
        "GIO_MODULE_DIR": "/tmp/bundle/gio",
        "GI_TYPELIB_PATH": "/tmp/bundle/gi",
        "GTK_PATH": "/tmp/bundle/gtk",
        "HOME": "/tmp/home",
        "LD_LIBRARY_PATH": "/tmp/bundle/lib",
        "LD_LIBRARY_PATH_ORIG": "/usr/lib/x86_64-linux-gnu",
        "PATH": "/tmp/bundle/bin:/custom/bin",
        "PYINSTALLER_SUPPRESS_SPLASH_SCREEN": "1",
        "PYTHONHOME": "/tmp/bundle/python",
        "PYTHONPATH": "/tmp/bundle/site-packages",
        "QT_PLUGIN_PATH": "/tmp/bundle/qt",
        "WAYLAND_DISPLAY": "wayland-0",
        "XDG_RUNTIME_DIR": "/run/user/1000",
    }

    env, info = build_host_subprocess_env(base_env)

    assert env["DISPLAY"] == ":1"
    assert env["DBUS_SESSION_BUS_ADDRESS"] == "unix:path=/run/user/1000/bus"
    assert env["WAYLAND_DISPLAY"] == "wayland-0"
    assert env["XDG_RUNTIME_DIR"] == "/run/user/1000"
    assert env["HOME"] == "/tmp/home"
    assert env["LD_LIBRARY_PATH"] == "/usr/lib/x86_64-linux-gnu"
    assert env["PATH"].split(":")[:2] == ["/tmp/bundle/bin", "/custom/bin"]

    for key in (
        "GIO_MODULE_DIR",
        "GI_TYPELIB_PATH",
        "GTK_PATH",
        "PYTHONHOME",
        "PYTHONPATH",
        "PYINSTALLER_SUPPRESS_SPLASH_SCREEN",
        "QT_PLUGIN_PATH",
    ):
        assert key not in env

    assert "GIO_MODULE_DIR" in info.removed_keys
    assert "LD_LIBRARY_PATH" in info.removed_keys
    assert "PYINSTALLER_SUPPRESS_SPLASH_SCREEN" in info.removed_keys
