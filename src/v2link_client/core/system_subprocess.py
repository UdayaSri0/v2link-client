"""Helpers for launching host-system subprocesses from packaged builds."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import sys
from typing import Mapping


HOST_SUBPROCESS_ENV_MODE = "clean-host"
STANDARD_SYSTEM_PATHS: tuple[str, ...] = (
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
)
SANITIZED_ENV_KEYS: tuple[str, ...] = (
    "GDK_PIXBUF_MODULEDIR",
    "GDK_PIXBUF_MODULE_FILE",
    "GIO_EXTRA_MODULES",
    "GIO_MODULE_DIR",
    "GI_TYPELIB_PATH",
    "GSETTINGS_SCHEMA_DIR",
    "GST_PLUGIN_PATH",
    "GST_PLUGIN_PATH_1_0",
    "GST_PLUGIN_SYSTEM_PATH",
    "GST_REGISTRY",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "PYTHONHOME",
    "PYTHONNOUSERSITE",
    "PYTHONPATH",
    "PYTHONSAFEPATH",
    "PYTHONUSERBASE",
    "GTK_DATA_PREFIX",
    "GTK_EXE_PREFIX",
    "GTK_PATH",
    "QML2_IMPORT_PATH",
    "QML_IMPORT_PATH",
    "QT_PLUGIN_PATH",
    "QT_QPA_PLATFORM_PLUGIN_PATH",
)
SANITIZED_ENV_PREFIXES: tuple[str, ...] = ("PYINSTALLER_", "_PYI", "_MEIPASS")
_DEB_INSTALL_PREFIX = "/opt/v2link-client/"


@dataclass(frozen=True, slots=True)
class HostSubprocessEnvInfo:
    mode: str
    runtime_kind: str
    executable_path: str
    removed_keys: tuple[str, ...]


def _looks_like_packaged_runtime() -> bool:
    return bool(getattr(sys, "frozen", False) or getattr(sys, "_MEIPASS", None))


def detect_runtime_kind() -> str:
    executable = str(Path(sys.executable).resolve())
    if not _looks_like_packaged_runtime():
        return "source"
    if os.getenv("APPIMAGE") or executable.endswith(".AppImage") or ".AppImage/" in executable:
        return "appimage"
    if executable.startswith(_DEB_INSTALL_PREFIX):
        return "deb"
    return "pyinstaller"


def _normalize_path(path_value: str) -> str:
    ordered: list[str] = []
    for candidate in [*path_value.split(os.pathsep), *STANDARD_SYSTEM_PATHS]:
        item = candidate.strip()
        if not item or item in ordered:
            continue
        ordered.append(item)
    return os.pathsep.join(ordered)


def _should_strip_env_var(name: str) -> bool:
    if name in SANITIZED_ENV_KEYS:
        return True
    return any(name.startswith(prefix) for prefix in SANITIZED_ENV_PREFIXES)


def build_host_subprocess_env(
    base_env: Mapping[str, str] | None = None,
) -> tuple[dict[str, str], HostSubprocessEnvInfo]:
    source_env = os.environ if base_env is None else base_env
    env = {str(key): str(value) for key, value in source_env.items()}

    removed_keys: list[str] = []
    original_ld_library_path = env.get("LD_LIBRARY_PATH_ORIG")
    for key in list(env):
        if not _should_strip_env_var(key):
            continue
        removed_keys.append(key)
        env.pop(key, None)

    if original_ld_library_path is not None:
        if original_ld_library_path.strip():
            env["LD_LIBRARY_PATH"] = original_ld_library_path.strip()
        else:
            env.pop("LD_LIBRARY_PATH", None)

    env["PATH"] = _normalize_path(env.get("PATH", ""))
    env.setdefault("HOME", str(Path.home()))

    info = HostSubprocessEnvInfo(
        mode=HOST_SUBPROCESS_ENV_MODE,
        runtime_kind=detect_runtime_kind(),
        executable_path=str(Path(sys.executable).resolve()),
        removed_keys=tuple(sorted(set(removed_keys))),
    )
    return env, info


def get_host_subprocess_env_info(base_env: Mapping[str, str] | None = None) -> HostSubprocessEnvInfo:
    _, info = build_host_subprocess_env(base_env=base_env)
    return info


def system_which(binary_name: str, *, base_env: Mapping[str, str] | None = None) -> str | None:
    env, _info = build_host_subprocess_env(base_env=base_env)
    return shutil.which(binary_name, path=env.get("PATH"))
