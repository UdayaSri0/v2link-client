"""Manage core process lifecycle.

The UI intentionally keeps policy decisions simple:
- Build a core config file (currently Xray JSON)
- Validate it using `xray run -test`
- Start/stop the process and surface logs to the user
"""

from __future__ import annotations

from dataclasses import dataclass
import errno
import logging
from pathlib import Path
import socket
import subprocess
from typing import IO

from v2link_client.core.errors import (
    BinaryMissingError,
    ConfigBuildError,
    PermissionDeniedError,
    PortInUseError,
)
from v2link_client.core.storage import get_logs_dir
from v2link_client.core.system_subprocess import build_host_subprocess_env, system_which

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class CoreBinary:
    name: str
    path: str


def find_xray_binary() -> CoreBinary:
    path = system_which("xray")
    if not path:
        raise BinaryMissingError(
            "xray not found in PATH",
            user_message="Xray-core binary not found. Install `xray` or add it to PATH.",
        )
    return CoreBinary(name="xray", path=path)


def ensure_port_available(host: str, port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError as exc:
            if exc.errno in {errno.EADDRINUSE, 48}:  # 48 is macOS EADDRINUSE
                raise PortInUseError(
                    f"Port {port} in use on {host}",
                    user_message=f"Port {port} is already in use on {host}.",
                ) from exc
            if exc.errno == errno.EACCES:
                raise PermissionDeniedError(
                    f"Permission denied binding {host}:{port}",
                    user_message=f"Permission denied binding {host}:{port}.",
                ) from exc
            raise


def find_free_port(host: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


def validate_xray_config(xray: CoreBinary, config_path: Path, *, timeout_s: float = 5) -> None:
    cmd = [xray.path, "run", "-test", "-c", str(config_path)]
    env, env_info = build_host_subprocess_env()
    logger.info(
        "Validating xray config: %s [env_mode=%s removed_env=%s]",
        cmd,
        env_info.mode,
        ",".join(env_info.removed_keys) or "none",
    )
    try:
        result = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            env=env,
        )
    except FileNotFoundError as exc:
        raise BinaryMissingError(
            f"{xray.name} binary missing: {xray.path}",
            user_message=f"{xray.name} binary not found: {xray.path}",
        ) from exc
    except PermissionError as exc:
        raise PermissionDeniedError(
            f"{xray.name} not executable: {xray.path}",
            user_message=f"{xray.name} binary is not executable: {xray.path}",
        ) from exc

    if result.returncode == 0:
        return

    stderr = (result.stderr or "").strip()
    stdout = (result.stdout or "").strip()
    detail = stderr or stdout or f"exit code {result.returncode}"

    raise ConfigBuildError(
        f"xray config validation failed: {detail}",
        user_message=f"Xray rejected the config: {detail}",
    )


class XrayProcessManager:
    def __init__(self, xray: CoreBinary | None = None) -> None:
        self._xray: CoreBinary | None = xray
        self._proc: subprocess.Popen[bytes] | None = None
        self._stdout_handle: IO[str] | None = None
        self._stdout_path: Path | None = None

    def _ensure_binary(self) -> CoreBinary:
        if self._xray is None:
            self._xray = find_xray_binary()
        return self._xray

    @property
    def binary(self) -> CoreBinary:
        return self._ensure_binary()

    @property
    def stdout_path(self) -> Path | None:
        return self._stdout_path

    @property
    def binary_path(self) -> str | None:
        if self._xray is None:
            return None
        return self._xray.path

    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def returncode(self) -> int | None:
        if self._proc is None:
            return None
        return self._proc.poll()

    def start(self, config_path: Path) -> None:
        if self.is_running():
            return

        xray = self._ensure_binary()
        logs_dir = get_logs_dir()
        logs_dir.mkdir(parents=True, exist_ok=True)
        self._stdout_path = logs_dir / "xray_stdout.log"
        self._stdout_handle = self._stdout_path.open("a", encoding="utf-8")

        cmd = [xray.path, "run", "-c", str(config_path)]
        env, env_info = build_host_subprocess_env()
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=self._stdout_handle,
                stderr=subprocess.STDOUT,
                env=env,
            )
        except FileNotFoundError as exc:
            raise BinaryMissingError(
                f"{xray.name} binary missing: {xray.path}",
                user_message=f"{xray.name} binary not found: {xray.path}",
            ) from exc
        except PermissionError as exc:
            raise PermissionDeniedError(
                f"{xray.name} not executable: {xray.path}",
                user_message=f"{xray.name} binary is not executable: {xray.path}",
            ) from exc

        logger.info(
            "Started xray pid=%s [env_mode=%s removed_env=%s]",
            self._proc.pid,
            env_info.mode,
            ",".join(env_info.removed_keys) or "none",
        )

    def stop(self, *, timeout_s: float = 5) -> None:
        if self._proc is None:
            return

        proc = self._proc
        self._proc = None

        try:
            proc.terminate()
            proc.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=timeout_s)
        finally:
            logger.info("Stopped xray with returncode=%s", proc.returncode)
            if self._stdout_handle is not None:
                self._stdout_handle.close()
            self._stdout_handle = None
