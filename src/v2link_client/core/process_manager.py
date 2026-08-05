"""Manage core process lifecycle.

The UI intentionally keeps policy decisions simple:
- Build a core config file (currently Xray JSON)
- Validate it using `xray run -test`
- Start/stop the process and surface logs to the user
"""

from __future__ import annotations

import errno
import logging
import os
from pathlib import Path
import socket
import subprocess
import threading

from v2link_client.core.errors import (
    BinaryMissingError,
    ConfigBuildError,
    PermissionDeniedError,
    PortInUseError,
)
from v2link_client.core.storage import get_logs_dir
from v2link_client.core.logging_setup import sanitize_sensitive_text
from v2link_client.core.owned_process import terminate_owned_process
from v2link_client.core.system_subprocess import build_xray_subprocess_env
from v2link_client.core.xray_locator import (
    MISSING_XRAY_MESSAGE,
    XrayBinary,
    find_xray_binary as locate_xray_binary,
)

logger = logging.getLogger(__name__)

XRAY_STDOUT_MAX_BYTES = 2 * 1024 * 1024
XRAY_STDOUT_BACKUP_COUNT = 2


CoreBinary = XrayBinary


def find_xray_binary() -> CoreBinary:
    xray = locate_xray_binary()
    if not xray.valid or not xray.path:
        raise BinaryMissingError(
            xray.error or MISSING_XRAY_MESSAGE,
            user_message=xray.error or MISSING_XRAY_MESSAGE,
        )
    return xray


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
    if not xray.path:
        raise BinaryMissingError(
            xray.error or MISSING_XRAY_MESSAGE,
            user_message=xray.error or MISSING_XRAY_MESSAGE,
        )
    cmd = [xray.path, "run", "-test", "-c", str(config_path)]
    env, env_info = build_xray_subprocess_env(xray.path)
    safe_cmd = sanitize_sensitive_text(" ".join(cmd))
    logger.info(
        "Validating xray config: %s [env_mode=%s removed_env=%s]",
        safe_cmd,
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
        safe_path = sanitize_sensitive_text(xray.path)
        raise BinaryMissingError(
            f"{xray.name} binary missing: {safe_path}",
            user_message=f"{xray.name} binary not found: {safe_path}",
        ) from exc
    except PermissionError as exc:
        safe_path = sanitize_sensitive_text(xray.path)
        raise PermissionDeniedError(
            f"{xray.name} not executable: {safe_path}",
            user_message=f"{xray.name} binary is not executable: {safe_path}",
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise ConfigBuildError(
            "xray config validation timed out",
            user_message="Xray configuration validation timed out.",
        ) from exc

    if result.returncode == 0:
        return

    stderr = (result.stderr or "").strip()
    stdout = (result.stdout or "").strip()
    detail = sanitize_sensitive_text(
        stderr or stdout or f"exit code {result.returncode}"
    )

    raise ConfigBuildError(
        f"xray config validation failed: {detail}",
        user_message=f"Xray rejected the config: {detail}",
    )


class XrayProcessManager:
    def __init__(self, xray: CoreBinary | None = None) -> None:
        self._xray: CoreBinary | None = xray
        self._proc: subprocess.Popen[bytes] | None = None
        self._stdout_path: Path | None = None
        self._stdout_thread: threading.Thread | None = None

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

    @property
    def pid(self) -> int | None:
        if self._proc is None or self._proc.poll() is not None:
            return None
        return int(self._proc.pid)

    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def returncode(self) -> int | None:
        if self._proc is None:
            return None
        return self._proc.poll()

    def start(self, config_path: Path) -> None:
        if self.is_running():
            return
        if self._proc is not None:
            self.stop()

        xray = self._ensure_binary()
        if not xray.path:
            raise BinaryMissingError(
                xray.error or MISSING_XRAY_MESSAGE,
                user_message=xray.error or MISSING_XRAY_MESSAGE,
            )
        logs_dir = get_logs_dir()
        logs_dir.mkdir(parents=True, exist_ok=True)
        self._stdout_path = logs_dir / "xray_stdout.log"
        _bound_existing_log(self._stdout_path)
        # Older releases wrote these directly from Xray. Keep legacy files
        # bounded even though current configs route diagnostic output through
        # the managed stdout stream.
        _bound_existing_log(logs_dir / "xray_access.log")
        _bound_existing_log(logs_dir / "xray_error.log")

        cmd = [xray.path, "run", "-c", str(config_path)]
        env, env_info = build_xray_subprocess_env(xray.path)
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
                start_new_session=True,
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

        proc = self._proc
        self._stdout_thread = threading.Thread(
            target=_pump_bounded_stdout,
            args=(proc, self._stdout_path),
            name="v2link-xray-log",
            daemon=True,
        )
        self._stdout_thread.start()

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
        returncode = proc.poll()
        try:
            returncode = terminate_owned_process(proc, timeout_s=timeout_s)
        finally:
            self._proc = None
            thread = self._stdout_thread
            self._stdout_thread = None
            if thread is not None:
                thread.join(max(0.1, float(timeout_s)))
            stdout = getattr(proc, "stdout", None)
            if stdout is not None and not stdout.closed:
                stdout.close()
            logger.info("Stopped xray with returncode=%s", returncode)


def _pump_bounded_stdout(proc: subprocess.Popen[bytes], path: Path) -> None:
    stream = proc.stdout
    if stream is None:
        return
    try:
        while True:
            chunk = stream.read1(64 * 1024)
            if not chunk:
                return
            _append_bounded(path, chunk)
    except (OSError, ValueError):
        logger.debug("Xray stdout stream closed during shutdown", exc_info=True)


def _append_bounded(path: Path, chunk: bytes) -> None:
    if len(chunk) > XRAY_STDOUT_MAX_BYTES:
        chunk = chunk[-XRAY_STDOUT_MAX_BYTES :]
    current_size = path.stat().st_size if path.exists() else 0
    if current_size + len(chunk) > XRAY_STDOUT_MAX_BYTES:
        _rotate_log(path)
    with path.open("ab") as handle:
        handle.write(chunk)


def _bound_existing_log(path: Path) -> None:
    try:
        if path.exists() and path.stat().st_size > XRAY_STDOUT_MAX_BYTES:
            with path.open("rb") as source:
                source.seek(-XRAY_STDOUT_MAX_BYTES, os.SEEK_END)
                tail = source.read()
            with path.open("wb") as target:
                target.write(tail)
    except OSError:
        logger.warning("Could not bound Xray log %s", path, exc_info=True)


def _rotate_log(path: Path) -> None:
    for index in range(XRAY_STDOUT_BACKUP_COUNT, 0, -1):
        source = path if index == 1 else path.with_name(f"{path.name}.{index - 1}")
        target = path.with_name(f"{path.name}.{index}")
        if not source.exists():
            continue
        if index == XRAY_STDOUT_BACKUP_COUNT:
            target.unlink(missing_ok=True)
        os.replace(source, target)
