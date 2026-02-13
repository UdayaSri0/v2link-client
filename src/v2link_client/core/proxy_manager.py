"""Apply and restore system proxy settings.

This is how we make the local Xray inbounds affect the whole desktop, not just
apps where the user manually configured proxy settings.

Currently supported:
- GNOME (and many desktops using libproxy) via `gsettings`.

We keep this module dependency-free by shelling out to the system tools.
"""

from __future__ import annotations

from dataclasses import dataclass
import ast
import logging
from pathlib import Path
import shutil
import socket
import subprocess
from typing import Final, Literal

from v2link_client.core.errors import ProxyApplyError
from v2link_client.core.storage import get_state_dir, load_json, save_json

logger = logging.getLogger(__name__)

SNAPSHOT_FILE: Final[str] = "system_proxy_snapshot.json"

ProxyBackendName = Literal["gsettings"]


@dataclass(frozen=True, slots=True)
class SystemProxyConfig:
    http_host: str
    http_port: int
    socks_host: str
    socks_port: int
    bypass_hosts: list[str]


def _run(cmd: list[str], *, timeout_s: float = 3.0) -> subprocess.CompletedProcess[str]:
    logger.info("Running command: %s", cmd)
    try:
        result = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired as exc:
        raise ProxyApplyError(
            f"Command timed out: {cmd}",
            user_message="Timed out while applying system proxy settings.",
        ) from exc
    except OSError as exc:
        raise ProxyApplyError(
            f"Command failed: {cmd}: {exc}",
            user_message="Failed to apply system proxy settings (missing tools/permissions).",
        ) from exc

    if result.returncode != 0:
        detail = (result.stderr or "").strip() or (result.stdout or "").strip() or "unknown error"
        raise ProxyApplyError(
            f"Command failed: {cmd}: {detail}",
            user_message=f"Failed to apply system proxy settings: {detail}",
        )

    return result


def _gsettings_available() -> bool:
    if shutil.which("gsettings") is None:
        return False
    try:
        out = _run(["gsettings", "list-keys", "org.gnome.system.proxy"], timeout_s=2.0).stdout
    except ProxyApplyError:
        return False
    return "mode" in out


_GSETTINGS_KEYS: Final[list[tuple[str, str]]] = [
    ("org.gnome.system.proxy", "mode"),
    ("org.gnome.system.proxy", "autoconfig-url"),
    ("org.gnome.system.proxy", "ignore-hosts"),
    ("org.gnome.system.proxy", "use-same-proxy"),
    ("org.gnome.system.proxy.ftp", "host"),
    ("org.gnome.system.proxy.ftp", "port"),
    ("org.gnome.system.proxy.http", "enabled"),
    ("org.gnome.system.proxy.http", "host"),
    ("org.gnome.system.proxy.http", "port"),
    ("org.gnome.system.proxy.http", "authentication-user"),
    ("org.gnome.system.proxy.http", "authentication-password"),
    ("org.gnome.system.proxy.http", "use-authentication"),
    ("org.gnome.system.proxy.https", "host"),
    ("org.gnome.system.proxy.https", "port"),
    ("org.gnome.system.proxy.socks", "host"),
    ("org.gnome.system.proxy.socks", "port"),
]

_DEFAULT_IGNORE_HOSTS: Final[list[str]] = ["localhost", "127.0.0.0/8", "::1"]


def _gsettings_get(schema: str, key: str) -> str:
    return _run(["gsettings", "get", schema, key], timeout_s=2.5).stdout.strip()


def _gsettings_set(schema: str, key: str, value: str) -> None:
    _run(["gsettings", "set", schema, key, value], timeout_s=2.5)


def _format_gsettings_str(value: str) -> str:
    # gsettings expects strings quoted with single quotes.
    value = (value or "").replace("'", "\\'")
    return f"'{value}'"


def _format_gsettings_str_list(values: list[str]) -> str:
    quoted = ", ".join(_format_gsettings_str(v) for v in values)
    return f"[{quoted}]"


def _parse_gsettings_str_list(raw: str) -> list[str]:
    raw = (raw or "").strip()
    if not raw:
        return []
    try:
        parsed = ast.literal_eval(raw)
    except Exception:
        return []
    if not isinstance(parsed, list):
        return []
    out: list[str] = []
    for item in parsed:
        if isinstance(item, str) and item.strip():
            out.append(item.strip())
    return out


def _parse_gsettings_str(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""
    try:
        parsed = ast.literal_eval(raw)
    except Exception:
        parsed = None
    if isinstance(parsed, str):
        return parsed.strip()
    if raw.startswith("'") and raw.endswith("'") and len(raw) >= 2:
        return raw[1:-1].strip()
    return raw


def _parse_gsettings_bool(raw: str) -> bool:
    raw = (raw or "").strip().lower()
    if raw == "true":
        return True
    if raw == "false":
        return False
    try:
        parsed = ast.literal_eval(raw)
    except Exception:
        return False
    return bool(parsed) if isinstance(parsed, bool) else False


def _parse_gsettings_int(raw: str, *, default: int = 0) -> int:
    try:
        return int((raw or "").strip())
    except ValueError:
        return default


def _normalize_proxy_mode(raw: str) -> str:
    return _parse_gsettings_str(raw).strip().lower()


def _merge_ignore_hosts(*sources: list[str]) -> list[str]:
    merged: list[str] = []
    for source in sources:
        for item in source:
            host = (item or "").strip()
            if not host or host in merged:
                continue
            merged.append(host)
    return merged


def _is_loopback_host(host: str) -> bool:
    return host.strip().lower() in {"127.0.0.1", "localhost", "::1"}


def _is_tcp_endpoint_reachable(host: str, port: int, *, timeout_s: float = 0.25) -> bool:
    try:
        sock = socket.create_connection((host, int(port)), timeout=timeout_s)
    except OSError:
        return False
    sock.close()
    return True


def _gsettings_snapshot() -> dict[str, str]:
    snap: dict[str, str] = {}
    for schema, key in _GSETTINGS_KEYS:
        snap[f"{schema}:{key}"] = _gsettings_get(schema, key)
    return snap


def _gsettings_restore(snapshot: dict[str, str]) -> None:
    # Restore non-mode keys first, then mode last to avoid transient broken proxy states.
    mode_value = snapshot.get("org.gnome.system.proxy:mode")
    for schema, key in _GSETTINGS_KEYS:
        if schema == "org.gnome.system.proxy" and key == "mode":
            continue
        raw_value = snapshot.get(f"{schema}:{key}")
        if raw_value is None:
            continue
        _gsettings_set(schema, key, raw_value)
    if mode_value is not None:
        _gsettings_set("org.gnome.system.proxy", "mode", mode_value)


def _gsettings_apply(cfg: SystemProxyConfig) -> None:
    # Merge bypass list with existing ignore-hosts.
    existing = _parse_gsettings_str_list(_gsettings_get("org.gnome.system.proxy", "ignore-hosts"))
    merged = _merge_ignore_hosts(existing, list(cfg.bypass_hosts or []), _DEFAULT_IGNORE_HOSTS)

    # Set per-protocol first, then switch mode to manual last.
    _gsettings_set("org.gnome.system.proxy.http", "enabled", "true")
    _gsettings_set("org.gnome.system.proxy.http", "host", _format_gsettings_str(cfg.http_host))
    _gsettings_set("org.gnome.system.proxy.http", "port", str(int(cfg.http_port)))
    _gsettings_set("org.gnome.system.proxy.https", "host", _format_gsettings_str(cfg.http_host))
    _gsettings_set("org.gnome.system.proxy.https", "port", str(int(cfg.http_port)))
    _gsettings_set("org.gnome.system.proxy.socks", "host", _format_gsettings_str(cfg.socks_host))
    _gsettings_set("org.gnome.system.proxy.socks", "port", str(int(cfg.socks_port)))
    _gsettings_set("org.gnome.system.proxy", "use-same-proxy", "true")
    _gsettings_set("org.gnome.system.proxy", "ignore-hosts", _format_gsettings_str_list(merged))
    _gsettings_set("org.gnome.system.proxy", "mode", "'manual'")


def _gsettings_force_no_proxy(*, ignore_hosts: list[str] | None = None) -> None:
    # Canonical no-proxy state. Some app stacks read per-protocol keys even when
    # mode is "none", so we normalize all related values.
    existing = ignore_hosts
    if existing is None:
        existing = _parse_gsettings_str_list(_gsettings_get("org.gnome.system.proxy", "ignore-hosts"))
    merged = _merge_ignore_hosts(existing, _DEFAULT_IGNORE_HOSTS)

    _gsettings_set("org.gnome.system.proxy", "autoconfig-url", _format_gsettings_str(""))
    _gsettings_set("org.gnome.system.proxy.http", "enabled", "false")
    _gsettings_set("org.gnome.system.proxy.http", "host", _format_gsettings_str(""))
    _gsettings_set("org.gnome.system.proxy.http", "port", "0")
    _gsettings_set("org.gnome.system.proxy.http", "authentication-user", _format_gsettings_str(""))
    _gsettings_set("org.gnome.system.proxy.http", "authentication-password", _format_gsettings_str(""))
    _gsettings_set("org.gnome.system.proxy.http", "use-authentication", "false")
    _gsettings_set("org.gnome.system.proxy.https", "host", _format_gsettings_str(""))
    _gsettings_set("org.gnome.system.proxy.https", "port", "0")
    _gsettings_set("org.gnome.system.proxy.socks", "host", _format_gsettings_str(""))
    _gsettings_set("org.gnome.system.proxy.socks", "port", "0")
    _gsettings_set("org.gnome.system.proxy.ftp", "host", _format_gsettings_str(""))
    _gsettings_set("org.gnome.system.proxy.ftp", "port", "0")
    _gsettings_set("org.gnome.system.proxy", "use-same-proxy", "false")
    _gsettings_set("org.gnome.system.proxy", "ignore-hosts", _format_gsettings_str_list(merged))
    _gsettings_set("org.gnome.system.proxy", "mode", "'none'")


class SystemProxyManager:
    def __init__(self, *, state_dir: Path | None = None) -> None:
        self._state_dir = state_dir or get_state_dir()

        backend: ProxyBackendName | None = None
        if _gsettings_available():
            backend = "gsettings"
        self._backend = backend

    @property
    def backend(self) -> ProxyBackendName | None:
        return self._backend

    @property
    def snapshot_path(self) -> Path:
        return self._state_dir / SNAPSHOT_FILE

    def is_supported(self) -> bool:
        return self._backend is not None

    def restore_if_needed(self) -> bool:
        """Restore system proxy if we have a snapshot from a previous run."""
        if not self.snapshot_path.exists():
            return False
        try:
            self.restore()
        except ProxyApplyError:
            # If restore fails, keep the snapshot so user/dev can investigate.
            raise
        return True

    def apply(self, cfg: SystemProxyConfig) -> None:
        if self._backend != "gsettings":
            raise ProxyApplyError(
                f"Unsupported system proxy backend: {self._backend}",
                user_message="System proxy apply not supported on this desktop yet.",
            )

        # Prevent stacking snapshots if apply is called multiple times.
        if self.snapshot_path.exists():
            logger.info("Existing system proxy snapshot found; restoring first")
            try:
                self.restore()
            except ProxyApplyError:
                # Keep going: user likely wants to re-apply.
                pass

        snapshot = _gsettings_snapshot()
        save_json(self.snapshot_path, {"backend": "gsettings", "snapshot": snapshot})

        try:
            _gsettings_apply(cfg)
        except ProxyApplyError:
            # Best-effort rollback.
            try:
                _gsettings_restore(snapshot)
            except ProxyApplyError:
                logger.exception("Failed to rollback system proxy settings")
            raise

    def force_no_proxy(self, *, ignore_hosts: list[str] | None = None) -> None:
        if self._backend is None:
            if _gsettings_available():
                self._backend = "gsettings"
            else:
                raise ProxyApplyError(
                    "System proxy backend unavailable",
                    user_message="System proxy backend unavailable; can't force no-proxy.",
                )
        if self._backend != "gsettings":
            raise ProxyApplyError(
                f"Unsupported system proxy backend: {self._backend}",
                user_message="System proxy force-no-proxy is not supported on this desktop yet.",
            )
        _gsettings_force_no_proxy(ignore_hosts=ignore_hosts)

    def restore(self) -> None:
        data = load_json(self.snapshot_path, None)
        if not isinstance(data, dict):
            return
        backend = data.get("backend")
        snapshot = data.get("snapshot")
        if backend != "gsettings" or not isinstance(snapshot, dict):
            raise ProxyApplyError(
                f"Invalid system proxy snapshot: backend={backend!r}",
                user_message="System proxy snapshot is invalid; can't restore.",
            )

        if self._backend is None:
            # If the current session can't access gsettings, we still try.
            self._backend = "gsettings"

        normalized_snapshot = {str(k): str(v) for k, v in snapshot.items()}
        expected_mode = _normalize_proxy_mode(normalized_snapshot.get("org.gnome.system.proxy:mode", ""))
        if expected_mode == "none":
            snap_hosts = _parse_gsettings_str_list(
                normalized_snapshot.get("org.gnome.system.proxy:ignore-hosts", "")
            )
            self.force_no_proxy(ignore_hosts=snap_hosts)
        else:
            _gsettings_restore(normalized_snapshot)

        if expected_mode:
            current_mode = _normalize_proxy_mode(_gsettings_get("org.gnome.system.proxy", "mode"))
            if current_mode != expected_mode:
                raise ProxyApplyError(
                    f"Proxy restore mode mismatch: expected={expected_mode!r}, got={current_mode!r}",
                    user_message="System proxy restore verification failed.",
                )
        try:
            self.snapshot_path.unlink()
        except OSError:
            logger.exception("Failed to remove system proxy snapshot: %s", self.snapshot_path)

    def repair_stale_loopback_proxy(self) -> bool:
        if self.snapshot_path.exists() or self._backend != "gsettings":
            return False

        mode = _normalize_proxy_mode(_gsettings_get("org.gnome.system.proxy", "mode"))
        if mode != "manual":
            return False

        if not _parse_gsettings_bool(_gsettings_get("org.gnome.system.proxy", "use-same-proxy")):
            return False

        host = _parse_gsettings_str(_gsettings_get("org.gnome.system.proxy.http", "host"))
        port = _parse_gsettings_int(_gsettings_get("org.gnome.system.proxy.http", "port"))
        if not _is_loopback_host(host) or port <= 0:
            return False

        if _is_tcp_endpoint_reachable(host, port, timeout_s=0.25):
            return False

        ignore_hosts = _parse_gsettings_str_list(_gsettings_get("org.gnome.system.proxy", "ignore-hosts"))
        self.force_no_proxy(ignore_hosts=ignore_hosts)
        return True
