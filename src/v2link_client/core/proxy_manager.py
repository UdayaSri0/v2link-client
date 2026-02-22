"""Apply and restore system proxy settings.

This module applies local Xray proxy endpoints to desktop-wide proxy settings and
restores the previous state on stop/exit.

Preferred backend:
- GNOME GSettings via Gio (python3-gi)

Fallback backend:
- `gsettings` CLI
"""

from __future__ import annotations

from dataclasses import dataclass
import ast
import json
import logging
import os
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import tempfile
from typing import Any, Final, Literal, cast

from v2link_client.core.errors import ProxyApplyError
from v2link_client.core.storage import get_state_dir, load_json

try:  # pragma: no cover - optional dependency in some environments
    import gi

    gi.require_version("Gio", "2.0")
    from gi.repository import Gio
except Exception:  # pragma: no cover - optional dependency in some environments
    Gio = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

SNAPSHOT_FILE: Final[str] = "system_proxy_snapshot.json"
SNAPSHOT_VERSION: Final[int] = 2

ProxyBackendName = Literal["gio", "gsettings"]
ValueKind = Literal["string", "bool", "int", "strv"]

_SCHEMA_PROXY: Final[str] = "org.gnome.system.proxy"
_SCHEMA_HTTP: Final[str] = "org.gnome.system.proxy.http"
_SCHEMA_HTTPS: Final[str] = "org.gnome.system.proxy.https"
_SCHEMA_SOCKS: Final[str] = "org.gnome.system.proxy.socks"
_SCHEMA_FTP: Final[str] = "org.gnome.system.proxy.ftp"

_DEFAULT_IGNORE_HOSTS: Final[list[str]] = ["localhost", "127.0.0.0/8", "::1"]


@dataclass(frozen=True, slots=True)
class SystemProxyConfig:
    http_host: str
    http_port: int
    socks_host: str
    socks_port: int
    bypass_hosts: list[str]


@dataclass(frozen=True, slots=True)
class SystemProxyStatus:
    mode: str
    http_enabled: bool
    http_host: str
    http_port: int
    socks_host: str
    socks_port: int


@dataclass(frozen=True, slots=True)
class _SettingSpec:
    schema: str
    key: str
    kind: ValueKind
    optional: bool = False


_MODE_SPEC = _SettingSpec(_SCHEMA_PROXY, "mode", "string")
_AUTOCONFIG_URL_SPEC = _SettingSpec(_SCHEMA_PROXY, "autoconfig-url", "string")
_IGNORE_HOSTS_SPEC = _SettingSpec(_SCHEMA_PROXY, "ignore-hosts", "strv")
_USE_SAME_PROXY_SPEC = _SettingSpec(_SCHEMA_PROXY, "use-same-proxy", "bool")

_HTTP_ENABLED_SPEC = _SettingSpec(_SCHEMA_HTTP, "enabled", "bool")
_HTTP_HOST_SPEC = _SettingSpec(_SCHEMA_HTTP, "host", "string")
_HTTP_PORT_SPEC = _SettingSpec(_SCHEMA_HTTP, "port", "int")
_HTTP_USE_AUTH_SPEC = _SettingSpec(_SCHEMA_HTTP, "use-authentication", "bool")
_HTTP_AUTH_USER_SPEC = _SettingSpec(_SCHEMA_HTTP, "authentication-user", "string", optional=True)

_HTTPS_HOST_SPEC = _SettingSpec(_SCHEMA_HTTPS, "host", "string")
_HTTPS_PORT_SPEC = _SettingSpec(_SCHEMA_HTTPS, "port", "int")

_SOCKS_HOST_SPEC = _SettingSpec(_SCHEMA_SOCKS, "host", "string")
_SOCKS_PORT_SPEC = _SettingSpec(_SCHEMA_SOCKS, "port", "int")

# Legacy keys retained for backward-compatible restore of old snapshots.
_FTP_HOST_SPEC = _SettingSpec(_SCHEMA_FTP, "host", "string", optional=True)
_FTP_PORT_SPEC = _SettingSpec(_SCHEMA_FTP, "port", "int", optional=True)
_HTTP_AUTH_PASSWORD_SPEC = _SettingSpec(
    _SCHEMA_HTTP,
    "authentication-password",
    "string",
    optional=True,
)

_SNAPSHOT_SPECS: Final[list[_SettingSpec]] = [
    _MODE_SPEC,
    _AUTOCONFIG_URL_SPEC,
    _IGNORE_HOSTS_SPEC,
    _USE_SAME_PROXY_SPEC,
    _HTTP_ENABLED_SPEC,
    _HTTP_HOST_SPEC,
    _HTTP_PORT_SPEC,
    _HTTP_USE_AUTH_SPEC,
    _HTTP_AUTH_USER_SPEC,
    _HTTPS_HOST_SPEC,
    _HTTPS_PORT_SPEC,
    _SOCKS_HOST_SPEC,
    _SOCKS_PORT_SPEC,
]

_LEGACY_RESTORE_SPECS: Final[list[_SettingSpec]] = [
    _FTP_HOST_SPEC,
    _FTP_PORT_SPEC,
    _HTTP_AUTH_PASSWORD_SPEC,
]

_ALL_RESTORE_SPECS: Final[list[_SettingSpec]] = [*_SNAPSHOT_SPECS, *_LEGACY_RESTORE_SPECS]

_SPEC_BY_PATH: Final[dict[str, _SettingSpec]] = {
    f"{spec.schema}:{spec.key}": spec for spec in _ALL_RESTORE_SPECS
}

_GSETTINGS_KEY_CACHE: dict[str, set[str]] = {}
_MISSING: Final[object] = object()


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


def _format_gsettings_str(value: str) -> str:
    value = (value or "").replace("'", "\\'")
    return f"'{value}'"


def _format_gsettings_str_list(values: list[str]) -> str:
    quoted = ", ".join(_format_gsettings_str(v) for v in values)
    return f"[{quoted}]"


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


def _to_string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return _parse_gsettings_str(value)
    return str(value).strip()


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return _parse_gsettings_bool(value)
    if isinstance(value, int):
        return bool(value)
    return False


def _to_int(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return _parse_gsettings_int(value)
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _to_strv(value: Any) -> list[str]:
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            if isinstance(item, str) and item.strip():
                out.append(item.strip())
            elif item is not None:
                text = str(item).strip()
                if text:
                    out.append(text)
        return out
    if isinstance(value, tuple):
        return _to_strv(list(value))
    if isinstance(value, str):
        if value.strip().startswith("["):
            return _parse_gsettings_str_list(value)
        text = _parse_gsettings_str(value)
        return [text] if text else []
    return []


def _decode_value(raw: Any, kind: ValueKind) -> Any:
    if kind == "string":
        return _to_string(raw)
    if kind == "bool":
        return _to_bool(raw)
    if kind == "int":
        return _to_int(raw)
    return _to_strv(raw)


def _encode_for_gsettings(kind: ValueKind, value: Any) -> str:
    if kind == "string":
        return _format_gsettings_str(_to_string(value))
    if kind == "bool":
        return "true" if _to_bool(value) else "false"
    if kind == "int":
        return str(int(_to_int(value)))
    return _format_gsettings_str_list(_to_strv(value))


def _format_cmd(cmd: list[str]) -> str:
    try:
        return shlex.join(cmd)
    except Exception:
        return str(cmd)


def _run(cmd: list[str], *, timeout_s: float = 3.0) -> subprocess.CompletedProcess[str]:
    command_text = _format_cmd(cmd)
    logger.info("Running command: %s", command_text)
    try:
        result = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired as exc:
        logger.exception("Command timed out: %s", command_text)
        raise ProxyApplyError(
            f"Command timed out: {command_text}",
            user_message="Timed out while applying system proxy settings.",
        ) from exc
    except OSError as exc:
        logger.exception("Command execution failed: %s", command_text)
        raise ProxyApplyError(
            f"Command failed: {command_text}: {exc}",
            user_message="Failed to apply system proxy settings (missing tools/permissions).",
        ) from exc

    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()
    logger.info(
        "Command result rc=%s cmd=%s stdout=%r stderr=%r",
        result.returncode,
        command_text,
        stdout,
        stderr,
    )

    if result.returncode != 0:
        detail = stderr or stdout or "unknown error"
        logger.error(
            "Command failed rc=%s cmd=%s stdout=%r stderr=%r",
            result.returncode,
            command_text,
            stdout,
            stderr,
        )
        raise ProxyApplyError(
            f"Command failed: {command_text}: {detail}",
            user_message=f"Failed to apply system proxy settings: {detail}",
        )

    return result


def _gsettings_available() -> bool:
    if shutil.which("gsettings") is None:
        return False
    try:
        out = _run(["gsettings", "list-keys", _SCHEMA_PROXY], timeout_s=2.0).stdout
    except ProxyApplyError:
        return False
    return "mode" in out


def _gsettings_list_keys(schema: str) -> set[str]:
    cached = _GSETTINGS_KEY_CACHE.get(schema)
    if cached is not None:
        return cached
    out = _run(["gsettings", "list-keys", schema], timeout_s=2.0).stdout
    keys = {line.strip() for line in (out or "").splitlines() if line.strip()}
    _GSETTINGS_KEY_CACHE[schema] = keys
    return keys


def _gsettings_has_key(schema: str, key: str) -> bool:
    try:
        return key in _gsettings_list_keys(schema)
    except ProxyApplyError:
        return False


def _gsettings_get_raw(schema: str, key: str) -> str:
    return _run(["gsettings", "get", schema, key], timeout_s=2.5).stdout.strip()


def _gsettings_set_raw(schema: str, key: str, value: str) -> None:
    _run(["gsettings", "set", schema, key, value], timeout_s=2.5)


def _gio_available() -> bool:
    if Gio is None:
        return False
    try:
        source = Gio.SettingsSchemaSource.get_default()
    except Exception:
        logger.exception("Failed to read Gio schema source")
        return False
    if source is None:
        return False
    for schema in (_SCHEMA_PROXY, _SCHEMA_HTTP, _SCHEMA_HTTPS, _SCHEMA_SOCKS):
        try:
            if source.lookup(schema, True) is None:
                return False
        except Exception:
            logger.exception("Failed to lookup Gio schema: %s", schema)
            return False
    return True


def _gio_settings(schema: str):
    if Gio is None:
        raise ProxyApplyError(
            "Gio backend unavailable",
            user_message="System proxy backend unavailable.",
        )
    try:
        return Gio.Settings.new(schema)
    except Exception as exc:
        logger.exception("Failed to create Gio.Settings for schema=%s", schema)
        raise ProxyApplyError(
            f"Failed to open schema: {schema}: {exc}",
            user_message="Failed to access GNOME proxy settings.",
        ) from exc


def _gio_has_key(schema: str, key: str) -> bool:
    settings = _gio_settings(schema)
    try:
        settings_schema = settings.props.settings_schema
        return bool(settings_schema is not None and settings_schema.has_key(key))
    except Exception:
        logger.exception("Failed to inspect Gio schema key: %s:%s", schema, key)
        return False


def _gio_sync() -> None:
    if Gio is None:
        return
    try:
        Gio.Settings.sync()
    except Exception as exc:
        logger.exception("Failed to sync Gio settings")
        raise ProxyApplyError(
            f"Failed to sync GNOME settings: {exc}",
            user_message="Failed to commit GNOME proxy settings.",
        ) from exc


def _read_setting_value(
    backend: ProxyBackendName,
    spec: _SettingSpec,
    *,
    allow_missing: bool,
) -> Any:
    if backend == "gio":
        if allow_missing and not _gio_has_key(spec.schema, spec.key):
            logger.info("Skipping missing optional Gio key: %s:%s", spec.schema, spec.key)
            return _MISSING
        if not _gio_has_key(spec.schema, spec.key):
            raise ProxyApplyError(
                f"Missing Gio key: {spec.schema}:{spec.key}",
                user_message="GNOME proxy schema is missing expected keys.",
            )
        settings = _gio_settings(spec.schema)
        try:
            if spec.kind == "string":
                return _to_string(settings.get_string(spec.key))
            if spec.kind == "bool":
                return bool(settings.get_boolean(spec.key))
            if spec.kind == "int":
                return int(settings.get_int(spec.key))
            return _to_strv(list(settings.get_strv(spec.key)))
        except Exception as exc:
            logger.exception("Failed to read Gio setting: %s:%s", spec.schema, spec.key)
            raise ProxyApplyError(
                f"Failed to read Gio setting {spec.schema}:{spec.key}: {exc}",
                user_message="Failed to read GNOME proxy settings.",
            ) from exc

    if allow_missing and not _gsettings_has_key(spec.schema, spec.key):
        logger.info("Skipping missing optional gsettings key: %s:%s", spec.schema, spec.key)
        return _MISSING
    raw_value = _gsettings_get_raw(spec.schema, spec.key)
    return _decode_value(raw_value, spec.kind)


def _write_setting_value(backend: ProxyBackendName, spec: _SettingSpec, value: Any) -> None:
    if backend == "gio":
        if not _gio_has_key(spec.schema, spec.key):
            if spec.optional:
                logger.info("Skipping missing optional Gio key: %s:%s", spec.schema, spec.key)
                return
            raise ProxyApplyError(
                f"Missing Gio key: {spec.schema}:{spec.key}",
                user_message="GNOME proxy schema is missing expected keys.",
            )

        settings = _gio_settings(spec.schema)
        try:
            if spec.kind == "string":
                settings.set_string(spec.key, _to_string(value))
            elif spec.kind == "bool":
                settings.set_boolean(spec.key, _to_bool(value))
            elif spec.kind == "int":
                settings.set_int(spec.key, int(_to_int(value)))
            else:
                settings.set_strv(spec.key, _to_strv(value))
            if settings.get_has_unapplied():
                settings.apply()
            return
        except Exception as exc:
            logger.exception("Failed to write Gio setting: %s:%s", spec.schema, spec.key)
            raise ProxyApplyError(
                f"Failed to write Gio setting {spec.schema}:{spec.key}: {exc}",
                user_message="Failed to apply GNOME proxy settings.",
            ) from exc

    encoded = _encode_for_gsettings(spec.kind, value)
    _gsettings_set_raw(spec.schema, spec.key, encoded)


def _sync_backend(backend: ProxyBackendName) -> None:
    if backend == "gio":
        _gio_sync()


def _detect_backend() -> ProxyBackendName | None:
    if _gio_available():
        return "gio"
    if _gsettings_available():
        return "gsettings"
    return None


def _capture_snapshot(backend: ProxyBackendName) -> dict[str, dict[str, Any]]:
    snapshot: dict[str, dict[str, Any]] = {}
    for spec in _SNAPSHOT_SPECS:
        value = _read_setting_value(backend, spec, allow_missing=spec.optional)
        if value is _MISSING:
            continue
        snapshot.setdefault(spec.schema, {})[spec.key] = value

    mode = snapshot.get(_SCHEMA_PROXY, {}).get("mode")
    if not isinstance(mode, str) or not _normalize_proxy_mode(mode):
        raise ProxyApplyError(
            "Failed to snapshot proxy mode",
            user_message="Failed to snapshot current system proxy settings.",
        )

    return snapshot


def _normalize_snapshot(snapshot: Any) -> dict[str, dict[str, Any]] | None:
    if not isinstance(snapshot, dict):
        return None

    normalized: dict[str, dict[str, Any]] = {}

    # New format: nested dict by schema.
    has_nested = any(isinstance(v, dict) for v in snapshot.values())
    if has_nested:
        for spec in _ALL_RESTORE_SPECS:
            by_schema = snapshot.get(spec.schema)
            if not isinstance(by_schema, dict):
                continue
            if spec.key not in by_schema:
                continue
            normalized.setdefault(spec.schema, {})[spec.key] = _decode_value(by_schema.get(spec.key), spec.kind)
    else:
        # Backward-compatible format: flat keys schema:key => raw gsettings string.
        for raw_key, raw_value in snapshot.items():
            if not isinstance(raw_key, str):
                continue
            spec = _SPEC_BY_PATH.get(raw_key)
            if spec is None:
                continue
            normalized.setdefault(spec.schema, {})[spec.key] = _decode_value(raw_value, spec.kind)

    mode = normalized.get(_SCHEMA_PROXY, {}).get("mode")
    if not isinstance(mode, str) or not _normalize_proxy_mode(mode):
        return None

    return normalized


def _write_snapshot_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    tmp_path: Path | None = None
    tmp_handle = None
    try:
        tmp_handle = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        )
        tmp_path = Path(tmp_handle.name)
        json.dump(payload, tmp_handle, indent=2, sort_keys=True)
        tmp_handle.flush()
        os.fsync(tmp_handle.fileno())
        tmp_handle.close()
        tmp_handle = None
        os.replace(tmp_path, path)
    except Exception as exc:
        logger.exception(
            "Failed to write system proxy snapshot atomically: target=%s temp=%s",
            path,
            tmp_path,
        )
        raise ProxyApplyError(
            f"Failed to write system proxy snapshot: {path}: {exc}",
            user_message="Failed to save system proxy snapshot. Check file permissions.",
        ) from exc
    finally:
        if tmp_handle is not None:
            try:
                tmp_handle.close()
            except OSError:
                logger.exception("Failed to close temporary snapshot handle")
        if tmp_path is not None and tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                logger.exception("Failed to remove temporary snapshot file: %s", tmp_path)


def _snapshot_specs_in_restore_order(snapshot: dict[str, dict[str, Any]]) -> list[_SettingSpec]:
    ordered: list[_SettingSpec] = []
    for spec in _ALL_RESTORE_SPECS:
        if spec.schema == _SCHEMA_PROXY and spec.key == "mode":
            continue
        if spec.key in snapshot.get(spec.schema, {}):
            ordered.append(spec)
    if "mode" in snapshot.get(_SCHEMA_PROXY, {}):
        ordered.append(_MODE_SPEC)
    return ordered


def _restore_snapshot(backend: ProxyBackendName, snapshot: dict[str, dict[str, Any]]) -> None:
    for spec in _snapshot_specs_in_restore_order(snapshot):
        value = snapshot.get(spec.schema, {}).get(spec.key)
        if value is None and spec.kind != "string":
            continue
        _write_setting_value(backend, spec, value)
    _sync_backend(backend)


def _validate_runtime_proxy_config(cfg: SystemProxyConfig) -> None:
    http_host = (cfg.http_host or "").strip()
    socks_host = (cfg.socks_host or "").strip()
    if not http_host:
        raise ProxyApplyError(
            "HTTP proxy host is empty",
            user_message="System proxy HTTP host is empty.",
        )
    if not socks_host:
        raise ProxyApplyError(
            "SOCKS proxy host is empty",
            user_message="System proxy SOCKS host is empty.",
        )

    if int(cfg.http_port) <= 0:
        raise ProxyApplyError(
            f"Invalid HTTP proxy port: {cfg.http_port}",
            user_message="System proxy HTTP port is invalid.",
        )
    if int(cfg.socks_port) <= 0:
        raise ProxyApplyError(
            f"Invalid SOCKS proxy port: {cfg.socks_port}",
            user_message="System proxy SOCKS port is invalid.",
        )


def _apply_runtime_proxy(backend: ProxyBackendName, cfg: SystemProxyConfig) -> None:
    _validate_runtime_proxy_config(cfg)

    existing = cast(
        list[str],
        _read_setting_value(backend, _IGNORE_HOSTS_SPEC, allow_missing=False),
    )
    merged_ignore_hosts = _merge_ignore_hosts(existing, list(cfg.bypass_hosts or []), _DEFAULT_IGNORE_HOSTS)

    _write_setting_value(backend, _HTTP_ENABLED_SPEC, True)
    _write_setting_value(backend, _HTTP_HOST_SPEC, cfg.http_host)
    _write_setting_value(backend, _HTTP_PORT_SPEC, int(cfg.http_port))
    _write_setting_value(backend, _HTTP_USE_AUTH_SPEC, False)
    _write_setting_value(backend, _HTTP_AUTH_USER_SPEC, "")

    _write_setting_value(backend, _HTTPS_HOST_SPEC, cfg.http_host)
    _write_setting_value(backend, _HTTPS_PORT_SPEC, int(cfg.http_port))

    _write_setting_value(backend, _SOCKS_HOST_SPEC, cfg.socks_host)
    _write_setting_value(backend, _SOCKS_PORT_SPEC, int(cfg.socks_port))

    _write_setting_value(backend, _USE_SAME_PROXY_SPEC, False)
    _write_setting_value(backend, _IGNORE_HOSTS_SPEC, merged_ignore_hosts)
    _write_setting_value(backend, _MODE_SPEC, "manual")

    _sync_backend(backend)


def _force_no_proxy(backend: ProxyBackendName, *, ignore_hosts: list[str] | None = None) -> None:
    existing_hosts = ignore_hosts
    if existing_hosts is None:
        existing_hosts = cast(
            list[str],
            _read_setting_value(backend, _IGNORE_HOSTS_SPEC, allow_missing=False),
        )
    merged_ignore_hosts = _merge_ignore_hosts(existing_hosts, _DEFAULT_IGNORE_HOSTS)

    _write_setting_value(backend, _AUTOCONFIG_URL_SPEC, "")
    _write_setting_value(backend, _HTTP_ENABLED_SPEC, False)
    _write_setting_value(backend, _HTTP_HOST_SPEC, "")
    _write_setting_value(backend, _HTTP_PORT_SPEC, 0)
    _write_setting_value(backend, _HTTP_AUTH_USER_SPEC, "")
    _write_setting_value(backend, _HTTP_AUTH_PASSWORD_SPEC, "")
    _write_setting_value(backend, _HTTP_USE_AUTH_SPEC, False)
    _write_setting_value(backend, _HTTPS_HOST_SPEC, "")
    _write_setting_value(backend, _HTTPS_PORT_SPEC, 0)
    _write_setting_value(backend, _SOCKS_HOST_SPEC, "")
    _write_setting_value(backend, _SOCKS_PORT_SPEC, 0)
    _write_setting_value(backend, _FTP_HOST_SPEC, "")
    _write_setting_value(backend, _FTP_PORT_SPEC, 0)
    _write_setting_value(backend, _USE_SAME_PROXY_SPEC, False)
    _write_setting_value(backend, _IGNORE_HOSTS_SPEC, merged_ignore_hosts)
    _write_setting_value(backend, _MODE_SPEC, "none")

    _sync_backend(backend)


def _read_status(backend: ProxyBackendName) -> SystemProxyStatus:
    mode = _normalize_proxy_mode(cast(str, _read_setting_value(backend, _MODE_SPEC, allow_missing=False)))
    http_enabled = bool(_read_setting_value(backend, _HTTP_ENABLED_SPEC, allow_missing=False))
    http_host = _to_string(_read_setting_value(backend, _HTTP_HOST_SPEC, allow_missing=False))
    http_port = _to_int(_read_setting_value(backend, _HTTP_PORT_SPEC, allow_missing=False))
    socks_host = _to_string(_read_setting_value(backend, _SOCKS_HOST_SPEC, allow_missing=False))
    socks_port = _to_int(_read_setting_value(backend, _SOCKS_PORT_SPEC, allow_missing=False))

    status = SystemProxyStatus(
        mode=mode,
        http_enabled=http_enabled,
        http_host=http_host,
        http_port=http_port,
        socks_host=socks_host,
        socks_port=socks_port,
    )
    logger.info(
        "System proxy status: mode=%s http_enabled=%s http=%s:%s socks=%s:%s",
        status.mode,
        status.http_enabled,
        status.http_host,
        status.http_port,
        status.socks_host,
        status.socks_port,
    )
    return status


def _verify_apply(backend: ProxyBackendName, cfg: SystemProxyConfig) -> SystemProxyStatus:
    status = _read_status(backend)

    expected_http_host = (cfg.http_host or "").strip()
    expected_socks_host = (cfg.socks_host or "").strip()
    expected_http_port = int(cfg.http_port)
    expected_socks_port = int(cfg.socks_port)

    mismatches: list[str] = []
    if status.mode != "manual":
        mismatches.append(f"mode expected='manual' got={status.mode!r}")
    if not status.http_enabled:
        mismatches.append("http.enabled expected=true got=false")
    if status.http_host != expected_http_host:
        mismatches.append(f"http.host expected={expected_http_host!r} got={status.http_host!r}")
    if status.http_port != expected_http_port:
        mismatches.append(f"http.port expected={expected_http_port} got={status.http_port}")
    if status.socks_host != expected_socks_host:
        mismatches.append(f"socks.host expected={expected_socks_host!r} got={status.socks_host!r}")
    if status.socks_port != expected_socks_port:
        mismatches.append(f"socks.port expected={expected_socks_port} got={status.socks_port}")

    if mismatches:
        detail = "; ".join(mismatches)
        logger.error("System proxy apply verification failed: %s", detail)
        raise ProxyApplyError(
            f"System proxy apply verification failed: {detail}",
            user_message=f"System proxy not applied correctly ({detail}).",
        )

    logger.info("System proxy apply verification passed")
    return status


def _verify_restore(backend: ProxyBackendName, snapshot: dict[str, dict[str, Any]]) -> SystemProxyStatus:
    mismatches: list[str] = []
    for spec in _snapshot_specs_in_restore_order(snapshot):
        expected = snapshot.get(spec.schema, {}).get(spec.key)
        if expected is None and spec.kind != "string":
            continue
        actual = _read_setting_value(backend, spec, allow_missing=False)
        normalized_expected = _decode_value(expected, spec.kind)
        normalized_actual = _decode_value(actual, spec.kind)
        if normalized_expected != normalized_actual:
            mismatches.append(
                f"{spec.schema}:{spec.key} expected={normalized_expected!r} got={normalized_actual!r}"
            )

    status = _read_status(backend)

    if mismatches:
        detail = "; ".join(mismatches)
        logger.error("System proxy restore verification failed: %s", detail)
        raise ProxyApplyError(
            f"System proxy restore verification failed: {detail}",
            user_message="System proxy restore verification failed.",
        )

    logger.info("System proxy restore verification passed")
    return status


def _verify_no_proxy(backend: ProxyBackendName) -> SystemProxyStatus:
    status = _read_status(backend)
    if status.mode != "none":
        raise ProxyApplyError(
            f"Expected mode='none' after no-proxy fallback, got {status.mode!r}",
            user_message="System proxy fallback failed to disable proxy mode.",
        )
    return status


class SystemProxyManager:
    def __init__(self, *, state_dir: Path | None = None) -> None:
        self._state_dir = state_dir or get_state_dir()
        self._backend: ProxyBackendName | None = _detect_backend()

    @property
    def backend(self) -> ProxyBackendName | None:
        return self._backend

    @property
    def snapshot_path(self) -> Path:
        return self._state_dir / SNAPSHOT_FILE

    def is_supported(self) -> bool:
        return self._backend is not None

    def _ensure_backend(self, *, preferred: ProxyBackendName | None = None) -> ProxyBackendName:
        if self._backend is not None:
            return self._backend

        if preferred == "gio" and _gio_available():
            self._backend = "gio"
            return self._backend
        if preferred == "gsettings" and _gsettings_available():
            self._backend = "gsettings"
            return self._backend

        detected = _detect_backend()
        if detected is not None:
            self._backend = detected
            return detected

        raise ProxyApplyError(
            "System proxy backend unavailable",
            user_message="System proxy backend unavailable on this desktop/session.",
        )

    def restore_if_needed(self) -> bool:
        """Restore system proxy if we have a snapshot from a previous run."""
        if not self.snapshot_path.exists():
            return False
        try:
            self.restore()
        except ProxyApplyError:
            # Keep snapshot for investigation if restore fails.
            raise
        return True

    def read_status(self) -> SystemProxyStatus:
        backend = self._ensure_backend()
        return _read_status(backend)

    def apply(self, cfg: SystemProxyConfig) -> SystemProxyStatus:
        backend = self._ensure_backend()

        # Prevent stacked snapshots across repeated applies.
        if self.snapshot_path.exists():
            logger.info("Existing system proxy snapshot found; restoring before apply")
            try:
                self.restore()
            except ProxyApplyError:
                logger.exception("Failed to restore previous snapshot before apply; continuing")

        snapshot = _capture_snapshot(backend)
        payload: dict[str, Any] = {
            "version": SNAPSHOT_VERSION,
            "backend": backend,
            "snapshot": snapshot,
        }
        _write_snapshot_atomic(self.snapshot_path, payload)

        try:
            _apply_runtime_proxy(backend, cfg)
            status = _verify_apply(backend, cfg)
            logger.info(
                "System proxy applied and verified: mode=%s http=%s:%s socks=%s:%s",
                status.mode,
                status.http_host,
                status.http_port,
                status.socks_host,
                status.socks_port,
            )
            return status
        except ProxyApplyError:
            logger.exception("System proxy apply failed; attempting rollback")
            rollback_ok = False
            try:
                _restore_snapshot(backend, snapshot)
                _verify_restore(backend, snapshot)
                rollback_ok = True
            except ProxyApplyError:
                logger.exception("Failed to rollback system proxy settings")

            if rollback_ok:
                try:
                    self.snapshot_path.unlink()
                except OSError:
                    logger.exception(
                        "Failed to remove snapshot after successful rollback: %s",
                        self.snapshot_path,
                    )
            raise

    def force_no_proxy(self, *, ignore_hosts: list[str] | None = None) -> SystemProxyStatus:
        backend = self._ensure_backend()
        _force_no_proxy(backend, ignore_hosts=ignore_hosts)
        status = _verify_no_proxy(backend)
        logger.warning(
            "Applied no-proxy mode: mode=%s http=%s:%s socks=%s:%s",
            status.mode,
            status.http_host,
            status.http_port,
            status.socks_host,
            status.socks_port,
        )
        return status

    def _fallback_restore_no_proxy(self, reason: str) -> SystemProxyStatus:
        logger.warning("%s -> fallback restore to mode='none'", reason)
        try:
            if self.snapshot_path.exists():
                self.snapshot_path.unlink()
        except OSError:
            logger.exception("Failed to remove invalid snapshot: %s", self.snapshot_path)
        return self.force_no_proxy()

    def restore(self) -> SystemProxyStatus:
        if not self.snapshot_path.exists():
            return self._fallback_restore_no_proxy("System proxy snapshot missing")

        try:
            data = load_json(self.snapshot_path, None)
        except Exception as exc:
            logger.exception("Failed to load system proxy snapshot: %s", self.snapshot_path)
            return self._fallback_restore_no_proxy(f"Snapshot read failed: {exc}")

        if not isinstance(data, dict):
            return self._fallback_restore_no_proxy("System proxy snapshot is corrupt")

        snapshot_backend = data.get("backend")
        preferred_backend: ProxyBackendName | None = None
        if snapshot_backend in {"gio", "gsettings"}:
            preferred_backend = cast(ProxyBackendName, snapshot_backend)

        snapshot = _normalize_snapshot(data.get("snapshot"))
        if snapshot is None:
            return self._fallback_restore_no_proxy("System proxy snapshot payload is invalid")

        backend = self._ensure_backend(preferred=preferred_backend)
        _restore_snapshot(backend, snapshot)
        status = _verify_restore(backend, snapshot)

        try:
            self.snapshot_path.unlink()
        except OSError:
            logger.exception("Failed to remove system proxy snapshot: %s", self.snapshot_path)

        return status

    def repair_stale_loopback_proxy(self) -> bool:
        if self.snapshot_path.exists():
            return False

        try:
            backend = self._ensure_backend()
        except ProxyApplyError:
            return False

        status = _read_status(backend)
        if status.mode != "manual":
            return False

        host = status.http_host
        port = status.http_port
        if not _is_loopback_host(host) or port <= 0:
            return False

        if _is_tcp_endpoint_reachable(host, port, timeout_s=0.25):
            return False

        ignore_hosts = cast(
            list[str],
            _read_setting_value(backend, _IGNORE_HOSTS_SPEC, allow_missing=False),
        )
        self.force_no_proxy(ignore_hosts=ignore_hosts)
        return True
