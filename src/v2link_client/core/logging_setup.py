"""Logging configuration and redaction helpers."""

from __future__ import annotations

import logging
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from v2link_client.core.storage import get_logs_dir

LOG_FILE_NAME = "app.log"
MAX_LOG_BYTES = 2 * 1024 * 1024
BACKUP_COUNT = 5
MAX_EXPORT_BYTES = 512 * 1024


class SanitizingLogFilter(logging.Filter):
    """Ensure ordinary log records cannot carry raw secret-bearing arguments."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - defensive logging boundary
            message = "Log message unavailable."
        record.msg = sanitize_sensitive_text(message)
        record.args = ()
        return True


class SanitizingFormatter(logging.Formatter):
    """Sanitize the final line, including any formatted exception traceback."""

    def __init__(
        self,
        *args: object,
        delegate: logging.Formatter | None = None,
        **kwargs: object,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._delegate = delegate

    def format(self, record: logging.LogRecord) -> str:
        formatted = (
            self._delegate.format(record)
            if self._delegate is not None
            else super().format(record)
        )
        return sanitize_sensitive_text(formatted)


def _secure_handler(handler: logging.Handler) -> None:
    if not any(isinstance(item, SanitizingLogFilter) for item in handler.filters):
        handler.addFilter(SanitizingLogFilter())
    current = handler.formatter
    if isinstance(current, SanitizingFormatter):
        return
    handler.setFormatter(SanitizingFormatter(delegate=current))


def setup_logging() -> Path:
    logs_dir = get_logs_dir()
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / LOG_FILE_NAME

    root = logging.getLogger()
    if root.handlers:
        for existing_handler in root.handlers:
            _secure_handler(existing_handler)
        return log_path

    root.setLevel(logging.INFO)

    formatter = SanitizingFormatter(
        fmt="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = RotatingFileHandler(
        log_path, maxBytes=MAX_LOG_BYTES, backupCount=BACKUP_COUNT
    )
    file_handler.setFormatter(formatter)
    _secure_handler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    _secure_handler(console_handler)

    root.addHandler(file_handler)
    root.addHandler(console_handler)

    return log_path


_URL_PATTERN = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s<>]+")
_PEM_BLOCK_PATTERN = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]+ )?(?:CERTIFICATE|PRIVATE KEY)-----.*?"
    r"(?:-----END (?:[A-Z0-9 ]+ )?(?:CERTIFICATE|PRIVATE KEY)-----|\Z)",
    re.DOTALL,
)
_UUID_PATTERN = re.compile(
    r"(?<![0-9A-Fa-f])"
    r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
    r"(?![0-9A-Fa-f])"
)
_EMAIL_PATTERN = re.compile(
    r"(?<![\w.+-])[\w.!#$%&'*+/=?^`{|}~-]+@"
    r"[\w-]+(?:\.[\w-]+)+(?![\w.-])"
)
_SECRET_KEY = (
    r"(?:access[_-]?token|api[_-]?key|x-api-key|auth(?:orization)?|"
    r"authentication-(?:user|password)|password|passwd|pwd|token|subscription|"
    r"secret|cookie|session(?:[_-]?id)?|user(?:name)?|email|key|sub)"
)
_SECRET_ASSIGNMENT_PATTERN = re.compile(
    rf"(?i)(\b{_SECRET_KEY}\b[\"']?\s*[=:]\s*)"
    r"(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;&}\]]+)"
)
_GSETTINGS_SECRET_PATTERN = re.compile(
    r"(?i)(\bauthentication-(?:user|password)\b\s+)([\"'])(.*?)(\2)"
)
_AUTH_HEADER_PATTERN = re.compile(
    r"(?im)(\b(?:proxy-)?authorization\s*:\s*)(?:bearer|basic)\s+[^\s,;]+"
)
_BEARER_PATTERN = re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]+")
_COOKIE_HEADER_PATTERN = re.compile(r"(?im)^(\s*(?:set-)?cookie\s*:\s*).+$")
_ENV_SECRET_PATTERN = re.compile(
    r"(?im)(\b[A-Z][A-Z0-9_]*(?:PASSWORD|PASSWD|PWD|TOKEN|AUTH|AUTHORIZATION|"
    r"SECRET|API_KEY|ACCESS_TOKEN|COOKIE|SESSION_ID|SUBSCRIPTION|USERNAME|EMAIL)"
    r"\s*=\s*)(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;]+)"
)
_CLI_SECRET_PATTERN = re.compile(
    rf"(?i)((?:^|\s)--?{_SECRET_KEY}\b(?:=|\s+))"
    r"(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;]+)"
)
_ENCODED_URL_PATTERN = re.compile(
    r"(?i)\b(?:https?|socks5?|vless|vmess|trojan|ss)"
    r"(?:%25|%)3A(?:%25|%)2F(?:%25|%)2F[^\s<>]+"
)
_USERINFO_PATTERN = re.compile(
    r"(?i)(?<![\w])[A-Za-z0-9._%+~-]{1,128}:[^\s/@]{1,256}@(?=[^\s/]+)"
)
_LONG_HEX_PATTERN = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{40,}(?![0-9A-Fa-f])")
_LONG_SECURITY_VALUE_PATTERN = re.compile(
    r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{43,}={0,2}"
    r"(?![A-Za-z0-9+/_=-])"
)
_COLON_SHA256_PATTERN = re.compile(
    r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])"
)
_HOME_PATH_PATTERN = re.compile(r"(?<![\w])/home/[^/\s]+(?=/|\b)")

_SHARE_SCHEMES = {"vless", "vmess", "trojan", "ss"}
_PROXY_SCHEMES = {"socks", "socks4", "socks5"}
_SENSITIVE_QUERY_KEYS = {
    "access_token",
    "api_key",
    "auth",
    "authorization",
    "email",
    "key",
    "passwd",
    "password",
    "secret",
    "session",
    "session_id",
    "sub",
    "subscription",
    "token",
    "user",
    "username",
}


def _redact_url(match: re.Match[str]) -> str:
    raw = match.group(0)
    # Avoid consuming common sentence punctuation without risking a permissive
    # URL parser exposing it again.
    trailing = ""
    while raw and raw[-1] in ".,;)]}'\"":
        trailing = raw[-1] + trailing
        raw = raw[:-1]
    try:
        parsed = urlsplit(raw)
    except (TypeError, ValueError):
        return "<redacted>"
    scheme = parsed.scheme.lower()
    if scheme in _SHARE_SCHEMES or scheme in _PROXY_SCHEMES:
        return f"{scheme}://<redacted>{trailing}"
    if scheme == "file" and parsed.path.startswith("/home/"):
        # Preserve the useful local filename; the home-path boundary below
        # replaces its account component after URL processing.
        return urlunsplit((scheme, "", parsed.path, "", "")) + trailing
    if not scheme or not parsed.hostname:
        return f"<redacted-url>{trailing}"
    try:
        parsed_port = parsed.port
    except ValueError:
        return f"{scheme}://<redacted>{trailing}"
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = f":{parsed_port}" if parsed_port else ""
    authority = f"{host}{port}"
    if parsed.username is not None or parsed.password is not None:
        return f"{scheme}://{authority}/<redacted-url>{trailing}"

    try:
        query = parse_qsl(parsed.query, keep_blank_values=True)
    except ValueError:
        return f"{scheme}://{authority}/<redacted-url>{trailing}"
    if any(key.casefold().replace("-", "_") in _SENSITIVE_QUERY_KEYS for key, _ in query):
        return f"{scheme}://{authority}/<redacted-url>{trailing}"
    subscription_host_path = host.casefold().startswith(
        ("sub.", "subscription.")
    ) and parsed.path not in {"", "/"}
    if "subscription" in parsed.path.casefold() or subscription_host_path:
        return f"{scheme}://{authority}/<redacted-url>{trailing}"
    return urlunsplit((scheme, parsed.netloc, parsed.path, parsed.query, parsed.fragment)) + trailing


def _redact_quoted_assignment(match: re.Match[str]) -> str:
    return f"{match.group(1)}{match.group(2)}<redacted>{match.group(4)}"


def sanitize_sensitive_text(text: object | None) -> str:
    """Remove common credentials before text reaches logs, UI, or exports.

    This is the application's central privacy boundary. It deliberately keeps
    ordinary component names, local ports, reason codes and field names so an
    error remains actionable. The operation is deterministic and idempotent;
    callers still should avoid collecting sensitive data in the first place.
    """
    if text is None:
        return ""
    try:
        value = text if isinstance(text, str) else str(text)
    except Exception:
        return "<redacted>"
    if not value:
        return ""
    sanitized = _PEM_BLOCK_PATTERN.sub("<redacted>", value)
    sanitized = _ENCODED_URL_PATTERN.sub("<redacted-url>", sanitized)
    sanitized = _URL_PATTERN.sub(_redact_url, sanitized)
    sanitized = _USERINFO_PATTERN.sub("<redacted>@", sanitized)
    sanitized = _AUTH_HEADER_PATTERN.sub(r"\1<redacted>", sanitized)
    sanitized = _BEARER_PATTERN.sub(r"\1<redacted>", sanitized)
    sanitized = _COOKIE_HEADER_PATTERN.sub(r"\1<redacted>", sanitized)
    sanitized = _ENV_SECRET_PATTERN.sub(r"\1<redacted>", sanitized)
    sanitized = _CLI_SECRET_PATTERN.sub(r"\1<redacted>", sanitized)
    sanitized = _GSETTINGS_SECRET_PATTERN.sub(_redact_quoted_assignment, sanitized)
    sanitized = _SECRET_ASSIGNMENT_PATTERN.sub(r"\1<redacted>", sanitized)
    sanitized = _UUID_PATTERN.sub("<redacted-id>", sanitized)
    sanitized = _EMAIL_PATTERN.sub("<redacted-email>", sanitized)
    sanitized = _COLON_SHA256_PATTERN.sub("<redacted>", sanitized)
    sanitized = _LONG_HEX_PATTERN.sub("<redacted>", sanitized)
    sanitized = _LONG_SECURITY_VALUE_PATTERN.sub("<redacted>", sanitized)
    sanitized = _HOME_PATH_PATTERN.sub("/home/<user>", sanitized)
    return sanitized


def _utf8_prefix(value: str, byte_limit: int) -> str:
    if byte_limit <= 0:
        return ""
    return value.encode("utf-8")[:byte_limit].decode("utf-8", errors="ignore")


def limit_export_text(
    text: object | None, *, max_bytes: int = MAX_EXPORT_BYTES
) -> str:
    """Sanitize and bound exported text without splitting a Unicode character."""
    sanitized = sanitize_sensitive_text(text)
    encoded = sanitized.encode("utf-8")
    if len(encoded) <= max_bytes:
        return sanitized
    suffix = f"\n[report truncated after {max_bytes} bytes]"
    suffix_size = len(suffix.encode("utf-8"))
    if max_bytes <= suffix_size:
        return _utf8_prefix(suffix, max_bytes)
    return _utf8_prefix(sanitized, max_bytes - suffix_size) + suffix


def redact(text: str) -> str:
    """Backward-compatible alias for the shared sensitive-text sanitizer."""
    return sanitize_sensitive_text(text)
