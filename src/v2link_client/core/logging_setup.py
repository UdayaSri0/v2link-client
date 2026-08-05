"""Logging configuration and redaction helpers."""

from __future__ import annotations

import logging
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path
from urllib.parse import urlparse

from v2link_client.core.storage import get_logs_dir

LOG_FILE_NAME = "app.log"
MAX_LOG_BYTES = 2 * 1024 * 1024
BACKUP_COUNT = 5


def setup_logging() -> Path:
    logs_dir = get_logs_dir()
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / LOG_FILE_NAME

    root = logging.getLogger()
    if root.handlers:
        return log_path

    root.setLevel(logging.INFO)

    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = RotatingFileHandler(
        log_path, maxBytes=MAX_LOG_BYTES, backupCount=BACKUP_COUNT
    )
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    root.addHandler(file_handler)
    root.addHandler(console_handler)

    return log_path


_URL_PATTERN = re.compile(r"\b[\w+.-]+://[^\s]+")
_PEM_CERTIFICATE_PATTERN = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)
_UUID_PATTERN = re.compile(
    r"(?<![0-9A-Fa-f])"
    r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
    r"(?![0-9A-Fa-f])"
)
_EMAIL_PATTERN = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?![\w.-])"
)
_SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)(\b(?:password|passwd|pwd|token|auth|authorization|subscription)\b"
    r"\s*[=:]\s*)([^\s,;&]+)"
)
_USERINFO_PATTERN = re.compile(r"(?i)(?<![\w])[^\s/@:]+:[^\s/@]+@(?=[^\s/]+)")
_LONG_HEX_PATTERN = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64,}(?![0-9A-Fa-f])")
_COLON_SHA256_PATTERN = re.compile(
    r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])"
)
_HOME_PATH_PATTERN = re.compile(r"(?<![\w/])/home/[^/\s]+(?=/|\b)")


def _redact_url(match: re.Match[str]) -> str:
    raw = match.group(0)
    parsed = urlparse(raw)
    scheme = parsed.scheme
    if scheme in {"vmess", "vless", "trojan", "ss"} and not parsed.netloc:
        return f"{scheme}://<redacted>"
    if not parsed.scheme or not parsed.hostname:
        return "<redacted>"
    host = parsed.hostname
    try:
        parsed_port = parsed.port
    except ValueError:
        return f"{scheme}://<redacted>"
    port = f":{parsed_port}" if parsed_port else ""
    return f"{scheme}://{host}{port}"


def sanitize_sensitive_text(text: str) -> str:
    """Remove common credentials from text before it reaches logs or UI.

    This deliberately preserves ordinary Xray component and field names so an
    error remains actionable. It is a defensive boundary, not a replacement
    for avoiding sensitive subprocess output in the first place.
    """
    if not text:
        return text
    sanitized = _PEM_CERTIFICATE_PATTERN.sub("<redacted>", text)
    sanitized = _URL_PATTERN.sub(_redact_url, sanitized)
    sanitized = _USERINFO_PATTERN.sub("<redacted>@", sanitized)
    sanitized = _SECRET_ASSIGNMENT_PATTERN.sub(r"\1<redacted>", sanitized)
    sanitized = _UUID_PATTERN.sub("<redacted>", sanitized)
    sanitized = _EMAIL_PATTERN.sub("<redacted>", sanitized)
    sanitized = _COLON_SHA256_PATTERN.sub("<redacted>", sanitized)
    sanitized = _LONG_HEX_PATTERN.sub("<redacted>", sanitized)
    sanitized = _HOME_PATH_PATTERN.sub("/home/<redacted>", sanitized)
    return sanitized


def redact(text: str) -> str:
    """Backward-compatible alias for the shared sensitive-text sanitizer."""
    return sanitize_sensitive_text(text)
