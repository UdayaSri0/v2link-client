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


def _redact_url(match: re.Match[str]) -> str:
    raw = match.group(0)
    parsed = urlparse(raw)
    scheme = parsed.scheme
    if scheme in {"vmess", "vless", "trojan", "ss"} and not parsed.netloc:
        return f"{scheme}://<redacted>"
    if not parsed.scheme or not parsed.hostname:
        return "<redacted>"
    host = parsed.hostname
    port = f":{parsed.port}" if parsed.port else ""
    return f"{scheme}://{host}{port}"


def redact(text: str) -> str:
    if not text:
        return text
    return _URL_PATTERN.sub(_redact_url, text)
