"""Qt-facing privacy boundary for copying and saving user-visible text."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import logging
from pathlib import Path
from typing import Callable

from PyQt6.QtWidgets import QApplication

from v2link_client.core.logging_setup import limit_export_text, sanitize_sensitive_text

logger = logging.getLogger(__name__)

Sanitizer = Callable[[object | None], str]


@dataclass(frozen=True)
class TextActionResult:
    """A content-free result suitable for presentation in a UI hint."""

    succeeded: bool
    message: str
    cancelled: bool = False


def prepare_safe_text(
    text: object | None,
    *,
    sanitizer: Sanitizer = sanitize_sensitive_text,
) -> str:
    """Sanitize and UTF-8-safely bound text before it leaves the application."""
    try:
        return limit_export_text(sanitizer(text))
    except Exception:  # pragma: no cover - defensive boundary
        logger.warning("Unable to prepare text for safe export")
        return ""


def copy_sanitized_text(
    text: object | None,
    *,
    label: str,
    sanitizer: Sanitizer = sanitize_sensitive_text,
) -> TextActionResult:
    """Copy sanitized text without logging or retaining its content."""
    safe_text = prepare_safe_text(text, sanitizer=sanitizer)
    if not safe_text.strip():
        return TextActionResult(False, f"No {label} is available to copy.")

    app = QApplication.instance()
    if app is None:
        return TextActionResult(False, f"Could not copy {label}: clipboard is unavailable.")

    try:
        clipboard = app.clipboard()
        if clipboard is None:
            return TextActionResult(False, f"Could not copy {label}: clipboard is unavailable.")
        clipboard.setText(safe_text)
    except Exception:
        logger.warning("Clipboard operation failed")
        return TextActionResult(False, f"Could not copy {label}.")

    return TextActionResult(True, f"{label.capitalize()} copied successfully.")


def save_sanitized_text(
    path: str | Path | None,
    text: object | None,
    *,
    label: str,
    sanitizer: Sanitizer = sanitize_sensitive_text,
) -> TextActionResult:
    """Write sanitized UTF-8 text to a user-selected path."""
    if not path:
        return TextActionResult(False, "Save cancelled.", cancelled=True)

    safe_text = prepare_safe_text(text, sanitizer=sanitizer)
    if not safe_text.strip():
        return TextActionResult(False, f"No {label} is available to save.")

    try:
        Path(path).write_text(safe_text, encoding="utf-8")
    except (OSError, ValueError):
        logger.warning("Sanitized text save failed")
        return TextActionResult(False, f"Could not save {label}.")

    return TextActionResult(True, f"{label.capitalize()} saved successfully.")


def diagnostics_filename(now: datetime | None = None) -> str:
    """Return a deterministic, identity-free default diagnostics filename."""
    timestamp = (now or datetime.now().astimezone()).strftime("%Y%m%d-%H%M%S")
    return f"v2link-client-diagnostics-{timestamp}.txt"
