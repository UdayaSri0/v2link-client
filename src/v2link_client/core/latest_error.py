"""Small, privacy-preserving store for user-relevant application errors."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from threading import RLock
from typing import Mapping

from v2link_client import __version__
from v2link_client.core.logging_setup import limit_export_text, sanitize_sensitive_text

_INFORMATIONAL_SEVERITIES = {"debug", "info", "informational"}
_MAX_ERROR_SUMMARY_BYTES = 8 * 1024
_MAX_ERROR_DETAILS_BYTES = 128 * 1024
_MAX_CONTEXT_VALUE_BYTES = 16 * 1024
_SECRET_CONTEXT_KEYS = {
    "access_token",
    "api_key",
    "auth",
    "authorization",
    "cookie",
    "email",
    "key",
    "password",
    "passwd",
    "secret",
    "session",
    "session_id",
    "sub",
    "subscription",
    "token",
    "user",
    "username",
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_timestamp(value: datetime | None) -> datetime:
    timestamp = value or _utc_now()
    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc)


def _safe_context(context: Mapping[str, object] | None) -> tuple[tuple[str, str], ...]:
    if not context:
        return ()
    result: list[tuple[str, str]] = []
    for raw_key, raw_value in sorted(context.items(), key=lambda item: str(item[0])):
        key = sanitize_sensitive_text(raw_key).strip() or "context"
        snake_key = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key)
        normalized_key = snake_key.casefold().replace("-", "_").replace(" ", "_")
        key_parts = {part for part in normalized_key.split("_") if part}
        secret_parts = {
            "auth", "authorization", "cookie", "email", "key", "password",
            "passwd", "secret", "session", "subscription", "token", "user",
            "username",
        }
        if normalized_key in _SECRET_CONTEXT_KEYS or key_parts & secret_parts:
            value = "<redacted>"
        else:
            value = limit_export_text(raw_value, max_bytes=_MAX_CONTEXT_VALUE_BYTES)
        result.append((key, value))
    return tuple(result)


@dataclass(frozen=True, slots=True)
class LatestError:
    """A sanitized error safe to retain in UI runtime state."""

    source: str
    summary: str
    details: str
    timestamp: datetime
    severity: str = "error"
    reason_code: str | None = None
    active: bool = True
    context: tuple[tuple[str, str], ...] = ()


def format_latest_error(
    error: LatestError | None, *, application_version: str = __version__
) -> str:
    """Format one latest-error record for the same safe export pipeline."""
    if error is None or not error.active:
        return "No recent error is available to copy."
    lines = [
        "v2link-client latest error",
        "Sensitive values are redacted by default.",
        f"Application version: v{sanitize_sensitive_text(application_version).lstrip('v')}",
        f"Timestamp: {error.timestamp.isoformat(timespec='seconds')}",
        f"Source: {error.source}",
        f"Severity: {error.severity}",
        f"Summary: {error.summary}",
    ]
    if error.reason_code:
        lines.append(f"Reason code: {error.reason_code}")
    if error.details:
        lines.extend(("Details:", error.details))
    if error.context:
        lines.append("Context:")
        lines.extend(f"- {key}: {value}" for key, value in error.context)
    return limit_export_text("\n".join(lines))


class LatestErrorStore:
    """Track the newest active error per source without retaining raw details."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._sequence = 0
        self._errors: dict[str, tuple[int, LatestError]] = {}

    def record(
        self,
        source: str,
        summary: str,
        *,
        details: object | None = "",
        timestamp: datetime | None = None,
        severity: str = "error",
        reason_code: str | None = None,
        context: Mapping[str, object] | None = None,
    ) -> LatestError | None:
        """Sanitize and retain an active error; informational events are ignored."""
        normalized_severity = (
            sanitize_sensitive_text(severity).strip().casefold() or "error"
        )
        if normalized_severity in _INFORMATIONAL_SEVERITIES:
            return None
        safe_source = sanitize_sensitive_text(source).strip() or "application runtime"
        safe_reason = sanitize_sensitive_text(reason_code).strip() if reason_code else None
        error = LatestError(
            source=safe_source,
            summary=limit_export_text(
                summary, max_bytes=_MAX_ERROR_SUMMARY_BYTES
            ).strip()
            or "Operation failed.",
            details=limit_export_text(
                details, max_bytes=_MAX_ERROR_DETAILS_BYTES
            ).strip(),
            timestamp=_normalize_timestamp(timestamp),
            severity=normalized_severity,
            reason_code=safe_reason,
            context=_safe_context(context),
        )
        with self._lock:
            existing_entry = self._errors.get(safe_source)
            if existing_entry is not None:
                existing = existing_entry[1]
                if (
                    existing.summary == error.summary
                    and existing.details == error.details
                    and existing.severity == error.severity
                    and existing.reason_code == error.reason_code
                    and existing.context == error.context
                ):
                    return existing
            self._sequence += 1
            self._errors[safe_source] = (self._sequence, error)
        return error

    def clear(self, source: str) -> bool:
        """Clear only the named operation/source after its successful recovery."""
        safe_source = sanitize_sensitive_text(source).strip() or "application runtime"
        with self._lock:
            return self._errors.pop(safe_source, None) is not None

    def clear_all(self) -> None:
        with self._lock:
            self._errors.clear()

    def latest_active(self) -> LatestError | None:
        with self._lock:
            candidates = tuple(self._errors.values())
        if not candidates:
            return None
        return max(candidates, key=lambda item: (item[1].timestamp, item[0]))[1]

    def format_latest(self, *, application_version: str = __version__) -> str:
        return format_latest_error(
            self.latest_active(), application_version=application_version
        )
