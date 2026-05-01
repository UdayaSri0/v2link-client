"""Human-friendly formatting helpers (bytes, speeds, durations)."""

from __future__ import annotations

from datetime import datetime


def format_bytes(num_bytes: int) -> str:
    value = float(max(0, int(num_bytes)))
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    unit = units[0]
    for next_unit in units[1:]:
        if value < 1024.0:
            break
        value /= 1024.0
        unit = next_unit
    if unit == "B":
        return f"{int(value)} {unit}"
    return f"{value:.1f} {unit}"


def format_speed(bytes_per_s: float) -> str:
    value = max(0.0, float(bytes_per_s))
    units = ["B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s"]
    unit = units[0]
    for next_unit in units[1:]:
        if value < 1024.0:
            break
        value /= 1024.0
        unit = next_unit
    if unit == "B/s":
        return f"{int(value)} {unit}"
    return f"{value:.1f} {unit}"


def format_mbps(bytes_per_s: float) -> str:
    bits_per_s = max(0.0, float(bytes_per_s)) * 8.0
    mbps = bits_per_s / 1_000_000.0
    return f"{mbps:.1f} Mbps"


def format_duration_s(seconds: float) -> str:
    total = int(max(0.0, float(seconds)))
    h = total // 3600
    m = (total % 3600) // 60
    s = total % 60
    return f"{h:02d}:{m:02d}:{s:02d}"


def format_duration(seconds: float) -> str:
    return format_duration_s(seconds)


def _parse_datetime(value: str | datetime | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def format_datetime(value: str | datetime | None) -> str:
    parsed = _parse_datetime(value)
    if parsed is None:
        return "none"
    return parsed.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def format_time_only(value: str | datetime | None) -> str:
    parsed = _parse_datetime(value)
    if parsed is None:
        return "none"
    return parsed.astimezone().strftime("%H:%M:%S")


def format_date(value: str | datetime | None) -> str:
    parsed = _parse_datetime(value)
    if parsed is None:
        text = str(value or "").strip()
        return text[:10] if text else "none"
    return parsed.astimezone().date().isoformat()
