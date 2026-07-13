"""Small offline chart widgets for Traffic Monitor history."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from PyQt6.QtCore import QPointF, QRectF, Qt
from PyQt6.QtGui import QColor, QFontMetrics, QPainter, QPen
from PyQt6.QtWidgets import QSizePolicy, QWidget

from v2link_client.core.humanize import format_bytes, format_speed, format_time_only
from v2link_client.core.traffic_store import DailyUsageBreakdown, ProxyTrafficSample

MAX_SESSION_CHART_POINTS = 900
SESSION_CHART_MARKER_LIMIT = 120

@dataclass(frozen=True, slots=True)
class DailyChartPoint:
    label: str
    download_bytes: int
    upload_bytes: int
    total_bytes: int


@dataclass(frozen=True, slots=True)
class SessionChartPoint:
    label: str
    download_value: float
    upload_value: float


def downsample_session_chart_points(
    points: Iterable[SessionChartPoint],
    *,
    maximum_points: int = MAX_SESSION_CHART_POINTS,
) -> list[SessionChartPoint]:
    """Min/max bucket a paired series while preserving endpoints and chronological order."""
    source = list(points)
    limit = max(2, int(maximum_points))
    if len(source) <= limit:
        return source

    # Two extrema per bucket retain peaks from both aligned series. Endpoint indices
    # are always included and final sorting preserves the original chronology.
    interior = source[1:-1]
    bucket_count = max(1, (limit - 2) // 2)
    selected_indices = {0, len(source) - 1}
    for bucket in range(bucket_count):
        start = 1 + (len(interior) * bucket // bucket_count)
        end = 1 + (len(interior) * (bucket + 1) // bucket_count)
        if end <= start:
            continue
        indices = range(start, end)
        download_peak = max(indices, key=lambda idx: (source[idx].download_value, -idx))
        upload_peak = max(range(start, end), key=lambda idx: (source[idx].upload_value, -idx))
        selected_indices.add(download_peak)
        selected_indices.add(upload_peak)

    ordered = [source[idx] for idx in sorted(selected_indices)]
    return ordered[:limit - 1] + [source[-1]] if len(ordered) > limit else ordered


def prepare_daily_chart_data(rows: Iterable[DailyUsageBreakdown]) -> list[DailyChartPoint]:
    points: list[DailyChartPoint] = []
    for row in rows:
        download = max(0, int(row.download_bytes))
        upload = max(0, int(row.upload_bytes))
        points.append(
            DailyChartPoint(
                label=row.date[5:] if len(row.date) >= 10 else row.date,
                download_bytes=download,
                upload_bytes=upload,
                total_bytes=download + upload,
            )
        )
    return points


def prepare_session_speed_chart_data(samples: Iterable[ProxyTrafficSample]) -> list[SessionChartPoint]:
    points = [
        SessionChartPoint(
            label=format_time_only(sample.timestamp),
            download_value=max(0.0, float(sample.download_bps)),
            upload_value=max(0.0, float(sample.upload_bps)),
        )
        for sample in samples
    ]
    return downsample_session_chart_points(points)


def prepare_session_cumulative_chart_data(samples: Iterable[ProxyTrafficSample]) -> list[SessionChartPoint]:
    source = list(samples)
    has_stored_totals = any(
        sample.session_uplink_bytes > 0 or sample.session_downlink_bytes > 0
        for sample in source
    )
    download_total = 0
    upload_total = 0
    points: list[SessionChartPoint] = []
    for sample in source:
        if has_stored_totals:
            download_total = max(0, int(sample.session_downlink_bytes))
            upload_total = max(0, int(sample.session_uplink_bytes))
        else:
            download_total += max(0, int(sample.downlink_delta_bytes))
            upload_total += max(0, int(sample.uplink_delta_bytes))
        points.append(
            SessionChartPoint(
                label=format_time_only(sample.timestamp),
                download_value=float(download_total),
                upload_value=float(upload_total),
            )
        )
    return downsample_session_chart_points(points)


class _ChartBase(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._empty_text = "No traffic history recorded for this range."
        self.setMinimumHeight(220)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def set_chart_height(self, height: int) -> None:
        bounded = max(120, min(360, int(height)))
        self.setMinimumHeight(bounded)
        self.setMaximumHeight(bounded)
        self.updateGeometry()
        self.update()

    def set_empty_text(self, text: str) -> None:
        self._empty_text = text
        self.update()

    def _colors(self) -> dict[str, QColor]:
        dark = self.palette().window().color().lightness() < 128
        if dark:
            return {
                "text": QColor("#cbd5e1"),
                "muted": QColor("#94a3b8"),
                "grid": QColor("#334155"),
                "download": QColor("#38bdf8"),
                "upload": QColor("#22c55e"),
                "axis": QColor("#64748b"),
            }
        return {
            "text": QColor("#0f172a"),
            "muted": QColor("#475569"),
            "grid": QColor("#cbd5e1"),
            "download": QColor("#0284c7"),
            "upload": QColor("#16a34a"),
            "axis": QColor("#64748b"),
        }

    def _plot_rect(self) -> QRectF:
        return QRectF(56, 24, max(20, self.width() - 76), max(40, self.height() - 76))

    def _draw_empty(self, painter: QPainter) -> None:
        colors = self._colors()
        painter.setPen(colors["muted"])
        painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, self._empty_text)

    def _draw_axes(self, painter: QPainter, plot: QRectF, max_value: float, *, value_kind: str) -> None:
        colors = self._colors()
        painter.setPen(QPen(colors["grid"], 1))
        metrics = QFontMetrics(painter.font())
        for idx in range(5):
            ratio = idx / 4
            y = plot.bottom() - plot.height() * ratio
            painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
            value = max_value * ratio
            label = format_speed(value) if value_kind == "speed" else format_bytes(int(value))
            painter.setPen(colors["muted"])
            painter.drawText(4, int(y - metrics.height() / 2), 48, metrics.height(), Qt.AlignmentFlag.AlignRight, label)
            painter.setPen(QPen(colors["grid"], 1))
        painter.setPen(QPen(colors["axis"], 1))
        painter.drawLine(plot.bottomLeft(), plot.bottomRight())
        painter.drawLine(plot.bottomLeft(), plot.topLeft())

    def _draw_legend(self, painter: QPainter, labels: tuple[str, str] = ("Download", "Upload")) -> None:
        colors = self._colors()
        x = int(self.width() - 190)
        y = 6
        for color_key, label in (("download", labels[0]), ("upload", labels[1])):
            painter.fillRect(x, y + 5, 14, 8, colors[color_key])
            painter.setPen(colors["text"])
            painter.drawText(x + 20, y, 80, 18, Qt.AlignmentFlag.AlignLeft, label)
            x += 92


class TrafficBarChartWidget(_ChartBase):
    def __init__(self) -> None:
        super().__init__()
        self._points: list[DailyChartPoint] = []

    def set_data(self, rows: Iterable[DailyUsageBreakdown | DailyChartPoint]) -> None:
        incoming = list(rows)
        if incoming and isinstance(incoming[0], DailyChartPoint):
            self._points = [point for point in incoming if isinstance(point, DailyChartPoint)]
        else:
            self._points = prepare_daily_chart_data(
                row for row in incoming if isinstance(row, DailyUsageBreakdown)
            )
        self.update()

    def paintEvent(self, event) -> None:  # type: ignore[override]
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        colors = self._colors()
        if not self._points:
            self._draw_empty(painter)
            painter.end()
            return

        plot = self._plot_rect()
        max_total = max((point.total_bytes for point in self._points), default=1)
        max_total = max(1, max_total)
        self._draw_axes(painter, plot, float(max_total), value_kind="bytes")
        self._draw_legend(painter)

        count = len(self._points)
        slot = plot.width() / max(1, count)
        bar_width = max(10.0, min(34.0, slot * 0.56))
        for idx, point in enumerate(self._points):
            center_x = plot.left() + slot * idx + slot / 2
            x = center_x - bar_width / 2
            total_height = (point.total_bytes / max_total) * plot.height()
            min_height = 3.0 if point.total_bytes > 0 else 0.0
            total_height = max(min_height, total_height)
            down_height = (
                total_height * (point.download_bytes / max(1, point.total_bytes))
                if point.total_bytes
                else 0.0
            )
            up_height = total_height - down_height
            y = plot.bottom() - total_height
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(colors["download"])
            painter.drawRoundedRect(QRectF(x, y, bar_width, down_height), 3, 3)
            painter.setBrush(colors["upload"])
            painter.drawRoundedRect(QRectF(x, y + down_height, bar_width, up_height), 3, 3)
            if count <= 14 or idx in {0, count - 1}:
                painter.setPen(colors["muted"])
                painter.drawText(
                    int(center_x - slot / 2),
                    int(plot.bottom() + 6),
                    int(slot),
                    18,
                    Qt.AlignmentFlag.AlignCenter,
                    point.label,
                )
            if count <= 8 and point.total_bytes > 0:
                painter.setPen(colors["text"])
                painter.drawText(
                    int(center_x - slot / 2),
                    int(max(0, y - 18)),
                    int(slot),
                    16,
                    Qt.AlignmentFlag.AlignCenter,
                    format_bytes(point.total_bytes),
                )
        painter.end()


class TrafficLineChartWidget(_ChartBase):
    def __init__(self) -> None:
        super().__init__()
        self._points: list[SessionChartPoint] = []
        self._value_kind = "speed"
        self.set_empty_text("Select a session to view traffic samples.")

    def set_data(self, points: Iterable[SessionChartPoint], *, value_kind: str = "speed") -> None:
        self._points = downsample_session_chart_points(points)
        self._value_kind = value_kind if value_kind in {"speed", "bytes"} else "speed"
        self.update()

    @property
    def points(self) -> tuple[SessionChartPoint, ...]:
        return tuple(self._points)

    @property
    def markers_enabled(self) -> bool:
        return len(self._points) <= SESSION_CHART_MARKER_LIMIT

    def paintEvent(self, event) -> None:  # type: ignore[override]
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        colors = self._colors()
        if not self._points:
            self._draw_empty(painter)
            painter.end()
            return

        plot = self._plot_rect()
        max_value = max(
            max(point.download_value, point.upload_value) for point in self._points
        )
        max_value = max(1.0, max_value)
        self._draw_axes(painter, plot, max_value, value_kind=self._value_kind)
        self._draw_legend(painter)

        def map_point(idx: int, value: float) -> QPointF:
            x = plot.left() if len(self._points) == 1 else plot.left() + (plot.width() * idx / (len(self._points) - 1))
            y = plot.bottom() - (max(0.0, value) / max_value) * plot.height()
            return QPointF(x, y)

        for key, attr in (("download", "download_value"), ("upload", "upload_value")):
            pen = QPen(colors[key], 2)
            painter.setPen(pen)
            previous: QPointF | None = None
            for idx, point in enumerate(self._points):
                current = map_point(idx, float(getattr(point, attr)))
                if previous is not None:
                    painter.drawLine(previous, current)
                if self.markers_enabled:
                    painter.setBrush(colors[key])
                    painter.drawEllipse(current, 2.4, 2.4)
                previous = current

        painter.setPen(colors["muted"])
        if self._points:
            painter.drawText(56, int(plot.bottom() + 6), 90, 18, Qt.AlignmentFlag.AlignLeft, self._points[0].label)
            painter.drawText(
                int(plot.right() - 90),
                int(plot.bottom() + 6),
                90,
                18,
                Qt.AlignmentFlag.AlignRight,
                self._points[-1].label,
            )
        painter.end()
