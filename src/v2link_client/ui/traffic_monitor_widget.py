"""Traffic Monitor UI."""

from __future__ import annotations

import logging
from typing import Iterable

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QPainter
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from v2link_client.core.humanize import format_bytes, format_mbps
from v2link_client.core.netmon_client import NetmonClient, NetmonStatus
from v2link_client.core.traffic_settings import (
    TrafficSettings,
    load_traffic_settings,
    save_traffic_settings,
)
from v2link_client.core.traffic_store import (
    AppIdentity,
    AppUsageSummary,
    DailyTrafficUsage,
    ProxyTrafficSample,
    TrafficStore,
    TrafficUsageSummary,
)

logger = logging.getLogger(__name__)


NOTICE_TEXT = (
    "Proxy/profile traffic is measured accurately through Xray. Per-application attribution is not "
    "enabled yet, so traffic from browsers, VS Code, Transmission, and other apps may appear "
    "together under the active proxy profile."
)
APP_PRIVACY_TEXT = (
    "Application traffic tracking records local process names, executable paths, and byte counters. "
    "It does not decrypt content, inspect messages, or upload data anywhere. All history is stored "
    "locally on this device."
)
APP_UNAVAILABLE_TEXT = (
    "Per-application tracking requires the optional v2link-netmon helper service. "
    "Proxy/profile tracking is still active."
)


class SortableTableItem(QTableWidgetItem):
    def __lt__(self, other: QTableWidgetItem) -> bool:
        left = self.data(Qt.ItemDataRole.UserRole)
        right = other.data(Qt.ItemDataRole.UserRole)
        if isinstance(left, (int, float)) and isinstance(right, (int, float)):
            return float(left) < float(right)
        return super().__lt__(other)


class DailyUsageChart(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._rows: list[DailyTrafficUsage] = []
        self.setMinimumHeight(180)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def set_usage(self, rows: Iterable[DailyTrafficUsage]) -> None:
        grouped: dict[str, tuple[int, int]] = {}
        for row in rows:
            up, down = grouped.get(row.date, (0, 0))
            grouped[row.date] = (up + row.uplink_bytes, down + row.downlink_bytes)
        self._rows = [
            DailyTrafficUsage(
                date=date,
                profile_id=None,
                connection_fingerprint=None,
                uplink_bytes=up,
                downlink_bytes=down,
            )
            for date, (up, down) in sorted(grouped.items())
        ]
        self.update()

    def paintEvent(self, event) -> None:  # type: ignore[override]
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = self.rect().adjusted(12, 12, -12, -24)
        if not self._rows:
            painter.setPen(QColor("#64748b"))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No traffic history yet")
            painter.end()
            return

        max_total = max((row.uplink_bytes + row.downlink_bytes for row in self._rows), default=0)
        if max_total <= 0:
            max_total = 1

        count = len(self._rows)
        gap = 5
        bar_width = max(4, int((rect.width() - gap * max(0, count - 1)) / max(1, count)))
        x = rect.left()
        up_color = QColor("#22c55e")
        down_color = QColor("#38bdf8")
        axis_color = QColor("#64748b")
        text_color = QColor("#94a3b8")

        painter.setPen(axis_color)
        painter.drawLine(rect.bottomLeft(), rect.bottomRight())

        for row in self._rows:
            total = row.uplink_bytes + row.downlink_bytes
            height = int((total / max_total) * max(1, rect.height()))
            bar_top = rect.bottom() - height
            down_height = int((row.downlink_bytes / max(1, total)) * height) if total else 0
            up_height = height - down_height

            painter.fillRect(x, bar_top, bar_width, down_height, down_color)
            painter.fillRect(x, bar_top + down_height, bar_width, up_height, up_color)

            if count <= 10 or row == self._rows[-1]:
                painter.setPen(text_color)
                painter.drawText(
                    x - 8,
                    rect.bottom() + 16,
                    bar_width + 16,
                    16,
                    Qt.AlignmentFlag.AlignCenter,
                    row.date[5:],
                )
            x += bar_width + gap

        painter.end()


class TrafficMonitorWidget(QWidget):
    settings_changed = pyqtSignal(object)

    def __init__(
        self,
        store: TrafficStore | None = None,
        *,
        settings: TrafficSettings | None = None,
        netmon_client: NetmonClient | None = None,
    ) -> None:
        super().__init__()
        self._store = store
        self._settings = settings or load_traffic_settings()
        self._netmon_client = netmon_client or NetmonClient(provider=self._settings.netmon_provider)
        self._netmon_status: NetmonStatus = self._netmon_client.get_status()
        self._current_session_id: str | None = None
        self._last_live_sample: ProxyTrafficSample | None = None
        self._last_warning: str | None = None

        self.notice_label = QLabel(NOTICE_TEXT)
        self.notice_label.setWordWrap(True)
        self.notice_label.setProperty("role", "muted")

        self.today_download_label = QLabel("0 B")
        self.today_upload_label = QLabel("0 B")
        self.session_download_label = QLabel("0 B")
        self.session_upload_label = QLabel("0 B")
        self.live_download_label = QLabel("0.0 Mbps")
        self.live_upload_label = QLabel("0.0 Mbps")

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_overview_tab(), "Overview")
        self.tabs.addTab(self._build_applications_tab(), "Applications")
        self.tabs.addTab(self._build_profiles_tab(), "Proxy Profiles")
        self.tabs.addTab(self._build_history_tab(), "History")
        self.tabs.addTab(self._build_settings_tab(), "Settings")
        self.tabs.addTab(self._build_diagnostics_tab(), "Diagnostics")

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        layout.addWidget(self.notice_label)
        layout.addWidget(self.tabs, 1)
        self.setLayout(layout)
        self.refresh()

    def set_store(self, store: TrafficStore | None) -> None:
        self._store = store
        self.refresh()

    @property
    def settings(self) -> TrafficSettings:
        return self._settings

    def set_settings(self, settings: TrafficSettings) -> None:
        self._settings = settings
        self._sync_settings_controls()
        self.refresh()

    def set_netmon_client(self, client: NetmonClient) -> None:
        self._netmon_client = client
        self.refresh()

    def set_current_session(self, session_id: str | None) -> None:
        self._current_session_id = session_id
        if session_id is None:
            self._last_live_sample = None
        self.session_id_label.setText(session_id or "none")
        self.refresh()

    def update_live_sample(self, sample: ProxyTrafficSample | None) -> None:
        if sample is None:
            self._last_live_sample = None
            self.live_upload_label.setText("0.0 Mbps")
            self.live_download_label.setText("0.0 Mbps")
            return

        self._last_live_sample = sample
        session_up = sample.session_uplink_bytes if sample.session_uplink_bytes else sample.uplink_bytes
        session_down = sample.session_downlink_bytes if sample.session_downlink_bytes else sample.downlink_bytes
        self.session_upload_label.setText(format_bytes(session_up))
        self.session_download_label.setText(format_bytes(session_down))
        self.live_upload_label.setText(format_mbps(sample.upload_bps))
        self.live_download_label.setText(format_mbps(sample.download_bps))
        self.last_sample_label.setText(sample.timestamp)
        if sample.warning:
            self.set_warning(sample.warning)

    def set_diagnostics(
        self,
        *,
        api_server: str | None,
        stats_available: bool,
        last_sample_time: str | None,
        warning: str | None,
        store_error: str | None,
    ) -> None:
        self.api_server_label.setText(api_server or "not configured")
        self.stats_available_label.setText("yes" if stats_available else "no")
        self.last_sample_label.setText(last_sample_time or "none")
        self.warning_label.setText(warning or "none")
        self.store_error_label.setText(store_error or "none")
        if warning:
            self._last_warning = warning

    def set_warning(self, warning: str | None) -> None:
        self._last_warning = warning
        self.warning_label.setText(warning or "none")

    def refresh(self) -> None:
        self._refresh_netmon_status()
        if self._store is None:
            self.db_path_label.setText("unavailable")
            self.app_tables_label.setText("unknown")
            return
        try:
            self.db_path_label.setText(str(self._store.db_path))
            self.app_tables_label.setText("yes" if self._store.app_tables_present() else "no")
            today = self._store.get_today_summary()
            self._set_today_summary(today)
            self._populate_applications()
            self._populate_profiles()
            self._populate_history()
            self._populate_current_session_from_samples()
        except Exception as exc:  # pragma: no cover - defensive UI guard
            logger.exception("Failed to refresh traffic monitor")
            self.store_error_label.setText(str(exc))

    def _build_overview_tab(self) -> QWidget:
        tab = QWidget()
        grid = QGridLayout()
        grid.setSpacing(10)
        self._add_metric(grid, 0, 0, "Today download", self.today_download_label)
        self._add_metric(grid, 0, 1, "Today upload", self.today_upload_label)
        self._add_metric(grid, 1, 0, "Current session download", self.session_download_label)
        self._add_metric(grid, 1, 1, "Current session upload", self.session_upload_label)
        self._add_metric(grid, 2, 0, "Current live download", self.live_download_label)
        self._add_metric(grid, 2, 1, "Current live upload", self.live_upload_label)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        tab.setLayout(grid)
        return tab

    def _build_profiles_tab(self) -> QWidget:
        tab = QWidget()
        self.profiles_table = QTableWidget(0, 5)
        self.profiles_table.setHorizontalHeaderLabels(["Profile", "Download", "Upload", "Total", "Last used"])
        self.profiles_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.profiles_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.profiles_table.setSortingEnabled(True)
        self.profiles_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.profiles_table)
        tab.setLayout(layout)
        return tab

    def _build_applications_tab(self) -> QWidget:
        tab = QWidget()
        self.app_status_label = QLabel(APP_UNAVAILABLE_TEXT)
        self.app_status_label.setWordWrap(True)
        self.app_status_label.setProperty("role", "hint")

        self.app_proxy_warning_label = QLabel(
            "Advanced / Optional / Requires helper service. Local proxy traffic can make Xray "
            "appear as the main network user until the helper provides process attribution."
        )
        self.app_proxy_warning_label.setWordWrap(True)
        self.app_proxy_warning_label.setProperty("role", "muted")

        self.app_privacy_label = QLabel(APP_PRIVACY_TEXT)
        self.app_privacy_label.setWordWrap(True)
        self.app_privacy_label.setProperty("role", "muted")

        self.app_filter_input = QLineEdit()
        self.app_filter_input.setPlaceholderText("Filter applications")
        self.app_filter_input.textChanged.connect(self._populate_applications)

        self.apps_table = QTableWidget(0, 7)
        self.apps_table.setHorizontalHeaderLabels(
            [
                "Application",
                "Download today",
                "Upload today",
                "Current download",
                "Current upload",
                "Last seen",
                "Confidence",
            ]
        )
        self.apps_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.apps_table.setSortingEnabled(True)
        self.apps_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)

        top_row = QHBoxLayout()
        top_row.addWidget(QLabel("Search"))
        top_row.addWidget(self.app_filter_input, 1)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        layout.addWidget(self.app_status_label)
        layout.addWidget(self.app_proxy_warning_label)
        layout.addWidget(self.app_privacy_label)
        layout.addLayout(top_row)
        layout.addWidget(self.apps_table, 1)
        tab.setLayout(layout)
        return tab

    def _build_history_tab(self) -> QWidget:
        tab = QWidget()
        self.range_selector = QComboBox()
        self.range_selector.addItem("Last 7 days", 7)
        self.range_selector.addItem("Last 30 days", 30)
        self.range_selector.currentIndexChanged.connect(self._populate_history)
        self.chart = DailyUsageChart()
        self.history_table = QTableWidget(0, 4)
        self.history_table.setHorizontalHeaderLabels(["Date", "Download", "Upload", "Total"])
        self.history_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.history_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        top_row = QHBoxLayout()
        top_row.addWidget(QLabel("Range"))
        top_row.addWidget(self.range_selector)
        top_row.addStretch(1)
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addLayout(top_row)
        layout.addWidget(self.chart)
        layout.addWidget(self.history_table, 1)
        tab.setLayout(layout)
        return tab

    def _build_diagnostics_tab(self) -> QWidget:
        tab = QWidget()
        self.db_path_label = QLabel("unknown")
        self.db_path_label.setWordWrap(True)
        self.api_server_label = QLabel("not configured")
        self.stats_available_label = QLabel("no")
        self.app_tracking_enabled_label = QLabel("no")
        self.helper_status_label = QLabel("unavailable")
        self.helper_backend_label = QLabel("unavailable")
        self.helper_endpoint_label = QLabel("not configured")
        self.helper_response_label = QLabel("none")
        self.helper_permission_label = QLabel("no")
        self.kernel_support_label = QLabel("not checked yet")
        self.app_tables_label = QLabel("unknown")
        self.session_id_label = QLabel("none")
        self.session_id_label.setWordWrap(True)
        self.last_sample_label = QLabel("none")
        self.warning_label = QLabel("none")
        self.warning_label.setWordWrap(True)
        self.store_error_label = QLabel("none")
        self.store_error_label.setWordWrap(True)
        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self.refresh)

        grid = QGridLayout()
        grid.setSpacing(8)
        labels = [
            ("Traffic DB path", self.db_path_label),
            ("Xray API server", self.api_server_label),
            ("Stats available", self.stats_available_label),
            ("App tracking setting", self.app_tracking_enabled_label),
            ("Helper installed/running", self.helper_status_label),
            ("Helper backend", self.helper_backend_label),
            ("Helper socket/API", self.helper_endpoint_label),
            ("Last helper response", self.helper_response_label),
            ("Permission state", self.helper_permission_label),
            ("Kernel support", self.kernel_support_label),
            ("DB app tables present", self.app_tables_label),
            ("Current session ID", self.session_id_label),
            ("Last sample time", self.last_sample_label),
            ("Warning", self.warning_label),
            ("Last store error", self.store_error_label),
        ]
        for row, (name, widget) in enumerate(labels):
            label = QLabel(name)
            label.setProperty("role", "muted")
            grid.addWidget(label, row, 0)
            grid.addWidget(widget, row, 1)
        grid.addWidget(refresh_button, len(labels), 0)
        grid.setColumnStretch(1, 1)
        tab.setLayout(grid)
        return tab

    def _build_settings_tab(self) -> QWidget:
        tab = QWidget()
        self.proxy_history_checkbox = QCheckBox("Enable proxy/profile history tracking")
        self.proxy_history_checkbox.setChecked(self._settings.proxy_history_enabled)
        self.proxy_history_checkbox.toggled.connect(self._save_settings_from_controls)

        self.app_tracking_checkbox = QCheckBox(
            "Enable per-application tracking (advanced / optional / requires helper service)"
        )
        self.app_tracking_checkbox.setChecked(self._settings.app_tracking_enabled)
        self.app_tracking_checkbox.toggled.connect(self._save_settings_from_controls)

        self.experimental_warning_checkbox = QCheckBox("Show experimental app attribution warning")
        self.experimental_warning_checkbox.setChecked(self._settings.show_experimental_warning)
        self.experimental_warning_checkbox.toggled.connect(self._save_settings_from_controls)

        self.retention_selector = QComboBox()
        for days in (7, 30, 90):
            self.retention_selector.addItem(f"Keep detailed samples for {days} days", days)
        self.retention_selector.setCurrentIndex(max(0, self.retention_selector.findData(self._settings.detailed_retention_days)))
        self.retention_selector.currentIndexChanged.connect(self._save_settings_from_controls)

        self.export_button = QPushButton("Export CSV")
        self.export_button.clicked.connect(self._on_export_clicked)
        self.clear_history_button = QPushButton("Clear traffic history")
        self.clear_history_button.setProperty("variant", "danger")
        self.clear_history_button.clicked.connect(self._on_clear_history_clicked)

        note = QLabel(
            "Daily totals are kept for 1 year. The GUI never runs as root; true per-application "
            "tracking will require the optional v2link-netmon helper service."
        )
        note.setWordWrap(True)
        note.setProperty("role", "muted")

        button_row = QHBoxLayout()
        button_row.addWidget(self.export_button)
        button_row.addWidget(self.clear_history_button)
        button_row.addStretch(1)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        layout.addWidget(self.proxy_history_checkbox)
        layout.addWidget(self.app_tracking_checkbox)
        layout.addWidget(self.experimental_warning_checkbox)
        layout.addWidget(QLabel("Retention"))
        layout.addWidget(self.retention_selector)
        layout.addWidget(note)
        layout.addLayout(button_row)
        layout.addStretch(1)
        tab.setLayout(layout)
        return tab

    def _add_metric(self, grid: QGridLayout, row: int, col: int, title: str, value_label: QLabel) -> None:
        title_label = QLabel(title)
        title_label.setProperty("role", "muted")
        value_label.setProperty("role", "pill")
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        cell = QVBoxLayout()
        cell.setSpacing(4)
        cell.addWidget(title_label)
        cell.addWidget(value_label)
        wrapper = QWidget()
        wrapper.setLayout(cell)
        grid.addWidget(wrapper, row, col)

    def _set_today_summary(self, summary: TrafficUsageSummary) -> None:
        self.today_upload_label.setText(format_bytes(summary.uplink_bytes))
        self.today_download_label.setText(format_bytes(summary.downlink_bytes))

    def _populate_profiles(self) -> None:
        if self._store is None:
            return
        rows = self._store.get_profile_summaries(limit=100)
        self.profiles_table.setSortingEnabled(False)
        self.profiles_table.setRowCount(len(rows))
        for row_idx, row in enumerate(rows):
            total = row.uplink_bytes + row.downlink_bytes
            values = [
                row.profile_name or row.profile_id,
                format_bytes(row.downlink_bytes),
                format_bytes(row.uplink_bytes),
                format_bytes(total),
                row.last_seen,
            ]
            sort_values = [values[0], row.downlink_bytes, row.uplink_bytes, total, row.last_seen]
            for col_idx, value in enumerate(values):
                item = SortableTableItem(value)
                item.setData(Qt.ItemDataRole.UserRole, sort_values[col_idx])
                self.profiles_table.setItem(row_idx, col_idx, item)
        self.profiles_table.setSortingEnabled(True)
        self.profiles_table.sortItems(3, Qt.SortOrder.DescendingOrder)

    def _populate_applications(self) -> None:
        if not hasattr(self, "apps_table"):
            return
        rows: list[AppUsageSummary] = []
        if self._settings.app_tracking_enabled and self._netmon_status.running:
            live_rows = self._netmon_client.get_live_apps()
            if self._store is not None:
                for row in live_rows:
                    self._store.record_app_sample(
                        AppIdentity(
                            id=row.app_id,
                            name=row.app_name,
                            executable_path=row.executable_path,
                            pid=row.pid,
                            uid=row.uid,
                            trusted_identity=row.confidence in {"exact", "high"},
                        ),
                        rx_bytes=row.rx_bytes,
                        tx_bytes=row.tx_bytes,
                        source=row.source,
                        confidence=row.confidence,
                    )
                rows = self._store.get_today_app_usage()
            else:
                rows = live_rows
        elif self._store is not None:
            rows = self._store.get_today_app_usage()

        filter_text = self.app_filter_input.text().strip().lower() if hasattr(self, "app_filter_input") else ""
        if filter_text:
            rows = [
                row
                for row in rows
                if filter_text in row.app_name.lower() or filter_text in row.executable_path.lower()
            ]

        self.apps_table.setSortingEnabled(False)
        self.apps_table.setRowCount(len(rows))
        for row_idx, row in enumerate(rows):
            values = [
                row.app_name,
                format_bytes(row.rx_bytes),
                format_bytes(row.tx_bytes),
                format_mbps(row.download_bps),
                format_mbps(row.upload_bps),
                row.last_seen or "unknown",
                row.confidence,
            ]
            sort_values = [
                row.app_name,
                row.rx_bytes,
                row.tx_bytes,
                row.download_bps,
                row.upload_bps,
                row.last_seen or "",
                row.confidence,
            ]
            for col_idx, value in enumerate(values):
                item = SortableTableItem(value)
                item.setData(Qt.ItemDataRole.UserRole, sort_values[col_idx])
                if col_idx == 0:
                    item.setToolTip(row.executable_path)
                self.apps_table.setItem(row_idx, col_idx, item)
        self.apps_table.setSortingEnabled(True)
        self.apps_table.sortItems(1, Qt.SortOrder.DescendingOrder)

    def _populate_history(self) -> None:
        if self._store is None:
            return
        days = int(self.range_selector.currentData() or 30)
        rows = self._store.get_daily_usage(days=days)
        grouped: dict[str, tuple[int, int]] = {}
        for row in rows:
            up, down = grouped.get(row.date, (0, 0))
            grouped[row.date] = (up + row.uplink_bytes, down + row.downlink_bytes)
        table_rows = sorted(grouped.items())

        self.chart.set_usage(rows)
        self.history_table.setRowCount(len(table_rows))
        for row_idx, (date, (up, down)) in enumerate(table_rows):
            total = up + down
            values = [date, format_bytes(down), format_bytes(up), format_bytes(total)]
            sort_values = [date, down, up, total]
            for col_idx, value in enumerate(values):
                item = SortableTableItem(value)
                item.setData(Qt.ItemDataRole.UserRole, sort_values[col_idx])
                self.history_table.setItem(row_idx, col_idx, item)

    def _populate_current_session_from_samples(self) -> None:
        if self._store is None or not self._current_session_id:
            self.session_upload_label.setText("0 B")
            self.session_download_label.setText("0 B")
            return
        if (
            self._last_live_sample is not None
            and self._last_live_sample.session_id == self._current_session_id
        ):
            return
        samples = self._store.get_recent_samples(session_id=self._current_session_id, limit=1)
        if samples:
            self.update_live_sample(samples[-1])

    def _refresh_netmon_status(self) -> None:
        self._netmon_status = self._netmon_client.get_status()
        enabled = self._settings.app_tracking_enabled
        if not enabled:
            status_text = "Per-application tracking is off. Proxy/profile tracking is still active."
        elif not self._netmon_status.installed:
            status_text = APP_UNAVAILABLE_TEXT
        elif self._netmon_status.running:
            status_text = self._netmon_status.message
        else:
            status_text = "Helper is installed but not running."
        if hasattr(self, "app_status_label"):
            self.app_status_label.setText(status_text)
        if hasattr(self, "app_proxy_warning_label"):
            self.app_proxy_warning_label.setVisible(self._settings.show_experimental_warning)
        if hasattr(self, "app_tracking_enabled_label"):
            self.app_tracking_enabled_label.setText("enabled" if enabled else "disabled")
            self.helper_status_label.setText(
                f"installed={'yes' if self._netmon_status.installed else 'no'}, "
                f"running={'yes' if self._netmon_status.running else 'no'}"
            )
            self.helper_backend_label.setText(self._netmon_status.backend)
            self.helper_endpoint_label.setText(
                self._netmon_status.api_url or self._netmon_status.socket_path or "not configured"
            )
            self.helper_response_label.setText(self._netmon_status.last_response or "none")
            self.helper_permission_label.setText("ok" if self._netmon_status.permission_ok else "not available")
            self.kernel_support_label.setText(self._netmon_status.kernel_support)

    def _sync_settings_controls(self) -> None:
        if not hasattr(self, "proxy_history_checkbox"):
            return
        self.proxy_history_checkbox.blockSignals(True)
        self.app_tracking_checkbox.blockSignals(True)
        self.experimental_warning_checkbox.blockSignals(True)
        self.retention_selector.blockSignals(True)
        self.proxy_history_checkbox.setChecked(self._settings.proxy_history_enabled)
        self.app_tracking_checkbox.setChecked(self._settings.app_tracking_enabled)
        self.experimental_warning_checkbox.setChecked(self._settings.show_experimental_warning)
        index = self.retention_selector.findData(self._settings.detailed_retention_days)
        self.retention_selector.setCurrentIndex(index if index >= 0 else 1)
        self.proxy_history_checkbox.blockSignals(False)
        self.app_tracking_checkbox.blockSignals(False)
        self.experimental_warning_checkbox.blockSignals(False)
        self.retention_selector.blockSignals(False)

    def _save_settings_from_controls(self) -> None:
        provider = self._settings.netmon_provider
        self._settings = TrafficSettings(
            proxy_history_enabled=bool(self.proxy_history_checkbox.isChecked()),
            app_tracking_enabled=bool(self.app_tracking_checkbox.isChecked()),
            show_experimental_warning=bool(self.experimental_warning_checkbox.isChecked()),
            detailed_retention_days=int(self.retention_selector.currentData() or 30),
            daily_retention_days=365,
            netmon_provider=provider,
        )
        save_traffic_settings(self._settings)
        if self._settings.app_tracking_enabled:
            self._netmon_client.start_tracking()
        else:
            self._netmon_client.stop_tracking()
        self.settings_changed.emit(self._settings)
        self.refresh()

    def _on_export_clicked(self) -> None:
        if self._store is None:
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Traffic CSV",
            "traffic-history.csv",
            "CSV files (*.csv)",
        )
        if not path:
            return
        self._store.export_csv(path, range_days=365)

    def _on_clear_history_clicked(self) -> None:
        if self._store is None:
            return
        result = QMessageBox.question(
            self,
            "Clear Traffic History",
            "Clear all stored proxy/profile and application traffic history from this device?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if result != QMessageBox.StandardButton.Yes:
            return
        self._store.clear_history(include_app_tracking=True)
        self.refresh()
