"""Traffic Monitor UI."""

from __future__ import annotations

import logging
import os
from datetime import date, datetime, timedelta

from PyQt6.QtCore import QDate, Qt, QUrl, pyqtSignal
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QDateEdit,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from v2link_client.core.humanize import (
    format_bytes,
    format_datetime,
    format_duration,
    format_mbps,
    format_speed,
    format_time_only,
)
from v2link_client.core.netmon_client import NetmonClient, NetmonStatus
from v2link_client.core.traffic_settings import (
    TrafficSettings,
    load_traffic_settings,
    save_traffic_settings,
)
from v2link_client.core.traffic_store import (
    AppIdentity,
    AppUsageSummary,
    DailyUsageBreakdown,
    ProxySessionDetail,
    ProxySessionSummary,
    ProxyTrafficSample,
    TrafficStore,
    TrafficUsageSummary,
)
from v2link_client.ui.traffic_chart_widget import (
    TrafficBarChartWidget,
    TrafficLineChartWidget,
    prepare_session_cumulative_chart_data,
    prepare_session_speed_chart_data,
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
NOTICE_COMPACT_TEXT = (
    "Proxy/profile traffic is measured through Xray. Per-app attribution requires the optional helper."
)
NOTICE_DETAILS_TEXT = (
    "Proxy/profile traffic is measured through Xray. Per-app attribution requires the optional "
    "v2link-netmon helper. Local proxy traffic may appear under Xray, and all history is stored "
    "locally on this device."
)
TRAFFIC_MONITOR_DOCS_URL = "https://github.com/UdayaSri0/v2link-client/blob/beta/docs/traffic-monitor.md"


def _wrap_scroll_area(widget: QWidget) -> QScrollArea:
    area = QScrollArea()
    area.setWidgetResizable(True)
    area.setFrameShape(QScrollArea.Shape.NoFrame)
    area.setWidget(widget)
    return area


def _elide_middle(text: str, *, max_chars: int = 96) -> str:
    cleaned = str(text)
    if len(cleaned) <= max_chars:
        return cleaned
    keep = max(8, (max_chars - 3) // 2)
    return f"{cleaned[:keep]}...{cleaned[-keep:]}"


class SortableTableItem(QTableWidgetItem):
    def __lt__(self, other: QTableWidgetItem) -> bool:
        left = self.data(Qt.ItemDataRole.UserRole)
        right = other.data(Qt.ItemDataRole.UserRole)
        if isinstance(left, (int, float)) and isinstance(right, (int, float)):
            return float(left) < float(right)
        return super().__lt__(other)


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
        self._selected_history_date: str | None = None
        self._selected_history_session_id: str | None = None
        self._history_daily_rows: list[DailyUsageBreakdown] = []
        self._history_session_rows: list[ProxySessionSummary] = []
        self._last_live_sample: ProxyTrafficSample | None = None
        self._last_warning: str | None = None
        self._layout_mode = "normal"
        self._focus_mode = False
        self._notice_expanded = False
        self._restoring_layout = False

        self.notice_label = QLabel(NOTICE_COMPACT_TEXT)
        self.notice_label.setWordWrap(True)
        self.notice_label.setProperty("role", "muted")
        self.notice_details_button = QPushButton("Details")
        self.notice_details_button.setProperty("variant", "ghost")
        self.notice_details_button.clicked.connect(self._toggle_notice_details)
        self.workspace_button = QPushButton("Workspace")
        self.workspace_button.setCheckable(True)
        self.workspace_button.setProperty("variant", "ghost")
        self.workspace_button.clicked.connect(self.toggle_workspace_mode)

        self.today_download_label = QLabel("0 B")
        self.today_upload_label = QLabel("0 B")
        self.today_total_label = QLabel("0 B")
        self.month_download_label = QLabel("0 B")
        self.month_upload_label = QLabel("0 B")
        self.month_total_label = QLabel("0 B")
        self.session_download_label = QLabel("0 B")
        self.session_upload_label = QLabel("0 B")
        self.session_total_label = QLabel("0 B")
        self.live_download_label = QLabel("0.0 Mbps")
        self.live_upload_label = QLabel("0.0 Mbps")
        self.live_total_label = QLabel("0.0 Mbps")

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_overview_tab(), "Overview")
        self.tabs.addTab(self._build_applications_tab(), "Applications")
        self.tabs.addTab(self._build_profiles_tab(), "Proxy Profiles")
        self.tabs.addTab(self._build_history_tab(), "History")
        self.tabs.addTab(self._build_settings_tab(), "Settings")
        self.tabs.addTab(self._build_diagnostics_tab(), "Diagnostics")

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        notice_row = QHBoxLayout()
        notice_row.setSpacing(6)
        notice_row.addWidget(self.notice_label, 1)
        notice_row.addWidget(self.notice_details_button)
        notice_row.addWidget(self.workspace_button)
        layout.addLayout(notice_row)
        layout.addWidget(self.tabs, 1)
        self.setLayout(layout)
        self.tabs.currentChanged.connect(lambda _idx: self._save_layout_state())
        self._apply_responsive_layout()
        self.refresh()

    def resizeEvent(self, event) -> None:  # type: ignore[override]
        super().resizeEvent(event)
        self._apply_responsive_layout()

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
            self.live_total_label.setText("0.0 Mbps")
            return

        self._last_live_sample = sample
        session_up = sample.session_uplink_bytes if sample.session_uplink_bytes else sample.uplink_bytes
        session_down = sample.session_downlink_bytes if sample.session_downlink_bytes else sample.downlink_bytes
        self.session_upload_label.setText(format_bytes(session_up))
        self.session_download_label.setText(format_bytes(session_down))
        self.session_total_label.setText(format_bytes(session_up + session_down))
        self.live_upload_label.setText(format_mbps(sample.upload_bps))
        self.live_download_label.setText(format_mbps(sample.download_bps))
        self.live_total_label.setText(format_mbps(sample.upload_bps + sample.download_bps))
        self.last_sample_label.setText(sample.timestamp)
        if sample.warning:
            self.set_warning(sample.warning)

    def set_diagnostics(
        self,
        *,
        api_server: str | None,
        stats_available: bool,
        last_stats_query_time: str | None,
        last_sample_time: str | None,
        warning: str | None,
        store_error: str | None,
    ) -> None:
        self.api_server_label.setText(api_server or "not configured")
        self.stats_available_label.setText("yes" if stats_available else "no")
        self.last_stats_query_label.setText(last_stats_query_time or "none")
        self.last_sample_label.setText(last_sample_time or "none")
        self.warning_label.setText(warning or "none")
        self.store_error_label.setText(store_error or "none")
        if warning:
            self._last_warning = warning

    def set_warning(self, warning: str | None) -> None:
        self._last_warning = warning
        self.warning_label.setText(warning or "none")

    def _is_compact_mode(self) -> bool:
        return self.window().height() < 820 and not self._is_workspace_mode()

    def _is_workspace_mode(self) -> bool:
        window = self.window()
        return bool(self._focus_mode or window.isMaximized() or (window.width() >= 1350 and window.height() >= 860))

    def toggle_workspace_mode(self) -> None:
        self._focus_mode = not self._focus_mode
        self.workspace_button.setChecked(self._focus_mode)
        self._apply_responsive_layout()
        self._save_layout_state()

    def exit_workspace_mode(self) -> None:
        if not self._focus_mode:
            return
        self._focus_mode = False
        self.workspace_button.setChecked(False)
        self._apply_responsive_layout()
        self._save_layout_state()

    def _toggle_notice_details(self) -> None:
        self._notice_expanded = not self._notice_expanded
        self._sync_notice()
        self._save_layout_state()

    def _sync_notice(self) -> None:
        compact = self._is_compact_mode()
        expanded = self._notice_expanded and not compact
        self.notice_label.setText(NOTICE_DETAILS_TEXT if expanded else NOTICE_COMPACT_TEXT)
        self.notice_details_button.setText("Less" if expanded else "Details")
        self.notice_label.setMaximumHeight(54 if expanded else 24)

    def _apply_responsive_layout(self) -> None:
        mode = "workspace" if self._is_workspace_mode() else "compact" if self._is_compact_mode() else "normal"
        if mode == self._layout_mode and not self._restoring_layout:
            self._sync_notice()
            return
        self._layout_mode = mode
        compact = mode == "compact"
        workspace = mode == "workspace"
        spacing = 4 if compact else 6
        margins = (0, 0, 0, 0)
        if self.layout() is not None:
            self.layout().setSpacing(spacing)
            self.layout().setContentsMargins(*margins)
        self._sync_notice()
        self._apply_table_bounds(compact=compact, workspace=workspace)
        self._apply_history_workspace(workspace=workspace)
        if hasattr(self, "app_privacy_label"):
            self.app_privacy_label.setVisible(not compact and bool(self._settings.show_experimental_warning))
        if hasattr(self, "app_proxy_warning_label"):
            self.app_proxy_warning_label.setVisible(not compact and bool(self._settings.show_experimental_warning))
        self.updateGeometry()

    def _apply_table_bounds(self, *, compact: bool, workspace: bool) -> None:
        row_height = 22 if compact else 24
        for table in self.findChildren(QTableWidget):
            table.verticalHeader().setDefaultSectionSize(row_height)
            table.verticalHeader().setMinimumSectionSize(18)
            table.setAlternatingRowColors(False)
            table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
            table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        if hasattr(self, "daily_chart"):
            self.daily_chart.set_chart_height(170 if compact else 300 if workspace else 230)
        if hasattr(self, "session_chart"):
            self.session_chart.set_chart_height(160 if compact else 280 if workspace else 210)
        if hasattr(self, "history_table"):
            self.history_table.setMaximumHeight(130 if compact else 220)
        if hasattr(self, "sessions_table"):
            self.sessions_table.setMaximumHeight(170 if compact else 260 if not workspace else 100000)
        if hasattr(self, "profiles_table"):
            self.profiles_table.setMinimumHeight(120)
        if hasattr(self, "apps_table"):
            self.apps_table.setMinimumHeight(120)

    def _apply_history_workspace(self, *, workspace: bool) -> None:
        if not hasattr(self, "history_main_splitter"):
            return
        if workspace:
            self.history_main_splitter.setOrientation(Qt.Orientation.Horizontal)
            if self.history_right_splitter.indexOf(self.history_sessions_section) < 0:
                self.history_right_splitter.addWidget(self.history_sessions_section)
            if self.history_right_splitter.indexOf(self.history_detail_section) < 0:
                self.history_right_splitter.addWidget(self.history_detail_section)
            if self.history_main_splitter.indexOf(self.history_daily_section) < 0:
                self.history_main_splitter.insertWidget(0, self.history_daily_section)
            if self.history_main_splitter.indexOf(self.history_right_splitter) < 0:
                self.history_main_splitter.addWidget(self.history_right_splitter)
            self.history_main_splitter.setSizes([520, 620])
            self.history_right_splitter.setSizes([280, 420])
            return

        self.history_main_splitter.setOrientation(Qt.Orientation.Vertical)
        if self.history_main_splitter.indexOf(self.history_daily_section) < 0:
            self.history_main_splitter.addWidget(self.history_daily_section)
        if self.history_main_splitter.indexOf(self.history_sessions_section) < 0:
            self.history_main_splitter.addWidget(self.history_sessions_section)
        if self.history_main_splitter.indexOf(self.history_detail_section) < 0:
            self.history_main_splitter.addWidget(self.history_detail_section)
        self.history_main_splitter.setSizes([330, 180, 280] if self._layout_mode == "compact" else [390, 220, 320])

    def _save_layout_state(self) -> dict[str, object]:
        state: dict[str, object] = {
            "traffic_tab_index": self.tabs.currentIndex() if hasattr(self, "tabs") else 0,
            "history_range": self.range_selector.currentData() if hasattr(self, "range_selector") else "7",
            "notice_expanded": bool(self._notice_expanded),
            "focus_mode": bool(self._focus_mode),
        }
        if hasattr(self, "history_main_splitter"):
            state["history_main_splitter"] = list(self.history_main_splitter.sizes())
        if hasattr(self, "history_right_splitter"):
            state["history_right_splitter"] = list(self.history_right_splitter.sizes())
        return state

    def _restore_layout_state(self, state: dict[str, object] | None) -> None:
        if not isinstance(state, dict):
            return
        self._restoring_layout = True
        main_sizes: list[int] | None = None
        right_sizes: list[int] | None = None
        try:
            index = int(state.get("traffic_tab_index", 0) or 0)
            if 0 <= index < self.tabs.count():
                self.tabs.setCurrentIndex(index)
            history_range = state.get("history_range")
            range_index = self.range_selector.findData(history_range)
            if range_index >= 0:
                self.range_selector.setCurrentIndex(range_index)
            self._notice_expanded = bool(state.get("notice_expanded", False))
            self._focus_mode = bool(state.get("focus_mode", False))
            self.workspace_button.setChecked(self._focus_mode)
            raw_main_sizes = state.get("history_main_splitter")
            if isinstance(raw_main_sizes, list):
                main_sizes = [int(size) for size in raw_main_sizes if isinstance(size, int)]
            raw_right_sizes = state.get("history_right_splitter")
            if isinstance(raw_right_sizes, list):
                right_sizes = [int(size) for size in raw_right_sizes if isinstance(size, int)]
        finally:
            self._restoring_layout = False
        self._apply_responsive_layout()
        if main_sizes:
            self.history_main_splitter.setSizes(main_sizes)
        if right_sizes:
            self.history_right_splitter.setSizes(right_sizes)

    def refresh(self) -> None:
        self._refresh_netmon_status()
        if self._store is None:
            self.db_path_label.setText("unavailable")
            self.app_tables_label.setText("unknown")
            return
        try:
            db_path_text = str(self._store.db_path)
            self.db_path_label.setText(_elide_middle(db_path_text))
            self.db_path_label.setToolTip(db_path_text)
            self.db_writable_label.setText("yes" if self._db_writable() else "no")
            self.app_tables_label.setText("yes" if self._store.app_tables_present() else "no")
            today = self._store.get_today_summary()
            month = self._store.get_month_summary()
            self._set_today_summary(today)
            self._set_month_summary(month)
            self._populate_applications()
            self._populate_profiles()
            self._populate_history()
            self._populate_current_session_from_samples()
            self._populate_overview_recent_sessions()
            self._populate_history_diagnostics()
        except Exception as exc:  # pragma: no cover - defensive UI guard
            logger.exception("Failed to refresh traffic monitor")
            self.store_error_label.setText(str(exc))

    def _build_overview_tab(self) -> QWidget:
        tab = QWidget()
        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self.refresh)
        export_button = QPushButton("Export CSV")
        export_button.clicked.connect(self._on_export_clicked)

        actions = QHBoxLayout()
        actions.addWidget(refresh_button)
        actions.addWidget(export_button)
        actions.addStretch(1)

        grid = QGridLayout()
        grid.setSpacing(10)
        self._add_metric_group(
            grid,
            0,
            0,
            "Today",
            [
                ("Download", self.today_download_label),
                ("Upload", self.today_upload_label),
                ("Total", self.today_total_label),
            ],
        )
        self._add_metric_group(
            grid,
            0,
            1,
            "Current Session",
            [
                ("Download", self.session_download_label),
                ("Upload", self.session_upload_label),
                ("Total", self.session_total_label),
            ],
        )
        self._add_metric_group(
            grid,
            1,
            0,
            "This Month",
            [
                ("Download", self.month_download_label),
                ("Upload", self.month_upload_label),
                ("Total", self.month_total_label),
            ],
        )
        self._add_metric_group(
            grid,
            1,
            1,
            "Live Speed",
            [
                ("Download", self.live_download_label),
                ("Upload", self.live_upload_label),
                ("Total", self.live_total_label),
            ],
        )
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        self.overview_status_label = QLabel("No active proxy session. Start the proxy to begin tracking live usage.")
        self.overview_status_label.setProperty("role", "muted")
        self.overview_status_label.setWordWrap(True)
        self.overview_recent_table = QTableWidget(0, 5)
        self.overview_recent_table.setHorizontalHeaderLabels(["Start", "Duration", "Profile", "Download", "Upload"])
        self.overview_recent_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.overview_recent_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.overview_recent_table.setMaximumHeight(150)
        layout = QVBoxLayout()
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(8)
        layout.addLayout(actions)
        layout.addLayout(grid)
        layout.addWidget(self.overview_status_label)
        layout.addWidget(QLabel("Recent Sessions"))
        layout.addWidget(self.overview_recent_table)
        tab.setLayout(layout)
        return _wrap_scroll_area(tab)

    def _build_profiles_tab(self) -> QWidget:
        tab = QWidget()
        self.profiles_table = QTableWidget(0, 5)
        self.profiles_table.setHorizontalHeaderLabels(["Profile", "Download", "Upload", "Total", "Last used"])
        self.profiles_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for col in (1, 2, 3):
            self.profiles_table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        self.profiles_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.profiles_table.setSortingEnabled(True)
        self.profiles_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.profiles_empty_label = QLabel("No traffic recorded yet. Start a proxy session to begin tracking.")
        self.profiles_empty_label.setProperty("role", "muted")
        self.profiles_empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout = QVBoxLayout()
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)
        layout.addWidget(self.profiles_empty_label)
        layout.addWidget(self.profiles_table, 1)
        tab.setLayout(layout)
        return tab

    def _build_applications_tab(self) -> QWidget:
        tab = QWidget()
        self.app_status_label = QLabel(APP_UNAVAILABLE_TEXT)
        self.app_status_label.setWordWrap(True)
        self.app_status_label.setProperty("role", "hint")
        self.app_status_title_label = QLabel("Per-application tracking helper is not installed")
        self.app_status_title_label.setProperty("role", "hint")

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
        self.apps_empty_label = QLabel("Per-application helper is not installed.")
        self.apps_empty_label.setProperty("role", "muted")
        self.apps_empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        docs_button = QPushButton("Open documentation")
        docs_button.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(TRAFFIC_MONITOR_DOCS_URL)))
        helper_refresh_button = QPushButton("Refresh helper status")
        helper_refresh_button.clicked.connect(self.refresh)
        copy_diag_button = QPushButton("Copy diagnostics")
        copy_diag_button.clicked.connect(self._copy_helper_diagnostics)

        card_actions = QHBoxLayout()
        card_actions.addWidget(docs_button)
        card_actions.addWidget(helper_refresh_button)
        card_actions.addWidget(copy_diag_button)
        card_actions.addStretch(1)

        self.app_helper_card = QWidget()
        card_layout = QVBoxLayout()
        card_layout.setContentsMargins(8, 8, 8, 8)
        card_layout.setSpacing(6)
        card_layout.addWidget(self.app_status_title_label)
        card_layout.addWidget(self.app_status_label)
        card_layout.addLayout(card_actions)
        self.app_helper_card.setLayout(card_layout)

        top_row = QHBoxLayout()
        top_row.addWidget(QLabel("Search"))
        top_row.addWidget(self.app_filter_input, 1)
        self.app_search_row = QWidget()
        self.app_search_row.setLayout(top_row)

        layout = QVBoxLayout()
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)
        layout.addWidget(self.app_helper_card)
        layout.addWidget(self.app_proxy_warning_label)
        layout.addWidget(self.app_privacy_label)
        layout.addWidget(self.app_search_row)
        layout.addWidget(self.apps_empty_label)
        layout.addWidget(self.apps_table, 1)
        tab.setLayout(layout)
        return _wrap_scroll_area(tab)

    def _build_history_tab(self) -> QWidget:
        tab = QWidget()
        self.range_selector = QComboBox()
        self.range_selector.addItem("Today", "today")
        self.range_selector.addItem("Last 7 days", "7")
        self.range_selector.addItem("Last 30 days", "30")
        self.range_selector.addItem("This month", "month")
        self.range_selector.addItem("Custom date range", "custom")
        self.range_selector.setCurrentIndex(1)
        self.range_selector.currentIndexChanged.connect(self._on_history_range_changed)

        today = QDate.currentDate()
        self.history_start_date = QDateEdit(today.addDays(-6))
        self.history_start_date.setCalendarPopup(True)
        self.history_start_date.dateChanged.connect(self._on_history_dates_changed)
        self.history_end_date = QDateEdit(today)
        self.history_end_date.setCalendarPopup(True)
        self.history_end_date.dateChanged.connect(self._on_history_dates_changed)

        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self._populate_history)
        self.history_export_selector = QComboBox()
        self.history_export_selector.addItem("Daily summary CSV", "daily")
        self.history_export_selector.addItem("Session summary CSV", "sessions")
        self.history_export_selector.addItem("Selected session samples CSV", "samples")
        export_button = QPushButton("Export CSV")
        export_button.clicked.connect(self._on_history_export_clicked)

        self.history_total_download_label = QLabel("0 B")
        self.history_total_upload_label = QLabel("0 B")
        self.history_total_traffic_label = QLabel("0 B")
        self.history_session_count_label = QLabel("0")
        self.history_most_active_day_label = QLabel("none")
        self.history_average_session_label = QLabel("0 B")

        summary_grid = QGridLayout()
        summary_grid.setSpacing(8)
        self._add_metric_group(
            summary_grid,
            0,
            0,
            "Selected Range",
            [
                ("Download", self.history_total_download_label),
                ("Upload", self.history_total_upload_label),
                ("Total", self.history_total_traffic_label),
            ],
        )
        self._add_metric_group(
            summary_grid,
            0,
            1,
            "Sessions",
            [
                ("Count", self.history_session_count_label),
                ("Most active day", self.history_most_active_day_label),
                ("Average usage", self.history_average_session_label),
            ],
        )

        self.daily_chart = TrafficBarChartWidget()
        self.daily_chart.set_empty_text("No traffic history recorded for this range.")

        self.history_table = QTableWidget(0, 7)
        self.history_table.setHorizontalHeaderLabels(
            ["Date", "Sessions", "First session", "Last session", "Download", "Upload", "Total"]
        )
        self.history_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.history_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.history_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.history_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self.history_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.history_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.history_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.history_table.itemSelectionChanged.connect(self._on_history_date_selected)

        self.sessions_table = QTableWidget(0, 9)
        self.sessions_table.setHorizontalHeaderLabels(
            ["Start time", "End time", "Duration", "Profile", "Download", "Upload", "Total", "Average speed", "Status"]
        )
        self.sessions_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.sessions_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.sessions_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.sessions_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.sessions_table.itemSelectionChanged.connect(self._on_history_session_selected)

        self.session_chart_mode = QComboBox()
        self.session_chart_mode.addItem("Speed view", "speed")
        self.session_chart_mode.addItem("Cumulative usage view", "bytes")
        self.session_chart_mode.currentIndexChanged.connect(self._refresh_selected_session_detail)
        self.session_chart = TrafficLineChartWidget()

        self.session_detail_labels: dict[str, QLabel] = {}
        detail_grid = QGridLayout()
        detail_grid.setHorizontalSpacing(10)
        detail_grid.setVerticalSpacing(4)
        detail_names = [
            ("Profile", "profile"),
            ("Start time", "start"),
            ("End time", "end"),
            ("Duration", "duration"),
            ("Download", "download"),
            ("Upload", "upload"),
            ("Total", "total"),
            ("Peak download speed", "peak_download"),
            ("Peak upload speed", "peak_upload"),
            ("Average download speed", "avg_download"),
            ("Average upload speed", "avg_upload"),
            ("API server", "api"),
            ("SOCKS port", "socks"),
            ("HTTP port", "http"),
            ("Status", "status"),
        ]
        for idx, (label_text, key) in enumerate(detail_names):
            col_group = idx % 3
            row_idx = idx // 3
            label_col = col_group * 2
            title = QLabel(label_text)
            title.setProperty("role", "muted")
            value = QLabel("none")
            value.setWordWrap(True)
            self.session_detail_labels[key] = value
            detail_grid.addWidget(title, row_idx, label_col)
            detail_grid.addWidget(value, row_idx, label_col + 1)
            detail_grid.setColumnStretch(label_col + 1, 1)

        self.history_empty_label = QLabel("No traffic history recorded for this range.")
        self.history_empty_label.setProperty("role", "muted")
        self.history_empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        top_row = QHBoxLayout()
        top_row.addWidget(QLabel("Range"))
        top_row.addWidget(self.range_selector)
        top_row.addWidget(QLabel("From"))
        top_row.addWidget(self.history_start_date)
        top_row.addWidget(QLabel("To"))
        top_row.addWidget(self.history_end_date)
        top_row.addWidget(refresh_button)
        top_row.addStretch(1)
        top_row.addWidget(self.history_export_selector)
        top_row.addWidget(export_button)

        self.history_daily_section = QWidget()
        daily_layout = QVBoxLayout()
        daily_layout.setContentsMargins(0, 0, 0, 0)
        daily_layout.setSpacing(4)
        daily_layout.addWidget(QLabel("Daily Usage"))
        daily_layout.addWidget(self.daily_chart)
        daily_layout.addWidget(self.history_empty_label)
        daily_layout.addWidget(self.history_table)
        self.history_daily_section.setLayout(daily_layout)

        self.history_sessions_section = QWidget()
        session_layout = QVBoxLayout()
        session_layout.setContentsMargins(0, 0, 0, 0)
        session_layout.setSpacing(4)
        session_layout.addWidget(QLabel("Sessions for Selected Date"))
        session_layout.addWidget(self.sessions_table)
        self.history_sessions_section.setLayout(session_layout)

        self.history_detail_section = QWidget()
        detail_layout = QVBoxLayout()
        detail_layout.setContentsMargins(0, 0, 0, 0)
        detail_layout.setSpacing(4)
        detail_layout.addWidget(QLabel("Selected Session Details"))
        mode_row = QHBoxLayout()
        mode_row.addWidget(QLabel("Chart"))
        mode_row.addWidget(self.session_chart_mode)
        mode_row.addStretch(1)
        detail_layout.addLayout(mode_row)
        detail_layout.addWidget(self.session_chart)
        detail_layout.addLayout(detail_grid)
        self.history_detail_section.setLayout(detail_layout)

        self.history_right_splitter = QSplitter(Qt.Orientation.Vertical)
        self.history_right_splitter.addWidget(self.history_sessions_section)
        self.history_right_splitter.addWidget(self.history_detail_section)
        self.history_right_splitter.setSizes([260, 360])

        self.history_main_splitter = QSplitter(Qt.Orientation.Vertical)
        self.history_main_splitter.addWidget(self.history_daily_section)
        self.history_main_splitter.addWidget(self.history_sessions_section)
        self.history_main_splitter.addWidget(self.history_detail_section)
        self.history_main_splitter.setSizes([360, 210, 300])
        self.history_main_splitter.splitterMoved.connect(lambda _pos, _index: self._save_layout_state())
        self.history_right_splitter.splitterMoved.connect(lambda _pos, _index: self._save_layout_state())

        layout = QVBoxLayout()
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)
        layout.addLayout(top_row)
        layout.addLayout(summary_grid)
        layout.addWidget(self.history_main_splitter, 1)
        tab.setLayout(layout)
        self._on_history_range_changed()
        return _wrap_scroll_area(tab)

    def _build_diagnostics_tab(self) -> QWidget:
        tab = QWidget()
        self.db_path_label = QLabel("unknown")
        self.db_path_label.setWordWrap(True)
        self.db_writable_label = QLabel("unknown")
        self.api_server_label = QLabel("not configured")
        self.stats_available_label = QLabel("no")
        self.last_stats_query_label = QLabel("none")
        self.app_tracking_enabled_label = QLabel("no")
        self.helper_status_label = QLabel("unavailable")
        self.helper_backend_label = QLabel("unavailable")
        self.helper_endpoint_label = QLabel("not configured")
        self.helper_response_label = QLabel("none")
        self.helper_error_label = QLabel("none")
        self.helper_error_label.setWordWrap(True)
        self.helper_permission_label = QLabel("no")
        self.kernel_support_label = QLabel("not checked yet")
        self.app_tables_label = QLabel("unknown")
        self.session_id_label = QLabel("none")
        self.session_id_label.setWordWrap(True)
        self.recorded_sessions_label = QLabel("0")
        self.recorded_samples_label = QLabel("0")
        self.oldest_session_label = QLabel("none")
        self.newest_session_label = QLabel("none")
        self.last_daily_aggregation_label = QLabel("on sample write")
        self.db_file_size_label = QLabel("0 B")
        self.unfinished_sessions_label = QLabel("0")
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
            ("Traffic DB writable", self.db_writable_label),
            ("Xray API server", self.api_server_label),
            ("Stats available", self.stats_available_label),
            ("Last stats query time", self.last_stats_query_label),
            ("App tracking setting", self.app_tracking_enabled_label),
            ("Helper installed/running", self.helper_status_label),
            ("Helper backend", self.helper_backend_label),
            ("Helper socket/API", self.helper_endpoint_label),
            ("Last helper response", self.helper_response_label),
            ("Last helper error", self.helper_error_label),
            ("Permission state", self.helper_permission_label),
            ("Kernel support", self.kernel_support_label),
            ("DB app tables present", self.app_tables_label),
            ("Current session ID", self.session_id_label),
            ("Recorded sessions", self.recorded_sessions_label),
            ("Recorded samples", self.recorded_samples_label),
            ("Oldest recorded session", self.oldest_session_label),
            ("Newest recorded session", self.newest_session_label),
            ("Last daily aggregation time", self.last_daily_aggregation_label),
            ("Database file size", self.db_file_size_label),
            ("Unfinished sessions", self.unfinished_sessions_label),
            ("Last sample time", self.last_sample_label),
            ("Warning", self.warning_label),
            ("Last store error", self.store_error_label),
        ]
        for row, (name, widget) in enumerate(labels):
            label = QLabel(name)
            label.setProperty("role", "muted")
            widget.setToolTip(widget.text() if isinstance(widget, QLabel) else "")
            grid.addWidget(label, row, 0)
            grid.addWidget(widget, row, 1)
        grid.addWidget(refresh_button, len(labels), 0)
        grid.setColumnStretch(1, 1)
        grid.setContentsMargins(6, 6, 6, 6)
        tab.setLayout(grid)
        return _wrap_scroll_area(tab)

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
        self.retention_selector.addItem("Keep detailed samples forever", 0)
        self.retention_selector.setCurrentIndex(max(0, self.retention_selector.findData(self._settings.detailed_retention_days)))
        self.retention_selector.currentIndexChanged.connect(self._save_settings_from_controls)

        self.summary_retention_selector = QComboBox()
        self.summary_retention_selector.addItem("Keep daily/session summaries for 1 year", 365)
        self.summary_retention_selector.addItem("Keep daily/session summaries forever", 0)
        summary_index = self.summary_retention_selector.findData(self._settings.daily_retention_days)
        self.summary_retention_selector.setCurrentIndex(summary_index if summary_index >= 0 else 0)
        self.summary_retention_selector.currentIndexChanged.connect(self._save_settings_from_controls)

        self.export_button = QPushButton("Export CSV")
        self.export_button.clicked.connect(self._on_export_clicked)
        self.clear_history_button = QPushButton("Clear traffic history")
        self.clear_history_button.setProperty("variant", "danger")
        self.clear_history_button.clicked.connect(self._on_clear_history_clicked)

        note = QLabel(
            "Detailed sample retention only removes old per-sample rows; session and daily summaries stay available. "
            "The GUI never runs as root; true per-application "
            "tracking will require the optional v2link-netmon helper service."
        )
        note.setWordWrap(True)
        note.setProperty("role", "muted")

        button_row = QHBoxLayout()
        button_row.addWidget(self.export_button)
        button_row.addWidget(self.clear_history_button)
        button_row.addStretch(1)

        layout = QVBoxLayout()
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(8)
        layout.addWidget(QLabel("Tracking"))
        layout.addWidget(self.proxy_history_checkbox)
        layout.addWidget(self.app_tracking_checkbox)
        layout.addWidget(self.experimental_warning_checkbox)
        layout.addWidget(QLabel("Retention"))
        layout.addWidget(self.retention_selector)
        layout.addWidget(self.summary_retention_selector)
        layout.addWidget(note)
        layout.addWidget(QLabel("Export / Maintenance"))
        layout.addLayout(button_row)
        tab.setLayout(layout)
        return _wrap_scroll_area(tab)

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

    def _add_metric_group(
        self,
        grid: QGridLayout,
        row: int,
        col: int,
        title: str,
        metrics: list[tuple[str, QLabel]],
    ) -> None:
        title_label = QLabel(title)
        title_label.setProperty("role", "hint")
        group = QGridLayout()
        group.setSpacing(6)
        group.addWidget(title_label, 0, 0, 1, 2)
        for idx, (label_text, value_label) in enumerate(metrics, start=1):
            label = QLabel(label_text)
            label.setProperty("role", "muted")
            value_label.setProperty("role", "pill")
            value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            group.addWidget(label, idx, 0)
            group.addWidget(value_label, idx, 1)
        wrapper = QWidget()
        wrapper.setLayout(group)
        grid.addWidget(wrapper, row, col)

    def _set_today_summary(self, summary: TrafficUsageSummary) -> None:
        self.today_upload_label.setText(format_bytes(summary.uplink_bytes))
        self.today_download_label.setText(format_bytes(summary.downlink_bytes))
        self.today_total_label.setText(format_bytes(summary.uplink_bytes + summary.downlink_bytes))

    def _set_month_summary(self, summary: TrafficUsageSummary) -> None:
        self.month_upload_label.setText(format_bytes(summary.uplink_bytes))
        self.month_download_label.setText(format_bytes(summary.downlink_bytes))
        self.month_total_label.setText(format_bytes(summary.uplink_bytes + summary.downlink_bytes))

    def _populate_profiles(self) -> None:
        if self._store is None:
            return
        rows = self._store.get_profile_summaries(limit=100)
        self.profiles_empty_label.setVisible(not rows)
        self.profiles_table.setVisible(bool(rows))
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
                item.setToolTip(value)
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
        self.apps_empty_label.setVisible(not rows)
        self.apps_table.setVisible(bool(rows))
        helper_available = self._netmon_status.installed or self._netmon_status.running
        if hasattr(self, "app_search_row"):
            self.app_search_row.setVisible(bool(rows) or helper_available)
        if hasattr(self, "app_status_title_label"):
            if not self._netmon_status.installed:
                self.app_status_title_label.setText("Per-application tracking helper is not installed")
            elif not self._netmon_status.running:
                self.app_status_title_label.setText("Per-application tracking helper is not running")
            else:
                self.app_status_title_label.setText("Per-application tracking helper is available")
        if not rows:
            if self._settings.app_tracking_enabled and not self._netmon_status.installed:
                self.apps_empty_label.setText("Per-application helper is not installed.")
            elif self._settings.app_tracking_enabled and not self._netmon_status.running:
                self.apps_empty_label.setText("Per-application helper is not running.")
            elif self._settings.app_tracking_enabled:
                self.apps_empty_label.setText("No application traffic recorded yet.")
            else:
                self.apps_empty_label.setText("Per-application tracking is off.")
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
                item.setToolTip(value)
                if col_idx == 0:
                    item.setToolTip(row.executable_path)
                self.apps_table.setItem(row_idx, col_idx, item)
        self.apps_table.setSortingEnabled(True)
        self.apps_table.sortItems(1, Qt.SortOrder.DescendingOrder)

    def _populate_history(self) -> None:
        if self._store is None:
            return
        start_date, end_date = self._history_range_dates()
        self._history_daily_rows = self._store.get_daily_usage_breakdown_for_range(start_date, end_date)
        self._history_session_rows = self._store.get_sessions_for_range(start_date, end_date)

        rows = self._history_daily_rows
        self._update_history_summary(rows, self._history_session_rows)
        self.history_empty_label.setVisible(not rows)
        self.history_table.setVisible(bool(rows))
        self.daily_chart.set_data(rows)

        self.history_table.blockSignals(True)
        self.history_table.setSortingEnabled(False)
        self.history_table.setRowCount(len(rows))
        for row_idx, row in enumerate(rows):
            values = [
                row.date,
                str(row.session_count),
                format_time_only(row.first_session_at),
                format_time_only(row.last_session_at),
                format_bytes(row.download_bytes),
                format_bytes(row.upload_bytes),
                format_bytes(row.total_bytes),
            ]
            sort_values = [
                row.date,
                row.session_count,
                row.first_session_at or "",
                row.last_session_at or "",
                row.download_bytes,
                row.upload_bytes,
                row.total_bytes,
            ]
            for col_idx, value in enumerate(values):
                item = SortableTableItem(value)
                item.setData(Qt.ItemDataRole.UserRole, sort_values[col_idx])
                item.setData(Qt.ItemDataRole.UserRole + 1, row.date)
                item.setToolTip(value)
                self.history_table.setItem(row_idx, col_idx, item)
        self.history_table.setSortingEnabled(True)
        self.history_table.blockSignals(False)

        target_date = self._selected_history_date
        available_dates = [row.date for row in rows]
        if target_date not in available_dates:
            today = date.today().isoformat()
            target_date = today if today in available_dates else (available_dates[-1] if available_dates else None)
        self._select_history_date(target_date)

    def _history_range_dates(self) -> tuple[str, str]:
        start = self.history_start_date.date().toPyDate().isoformat()
        end = self.history_end_date.date().toPyDate().isoformat()
        if end < start:
            return end, start
        return start, end

    def _on_history_range_changed(self) -> None:
        value = self.range_selector.currentData()
        today = date.today()
        if value == "today":
            start = end = today
        elif value == "30":
            start = today - timedelta(days=29)
            end = today
        elif value == "month":
            start = today.replace(day=1)
            end = today
        elif value == "custom":
            self.history_start_date.setEnabled(True)
            self.history_end_date.setEnabled(True)
            self._populate_history()
            return
        else:
            start = today - timedelta(days=6)
            end = today
        self.history_start_date.blockSignals(True)
        self.history_end_date.blockSignals(True)
        self.history_start_date.setDate(QDate(start.year, start.month, start.day))
        self.history_end_date.setDate(QDate(end.year, end.month, end.day))
        self.history_start_date.blockSignals(False)
        self.history_end_date.blockSignals(False)
        self.history_start_date.setEnabled(False)
        self.history_end_date.setEnabled(False)
        self._populate_history()

    def _on_history_dates_changed(self) -> None:
        if self.range_selector.currentData() == "custom":
            self._populate_history()

    def _select_history_date(self, selected_date: str | None) -> None:
        self._selected_history_date = selected_date
        self.history_table.blockSignals(True)
        self.history_table.clearSelection()
        if selected_date:
            for row_idx in range(self.history_table.rowCount()):
                item = self.history_table.item(row_idx, 0)
                if item and item.data(Qt.ItemDataRole.UserRole + 1) == selected_date:
                    self.history_table.selectRow(row_idx)
                    break
        self.history_table.blockSignals(False)
        self._populate_sessions_for_selected_date()

    def _on_history_date_selected(self) -> None:
        selected = self.history_table.selectedItems()
        if not selected:
            return
        selected_date = selected[0].data(Qt.ItemDataRole.UserRole + 1)
        if isinstance(selected_date, str):
            self._selected_history_date = selected_date
            self._populate_sessions_for_selected_date()

    def _populate_sessions_for_selected_date(self) -> None:
        if self._store is None or not self._selected_history_date:
            self.sessions_table.setRowCount(0)
            self._selected_history_session_id = None
            self._clear_session_detail()
            return
        rows = self._store.get_sessions_for_date(self._selected_history_date)
        self._history_session_rows = rows
        self.sessions_table.blockSignals(True)
        self.sessions_table.setSortingEnabled(False)
        self.sessions_table.setRowCount(len(rows))
        for row_idx, row in enumerate(rows):
            avg_speed = row.average_download_bps + row.average_upload_bps
            values = [
                format_time_only(row.started_at),
                format_time_only(row.ended_at) if row.ended_at else "running" if row.status == "active" else "none",
                format_duration(row.duration_seconds),
                row.profile_name or row.profile_id or "Unsaved profile",
                format_bytes(row.download_bytes),
                format_bytes(row.upload_bytes),
                format_bytes(row.total_bytes),
                format_speed(avg_speed),
                row.status,
            ]
            sort_values = [
                row.started_at,
                row.ended_at or "",
                row.duration_seconds,
                row.profile_name or "",
                row.download_bytes,
                row.upload_bytes,
                row.total_bytes,
                avg_speed,
                row.status,
            ]
            for col_idx, value in enumerate(values):
                item = SortableTableItem(value)
                item.setData(Qt.ItemDataRole.UserRole, sort_values[col_idx])
                item.setData(Qt.ItemDataRole.UserRole + 1, row.session_id)
                item.setToolTip(value)
                self.sessions_table.setItem(row_idx, col_idx, item)
        self.sessions_table.setSortingEnabled(True)
        self.sessions_table.blockSignals(False)

        target_session = self._selected_history_session_id
        session_ids = [row.session_id for row in rows]
        if target_session not in session_ids:
            target_session = session_ids[-1] if session_ids else None
        self._select_history_session(target_session)

    def _select_history_session(self, session_id: str | None) -> None:
        self._selected_history_session_id = session_id
        self.sessions_table.blockSignals(True)
        self.sessions_table.clearSelection()
        if session_id:
            for row_idx in range(self.sessions_table.rowCount()):
                item = self.sessions_table.item(row_idx, 0)
                if item and item.data(Qt.ItemDataRole.UserRole + 1) == session_id:
                    self.sessions_table.selectRow(row_idx)
                    break
        self.sessions_table.blockSignals(False)
        self._refresh_selected_session_detail()

    def _on_history_session_selected(self) -> None:
        selected = self.sessions_table.selectedItems()
        if not selected:
            return
        session_id = selected[0].data(Qt.ItemDataRole.UserRole + 1)
        if isinstance(session_id, str):
            self._selected_history_session_id = session_id
            self._refresh_selected_session_detail()

    def _refresh_selected_session_detail(self) -> None:
        if self._store is None or not self._selected_history_session_id:
            self._clear_session_detail()
            return
        try:
            detail = self._store.get_session_detail(self._selected_history_session_id)
            samples = self._store.get_session_samples(self._selected_history_session_id)
        except KeyError:
            self._clear_session_detail()
            return
        self._set_session_detail(detail, samples)

    def _clear_session_detail(self) -> None:
        for label in getattr(self, "session_detail_labels", {}).values():
            label.setText("none")
        if hasattr(self, "session_chart"):
            self.session_chart.set_data([])

    def _set_session_detail(
        self,
        detail: ProxySessionDetail,
        samples: list[ProxyTrafficSample],
    ) -> None:
        labels = self.session_detail_labels
        labels["profile"].setText(detail.profile_name or detail.profile_id or "Unsaved profile")
        labels["start"].setText(format_datetime(detail.started_at))
        labels["end"].setText(format_datetime(detail.ended_at) if detail.ended_at else "running" if detail.status == "active" else "none")
        labels["duration"].setText(format_duration(detail.duration_seconds))
        labels["download"].setText(format_bytes(detail.download_bytes))
        labels["upload"].setText(format_bytes(detail.upload_bytes))
        labels["total"].setText(format_bytes(detail.total_bytes))
        labels["peak_download"].setText(format_speed(detail.peak_download_bps))
        labels["peak_upload"].setText(format_speed(detail.peak_upload_bps))
        labels["avg_download"].setText(format_speed(detail.average_download_bps))
        labels["avg_upload"].setText(format_speed(detail.average_upload_bps))
        labels["api"].setText(detail.xray_api_server or "not configured")
        labels["socks"].setText(str(detail.socks_port) if detail.socks_port is not None else "none")
        labels["http"].setText(str(detail.http_port) if detail.http_port is not None else "none")
        labels["status"].setText(detail.status)
        mode = self.session_chart_mode.currentData()
        if mode == "bytes":
            self.session_chart.set_empty_text("No samples recorded for this session.")
            self.session_chart.set_data(
                prepare_session_cumulative_chart_data(samples),
                value_kind="bytes",
            )
        else:
            self.session_chart.set_empty_text("No samples recorded for this session.")
            self.session_chart.set_data(
                prepare_session_speed_chart_data(samples),
                value_kind="speed",
            )

    def _update_history_summary(
        self,
        daily_rows: list[DailyUsageBreakdown],
        session_rows: list[ProxySessionSummary],
    ) -> None:
        download = sum(row.download_bytes for row in daily_rows)
        upload = sum(row.upload_bytes for row in daily_rows)
        total = download + upload
        session_count = sum(row.session_count for row in daily_rows)
        if session_count <= 0:
            session_count = len(session_rows)
        most_active = max(daily_rows, key=lambda row: row.total_bytes, default=None)
        average = int(total / session_count) if session_count else 0
        self.history_total_download_label.setText(format_bytes(download))
        self.history_total_upload_label.setText(format_bytes(upload))
        self.history_total_traffic_label.setText(format_bytes(total))
        self.history_session_count_label.setText(str(session_count))
        self.history_most_active_day_label.setText(
            f"{most_active.date} ({format_bytes(most_active.total_bytes)})" if most_active else "none"
        )
        self.history_average_session_label.setText(format_bytes(average))

    def _populate_current_session_from_samples(self) -> None:
        if self._store is None or not self._current_session_id:
            self.session_upload_label.setText("0 B")
            self.session_download_label.setText("0 B")
            self.session_total_label.setText("0 B")
            return
        if (
            self._last_live_sample is not None
            and self._last_live_sample.session_id == self._current_session_id
        ):
            return
        samples = self._store.get_recent_samples(session_id=self._current_session_id, limit=1)
        if samples:
            self.update_live_sample(samples[-1])

    def _populate_overview_recent_sessions(self) -> None:
        if self._store is None or not hasattr(self, "overview_recent_table"):
            return
        end_date = date.today().isoformat()
        start_date = (date.today() - timedelta(days=30)).isoformat()
        rows = self._store.get_sessions_for_range(start_date, end_date)[-5:]
        rows.reverse()
        self.overview_status_label.setVisible(self._current_session_id is None)
        self.overview_recent_table.setRowCount(len(rows))
        for row_idx, row in enumerate(rows):
            values = [
                format_datetime(row.started_at),
                format_duration(row.duration_seconds),
                row.profile_name or row.profile_id or "Unsaved profile",
                format_bytes(row.download_bytes),
                format_bytes(row.upload_bytes),
            ]
            for col_idx, value in enumerate(values):
                item = SortableTableItem(value)
                item.setToolTip(value)
                self.overview_recent_table.setItem(row_idx, col_idx, item)

    def _populate_history_diagnostics(self) -> None:
        if self._store is None or not hasattr(self, "recorded_sessions_label"):
            return
        info = self._store.get_history_diagnostics()
        self.recorded_sessions_label.setText(str(info.session_count))
        self.recorded_samples_label.setText(str(info.sample_count))
        self.oldest_session_label.setText(format_datetime(info.oldest_session_at))
        self.newest_session_label.setText(format_datetime(info.newest_session_at))
        self.last_daily_aggregation_label.setText("on sample write")
        self.db_file_size_label.setText(format_bytes(info.db_file_size_bytes))
        self.unfinished_sessions_label.setText(str(info.unfinished_session_count))

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
            endpoint = self._netmon_status.api_url or self._netmon_status.socket_path or "not configured"
            self.helper_endpoint_label.setText(_elide_middle(endpoint))
            self.helper_endpoint_label.setToolTip(endpoint)
            self.helper_response_label.setText(self._netmon_status.last_response or "none")
            self.helper_error_label.setText(self._netmon_status.last_error or "none")
            self.helper_permission_label.setText("ok" if self._netmon_status.permission_ok else "not available")
            self.kernel_support_label.setText(self._netmon_status.kernel_support)

    def _copy_helper_diagnostics(self) -> None:
        text = (
            f"helper_installed={self._netmon_status.installed}\n"
            f"helper_running={self._netmon_status.running}\n"
            f"backend={self._netmon_status.backend}\n"
            f"endpoint={self._netmon_status.api_url or self._netmon_status.socket_path or 'not configured'}\n"
            f"last_response={self._netmon_status.last_response or 'none'}\n"
            f"last_error={self._netmon_status.last_error or 'none'}"
        )
        clipboard = QApplication.clipboard() if QApplication.instance() else None
        if clipboard is not None:
            clipboard.setText(text)

    def _db_writable(self) -> bool:
        if self._store is None:
            return False
        path = self._store.db_path
        if path.exists():
            return os.access(path, os.W_OK)
        return os.access(path.parent, os.W_OK)

    def _sync_settings_controls(self) -> None:
        if not hasattr(self, "proxy_history_checkbox"):
            return
        self.proxy_history_checkbox.blockSignals(True)
        self.app_tracking_checkbox.blockSignals(True)
        self.experimental_warning_checkbox.blockSignals(True)
        self.retention_selector.blockSignals(True)
        self.summary_retention_selector.blockSignals(True)
        self.proxy_history_checkbox.setChecked(self._settings.proxy_history_enabled)
        self.app_tracking_checkbox.setChecked(self._settings.app_tracking_enabled)
        self.experimental_warning_checkbox.setChecked(self._settings.show_experimental_warning)
        index = self.retention_selector.findData(self._settings.detailed_retention_days)
        self.retention_selector.setCurrentIndex(index if index >= 0 else 1)
        summary_index = self.summary_retention_selector.findData(self._settings.daily_retention_days)
        self.summary_retention_selector.setCurrentIndex(summary_index if summary_index >= 0 else 0)
        self.proxy_history_checkbox.blockSignals(False)
        self.app_tracking_checkbox.blockSignals(False)
        self.experimental_warning_checkbox.blockSignals(False)
        self.retention_selector.blockSignals(False)
        self.summary_retention_selector.blockSignals(False)

    def _save_settings_from_controls(self) -> None:
        provider = self._settings.netmon_provider
        self._settings = TrafficSettings(
            proxy_history_enabled=bool(self.proxy_history_checkbox.isChecked()),
            app_tracking_enabled=bool(self.app_tracking_checkbox.isChecked()),
            show_experimental_warning=bool(self.experimental_warning_checkbox.isChecked()),
            detailed_retention_days=int(self.retention_selector.currentData() if self.retention_selector.currentData() is not None else 30),
            daily_retention_days=int(
                self.summary_retention_selector.currentData()
                if self.summary_retention_selector.currentData() is not None
                else 365
            ),
            netmon_provider=provider,
        )
        save_traffic_settings(self._settings)
        if self._store is not None:
            self._store.cleanup_old_samples(self._settings.detailed_retention_days)
        if self._settings.app_tracking_enabled:
            self._netmon_client.start_tracking()
        else:
            self._netmon_client.stop_tracking()
        self.settings_changed.emit(self._settings)
        self.refresh()

    def _on_history_export_clicked(self) -> None:
        if self._store is None:
            return
        start_date, end_date = self._history_range_dates()
        export_kind = self.history_export_selector.currentData()
        if export_kind == "sessions":
            filename = f"v2link-traffic-sessions-{start_date}_to_{end_date}.csv"
            title = "Export Session Summary CSV"
        elif export_kind == "samples":
            if not self._selected_history_session_id:
                QMessageBox.information(self, "Export Traffic CSV", "Select a session first.")
                return
            filename = f"v2link-traffic-session-{self._selected_history_session_id}.csv"
            title = "Export Session Samples CSV"
        else:
            filename = f"v2link-traffic-daily-{start_date}_to_{end_date}.csv"
            title = "Export Daily Summary CSV"
        path, _ = QFileDialog.getSaveFileName(
            self,
            title,
            filename,
            "CSV files (*.csv)",
        )
        if not path:
            return
        if export_kind == "sessions":
            self._store.export_session_summary_csv(path, start_date=start_date, end_date=end_date)
        elif export_kind == "samples":
            self._store.export_session_samples_csv(path, session_id=str(self._selected_history_session_id))
        else:
            self._store.export_daily_summary_csv(path, start_date=start_date, end_date=end_date)

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
