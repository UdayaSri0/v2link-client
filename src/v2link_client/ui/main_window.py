"""Main application window."""

from __future__ import annotations

import logging
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
import socket
import tempfile
import threading
import time

from PyQt6.QtCore import QEvent, QObject, QRunnable, Qt, QThreadPool, QTimer, QUrl, pyqtSignal
from PyQt6.QtGui import QAction, QDesktopServices, QIcon, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from v2link_client import __author__, __version__
from v2link_client.app_assets import get_app_icon_path
from v2link_client.core.config_builder import (
    DEFAULT_API_PORT,
    DEFAULT_HTTP_PORT,
    DEFAULT_LISTEN,
    DEFAULT_SOCKS_PORT,
    build_xray_config,
)
from v2link_client.core.errors import AppError
from v2link_client.core.health_check import ProxyHealthResult, check_http_proxy
from v2link_client.core.humanize import format_bytes, format_duration_s, format_mbps
from v2link_client.core.link_parser import parse_link
from v2link_client.core.netmon_client import NetmonClient
from v2link_client.core.net_probe import ServerPingResult, ping_server
from v2link_client.core.profile_store import (
    Profile,
    ProfileStore,
    connection_fingerprint,
)
from v2link_client.core.proxy_manager import (
    SystemProxyAuditResult,
    SystemProxyConfig,
    SystemProxyManager,
)
from v2link_client.core.process_manager import (
    XrayProcessManager,
    ensure_port_available,
    find_free_port,
    find_xray_binary,
    validate_xray_config,
)
from v2link_client.core.speed_test import SpeedTestResult, run_speed_test_via_http_proxy
from v2link_client.core.storage import get_config_dir, get_state_dir, load_json, save_json
from v2link_client.core.system_subprocess import detect_runtime_kind
from v2link_client.core.traffic_settings import TrafficSettings, load_traffic_settings
from v2link_client.core.traffic_store import ProxyTrafficSample, TrafficStore
from v2link_client.core.traffic_storage_worker import TrafficStorageWorker
from v2link_client.core.update_check import UpdateCheckResult, check_for_updates
from v2link_client.core.xray_api import (
    TrafficStats,
    active_stats_query_pid,
    cancel_active_stats_queries,
    get_outbound_traffic,
)
from v2link_client.core.xray_locator import (
    XrayBinary,
    find_xray_binary as locate_xray_binary,
    validate_xray_binary,
    xray_asset_status,
)
from v2link_client.core.xray_settings import XraySettings, load_xray_settings, save_xray_settings
from v2link_client.ui.diagnostics_widget import DiagnosticsWidget
from v2link_client.ui.profile_dialogs import ProfileEditorDialog, ProfileManagerDialog
from v2link_client.ui.theme import ThemeName, apply_theme, normalize_theme, theme_display_name
from v2link_client.ui.traffic_monitor_widget import TrafficMonitorWidget

logger = logging.getLogger(__name__)

PROJECT_REPOSITORY_URL = "https://github.com/UdayaSri0/v2link-client"
PROFILE_FILE = "profile.json"
XRAY_CONFIG_FILE = "xray_config.json"
PROFILE_KEY_APPLY_SYSTEM_PROXY = "apply_system_proxy"
PROFILE_KEY_APPLY_SYSTEM_PROXY_EXPLICIT = "apply_system_proxy_explicit"
PROFILE_KEY_PROFILES_MIGRATED = "profiles_migrated_v1"

HEALTH_INTERVAL_MS = 5000
PROXY_AUDIT_INTERVAL_MS = 4000
PROXY_AUDIT_MAX_BACKOFF_S = 30.0
PROXY_AUDIT_SHUTDOWN_WAIT_S = 3.5
STATUS_INTERVAL_MS = 1000
STATS_INTERVAL_MS = 2000
TRAFFIC_PERSISTENCE_INTERVAL_MS = 5000
TRAFFIC_FINAL_FLUSH_TIMEOUT_S = 5.0
OVERVIEW_INTERVAL_MS = 10_000
DIAGNOSTICS_INTERVAL_MS = 30_000
STATS_QUERY_TIMEOUT_S = 3.0
SLOW_STATS_CALLBACK_MS = 100.0
SLOW_STATS_WARNING_INTERVAL_S = 30.0
SLOW_STATS_QUERY_MS = 500.0
SLOW_DATABASE_WRITE_MS = 100.0
SLOW_OVERVIEW_REFRESH_MS = 200.0
SLOW_HISTORY_REFRESH_MS = 500.0
RECENT_TRAFFIC_WINDOW_S = 15.0
WINDOW_GEOMETRY_KEY = "window_geometry_v1"
WINDOW_MAXIMIZED_KEY = "window_maximized"
TRAFFIC_MONITOR_LAYOUT_KEY = "traffic_monitor_layout_v1"


class HealthCheckWorkerSignals(QObject):
    result = pyqtSignal(object)
    error = pyqtSignal(str)


class HealthCheckWorker(QRunnable):
    def __init__(self, fn) -> None:
        super().__init__()
        self.fn = fn
        self.signals = HealthCheckWorkerSignals()

    def run(self) -> None:
        try:
            payload = self.fn()
        except Exception as exc:  # pragma: no cover - defensive
            self.signals.error.emit(str(exc))
            return
        self.signals.result.emit(payload)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self._closing = False
        self._shutdown_complete = False
        self.setWindowTitle(f"v2link-client v{__version__}")
        self.resize(1180, 760)
        screen = QApplication.primaryScreen()
        if screen is not None:
            available = screen.availableGeometry()
            self.setMinimumSize(
                min(1000, max(640, available.width() - 40)),
                min(680, max(520, available.height() - 40)),
            )
        else:
            self.setMinimumSize(1000, 680)
        self._last_responsive_mode: str | None = None
        self._layout_state_loaded = False
        icon_path = get_app_icon_path()
        if icon_path is not None:
            self.setWindowIcon(QIcon(str(icon_path)))

        self._setup_menu()

        self._theme: ThemeName = "dark"

        central = QWidget(self)
        central.setObjectName("central")
        self.setCentralWidget(central)

        self.link_input = QLineEdit()
        self.link_input.setPlaceholderText("Paste a vless:// link")

        self.profile_selector = QComboBox()
        self.profile_selector.setMinimumWidth(260)
        self.profile_selector.setToolTip("Select a saved profile")

        self.manage_profiles_button = QPushButton("Manage")
        self.manage_profiles_button.clicked.connect(self._on_manage_profiles_clicked)
        self.manage_profiles_button.setProperty("variant", "ghost")

        self.validate_button = QPushButton("Validate & Save")
        self.validate_button.clicked.connect(self._on_validate_clicked)
        self.validate_button.setProperty("variant", "primary")

        self.system_proxy_checkbox = QCheckBox("System Proxy")
        self.system_proxy_checkbox.setToolTip(
            "Apply system proxy settings while running so most apps use the tunnel automatically."
        )
        self.system_proxy_checkbox.setChecked(True)

        self.start_stop_button = QPushButton("Start")
        self.start_stop_button.setEnabled(False)
        self.start_stop_button.clicked.connect(self._on_start_stop_clicked)
        self.start_stop_button.setProperty("variant", "primary")

        self.ping_button = QPushButton("Ping Server")
        self.ping_button.setEnabled(False)
        self.ping_button.clicked.connect(self._on_ping_clicked)
        self.ping_button.setProperty("variant", "ghost")

        self.speed_test_button = QPushButton("Speed Test")
        self.speed_test_button.setEnabled(False)
        self.speed_test_button.clicked.connect(self._on_speed_test_clicked)
        self.speed_test_button.setProperty("variant", "ghost")

        self.status_label = QLabel("STOPPED")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.status_label.setProperty("role", "pill")

        self.health_label = QLabel("OFFLINE")
        self.health_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.health_label.setProperty("role", "pill")
        self._set_health_state("offline", "Not running")

        self.theme_selector = QComboBox()
        self.theme_selector.addItems(["Dark", "Light"])
        self.theme_selector.setFixedWidth(120)
        self.theme_selector.setToolTip("Switch theme")

        self.check_updates_button = QPushButton("Check Updates")
        self.check_updates_button.clicked.connect(self._on_check_updates_clicked)
        self.check_updates_button.setProperty("variant", "ghost")

        self.xray_settings_button = QPushButton("Xray Settings")
        self.xray_settings_button.clicked.connect(self._show_xray_settings)
        self.xray_settings_button.setProperty("variant", "ghost")

        self.about_button = QPushButton("About")
        self.about_button.clicked.connect(self._show_about)
        self.about_button.setProperty("variant", "ghost")

        profile_row = QHBoxLayout()
        profile_row.setSpacing(10)
        profile_row.addWidget(QLabel("Profile"))
        profile_row.addWidget(self.profile_selector, 1)
        profile_row.addWidget(self.manage_profiles_button)

        top_row = QHBoxLayout()
        top_row.setSpacing(10)
        top_row.addWidget(self.link_input, 1)
        top_row.addWidget(self.validate_button)
        top_row.addWidget(self.system_proxy_checkbox)
        top_row.addWidget(self.theme_selector)

        control_row = QHBoxLayout()
        control_row.setSpacing(10)
        control_row.addWidget(self.start_stop_button)
        control_row.addWidget(self.ping_button)
        control_row.addWidget(self.speed_test_button)
        control_row.addWidget(QLabel("Status:"))
        control_row.addWidget(self.status_label, 1)
        control_row.addWidget(QLabel("Connectivity:"))
        control_row.addWidget(self.health_label)

        self.uptime_label = QLabel("UPTIME (00:00:00)")
        self.uptime_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.uptime_label.setProperty("role", "pill")

        self.speed_label = QLabel("SPEED (↑ 0.0 Mbps / ↓ 0.0 Mbps)")
        self.speed_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.speed_label.setProperty("role", "pill")

        self.traffic_label = QLabel("TRAFFIC (↑ 0 B / ↓ 0 B)")
        self.traffic_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.traffic_label.setProperty("role", "pill")

        metrics_row = QHBoxLayout()
        metrics_row.setSpacing(10)
        metrics_row.addWidget(self.uptime_label)
        metrics_row.addWidget(self.speed_label, 1)
        metrics_row.addWidget(self.traffic_label)

        help_row = QHBoxLayout()
        help_row.setSpacing(10)
        help_row.addWidget(QLabel("Help"))
        help_row.addStretch(1)
        help_row.addWidget(self.check_updates_button)
        help_row.addWidget(self.xray_settings_button)
        help_row.addWidget(self.about_button)

        self.diagnostics_widget = DiagnosticsWidget()
        self._traffic_settings: TrafficSettings = load_traffic_settings()
        self._netmon_client = NetmonClient(provider=self._traffic_settings.netmon_provider)
        if self._traffic_settings.app_tracking_enabled:
            self._netmon_client.start_tracking()
        self._last_traffic_store_error: str | None = None
        try:
            self._traffic_store: TrafficStore | None = TrafficStore()
        except Exception as exc:  # pragma: no cover - defensive startup guard
            logger.exception("Failed to initialize traffic store")
            self._traffic_store = None
            self._last_traffic_store_error = str(exc)
        self._traffic_storage_worker = (
            TrafficStorageWorker(self._traffic_store)
            if self._traffic_store is not None
            else None
        )
        self.traffic_monitor_widget = TrafficMonitorWidget(
            self._traffic_store,
            settings=self._traffic_settings,
            netmon_client=self._netmon_client,
        )
        self.traffic_monitor_widget.settings_changed.connect(self._on_traffic_settings_changed)
        self._workspace_shortcut = QShortcut(QKeySequence("F11"), self)
        self._workspace_shortcut.activated.connect(self.traffic_monitor_widget.toggle_workspace_mode)
        self._escape_shortcut = QShortcut(QKeySequence(Qt.Key.Key_Escape), self)
        self._escape_shortcut.activated.connect(self.traffic_monitor_widget.exit_workspace_mode)
        if self._last_traffic_store_error:
            self.traffic_monitor_widget.set_diagnostics(
                api_server=None,
                stats_available=False,
                last_stats_query_time=None,
                last_sample_time=None,
                warning=None,
                store_error=self._last_traffic_store_error,
            )

        self.runtime_tabs = QTabWidget()
        self.runtime_tabs.addTab(self.traffic_monitor_widget, "Traffic Monitor")
        self.runtime_tabs.addTab(self.diagnostics_widget, "Diagnostics")
        self.runtime_tabs.currentChanged.connect(self._on_runtime_tab_changed)

        layout = QVBoxLayout()
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)
        layout.addLayout(profile_row)
        layout.addLayout(top_row)
        layout.addLayout(control_row)
        layout.addLayout(metrics_row)
        layout.addLayout(help_row)
        layout.addWidget(self.runtime_tabs, 1)

        central.setLayout(layout)
        self._main_layout = layout

        self._process = XrayProcessManager()
        self._last_xray_resolution: XrayBinary = locate_xray_binary()
        self._validated_config_path = None
        self._validated_link = None
        self._validated_fingerprint: str | None = None
        self._validated_profile_id: str | None = None
        self._socks_port = DEFAULT_SOCKS_PORT
        self._http_port = DEFAULT_HTTP_PORT
        self._api_port: int | None = None
        self.diagnostics_widget.set_proxy_ports(
            socks_port=self._socks_port, http_port=self._http_port
        )
        self._thread_pool = QThreadPool.globalInstance()
        self._profile_store = ProfileStore()
        self._selected_profile_id: str | None = None
        self._profile_selector_syncing = False

        self._system_proxy = SystemProxyManager()
        self._system_proxy_applied = False
        self._system_proxy_cfg: SystemProxyConfig | None = None
        self._last_proxy_audit: SystemProxyAuditResult | None = None
        self._last_proxy_audit_error: str | None = None
        self._last_proxy_reapply_at: str | None = None
        self._last_proxy_reapply_reason: str | None = None
        self._proxy_audit_failures = 0
        self._next_proxy_reconcile_at = 0.0
        self._proxy_audit_running = False
        self._proxy_audit_token = 0
        self._proxy_audit_active_token: int | None = None
        self._proxy_audit_finished = threading.Event()
        self._proxy_audit_finished.set()
        if not self._system_proxy.is_supported():
            self.system_proxy_checkbox.setEnabled(False)
            self.system_proxy_checkbox.setToolTip(
                "System proxy auto-apply is not supported on this desktop yet. Use manual proxy settings."
            )

        self._health_timer = QTimer(self)
        self._health_timer.setInterval(HEALTH_INTERVAL_MS)
        self._health_timer.timeout.connect(self._kick_health_check)
        self._health_in_flight = False
        self._health_token = 0
        self._last_health_ok: bool | None = None
        self._last_health_result: ProxyHealthResult | None = None
        self._health_state = "offline"
        self._health_detail = "Not running"

        self._proxy_audit_timer = QTimer(self)
        self._proxy_audit_timer.setInterval(PROXY_AUDIT_INTERVAL_MS)
        self._proxy_audit_timer.timeout.connect(self._audit_system_proxy_runtime)

        self._status_timer = QTimer(self)
        self._status_timer.setInterval(STATUS_INTERVAL_MS)
        self._status_timer.timeout.connect(self._poll_core_status)

        self._stats_timer = QTimer(self)
        self._stats_timer.setInterval(STATS_INTERVAL_MS)
        self._stats_timer.timeout.connect(self._kick_stats_poll)

        self._traffic_persistence_timer = QTimer(self)
        self._traffic_persistence_timer.setInterval(TRAFFIC_PERSISTENCE_INTERVAL_MS)
        self._traffic_persistence_timer.timeout.connect(self._persist_latest_traffic_sample)

        self._overview_timer = QTimer(self)
        self._overview_timer.setInterval(OVERVIEW_INTERVAL_MS)
        self._overview_timer.timeout.connect(self._refresh_scheduled_overview)

        self._diagnostics_timer = QTimer(self)
        self._diagnostics_timer.setInterval(DIAGNOSTICS_INTERVAL_MS)
        self._diagnostics_timer.timeout.connect(self._refresh_scheduled_diagnostics)

        self._core_started_at: float | None = None
        self._stats_in_flight = False
        self._stats_token = 0
        self._stats_active_token: int | None = None
        self._stats_skipped_polls = 0
        self._stats_query_started_at: float | None = None
        self._last_stats_query_duration_ms: float | None = None
        self._stats_queries_started = 0
        self._stats_queries_completed = 0
        self._stats_query_failures = 0
        self._stats_query_duration_total_ms = 0.0
        self._stats_query_duration_max_ms = 0.0
        self._stats_callback_count = 0
        self._stats_callback_duration_total_ms = 0.0
        self._stats_callback_duration_max_ms = 0.0
        self._last_overview_refresh_ms: float | None = None
        self._cached_storage_diagnostics: dict[str, object] = {}
        self._cached_listener_reachability = (False, False)
        self._cached_netmon_diagnostics: dict[str, object] = {}
        self._runtime_diagnostics_in_flight = False
        self._runtime_diagnostics_token = 0
        self._last_stats_failure_log_at: float | None = None
        self._last_stats_failure_message: str | None = None
        self._last_slow_stats_callback_warning_at: float | None = None
        self._last_stats_at: float | None = None
        self._last_uplink: int | None = None
        self._last_downlink: int | None = None
        self._last_stats_query_result: str | None = None
        self._last_stats_query_time: str | None = None
        self._stats_available = False
        self._traffic_session_id: str | None = None
        self._last_traffic_sample: ProxyTrafficSample | None = None
        self._pending_traffic_stats: TrafficStats | None = None
        self._traffic_session_uplink_bytes = 0
        self._traffic_session_downlink_bytes = 0
        self._last_traffic_activity_at: float | None = None
        self._ping_in_flight = False
        self._speed_test_in_flight = False
        self._update_check_in_flight = False

        profile_data = self._load_profile()
        self._load_saved_profiles(profile_data)
        self._restore_layout_state(profile_data)
        self.link_input.textChanged.connect(self._on_link_input_changed)
        self.profile_selector.currentIndexChanged.connect(self._on_profile_selected)
        self.system_proxy_checkbox.toggled.connect(self._on_system_proxy_toggled)
        self._apply_theme(self._theme, persist=False)
        self.theme_selector.currentTextChanged.connect(self._on_theme_changed)
        self._reconcile_runtime_validation_for_current_link(announce_restored=True)

        # If the app previously applied system proxy and crashed, attempt to restore.
        try:
            if self._system_proxy.restore_if_needed():
                logger.info("Restored system proxy from previous session")
        except Exception:
            logger.exception("Failed to restore system proxy from previous session")
        try:
            if self._system_proxy.repair_stale_loopback_proxy():
                logger.info("Repaired stale loopback proxy settings from previous session")
                self.diagnostics_widget.set_hint(
                    "Detected stale system proxy settings and reset to no-proxy."
                )
        except Exception:
            logger.exception("Failed to auto-repair stale loopback proxy settings")
        self._update_diagnostics_runtime_state()
        if self._traffic_storage_worker is not None:
            self._traffic_storage_worker.submit_cleanup(
                self._traffic_settings.detailed_retention_days
            )
        self._overview_timer.start()
        self._diagnostics_timer.start()

    def resizeEvent(self, event) -> None:  # type: ignore[override]
        super().resizeEvent(event)
        self._apply_responsive_layout()

    def changeEvent(self, event) -> None:  # type: ignore[override]
        super().changeEvent(event)
        if event.type() == QEvent.Type.WindowStateChange:
            self._apply_responsive_layout()

    def _setup_menu(self) -> None:
        help_menu = self.menuBar().addMenu("&Help")
        self.check_updates_action = QAction("Check for Updates…", self)
        self.check_updates_action.triggered.connect(self._on_check_updates_clicked)
        help_menu.addAction(self.check_updates_action)
        self.about_action = QAction("About", self)
        self.about_action.triggered.connect(self._show_about)
        help_menu.addAction(self.about_action)

    def _current_xray_resolution(self, *, refresh: bool = False) -> XrayBinary:
        process_binary = getattr(self._process, "_xray", None)
        if isinstance(process_binary, XrayBinary):
            self._last_xray_resolution = process_binary
            return process_binary
        if refresh:
            self._last_xray_resolution = locate_xray_binary()
        return self._last_xray_resolution

    def _xray_source_label(self, source: str | None) -> str:
        if source == "user-configured":
            return "user configured"
        if source == "system-path":
            return "system PATH"
        return "bundled"

    def _xray_status_summary(self, xray: XrayBinary) -> str:
        if xray.valid:
            return f"{xray.version or 'unknown version'} ({self._xray_source_label(xray.source)})"
        return xray.error or "Xray-core was not found."

    def _show_xray_settings(self) -> None:
        if self._process.is_running():
            QMessageBox.warning(
                self,
                "Xray Settings",
                "Stop the core before changing the Xray binary.",
            )
            return

        settings = load_xray_settings()
        dialog = QDialog(self)
        dialog.setWindowTitle("Xray Settings")
        layout = QVBoxLayout(dialog)
        layout.setSpacing(10)

        custom_checkbox = QCheckBox("Use custom Xray binary")
        custom_checkbox.setChecked(settings.use_custom_binary)
        detailed_logging_checkbox = QCheckBox("Enable detailed Xray diagnostic logging")
        detailed_logging_checkbox.setChecked(settings.detailed_logging)
        detailed_logging_checkbox.setToolTip(
            "Adds debug detail to bounded xray_stdout.log; access logging stays disabled."
        )
        path_input = QLineEdit(settings.custom_binary_path or "")
        path_input.setPlaceholderText("Choose an xray executable")

        browse_button = QPushButton("Browse")
        reset_button = QPushButton("Reset to bundled/default")
        validate_button = QPushButton("Validate")
        self_test_button = QPushButton("Test Xray installation")
        save_button = QPushButton("Save")
        cancel_button = QPushButton("Cancel")
        status_label = QLabel("")
        status_label.setWordWrap(True)
        status_label.setProperty("role", "hint")

        path_row = QHBoxLayout()
        path_row.addWidget(path_input, 1)
        path_row.addWidget(browse_button)

        button_row = QHBoxLayout()
        button_row.addWidget(reset_button)
        button_row.addStretch(1)
        button_row.addWidget(validate_button)
        button_row.addWidget(self_test_button)
        button_row.addWidget(cancel_button)
        button_row.addWidget(save_button)

        layout.addWidget(custom_checkbox)
        layout.addLayout(path_row)
        layout.addWidget(detailed_logging_checkbox)
        layout.addWidget(status_label)
        layout.addLayout(button_row)

        def update_enabled() -> None:
            enabled = custom_checkbox.isChecked()
            path_input.setEnabled(enabled)
            browse_button.setEnabled(enabled)
            validate_button.setEnabled(enabled)

        def choose_file() -> None:
            selected, _selected_filter = QFileDialog.getOpenFileName(
                dialog,
                "Choose Xray binary",
                path_input.text().strip() or str(Path.home()),
            )
            if selected:
                path_input.setText(selected)

        def validate_current() -> XrayBinary:
            if custom_checkbox.isChecked():
                result = validate_xray_binary(path_input.text().strip(), source="user-configured")
            else:
                result = locate_xray_binary()
            status_label.setText(
                f"Valid Xray-core: {self._xray_status_summary(result)}"
                if result.valid
                else result.error or "Xray-core was not found."
            )
            return result

        def reset_default() -> None:
            custom_checkbox.setChecked(False)
            path_input.clear()
            update_enabled()
            validate_current()

        def run_self_test() -> None:
            result = validate_current()
            if not result.valid or not result.path:
                QMessageBox.warning(dialog, "Xray Self-Test", result.error or "Xray-core is unavailable.")
                return
            assets = xray_asset_status(result)
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".json", encoding="utf-8", delete=False
                ) as handle:
                    handle.write(
                        '{"log":{"loglevel":"none"},"inbounds":[],'
                        '"outbounds":[{"protocol":"freedom","settings":{}}]}'
                    )
                    config_path = Path(handle.name)
                try:
                    validate_xray_config(result, config_path)
                finally:
                    config_path.unlink(missing_ok=True)
            except AppError as exc:
                QMessageBox.warning(dialog, "Xray Self-Test", exc.user_message)
                return
            QMessageBox.information(
                dialog,
                "Xray Self-Test",
                f"Xray-core {result.version or ''} passed offline configuration validation.\n"
                f"geoip.dat: {'Found' if assets['geoip_found'] else 'Missing'}\n"
                f"geosite.dat: {'Found' if assets['geosite_found'] else 'Missing'}",
            )

        def save_current() -> None:
            if custom_checkbox.isChecked():
                result = validate_current()
                if not result.valid:
                    QMessageBox.warning(
                        dialog,
                        "Invalid Xray Binary",
                        result.error or "Selected file is not a valid Xray-core binary.",
                    )
                    return
                save_xray_settings(
                    XraySettings(
                        use_custom_binary=True,
                        custom_binary_path=path_input.text().strip(),
                        detailed_logging=detailed_logging_checkbox.isChecked(),
                    )
                )
            else:
                save_xray_settings(
                    XraySettings(detailed_logging=detailed_logging_checkbox.isChecked())
                )
                result = locate_xray_binary()

            self._last_xray_resolution = result
            self._reset_validation_state()
            self.diagnostics_widget.set_hint(
                f"Xray settings updated: {self._xray_status_summary(result)}"
            )
            dialog.accept()

        custom_checkbox.toggled.connect(lambda _checked: update_enabled())
        browse_button.clicked.connect(choose_file)
        reset_button.clicked.connect(reset_default)
        validate_button.clicked.connect(validate_current)
        self_test_button.clicked.connect(run_self_test)
        save_button.clicked.connect(save_current)
        cancel_button.clicked.connect(dialog.reject)

        update_enabled()
        validate_current()
        dialog.exec()

    def _show_about(self) -> None:
        xray = self._current_xray_resolution(refresh=True)
        text = (
            "<b>v2link-client</b><br>"
            f"Version: v{__version__}<br>"
            f"Xray-core: {self._xray_status_summary(xray)}<br>"
            f"Author: {__author__}<br><br>"
            f"Repository: {PROJECT_REPOSITORY_URL}<br><br>"
            "Linux desktop client for V2Ray-style links powered by Xray-core.<br><br>"
            "<b>Highlights</b><br>"
            "• Saved profiles with validation persistence across restarts<br>"
            "• Traffic Monitor with local SQLite proxy/profile history<br>"
            "• Session history, daily charts, and CSV exports<br>"
            "• Optional v2link-netmon helper preparation for per-app tracking<br>"
            "• Runtime diagnostics and system proxy drift reconciliation"
        )
        QMessageBox.about(self, "About v2link-client", text)

    def _set_update_check_busy(self, busy: bool) -> None:
        self._update_check_in_flight = busy
        self.check_updates_action.setEnabled(not busy)
        self.check_updates_action.setText("Checking for Updates…" if busy else "Check for Updates…")
        self.check_updates_button.setEnabled(not busy)
        self.check_updates_button.setText("Checking..." if busy else "Check Updates")

    def _on_check_updates_clicked(self) -> None:
        if self._update_check_in_flight:
            return
        self._set_update_check_busy(True)
        self.diagnostics_widget.set_hint("Checking GitHub Releases for updates...")

        def _run():
            try:
                return check_for_updates(__version__)
            except AppError as exc:
                raise RuntimeError(exc.user_message) from exc

        worker = HealthCheckWorker(_run)
        worker.signals.result.connect(self._on_update_check_result)
        worker.signals.error.connect(self._on_update_check_error)
        self._thread_pool.start(worker)

    def _on_update_check_result(self, payload: object) -> None:
        if self._closing:
            return
        self._set_update_check_busy(False)
        if not isinstance(payload, UpdateCheckResult):  # pragma: no cover - defensive
            self.diagnostics_widget.set_hint("Update check failed: invalid response.")
            QMessageBox.warning(self, "Update Check Failed", "Received an invalid update check response.")
            return

        if not payload.update_available:
            self.diagnostics_widget.set_hint(
                f"You're up to date (installed v{payload.current_version}, latest v{payload.latest_version})."
            )
            QMessageBox.information(
                self,
                "Check for Updates",
                (
                    "You're up to date.\n\n"
                    f"Installed version: v{payload.current_version}\n"
                    f"Latest release: v{payload.latest_version}"
                ),
            )
            return

        self.diagnostics_widget.set_hint(
            f"Update available: v{payload.latest_version} (installed v{payload.current_version})."
        )
        self._show_update_available_dialog(payload)

    def _on_update_check_error(self, message: str) -> None:
        if self._closing:
            return
        self._set_update_check_busy(False)
        detail = (message or "Unknown error").strip()
        logger.warning("Update check failed: %s", detail)
        self.diagnostics_widget.set_hint(f"Update check failed: {detail}")
        QMessageBox.warning(self, "Update Check Failed", detail)

    def _show_update_available_dialog(self, result: UpdateCheckResult) -> None:
        download_url = result.preferred_download_url or result.release_url

        summary_lines = [
            "A newer version is available.",
            f"Installed: v{result.current_version}",
            f"Latest: v{result.latest_version}",
        ]
        extra_lines: list[str] = []
        if result.appimage_asset is not None:
            extra_lines.append(f"AppImage: {result.appimage_asset.name}")
        if result.deb_asset is not None:
            extra_lines.append(f"Debian package: {result.deb_asset.name}")
        if download_url:
            extra_lines.append(f"Download link: {download_url}")

        dialog = QMessageBox(self)
        dialog.setIcon(QMessageBox.Icon.Information)
        dialog.setWindowTitle("Update Available")
        dialog.setText("\n".join(summary_lines))
        info_lines: list[str] = []
        if result.notes:
            info_lines.append(result.notes)
        if extra_lines:
            info_lines.append("\n".join(extra_lines))
        if info_lines:
            dialog.setInformativeText("\n\n".join(info_lines))

        open_button = dialog.addButton("Open Download Page", QMessageBox.ButtonRole.AcceptRole)
        copy_button = dialog.addButton("Copy Download Link", QMessageBox.ButtonRole.ActionRole)
        dialog.addButton(QMessageBox.StandardButton.Close)
        dialog.exec()

        clicked = dialog.clickedButton()
        if clicked == open_button:
            QDesktopServices.openUrl(QUrl(result.release_url))
            self.diagnostics_widget.set_hint("Opened release download page in your browser.")
        elif clicked == copy_button:
            QApplication.clipboard().setText(download_url)
            self.diagnostics_widget.set_hint("Release download link copied to clipboard.")

    def _on_validate_clicked(self) -> None:
        self._reset_validation_state()
        raw_link = self.link_input.text().strip()

        try:
            parsed_link, config_path, xray, socks_port, http_port, api_port = self._validate_link(
                raw_link, persist_runtime_config=True
            )
        except AppError as exc:
            self.diagnostics_widget.set_hint(exc.user_message)
            return
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("Validation failed")
            self.diagnostics_widget.set_hint(f"Validation failed: {exc}")
            return

        saved_profile = self._handle_profile_save_after_validation(raw_link, parsed_link)
        validation_profile = saved_profile
        if validation_profile is None:
            validation_profile = self._profile_store.find_by_url(raw_link)
        if validation_profile is not None:
            marked_profile = self._profile_store.mark_profile_validated(validation_profile.id)
            if marked_profile is not None:
                validation_profile = marked_profile
            self._selected_profile_id = validation_profile.id
            self._refresh_profile_selector(select_profile_id=validation_profile.id)

        self._save_profile_preferences(link=raw_link)
        self._set_runtime_validation_state(
            parsed_link=parsed_link,
            config_path=config_path,
            socks_port=socks_port,
            http_port=http_port,
            api_port=api_port,
            profile_id=validation_profile.id if validation_profile is not None else None,
            fingerprint=connection_fingerprint(raw_link),
            xray=xray,
        )
        self._last_xray_resolution = xray

        hint = (
            f"Validated: {parsed_link.display_name()}. "
            f"Ready to start (SOCKS5 {DEFAULT_LISTEN}:{self._socks_port}, HTTP {DEFAULT_LISTEN}:{self._http_port})."
        )
        warning = self._validation_warning(parsed_link)
        if warning:
            hint = f"{hint}  Warning: {warning}"
        if saved_profile is not None:
            hint = f"{hint} Profile saved: {saved_profile.name}."
        elif validation_profile is not None:
            hint = f"{hint} Using existing saved profile."
        else:
            hint = f"{hint} URL validated but not saved as a profile."
        self.diagnostics_widget.set_hint(hint)
        self._set_health_state("offline", "Not running")

    def _reset_validation_state(self) -> None:
        self.status_label.setText("STOPPED")
        self._validated_config_path = None
        self._validated_link = None
        self._validated_fingerprint = None
        self._validated_profile_id = None
        self.start_stop_button.setEnabled(False)
        self.ping_button.setEnabled(False)
        self.speed_test_button.setEnabled(False)
        self.system_proxy_checkbox.setEnabled(self._system_proxy.is_supported())
        self._api_port = None
        self._core_started_at = None
        self._stats_token += 1
        self._last_stats_at = None
        self._last_uplink = None
        self._last_downlink = None
        self._last_stats_query_result = None
        self._last_stats_query_time = None
        self._stats_available = False
        self._last_traffic_activity_at = None
        self._last_health_result = None
        self._set_metrics_defaults()
        self._update_diagnostics_runtime_state()

    def _set_runtime_validation_state(
        self,
        *,
        parsed_link: object,
        config_path: Path,
        socks_port: int,
        http_port: int,
        api_port: int,
        profile_id: str | None,
        fingerprint: str | None,
        xray: object | None = None,
    ) -> None:
        if xray is None:
            self._process = XrayProcessManager()
        else:
            self._process = XrayProcessManager(xray)
            if isinstance(xray, XrayBinary):
                self._last_xray_resolution = xray
        self._validated_config_path = config_path
        self._validated_link = parsed_link
        self._validated_profile_id = profile_id
        self._validated_fingerprint = fingerprint
        self._socks_port = socks_port
        self._http_port = http_port
        self._api_port = api_port
        self.diagnostics_widget.set_proxy_ports(
            socks_port=self._socks_port,
            http_port=self._http_port,
        )
        self.start_stop_button.setEnabled(True)
        self.ping_button.setEnabled(True)

    def _profile_for_current_link(self) -> Profile | None:
        current_url = self.link_input.text().strip()
        if not current_url:
            return None

        if self._selected_profile_id:
            selected = self._profile_store.get_by_id(self._selected_profile_id)
            if selected is not None and selected.url.strip() == current_url:
                return selected
        return self._profile_store.find_by_url(current_url)

    def _prepare_runtime_config(self, raw_link: str) -> tuple[object, Path, int, int, int]:
        parsed_link = parse_link(raw_link)
        socks_port, http_port, api_port = self._pick_proxy_ports()
        config = build_xray_config(
            parsed_link,
            socks_port=socks_port,
            http_port=http_port,
            api_port=api_port,
            detailed_logging=load_xray_settings().detailed_logging,
        )
        config_path = get_state_dir() / XRAY_CONFIG_FILE
        save_json(config_path, config)
        return parsed_link, config_path, socks_port, http_port, api_port

    def _restore_saved_validation(self, *, announce: bool) -> bool:
        raw_link = self.link_input.text().strip()
        if not raw_link:
            return False

        profile = self._profile_for_current_link()
        if profile is None:
            return False
        if not self._profile_store.is_profile_validation_current(profile):
            return False

        fingerprint = connection_fingerprint(raw_link)
        if not fingerprint or profile.validation_fingerprint != fingerprint:
            return False

        if self._validated_fingerprint == fingerprint and self._validated_link is not None:
            self._validated_profile_id = profile.id
            self.start_stop_button.setEnabled(True)
            self.ping_button.setEnabled(True)
            return True

        try:
            parsed_link, config_path, socks_port, http_port, api_port = self._prepare_runtime_config(raw_link)
        except AppError as exc:
            self._profile_store.clear_profile_validation(profile.id)
            self.diagnostics_widget.set_hint(
                f"Saved validation expired for '{profile.name}': {exc.user_message}"
            )
            return False
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("Failed to restore saved validation for profile %s", profile.id)
            self._profile_store.clear_profile_validation(profile.id)
            self.diagnostics_widget.set_hint(
                f"Saved validation expired for '{profile.name}': {exc}"
            )
            return False

        self._set_runtime_validation_state(
            parsed_link=parsed_link,
            config_path=config_path,
            socks_port=socks_port,
            http_port=http_port,
            api_port=api_port,
            profile_id=profile.id,
            fingerprint=fingerprint,
        )
        if announce:
            self.diagnostics_widget.set_hint(f"Loaded validated profile '{profile.name}'. Ready to start.")
        self._set_health_state("offline", "Not running")
        return True

    def _reconcile_runtime_validation_for_current_link(self, *, announce_restored: bool = False) -> None:
        if self._process.is_running():
            return
        raw_link = self.link_input.text().strip()
        current_fingerprint = connection_fingerprint(raw_link)
        if (
            self._validated_link is not None
            and self._validated_fingerprint
            and current_fingerprint
            and self._validated_fingerprint == current_fingerprint
        ):
            self.start_stop_button.setEnabled(True)
            self.ping_button.setEnabled(True)
            return

        if self._restore_saved_validation(announce=announce_restored):
            return

        if self._validated_link is not None or self._validated_config_path is not None:
            self._reset_validation_state()

    def _on_link_input_changed(self, _value: str) -> None:
        self._reconcile_runtime_validation_for_current_link()

    def _validate_link(
        self, raw_link: str, *, persist_runtime_config: bool
    ) -> tuple[object, Path, object, int, int, int]:
        parsed_link = parse_link(raw_link)
        socks_port, http_port, api_port = self._pick_proxy_ports()
        config = build_xray_config(
            parsed_link,
            socks_port=socks_port,
            http_port=http_port,
            api_port=api_port,
            detailed_logging=load_xray_settings().detailed_logging,
        )

        if persist_runtime_config:
            config_path = get_state_dir() / XRAY_CONFIG_FILE
            save_json(config_path, config)
        else:
            with tempfile.NamedTemporaryFile(
                prefix="xray_validate_",
                suffix=".json",
                dir=str(get_state_dir()),
                delete=False,
            ) as handle:
                config_path = Path(handle.name)
            save_json(config_path, config)

        xray = find_xray_binary()
        try:
            validate_xray_config(xray, config_path)
        except Exception:
            if not persist_runtime_config:
                try:
                    config_path.unlink(missing_ok=True)
                except Exception:
                    logger.exception("Failed to clean temporary validation config")
            raise

        if not persist_runtime_config:
            try:
                config_path.unlink(missing_ok=True)
            except Exception:
                logger.exception("Failed to clean temporary validation config")

        return parsed_link, config_path, xray, socks_port, http_port, api_port

    def _validate_link_for_dialog(self, raw_link: str) -> tuple[bool, str]:
        try:
            parsed_link, _, _, _, _, _ = self._validate_link(raw_link, persist_runtime_config=False)
        except AppError as exc:
            return False, exc.user_message
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("Validation failed in profile dialog")
            return False, f"Validation failed: {exc}"
        return True, f"Valid: {parsed_link.display_name()}"

    def _handle_profile_save_after_validation(self, raw_link: str, parsed_link) -> Profile | None:
        existing = self._profile_store.find_by_url(raw_link)
        if existing is not None:
            chooser = QMessageBox(self)
            chooser.setIcon(QMessageBox.Icon.Question)
            chooser.setWindowTitle("URL Already Saved")
            chooser.setText(
                f"This URL is already saved in profile '{existing.name}'. "
                "Do you want to update it or save as a new profile?"
            )
            update_button = chooser.addButton("Update Profile", QMessageBox.ButtonRole.AcceptRole)
            save_new_button = chooser.addButton("Save as New", QMessageBox.ButtonRole.ActionRole)
            chooser.addButton("Keep Existing", QMessageBox.ButtonRole.RejectRole)
            chooser.setDefaultButton(update_button)
            chooser.exec()
            clicked = chooser.clickedButton()
            if clicked == update_button:
                return self._edit_profile(existing, forced_url=raw_link)
            if clicked == save_new_button:
                return self._add_profile(raw_link=raw_link, suggested_name=self._suggest_profile_name(parsed_link))
            return existing

        return self._add_profile(raw_link=raw_link, suggested_name=self._suggest_profile_name(parsed_link))

    def _suggest_profile_name(self, parsed_link) -> str:
        name = ""
        try:
            name = str(parsed_link.display_name())
        except Exception:  # pragma: no cover - defensive
            name = ""
        return name.strip() or "Saved Profile"

    def _add_profile(self, *, raw_link: str, suggested_name: str) -> Profile | None:
        dialog = ProfileEditorDialog(
            validate_fn=self._validate_link_for_dialog,
            default_profile_id=self._profile_store.default_profile_id,
            preset_url=raw_link,
            parent=self,
        )
        dialog.name_input.setText(suggested_name)
        if self._profile_store.default_profile_id is None:
            dialog.default_checkbox.setChecked(True)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return None

        profile = self._profile_store.add_profile(dialog.build_profile())
        if dialog.set_as_default:
            self._profile_store.set_default(profile.id)
        return profile

    def _edit_profile(self, profile: Profile, *, forced_url: str | None = None) -> Profile | None:
        dialog = ProfileEditorDialog(
            validate_fn=self._validate_link_for_dialog,
            profile=profile,
            default_profile_id=self._profile_store.default_profile_id,
            parent=self,
        )
        if forced_url:
            dialog.url_input.setText(forced_url)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return None

        updated = self._profile_store.update_profile(dialog.build_profile())
        if dialog.set_as_default:
            self._profile_store.set_default(updated.id)
        return updated

    def _on_start_stop_clicked(self) -> None:
        if self._process.is_running():
            self._stop_core(user_message="Stopped.")
            return

        if not self._validated_config_path:
            self.diagnostics_widget.set_hint("Validate & Save a link first.")
            return

        try:
            ensure_port_available(DEFAULT_LISTEN, self._socks_port)
            ensure_port_available(DEFAULT_LISTEN, self._http_port)
            if self._api_port is not None:
                ensure_port_available(DEFAULT_LISTEN, int(self._api_port))
            self._process.start(self._validated_config_path)
        except AppError as exc:
            self.diagnostics_widget.set_hint(exc.user_message)
            return
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("Start failed")
            self.diagnostics_widget.set_hint(f"Start failed: {exc}")
            return

        self.status_label.setText("RUNNING")
        self.start_stop_button.setText("Stop")
        self.start_stop_button.setProperty("variant", "danger")
        self._refresh_style(self.start_stop_button)
        self.link_input.setEnabled(False)
        self.profile_selector.setEnabled(False)
        self.manage_profiles_button.setEnabled(False)
        self.validate_button.setEnabled(False)
        self.system_proxy_checkbox.setEnabled(False)
        self.ping_button.setEnabled(False)
        self.speed_test_button.setEnabled(True)
        self._core_started_at = time.monotonic()
        self._stats_token += 1
        self._last_stats_at = None
        self._last_uplink = None
        self._last_downlink = None
        self._last_stats_query_result = None
        self._last_stats_query_time = None
        self._stats_available = False
        self._last_traffic_activity_at = None
        self._start_traffic_session()
        self._health_token += 1
        self._last_health_ok = None
        self._last_health_result = None
        self._set_health_state("connecting", "Checking…")
        self._health_timer.start()
        self._kick_health_check()
        base_hint = (
            f"Started Xray. SOCKS5 {DEFAULT_LISTEN}:{self._socks_port} / "
            f"HTTP {DEFAULT_LISTEN}:{self._http_port}"
        )
        self.diagnostics_widget.set_hint(base_hint)
        self._mark_profile_last_used()
        if self.system_proxy_checkbox.isChecked():
            self._apply_system_proxy()
        else:
            self._system_proxy_applied = False
            self._system_proxy_cfg = None
            self._last_proxy_audit = None
            self._last_proxy_audit_error = None
            self._proxy_audit_timer.stop()
            self._proxy_audit_running = False
            self.diagnostics_widget.set_hint(
                f"{base_hint}. System Proxy is OFF, so only apps configured to use these local "
                "proxy ports will use the tunnel."
            )
        self._update_diagnostics_runtime_state()
        self._status_timer.start()
        self._stats_timer.start()
        self._traffic_persistence_timer.start()
        self._kick_stats_poll()

    def _poll_core_status(self) -> None:
        if self._process.is_running():
            self._update_uptime()
            return

        code = self._process.returncode()
        self._status_timer.stop()
        self._stats_timer.stop()
        self._traffic_persistence_timer.stop()
        self.status_label.setText("STOPPED")
        self.start_stop_button.setText("Start")
        self.start_stop_button.setProperty("variant", "primary")
        self._refresh_style(self.start_stop_button)
        self.link_input.setEnabled(True)
        self.profile_selector.setEnabled(True)
        self.manage_profiles_button.setEnabled(True)
        self.validate_button.setEnabled(True)
        self.system_proxy_checkbox.setEnabled(self._system_proxy.is_supported())
        self.ping_button.setEnabled(True if self._validated_link is not None else False)
        self.speed_test_button.setEnabled(False)
        self._health_timer.stop()
        self._proxy_audit_timer.stop()
        self._health_token += 1
        self._stats_token += 1
        self._stats_active_token = None
        self._stats_in_flight = False
        cancel_active_stats_queries(timeout_s=1.0)
        self._set_health_state("offline", "Not running")
        proxy_note = self._restore_system_proxy()
        self._end_traffic_session(final_stats=self._last_known_stats())
        self._core_started_at = None
        self._last_traffic_activity_at = None
        self._set_metrics_defaults()

        suffix = f" (exit code {code})" if code is not None else ""
        hint = f"Core stopped{suffix}. Check logs for details."
        if self._process.stdout_path:
            hint = f"Core stopped{suffix}. Logs: {self._process.stdout_path}"
        if proxy_note:
            hint = f"{hint} {proxy_note}"
        self.diagnostics_widget.set_hint(hint)
        self._update_diagnostics_runtime_state()

    def _stop_core(self, *, user_message: str) -> None:
        self._status_timer.stop()
        self._stats_timer.stop()
        self._traffic_persistence_timer.stop()
        self._health_timer.stop()
        self._proxy_audit_timer.stop()
        self._health_token += 1
        self._stats_token += 1
        self._stats_active_token = None
        self._stats_in_flight = False
        final_stats = self._last_known_stats()
        cancel_active_stats_queries(timeout_s=1.0)
        try:
            self._process.stop()
        except Exception:  # pragma: no cover - defensive
            logger.exception("Stop failed")

        self.status_label.setText("STOPPED")
        self.start_stop_button.setText("Start")
        self.start_stop_button.setProperty("variant", "primary")
        self._refresh_style(self.start_stop_button)
        self.link_input.setEnabled(True)
        self.profile_selector.setEnabled(True)
        self.manage_profiles_button.setEnabled(True)
        self.validate_button.setEnabled(True)
        self.system_proxy_checkbox.setEnabled(self._system_proxy.is_supported())
        self.ping_button.setEnabled(True if self._validated_link is not None else False)
        self.speed_test_button.setEnabled(False)
        self._set_health_state("offline", "Not running")
        self._last_health_result = None
        proxy_note = self._restore_system_proxy()
        self._end_traffic_session(final_stats=final_stats)
        self._core_started_at = None
        self._last_traffic_activity_at = None
        self._set_metrics_defaults()
        if proxy_note:
            self.diagnostics_widget.set_hint(f"{user_message} {proxy_note}")
        else:
            self.diagnostics_widget.set_hint(user_message)
        self._update_diagnostics_runtime_state()

    def _load_profile(self) -> dict:
        profile_path = get_config_dir() / PROFILE_FILE
        data = load_json(profile_path, {})
        if not isinstance(data, dict):
            data = {}

        self._theme = normalize_theme(data.get("theme"))
        self.theme_selector.setCurrentText(theme_display_name(self._theme))
        supported = self._system_proxy.is_supported()
        apply_system_proxy = data.get(PROFILE_KEY_APPLY_SYSTEM_PROXY)
        apply_system_proxy_explicit = data.get(PROFILE_KEY_APPLY_SYSTEM_PROXY_EXPLICIT)

        changed = False
        resolved_apply_system_proxy = supported

        if isinstance(apply_system_proxy, bool) and isinstance(apply_system_proxy_explicit, bool):
            resolved_apply_system_proxy = apply_system_proxy and supported
        elif isinstance(apply_system_proxy, bool):
            # Legacy migration: older versions persisted unchecked as a silent default.
            resolved_apply_system_proxy = supported
            data[PROFILE_KEY_APPLY_SYSTEM_PROXY] = resolved_apply_system_proxy
            data[PROFILE_KEY_APPLY_SYSTEM_PROXY_EXPLICIT] = True
            changed = True
        else:
            data[PROFILE_KEY_APPLY_SYSTEM_PROXY] = resolved_apply_system_proxy
            data[PROFILE_KEY_APPLY_SYSTEM_PROXY_EXPLICIT] = True
            changed = True

        self.system_proxy_checkbox.setChecked(resolved_apply_system_proxy)
        if changed:
            save_json(profile_path, data)
        return data

    def _load_saved_profiles(self, profile_data: dict) -> None:
        self._profile_store.load()
        if self._profile_store.last_load_error:
            QMessageBox.warning(
                self,
                "Saved Profiles Error",
                self._profile_store.last_load_error,
            )
            self.diagnostics_widget.set_hint(self._profile_store.last_load_error)

        self._migrate_legacy_link(profile_data)
        self._refresh_profile_selector(select_profile_id=self._profile_store.default_profile_id)

        default_profile = self._profile_store.get_default()
        if default_profile is not None:
            self._set_selected_profile(default_profile.id, populate_url=True)
            return

        legacy_link = profile_data.get("link")
        if isinstance(legacy_link, str) and legacy_link.strip():
            self.link_input.setText(legacy_link.strip())
            existing = self._profile_store.find_by_url(legacy_link.strip())
            self._selected_profile_id = existing.id if existing is not None else None
            self._refresh_profile_selector(select_profile_id=self._selected_profile_id)

    def _migrate_legacy_link(self, profile_data: dict) -> None:
        already_migrated = bool(profile_data.get(PROFILE_KEY_PROFILES_MIGRATED))
        if already_migrated:
            return

        imported = False
        legacy_link = profile_data.get("link")
        if isinstance(legacy_link, str) and legacy_link.strip() and not self._profile_store.profiles:
            name = "Imported Profile"
            try:
                parsed_link = parse_link(legacy_link.strip())
                display_name = parsed_link.display_name().strip()
                if display_name:
                    name = display_name
            except AppError:
                pass
            profile = Profile.create(name=name, url=legacy_link.strip())
            saved_profile = self._profile_store.add_profile(profile)
            self._profile_store.set_default(saved_profile.id)
            imported = True

        profile_data[PROFILE_KEY_PROFILES_MIGRATED] = True
        save_json(get_config_dir() / PROFILE_FILE, profile_data)
        if imported:
            self.diagnostics_widget.set_hint("Imported your previous saved URL into Saved Profiles.")

    def _refresh_profile_selector(self, *, select_profile_id: str | None = None) -> None:
        profiles = sorted(
            self._profile_store.profiles,
            key=lambda profile: (not profile.favorite, profile.name.lower(), profile.created_at),
        )
        current_target = select_profile_id or self._selected_profile_id

        self._profile_selector_syncing = True
        self.profile_selector.blockSignals(True)
        self.profile_selector.clear()
        self.profile_selector.addItem("Select profile...", None)

        selected_index = 0
        for profile in profiles:
            label = profile.name
            if profile.favorite:
                label = f"★ {label}"
            if self._profile_store.default_profile_id == profile.id:
                label = f"{label} (default)"
            self.profile_selector.addItem(label, profile.id)
            if current_target and current_target == profile.id:
                selected_index = self.profile_selector.count() - 1

        self.profile_selector.setCurrentIndex(selected_index)
        self.profile_selector.blockSignals(False)
        self._profile_selector_syncing = False

    def _set_selected_profile(self, profile_id: str | None, *, populate_url: bool) -> None:
        self._selected_profile_id = profile_id
        self._refresh_profile_selector(select_profile_id=profile_id)
        if not populate_url or not profile_id:
            return
        profile = self._profile_store.get_by_id(profile_id)
        if profile is not None:
            self.link_input.setText(profile.url)

    def _on_profile_selected(self, index: int) -> None:
        if self._profile_selector_syncing:
            return
        profile_id = self.profile_selector.itemData(index)
        if not isinstance(profile_id, str):
            self._selected_profile_id = None
            self._reconcile_runtime_validation_for_current_link()
            return

        profile = self._profile_store.get_by_id(profile_id)
        if profile is None:
            self._selected_profile_id = None
            self._reconcile_runtime_validation_for_current_link()
            return

        self._selected_profile_id = profile.id
        self.link_input.setText(profile.url)
        self._reconcile_runtime_validation_for_current_link()

    def _on_manage_profiles_clicked(self) -> None:
        dialog = ProfileManagerDialog(
            store=self._profile_store,
            validate_fn=self._validate_link_for_dialog,
            parent=self,
        )
        dialog.exec()
        if not dialog.changed:
            return

        current_url = self.link_input.text().strip()
        matched_profile = self._profile_store.find_by_url(current_url)
        target_id = matched_profile.id if matched_profile is not None else self._profile_store.default_profile_id
        self._set_selected_profile(target_id, populate_url=False)

        if not current_url:
            default_profile = self._profile_store.get_default()
            if default_profile is not None:
                self._set_selected_profile(default_profile.id, populate_url=True)

        self._reconcile_runtime_validation_for_current_link()

    def _mark_profile_last_used(self) -> None:
        current_url = self.link_input.text().strip()
        if not current_url:
            return

        profile = None
        if self._selected_profile_id:
            selected = self._profile_store.get_by_id(self._selected_profile_id)
            if selected is not None and selected.url.strip() == current_url:
                profile = selected
        if profile is None:
            profile = self._profile_store.find_by_url(current_url)
        if profile is None:
            return

        self._profile_store.touch_last_used(profile.id)
        self._set_selected_profile(profile.id, populate_url=False)

    def _on_system_proxy_toggled(self, checked: bool) -> None:
        self._save_profile_preferences()
        self._update_diagnostics_runtime_state()

    def _on_theme_changed(self, value: str) -> None:
        self._apply_theme(normalize_theme(value), persist=True)

    def _apply_theme(self, theme: ThemeName, *, persist: bool) -> None:
        self._theme = theme
        app = QApplication.instance()
        if app is not None:
            apply_theme(app, theme)

        if persist:
            self._save_profile_preferences()

        self.theme_selector.blockSignals(True)
        self.theme_selector.setCurrentText(theme_display_name(theme))
        self.theme_selector.blockSignals(False)

        for widget in (
            self.validate_button,
            self.start_stop_button,
            self.theme_selector,
            self.manage_profiles_button,
            self.profile_selector,
            self.check_updates_button,
            self.xray_settings_button,
            self.about_button,
        ):
            self._refresh_style(widget)

    def _save_profile_preferences(self, *, link: str | None = None) -> None:
        profile_path = get_config_dir() / PROFILE_FILE
        data = load_json(profile_path, {})
        if not isinstance(data, dict):
            data = {}
        data["theme"] = self._theme
        data[PROFILE_KEY_APPLY_SYSTEM_PROXY] = bool(self.system_proxy_checkbox.isChecked())
        data[PROFILE_KEY_APPLY_SYSTEM_PROXY_EXPLICIT] = True
        if link is not None:
            data["link"] = link
        data.update(self._current_layout_state())
        save_json(profile_path, data)

    def _current_layout_state(self) -> dict[str, object]:
        geometry = self.normalGeometry() if self.isMaximized() and self.normalGeometry().isValid() else self.geometry()
        return {
            WINDOW_GEOMETRY_KEY: {
                "x": int(geometry.x()),
                "y": int(geometry.y()),
                "width": int(geometry.width()),
                "height": int(geometry.height()),
            },
            WINDOW_MAXIMIZED_KEY: bool(self.isMaximized()),
            TRAFFIC_MONITOR_LAYOUT_KEY: self.traffic_monitor_widget._save_layout_state()
            if hasattr(self, "traffic_monitor_widget")
            else {},
        }

    def _restore_layout_state(self, data: dict) -> None:
        if not isinstance(data, dict):
            self._apply_responsive_layout()
            return
        self._restore_window_geometry(data.get(WINDOW_GEOMETRY_KEY), bool(data.get(WINDOW_MAXIMIZED_KEY, False)))
        traffic_state = data.get(TRAFFIC_MONITOR_LAYOUT_KEY)
        if isinstance(traffic_state, dict) and hasattr(self, "traffic_monitor_widget"):
            self.traffic_monitor_widget._restore_layout_state(traffic_state)
        self._layout_state_loaded = True
        self._apply_responsive_layout()

    def _restore_window_geometry(self, geometry_state: object, maximized: bool) -> None:
        screen = QApplication.primaryScreen()
        available = screen.availableGeometry() if screen is not None else None
        safe_width = 1180
        safe_height = 760
        if available is not None:
            safe_width = min(safe_width, max(640, available.width() - 40))
            safe_height = min(safe_height, max(520, available.height() - 40))

        restored = False
        if isinstance(geometry_state, dict):
            try:
                width = max(640, int(geometry_state.get("width", safe_width)))
                height = max(520, int(geometry_state.get("height", safe_height)))
                x = int(geometry_state.get("x", 0))
                y = int(geometry_state.get("y", 0))
            except (TypeError, ValueError):
                width, height, x, y = safe_width, safe_height, 0, 0

            if available is not None:
                width = min(width, available.width())
                height = min(height, available.height())
                x = min(max(x, available.left()), max(available.left(), available.right() - width + 1))
                y = min(max(y, available.top()), max(available.top(), available.bottom() - height + 1))
                restored = width <= available.width() and height <= available.height()
            else:
                restored = True
            if restored:
                self.setGeometry(x, y, width, height)

        if not restored:
            self.resize(safe_width, safe_height)

        if maximized:
            self.showMaximized()

    def _is_compact_mode(self) -> bool:
        return self.height() < 820 and not self._is_workspace_mode()

    def _is_workspace_mode(self) -> bool:
        return bool(self.isMaximized() or (self.width() >= 1350 and self.height() >= 860))

    def _apply_responsive_layout(self) -> None:
        mode = "workspace" if self._is_workspace_mode() else "compact" if self._is_compact_mode() else "normal"
        if mode == self._last_responsive_mode:
            if hasattr(self, "traffic_monitor_widget"):
                self.traffic_monitor_widget._apply_responsive_layout()
            return
        self._last_responsive_mode = mode
        compact = mode == "compact"
        margins = 8 if compact else 12 if mode == "normal" else 14
        spacing = 6 if compact else 10
        if hasattr(self, "_main_layout"):
            self._main_layout.setContentsMargins(margins, margins, margins, margins)
            self._main_layout.setSpacing(spacing)
        for row in self.findChildren(QPushButton):
            row.setMinimumHeight(30 if compact else 32)
        if hasattr(self, "traffic_monitor_widget"):
            self.traffic_monitor_widget._apply_responsive_layout()

    def _refresh_style(self, widget) -> None:
        style = widget.style()
        style.unpolish(widget)
        style.polish(widget)
        widget.update()

    def _pick_proxy_ports(self) -> tuple[int, int, int]:
        socks_port = DEFAULT_SOCKS_PORT
        http_port = DEFAULT_HTTP_PORT
        api_port = DEFAULT_API_PORT

        try:
            ensure_port_available(DEFAULT_LISTEN, socks_port)
        except AppError:
            socks_port = find_free_port(DEFAULT_LISTEN)

        try:
            ensure_port_available(DEFAULT_LISTEN, http_port)
        except AppError:
            http_port = find_free_port(DEFAULT_LISTEN)

        while http_port == socks_port:
            http_port = find_free_port(DEFAULT_LISTEN)

        try:
            ensure_port_available(DEFAULT_LISTEN, api_port)
        except AppError:
            api_port = find_free_port(DEFAULT_LISTEN)

        while api_port in {socks_port, http_port}:
            api_port = find_free_port(DEFAULT_LISTEN)

        return socks_port, http_port, api_port

    def _set_metrics_defaults(self) -> None:
        self.uptime_label.setText("UPTIME (00:00:00)")
        self.speed_label.setText("SPEED (↑ 0.0 Mbps / ↓ 0.0 Mbps)")
        self.traffic_label.setText("TRAFFIC (↑ 0 B / ↓ 0 B)")
        if hasattr(self, "traffic_monitor_widget"):
            self.traffic_monitor_widget.update_live_sample(None)

    def _last_known_stats(self) -> TrafficStats | None:
        if self._last_uplink is None or self._last_downlink is None:
            return None
        return TrafficStats(
            uplink_bytes=int(self._last_uplink),
            downlink_bytes=int(self._last_downlink),
        )

    def _active_traffic_profile(self) -> tuple[str | None, str, str | None]:
        current_url = self.link_input.text().strip()
        profile = None
        if self._validated_profile_id:
            candidate = self._profile_store.get_by_id(self._validated_profile_id)
            if candidate is not None and candidate.url.strip() == current_url:
                profile = candidate
        if profile is None:
            profile = self._profile_for_current_link()
        if profile is None:
            return None, "Unsaved profile", self._validated_fingerprint or connection_fingerprint(current_url)
        return profile.id, profile.name, self._validated_fingerprint or connection_fingerprint(profile.url)

    def _traffic_api_server(self) -> str | None:
        if self._api_port is None:
            return None
        return f"{DEFAULT_LISTEN}:{self._api_port}"

    def _start_traffic_session(self) -> None:
        self._traffic_session_id = None
        self._last_traffic_sample = None
        self._pending_traffic_stats = None
        self._traffic_session_uplink_bytes = 0
        self._traffic_session_downlink_bytes = 0
        self.traffic_monitor_widget.set_current_session(None)
        if not self._traffic_settings.proxy_history_enabled:
            self._refresh_traffic_monitor()
            return
        if self._traffic_store is None:
            self._last_traffic_store_error = self._last_traffic_store_error or "Traffic store unavailable."
            self._refresh_traffic_monitor()
            return

        profile_id, profile_name, fingerprint = self._active_traffic_profile()
        try:
            self._traffic_session_id = self._traffic_store.start_proxy_session(
                profile_id=profile_id,
                profile_name=profile_name,
                connection_fingerprint=fingerprint,
                initial_stats=TrafficStats(uplink_bytes=0, downlink_bytes=0),
                api_server=self._traffic_api_server(),
                socks_port=int(self._socks_port),
                http_port=int(self._http_port),
            )
            self._last_traffic_store_error = None
            self.traffic_monitor_widget.set_current_session(self._traffic_session_id)
        except Exception as exc:  # pragma: no cover - defensive persistence guard
            logger.exception("Failed to start traffic session")
            self._last_traffic_store_error = str(exc)
        self._refresh_traffic_monitor()

    def _record_traffic_sample(self, stats: TrafficStats) -> ProxyTrafficSample | None:
        # Hot path is memory-only. The five-second persistence timer queues cumulative
        # counters to the bounded storage worker, so work does not grow with DB size.
        if not self._traffic_settings.proxy_history_enabled:
            return None
        if self._traffic_session_id is None:
            return None
        previous_up = self._last_uplink if self._last_uplink is not None else 0
        previous_down = self._last_downlink if self._last_downlink is not None else 0
        raw_up_delta = int(stats.uplink_bytes) - int(previous_up)
        raw_down_delta = int(stats.downlink_bytes) - int(previous_down)
        warnings: list[str] = []
        up_delta = max(0, raw_up_delta)
        down_delta = max(0, raw_down_delta)
        if raw_up_delta < 0:
            warnings.append(f"uplink counter reset/decreased ({previous_up} -> {stats.uplink_bytes})")
        if raw_down_delta < 0:
            warnings.append(f"downlink counter reset/decreased ({previous_down} -> {stats.downlink_bytes})")
        now = time.monotonic()
        elapsed = max(0.001, now - self._last_stats_at) if self._last_stats_at is not None else 1.0
        self._traffic_session_uplink_bytes += up_delta
        self._traffic_session_downlink_bytes += down_delta
        sample = ProxyTrafficSample(
            session_id=self._traffic_session_id,
            timestamp=self._now_iso_seconds(),
            uplink_bytes=int(stats.uplink_bytes),
            downlink_bytes=int(stats.downlink_bytes),
            uplink_delta_bytes=up_delta,
            downlink_delta_bytes=down_delta,
            upload_bps=float(up_delta) / elapsed,
            download_bps=float(down_delta) / elapsed,
            session_uplink_bytes=self._traffic_session_uplink_bytes,
            session_downlink_bytes=self._traffic_session_downlink_bytes,
            warning="; ".join(warnings) if warnings else None,
        )
        self._last_traffic_sample = sample
        self._pending_traffic_stats = stats
        self.traffic_monitor_widget.update_live_sample(sample)
        return sample

    def _persist_latest_traffic_sample(self) -> None:
        worker = self._traffic_storage_worker
        session_id = self._traffic_session_id
        stats = self._pending_traffic_stats
        if self._closing or worker is None or session_id is None or stats is None:
            return
        if not worker.submit_sample(session_id, stats):
            self._last_traffic_store_error = "Traffic persistence queue is full; latest counters will be retried."
            return
        self._last_traffic_store_error = worker.last_error

    def _end_traffic_session(self, *, final_stats: TrafficStats | None = None) -> None:
        session_id = self._traffic_session_id
        if self._traffic_store is not None and session_id is not None:
            try:
                persisted = False
                if self._traffic_storage_worker is not None:
                    persisted = self._traffic_storage_worker.end_session(
                        session_id,
                        final_stats,
                        timeout_s=TRAFFIC_FINAL_FLUSH_TIMEOUT_S,
                    )
                if not persisted:
                    self._traffic_store.end_proxy_session(session_id, final_stats=final_stats)
                self._last_traffic_store_error = None
            except Exception as exc:  # pragma: no cover - defensive persistence guard
                logger.exception("Failed to end traffic session")
                self._last_traffic_store_error = str(exc)
        self._traffic_session_id = None
        self._last_traffic_sample = None
        self._pending_traffic_stats = None
        self.traffic_monitor_widget.set_current_session(None)
        self._refresh_traffic_monitor()

    def _refresh_traffic_monitor(self) -> None:
        if not hasattr(self, "traffic_monitor_widget"):
            return
        self._update_traffic_monitor_diagnostics()
        if self._traffic_monitor_is_visible():
            self.traffic_monitor_widget.refresh_visible_tab(force=True)

    def _update_traffic_monitor_diagnostics(self) -> None:
        if not hasattr(self, "traffic_monitor_widget"):
            return
        warning = None
        if self._last_traffic_sample is not None and self._last_traffic_sample.warning:
            warning = self._last_traffic_sample.warning
        elif not self._stats_available:
            warning = self._last_stats_query_result
        worker_error = (
            self._traffic_storage_worker.last_error
            if self._traffic_storage_worker is not None
            else None
        )
        self.traffic_monitor_widget.set_diagnostics(
            api_server=self._traffic_api_server(),
            stats_available=self._stats_available,
            last_stats_query_time=self._last_stats_query_time,
            last_sample_time=(
                self._last_traffic_sample.timestamp if self._last_traffic_sample is not None else None
            ),
            warning=warning,
            store_error=self._last_traffic_store_error or worker_error,
        )

    def _traffic_monitor_is_visible(self) -> bool:
        return bool(
            not self._closing
            and self.isVisible()
            and not self.isMinimized()
            and self.runtime_tabs.currentWidget() is self.traffic_monitor_widget
        )

    def _on_runtime_tab_changed(self, _index: int) -> None:
        if self._closing or not self.isVisible() or self.isMinimized():
            return
        current = self.runtime_tabs.currentWidget()
        if current is self.traffic_monitor_widget:
            self._update_traffic_monitor_diagnostics()
            self.traffic_monitor_widget.refresh_visible_tab(force=True)
        elif current is self.diagnostics_widget:
            self._update_diagnostics_runtime_state(expensive=True)
            self.diagnostics_widget.refresh()

    def _refresh_scheduled_overview(self) -> None:
        if not self._traffic_monitor_is_visible():
            return
        if self.traffic_monitor_widget.tabs.currentIndex() == 0:
            started_at = time.monotonic()
            self.traffic_monitor_widget.refresh_overview()
            self._last_overview_refresh_ms = (time.monotonic() - started_at) * 1000.0

    def _refresh_scheduled_diagnostics(self) -> None:
        if self._closing or not self.isVisible() or self.isMinimized():
            return
        current = self.runtime_tabs.currentWidget()
        if current is self.traffic_monitor_widget:
            if self.traffic_monitor_widget.tabs.currentIndex() != 5:
                return
            self._update_diagnostics_runtime_state(expensive=True)
            self._update_traffic_monitor_diagnostics()
            self.traffic_monitor_widget.refresh_diagnostics()
        elif current is self.diagnostics_widget:
            self._update_diagnostics_runtime_state(expensive=True)
            self.diagnostics_widget.refresh()

    def _on_traffic_settings_changed(self, settings: object) -> None:
        if not isinstance(settings, TrafficSettings):
            return
        self._traffic_settings = settings
        self._netmon_client = NetmonClient(provider=settings.netmon_provider)
        if settings.app_tracking_enabled:
            self._netmon_client.start_tracking()
        else:
            self._netmon_client.stop_tracking()
        self.traffic_monitor_widget.set_netmon_client(self._netmon_client)
        if self._traffic_storage_worker is not None:
            self._traffic_storage_worker.submit_cleanup(
                settings.detailed_retention_days,
                force=True,
            )
        self._update_diagnostics_runtime_state()

    def _tcp_reachable(self, host: str, port: int, *, timeout_s: float = 0.25) -> bool:
        try:
            sock = socket.create_connection((host, int(port)), timeout=timeout_s)
        except OSError:
            return False
        sock.close()
        return True

    def _listener_reachability(self) -> tuple[bool, bool]:
        if not self._process.is_running():
            return False, False
        http_ok = self._tcp_reachable(DEFAULT_LISTEN, int(self._http_port))
        socks_ok = self._tcp_reachable(DEFAULT_LISTEN, int(self._socks_port))
        return http_ok, socks_ok

    def _recent_traffic_flowing(self, *, now: float | None = None) -> bool:
        if self._last_traffic_activity_at is None:
            return False
        current = now if now is not None else time.monotonic()
        return (current - self._last_traffic_activity_at) <= RECENT_TRAFFIC_WINDOW_S

    def _proxy_status_to_dict(self, status) -> dict[str, object] | None:
        if status is None:
            return None
        return {
            "mode": status.mode,
            "http_enabled": bool(status.http_enabled),
            "http_host": status.http_host,
            "http_port": int(status.http_port),
            "socks_host": status.socks_host,
            "socks_port": int(status.socks_port),
        }

    def _update_diagnostics_runtime_state(self, *, expensive: bool = False) -> None:
        if expensive:
            self._kick_runtime_diagnostics_refresh()
        http_ok, socks_ok = self._cached_listener_reachability
        audit = self._last_proxy_audit
        now = time.monotonic()
        xray_resolution = self._current_xray_resolution(refresh=False)
        xray_assets = xray_asset_status(xray_resolution)
        cleanup = (
            self._traffic_storage_worker.last_cleanup
            if self._traffic_storage_worker is not None
            else None
        )
        storage_diagnostics = self._cached_storage_diagnostics
        write_metrics = (
            self._traffic_storage_worker.write_metrics
            if self._traffic_storage_worker is not None
            else {}
        )
        monitor_metrics = self.traffic_monitor_widget.performance_snapshot()
        stats_completed = self._stats_queries_completed

        desired = self._proxy_status_to_dict(audit.desired if audit is not None else None)
        actual = self._proxy_status_to_dict(audit.actual if audit is not None else None)
        mismatches: list[str] = []
        if audit is not None and audit.mismatches:
            mismatches = list(audit.mismatches)

        if desired is None and self._system_proxy_cfg is not None:
            cfg = self._system_proxy_cfg
            desired = {
                "mode": "manual",
                "http_enabled": True,
                "http_host": cfg.http_host,
                "http_port": int(cfg.http_port),
                "socks_host": cfg.socks_host,
                "socks_port": int(cfg.socks_port),
            }

        state = {
            "system_proxy": {
                "enabled_preference": bool(self.system_proxy_checkbox.isChecked()),
                "supported": bool(self._system_proxy.is_supported()),
                "applied_by_session": bool(self._system_proxy_applied),
                "backend": self._system_proxy.backend,
                "desired": desired,
                "actual": actual,
                "matches_desired": bool(audit.matches_desired) if audit is not None else None,
                "mismatches": mismatches,
                "last_audit_error": self._last_proxy_audit_error,
                "last_auto_reapply_at": self._last_proxy_reapply_at,
                "last_auto_reapply_reason": self._last_proxy_reapply_reason,
            },
            "xray": {
                "running": bool(self._process.is_running()),
                "pid": self._process.pid,
                "stats_query_pid": active_stats_query_pid(),
                "status": "found" if xray_resolution.valid else "missing",
                "source": xray_resolution.source,
                "binary_path": self._process.binary_path,
                "resolved_path": xray_resolution.path,
                "version": xray_resolution.version,
                "architecture": xray_resolution.architecture,
                "valid": xray_resolution.valid,
                "error": xray_resolution.error,
                "warning": xray_resolution.warning,
                "bundled_missing_in_packaged_build": (
                    detect_runtime_kind() in {"appimage", "deb"} and xray_resolution.source != "bundled"
                ),
                **xray_assets,
                "stats_api_configured": self._api_port is not None,
                "stats_api_server": self._traffic_api_server(),
                "last_stats_query_result": self._last_stats_query_result,
                "last_stats_query_time": self._last_stats_query_time,
                "last_stats_query_duration_ms": self._last_stats_query_duration_ms,
                "stats_query_in_flight": self._stats_in_flight,
                "stats_skipped_polls": self._stats_skipped_polls,
                "health_state": self._health_state,
                "health_detail": self._health_detail,
                "health_checked_url": (
                    self._last_health_result.checked_url if self._last_health_result is not None else None
                ),
                "health_status_code": (
                    self._last_health_result.status_code if self._last_health_result is not None else None
                ),
                "health_latency_ms": (
                    self._last_health_result.latency_ms if self._last_health_result is not None else None
                ),
                "health_error": (
                    self._last_health_result.error if self._last_health_result is not None else None
                ),
                "http_listener_reachable": http_ok,
                "socks_listener_reachable": socks_ok,
                "recent_traffic_flowing": self._recent_traffic_flowing(now=now),
            },
            "traffic": {
                "db_path": str(self._traffic_store.db_path) if self._traffic_store is not None else None,
                "current_session_active": self._traffic_session_id is not None,
                "last_sample_time": (
                    self._last_traffic_sample.timestamp
                    if self._last_traffic_sample is not None
                    else None
                ),
                "last_store_error": self._last_traffic_store_error,
                "persistence_queue_size": (
                    self._traffic_storage_worker.queue_size
                    if self._traffic_storage_worker is not None
                    else 0
                ),
                "persistence_queue_dropped": (
                    self._traffic_storage_worker.dropped_requests
                    if self._traffic_storage_worker is not None
                    else 0
                ),
                "persistence_worker_error": (
                    self._traffic_storage_worker.last_error
                    if self._traffic_storage_worker is not None
                    else None
                ),
                "last_retention_cleanup_at": cleanup.completed_at if cleanup is not None else None,
                "last_retention_cleanup_duration_ms": cleanup.duration_ms if cleanup is not None else None,
                "last_retention_cleanup_rows_removed": cleanup.rows_removed if cleanup is not None else None,
                "last_retention_cleanup_error": cleanup.error if cleanup is not None else None,
                "proxy_history_enabled": bool(self._traffic_settings.proxy_history_enabled),
                "app_tracking_enabled": bool(self._traffic_settings.app_tracking_enabled),
                "detailed_retention_days": int(self._traffic_settings.detailed_retention_days),
                "daily_retention_days": int(self._traffic_settings.daily_retention_days),
                "app_tables_present": bool(storage_diagnostics.get("app_tables_present", False)),
                "database_size_bytes": storage_diagnostics.get("db_size_bytes"),
                "wal_size_bytes": storage_diagnostics.get("wal_size_bytes"),
                "session_count": storage_diagnostics.get("session_count"),
                "sample_count": storage_diagnostics.get("sample_count"),
                "current_session_sample_count": storage_diagnostics.get(
                    "current_session_sample_count"
                ),
                "diagnostics_error": storage_diagnostics.get("error"),
                "netmon": self._cached_netmon_diagnostics,
            },
            "performance": {
                "closing": self._closing,
                "current_runtime_tab": self.runtime_tabs.tabText(self.runtime_tabs.currentIndex()),
                "current_traffic_tab": self.traffic_monitor_widget.tabs.tabText(
                    self.traffic_monitor_widget.tabs.currentIndex()
                ),
                "stats_interval_ms": STATS_INTERVAL_MS,
                "stats_in_flight": self._stats_in_flight,
                "stats_started": self._stats_queries_started,
                "stats_completed": stats_completed,
                "stats_skipped": self._stats_skipped_polls,
                "stats_last_ms": self._last_stats_query_duration_ms,
                "stats_average_ms": (
                    self._stats_query_duration_total_ms / stats_completed
                    if stats_completed
                    else None
                ),
                "stats_max_ms": self._stats_query_duration_max_ms,
                "stats_failures": self._stats_query_failures,
                "live_callback_average_ms": (
                    self._stats_callback_duration_total_ms / self._stats_callback_count
                    if self._stats_callback_count
                    else None
                ),
                "live_callback_max_ms": self._stats_callback_duration_max_ms,
                "persistence_interval_ms": TRAFFIC_PERSISTENCE_INTERVAL_MS,
                "persistence_queue_depth": (
                    self._traffic_storage_worker.queue_size
                    if self._traffic_storage_worker is not None
                    else 0
                ),
                "db_write_last_ms": write_metrics.get("last_ms"),
                "db_write_average_ms": write_metrics.get("average_ms"),
                "db_write_failures": write_metrics.get("failures", 0),
                "overview_refresh_last_ms": self._last_overview_refresh_ms,
                **monitor_metrics,
                "thresholds_ms": {
                    "stats_query": SLOW_STATS_QUERY_MS,
                    "database_write": SLOW_DATABASE_WRITE_MS,
                    "overview_refresh": SLOW_OVERVIEW_REFRESH_MS,
                    "history_refresh": SLOW_HISTORY_REFRESH_MS,
                },
            },
        }
        self.diagnostics_widget.set_runtime_state(state)

    def _kick_runtime_diagnostics_refresh(self) -> None:
        if self._closing or self._runtime_diagnostics_in_flight:
            return
        self._runtime_diagnostics_in_flight = True
        self._runtime_diagnostics_token += 1
        token = self._runtime_diagnostics_token
        store = self._traffic_store
        session_id = self._traffic_session_id

        def _run():
            listener_state = self._listener_reachability()
            try:
                netmon_state: dict[str, object] = asdict(self._netmon_client.get_status())
            except Exception as exc:  # pragma: no cover - defensive diagnostics guard
                netmon_state = {"last_error": str(exc)}
            storage_state: dict[str, object] = {}
            if store is not None:
                try:
                    history = store.get_history_diagnostics()
                    db_path = store.db_path
                    wal_path = Path(f"{db_path}-wal")
                    storage_state = {
                        "app_tables_present": store.app_tables_present(),
                        "db_size_bytes": db_path.stat().st_size if db_path.exists() else 0,
                        "wal_size_bytes": wal_path.stat().st_size if wal_path.exists() else 0,
                        "session_count": history.session_count,
                        "sample_count": history.sample_count,
                        "current_session_sample_count": (
                            store.get_session_sample_count(session_id)
                            if session_id is not None
                            else 0
                        ),
                    }
                except Exception as exc:  # pragma: no cover - diagnostics remain usable
                    storage_state = {"error": str(exc)}
            return token, listener_state, netmon_state, storage_state

        worker = HealthCheckWorker(_run)
        worker.signals.result.connect(self._on_runtime_diagnostics_result)
        worker.signals.error.connect(
            lambda message: self._on_runtime_diagnostics_error(token, message)
        )
        self._thread_pool.start(worker)

    def _on_runtime_diagnostics_result(self, payload: object) -> None:
        token, listener_state, netmon_state, storage_state = payload  # type: ignore[misc]
        if self._closing or token != self._runtime_diagnostics_token:
            return
        self._runtime_diagnostics_in_flight = False
        self._cached_listener_reachability = listener_state
        self._cached_netmon_diagnostics = netmon_state
        self._cached_storage_diagnostics = storage_state
        self._update_diagnostics_runtime_state()
        if self.runtime_tabs.currentWidget() is self.diagnostics_widget:
            self.diagnostics_widget.refresh()

    def _on_runtime_diagnostics_error(self, token: int, message: str) -> None:
        if self._closing or token != self._runtime_diagnostics_token:
            return
        self._runtime_diagnostics_in_flight = False
        self._cached_storage_diagnostics = {"error": message}
        self._update_diagnostics_runtime_state()

    def _audit_system_proxy_runtime(self) -> None:
        if self._closing or self._proxy_audit_running:
            return
        if not self._process.is_running() or not self._system_proxy_applied or self._system_proxy_cfg is None:
            self._proxy_audit_timer.stop()
            return

        self._proxy_audit_running = True
        self._proxy_audit_finished.clear()
        token = self._proxy_audit_token
        self._proxy_audit_active_token = token
        now = time.monotonic()
        cfg = self._system_proxy_cfg
        allow_reconcile = now >= self._next_proxy_reconcile_at

        def _run():
            try:
                audit = self._system_proxy.audit_runtime(cfg, reconcile=False)
                drift_reason = "; ".join(audit.mismatches)
                reconciled = False
                if self._closing or token != self._proxy_audit_token:
                    return token, "stale", audit, drift_reason, False, now
                if audit.mismatches and allow_reconcile:
                    audit = self._system_proxy.audit_runtime(cfg, reconcile=True)
                    reconciled = True
                return token, "ok", audit, drift_reason, reconciled, now
            except AppError as exc:
                return token, "error", exc.user_message, True, False, now
            except Exception as exc:  # pragma: no cover - defensive
                return token, "error", str(exc), False, False, now
            finally:
                self._proxy_audit_finished.set()

        worker = HealthCheckWorker(_run)
        worker.signals.result.connect(self._on_proxy_audit_result)
        worker.signals.error.connect(lambda message: self._on_proxy_audit_worker_error(token, message))
        self._thread_pool.start(worker)

    def _on_proxy_audit_result(self, payload: object) -> None:
        token, kind, value, detail, reconciled, started_at = payload  # type: ignore[misc]
        if token != self._proxy_audit_active_token:
            return
        self._proxy_audit_running = False
        self._proxy_audit_active_token = None
        if self._closing or token != self._proxy_audit_token:
            return
        if not self._process.is_running() or not self._system_proxy_applied or self._system_proxy_cfg is None:
            return
        if kind == "error":
            self._handle_proxy_audit_error(str(value), expected=bool(detail), now=float(started_at))
            return

        audit = value
        self._last_proxy_audit = audit
        self._last_proxy_audit_error = None
        drift_reason = str(detail)
        if reconciled:
            self._proxy_audit_failures = 0
            self._next_proxy_reconcile_at = 0.0
            self._last_proxy_reapply_at = time.strftime("%Y-%m-%d %H:%M:%S")
            self._last_proxy_reapply_reason = drift_reason
            self.diagnostics_widget.set_hint(
                f"System proxy drift detected and auto-reapplied ({drift_reason})."
            )
        elif audit.mismatches:
            wait_s = max(0.0, self._next_proxy_reconcile_at - time.monotonic())
            logger.debug("System proxy drift detected, waiting %.1fs before reconcile retry", wait_s)
            self.diagnostics_widget.set_hint(
                f"System proxy drift detected; retrying auto-reapply in {wait_s:.1f}s."
            )
        else:
            self._proxy_audit_failures = 0
            self._next_proxy_reconcile_at = 0.0

    def _on_proxy_audit_worker_error(self, token: int, message: str) -> None:
        if token != self._proxy_audit_active_token:
            return
        self._proxy_audit_running = False
        self._proxy_audit_active_token = None
        if not self._closing and token == self._proxy_audit_token:
            self._handle_proxy_audit_error(message, expected=False, now=time.monotonic())

    def _handle_proxy_audit_error(self, message: str, *, expected: bool, now: float) -> None:
        self._last_proxy_audit_error = message
        self._proxy_audit_failures += 1
        backoff = min(PROXY_AUDIT_MAX_BACKOFF_S, float(2 ** min(self._proxy_audit_failures, 5)))
        self._next_proxy_reconcile_at = now + backoff
        logger.warning(
            "System proxy audit failed (attempt %s, backoff %.1fs): %s",
            self._proxy_audit_failures,
            backoff,
            message,
        )
        suffix = message if expected else "an unexpected error"
        self.diagnostics_widget.set_hint(
            f"System proxy drift detected, but auto-reapply failed: {suffix}."
        )

    def _update_uptime(self) -> None:
        if self._core_started_at is None:
            self.uptime_label.setText("UPTIME (00:00:00)")
            return
        self.uptime_label.setText(
            f"UPTIME ({format_duration_s(time.monotonic() - self._core_started_at)})"
        )

    def _kick_stats_poll(self) -> None:
        if self._closing:
            return
        if self._stats_in_flight:
            self._stats_skipped_polls += 1
            logger.debug("Skipping stats poll while request is in flight (skipped=%s)", self._stats_skipped_polls)
            return
        if self._api_port is None:
            return
        if not self._process.is_running():
            return

        token = self._stats_token
        api_server = f"{DEFAULT_LISTEN}:{self._api_port}"
        xray_path = self._process.binary.path
        self._stats_in_flight = True
        self._stats_active_token = token
        self._stats_query_started_at = time.monotonic()
        self._stats_queries_started = getattr(self, "_stats_queries_started", 0) + 1

        def _run():
            started_at = time.monotonic()
            try:
                stats = get_outbound_traffic(
                    xray_path,
                    server=api_server,
                    timeout_s=STATS_QUERY_TIMEOUT_S,
                )
            except Exception as exc:
                finished_at = time.monotonic()
                return token, finished_at, (finished_at - started_at) * 1000.0, exc
            finished_at = time.monotonic()
            return token, finished_at, (finished_at - started_at) * 1000.0, stats

        worker = HealthCheckWorker(_run)
        worker.signals.result.connect(self._on_stats_worker_finished)
        worker.signals.error.connect(
            lambda msg: self._on_stats_error(
                token,
                msg,
                max(0.0, (time.monotonic() - (self._stats_query_started_at or time.monotonic())) * 1000.0),
            )
        )
        self._thread_pool.start(worker)

    def _on_stats_worker_finished(self, payload: object) -> None:
        token, _now, duration_ms, result = payload  # type: ignore[misc]
        if isinstance(result, Exception):
            message = result.user_message if isinstance(result, AppError) else str(result)
            self._on_stats_error(int(token), message, float(duration_ms))
            return
        self._on_stats_result(payload)

    def _on_stats_result(self, payload: object) -> None:
        callback_started_at = time.monotonic()
        token, now, duration_ms, stats = payload  # type: ignore[misc]
        if token != self._stats_active_token:
            return
        self._stats_in_flight = False
        self._stats_active_token = None
        self._stats_query_started_at = None
        self._last_stats_query_duration_ms = float(duration_ms)
        self._stats_queries_completed = getattr(self, "_stats_queries_completed", 0) + 1
        self._stats_query_duration_total_ms = (
            getattr(self, "_stats_query_duration_total_ms", 0.0) + float(duration_ms)
        )
        self._stats_query_duration_max_ms = max(
            getattr(self, "_stats_query_duration_max_ms", 0.0),
            float(duration_ms),
        )
        if token != self._stats_token or self._closing:
            logger.debug("Ignoring stale stats result for generation %s", token)
            return
        if not isinstance(stats, TrafficStats):  # pragma: no cover - defensive
            return

        self._stats_available = True
        self._last_stats_query_result = (
            f"ok: uplink={stats.uplink_bytes} downlink={stats.downlink_bytes}"
        )
        self._last_stats_query_time = self._now_iso_seconds()
        logger.debug(
            "Stats poll succeeded in %.1f ms (uplink=%s downlink=%s)",
            duration_ms,
            stats.uplink_bytes,
            stats.downlink_bytes,
        )
        traffic_sample = self._record_traffic_sample(stats)

        self.traffic_label.setText(
            f"TRAFFIC (↑ {format_bytes(stats.uplink_bytes)} / ↓ {format_bytes(stats.downlink_bytes)})"
        )

        # Speed = delta bytes / delta time.
        up_delta = 0
        down_delta = 0
        up_bps = 0.0
        down_bps = 0.0
        if self._last_stats_at is not None and self._last_uplink is not None and self._last_downlink is not None:
            dt = max(0.001, float(now) - float(self._last_stats_at))
            up_delta = int(stats.uplink_bytes - self._last_uplink)
            down_delta = int(stats.downlink_bytes - self._last_downlink)
            up_bps = up_delta / dt
            down_bps = down_delta / dt
            if traffic_sample is not None:
                up_bps = traffic_sample.upload_bps
                down_bps = traffic_sample.download_bps
            self.speed_label.setText(
                f"SPEED (↑ {format_mbps(up_bps)} / ↓ {format_mbps(down_bps)})"
            )

        if up_delta > 0 or down_delta > 0:
            self._last_traffic_activity_at = float(now)

        self._last_stats_at = float(now)
        self._last_uplink = int(stats.uplink_bytes)
        self._last_downlink = int(stats.downlink_bytes)
        if traffic_sample is None:
            self.traffic_monitor_widget.update_live_metrics(
                upload_bps=up_bps,
                download_bps=down_bps,
                session_uplink_bytes=stats.uplink_bytes,
                session_downlink_bytes=stats.downlink_bytes,
                last_stats_timestamp=self._last_stats_query_time,
            )
        self._update_traffic_monitor_diagnostics()

        callback_ms = (time.monotonic() - callback_started_at) * 1000.0
        self._stats_callback_count = getattr(self, "_stats_callback_count", 0) + 1
        self._stats_callback_duration_total_ms = (
            getattr(self, "_stats_callback_duration_total_ms", 0.0) + callback_ms
        )
        self._stats_callback_duration_max_ms = max(
            getattr(self, "_stats_callback_duration_max_ms", 0.0),
            callback_ms,
        )
        logger.debug("Live stats callback completed in %.1f ms", callback_ms)
        if callback_ms > SLOW_STATS_CALLBACK_MS:
            current = time.monotonic()
            last_warning = self._last_slow_stats_callback_warning_at
            if last_warning is None or current - last_warning >= SLOW_STATS_WARNING_INTERVAL_S:
                logger.warning("Live stats callback took %.1f ms", callback_ms)
                self._last_slow_stats_callback_warning_at = current

    def _on_stats_error(self, token: int, message: str, duration_ms: float = 0.0) -> None:
        if token != self._stats_active_token:
            return
        self._stats_in_flight = False
        self._stats_active_token = None
        self._stats_query_started_at = None
        self._last_stats_query_duration_ms = float(duration_ms)
        self._stats_queries_completed = getattr(self, "_stats_queries_completed", 0) + 1
        if token != self._stats_token or self._closing:
            logger.debug("Ignoring stale stats error for generation %s: %s", token, message)
            return
        self._stats_query_failures = getattr(self, "_stats_query_failures", 0) + 1
        self._stats_query_duration_total_ms = (
            getattr(self, "_stats_query_duration_total_ms", 0.0) + float(duration_ms)
        )
        self._stats_query_duration_max_ms = max(
            getattr(self, "_stats_query_duration_max_ms", 0.0),
            float(duration_ms),
        )
        # Keep the UI stable; stats may be unavailable if API isn't ready yet.
        now = time.monotonic()
        should_warn = (
            message != self._last_stats_failure_message
            or self._last_stats_failure_log_at is None
            or now - self._last_stats_failure_log_at >= 30.0
        )
        if should_warn:
            logger.warning("Stats poll failed after %.1f ms: %s", duration_ms, message)
            self._last_stats_failure_log_at = now
            self._last_stats_failure_message = message
        else:
            logger.debug("Stats poll still failing after %.1f ms: %s", duration_ms, message)
        self._stats_available = False
        self._last_stats_query_result = message
        self._last_stats_query_time = self._now_iso_seconds()
        self._update_traffic_monitor_diagnostics()

    def _now_iso_seconds(self) -> str:
        return datetime.now().astimezone().isoformat(timespec="seconds")

    def _on_ping_clicked(self) -> None:
        if self._ping_in_flight:
            return
        if self._validated_link is None:
            self.diagnostics_widget.set_hint("Validate & Save a link first.")
            return

        link = self._validated_link
        self._ping_in_flight = True
        self.ping_button.setEnabled(False)
        self.diagnostics_widget.set_hint(f"Pinging {link.host}:{link.port} ...")

        def _run():
            return ping_server(
                link.host,
                link.port,
                security=link.security,
                sni=link.sni,
                allow_insecure=link.allow_insecure,
                timeout_s=4.0,
            )

        worker = HealthCheckWorker(_run)
        worker.signals.result.connect(self._on_ping_result)
        worker.signals.error.connect(self._on_ping_error)
        self._thread_pool.start(worker)

    def _on_ping_result(self, payload: object) -> None:
        if self._closing:
            return
        self._ping_in_flight = False
        self.ping_button.setEnabled(True)
        if not isinstance(payload, ServerPingResult):  # pragma: no cover - defensive
            self.diagnostics_widget.set_hint("Ping failed: invalid result.")
            return

        parts: list[str] = []
        if payload.tcp_ms is not None:
            parts.append(f"TCP {payload.tcp_ms} ms")
        if payload.tls_sni_ms is not None:
            parts.append(f"TLS(SNI) {payload.tls_sni_ms} ms")
        if payload.tls_host_ms is not None:
            parts.append(f"TLS(host) {payload.tls_host_ms} ms")
        summary = ", ".join(parts) if parts else "No timing data"
        if payload.error:
            summary = f"{summary}. {payload.error}"
        self.diagnostics_widget.set_hint(f"Ping: {summary}")

    def _on_ping_error(self, message: str) -> None:
        if self._closing:
            return
        self._ping_in_flight = False
        self.ping_button.setEnabled(True)
        self.diagnostics_widget.set_hint(f"Ping failed: {message}")

    def _on_speed_test_clicked(self) -> None:
        if self._speed_test_in_flight:
            return
        if not self._process.is_running():
            self.diagnostics_widget.set_hint("Start the core first.")
            return

        self._speed_test_in_flight = True
        self.speed_test_button.setEnabled(False)
        self.diagnostics_widget.set_hint("Running speed test (download + upload) ...")

        http_port = self._http_port

        def _run():
            return run_speed_test_via_http_proxy(DEFAULT_LISTEN, http_port)

        worker = HealthCheckWorker(_run)
        worker.signals.result.connect(self._on_speed_test_result)
        worker.signals.error.connect(self._on_speed_test_error)
        self._thread_pool.start(worker)

    def _on_speed_test_result(self, payload: object) -> None:
        if self._closing:
            return
        self._speed_test_in_flight = False
        self.speed_test_button.setEnabled(True)
        if not isinstance(payload, SpeedTestResult):  # pragma: no cover - defensive
            self.diagnostics_widget.set_hint("Speed test failed: invalid result.")
            return

        if payload.error:
            self.diagnostics_widget.set_hint(f"Speed test failed: {payload.error}")
            return

        down = format_mbps(payload.download_bps or 0.0)
        up = format_mbps(payload.upload_bps or 0.0)
        self.diagnostics_widget.set_hint(f"Speed test: ↓ {down} / ↑ {up}")

    def _on_speed_test_error(self, message: str) -> None:
        if self._closing:
            return
        self._speed_test_in_flight = False
        self.speed_test_button.setEnabled(True)
        self.diagnostics_widget.set_hint(f"Speed test failed: {message}")

    def _validation_warning(self, link) -> str | None:
        if getattr(link, "security", None) != "tls":
            return None
        if bool(getattr(link, "allow_insecure", False)):
            return None

        host = str(getattr(link, "host", "") or "")
        sni = getattr(link, "sni", None)
        if sni and host and sni != host:
            return (
                "TLS SNI differs from host. Some servers present a certificate for the host even when SNI differs. "
                "If connectivity fails, check logs and try setting `sni` to the host (or set allowInsecure=1 if you understand the risk)."
            )
        return None

    def _kick_health_check(self) -> None:
        if self._health_in_flight:
            return
        if not self._process.is_running():
            return

        token = self._health_token
        http_port = self._http_port
        self._health_in_flight = True

        def _run():
            return token, check_http_proxy(DEFAULT_LISTEN, http_port)

        worker = HealthCheckWorker(_run)
        worker.signals.result.connect(self._on_health_result)
        worker.signals.error.connect(lambda msg: self._on_health_error(token, msg))
        self._thread_pool.start(worker)

    def _on_health_result(self, payload: object) -> None:
        token, result = payload  # type: ignore[misc]
        if self._closing or token != self._health_token:
            return
        self._health_in_flight = False
        if not isinstance(result, ProxyHealthResult):  # pragma: no cover - defensive
            self._last_health_result = None
            self._set_health_state("offline", "Health check error")
            return

        self._last_health_result = result
        if result.state == "online":
            latency = f"{result.latency_ms} ms" if result.latency_ms is not None else "ok"
            self._set_health_state("online", latency)
        elif result.state == "degraded":
            self._set_health_state("degraded", result.error or "Degraded")
        else:
            self._set_health_state("offline", result.error or "Offline")

        ok_now = result.state == "online"
        if self._last_health_ok is True and not ok_now:
            self.diagnostics_widget.set_hint(
                f"Connectivity went offline: {result.error or 'unknown error'}"
            )
        self._last_health_ok = ok_now

    def _on_health_error(self, token: int, message: str) -> None:
        if self._closing or token != self._health_token:
            return
        self._health_in_flight = False
        self._last_health_result = None
        self._set_health_state("offline", message)

    def _set_health_state(self, state: str, detail: str) -> None:
        state = state.lower()
        detail = detail.strip() or "—"
        self._health_state = state
        self._health_detail = detail
        detail_short = detail if len(detail) <= 60 else f"{detail[:57]}…"
        self.health_label.setToolTip(detail)
        if state == "online":
            self.health_label.setText(f"ONLINE ({detail_short})")
            self.health_label.setStyleSheet("color: #2e7d32; font-weight: 600;")
        elif state == "connecting":
            self.health_label.setText(f"CONNECTING ({detail_short})")
            self.health_label.setStyleSheet("color: #546e7a; font-weight: 600;")
        elif state == "degraded":
            self.health_label.setText(f"DEGRADED ({detail_short})")
            self.health_label.setStyleSheet("color: #ef6c00; font-weight: 600;")
        else:
            self.health_label.setText(f"OFFLINE ({detail_short})")
            self.health_label.setStyleSheet("color: #c62828; font-weight: 600;")

    def closeEvent(self, event) -> None:  # type: ignore[override]
        self._shutdown_application()
        super().closeEvent(event)

    def _shutdown_application(self) -> None:
        """Perform the ordered, idempotent application-owned shutdown."""
        if self._shutdown_complete:
            return
        self._closing = True
        for timer in (
            self._status_timer,
            self._stats_timer,
            self._traffic_persistence_timer,
            self._overview_timer,
            self._diagnostics_timer,
            self._health_timer,
            self._proxy_audit_timer,
        ):
            timer.stop()
        self._stats_token += 1
        self._health_token += 1
        self._proxy_audit_token += 1
        self._runtime_diagnostics_token = getattr(self, "_runtime_diagnostics_token", 0) + 1
        self._stats_active_token = None
        self._proxy_audit_active_token = None
        self._stats_in_flight = False
        self._health_in_flight = False
        self._proxy_audit_running = False
        self._runtime_diagnostics_in_flight = False
        self._save_profile_preferences()

        final_stats = self._last_known_stats()
        self._end_traffic_session(final_stats=final_stats)
        self.traffic_monitor_widget.shutdown()
        self.diagnostics_widget.shutdown()

        cancel_active_stats_queries(timeout_s=1.0)
        audit_finished = getattr(self, "_proxy_audit_finished", None)
        if audit_finished is not None and not audit_finished.wait(PROXY_AUDIT_SHUTDOWN_WAIT_S):
            logger.warning("Proxy audit did not finish before shutdown restore timeout")
        try:
            self._process.stop(timeout_s=3.0)
        except Exception:  # pragma: no cover - defensive shutdown guard
            logger.exception("Failed to stop app-owned Xray process group")
        self._restore_system_proxy()

        # Remove queued QRunnables and allow already-running callbacks a short,
        # bounded window to observe their invalid generation tokens.
        self._thread_pool.clear()
        if not self._thread_pool.waitForDone(1500):
            logger.warning("Background jobs did not finish before shutdown timeout")
        if self._traffic_storage_worker is not None:
            if not self._traffic_storage_worker.shutdown(
                drain=True,
                timeout_s=TRAFFIC_FINAL_FLUSH_TIMEOUT_S,
            ):
                logger.warning("Traffic storage worker did not stop before shutdown timeout")
        self._shutdown_complete = True

    def _apply_system_proxy(self) -> None:
        if self._system_proxy_applied:
            return
        if not self._system_proxy.is_supported():
            self.diagnostics_widget.set_hint(
                "System proxy apply is not supported on this desktop yet. Use manual proxy settings."
            )
            return
        cfg = SystemProxyConfig(
            http_host=DEFAULT_LISTEN,
            http_port=int(self._http_port),
            socks_host=DEFAULT_LISTEN,
            socks_port=int(self._socks_port),
            bypass_hosts=["localhost", "127.0.0.0/8", "::1"],
        )
        try:
            status = self._system_proxy.apply(cfg)
        except AppError as exc:
            self.diagnostics_widget.set_hint(f"Started, but failed to apply system proxy: {exc.user_message}")
            return
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("System proxy apply failed")
            self.diagnostics_widget.set_hint(f"Started, but failed to apply system proxy: {exc}")
            return

        self._system_proxy_applied = True
        self._system_proxy_cfg = cfg
        self._last_proxy_audit = None
        self._last_proxy_audit_error = None
        self._last_proxy_reapply_at = None
        self._last_proxy_reapply_reason = None
        self._proxy_audit_failures = 0
        self._next_proxy_reconcile_at = 0.0
        self._proxy_audit_token += 1
        self._proxy_audit_timer.start()
        self._audit_system_proxy_runtime()
        self.diagnostics_widget.set_hint(
            "System proxy applied and verified: "
            f"mode={status.mode}, "
            f"http={status.http_host}:{status.http_port} (enabled={status.http_enabled}), "
            f"socks={status.socks_host}:{status.socks_port}."
        )
        self._update_diagnostics_runtime_state()

    def _restore_system_proxy(self) -> str | None:
        if not self._system_proxy_applied:
            return None
        self._proxy_audit_timer.stop()
        self._proxy_audit_token += 1
        restore_note: str | None = None
        try:
            status = self._system_proxy.restore_if_owned()
            if status is None:
                restore_note = "System proxy restore skipped (this session is not the snapshot owner)."
            else:
                restore_note = (
                    "System proxy restored: "
                    f"mode={status.mode}, "
                    f"http={status.http_host}:{status.http_port}, "
                    f"socks={status.socks_host}:{status.socks_port}."
                )
        except AppError as exc:
            logger.exception("System proxy restore failed")
            try:
                status = self._system_proxy.force_no_proxy()
                logger.warning("Applied no-proxy fallback after restore failure")
                restore_note = (
                    f"System proxy restore failed ({exc.user_message}); "
                    f"fallback applied: mode={status.mode}."
                )
            except Exception as fallback_exc:
                logger.exception("Failed to apply no-proxy fallback after restore failure")
                restore_note = (
                    f"System proxy restore failed ({exc.user_message}); "
                    f"fallback also failed: {fallback_exc}."
                )
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("System proxy restore failed")
            restore_note = f"System proxy restore failed: {exc}."
        self._system_proxy_applied = False
        self._system_proxy_cfg = None
        self._last_proxy_audit = None
        self._last_proxy_audit_error = None
        self._proxy_audit_failures = 0
        self._next_proxy_reconcile_at = 0.0
        self._proxy_audit_running = False
        self._last_health_result = None
        self._update_diagnostics_runtime_state()
        return restore_note
