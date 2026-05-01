"""Main application window."""

from __future__ import annotations

import logging
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
import socket
import tempfile
import time

from PyQt6.QtCore import QObject, QRunnable, Qt, QThreadPool, QTimer, QUrl, pyqtSignal
from PyQt6.QtGui import QAction, QDesktopServices, QIcon
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
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
from v2link_client.core.traffic_settings import TrafficSettings, load_traffic_settings
from v2link_client.core.traffic_store import ProxyTrafficSample, TrafficStore
from v2link_client.core.update_check import UpdateCheckResult, check_for_updates
from v2link_client.core.xray_api import TrafficStats, get_outbound_traffic
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
RECENT_TRAFFIC_WINDOW_S = 15.0


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
        self.setWindowTitle(f"v2link-client v{__version__}")
        self.resize(900, 640)
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
        self.traffic_monitor_widget = TrafficMonitorWidget(
            self._traffic_store,
            settings=self._traffic_settings,
            netmon_client=self._netmon_client,
        )
        self.traffic_monitor_widget.settings_changed.connect(self._on_traffic_settings_changed)
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

        self._process = XrayProcessManager()
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
        self._status_timer.setInterval(1000)
        self._status_timer.timeout.connect(self._poll_core_status)

        self._core_started_at: float | None = None
        self._stats_in_flight = False
        self._stats_token = 0
        self._last_stats_at: float | None = None
        self._last_uplink: int | None = None
        self._last_downlink: int | None = None
        self._last_stats_query_result: str | None = None
        self._last_stats_query_time: str | None = None
        self._stats_available = False
        self._traffic_session_id: str | None = None
        self._last_traffic_sample: ProxyTrafficSample | None = None
        self._last_traffic_activity_at: float | None = None
        self._ping_in_flight = False
        self._speed_test_in_flight = False
        self._update_check_in_flight = False

        profile_data = self._load_profile()
        self._load_saved_profiles(profile_data)
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

    def _setup_menu(self) -> None:
        help_menu = self.menuBar().addMenu("&Help")
        self.check_updates_action = QAction("Check for Updates…", self)
        self.check_updates_action.triggered.connect(self._on_check_updates_clicked)
        help_menu.addAction(self.check_updates_action)
        self.about_action = QAction("About", self)
        self.about_action.triggered.connect(self._show_about)
        help_menu.addAction(self.about_action)

    def _show_about(self) -> None:
        text = (
            "<b>v2link-client</b><br>"
            f"Version: v{__version__}<br>"
            f"Author: {__author__}<br><br>"
            f"Repository: {PROJECT_REPOSITORY_URL}<br><br>"
            "Linux desktop client for V2Ray-style links powered by Xray-core.<br><br>"
            "<b>Highlights</b><br>"
            "• Saved profiles with validation persistence across restarts<br>"
            "• Profile manager with default/favorite/edit/duplicate actions<br>"
            "• Runtime diagnostics and system proxy drift reconciliation<br>"
            "• Update checks for GitHub releases (.AppImage and .deb)"
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
            parsed_link, socks_port=socks_port, http_port=http_port, api_port=api_port
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

    def _poll_core_status(self) -> None:
        if self._process.is_running():
            self._update_uptime()
            self._kick_stats_poll()
            return

        code = self._process.returncode()
        self._status_timer.stop()
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
        self._health_timer.stop()
        self._proxy_audit_timer.stop()
        self._health_token += 1
        self._stats_token += 1
        final_stats = self._last_known_stats()
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
        save_json(profile_path, data)

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
        if not self._traffic_settings.proxy_history_enabled:
            self._refresh_traffic_monitor()
            return None
        if self._traffic_store is None or self._traffic_session_id is None:
            self._refresh_traffic_monitor()
            return None
        try:
            sample = self._traffic_store.record_proxy_sample(self._traffic_session_id, stats)
        except Exception as exc:  # pragma: no cover - defensive persistence guard
            logger.exception("Failed to record traffic sample")
            self._last_traffic_store_error = str(exc)
            self._refresh_traffic_monitor()
            return None

        self._last_traffic_store_error = None
        self._last_traffic_sample = sample
        self.traffic_monitor_widget.update_live_sample(sample)
        self._refresh_traffic_monitor()
        return sample

    def _end_traffic_session(self, *, final_stats: TrafficStats | None = None) -> None:
        if self._traffic_store is not None and self._traffic_session_id is not None:
            try:
                self._traffic_store.end_proxy_session(self._traffic_session_id, final_stats=final_stats)
                self._last_traffic_store_error = None
            except Exception as exc:  # pragma: no cover - defensive persistence guard
                logger.exception("Failed to end traffic session")
                self._last_traffic_store_error = str(exc)
        self._traffic_session_id = None
        self._last_traffic_sample = None
        self.traffic_monitor_widget.set_current_session(None)
        self._refresh_traffic_monitor()

    def _refresh_traffic_monitor(self) -> None:
        if not hasattr(self, "traffic_monitor_widget"):
            return
        warning = None
        if self._last_traffic_sample is not None and self._last_traffic_sample.warning:
            warning = self._last_traffic_sample.warning
        elif not self._stats_available:
            warning = self._last_stats_query_result
        self.traffic_monitor_widget.set_diagnostics(
            api_server=self._traffic_api_server(),
            stats_available=self._stats_available,
            last_stats_query_time=self._last_stats_query_time,
            last_sample_time=(
                self._last_traffic_sample.timestamp if self._last_traffic_sample is not None else None
            ),
            warning=warning,
            store_error=self._last_traffic_store_error,
        )
        self.traffic_monitor_widget.refresh()

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

    def _update_diagnostics_runtime_state(self) -> None:
        http_ok, socks_ok = self._listener_reachability()
        audit = self._last_proxy_audit
        now = time.monotonic()

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
                "binary_path": self._process.binary_path,
                "stats_api_configured": self._api_port is not None,
                "stats_api_server": self._traffic_api_server(),
                "last_stats_query_result": self._last_stats_query_result,
                "last_stats_query_time": self._last_stats_query_time,
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
                "current_session_id": self._traffic_session_id,
                "last_sample_time": (
                    self._last_traffic_sample.timestamp
                    if self._last_traffic_sample is not None
                    else None
                ),
                "last_store_error": self._last_traffic_store_error,
                "proxy_history_enabled": bool(self._traffic_settings.proxy_history_enabled),
                "app_tracking_enabled": bool(self._traffic_settings.app_tracking_enabled),
                "detailed_retention_days": int(self._traffic_settings.detailed_retention_days),
                "daily_retention_days": int(self._traffic_settings.daily_retention_days),
                "app_tables_present": (
                    self._traffic_store.app_tables_present()
                    if self._traffic_store is not None
                    else False
                ),
                "netmon": asdict(self._netmon_client.get_status()),
            },
        }
        self.diagnostics_widget.set_runtime_state(state)

    def _audit_system_proxy_runtime(self) -> None:
        if self._proxy_audit_running:
            return
        if not self._process.is_running() or not self._system_proxy_applied or self._system_proxy_cfg is None:
            self._proxy_audit_timer.stop()
            self._update_diagnostics_runtime_state()
            return

        self._proxy_audit_running = True
        now = time.monotonic()
        try:
            audit = self._system_proxy.audit_runtime(self._system_proxy_cfg, reconcile=False)
            self._last_proxy_audit = audit
            self._last_proxy_audit_error = None

            if audit.mismatches:
                if now < self._next_proxy_reconcile_at:
                    wait_s = max(0.0, self._next_proxy_reconcile_at - now)
                    logger.info(
                        "System proxy drift detected, waiting %.1fs before reconcile retry",
                        wait_s,
                    )
                    self.diagnostics_widget.set_hint(
                        f"System proxy drift detected; retrying auto-reapply in {wait_s:.1f}s."
                    )
                else:
                    drift_reason = "; ".join(audit.mismatches)
                    reconciled = self._system_proxy.audit_runtime(self._system_proxy_cfg, reconcile=True)
                    self._last_proxy_audit = reconciled
                    self._proxy_audit_failures = 0
                    self._next_proxy_reconcile_at = 0.0
                    self._last_proxy_reapply_at = time.strftime("%Y-%m-%d %H:%M:%S")
                    self._last_proxy_reapply_reason = drift_reason
                    self.diagnostics_widget.set_hint(
                        f"System proxy drift detected and auto-reapplied ({drift_reason})."
                    )
            else:
                self._proxy_audit_failures = 0
                self._next_proxy_reconcile_at = 0.0
        except AppError as exc:
            self._last_proxy_audit_error = exc.user_message
            self._proxy_audit_failures += 1
            backoff = min(PROXY_AUDIT_MAX_BACKOFF_S, float(2 ** min(self._proxy_audit_failures, 5)))
            self._next_proxy_reconcile_at = now + backoff
            logger.warning(
                "System proxy audit failed (attempt %s, backoff %.1fs): %s",
                self._proxy_audit_failures,
                backoff,
                exc.user_message,
            )
            self.diagnostics_widget.set_hint(
                f"System proxy drift detected, but auto-reapply failed: {exc.user_message}"
            )
        except Exception as exc:  # pragma: no cover - defensive
            self._last_proxy_audit_error = str(exc)
            self._proxy_audit_failures += 1
            backoff = min(PROXY_AUDIT_MAX_BACKOFF_S, float(2 ** min(self._proxy_audit_failures, 5)))
            self._next_proxy_reconcile_at = now + backoff
            logger.exception("System proxy runtime audit failed")
            self.diagnostics_widget.set_hint(
                "System proxy drift detected, but auto-reapply hit an unexpected error."
            )
        finally:
            self._proxy_audit_running = False
            self._update_diagnostics_runtime_state()

    def _update_uptime(self) -> None:
        if self._core_started_at is None:
            self.uptime_label.setText("UPTIME (00:00:00)")
            return
        self.uptime_label.setText(
            f"UPTIME ({format_duration_s(time.monotonic() - self._core_started_at)})"
        )

    def _kick_stats_poll(self) -> None:
        if self._stats_in_flight:
            return
        if self._api_port is None:
            return
        if not self._process.is_running():
            return

        token = self._stats_token
        api_server = f"{DEFAULT_LISTEN}:{self._api_port}"
        xray_path = self._process.binary.path
        self._stats_in_flight = True

        def _run():
            stats = get_outbound_traffic(xray_path, server=api_server)
            return token, time.monotonic(), stats

        worker = HealthCheckWorker(_run)
        worker.signals.result.connect(self._on_stats_result)
        worker.signals.error.connect(lambda msg: self._on_stats_error(token, msg))
        self._thread_pool.start(worker)

    def _on_stats_result(self, payload: object) -> None:
        self._stats_in_flight = False
        token, now, stats = payload  # type: ignore[misc]
        if token != self._stats_token:
            return
        if not isinstance(stats, TrafficStats):  # pragma: no cover - defensive
            return

        self._stats_available = True
        self._last_stats_query_result = (
            f"ok: uplink={stats.uplink_bytes} downlink={stats.downlink_bytes}"
        )
        self._last_stats_query_time = self._now_iso_seconds()
        traffic_sample = self._record_traffic_sample(stats)

        self.traffic_label.setText(
            f"TRAFFIC (↑ {format_bytes(stats.uplink_bytes)} / ↓ {format_bytes(stats.downlink_bytes)})"
        )

        # Speed = delta bytes / delta time.
        up_delta = 0
        down_delta = 0
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
        self._update_diagnostics_runtime_state()

    def _on_stats_error(self, token: int, message: str) -> None:
        self._stats_in_flight = False
        if token != self._stats_token:
            return
        # Keep the UI stable; stats may be unavailable if API isn't ready yet.
        logger.info("Stats poll failed: %s", message)
        self._stats_available = False
        self._last_stats_query_result = message
        self._last_stats_query_time = self._now_iso_seconds()
        self._refresh_traffic_monitor()
        self._update_diagnostics_runtime_state()

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
        self._health_in_flight = False

        token, result = payload  # type: ignore[misc]
        if token != self._health_token:
            return
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
        self._update_diagnostics_runtime_state()

    def _on_health_error(self, token: int, message: str) -> None:
        self._health_in_flight = False
        if token != self._health_token:
            return
        self._last_health_result = None
        self._set_health_state("offline", message)
        self._update_diagnostics_runtime_state()

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
        if self._process.is_running():
            self._stop_core(user_message="Stopped (app closed).")
        super().closeEvent(event)

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
