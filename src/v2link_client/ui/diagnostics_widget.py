"""Diagnostics panel widget."""

from __future__ import annotations

import copy
from datetime import datetime
import logging
from typing import Any, Callable

from PyQt6.QtCore import QObject, QRunnable, Qt, QThreadPool, pyqtSignal
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QFileDialog,
    QGridLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from PyQt6.QtCore import QUrl

from v2link_client.core.diagnostics import collect_diagnostics
from v2link_client.core.storage import get_logs_dir
from v2link_client.ui.safe_text_actions import (
    copy_sanitized_text,
    diagnostics_filename,
    prepare_safe_text,
    save_sanitized_text,
)

logger = logging.getLogger(__name__)


class DiagnosticsWorkerSignals(QObject):
    result = pyqtSignal(str)
    error = pyqtSignal(str)


class DiagnosticsWorker(QRunnable):
    def __init__(self, fn: Callable[[], str]) -> None:
        super().__init__()
        self.fn = fn
        self.signals = DiagnosticsWorkerSignals()

    def run(self) -> None:
        try:
            text = self.fn()
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Diagnostics collection failed")
            self.signals.error.emit(prepare_safe_text(str(exc)))
            return
        self.signals.result.emit(text)


class DiagnosticsWidget(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.thread_pool = QThreadPool.globalInstance()
        self._socks_port = 1080
        self._http_port = 8080
        self._runtime_state: dict[str, Any] | None = None
        self._closing = False
        self._refresh_generation = 0
        self._latest_error_provider: Callable[[], str | None] = lambda: None
        self._latest_error_state_provider: Callable[[], dict[str, Any] | None] = (
            lambda: None
        )

        self.hint_label = QLabel("")
        self.hint_label.setProperty("role", "hint")
        self.hint_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.hint_label.setWordWrap(True)
        self.hint_label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self.hint_label.setMinimumHeight(40)
        self.hint_label.setMaximumHeight(40)

        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)
        self.text_area.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)

        self.refresh_button = QPushButton("Refresh")
        self.copy_button = QPushButton("Copy diagnostics report")
        self.copy_latest_error_button = QPushButton("Copy latest error")
        self.save_button = QPushButton("Save diagnostics report")
        self.open_logs_button = QPushButton("Open logs folder")
        self.copy_manual_button = QPushButton("Copy manual proxy settings")

        self.refresh_button.setAccessibleName("Refresh diagnostics")
        self.copy_button.setAccessibleName("Copy diagnostics report")
        self.copy_latest_error_button.setAccessibleName("Copy latest error")
        self.save_button.setAccessibleName("Save diagnostics report")
        self.open_logs_button.setAccessibleName("Open logs folder")
        self.copy_manual_button.setAccessibleName("Copy manual proxy settings")
        self.copy_latest_error_button.setToolTip(
            "Copy the most recent active error with private values redacted"
        )
        self.save_button.setToolTip("Save a sanitized diagnostics report as UTF-8 text")

        self.refresh_button.clicked.connect(self.refresh)
        self.copy_button.clicked.connect(self.copy_report)
        self.copy_latest_error_button.clicked.connect(self.copy_latest_error)
        self.save_button.clicked.connect(self.save_report)
        self.open_logs_button.clicked.connect(self.open_logs_folder)
        self.copy_manual_button.clicked.connect(self.copy_manual_proxy)

        button_grid = QGridLayout()
        button_grid.setHorizontalSpacing(8)
        button_grid.setVerticalSpacing(8)
        button_grid.addWidget(self.refresh_button, 0, 0)
        button_grid.addWidget(self.copy_button, 0, 1)
        button_grid.addWidget(self.copy_latest_error_button, 0, 2)
        button_grid.addWidget(self.save_button, 1, 0)
        button_grid.addWidget(self.open_logs_button, 1, 1)
        button_grid.addWidget(self.copy_manual_button, 1, 2)
        for column in range(3):
            button_grid.setColumnStretch(column, 1)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        layout.addWidget(self.hint_label)
        layout.addLayout(button_grid)
        layout.addWidget(self.text_area, 1)
        self.setLayout(layout)

        QWidget.setTabOrder(self.refresh_button, self.copy_button)
        QWidget.setTabOrder(self.copy_button, self.copy_latest_error_button)
        QWidget.setTabOrder(self.copy_latest_error_button, self.save_button)
        QWidget.setTabOrder(self.save_button, self.open_logs_button)
        QWidget.setTabOrder(self.open_logs_button, self.copy_manual_button)

        self.refresh()

    def set_hint(self, text: str) -> None:
        self.hint_label.setText(text)
        self.hint_label.setToolTip(text if text else "")

    def set_proxy_ports(self, *, socks_port: int, http_port: int) -> None:
        self._socks_port = socks_port
        self._http_port = http_port

    def set_runtime_state(self, state: dict[str, Any] | None) -> None:
        self._runtime_state = copy.deepcopy(state) if isinstance(state, dict) else None

    def set_latest_error_provider(self, provider: Callable[[], str | None]) -> None:
        self._latest_error_provider = provider

    def set_latest_error_state_provider(
        self, provider: Callable[[], dict[str, Any] | None]
    ) -> None:
        """Supply the current structured error when each report is refreshed."""
        self._latest_error_state_provider = provider

    def refresh(self) -> None:
        if self._closing:
            return
        self._refresh_generation += 1
        generation = self._refresh_generation
        self.set_hint("")
        self.text_area.setPlainText("Refreshing diagnostics...")
        self.refresh_button.setEnabled(False)
        self.copy_button.setEnabled(False)
        self.save_button.setEnabled(False)

        state_snapshot = copy.deepcopy(self._runtime_state)
        try:
            current_error = self._latest_error_state_provider()
        except Exception:
            logger.warning("Latest-error state provider failed")
            current_error = None
        if current_error is not None:
            if state_snapshot is None:
                state_snapshot = {}
            state_snapshot["recent_error"] = copy.deepcopy(current_error)
        elif state_snapshot is not None:
            state_snapshot.pop("recent_error", None)
        worker = DiagnosticsWorker(lambda: collect_diagnostics(state=state_snapshot))
        worker.signals.result.connect(lambda text: self._on_result(generation, text))
        worker.signals.error.connect(lambda message: self._on_error(generation, message))
        self.thread_pool.start(worker)

    def _on_result(self, generation: int, text: str) -> None:
        if self._closing or generation != self._refresh_generation:
            return
        self.text_area.setPlainText(prepare_safe_text(text))
        self.refresh_button.setEnabled(True)
        self.copy_button.setEnabled(bool(self.text_area.toPlainText().strip()))
        self.save_button.setEnabled(bool(self.text_area.toPlainText().strip()))

    def _on_error(self, generation: int, message: str) -> None:
        if self._closing or generation != self._refresh_generation:
            return
        self.text_area.setPlainText(prepare_safe_text(f"Diagnostics error: {message}"))
        self.refresh_button.setEnabled(True)
        self.copy_button.setEnabled(True)
        self.save_button.setEnabled(True)

    def shutdown(self) -> None:
        self._closing = True
        self._refresh_generation += 1

    def copy_report(self) -> None:
        result = copy_sanitized_text(
            self.text_area.toPlainText(),
            label="diagnostics report",
        )
        self.set_hint(result.message)

    def copy_latest_error(self) -> None:
        try:
            text = self._latest_error_provider()
        except Exception:
            logger.warning("Latest-error provider failed")
            text = None
        result = copy_sanitized_text(text, label="latest error")
        if not text:
            self.set_hint("No recent error is available to copy.")
            return
        self.set_hint(result.message)

    def save_report(self) -> None:
        report = self.text_area.toPlainText()
        if not report.strip():
            self.set_hint("No diagnostics report is available to save.")
            return
        selected_path, _selected_filter = QFileDialog.getSaveFileName(
            self,
            "Save diagnostics report",
            diagnostics_filename(datetime.now().astimezone()),
            "Text files (*.txt);;All files (*)",
        )
        result = save_sanitized_text(
            selected_path,
            report,
            label="diagnostics report",
        )
        if result.cancelled:
            self.set_hint("Save cancelled.")
            return
        self.set_hint(result.message)

    def open_logs_folder(self) -> None:
        logs_dir = get_logs_dir()
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(logs_dir)))
        self.set_hint(prepare_safe_text(f"Opened logs folder: {logs_dir}"))

    def copy_manual_proxy(self) -> None:
        text = (
            f"SOCKS5 Proxy: 127.0.0.1:{self._socks_port}\n"
            f"HTTP Proxy: 127.0.0.1:{self._http_port}"
        )
        result = copy_sanitized_text(text, label="manual proxy settings")
        self.set_hint(result.message)
