"""Diagnostics panel widget."""

from __future__ import annotations

import logging
from typing import Callable

from PyQt6.QtCore import QObject, QRunnable, Qt, QThreadPool, pyqtSignal
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from PyQt6.QtCore import QUrl

from v2link_client.core.diagnostics import collect_diagnostics
from v2link_client.core.storage import get_logs_dir

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
            logger.exception("Diagnostics failed")
            self.signals.error.emit(str(exc))
            return
        self.signals.result.emit(text)


class DiagnosticsWidget(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.thread_pool = QThreadPool.globalInstance()
        self._socks_port = 1080
        self._http_port = 8080

        self.hint_label = QLabel("")
        self.hint_label.setProperty("role", "hint")
        self.hint_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)
        self.text_area.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)

        self.refresh_button = QPushButton("Refresh")
        self.copy_button = QPushButton("Copy diagnostics report")
        self.open_logs_button = QPushButton("Open logs folder")
        self.copy_manual_button = QPushButton("Copy manual proxy settings")

        self.refresh_button.clicked.connect(self.refresh)
        self.copy_button.clicked.connect(self.copy_report)
        self.open_logs_button.clicked.connect(self.open_logs_folder)
        self.copy_manual_button.clicked.connect(self.copy_manual_proxy)

        button_row = QHBoxLayout()
        button_row.setSpacing(8)
        button_row.addWidget(self.refresh_button)
        button_row.addWidget(self.copy_button)
        button_row.addWidget(self.open_logs_button)
        button_row.addWidget(self.copy_manual_button)
        button_row.addStretch(1)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        layout.addWidget(self.hint_label)
        layout.addLayout(button_row)
        layout.addWidget(self.text_area, 1)
        self.setLayout(layout)

        self.refresh()

    def set_hint(self, text: str) -> None:
        self.hint_label.setText(text)

    def set_proxy_ports(self, *, socks_port: int, http_port: int) -> None:
        self._socks_port = socks_port
        self._http_port = http_port

    def refresh(self) -> None:
        self.set_hint("")
        self.text_area.setPlainText("Refreshing diagnostics...")
        self.refresh_button.setEnabled(False)

        worker = DiagnosticsWorker(collect_diagnostics)
        worker.signals.result.connect(self._on_result)
        worker.signals.error.connect(self._on_error)
        self.thread_pool.start(worker)

    def _on_result(self, text: str) -> None:
        self.text_area.setPlainText(text)
        self.refresh_button.setEnabled(True)

    def _on_error(self, message: str) -> None:
        self.text_area.setPlainText(f"Diagnostics error: {message}")
        self.refresh_button.setEnabled(True)

    def copy_report(self) -> None:
        text = self.text_area.toPlainText()
        QApplication.clipboard().setText(text)
        self.set_hint("Diagnostics copied to clipboard.")

    def open_logs_folder(self) -> None:
        logs_dir = get_logs_dir()
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(logs_dir)))
        self.set_hint(f"Opened logs folder: {logs_dir}")

    def copy_manual_proxy(self) -> None:
        text = (
            f"SOCKS5 Proxy: 127.0.0.1:{self._socks_port}\n"
            f"HTTP Proxy: 127.0.0.1:{self._http_port}"
        )
        QApplication.clipboard().setText(text)
        self.set_hint("Manual proxy settings copied.")
