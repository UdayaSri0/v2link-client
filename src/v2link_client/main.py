"""Application entry point."""

from __future__ import annotations

import sys

from PyQt6.QtWidgets import QApplication

from v2link_client import __version__
from v2link_client.core.logging_setup import setup_logging
from v2link_client.core.storage import ensure_dirs
from v2link_client.ui.main_window import MainWindow


def main() -> int:
    ensure_dirs()
    setup_logging()
    app = QApplication(sys.argv)
    app.setApplicationName("v2link-client")
    app.setApplicationVersion(__version__)

    window = MainWindow()
    window.show()

    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
