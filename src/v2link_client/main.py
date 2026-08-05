"""Application entry point."""

from __future__ import annotations

import sys

from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication

from v2link_client import __version__
from v2link_client.app_assets import get_app_icon_path
from v2link_client.core.logging_setup import setup_logging
from v2link_client.core.storage import ensure_dirs
from v2link_client.ui.main_window import MainWindow


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] in {"--version", "-V"}:
        print(__version__)
        return 0

    ensure_dirs()
    setup_logging()
    app = QApplication(sys.argv)
    app.setApplicationName("v2link-client")
    app.setApplicationVersion(__version__)
    app.setDesktopFileName("v2link-client")

    icon_path = get_app_icon_path()
    if icon_path is not None:
        app.setWindowIcon(QIcon(str(icon_path)))

    window = MainWindow()
    window.show()

    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
