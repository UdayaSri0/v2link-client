"""App theming (light/dark) using Qt palettes + style sheets."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from PyQt6.QtGui import QColor, QPalette
from PyQt6.QtWidgets import QApplication

ThemeName = Literal["dark", "light"]
DEFAULT_THEME: ThemeName = "dark"


@dataclass(frozen=True, slots=True)
class Theme:
    name: ThemeName
    display_name: str
    palette: QPalette
    qss: str


def normalize_theme(value: str | None) -> ThemeName:
    if not value:
        return DEFAULT_THEME
    value = value.strip().lower()
    if value in {"dark", "d"}:
        return "dark"
    if value in {"light", "l"}:
        return "light"
    return DEFAULT_THEME


def theme_display_name(name: ThemeName) -> str:
    return "Dark" if name == "dark" else "Light"


def get_theme(name: ThemeName) -> Theme:
    if name == "light":
        return _light_theme()
    return _dark_theme()


def apply_theme(app: QApplication, name: ThemeName) -> None:
    theme = get_theme(name)
    app.setStyle("Fusion")
    app.setPalette(theme.palette)
    app.setStyleSheet(theme.qss)


def _dark_theme() -> Theme:
    # Modern slate palette (no pure black/white).
    bg = QColor("#0b1220")
    surface = QColor("#111827")
    surface_2 = QColor("#0f172a")
    border = QColor("#243042")
    text = QColor("#e5e7eb")
    muted = QColor("#94a3b8")
    accent = QColor("#60a5fa")
    highlight = QColor("#1d4ed8")

    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, bg)
    palette.setColor(QPalette.ColorRole.WindowText, text)
    palette.setColor(QPalette.ColorRole.Base, surface)
    palette.setColor(QPalette.ColorRole.AlternateBase, surface_2)
    palette.setColor(QPalette.ColorRole.Text, text)
    palette.setColor(QPalette.ColorRole.Button, surface)
    palette.setColor(QPalette.ColorRole.ButtonText, text)
    palette.setColor(QPalette.ColorRole.ToolTipBase, surface)
    palette.setColor(QPalette.ColorRole.ToolTipText, text)
    palette.setColor(QPalette.ColorRole.Highlight, highlight)
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#f8fafc"))
    palette.setColor(QPalette.ColorRole.Link, accent)

    qss = f"""
    QWidget {{
      background: {bg.name()};
      color: {text.name()};
      font-size: 13px;
    }}

    QLabel[role="muted"] {{
      color: {muted.name()};
    }}

    QLabel[role="hint"] {{
      color: {accent.name()};
    }}

    QLabel[role="pill"] {{
      padding: 3px 8px;
      border-radius: 999px;
      background: {surface_2.name()};
      border: 1px solid {border.name()};
    }}

    QLineEdit, QTextEdit, QPlainTextEdit {{
      background: {surface.name()};
      border: 1px solid {border.name()};
      border-radius: 10px;
      min-height: 34px;
      padding: 8px 10px;
      selection-background-color: {highlight.name()};
      selection-color: #f8fafc;
    }}

    QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {{
      border: 1px solid {accent.name()};
    }}

    QTextEdit, QPlainTextEdit {{
      font-family: "Ubuntu Mono", "DejaVu Sans Mono", monospace;
      font-size: 12px;
    }}

    QPushButton {{
      background: #182235;
      border: 1px solid {border.name()};
      border-radius: 10px;
      min-height: 32px;
      padding: 7px 12px;
    }}

    QPushButton:hover {{
      background: #1f2b44;
    }}

    QPushButton:pressed {{
      background: {surface_2.name()};
    }}

    QPushButton:disabled {{
      color: #64748b;
      background: {surface_2.name()};
      border: 1px solid #1f2b44;
    }}

    QPushButton[variant="primary"] {{
      background: #2563eb;
      border: 1px solid #2563eb;
      color: #f8fafc;
      font-weight: 600;
    }}

    QPushButton[variant="primary"]:hover {{
      background: #1d4ed8;
      border: 1px solid #1d4ed8;
    }}

    QPushButton[variant="danger"] {{
      background: #dc2626;
      border: 1px solid #dc2626;
      color: #f8fafc;
      font-weight: 600;
    }}

    QPushButton[variant="danger"]:hover {{
      background: #b91c1c;
      border: 1px solid #b91c1c;
    }}

    QPushButton[variant="ghost"] {{
      background: transparent;
      border: 1px solid {border.name()};
      color: {text.name()};
    }}

    QPushButton[variant="ghost"]:hover {{
      background: {surface_2.name()};
    }}

    QComboBox {{
      background: {surface.name()};
      border: 1px solid {border.name()};
      border-radius: 10px;
      min-height: 32px;
      padding: 6px 10px;
    }}

    QComboBox::drop-down {{
      border: 0;
      width: 24px;
    }}

    QComboBox QAbstractItemView {{
      background: {surface.name()};
      border: 1px solid {border.name()};
      selection-background-color: {highlight.name()};
      selection-color: #f8fafc;
      outline: 0;
    }}

    QToolTip {{
      background: {surface.name()};
      color: {text.name()};
      border: 1px solid {border.name()};
      padding: 6px;
      border-radius: 8px;
    }}
    """

    return Theme(name="dark", display_name="Dark", palette=palette, qss=qss)


def _light_theme() -> Theme:
    # Soft neutrals (no pure white).
    bg = QColor("#f6f8fc")
    surface = QColor("#ffffff")
    surface_2 = QColor("#eef2f7")
    border = QColor("#cbd5e1")
    text = QColor("#111827")
    muted = QColor("#64748b")
    accent = QColor("#2563eb")
    highlight = QColor("#1d4ed8")

    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, bg)
    palette.setColor(QPalette.ColorRole.WindowText, text)
    palette.setColor(QPalette.ColorRole.Base, surface)
    palette.setColor(QPalette.ColorRole.AlternateBase, surface_2)
    palette.setColor(QPalette.ColorRole.Text, text)
    palette.setColor(QPalette.ColorRole.Button, surface_2)
    palette.setColor(QPalette.ColorRole.ButtonText, text)
    palette.setColor(QPalette.ColorRole.ToolTipBase, surface)
    palette.setColor(QPalette.ColorRole.ToolTipText, text)
    palette.setColor(QPalette.ColorRole.Highlight, highlight)
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#f8fafc"))
    palette.setColor(QPalette.ColorRole.Link, accent)

    qss = f"""
    QWidget {{
      background: {bg.name()};
      color: {text.name()};
      font-size: 13px;
    }}

    QLabel[role="muted"] {{
      color: {muted.name()};
    }}

    QLabel[role="hint"] {{
      color: {accent.name()};
      font-weight: 600;
    }}

    QLabel[role="pill"] {{
      padding: 3px 8px;
      border-radius: 999px;
      background: {surface_2.name()};
      border: 1px solid {border.name()};
    }}

    QLineEdit, QTextEdit, QPlainTextEdit {{
      background: {surface.name()};
      border: 1px solid {border.name()};
      border-radius: 10px;
      min-height: 34px;
      padding: 8px 10px;
      selection-background-color: {highlight.name()};
      selection-color: #f8fafc;
    }}

    QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {{
      border: 1px solid {accent.name()};
    }}

    QTextEdit, QPlainTextEdit {{
      font-family: "Ubuntu Mono", "DejaVu Sans Mono", monospace;
      font-size: 12px;
    }}

    QPushButton {{
      background: {surface_2.name()};
      border: 1px solid {border.name()};
      border-radius: 10px;
      min-height: 32px;
      padding: 7px 12px;
    }}

    QPushButton:hover {{
      background: #e2e8f0;
    }}

    QPushButton:pressed {{
      background: #dbe3ee;
    }}

    QPushButton:disabled {{
      color: #94a3b8;
      background: #f1f5f9;
      border: 1px solid #e2e8f0;
    }}

    QPushButton[variant="primary"] {{
      background: #2563eb;
      border: 1px solid #2563eb;
      color: #f8fafc;
      font-weight: 600;
    }}

    QPushButton[variant="primary"]:hover {{
      background: #1d4ed8;
      border: 1px solid #1d4ed8;
    }}

    QPushButton[variant="danger"] {{
      background: #dc2626;
      border: 1px solid #dc2626;
      color: #f8fafc;
      font-weight: 600;
    }}

    QPushButton[variant="danger"]:hover {{
      background: #b91c1c;
      border: 1px solid #b91c1c;
    }}

    QPushButton[variant="ghost"] {{
      background: transparent;
      border: 1px solid {border.name()};
      color: {text.name()};
    }}

    QPushButton[variant="ghost"]:hover {{
      background: #e2e8f0;
    }}

    QComboBox {{
      background: {surface.name()};
      border: 1px solid {border.name()};
      border-radius: 10px;
      min-height: 32px;
      padding: 6px 10px;
    }}

    QComboBox::drop-down {{
      border: 0;
      width: 24px;
    }}

    QComboBox QAbstractItemView {{
      background: {surface.name()};
      border: 1px solid {border.name()};
      selection-background-color: {highlight.name()};
      selection-color: #f8fafc;
      outline: 0;
    }}

    QToolTip {{
      background: {surface.name()};
      color: {text.name()};
      border: 1px solid {border.name()};
      padding: 6px;
      border-radius: 8px;
    }}
    """

    return Theme(name="light", display_name="Light", palette=palette, qss=qss)
