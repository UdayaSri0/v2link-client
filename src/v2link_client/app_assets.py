"""Resolve runtime asset locations for source and packaged builds."""

from __future__ import annotations

from pathlib import Path
import sys


def get_app_icon_path() -> Path | None:
    candidates: list[Path] = []

    if getattr(sys, "frozen", False):
        candidates.append(Path(sys.executable).resolve().with_name("icon.png"))
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            candidates.append(Path(str(meipass)).resolve() / "icon.png")

    repo_root = Path(__file__).resolve().parents[2]
    candidates.append(repo_root / "packaging" / "icon.png")
    candidates.append(repo_root / "icon" / "logo.png")

    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None
