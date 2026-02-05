"""Storage paths and JSON helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from platformdirs import user_config_path, user_data_path, user_state_path

APP_NAME = "v2link-client"


def get_config_dir() -> Path:
    return Path(user_config_path(APP_NAME))


def get_data_dir() -> Path:
    return Path(user_data_path(APP_NAME))


def get_state_dir() -> Path:
    return Path(user_state_path(APP_NAME))


def get_logs_dir() -> Path:
    return get_state_dir() / "logs"


def ensure_dirs() -> None:
    for path in (get_config_dir(), get_data_dir(), get_state_dir(), get_logs_dir()):
        path.mkdir(parents=True, exist_ok=True)


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except json.JSONDecodeError:
        return default


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
