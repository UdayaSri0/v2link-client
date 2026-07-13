from __future__ import annotations

import logging

import v2link_client.core.logging_setup as logging_setup


def test_python_log_rotation_is_bounded(tmp_path, monkeypatch) -> None:
    root = logging.getLogger()
    original_handlers = list(root.handlers)
    for handler in original_handlers:
        root.removeHandler(handler)
    monkeypatch.setattr(logging_setup, "get_logs_dir", lambda: tmp_path)
    monkeypatch.setattr(logging_setup, "MAX_LOG_BYTES", 256)
    monkeypatch.setattr(logging_setup, "BACKUP_COUNT", 2)
    try:
        path = logging_setup.setup_logging()
        for index in range(100):
            logging.getLogger("rotation-test").warning("event=%s %s", index, "x" * 40)
        for handler in list(root.handlers):
            handler.flush()

        files = list(tmp_path.glob("app.log*"))
        assert path in files
        assert len(files) <= 3
        assert all(file.stat().st_size <= 512 for file in files)
    finally:
        for handler in list(root.handlers):
            root.removeHandler(handler)
            handler.close()
        for handler in original_handlers:
            root.addHandler(handler)
