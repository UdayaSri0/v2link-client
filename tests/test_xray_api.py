from __future__ import annotations

from pathlib import Path
import threading
import time

import pytest

from v2link_client.core.xray_api import (
    XrayApiError,
    active_stats_query_pid,
    cancel_active_stats_queries,
    statsquery,
)


def _script(path: Path, body: str) -> Path:
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def test_statsquery_parses_json_and_reaps_child(tmp_path) -> None:
    script = _script(
        tmp_path / "xray",
        "printf '%s\\n' '{\"stat\":[{\"name\":\"counter\",\"value\":7}]}'",
    )

    assert statsquery(str(script), server="127.0.0.1:1") == {"counter": 7}
    assert active_stats_query_pid() is None


def test_cancel_active_stats_query_reaps_it(tmp_path) -> None:
    script = _script(tmp_path / "xray", "trap '' TERM\nsleep 60")
    result: list[Exception] = []

    def run() -> None:
        try:
            statsquery(str(script), server="127.0.0.1:1", timeout_s=30.0)
        except Exception as exc:  # expected cancellation path
            result.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    deadline = time.monotonic() + 2.0
    while active_stats_query_pid() is None and time.monotonic() < deadline:
        time.sleep(0.01)
    assert active_stats_query_pid() is not None

    assert cancel_active_stats_queries(timeout_s=0.2) == 1
    thread.join(2.0)

    assert not thread.is_alive()
    assert active_stats_query_pid() is None
    assert result


def test_statsquery_timeout_is_bounded(tmp_path) -> None:
    script = _script(tmp_path / "xray", "trap '' TERM\nsleep 60")

    with pytest.raises(XrayApiError, match="timed out"):
        statsquery(str(script), server="127.0.0.1:1", timeout_s=0.1)

    assert active_stats_query_pid() is None
