from __future__ import annotations

import subprocess

import v2link_client.core.diagnostics as diag
from v2link_client.core.proxy_manager import SNAPSHOT_FILE


def test_collect_diagnostics_includes_gsettings_proxy_state(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(diag, "_tool_available", lambda name: name == "gsettings")
    monkeypatch.setattr(diag, "get_state_dir", lambda: tmp_path)
    (tmp_path / SNAPSHOT_FILE).write_text("{}", encoding="utf-8")

    def fake_run(cmd, check, capture_output, text, timeout):  # noqa: ANN001
        if cmd == ["gsettings", "list-recursively", "org.gnome.system.proxy"]:
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout=(
                    "org.gnome.system.proxy mode 'none'\n"
                    "org.gnome.system.proxy.http host ''\n"
                    "org.gnome.system.proxy.http port 0\n"
                ),
                stderr="",
            )
        raise AssertionError(f"Unexpected command: {cmd}")

    monkeypatch.setattr(diag.subprocess, "run", fake_run)

    report = diag.collect_diagnostics()
    assert "System Proxy (gsettings)" in report
    assert "System proxy snapshot: present" in report
    assert "- org.gnome.system.proxy:mode = 'none'" in report
    assert "- org.gnome.system.proxy.http:port = 0" in report


def test_collect_diagnostics_handles_missing_gsettings(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(diag, "_tool_available", lambda _name: False)
    monkeypatch.setattr(diag, "get_state_dir", lambda: tmp_path)

    report = diag.collect_diagnostics()
    assert "System Proxy (gsettings)" in report
    assert "- gsettings unavailable" in report
    assert "System proxy snapshot: absent" in report

