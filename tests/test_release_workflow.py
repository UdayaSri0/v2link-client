from __future__ import annotations

from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _workflow() -> dict:
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())


def test_ci_workflow_exists_and_has_safe_triggers() -> None:
    workflow_path = ROOT / ".github" / "workflows" / "ci.yml"
    assert workflow_path.is_file()
    workflow = _workflow()
    # PyYAML 5.x follows YAML 1.1 and parses the key `on` as boolean True.
    triggers = workflow.get("on", workflow.get(True))
    assert isinstance(triggers, dict)
    assert "pull_request" in triggers
    assert triggers["pull_request"]["branches"] == ["main"]
    assert "push" in triggers
    assert triggers["push"]["branches"] == ["main"]
    assert "workflow_dispatch" in triggers
    assert workflow["permissions"] == {"contents": "read"}
    assert "pull_request_target" not in workflow_path.read_text()


def test_ci_jobs_cover_required_validation_and_no_publication() -> None:
    workflow_path = ROOT / ".github" / "workflows" / "ci.yml"
    text = workflow_path.read_text()
    workflow = _workflow()
    jobs = workflow["jobs"]
    assert {"python", "rust", "packaging"} <= set(jobs)
    assert "python -m pytest -q" in text
    assert "tests/test_xray_tls_integration.py" in text
    assert "compileall" in text
    assert "cargo fmt" in text
    assert "cargo test" in text
    assert "cargo clippy" in text
    assert "shellcheck" in text
    assert "build_release.sh" in text
    assert "verify_release_artifacts.sh" in text
    assert "sha256sum -c" in text
    assert "upload-artifact@v4" in text
    assert "retention-days: 3" in text
    assert "contents: write" not in text
    assert "create-release" not in text
    assert "create tag" not in text.lower()
    assert "publish_apt" not in text
    assert "apt/dists" not in text
    assert "release.yml" not in text
    assert "sudo systemctl" not in text
    assert "pkexec" not in text
