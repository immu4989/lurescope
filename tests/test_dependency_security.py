"""Keep reviewed dependency security floors in local resolution and builds."""

import tomllib
from pathlib import Path

from packaging.version import Version

ROOT = Path(__file__).parents[1]


def test_certificate_security_floor_and_lock_agree():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    lock = tomllib.loads((ROOT / "uv.lock").read_text())
    assert "certifi>=2026.10.19" in project["tool"]["uv"]["constraint-dependencies"]
    assert {"name": "certifi", "specifier": ">=2026.10.19"} in lock["manifest"]["constraints"]
    certificates = [item for item in lock["package"] if item["name"] == "certifi"]
    assert certificates
    assert all(Version(item["version"]) >= Version("2026.10.19") for item in certificates)
    # This constraint must not turn an optional HTTP transport into a runtime dependency.
    assert not any(item.startswith("certifi") for item in project["project"]["dependencies"])


def test_build_backend_security_floor():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert "setuptools>=84.1.0" in project["build-system"]["requires"]


def test_supported_python_baseline_and_ci_agree():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert project["project"]["requires-python"] == ">=3.11"
    assert "Programming Language :: Python :: 3.10" not in project["project"]["classifiers"]
    for workflow in ("ci.yml", "pypi-smoke.yml"):
        text = (ROOT / ".github" / "workflows" / workflow).read_text()
        assert 'python-version: ["3.11", "3.12", "3.13"]' in text
        assert '"3.10"' not in text
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "uv sync --locked" in ci
    assert "uv sync --frozen" not in ci
