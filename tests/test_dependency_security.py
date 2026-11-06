"""Keep reviewed dependency security floors in local resolution and builds."""

import tomllib
from pathlib import Path

from packaging.requirements import Requirement
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


def test_visualization_security_floor_is_an_extra_requirement_and_locked():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    lock = tomllib.loads((ROOT / "uv.lock").read_text())
    requirements = {item.name: item for item in map(
        Requirement, project["project"]["optional-dependencies"]["viz"])}
    pillow = requirements["pillow"]
    assert pillow.marker is None
    assert str(pillow.specifier) == ">=13.0.0"
    assert "12.3.0" not in pillow.specifier and "13.0.0" in pillow.specifier
    locked = [item for item in lock["package"] if item["name"] == "pillow"]
    assert locked and all(Version(item["version"]) >= Version("13.0.0") for item in locked)
    package, = [item for item in lock["package"] if item["name"] == "lurescope"]
    assert {"name": "pillow", "marker": "extra == 'viz'", "specifier": ">=13.0.0"} in (
        package["metadata"]["requires-dist"])


def test_default_dependency_graph_does_not_pull_visualization_stack():
    lock = tomllib.loads((ROOT / "uv.lock").read_text())
    packages = {}
    for package in lock["package"]:
        packages.setdefault(package["name"], []).append(package)
    pending, visited = [("lurescope", ())], set()
    while pending:
        name, extras = pending.pop()
        if (name, extras) in visited:
            continue
        visited.add((name, extras))
        for package in packages.get(name, []):
            dependencies = list(package.get("dependencies", []))
            for extra in extras:
                dependencies.extend(package.get("optional-dependencies", {}).get(extra, []))
            pending.extend((item["name"], tuple(item.get("extra", []))) for item in dependencies)
    assert {"pillow", "matplotlib"}.isdisjoint(name for name, _ in visited)


def test_visualization_ci_requires_opt_in_and_installs_the_reviewed_extra():
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    job = ci.split("\n  visualization:\n", 1)[1].split("\n  container:\n", 1)[0]
    assert 'python-version: ["3.11", "3.12", "3.13"]' in job
    assert "uv sync --locked" in job and "--extra viz" in job
    assert 'LURESCOPE_TEST_VIZ: "1"' in job
    assert "tests/test_scorecard_viz.py" in job
    assert "continue-on-error" not in job


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
