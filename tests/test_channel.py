from __future__ import annotations

import ast
import base64
import copy
import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from lurescope.channel import (
    VERIFICATION_SCHEMA,
    _derive,
    create_channel_verification,
    load_channel_verification,
    validate_channel_evaluation,
    validate_channel_verification,
)
from lurescope.cli import main
from lurescope.permit import _canonical

ROOT = Path(__file__).parents[1]
VECTOR = ROOT / "conformance" / "lurechannel-v1"


def _load(name: str) -> dict:
    return json.loads((VECTOR / name).read_text(encoding="utf-8"))


def _write(path: Path, value: object) -> None:
    path.write_bytes(_canonical(value))


def _registry() -> Registry:
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def test_independent_evaluator_reproduces_public_evaluation():
    expected = _load("evaluation.json")
    actual = _derive(_load("plan.json"), _load("run.json"), expected["evaluated_at"])
    assert actual == expected
    assert validate_channel_evaluation(expected) == expected


def test_self_contained_verification_reparses_exact_sources(tmp_path: Path):
    output = tmp_path / "verification.json"
    result = create_channel_verification(
        VECTOR / "plan.json",
        VECTOR / "run.json",
        VECTOR / "evaluation.json",
        output,
        verified_at="2026-09-05T00:09:00Z",
    )
    assert result["schema"] == VERIFICATION_SCHEMA
    assert result["summary"]["source_documents_reparsed"] is True
    assert result["summary"]["producer_evaluation_reproduced"] is True
    assert result["summary"]["bounded_noninterference_observed"] is True
    assert result == _load("verification.json")
    assert load_channel_verification(output) == result
    if os.name == "posix":
        assert output.stat().st_mode & 0o777 == 0o600

    schema = json.loads(
        (ROOT / "spec" / "lurechannel-verification-v1.schema.json").read_text(encoding="utf-8")
    )
    assert schema["$id"] == VERIFICATION_SCHEMA
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, registry=_registry(), format_checker=FormatChecker()).validate(
        result
    )


def test_direct_forbidden_flow_is_preserved_as_verified_failure(tmp_path: Path):
    plan = _load("plan.json")
    run = _load("run.json")
    run["probes"][1]["sightings"] = [
        {
            "sighting_id": "forbidden-package-flow",
            "sensor_id": "package-sensor",
            "observer_run_id": "run-b",
            "channel_id": "package-cache",
            "observed_at": "2026-09-05T00:03:00.100000Z",
        }
    ]
    evaluation = _derive(plan, run, "2026-09-05T00:08:00Z")
    assert evaluation["summary"]["verdict"] == "fail"
    plan_path, run_path, evaluation_path = (
        tmp_path / "plan.json",
        tmp_path / "run.json",
        tmp_path / "evaluation.json",
    )
    _write(plan_path, plan)
    _write(run_path, run)
    _write(evaluation_path, evaluation)
    report = create_channel_verification(
        plan_path,
        run_path,
        evaluation_path,
        tmp_path / "verification.json",
        verified_at="2026-09-05T00:09:00Z",
    )
    assert report["summary"]["verdict"] == "fail"
    assert report["summary"]["bounded_noninterference_observed"] is False
    assert report["producer_evaluation"]["findings"] == [
        {
            "code": "unauthorized_flow",
            "test_id": "active-package-isolation",
            "subject": "forbidden-package-flow",
        }
    ]


def test_independent_verifier_rejects_unobservable_deadlines_and_sightings():
    plan = _load("plan.json")
    run = _load("run.json")
    run["completed_at"] = "2026-09-05T00:03:00.500000Z"
    with pytest.raises(ValueError, match="deadline falls outside observation run"):
        _derive(plan, run, "2026-09-05T00:08:00Z")

    run = _load("run.json")
    run["probes"][0]["sightings"][0]["sensor_id"] = "package-sensor"
    with pytest.raises(ValueError, match="outside declared sensor topology"):
        _derive(plan, run, "2026-09-05T00:08:00Z")


def test_changed_source_or_producer_summary_is_rejected(tmp_path: Path):
    changed_run = _load("run.json")
    changed_run["completed_at"] = "2026-09-05T00:07:01Z"
    run_path = tmp_path / "changed-run.json"
    _write(run_path, changed_run)
    with pytest.raises(ValueError, match="supplied plan and run"):
        create_channel_verification(
            VECTOR / "plan.json",
            run_path,
            VECTOR / "evaluation.json",
            tmp_path / "verification.json",
            verified_at="2026-09-05T00:09:00Z",
        )

    changed_evaluation = _load("evaluation.json")
    changed_evaluation["summary"]["finding_count"] = 1
    with pytest.raises(ValueError, match="independently recompute"):
        validate_channel_evaluation(changed_evaluation)


def test_embedded_source_tampering_is_rejected(tmp_path: Path):
    output = tmp_path / "verification.json"
    report = create_channel_verification(
        VECTOR / "plan.json",
        VECTOR / "run.json",
        VECTOR / "evaluation.json",
        output,
        verified_at="2026-09-05T00:09:00Z",
    )
    changed = copy.deepcopy(report)
    payload = bytearray(base64.b64decode(changed["documents"]["run"]["payload_base64"]))
    payload[-2] ^= 1
    changed["documents"]["run"]["payload_base64"] = base64.b64encode(payload).decode()
    with pytest.raises(ValueError, match="digest does not match"):
        validate_channel_verification(changed)


def test_cli_verifies_and_refuses_overwrite(tmp_path: Path):
    output = tmp_path / "verification.json"
    args = [
        "channel",
        "verify",
        str(VECTOR / "plan.json"),
        str(VECTOR / "run.json"),
        str(VECTOR / "evaluation.json"),
        "--verified-at",
        "2026-09-05T00:09:00Z",
        "--out",
        str(output),
    ]
    assert main(args) == 0
    assert main(args) == 2
    assert main(["channel", "check", str(output)]) == 0


def test_verifier_imports_no_lurebench_network_model_or_process_runtime():
    tree = ast.parse((ROOT / "lurescope" / "channel.py").read_text(encoding="utf-8"))
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module and not node.level
    )
    assert not any(name == "lurebench" or name.startswith("lurebench.") for name in imports)
    assert not any(
        name.split(".")[0] in {"requests", "socket", "subprocess", "torch", "transformers"}
        for name in imports
    )
