from __future__ import annotations

import ast
import copy
import json
import os
from pathlib import Path

import jsonschema
import pytest
from referencing import Registry, Resource

from lurescope.cli import main
from lurescope.recall import (
    VERIFICATION_SCHEMA,
    compose_recall_plan,
    create_recall_verification,
    evaluate_recall_run,
    validate_recall_evaluation,
    validate_recall_verification,
)

ROOT = Path(__file__).parents[1]
VECTOR = ROOT / "conformance" / "lurerecall-v1"
ARTIFACT_PLAN = ROOT / "conformance" / "lureartifact-v1" / "plan.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, value: dict) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _registry() -> Registry:
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        schema = _load(path)
        if "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def test_local_reimplementation_matches_public_plan_and_evaluation():
    artifact_plan = _load(ARTIFACT_PLAN)
    lineage = _load(VECTOR / "lineage.json")
    advisory = _load(VECTOR / "advisory.json")
    assert compose_recall_plan(artifact_plan, lineage, advisory) == _load(
        VECTOR / "plan.json"
    )
    evaluation = _load(VECTOR / "evaluation.json")
    assert validate_recall_evaluation(evaluation) == evaluation


def test_verification_is_self_contained_recomputable_private_and_schema_valid(
    tmp_path: Path,
):
    output = tmp_path / "recall-verification.json"
    report = create_recall_verification(
        ARTIFACT_PLAN,
        VECTOR / "lineage.json",
        VECTOR / "advisory.json",
        VECTOR / "plan.json",
        VECTOR / "run.json",
        VECTOR / "evaluation.json",
        output,
        verified_at="2026-09-03T00:13:00Z",
    )
    assert report["schema"] == VERIFICATION_SCHEMA
    assert report["overall_status"] == "pass"
    assert report["summary"]["affected_deployment_count"] == 2
    assert report["summary"]["quarantine_recall"] == 1
    assert report["summary"]["recovery_recall"] == 1
    assert len(report["checks"]) == 12
    assert all(item["status"] == "pass" for item in report["checks"])
    assert os.stat(output).st_mode & 0o777 == 0o600
    assert validate_recall_verification(_load(output)) == report

    schema = _load(ROOT / "spec" / "lurerecall-verification-v1.schema.json")
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(
        schema,
        registry=_registry(),
        format_checker=jsonschema.FormatChecker(),
    ).validate(report)


def test_valid_failing_response_remains_a_valid_failing_verification(tmp_path: Path):
    plan = _load(VECTOR / "plan.json")
    run = _load(VECTOR / "run.json")
    probe = next(
        item
        for item in plan["probes"]
        if item["phase"] == "post_quarantine_deadline"
        and item["expected_decision"] == "block"
    )
    observation = next(
        item for item in run["response_observations"] if item["probe_id"] == probe["probe_id"]
    )
    observation["decision"] = "allow"
    observation["reason_code"] = "artifact_not_quarantined"
    observation["observed_artifact_set_sha256"] = probe["artifact_set_sha256"]
    evaluation = evaluate_recall_run(
        plan, run, generated_at="2026-09-03T00:12:00Z"
    )
    assert evaluation["summary"]["verdict"] == "fail"
    run_path = _write(tmp_path / "run.json", run)
    evaluation_path = _write(tmp_path / "evaluation.json", evaluation)
    report = create_recall_verification(
        ARTIFACT_PLAN,
        VECTOR / "lineage.json",
        VECTOR / "advisory.json",
        VECTOR / "plan.json",
        run_path,
        evaluation_path,
        verified_at="2026-09-03T00:13:00Z",
    )
    assert report["overall_status"] == "fail"
    assert [item["status"] for item in report["checks"]].count("fail") == 1
    assert report["checks"][-1] == {
        "check_id": "recall_response_policy_satisfied",
        "status": "fail",
    }
    assert validate_recall_verification(report) == report


def test_verification_rejects_cross_source_tampering_and_predated_time(tmp_path: Path):
    plan = _load(VECTOR / "plan.json")
    plan["impact"]["affected_root_artifact_count"] = 2
    plan_path = _write(tmp_path / "tampered-plan.json", plan)
    with pytest.raises(ValueError, match="independently recompile|independently derived"):
        create_recall_verification(
            ARTIFACT_PLAN,
            VECTOR / "lineage.json",
            VECTOR / "advisory.json",
            plan_path,
            VECTOR / "run.json",
            VECTOR / "evaluation.json",
            verified_at="2026-09-03T00:13:00Z",
        )

    with pytest.raises(ValueError, match="predates"):
        create_recall_verification(
            ARTIFACT_PLAN,
            VECTOR / "lineage.json",
            VECTOR / "advisory.json",
            VECTOR / "plan.json",
            VECTOR / "run.json",
            VECTOR / "evaluation.json",
            verified_at="2026-09-03T00:11:30Z",
        )

    report = create_recall_verification(
        ARTIFACT_PLAN,
        VECTOR / "lineage.json",
        VECTOR / "advisory.json",
        VECTOR / "plan.json",
        VECTOR / "run.json",
        VECTOR / "evaluation.json",
        verified_at="2026-09-03T00:13:00Z",
    )
    tampered = copy.deepcopy(report)
    tampered["digests"]["advisory_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="independently recompute"):
        validate_recall_verification(tampered)


def test_recall_module_imports_no_lurebench_code():
    tree = ast.parse((ROOT / "lurescope" / "recall.py").read_text(encoding="utf-8"))
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
    assert not any(name == "lurebench" or name.startswith("lurebench.") for name in imported)


def test_recall_cli_verifies_checks_and_never_overwrites(tmp_path: Path):
    output = tmp_path / "recall-verification.json"
    args = [
        "recall",
        "verify",
        str(ARTIFACT_PLAN),
        str(VECTOR / "lineage.json"),
        str(VECTOR / "advisory.json"),
        str(VECTOR / "plan.json"),
        str(VECTOR / "run.json"),
        str(VECTOR / "evaluation.json"),
        "--verified-at",
        "2026-09-03T00:13:00Z",
        "--out",
        str(output),
    ]
    assert main(args) == 0
    assert main(["recall", "check", str(output)]) == 0
    assert main(args) == 2
