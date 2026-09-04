from __future__ import annotations

import ast
import copy
import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from lurescope.artifact import (
    VERIFICATION_SCHEMA,
    create_artifact_verification,
    derive_artifact_evaluation,
    derive_artifact_plan,
    load_artifact_verification,
    validate_artifact_evaluation,
    validate_artifact_verification,
)
from lurescope.cli import main
from lurescope.identity_campaign import create_identity_campaign_verification
from lurescope.permit import _canonical

ROOT = Path(__file__).parents[1]
VECTOR = ROOT / "conformance" / "lureartifact-v1"
IDENTITY_VECTOR = ROOT / "conformance" / "lureidentity-campaign-v1"


def _load(name: str) -> dict:
    return json.loads((VECTOR / name).read_text(encoding="utf-8"))


def _write(path: Path, value: dict) -> None:
    path.write_bytes(_canonical(value))


def _identity_verification(tmp_path: Path) -> Path:
    output = tmp_path / "identity-campaign-verification.json"
    create_identity_campaign_verification(
        IDENTITY_VECTOR / "campaign.json",
        IDENTITY_VECTOR / "plan.json",
        output,
        verified_at="2026-09-03T00:04:00Z",
    )
    return output


def _registry() -> Registry:
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def test_shared_lureartifact_vector_and_schemas_are_byte_identical():
    producer = ROOT.parent / "lurebench"
    files = [
        "spec/lureartifact-campaign-v1.schema.json",
        "spec/lureartifact-plan-v1.schema.json",
        "spec/lureartifact-observation-v1.schema.json",
        "spec/lureartifact-evaluation-v1.schema.json",
        "conformance/lureartifact-v1/identity-plan.json",
        "conformance/lureartifact-v1/campaign.json",
        "conformance/lureartifact-v1/plan.json",
        "conformance/lureartifact-v1/observation.json",
        "conformance/lureartifact-v1/evaluation.json",
    ]
    for relative in files:
        assert (ROOT / relative).read_bytes() == (producer / relative).read_bytes()


def test_independent_module_imports_no_lurebench_code():
    source = (ROOT / "lurescope" / "artifact.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
    assert all(not name.startswith("lurebench") for name in imported)


def test_independent_compiler_and_evaluator_match_public_golden_vector():
    assert derive_artifact_plan(_load("identity-plan.json"), _load("campaign.json")) == _load(
        "plan.json"
    )
    expected = derive_artifact_evaluation(
        _load("plan.json"),
        _load("observation.json"),
        generated_at="2026-09-03T00:07:00Z",
    )
    assert expected == _load("evaluation.json")
    assert validate_artifact_evaluation(expected) == expected


def test_verification_is_self_contained_recomputable_and_schema_valid(tmp_path: Path):
    identity_verification = _identity_verification(tmp_path)
    output = tmp_path / "artifact-verification.json"
    report = create_artifact_verification(
        identity_verification,
        VECTOR / "campaign.json",
        VECTOR / "plan.json",
        VECTOR / "observation.json",
        VECTOR / "evaluation.json",
        output,
        verified_at="2026-09-03T00:08:00Z",
    )
    assert report["overall_status"] == "pass"
    assert report["summary"] == {
        "active_workload_count": 2,
        "deployment_count": 3,
        "artifact_binding_count": 12,
        "provenance_binding_count": 9,
        "ai_bom_binding_count": 3,
        "finding_count": 0,
        "verdict": "pass",
    }
    assert len(report["checks"]) == 13
    assert all(item["status"] == "pass" for item in report["checks"])
    assert validate_artifact_verification(report) == report
    assert load_artifact_verification(output) == report

    schema = json.loads(
        (ROOT / "spec" / "lureartifact-verification-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    assert schema["$id"] == VERIFICATION_SCHEMA
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(
        schema, registry=_registry(), format_checker=FormatChecker()
    ).validate(report)


def test_verifier_rejects_valid_but_different_plan_and_evaluation_sources(tmp_path: Path):
    identity_verification = _identity_verification(tmp_path)
    plan = _load("plan.json")
    plan["workloads"][0]["artifacts"][0]["sha256"] = "1" * 64
    plan["workloads"][0]["ai_bom"]["document_sha256"] = "1" * 64
    changed_plan = tmp_path / "changed-plan.json"
    _write(changed_plan, plan)
    with pytest.raises(ValueError, match="exact independently derived"):
        create_artifact_verification(
            identity_verification,
            VECTOR / "campaign.json",
            changed_plan,
            VECTOR / "observation.json",
            VECTOR / "evaluation.json",
            verified_at="2026-09-03T00:08:00Z",
        )

    evaluation = _load("evaluation.json")
    evaluation["summary"]["finding_count"] = 1
    changed_evaluation = tmp_path / "changed-evaluation.json"
    _write(changed_evaluation, evaluation)
    with pytest.raises(ValueError, match="independently recompute"):
        create_artifact_verification(
            identity_verification,
            VECTOR / "campaign.json",
            VECTOR / "plan.json",
            VECTOR / "observation.json",
            changed_evaluation,
            verified_at="2026-09-03T00:08:00Z",
        )


def test_verification_preserves_and_recomputes_a_failing_deployment(tmp_path: Path):
    identity_verification = _identity_verification(tmp_path)
    observation = _load("observation.json")
    deployment = observation["deployments"][0]
    model = next(item for item in deployment["artifacts"] if item["role"] == "model_weights")
    model["sha256"] = "1" * 64
    model["model_serialization"] = "pickle"
    provenance = next(
        item
        for item in deployment["attestations"]
        if item["subject_artifact_id"] == model["artifact_id"]
    )
    provenance["subject_sha256"] = "1" * 64
    observation_path = tmp_path / "failing-observation.json"
    _write(observation_path, observation)
    evaluation = derive_artifact_evaluation(
        _load("plan.json"), observation, generated_at="2026-09-03T00:07:00Z"
    )
    evaluation_path = tmp_path / "failing-evaluation.json"
    _write(evaluation_path, evaluation)

    report = create_artifact_verification(
        identity_verification,
        VECTOR / "campaign.json",
        VECTOR / "plan.json",
        observation_path,
        evaluation_path,
        verified_at="2026-09-03T00:08:00Z",
    )
    assert report["overall_status"] == "fail"
    assert report["summary"]["finding_count"] == 3
    assert report["checks"][-1] == {
        "check_id": "deployment_artifact_policy_satisfied",
        "status": "fail",
    }
    assert validate_artifact_verification(report) == report


def test_verification_rejects_tampering_and_predated_timestamp(tmp_path: Path):
    identity_verification = _identity_verification(tmp_path)
    report = create_artifact_verification(
        identity_verification,
        VECTOR / "campaign.json",
        VECTOR / "plan.json",
        VECTOR / "observation.json",
        VECTOR / "evaluation.json",
        verified_at="2026-09-03T00:08:00Z",
    )
    tampered = copy.deepcopy(report)
    tampered["digests"]["artifact_plan_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="does not independently recompute"):
        validate_artifact_verification(tampered)

    with pytest.raises(ValueError, match="predates source evidence"):
        create_artifact_verification(
            identity_verification,
            VECTOR / "campaign.json",
            VECTOR / "plan.json",
            VECTOR / "observation.json",
            VECTOR / "evaluation.json",
            verified_at="2026-09-03T00:06:30Z",
        )


def test_artifact_cli_is_private_and_never_overwrites(tmp_path: Path, capsys):
    identity_verification = _identity_verification(tmp_path)
    output = tmp_path / "artifact-verification.json"
    args = [
        "artifact",
        "verify",
        str(identity_verification),
        str(VECTOR / "campaign.json"),
        str(VECTOR / "plan.json"),
        str(VECTOR / "observation.json"),
        str(VECTOR / "evaluation.json"),
        "--verified-at",
        "2026-09-03T00:08:00Z",
        "--out",
        str(output),
    ]
    assert main(args) == 0
    assert main(["artifact", "check", str(output)]) == 0
    assert "LUREARTIFACT INDEPENDENT VERIFICATION: PASS" in capsys.readouterr().out
    if os.name == "posix":
        assert output.stat().st_mode & 0o777 == 0o600
    original = output.read_bytes()
    assert main(args) == 2
    assert output.read_bytes() == original
