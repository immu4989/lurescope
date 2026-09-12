from __future__ import annotations

import ast
import copy
import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from lurescope.cli import main
from lurescope.mandate import create_mandate_verification
from lurescope.mandate_gate import (
    create_mandate_deployment_gate,
    load_approver_key_policy,
    validate_approver_key_policy,
    verify_mandate_deployment_gate,
)

ROOT = Path(__file__).parents[1]
VECTOR = ROOT / "conformance" / "luremandate-v1"
POLICY = {
    "minimum_run_started_at": "2026-09-05T15:00:00Z",
    "expected_engine_id": "luremandate-reference",
    "expected_engine_version": "1.0.0",
    "expected_engine_artifact_sha256": "a" * 64,
    "expected_receiver_instance_id": "authority-gateway-instance-1",
    "expected_receiver_key_id": "23b870f8eb429486d3ebab388918350ca0a9b8d5b735c18de5d2ed4ebd6c7211",
}


def _load(name: str) -> dict:
    return json.loads((VECTOR / name).read_text(encoding="utf-8"))


def _registry() -> Registry:
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def _create(output: Path, **overrides):
    options = dict(POLICY)
    options.update(overrides)
    return create_mandate_deployment_gate(
        VECTOR / "verification.json",
        VECTOR / "authenticated-verification.json",
        VECTOR / "otel-projection.json",
        VECTOR / "authenticated-otel-projection.json",
        VECTOR / "approver-key-policy.json",
        output,
        gate_id="test-luremandate-gate",
        created_at="2026-09-05T15:21:00Z",
        **options,
    )


def test_public_gate_and_key_policy_validate_and_recompute():
    policy = _load("approver-key-policy.json")
    gate = _load("deployment-gate.json")
    assert load_approver_key_policy(VECTOR / "approver-key-policy.json") == policy
    assert gate["overall_status"] == "pass"
    assert gate["sources"]["authenticated_verification"]["authenticated_approval_count"] == 18
    assert gate["sources"]["otel_projection"]["record_count"] == 67
    assert len(gate["checks"]) == 10

    registry = _registry()
    for filename, value in (
        ("luremandate-approver-key-policy-v1.schema.json", policy),
        ("luremandate-deployment-gate-v1.schema.json", gate),
    ):
        schema = json.loads((ROOT / "spec" / filename).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(
            schema,
            registry=registry,
            format_checker=FormatChecker(),
        ).validate(value)

    verified = verify_mandate_deployment_gate(
        VECTOR / "deployment-gate.json",
        VECTOR / "verification.json",
        VECTOR / "authenticated-verification.json",
        VECTOR / "otel-projection.json",
        VECTOR / "authenticated-otel-projection.json",
        VECTOR / "approver-key-policy.json",
        **POLICY,
    )
    assert verified["valid"] is True
    assert verified["overall_status"] == "pass"


def test_gate_creation_is_private_non_overwriting_and_exact(tmp_path: Path):
    output = tmp_path / "gate.json"
    result = _create(output)
    assert json.loads(output.read_text(encoding="utf-8")) == result
    assert result["contract"]["run_sha256"] == _load("otel-projection.json")["run_sha256"]
    if os.name == "posix":
        assert output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        _create(output)


def test_external_key_policy_is_exact_distinct_and_preregistered(tmp_path: Path):
    policy = _load("approver-key-policy.json")

    substituted = copy.deepcopy(policy)
    substituted["approver_keys"][0]["public_key_sha256"] = "0" * 64
    substituted_path = tmp_path / "substituted.json"
    substituted_path.write_text(json.dumps(substituted), encoding="utf-8")
    with pytest.raises(ValueError, match="differ from the external key policy"):
        create_mandate_deployment_gate(
            VECTOR / "verification.json",
            VECTOR / "authenticated-verification.json",
            VECTOR / "otel-projection.json",
            VECTOR / "authenticated-otel-projection.json",
            substituted_path,
            tmp_path / "substituted-gate.json",
            gate_id="substituted-key-gate",
            created_at="2026-09-05T15:21:00Z",
            **POLICY,
        )

    aliased = copy.deepcopy(policy)
    aliased["approver_keys"][1]["public_key_sha256"] = aliased["approver_keys"][0][
        "public_key_sha256"
    ]
    with pytest.raises(ValueError, match="one distinct key"):
        validate_approver_key_policy(aliased)

    late = copy.deepcopy(policy)
    late["created_at"] = "2026-09-05T15:00:00Z"
    late_path = tmp_path / "late.json"
    late_path.write_text(json.dumps(late), encoding="utf-8")
    with pytest.raises(ValueError, match="not preregistered"):
        create_mandate_deployment_gate(
            VECTOR / "verification.json",
            VECTOR / "authenticated-verification.json",
            VECTOR / "otel-projection.json",
            VECTOR / "authenticated-otel-projection.json",
            late_path,
            tmp_path / "late-gate.json",
            gate_id="late-key-policy-gate",
            created_at="2026-09-05T15:21:00Z",
            **POLICY,
        )


def test_semantically_equal_but_different_source_bytes_cannot_be_mixed(tmp_path: Path):
    compact_paths = {}
    for name in ("plan.json", "run.json", "evaluation.json"):
        path = tmp_path / name
        path.write_text(json.dumps(_load(name), separators=(",", ":")), encoding="utf-8")
        compact_paths[name] = path
    semantic = tmp_path / "semantic.json"
    create_mandate_verification(
        compact_paths["plan.json"],
        compact_paths["run.json"],
        compact_paths["evaluation.json"],
        semantic,
        verified_at="2026-09-05T15:18:00Z",
    )
    with pytest.raises(ValueError, match="do not bind exact source bytes"):
        create_mandate_deployment_gate(
            semantic,
            VECTOR / "authenticated-verification.json",
            VECTOR / "otel-projection.json",
            VECTOR / "authenticated-otel-projection.json",
            VECTOR / "approver-key-policy.json",
            tmp_path / "mixed-gate.json",
            gate_id="mixed-source-gate",
            created_at="2026-09-05T15:21:00Z",
            **POLICY,
        )


def test_gate_tamper_and_wrong_external_engine_fail_closed(tmp_path: Path):
    tampered = _load("deployment-gate.json")
    tampered["sources"]["semantic_verification"]["sha256"] = "0" * 64
    tampered_path = tmp_path / "tampered-gate.json"
    tampered_path.write_text(
        json.dumps(tampered, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    tampered_path.chmod(0o600)
    with pytest.raises(ValueError, match="does not independently reproduce"):
        verify_mandate_deployment_gate(
            tampered_path,
            VECTOR / "verification.json",
            VECTOR / "authenticated-verification.json",
            VECTOR / "otel-projection.json",
            VECTOR / "authenticated-otel-projection.json",
            VECTOR / "approver-key-policy.json",
            **POLICY,
        )

    with pytest.raises(ValueError, match="engine differs"):
        _create(tmp_path / "wrong-engine.json", expected_engine_version="9.9.9")


def test_gate_cli_and_module_have_independent_runtime_boundary():
    common = [
        str(VECTOR / "verification.json"),
        str(VECTOR / "authenticated-verification.json"),
        str(VECTOR / "otel-projection.json"),
        str(VECTOR / "authenticated-otel-projection.json"),
        str(VECTOR / "approver-key-policy.json"),
        "--minimum-run-started-at",
        POLICY["minimum_run_started_at"],
        "--expected-engine-id",
        POLICY["expected_engine_id"],
        "--expected-engine-version",
        POLICY["expected_engine_version"],
        "--expected-engine-artifact-sha256",
        POLICY["expected_engine_artifact_sha256"],
        "--expected-receiver-instance-id",
        POLICY["expected_receiver_instance_id"],
        "--expected-receiver-key-id",
        POLICY["expected_receiver_key_id"],
    ]
    assert main(["mandate", "verify-gate", str(VECTOR / "deployment-gate.json"), *common]) == 0
    tree = ast.parse((ROOT / "lurescope" / "mandate_gate.py").read_text(encoding="utf-8"))
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
