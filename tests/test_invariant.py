from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from lurescope.cli import main
from lurescope.invariant import (
    BUNDLE_LIMITATIONS,
    COMPARISON_LIMITATIONS,
    OBSERVATION_LIMITATIONS,
    PLAN_LIMITATIONS,
    _canonical,
    _derive,
    _sha256,
    _validate_observations,
    _validate_plan,
    compare_invariant_bundles,
    create_invariant_bundle,
    verify_invariant_bundle,
    verify_remediation_comparison,
)

ROOT = Path(__file__).parents[1]


def _keypair() -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private, public


def _source_artifacts(
    root: Path,
    *,
    active: bool,
    captured_at: str,
    plan_version: str,
    invariant_title: str = "Evaluation agent cannot reach the public network",
) -> tuple[Path, Path, Path]:
    root.mkdir()
    plan = {
        "schema": "https://github.com/immu4989/lurebench/spec/agent-invariant-plan/v1",
        "schema_version": 1,
        "plan_id": "synthetic-defense",
        "plan_version": plan_version,
        "system_id": "synthetic-platform",
        "created_at": "2026-08-29T10:00:00Z",
        "sources": [
            {
                "source_id": "topology",
                "source_type": "synthetic_fixture",
                "artifact_sha256": "a" * 64,
                "required": True,
            }
        ],
        "nodes": [
            {
                "node_id": "eval-agent",
                "node_type": "agent",
                "trust_zone": "evaluation",
                "tenant_id": "tenant-a",
                "sensitivity": "internal",
            },
            {
                "node_id": "public-network",
                "node_type": "network_zone",
                "trust_zone": "external",
                "tenant_id": None,
                "sensitivity": "public",
            },
        ],
        "edges": [
            {
                "edge_id": "agent-to-public",
                "source_node_id": "eval-agent",
                "target_node_id": "public-network",
                "capability": "reach",
                "channel_type": "network",
                "state": "active" if active else "inactive",
                "evidence_source_id": "topology",
            }
        ],
        "invariants": [
            {
                "invariant_id": "no-public-egress",
                "invariant_type": "forbidden_reachability",
                "title": invariant_title,
                "severity": "critical",
                "subject_node_ids": ["eval-agent"],
                "target_node_ids": ["public-network"],
                "traversable_capabilities": ["reach"],
                "mediation_node_ids": [],
                "trigger_event_type": None,
                "response_event_type": None,
                "prohibited_event_types": [],
                "maximum_delay_ms": None,
            }
        ],
        "acceptance": {"maximum_violations": 0, "allow_insufficient_evidence": False},
        "limitations": list(PLAN_LIMITATIONS),
    }
    plan_raw = _canonical(plan)
    observations = {
        "schema": (
            "https://github.com/immu4989/lurebench/spec/"
            "agent-invariant-observations/v1"
        ),
        "schema_version": 1,
        "captured_at": captured_at,
        "plan_sha256": _sha256(plan_raw),
        "source_status": [
            {"source_id": "topology", "artifact_sha256": "a" * 64, "complete": True}
        ],
        "events": [],
        "limitations": list(OBSERVATION_LIMITATIONS),
    }
    observations_raw = _canonical(observations)
    validated_plan = _validate_plan(plan)
    validated_observations = _validate_observations(
        observations, validated_plan, _sha256(plan_raw)
    )
    evaluation = _derive(
        validated_plan,
        plan_raw,
        validated_observations,
        observations_raw,
        "2026-08-29T15:00:00Z",
    )
    plan_path = root / "plan.json"
    observations_path = root / "observations.json"
    evaluation_path = root / "evaluation.json"
    plan_path.write_bytes(plan_raw)
    observations_path.write_bytes(observations_raw)
    evaluation_path.write_bytes(_canonical(evaluation))
    return plan_path, observations_path, evaluation_path


def _bundle(
    root: Path,
    source: tuple[Path, Path, Path],
    *,
    bundle_id: str,
    private: bytes | None = None,
    public: bytes | None = None,
) -> dict:
    plan, observations, evaluation = source
    return create_invariant_bundle(
        root,
        bundle_id=bundle_id,
        environment="evaluation",
        plan=plan,
        observations=observations,
        evaluation=evaluation,
        signer_public_key_pem=public,
        signing_key_pem=private,
        created_at="2026-08-29T16:00:00Z",
    )


def _validate_public_schema(file_name: str, artifact: Path) -> None:
    schema = json.loads((ROOT / "spec" / file_name).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    ).validate(json.loads(artifact.read_text(encoding="utf-8")))


def test_signed_bundle_recomputes_semantics_and_validates_public_artifacts(tmp_path: Path):
    private, public = _keypair()
    source = _source_artifacts(
        tmp_path / "source",
        active=False,
        captured_at="2026-08-29T12:00:00Z",
        plan_version="1.0.0-after",
    )
    bundle = tmp_path / "bundle"
    manifest = _bundle(bundle, source, bundle_id="after-1", private=private, public=public)
    result = verify_invariant_bundle(bundle, public_key_pem=public)

    assert manifest["overall_status"] == "pass"
    assert result["valid"] is True
    assert result["authenticated"] is True
    assert result["overall_status"] == "pass"
    assert result["key_ids"] == [manifest["authentication"]["signer_key_id"]]
    assert manifest["limitations"] == BUNDLE_LIMITATIONS
    _validate_public_schema("invariant-evidence-bundle-v1.schema.json", bundle / "bundle.json")
    _validate_public_schema(
        "invariant-evidence-checkpoint-v1.schema.json",
        bundle / "checkpoint.statement.json",
    )
    _validate_public_schema(
        "invariant-evidence-dsse-v1.schema.json", bundle / "checkpoint.dsse.json"
    )


def test_bundle_rejects_tampering_wrong_key_and_unexpected_artifacts(tmp_path: Path):
    private, public = _keypair()
    source = _source_artifacts(
        tmp_path / "source",
        active=False,
        captured_at="2026-08-29T12:00:00Z",
        plan_version="1.0.0-after",
    )
    bundle = tmp_path / "bundle"
    _bundle(bundle, source, bundle_id="after-1", private=private, public=public)

    _, wrong_public = _keypair()
    with pytest.raises(ValueError, match="public key differs"):
        verify_invariant_bundle(bundle, public_key_pem=wrong_public)

    unexpected = bundle / "notes.txt"
    unexpected.write_text("not part of the evidence set\n", encoding="utf-8")
    unexpected.chmod(0o600)
    with pytest.raises(ValueError, match="unexpected artifacts"):
        verify_invariant_bundle(bundle, public_key_pem=public)
    unexpected.unlink()

    evaluation = bundle / "evidence" / "evaluation.json"
    value = json.loads(evaluation.read_text(encoding="utf-8"))
    value["summary"]["verdict"] = "fail"
    evaluation.write_bytes(_canonical(value))
    with pytest.raises(ValueError, match=r"does not .*recompute"):
        verify_invariant_bundle(bundle, public_key_pem=public)


def test_effective_comparison_is_recomputed_and_rejects_weaker_contract(tmp_path: Path):
    before_source = _source_artifacts(
        tmp_path / "before-source",
        active=True,
        captured_at="2026-08-29T12:00:00Z",
        plan_version="1.0.0-before",
    )
    after_source = _source_artifacts(
        tmp_path / "after-source",
        active=False,
        captured_at="2026-08-29T13:00:00Z",
        plan_version="1.0.0-after",
    )
    before_bundle = tmp_path / "before-bundle"
    after_bundle = tmp_path / "after-bundle"
    _bundle(before_bundle, before_source, bundle_id="before-1")
    _bundle(after_bundle, after_source, bundle_id="after-1")
    comparison_path = tmp_path / "comparison.json"
    comparison = compare_invariant_bundles(
        before_bundle,
        after_bundle,
        comparison_path,
        comparison_id="remediation-1",
        created_at="2026-08-29T14:00:00Z",
    )
    verified = verify_remediation_comparison(
        comparison_path, before_bundle, after_bundle
    )

    assert comparison["summary"] == {
        "resolved": 1,
        "persistent": 0,
        "new": 0,
        "insufficient_after": 0,
        "status": "effective",
    }
    assert comparison["resolved_invariant_ids"] == ["no-public-egress"]
    assert comparison["limitations"] == COMPARISON_LIMITATIONS
    assert verified["status"] == "effective"
    _validate_public_schema(
        "invariant-remediation-comparison-v1.schema.json", comparison_path
    )

    changed_source = _source_artifacts(
        tmp_path / "changed-source",
        active=False,
        captured_at="2026-08-29T13:00:00Z",
        plan_version="1.0.0-after",
        invariant_title="A weaker and therefore incomparable invariant",
    )
    changed_bundle = tmp_path / "changed-bundle"
    _bundle(changed_bundle, changed_source, bundle_id="changed-1")
    with pytest.raises(ValueError, match="weakened or changed invariants"):
        compare_invariant_bundles(
            before_bundle,
            changed_bundle,
            tmp_path / "must-not-exist.json",
            comparison_id="invalid-comparison",
        )
    assert not (tmp_path / "must-not-exist.json").exists()


def test_independent_semantics_fail_closed_on_contract_time_and_outcome(tmp_path: Path):
    source = _source_artifacts(
        tmp_path / "source",
        active=False,
        captured_at="2026-08-29T12:00:00Z",
        plan_version="1.0.0-after",
    )
    plan = json.loads(source[0].read_text(encoding="utf-8"))
    observations = json.loads(source[1].read_text(encoding="utf-8"))

    weakened = json.loads(json.dumps(plan))
    weakened["acceptance"]["allow_insufficient_evidence"] = True
    with pytest.raises(ValueError, match="never accepts insufficient"):
        _validate_plan(weakened)

    predating = json.loads(json.dumps(observations))
    predating["captured_at"] = "2026-08-29T09:00:00Z"
    with pytest.raises(ValueError, match="cannot predate"):
        _validate_observations(predating, plan, _sha256(source[0].read_bytes()))

    temporal_plan = json.loads(json.dumps(plan))
    temporal_plan["invariants"][0] = {
        "invariant_id": "bounded-stop",
        "invariant_type": "bounded_response",
        "title": "Stop completes inside the declared response bound",
        "severity": "critical",
        "subject_node_ids": [],
        "target_node_ids": [],
        "traversable_capabilities": [],
        "mediation_node_ids": [],
        "trigger_event_type": "stop_requested",
        "response_event_type": "all_children_stopped",
        "prohibited_event_types": [],
        "maximum_delay_ms": 5000,
    }
    temporal_plan = _validate_plan(temporal_plan)
    temporal_raw = _canonical(temporal_plan)
    temporal_observations = json.loads(json.dumps(observations))
    temporal_observations["plan_sha256"] = _sha256(temporal_raw)
    temporal_observations["events"] = [
        {
            "event_id": "stop-request",
            "occurred_ms": 1000,
            "event_type": "stop_requested",
            "run_id": "run-a",
            "actor_node_id": "eval-agent",
            "target_node_id": None,
            "outcome": "observed",
            "evidence_source_id": "topology",
        },
        {
            "event_id": "failed-response",
            "occurred_ms": 2000,
            "event_type": "all_children_stopped",
            "run_id": "run-a",
            "actor_node_id": "eval-agent",
            "target_node_id": None,
            "outcome": "failed",
            "evidence_source_id": "topology",
        },
    ]
    temporal_observations = _validate_observations(
        temporal_observations, temporal_plan, _sha256(temporal_raw)
    )
    report = _derive(
        temporal_plan,
        temporal_raw,
        temporal_observations,
        _canonical(temporal_observations),
        "2026-08-29T15:00:00Z",
    )
    assert report["results"][0]["status"] == "violated"
    assert report["results"][0]["response_event_ids"] == []

    mismatch = json.loads(json.dumps(temporal_observations))
    mismatch["events"][1]["event_type"] = "tool_call_succeeded"
    with pytest.raises(ValueError, match="requires a succeeded outcome"):
        _validate_observations(mismatch, temporal_plan, _sha256(temporal_raw))

    with pytest.raises(ValueError, match="evaluation cannot predate"):
        _derive(
            temporal_plan,
            temporal_raw,
            temporal_observations,
            _canonical(temporal_observations),
            "2026-08-29T11:00:00Z",
        )


def test_cli_uses_status_exit_codes_and_never_overwrites(tmp_path: Path, capsys):
    before = _source_artifacts(
        tmp_path / "before",
        active=True,
        captured_at="2026-08-29T12:00:00Z",
        plan_version="1.0.0-before",
    )
    bundle = tmp_path / "bundle"
    arguments = [
        "invariant",
        "create",
        "--plan",
        str(before[0]),
        "--observations",
        str(before[1]),
        "--evaluation",
        str(before[2]),
        "--bundle-id",
        "before-cli",
        "--environment",
        "evaluation",
        "--out",
        str(bundle),
    ]
    assert main(arguments) == 1
    assert "FAIL" in capsys.readouterr().out
    assert main(arguments) == 2
    assert "already exists" in capsys.readouterr().err
    assert main(["invariant", "verify", str(bundle), "--json"]) == 1
    output = json.loads(capsys.readouterr().out)
    assert output["overall_status"] == "fail"
    assert "plan" not in output
    assert "evaluation" not in output
