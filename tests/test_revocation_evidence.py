from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import jsonschema
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from referencing import Registry, Resource

from lurescope.boundary import public_key_id
from lurescope.cli import main
from lurescope.permit import PERMIT_LIMITATIONS, PERMIT_SCHEMA, _canonical, _write_new
from lurescope.revocation import (
    BUNDLE_LIMITATIONS,
    BUNDLE_SCHEMA,
    CAEP_SESSION_REVOKED,
    COMPARISON_SCHEMA,
    EVALUATION_LIMITATIONS,
    EVALUATION_SCHEMA,
    INTERPRETATION,
    PLAN_LIMITATIONS,
    PLAN_SCHEMA,
    RUN_LIMITATIONS,
    RUN_SCHEMA,
    _validate_plan,
    compare_revocation_bundles,
    create_revocation_bundle,
    export_revocation_oscal,
    export_revocation_sarif,
    validate_revocation_evaluation,
    verify_revocation_bundle,
    verify_revocation_comparison,
)
from lurescope.revocation_gate import (
    GATE_SCHEMA,
    _require_probe_phase_coverage,
    _require_strict_acceptance,
    create_revocation_deployment_gate,
    verify_revocation_deployment_gate,
)
from lurescope.revocation_otel import (
    ACCESS_EVENT,
    CLOCK_BOUNDARY,
    EXPORT_LIMITATIONS,
    OTEL_EXPORT_SCHEMA,
    OTEL_PROJECTION_SCHEMA,
    PRIVACY,
    PROJECTION_LIMITATIONS,
    SIGNAL_EVENT,
    validate_otel_revocation_projection,
)
from lurescope.revocation_registry import (
    _consistency_path,
    _frontier_add,
    _frontier_root,
    _inclusion_path,
    _leaf_hash,
    _node_hash,
    _verify_consistency_path,
    _verify_inclusion_path,
    append_revocation_registry,
    compare_revocation_tree_heads,
    create_revocation_consistency_proof,
    create_revocation_inclusion_proof,
    create_revocation_registry,
    verify_revocation_consistency_proof,
    verify_revocation_head_comparison,
    verify_revocation_inclusion_proof,
    verify_revocation_registry,
)
from lurescope.revocation_topology import (
    TOPOLOGY_AUDIT_SCHEMA,
    TOPOLOGY_LIMITATIONS,
    validate_revocation_topology_audit,
)
from lurescope.runtime import PROFILE_LIMITATIONS, PROFILE_SCHEMA
from lurescope.witness import (
    create_witness_request,
    issue_witness_receipt,
    verify_witness_receipt,
    verify_witness_request_binding,
)

ROOT = Path(__file__).parents[1]
ACTIONS = [
    "credential_use",
    "delegate",
    "evaluator_access",
    "high_impact_change",
    "incident_escalation",
    "local_tool_call",
    "network_request",
    "process_activity",
    "registry_read",
    "shared_state_write",
    "storage_read",
]


def _recursive_rfc9162_root(entries: list[bytes]) -> bytes:
    if not entries:
        return hashlib.sha256(b"").digest()
    if len(entries) == 1:
        return hashlib.sha256(b"\x00" + entries[0]).digest()
    split = 1 << (len(entries) - 1).bit_length() - 1
    if split == len(entries):
        split //= 2
    return hashlib.sha256(
        b"\x01"
        + _recursive_rfc9162_root(entries[:split])
        + _recursive_rfc9162_root(entries[split:])
    ).digest()


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


def _topology_profile() -> dict:
    permit = {
        "schema": PERMIT_SCHEMA,
        "schema_version": 1,
        "permit_id": "topology-permit",
        "permit_version": "1.0.0",
        "system_id": "revocation-test-system",
        "run_id": "topology-run",
        "created_at": "2026-08-30T10:00:00Z",
        "subject": {
            "agent_id": "agent-a",
            "tenant_id": "tenant-a",
            "workload_identity": "workload-a",
        },
        "authorization": {
            "allowed_action_types": ACTIONS,
            "allowed_resource_ids": ["local_workspace"],
            "allowed_capabilities": ["call"],
            "external_network_policy": "deny",
            "credential_policy": "synthetic_brokered_only",
            "credential_audience": "lurerange",
            "maximum_delegation_depth": 1,
            "approval_required_action_types": ["high_impact_change"],
        },
        "isolation": {
            "workload_isolated": True,
            "network_isolated": True,
            "per_run_storage": True,
            "shared_service_write_policy": "deny",
        },
        "budgets": {
            "maximum_actions": 10,
            "maximum_duration_ms": 60000,
            "maximum_consecutive_failures": 3,
        },
        "monitoring": {"required_sensor_ids": ["policy-gateway", "runtime-monitor"]},
        "stop": {
            "shutdown_deadline_ms": 5000,
            "revoke_credentials": True,
            "terminate_children": True,
        },
        "acceptance": {
            "minimum_violation_control_rate": 1.0,
            "minimum_benign_allow_rate": 1.0,
            "minimum_reason_accuracy": 1.0,
            "minimum_safe_stop_recall": 1.0,
        },
        "limitations": list(PERMIT_LIMITATIONS),
    }
    return {
        "schema": PROFILE_SCHEMA,
        "schema_version": 1,
        "profile_id": "topology-profile",
        "profile_version": "1.0.0",
        "created_at": "2026-08-30T10:00:00Z",
        "permit": permit,
        "permit_sha256": hashlib.sha256(_canonical(permit)).hexdigest(),
        "identity": {
            "allowed_spiffe_trust_domains": ["example.gov"],
            "require_workload_identity": True,
            "human_authority_action_types": ["high_impact_change"],
            "minimum_policy_generation": 2,
            "maximum_request_age_ms": 60000,
        },
        "protocols": {
            "allowed": ["direct", "mcp"],
            "mcp_allowed_server_ids": ["mock-mcp"],
            "mcp_allowed_methods": ["resources/read", "tools/call"],
            "oauth_resource_indicator_required": True,
            "token_passthrough_prohibited": True,
        },
        "mediation_points": [
            {
                "point_id": "tool-gateway",
                "action_types": ACTIONS,
                "required_sensor_ids": ["runtime-audit"],
            }
        ],
        "receipt_policy": {
            "chain_required": True,
            "replay_protection_required": True,
            "maximum_clock_skew_ms": 5000,
        },
        "acceptance": {
            "minimum_decision_accuracy": 1.0,
            "minimum_reason_accuracy": 1.0,
            "minimum_mediation_coverage_rate": 1.0,
            "minimum_mediation_point_coverage_rate": 1.0,
            "maximum_control_bypass_count": 0,
            "maximum_unmediated_count": 0,
            "maximum_unknown_rate": 0.0,
        },
        "limitations": list(PROFILE_LIMITATIONS),
    }


def test_incremental_registry_root_matches_rfc9162_recursive_definition():
    entries = [f"canonical-entry-{index}\n".encode() for index in range(1, 18)]
    frontier = []
    for size, entry in enumerate(entries, start=1):
        _frontier_add(frontier, _leaf_hash(entry))
        assert _frontier_root(frontier) == _recursive_rfc9162_root(entries[:size])


def test_registry_inclusion_paths_cover_every_leaf_in_unbalanced_trees():
    entries = [f"portable-entry-{index}\n".encode() for index in range(1, 18)]
    for tree_size in range(1, len(entries) + 1):
        root = _recursive_rfc9162_root(entries[:tree_size])
        for leaf_index in range(tree_size):
            path = _inclusion_path(leaf_index, entries[:tree_size])
            assert (
                _verify_inclusion_path(
                    _leaf_hash(entries[leaf_index]),
                    leaf_index=leaf_index,
                    tree_size=tree_size,
                    inclusion_path=path,
                )
                == root
            )


def test_registry_consistency_paths_cover_every_unbalanced_prefix_pair():
    entries = [f"append-only-entry-{index}\n".encode() for index in range(1, 18)]
    for second_size in range(2, len(entries) + 1):
        second_root = _recursive_rfc9162_root(entries[:second_size])
        for first_size in range(1, second_size):
            path = _consistency_path(first_size, entries[:second_size])
            assert path
            assert (
                _verify_consistency_path(
                    _recursive_rfc9162_root(entries[:first_size]),
                    second_root,
                    first_size=first_size,
                    second_size=second_size,
                    consistency_path=path,
                )
                is None
            )


def test_registry_paths_match_rfc9162_seven_leaf_example():
    """Pin path ordering to the named tree in RFC 9162 Section 2.1.5."""
    entries = [f"d{index}".encode() for index in range(7)]
    a, b, c, d, e, f, j = [_leaf_hash(entry) for entry in entries]
    g = _node_hash(a, b)
    h = _node_hash(c, d)
    i = _node_hash(e, f)
    k = _node_hash(g, h)
    node_l = _node_hash(i, j)

    assert _inclusion_path(0, entries) == [b, h, node_l]
    assert _inclusion_path(3, entries) == [c, g, node_l]
    assert _inclusion_path(4, entries) == [f, j, k]
    assert _inclusion_path(6, entries) == [i, k]

    assert _consistency_path(3, entries) == [c, d, g, node_l]
    assert _consistency_path(4, entries) == [node_l]
    assert _consistency_path(6, entries) == [i, j, k]


def _evaluation(
    *,
    passing: bool,
    run_generated_at: str = "2026-08-30T11:00:00Z",
    generated_at: str = "2026-08-30T11:01:00Z",
    receiver_version: str = "1.0.0",
) -> dict:
    event = {
        "event_id": "revocation-1",
        "sequence": 1,
        "occurred_at_ms": 1000,
        "event_type": CAEP_SESSION_REVOKED,
        "subject": {"format": "opaque", "id": "subject-session-a"},
        "attenuation_reason": "session_revoked",
    }
    event["signal_sha256"] = hashlib.sha256(_canonical(event)).hexdigest()
    plan = {
        "schema": PLAN_SCHEMA,
        "schema_version": 1,
        "plan_id": "revocation-test-plan",
        "created_at": "2026-08-30T10:00:00Z",
        "system_id": "revocation-test-system",
        "stream": {
            "transmitter_id": "test-transmitter",
            "receiver_audience_id": "test-receiver",
            "stream_id": "test-stream",
            "profile": "openid-caep-1.0-final-metadata-projection",
            "authentication_boundary": "externally_verified_set_metadata",
        },
        "nodes": [{"node_id": "policy-node", "mediation_point_id": "tool-gateway"}],
        "events": [event],
        "probes": [
            {
                "probe_id": "probe-before",
                "event_id": "revocation-1",
                "node_id": "policy-node",
                "attempted_at_ms": 950,
                "subject_id": "subject-session-a",
            },
            {
                "probe_id": "probe-propagation",
                "event_id": "revocation-1",
                "node_id": "policy-node",
                "attempted_at_ms": 1050,
                "subject_id": "subject-session-a",
            },
            {
                "probe_id": "probe-after",
                "event_id": "revocation-1",
                "node_id": "policy-node",
                "attempted_at_ms": 1600,
                "subject_id": "subject-session-a",
            },
            {
                "probe_id": "probe-other",
                "event_id": "revocation-1",
                "node_id": "policy-node",
                "attempted_at_ms": 1600,
                "subject_id": "unrelated-subject",
            },
        ],
        "acceptance": {
            "maximum_convergence_ms": 500,
            "maximum_deadline_miss_count": 0,
            "maximum_post_deadline_allow_count": 0,
            "maximum_collateral_block_count": 0,
            "minimum_delivery_coverage_rate": 1.0,
            "minimum_revoked_block_recall": 1.0,
            "minimum_pre_event_allow_rate": 1.0,
            "minimum_signal_disposition_accuracy": 1.0,
        },
        "limitations": list(PLAN_LIMITATIONS),
    }
    access = [
        {
            "probe_id": "probe-before",
            "decision": "allow",
            "reason_code": "revocation_not_effective",
        },
        {
            "probe_id": "probe-propagation",
            "decision": "allow",
            "reason_code": "propagation_window",
        },
        {
            "probe_id": "probe-after",
            "decision": "block" if passing else "allow",
            "reason_code": "subject_revoked",
        },
        {
            "probe_id": "probe-other",
            "decision": "allow",
            "reason_code": "subject_not_revoked",
        },
    ]
    run = {
        "schema": RUN_SCHEMA,
        "schema_version": 1,
        "run_id": "revocation-test-run",
        "generated_at": run_generated_at,
        "implementation": {
            "name": "receiver-under-test",
            "version": receiver_version,
            "artifact_sha256": "a" * 64,
        },
        "plan_sha256": hashlib.sha256(_canonical(plan)).hexdigest(),
        "signal_observations": [
            {
                "observation_id": "signal-invalid",
                "event_id": "revocation-1",
                "node_id": "policy-node",
                "received_at_ms": 1010,
                "signal_sha256": "0" * 64,
                "disposition": "invalid",
            },
            {
                "observation_id": "signal-applied",
                "event_id": "revocation-1",
                "node_id": "policy-node",
                "received_at_ms": 1100,
                "signal_sha256": event["signal_sha256"],
                "disposition": "applied",
            },
            {
                "observation_id": "signal-duplicate",
                "event_id": "revocation-1",
                "node_id": "policy-node",
                "received_at_ms": 1101,
                "signal_sha256": event["signal_sha256"],
                "disposition": "duplicate",
            },
        ],
        "access_observations": access,
        "limitations": list(RUN_LIMITATIONS),
    }
    report = {
        "schema": EVALUATION_SCHEMA,
        "schema_version": 1,
        "generated_at": generated_at,
        "implementation": {"name": "lurebench", "version": "0.11.0"},
        "plan": plan,
        "plan_sha256": hashlib.sha256(_canonical(plan)).hexdigest(),
        "run": run,
        "run_sha256": hashlib.sha256(_canonical(run)).hexdigest(),
        "summary": {
            "event_count": 1,
            "node_count": 1,
            "required_delivery_count": 1,
            "applied_delivery_count": 1,
            "delivery_coverage_rate": 1.0,
            "maximum_convergence_ms": 100,
            "p95_convergence_ms": 100,
            "deadline_miss_count": 0,
            "post_deadline_allow_count": 0 if passing else 1,
            "collateral_block_count": 0,
            "revoked_block_recall": 1.0 if passing else 0.0,
            "pre_event_allow_rate": 1.0,
            "signal_disposition_accuracy": 1.0,
            "incorrect_decision_count": 0 if passing else 1,
            "incorrect_reason_count": 0,
            "verdict": "pass" if passing else "fail",
        },
        "delivery_results": [
            {
                "event_id": "revocation-1",
                "node_id": "policy-node",
                "applied_at_ms": 1100,
                "convergence_ms": 100,
                "deadline_met": True,
            }
        ],
        "probe_results": [
            {
                "probe_id": "probe-before",
                "event_id": "revocation-1",
                "node_id": "policy-node",
                "phase": "pre_event",
                "expected_decision": "allow",
                "submitted_decision": "allow",
                "expected_reason_code": "revocation_not_effective",
                "submitted_reason_code": "revocation_not_effective",
                "classification": "correct",
            },
            {
                "probe_id": "probe-propagation",
                "event_id": "revocation-1",
                "node_id": "policy-node",
                "phase": "propagation_window",
                "expected_decision": "allow",
                "submitted_decision": "allow",
                "expected_reason_code": "propagation_window",
                "submitted_reason_code": "propagation_window",
                "classification": "correct",
            },
            {
                "probe_id": "probe-after",
                "event_id": "revocation-1",
                "node_id": "policy-node",
                "phase": "revoked",
                "expected_decision": "block",
                "submitted_decision": "block" if passing else "allow",
                "expected_reason_code": "subject_revoked",
                "submitted_reason_code": "subject_revoked",
                "classification": "correct" if passing else "revocation_bypass",
            },
            {
                "probe_id": "probe-other",
                "event_id": "revocation-1",
                "node_id": "policy-node",
                "phase": "unrelated_subject",
                "expected_decision": "allow",
                "submitted_decision": "allow",
                "expected_reason_code": "subject_not_revoked",
                "submitted_reason_code": "subject_not_revoked",
                "classification": "correct",
            },
        ],
        "limitations": list(EVALUATION_LIMITATIONS),
    }
    return report


def _otel_projection() -> dict:
    report = _evaluation(passing=True)
    plan = report["plan"]
    source_run = report["run"]
    origin = int(datetime(2026, 8, 30, tzinfo=timezone.utc).timestamp()) * 1_000_000_000
    probes = {item["probe_id"]: item for item in plan["probes"]}
    records = []
    for index, signal in enumerate(source_run["signal_observations"], start=1):
        timestamp = origin + signal["received_at_ms"] * 1_000_000
        records.append(
            {
                "Timestamp": timestamp,
                "ObservedTimestamp": timestamp + 1_000_000,
                "TraceId": f"{index:032x}",
                "SpanId": f"{index:016x}",
                "EventName": SIGNAL_EVENT,
                "Resource": {
                    "service.name": source_run["implementation"]["name"],
                    "service.instance.id": signal["node_id"],
                    "service.version": source_run["implementation"]["version"],
                },
                "Attributes": {
                    key: value for key, value in signal.items() if key != "received_at_ms"
                },
            }
        )
    offset = len(records)
    for index, access in enumerate(source_run["access_observations"], start=1):
        probe = probes[access["probe_id"]]
        timestamp = origin + probe["attempted_at_ms"] * 1_000_000
        context = offset + index
        records.append(
            {
                "Timestamp": timestamp,
                "ObservedTimestamp": timestamp + 1_000_000,
                "TraceId": f"{context:032x}",
                "SpanId": f"{context:016x}",
                "EventName": ACCESS_EVENT,
                "Resource": {
                    "service.name": source_run["implementation"]["name"],
                    "service.instance.id": probe["node_id"],
                    "service.version": source_run["implementation"]["version"],
                },
                "Attributes": dict(access),
            }
        )
    export = {
        "schema": OTEL_EXPORT_SCHEMA,
        "schema_version": 1,
        "export_id": "independent-otel-projection",
        "generated_at": source_run["generated_at"],
        "time_origin_unix_nano": origin,
        "receiver": dict(source_run["implementation"]),
        "records": records,
        "limitations": list(EXPORT_LIMITATIONS),
    }
    ordered = sorted(records, key=lambda item: (item["Timestamp"], item["TraceId"], item["SpanId"]))
    run = dict(source_run)
    run["signal_observations"] = [
        dict(item["Attributes"]) | {"received_at_ms": (item["Timestamp"] - origin) // 1_000_000}
        for item in ordered
        if item["EventName"] == SIGNAL_EVENT
    ]
    run["access_observations"] = [
        dict(item["Attributes"]) for item in ordered if item["EventName"] == ACCESS_EVENT
    ]
    return {
        "schema": OTEL_PROJECTION_SCHEMA,
        "schema_version": 1,
        "generated_at": export["generated_at"],
        "implementation": {"name": "lurebench", "version": "0.11.0"},
        "inputs": {
            "revocation_plan": plan,
            "revocation_plan_sha256": hashlib.sha256(_canonical(plan)).hexdigest(),
            "otel_log_export": export,
            "otel_log_export_sha256": hashlib.sha256(_canonical(export)).hexdigest(),
        },
        "run": run,
        "run_sha256": hashlib.sha256(_canonical(run)).hexdigest(),
        "clock_boundary": dict(CLOCK_BOUNDARY),
        "privacy": dict(PRIVACY),
        "limitations": list(PROJECTION_LIMITATIONS),
    }


def _schema(filename: str, value: dict) -> None:
    schema = json.loads((ROOT / "spec" / filename).read_text(encoding="utf-8"))
    resources = []
    for path in (ROOT / "spec").glob("*.json"):
        candidate = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in candidate:
            resources.append((candidate["$id"], Resource.from_contents(candidate)))
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(
        schema,
        registry=Registry().with_resources(resources),
        format_checker=jsonschema.FormatChecker(),
    ).validate(value)


def _official_oscal_validator():
    schema = json.loads(
        (ROOT / "tests/vendor/oscal-1.2.2/oscal_assessment-results_schema.json").read_text(
            encoding="utf-8"
        )
    )
    default_pattern = jsonschema.Draft7Validator.VALIDATORS["pattern"]

    def unicode_pattern(validator, pattern, instance, current_schema):
        translated = pattern.replace(r"\p{L}", r"[^\W\d_]").replace(r"\p{N}", r"\d")
        yield from default_pattern(validator, translated, instance, current_schema)

    validator_type = jsonschema.validators.extend(
        jsonschema.Draft7Validator, {"pattern": unicode_pattern}
    )
    return validator_type(schema, format_checker=jsonschema.FormatChecker())


def test_independent_revocation_recomputation_rejects_tampering():
    report = _evaluation(passing=True)
    assert validate_revocation_evaluation(report)["summary"]["verdict"] == "pass"

    changed = json.loads(json.dumps(report))
    changed["summary"]["p95_convergence_ms"] = 1
    with pytest.raises(ValueError, match="independently recompute"):
        validate_revocation_evaluation(changed)

    changed = json.loads(json.dumps(report))
    changed["plan"]["events"][0]["subject"]["id"] = "substituted-subject"
    with pytest.raises(ValueError, match="signal digest"):
        validate_revocation_evaluation(changed)


def test_signed_revocation_bundle_schemas_tamper_and_exports(tmp_path: Path):
    private, public = _keypair()
    source = tmp_path / "revocation.json"
    _write_new(source, _canonical(_evaluation(passing=False)))
    bundle = tmp_path / "bundle"
    manifest = create_revocation_bundle(
        bundle,
        bundle_id="revocation-signed",
        environment="evaluation",
        evaluation=source,
        signer_public_key_pem=public,
        signing_key_pem=private,
        created_at="2026-08-30T11:02:00Z",
    )
    verified = verify_revocation_bundle(bundle, public_key_pem=public)
    assert verified["authenticated"] is True
    assert verified["overall_status"] == "fail"
    public_path = tmp_path / "public.pem"
    _write_new(public_path, public)
    assert main(["revoke", "verify", str(bundle), "--public-key", str(public_path)]) == 1
    assert manifest["schema"] == BUNDLE_SCHEMA
    assert manifest["limitations"] == BUNDLE_LIMITATIONS
    assert manifest["interpretation_boundary"] == INTERPRETATION
    _schema("lurerevoke-evidence-bundle-v1.schema.json", manifest)
    _schema(
        "lurerevoke-evidence-checkpoint-v1.schema.json",
        json.loads((bundle / "checkpoint.statement.json").read_text(encoding="utf-8")),
    )
    _schema(
        "lurerevoke-evidence-dsse-v1.schema.json",
        json.loads((bundle / "checkpoint.dsse.json").read_text(encoding="utf-8")),
    )

    oscal = export_revocation_oscal(
        bundle,
        tmp_path / "revocation.oscal.json",
        assessment_plan_href="urn:example:assessment-plan:revocation",
        public_key_pem=public,
    )
    _official_oscal_validator().validate(oscal)
    assert "findings" not in oscal["assessment-results"]["results"][0]

    sarif = export_revocation_sarif(
        bundle, tmp_path / "revocation.sarif.json", public_key_pem=public
    )
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "LURE-REVOKE-002"
    assert "locations" not in sarif["runs"][0]["results"][0]

    evidence = bundle / "evidence/revocation-evaluation.json"
    original = evidence.read_bytes()
    evidence.write_bytes(original.replace(b'"verdict":"fail"', b'"verdict":"pass"'))
    with pytest.raises(ValueError):
        verify_revocation_bundle(bundle, public_key_pem=public)


def test_revocation_remediation_comparison_is_same_contract_and_recomputable(
    tmp_path: Path,
):
    before_private, before_public = _keypair()
    after_private, after_public = _keypair()
    before_source = tmp_path / "before.json"
    after_source = tmp_path / "after.json"
    _write_new(before_source, _canonical(_evaluation(passing=False)))
    _write_new(
        after_source,
        _canonical(
            _evaluation(
                passing=True,
                run_generated_at="2026-08-30T12:00:00Z",
                generated_at="2026-08-30T12:01:00Z",
                receiver_version="1.1.0",
            )
        ),
    )
    before_bundle, after_bundle = tmp_path / "before.bundle", tmp_path / "after.bundle"
    create_revocation_bundle(
        before_bundle,
        bundle_id="revocation-before",
        environment="evaluation",
        evaluation=before_source,
        signer_public_key_pem=before_public,
        signing_key_pem=before_private,
        created_at="2026-08-30T11:02:00Z",
    )
    create_revocation_bundle(
        after_bundle,
        bundle_id="revocation-after",
        environment="evaluation",
        evaluation=after_source,
        signer_public_key_pem=after_public,
        signing_key_pem=after_private,
        created_at="2026-08-30T12:02:00Z",
    )

    comparison_path = tmp_path / "remediation.json"
    comparison = compare_revocation_bundles(
        before_bundle,
        after_bundle,
        comparison_path,
        comparison_id="receiver-remediation-1",
        before_public_key_pem=before_public,
        after_public_key_pem=after_public,
        created_at="2026-08-30T12:03:00Z",
    )
    assert comparison["schema"] == COMPARISON_SCHEMA
    assert comparison["summary"] == {
        "resolved": 1,
        "persistent": 0,
        "new": 0,
        "status": "effective",
    }
    assert comparison["resolved_failure_ids"] == ["probe/probe-after"]
    assert comparison["metric_deltas"]["post_deadline_allow_count_delta"] == -1
    assert comparison["metric_deltas"]["revoked_block_recall_delta"] == 1.0
    assert comparison["before"]["authenticated"] is True
    assert comparison["after"]["authenticated"] is True
    _schema("lurerevoke-remediation-comparison-v1.schema.json", comparison)

    verified = verify_revocation_comparison(
        comparison_path,
        before_bundle,
        after_bundle,
        before_public_key_pem=before_public,
        after_public_key_pem=after_public,
    )
    assert verified["status"] == "effective"

    before_key_path, after_key_path = tmp_path / "before.pem", tmp_path / "after.pem"
    _write_new(before_key_path, before_public)
    _write_new(after_key_path, after_public)
    assert (
        main(
            [
                "revoke",
                "verify-comparison",
                str(comparison_path),
                str(before_bundle),
                str(after_bundle),
                "--before-public-key",
                str(before_key_path),
                "--after-public-key",
                str(after_key_path),
            ]
        )
        == 0
    )

    tampered = json.loads(comparison_path.read_text(encoding="utf-8"))
    tampered["summary"]["status"] = "ineffective"
    comparison_path.write_bytes(_canonical(tampered))
    with pytest.raises(ValueError, match="independently recompute"):
        verify_revocation_comparison(
            comparison_path,
            before_bundle,
            after_bundle,
            before_public_key_pem=before_public,
            after_public_key_pem=after_public,
        )


def test_revocation_comparison_rejects_moved_goalposts(tmp_path: Path):
    before_source, after_source = tmp_path / "before.json", tmp_path / "after.json"
    before = _evaluation(passing=True)
    after = _evaluation(
        passing=True,
        run_generated_at="2026-08-30T12:00:00Z",
        generated_at="2026-08-30T12:01:00Z",
        receiver_version="1.1.0",
    )
    after["plan"]["acceptance"]["maximum_convergence_ms"] = 600
    plan_sha256 = hashlib.sha256(_canonical(after["plan"])).hexdigest()
    after["plan_sha256"] = plan_sha256
    after["run"]["plan_sha256"] = plan_sha256
    after["run_sha256"] = hashlib.sha256(_canonical(after["run"])).hexdigest()
    assert validate_revocation_evaluation(after)["summary"]["verdict"] == "pass"
    _write_new(before_source, _canonical(before))
    _write_new(after_source, _canonical(after))
    before_bundle, after_bundle = tmp_path / "before.bundle", tmp_path / "after.bundle"
    create_revocation_bundle(
        before_bundle,
        bundle_id="before-plan",
        environment="evaluation",
        evaluation=before_source,
        created_at="2026-08-30T11:02:00Z",
    )
    create_revocation_bundle(
        after_bundle,
        bundle_id="after-plan",
        environment="evaluation",
        evaluation=after_source,
        created_at="2026-08-30T12:02:00Z",
    )
    with pytest.raises(ValueError, match="changed plan or acceptance"):
        compare_revocation_bundles(
            before_bundle,
            after_bundle,
            tmp_path / "comparison.json",
            comparison_id="moved-goalposts",
        )


def test_independent_witness_observes_only_a_signed_revocation_checkpoint(tmp_path: Path):
    bundle_private, bundle_public = _keypair()
    source = tmp_path / "evaluation.json"
    _write_new(source, _canonical(_evaluation(passing=True)))
    bundle = tmp_path / "revocation.bundle"
    create_revocation_bundle(
        bundle,
        bundle_id="witnessed-revocation",
        environment="evaluation",
        evaluation=source,
        signer_public_key_pem=bundle_public,
        signing_key_pem=bundle_private,
        created_at="2026-08-30T11:02:00Z",
    )

    request_path = tmp_path / "witness-request.json"
    request = create_witness_request(
        bundle,
        request_path,
        bundle_kind="lurerevoke",
        public_key_pem=bundle_public,
        request_id="revocation-witness-request",
        nonce="independent-challenge-123",
        created_at="2026-08-30T11:03:00Z",
    )
    assert request["bundle_kind"] == "lurerevoke"
    assert request["checkpoint_sequence"] == 1
    assert request["status"] == "pass"
    _schema("checkpoint-witness-request-v1.schema.json", request)

    witness_private, witness_public = _keypair()
    receipt_path = tmp_path / "witness-receipt.json"
    receipt = issue_witness_receipt(
        request_path,
        receipt_path,
        witness_id="independent-auditor",
        signing_key_pem=witness_private,
        issued_at="2026-08-30T11:04:00Z",
    )
    _schema("checkpoint-witness-receipt-v1.schema.json", receipt)
    verified = verify_witness_receipt(request_path, receipt_path, public_key_pem=witness_public)
    assert verified["checkpoint_statement_sha256"] == request["checkpoint_statement_sha256"]
    assert verify_witness_request_binding(request_path, bundle, public_key_pem=bundle_public)[
        "valid"
    ]

    unsigned = tmp_path / "unsigned.bundle"
    create_revocation_bundle(
        unsigned,
        bundle_id="unsigned-revocation",
        environment="evaluation",
        evaluation=source,
        created_at="2026-08-30T11:02:00Z",
    )
    with pytest.raises(ValueError, match="requires a signed bundle"):
        create_witness_request(
            unsigned,
            tmp_path / "unsigned-request.json",
            bundle_kind="lurerevoke",
        )


def test_signed_revocation_registry_commits_order_and_detects_rollback(tmp_path: Path):
    registry_private, registry_public = _keypair()
    bundle_private, bundle_public = _keypair()
    public_path = tmp_path / "registry-public.pem"
    _write_new(public_path, registry_public)
    registry = tmp_path / "registry"
    config = create_revocation_registry(
        registry,
        registry_id="agency-revocation-history",
        system_id="revocation-test-system",
        environment="evaluation",
        receiver_name="receiver-under-test",
        signer_public_key_pem=registry_public,
        created_at="2026-08-30T10:30:00Z",
    )
    _schema("lurerevoke-registry-v1.schema.json", config)
    interrupted_staging = tmp_path / ".registry.pending-append-interrupted"
    interrupted_staging.mkdir(mode=0o700)
    _write_new(interrupted_staging / "entry.json", b"partial")
    assert verify_revocation_registry(registry, public_key_pem=registry_public)["tree_size"] == 0

    bundles = []
    for index, (passing, hour) in enumerate(((False, 11), (True, 12)), start=1):
        source = tmp_path / f"evaluation-{index}.json"
        _write_new(
            source,
            _canonical(
                _evaluation(
                    passing=passing,
                    run_generated_at=f"2026-08-30T{hour:02d}:00:00Z",
                    generated_at=f"2026-08-30T{hour:02d}:01:00Z",
                    receiver_version=f"1.{index - 1}.0",
                )
            ),
        )
        bundle = tmp_path / f"bundle-{index}"
        create_revocation_bundle(
            bundle,
            bundle_id=f"registry-bundle-{index}",
            environment="evaluation",
            evaluation=source,
            signer_public_key_pem=bundle_public,
            signing_key_pem=bundle_private,
            created_at=f"2026-08-30T{hour:02d}:02:00Z",
        )
        bundles.append(bundle)

    first = append_revocation_registry(
        registry,
        bundles[0],
        registry_public_key_pem=registry_public,
        registry_signing_key_pem=registry_private,
        bundle_public_key_pem=bundle_public,
        registered_at="2026-08-30T11:03:00Z",
    )
    assert first["tree_size"] == 1
    assert not any(item.name.startswith(".pending") for item in (registry / "entries").iterdir())
    trusted_statement = tmp_path / "trusted-head.statement.json"
    trusted_dsse = tmp_path / "trusted-head.dsse.json"
    _write_new(
        trusted_statement,
        (registry / "entries/00000001/tree-head.statement.json").read_bytes(),
    )
    _write_new(
        trusted_dsse,
        (registry / "entries/00000001/tree-head.dsse.json").read_bytes(),
    )

    second = append_revocation_registry(
        registry,
        bundles[1],
        registry_public_key_pem=registry_public,
        registry_signing_key_pem=registry_private,
        bundle_public_key_pem=bundle_public,
        registered_at="2026-08-30T12:03:00Z",
    )
    assert second["tree_size"] == 2
    first_raw = (registry / "entries/00000001/entry.json").read_bytes()
    second_raw = (registry / "entries/00000002/entry.json").read_bytes()
    expected_root = hashlib.sha256(
        b"\x01"
        + hashlib.sha256(b"\x00" + first_raw).digest()
        + hashlib.sha256(b"\x00" + second_raw).digest()
    ).hexdigest()
    assert second["root_sha256"] == expected_root
    _schema("lurerevoke-registry-entry-v1.schema.json", json.loads(first_raw))
    _schema(
        "lurerevoke-registry-tree-head-v1.schema.json",
        json.loads(
            (registry / "entries/00000002/tree-head.statement.json").read_text(encoding="utf-8")
        ),
    )
    verified = verify_revocation_registry(
        registry,
        public_key_pem=registry_public,
        trusted_head_statement=trusted_statement,
        trusted_head_dsse=trusted_dsse,
    )
    assert verified["trusted_tree_size"] == 1
    proof_path = tmp_path / "entry-1.inclusion.json"
    proof = create_revocation_inclusion_proof(
        registry,
        proof_path,
        sequence=1,
        tree_size=2,
        public_key_pem=registry_public,
    )
    assert proof["leaf_index"] == 0
    assert proof["entry"] == json.loads(first_raw)
    assert len(proof["inclusion_path_sha256"]) == 1
    _schema("lurerevoke-registry-inclusion-proof-v1.schema.json", proof)
    proof_result = verify_revocation_inclusion_proof(
        proof_path,
        public_key_pem=registry_public,
    )
    assert proof_result["authenticated"] is True
    assert proof_result["root_sha256"] == expected_root
    assert (
        main(
            [
                "revoke",
                "registry-verify-inclusion",
                str(proof_path),
                "--registry-public-key",
                str(public_path),
            ]
        )
        == 0
    )
    altered_proof = json.loads(proof_path.read_text(encoding="utf-8"))
    sibling = altered_proof["inclusion_path_sha256"][0]
    altered_proof["inclusion_path_sha256"][0] = ("0" if sibling[0] != "0" else "1") + sibling[1:]
    altered_path = tmp_path / "altered-inclusion.json"
    _write_new(altered_path, _canonical(altered_proof))
    with pytest.raises(ValueError, match="does not recompute"):
        verify_revocation_inclusion_proof(altered_path, public_key_pem=registry_public)
    consistency_path = tmp_path / "head-1-to-2.consistency.json"
    consistency = create_revocation_consistency_proof(
        registry,
        consistency_path,
        first_tree_size=1,
        second_tree_size=2,
        public_key_pem=registry_public,
    )
    assert consistency["first_root_sha256"] == _leaf_hash(first_raw).hex()
    assert consistency["second_root_sha256"] == expected_root
    _schema("lurerevoke-registry-consistency-proof-v1.schema.json", consistency)
    consistency_result = verify_revocation_consistency_proof(
        consistency_path,
        public_key_pem=registry_public,
    )
    assert consistency_result["authenticated"] is True
    assert consistency_result["first_tree_size"] == 1
    assert consistency_result["second_tree_size"] == 2
    assert (
        main(
            [
                "revoke",
                "registry-verify-consistency",
                str(consistency_path),
                "--registry-public-key",
                str(public_path),
            ]
        )
        == 0
    )
    changed_consistency = json.loads(consistency_path.read_text(encoding="utf-8"))
    node = changed_consistency["consistency_path_sha256"][0]
    changed_consistency["consistency_path_sha256"][0] = ("0" if node[0] != "0" else "1") + node[1:]
    changed_consistency_path = tmp_path / "changed-consistency.json"
    _write_new(changed_consistency_path, _canonical(changed_consistency))
    with pytest.raises(ValueError, match="does not reconcile"):
        verify_revocation_consistency_proof(
            changed_consistency_path,
            public_key_pem=registry_public,
        )
    first_head = registry / "entries/00000001/tree-head.statement.json"
    first_head_dsse = registry / "entries/00000001/tree-head.dsse.json"
    second_head = registry / "entries/00000002/tree-head.statement.json"
    second_head_dsse = registry / "entries/00000002/tree-head.dsse.json"
    identical_path = tmp_path / "identical-heads.json"
    identical = compare_revocation_tree_heads(
        registry / "registry.json",
        first_head,
        first_head_dsse,
        first_head,
        first_head_dsse,
        identical_path,
        public_key_pem=registry_public,
    )
    assert identical["summary"]["status"] == "identical"
    different_sizes_path = tmp_path / "different-size-heads.json"
    different_sizes = compare_revocation_tree_heads(
        registry / "registry.json",
        first_head,
        first_head_dsse,
        second_head,
        second_head_dsse,
        different_sizes_path,
        public_key_pem=registry_public,
    )
    assert different_sizes["summary"]["status"] == "different_sizes_consistency_not_evaluated"

    forked_registry = tmp_path / "forked-registry"
    create_revocation_registry(
        forked_registry,
        registry_id="agency-revocation-history",
        system_id="revocation-test-system",
        environment="evaluation",
        receiver_name="receiver-under-test",
        signer_public_key_pem=registry_public,
        created_at="2026-08-30T10:30:00Z",
    )
    append_revocation_registry(
        forked_registry,
        bundles[1],
        registry_public_key_pem=registry_public,
        registry_signing_key_pem=registry_private,
        bundle_public_key_pem=bundle_public,
        registered_at="2026-08-30T12:03:00Z",
    )
    equivocation_path = tmp_path / "equivocation.json"
    equivocation = compare_revocation_tree_heads(
        registry / "registry.json",
        first_head,
        first_head_dsse,
        forked_registry / "entries/00000001/tree-head.statement.json",
        forked_registry / "entries/00000001/tree-head.dsse.json",
        equivocation_path,
        public_key_pem=registry_public,
    )
    assert equivocation["summary"]["status"] == "equivocation"
    assert equivocation["summary"]["same_tree_size"] is True
    assert equivocation["summary"]["same_statement"] is False
    _schema("lurerevoke-registry-head-comparison-v1.schema.json", equivocation)
    verified_equivocation = verify_revocation_head_comparison(
        equivocation_path,
        public_key_pem=registry_public,
    )
    assert verified_equivocation["summary"]["status"] == "equivocation"
    assert (
        main(
            [
                "revoke",
                "registry-verify-head-comparison",
                str(equivocation_path),
                "--registry-public-key",
                str(public_path),
            ]
        )
        == 1
    )
    assert (
        main(
            [
                "revoke",
                "registry-verify",
                str(registry),
                "--registry-public-key",
                str(public_path),
            ]
        )
        == 0
    )
    with pytest.raises(ValueError, match="replayed"):
        append_revocation_registry(
            registry,
            bundles[1],
            registry_public_key_pem=registry_public,
            registry_signing_key_pem=registry_private,
            bundle_public_key_pem=bundle_public,
            registered_at="2026-08-30T13:03:00Z",
        )

    rolled_back = tmp_path / "rolled-back-registry"
    create_revocation_registry(
        rolled_back,
        registry_id="agency-revocation-history",
        system_id="revocation-test-system",
        environment="evaluation",
        receiver_name="receiver-under-test",
        signer_public_key_pem=registry_public,
        created_at="2026-08-30T10:30:00Z",
    )
    append_revocation_registry(
        rolled_back,
        bundles[0],
        registry_public_key_pem=registry_public,
        registry_signing_key_pem=registry_private,
        bundle_public_key_pem=bundle_public,
        registered_at="2026-08-30T11:03:00Z",
    )
    with pytest.raises(ValueError, match="shorter than"):
        verify_revocation_registry(
            rolled_back,
            public_key_pem=registry_public,
            trusted_head_statement=registry / "entries/00000002/tree-head.statement.json",
            trusted_head_dsse=registry / "entries/00000002/tree-head.dsse.json",
        )

    changed = json.loads(second_raw)
    changed["evidence"]["overall_status"] = "fail"
    (registry / "entries/00000002/entry.json").write_bytes(_canonical(changed))
    with pytest.raises(ValueError, match="tree head"):
        verify_revocation_registry(registry, public_key_pem=registry_public)


def test_topology_audit_is_independently_recomputed_and_cli_verified(tmp_path: Path):
    plan = _evaluation(passing=True)["plan"]
    profile = _topology_profile()
    report = {
        "schema": TOPOLOGY_AUDIT_SCHEMA,
        "schema_version": 1,
        "generated_at": "2026-08-30T11:05:00Z",
        "implementation": {"name": "lurebench", "version": "0.11.0"},
        "inputs": {
            "revocation_plan": plan,
            "revocation_plan_sha256": hashlib.sha256(_canonical(plan)).hexdigest(),
            "runtime_profile": profile,
            "runtime_profile_sha256": hashlib.sha256(_canonical(profile)).hexdigest(),
        },
        "results": [
            {
                "mediation_point_id": "tool-gateway",
                "action_types": sorted(ACTIONS),
                "required_sensor_ids": ["runtime-audit"],
                "node_ids": ["policy-node"],
                "replica_count": 1,
                "covered": True,
            }
        ],
        "missing_mediation_point_ids": [],
        "unmapped_nodes": [],
        "summary": {
            "required_mediation_point_count": 1,
            "covered_mediation_point_count": 1,
            "missing_mediation_point_count": 0,
            "unmapped_node_count": 0,
            "mediation_point_coverage_rate": 1.0,
            "verdict": "pass",
        },
        "limitations": list(TOPOLOGY_LIMITATIONS),
    }
    assert validate_revocation_topology_audit(report) == report
    path = tmp_path / "topology-audit.json"
    _write_new(path, _canonical(report))
    assert main(["revoke", "verify-topology", str(path)]) == 0

    changed = json.loads(json.dumps(report))
    changed["summary"]["mediation_point_coverage_rate"] = 0.0
    with pytest.raises(ValueError, match="independently recompute"):
        validate_revocation_topology_audit(changed)


def test_otel_projection_is_independently_recomputed_and_cli_verified(tmp_path: Path):
    projection = _otel_projection()
    assert validate_otel_revocation_projection(projection) == projection
    path = tmp_path / "otel-projection.json"
    _write_new(path, _canonical(projection))
    assert main(["revoke", "verify-otel", str(path)]) == 0

    changed = json.loads(json.dumps(projection))
    changed["inputs"]["otel_log_export_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="independently recompute"):
        validate_otel_revocation_projection(changed)

    body = json.loads(json.dumps(projection))
    body["inputs"]["otel_log_export"]["records"][0]["Body"] = "rejected"
    with pytest.raises(ValueError, match="field allowlist"):
        validate_otel_revocation_projection(body)


def test_deployment_gate_binds_topology_otel_and_signed_evidence(tmp_path: Path):
    projection = _otel_projection()
    evaluation = _evaluation(passing=True)
    assert projection["run"] == evaluation["run"]
    plan = projection["inputs"]["revocation_plan"]
    _require_probe_phase_coverage(plan)
    sparse_plan = json.loads(json.dumps(plan))
    sparse_plan["probes"] = [
        item for item in sparse_plan["probes"] if item["probe_id"] != "probe-propagation"
    ]
    with pytest.raises(ValueError, match="full probe-phase coverage"):
        _require_probe_phase_coverage(sparse_plan)
    contaminated_plan = json.loads(json.dumps(plan))
    next(item for item in contaminated_plan["probes"] if item["probe_id"] == "probe-other")[
        "subject_id"
    ] = "subject-session-a"
    with pytest.raises(ValueError, match="full probe-phase coverage"):
        _require_probe_phase_coverage(contaminated_plan)
    cross_event_plan = json.loads(json.dumps(plan))
    second_event = json.loads(json.dumps(cross_event_plan["events"][0]))
    second_event["event_id"] = "revocation-2"
    second_event["sequence"] = 2
    second_event["occurred_at_ms"] = 2000
    second_event["subject"]["id"] = "subject-session-b"
    second_event.pop("signal_sha256")
    second_event["signal_sha256"] = hashlib.sha256(_canonical(second_event)).hexdigest()
    cross_event_plan["events"].append(second_event)
    next(item for item in cross_event_plan["probes"] if item["probe_id"] == "probe-other")[
        "subject_id"
    ] = "subject-session-b"
    with pytest.raises(ValueError, match="another campaign event"):
        _validate_plan(cross_event_plan)
    weakened_plan = json.loads(json.dumps(plan))
    weakened_plan["acceptance"]["minimum_delivery_coverage_rate"] = 0.5
    with pytest.raises(ValueError, match="weakens strict revocation acceptance"):
        _require_strict_acceptance(weakened_plan)
    profile = _topology_profile()
    topology = {
        "schema": TOPOLOGY_AUDIT_SCHEMA,
        "schema_version": 1,
        "generated_at": "2026-08-30T11:05:00Z",
        "implementation": {"name": "lurebench", "version": "0.11.0"},
        "inputs": {
            "revocation_plan": plan,
            "revocation_plan_sha256": hashlib.sha256(_canonical(plan)).hexdigest(),
            "runtime_profile": profile,
            "runtime_profile_sha256": hashlib.sha256(_canonical(profile)).hexdigest(),
        },
        "results": [
            {
                "mediation_point_id": "tool-gateway",
                "action_types": sorted(ACTIONS),
                "required_sensor_ids": ["runtime-audit"],
                "node_ids": ["policy-node"],
                "replica_count": 1,
                "covered": True,
            }
        ],
        "missing_mediation_point_ids": [],
        "unmapped_nodes": [],
        "summary": {
            "required_mediation_point_count": 1,
            "covered_mediation_point_count": 1,
            "missing_mediation_point_count": 0,
            "unmapped_node_count": 0,
            "mediation_point_coverage_rate": 1.0,
            "verdict": "pass",
        },
        "limitations": list(TOPOLOGY_LIMITATIONS),
    }
    validate_revocation_topology_audit(topology)
    topology_path = tmp_path / "topology.json"
    projection_path = tmp_path / "otel-projection.json"
    evaluation_path = tmp_path / "evaluation.json"
    _write_new(topology_path, _canonical(topology))
    _write_new(projection_path, _canonical(projection))
    _write_new(evaluation_path, _canonical(evaluation))

    private_key, public_key = _keypair()
    expected_key_id = public_key_id(public_key)
    gate_policy = {
        "maximum_allowed_convergence_ms": 500,
        "minimum_run_generated_at": "2026-08-30T11:00:00Z",
        "expected_system_id": "revocation-test-system",
        "expected_environment": "evaluation",
        "expected_receiver_name": "receiver-under-test",
        "expected_receiver_artifact_sha256": "a" * 64,
    }
    public_path = tmp_path / "bundle-public.pem"
    _write_new(public_path, public_key)
    bundle = tmp_path / "revocation.bundle"
    create_revocation_bundle(
        bundle,
        bundle_id="deployment-gate-source",
        environment="evaluation",
        evaluation=evaluation_path,
        signer_public_key_pem=public_key,
        signing_key_pem=private_key,
        created_at="2026-08-30T11:02:00Z",
    )
    gate_path = tmp_path / "deployment-gate.json"
    gate = create_revocation_deployment_gate(
        topology_path,
        projection_path,
        bundle,
        gate_path,
        gate_id="agency-revocation-deployment-gate",
        bundle_public_key_pem=public_key,
        expected_bundle_key_id=expected_key_id,
        **gate_policy,
        created_at="2026-08-30T11:06:00Z",
    )
    assert gate["schema"] == GATE_SCHEMA
    assert gate["overall_status"] == "pass"
    assert len(gate["checks"]) == 10
    assert {item["status"] for item in gate["checks"]} == {"pass"}
    _schema("lurerevoke-deployment-gate-v1.schema.json", gate)
    verified = verify_revocation_deployment_gate(
        gate_path,
        topology_path,
        projection_path,
        bundle,
        bundle_public_key_pem=public_key,
        expected_bundle_key_id=expected_key_id,
        **gate_policy,
    )
    assert verified["overall_status"] == "pass"
    assert (
        main(
            [
                "revoke",
                "verify-gate",
                str(gate_path),
                str(topology_path),
                str(projection_path),
                str(bundle),
                "--bundle-public-key",
                str(public_path),
                "--expected-bundle-key-id",
                expected_key_id,
                "--maximum-allowed-convergence-ms",
                "500",
                "--minimum-run-generated-at",
                "2026-08-30T11:00:00Z",
                "--expected-system-id",
                "revocation-test-system",
                "--expected-environment",
                "evaluation",
                "--expected-receiver-name",
                "receiver-under-test",
                "--expected-receiver-artifact-sha256",
                "a" * 64,
            ]
        )
        == 0
    )

    tampered = json.loads(gate_path.read_text(encoding="utf-8"))
    tampered["contract"]["run_sha256"] = "0" * 64
    tampered_path = tmp_path / "tampered-gate.json"
    _write_new(tampered_path, _canonical(tampered))
    with pytest.raises(ValueError, match="independently recompute"):
        verify_revocation_deployment_gate(
            tampered_path,
            topology_path,
            projection_path,
            bundle,
            bundle_public_key_pem=public_key,
            expected_bundle_key_id=expected_key_id,
            **gate_policy,
        )

    other_topology = json.loads(json.dumps(topology))
    other_topology["inputs"]["revocation_plan"]["plan_id"] = "other-valid-campaign"
    other_topology["inputs"]["revocation_plan_sha256"] = hashlib.sha256(
        _canonical(other_topology["inputs"]["revocation_plan"])
    ).hexdigest()
    validate_revocation_topology_audit(other_topology)
    other_topology_path = tmp_path / "other-valid-topology.json"
    _write_new(other_topology_path, _canonical(other_topology))
    with pytest.raises(ValueError, match="same exact revocation plan"):
        create_revocation_deployment_gate(
            other_topology_path,
            projection_path,
            bundle,
            tmp_path / "mixed-plan-gate.json",
            gate_id="mixed-plan-gate",
            bundle_public_key_pem=public_key,
            expected_bundle_key_id=expected_key_id,
            **gate_policy,
            created_at="2026-08-30T11:06:00Z",
        )

    other_projection = json.loads(json.dumps(projection))
    other_projection["inputs"]["otel_log_export"]["receiver"]["version"] = "2.0.0"
    for record in other_projection["inputs"]["otel_log_export"]["records"]:
        record["Resource"]["service.version"] = "2.0.0"
    other_projection["run"]["implementation"]["version"] = "2.0.0"
    other_projection["inputs"]["otel_log_export_sha256"] = hashlib.sha256(
        _canonical(other_projection["inputs"]["otel_log_export"])
    ).hexdigest()
    other_projection["run_sha256"] = hashlib.sha256(_canonical(other_projection["run"])).hexdigest()
    validate_otel_revocation_projection(other_projection)
    other_projection_path = tmp_path / "other-valid-projection.json"
    _write_new(other_projection_path, _canonical(other_projection))
    with pytest.raises(ValueError, match="same exact run"):
        create_revocation_deployment_gate(
            topology_path,
            other_projection_path,
            bundle,
            tmp_path / "mixed-run-gate.json",
            gate_id="mixed-run-gate",
            bundle_public_key_pem=public_key,
            expected_bundle_key_id=expected_key_id,
            **gate_policy,
            created_at="2026-08-30T11:06:00Z",
        )

    post_hoc_topology = json.loads(json.dumps(topology))
    profile = post_hoc_topology["inputs"]["runtime_profile"]
    profile["created_at"] = "2026-08-30T11:03:00Z"
    profile["permit"]["created_at"] = "2026-08-30T11:03:00Z"
    profile["permit_sha256"] = hashlib.sha256(_canonical(profile["permit"])).hexdigest()
    post_hoc_topology["inputs"]["runtime_profile_sha256"] = hashlib.sha256(
        _canonical(profile)
    ).hexdigest()
    validate_revocation_topology_audit(post_hoc_topology)
    post_hoc_topology_path = tmp_path / "post-hoc-valid-topology.json"
    _write_new(post_hoc_topology_path, _canonical(post_hoc_topology))
    with pytest.raises(ValueError, match="not preregistered"):
        create_revocation_deployment_gate(
            post_hoc_topology_path,
            projection_path,
            bundle,
            tmp_path / "post-hoc-topology-gate.json",
            gate_id="post-hoc-topology-gate",
            bundle_public_key_pem=public_key,
            expected_bundle_key_id=expected_key_id,
            **gate_policy,
            created_at="2026-08-30T11:06:00Z",
        )

    with pytest.raises(ValueError, match="pinned expected key id"):
        create_revocation_deployment_gate(
            topology_path,
            projection_path,
            bundle,
            tmp_path / "wrong-trust-anchor-gate.json",
            gate_id="wrong-trust-anchor-gate",
            bundle_public_key_pem=public_key,
            expected_bundle_key_id="0" * 64,
            **gate_policy,
            created_at="2026-08-30T11:06:00Z",
        )

    with pytest.raises(ValueError, match="exceeds external policy"):
        create_revocation_deployment_gate(
            topology_path,
            projection_path,
            bundle,
            tmp_path / "deadline-policy-gate.json",
            gate_id="deadline-policy-gate",
            bundle_public_key_pem=public_key,
            expected_bundle_key_id=expected_key_id,
            **(gate_policy | {"maximum_allowed_convergence_ms": 499}),
            created_at="2026-08-30T11:06:00Z",
        )

    with pytest.raises(ValueError, match="predates external freshness policy"):
        create_revocation_deployment_gate(
            topology_path,
            projection_path,
            bundle,
            tmp_path / "stale-run-policy-gate.json",
            gate_id="stale-run-policy-gate",
            bundle_public_key_pem=public_key,
            expected_bundle_key_id=expected_key_id,
            **(gate_policy | {"minimum_run_generated_at": "2026-08-30T11:00:01Z"}),
            created_at="2026-08-30T11:06:00Z",
        )

    with pytest.raises(ValueError, match="source identity differs"):
        create_revocation_deployment_gate(
            topology_path,
            projection_path,
            bundle,
            tmp_path / "wrong-deployment-identity-gate.json",
            gate_id="wrong-deployment-identity-gate",
            bundle_public_key_pem=public_key,
            expected_bundle_key_id=expected_key_id,
            **(gate_policy | {"expected_environment": "production"}),
            created_at="2026-08-30T11:06:00Z",
        )
