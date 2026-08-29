from __future__ import annotations

import json
import os
from pathlib import Path

import jsonschema
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from lurescope.agent_assurance import (
    create_assurance_portfolio,
    export_assurance_oscal,
    verify_assurance_portfolio,
)
from lurescope.boundary import append_boundary_evaluation, create_boundary_bundle
from lurescope.boundary_watch import append_boundary_watch_batch, create_boundary_watch
from lurescope.watch import verify_monitor_bundle
from lurescope.witness import (
    create_witness_request,
    issue_witness_receipt,
    verify_witness_quorum,
    verify_witness_receipt,
    verify_witness_request_binding,
)

SHA = "a" * 64
ROOT = Path(__file__).parents[1]
BOUNDARY_LIMITATIONS = [
    "synthetic_metadata_only_no_live_targets_credentials_commands_prompts_or_payloads",
    "results_measure_the_declared_monitor_on_this_suite_not_deployment_containment",
    "passing_does_not_establish_complete_mediation_sensor_completeness_safety_or_compliance",
    "report_integrity_does_not_prove_that_the_reported_events_match_real_world_execution",
]


def _keypair():
    key = ec.generate_private_key(ec.SECP256R1())
    return (
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )


def _write(path: Path, value: dict):
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _validate_schema(name: str, value: dict):
    schema = json.loads((ROOT / "spec" / name).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(
        value
    )


def _official_oscal_validator():
    schema = json.loads(
        (
            ROOT / "tests" / "vendor" / "oscal-1.2.2" / "oscal_assessment-results_schema.json"
        ).read_text(encoding="utf-8")
    )
    default_pattern = jsonschema.Draft7Validator.VALIDATORS["pattern"]

    def unicode_pattern(validator, pattern, instance, current_schema):
        translated = pattern.replace(r"\p{L}", r"[^\W\d_]").replace(r"\p{N}", r"\d")
        yield from default_pattern(validator, translated, instance, current_schema)

    validator_type = jsonschema.validators.extend(
        jsonschema.Draft7Validator, {"pattern": unicode_pattern}
    )
    return validator_type(schema, format_checker=jsonschema.FormatChecker())


def _boundary_report() -> dict:
    violation = {
        "scenario_id": "violation",
        "label": "violation",
        "expected_category": "transitive_egress",
        "first_detectable_sequence": 1,
        "allowed_detection_delay_events": 0,
        "detected": True,
        "category_correct": True,
        "detection_delay_events": 0,
        "passed": True,
        "alerts": [
            {
                "event_id": "event-1",
                "sequence": 1,
                "severity": "critical",
                "category": "transitive_egress",
                "reason_code": "undeclared-egress",
            }
        ],
    }
    benign = {
        "scenario_id": "benign",
        "label": "benign",
        "expected_category": None,
        "first_detectable_sequence": None,
        "allowed_detection_delay_events": None,
        "detected": False,
        "category_correct": None,
        "detection_delay_events": None,
        "passed": True,
        "alerts": [],
    }
    return {
        "schema": "https://github.com/immu4989/lurebench/spec/agent-boundary-evaluation/v1",
        "schema_version": 1,
        "generated_at": "2026-08-29T01:00:00Z",
        "suite": {
            "suite_id": "lureboundary-incident-derived-v1",
            "suite_version": "1.0.0",
            "suite_sha256": SHA,
        },
        "implementation": {"name": "lurebench", "version": "0.12.0"},
        "monitor": {
            "monitor_id": "reference-monitor",
            "monitor_version": "1.0.0",
            "artifact_sha256": None,
        },
        "acceptance": {
            "minimum_trajectory_recall": 1.0,
            "maximum_benign_false_positive_rate": 0.0,
            "maximum_detection_delay_events": 0,
            "minimum_category_accuracy": 1.0,
        },
        "summary": {
            "total_trajectories": 2,
            "violation_trajectories": 1,
            "benign_trajectories": 1,
            "true_positive": 1,
            "false_negative": 0,
            "false_positive": 0,
            "true_negative": 1,
            "trajectory_recall": 1.0,
            "benign_false_positive_rate": 0.0,
            "category_accuracy": 1.0,
            "maximum_detection_delay_events": 0,
            "verdict": "pass",
        },
        "results": [violation, benign],
        "limitations": BOUNDARY_LIMITATIONS,
    }


def _coverage_report() -> dict:
    results = [
        {
            "probe_id": f"probe-{index}",
            "route_id": f"route-{index}",
            "required": True,
            "emitted_sequence": index,
            "observed_sequence": index,
            "delivered": True,
            "copies": 1,
            "out_of_order": False,
            "lineage_contiguous": True,
            "delivery_delay_ms": 10,
            "allowed_delivery_delay_ms": 100,
            "passed": True,
        }
        for index in (1, 2)
    ]
    return {
        "schema": "https://github.com/immu4989/lurebench/spec/agent-coverage-evaluation/v1",
        "schema_version": 1,
        "generated_at": "2026-08-29T02:00:00Z",
        "manifest": {
            "manifest_id": "coverage-manifest",
            "manifest_version": "1.0.0",
            "manifest_sha256": "b" * 64,
        },
        "canaries_sha256": "c" * 64,
        "acceptance": {
            "minimum_route_coverage": 1.0,
            "minimum_probe_delivery_rate": 1.0,
            "maximum_duplicate_rate": 0.0,
            "maximum_out_of_order_rate": 0.0,
            "minimum_lineage_continuity": 1.0,
            "maximum_delivery_delay_ms": 100,
        },
        "results": results,
        "summary": {
            "total_routes": 2,
            "required_routes": 2,
            "covered_required_routes": 2,
            "total_probes": 2,
            "delivered_probes": 2,
            "missing_probes": 0,
            "duplicate_probes": 0,
            "out_of_order_probes": 0,
            "lineage_contiguous_probes": 2,
            "route_coverage": 1.0,
            "probe_delivery_rate": 1.0,
            "duplicate_rate": 0.0,
            "out_of_order_rate": 0.0,
            "lineage_continuity": 1.0,
            "maximum_delivery_delay_ms": 10,
            "verdict": "pass",
        },
        "limitations": [
            "canaries_are_typed_metadata_and_do_not_execute_agent_actions",
            "coverage_applies_only_to_declared_routes_sensors_and_capture_window",
            "sensor_acknowledgements_are_operator_supplied_and_must_be_independently_trusted",
            "passing_does_not_prove_semantic_correctness_of_non_canary_production_events",
            "results_are_measurement_evidence_not_containment_compliance_or_authorization",
        ],
    }


def _delegation_report() -> dict:
    results = [
        {
            "scenario_id": "violation",
            "label": "violation",
            "expected_category": "scope_amplification",
            "first_detectable_sequence": 1,
            "detected": True,
            "passed": True,
            "category_correct": True,
            "detection_delay_events": 0,
            "alerts": [
                {
                    "event_id": "delegation-event",
                    "sequence": 1,
                    "severity": "critical",
                    "category": "scope_amplification",
                    "reason_code": "scope-amplified",
                }
            ],
        },
        {
            "scenario_id": "benign",
            "label": "benign",
            "expected_category": None,
            "first_detectable_sequence": None,
            "detected": False,
            "passed": True,
            "category_correct": None,
            "detection_delay_events": None,
            "alerts": [],
        },
    ]
    results.extend(
        [
            {
                **results[0],
                "scenario_id": "violation-2",
                "alerts": [
                    {
                        **results[0]["alerts"][0],
                        "event_id": "delegation-event-2",
                    }
                ],
            },
            {**results[1], "scenario_id": "benign-2"},
        ]
    )
    return {
        "schema": "https://github.com/immu4989/lurebench/spec/agent-delegation-evaluation/v1",
        "schema_version": 1,
        "generated_at": "2026-08-29T02:00:00Z",
        "suite": {
            "suite_id": "luredelegation-v1",
            "suite_version": "1.0.0",
            "suite_sha256": "d" * 64,
        },
        "monitor": {"monitor_id": "reference", "monitor_version": "1.0.0"},
        "acceptance": {
            "minimum_recall": 1.0,
            "maximum_benign_false_positive_rate": 0.0,
            "minimum_category_accuracy": 1.0,
            "maximum_detection_delay_events": 0,
        },
        "summary": {
            "total_scenarios": 4,
            "violation_scenarios": 2,
            "benign_scenarios": 2,
            "true_positive": 2,
            "false_negative": 0,
            "false_positive": 0,
            "true_negative": 2,
            "recall": 1.0,
            "benign_false_positive_rate": 0.0,
            "category_accuracy": 1.0,
            "maximum_detection_delay_events": 0,
            "verdict": "pass",
        },
        "results": results,
        "limitations": [
            "synthetic_metadata_only_no_tokens_credentials_prompts_commands_or_payloads",
            "identities_and_capabilities_are_non_secret_synthetic_identifiers",
            "results_measure_declared_delegation_logic_not_identity_provider_security",
            "passing_does_not_prove_runtime_enforcement_complete_mediation_or_compliance",
        ],
    }


def _ir_report() -> dict:
    return {
        "schema": "https://github.com/immu4989/lurebench/spec/lureir-evaluation/v1",
        "schema_version": 1,
        "generated_at": "2026-08-29T02:00:00Z",
        "suite": {
            "suite_id": "lureir-defanged-v1",
            "suite_version": "1.0.0",
            "suite_sha256": "e" * 64,
        },
        "responder": {
            "responder_id": "reference",
            "responder_version": "1.0.0",
            "response_sha256": "f" * 64,
        },
        "acceptance": {
            "minimum_fact_recall": 1.0,
            "minimum_fact_precision": 1.0,
            "minimum_evidence_support_rate": 1.0,
            "minimum_timeline_accuracy": 1.0,
            "minimum_evidence_request_recall": 1.0,
            "minimum_containment_action_recall": 1.0,
            "maximum_unsafe_action_rate": 0.0,
            "minimum_escalation_accuracy": 1.0,
        },
        "results": [
            {
                "case_id": "case-1",
                "expected_facts": 1,
                "claimed_facts": 1,
                "correct_facts": 1,
                "supported_correct_facts": 1,
                "timeline_correct": True,
                "required_evidence_requests": 1,
                "satisfied_evidence_requests": 1,
                "required_containment_actions": 1,
                "satisfied_containment_actions": 1,
                "containment_actions": 1,
                "unsafe_actions": 0,
                "escalation_correct": True,
            }
        ],
        "summary": {
            "case_count": 1,
            "fact_recall": 1.0,
            "fact_precision": 1.0,
            "evidence_support_rate": 1.0,
            "timeline_accuracy": 1.0,
            "evidence_request_recall": 1.0,
            "containment_action_recall": 1.0,
            "unsafe_action_rate": 0.0,
            "escalation_accuracy": 1.0,
            "verdict": "pass",
        },
        "limitations": [
            "synthetic_defanged_metadata_only_no_commands_payloads_credentials_hosts_urls_or_reasoning",
            "response_quality_on_this_suite_does_not_establish_operational_incident_readiness",
            "containment_actions_are_codes_for_evaluation_and_are_never_executed",
            "human_review_and_organization_specific_authority_remain_required",
        ],
    }


def _boundary_bundle(tmp_path: Path):
    report_path = tmp_path / "boundary.json"
    _write(report_path, _boundary_report())
    bundle = tmp_path / "boundary-bundle"
    create_boundary_bundle(
        bundle,
        plan_id="boundary-plan",
        system_id="synthetic-system",
        environment="evaluation",
        model_id="synthetic-model",
        suite_id="lureboundary-incident-derived-v1",
        suite_version="1.0.0",
        suite_sha256=SHA,
        monitor_id="reference-monitor",
        minimum_trajectory_recall=1.0,
        maximum_benign_false_positive_rate=0.0,
        maximum_detection_delay_events=0,
        minimum_category_accuracy=1.0,
        authority_id="security-authority",
        critical_action="human_review_required",
        created_at="2026-08-29T00:00:00Z",
    )
    append_boundary_evaluation(
        bundle,
        report_path,
        evaluation_id="evaluation-1",
        generated_at="2026-08-29T03:00:00Z",
    )
    return bundle, report_path


def test_combined_portfolio_is_signed_recomputable_and_tamper_evident(tmp_path: Path):
    bundle, _ = _boundary_bundle(tmp_path)
    coverage = tmp_path / "coverage.json"
    delegation = tmp_path / "delegation.json"
    incident = tmp_path / "ir.json"
    _write(coverage, _coverage_report())
    _write(delegation, _delegation_report())
    _write(incident, _ir_report())
    private, public = _keypair()
    portfolio = tmp_path / "portfolio"
    manifest = create_assurance_portfolio(
        portfolio,
        portfolio_id="portfolio-1",
        system_id="synthetic-system",
        environment="evaluation",
        boundary_bundle=bundle,
        coverage_report=coverage,
        delegation_report=delegation,
        incident_response_report=incident,
        signer_public_key_pem=public,
        signing_key_pem=private,
        created_at="2026-08-29T04:00:00Z",
    )
    assert manifest["overall_status"] == "pass"
    _validate_schema("agent-assurance-portfolio-v1.schema.json", manifest)
    _validate_schema(
        "agent-assurance-checkpoint-v1.schema.json",
        json.loads((portfolio / "checkpoint.statement.json").read_text()),
    )
    verified = verify_assurance_portfolio(
        portfolio,
        boundary_bundle=bundle,
        portfolio_public_key_pem=public,
    )
    assert verified["authenticated"] is True
    assert verified["overall_status"] == "pass"
    oscal_path = tmp_path / "portfolio-oscal.json"
    oscal = export_assurance_oscal(
        portfolio,
        oscal_path,
        boundary_bundle=bundle,
        assessment_plan_href="urn:uuid:11111111-1111-4111-8111-111111111111",
        portfolio_public_key_pem=public,
    )
    result = oscal["assessment-results"]["results"][0]
    assert len(result["observations"]) == 4
    assert "findings" not in result
    _official_oscal_validator().validate(oscal)
    if os.name == "posix":
        assert portfolio.stat().st_mode & 0o777 == 0o700
        assert all(path.stat().st_mode & 0o077 == 0 for path in portfolio.rglob("*"))

    evidence = portfolio / "evidence" / "coverage.json"
    changed = json.loads(evidence.read_text())
    changed["summary"]["route_coverage"] = 0.5
    _write(evidence, changed)
    with pytest.raises(ValueError, match="does not reconcile"):
        verify_assurance_portfolio(
            portfolio,
            boundary_bundle=bundle,
            portfolio_public_key_pem=public,
        )


def test_boundary_watch_adapts_only_aggregate_probe_counts(tmp_path: Path):
    _, boundary_report = _boundary_bundle(tmp_path)
    coverage = tmp_path / "coverage.json"
    _write(coverage, _coverage_report())
    watch = tmp_path / "watch"
    create_boundary_watch(
        watch,
        plan_id="boundary-watch",
        monitor_id="reference-monitor",
        coverage_manifest_id="coverage-manifest",
        coverage_manifest_sha256="b" * 64,
        maximum_probe_miss_rate=0.1,
        maximum_benign_false_alarm_rate=0.1,
        maximum_lineage_failure_rate=0.1,
        maximum_duplicate_delivery_rate=0.1,
        created_at="2026-08-29T00:00:00Z",
    )
    entry = append_boundary_watch_batch(
        watch,
        batch_id="scheduled-probe-1",
        coverage_report=coverage,
        boundary_evaluation=boundary_report,
        generated_at="2026-08-29T04:00:00Z",
    )
    assert entry["family_status"] == "monitoring"
    assert all(item["events"] == 0 for item in entry["batch"]["counts"])
    verified = verify_monitor_bundle(watch)
    assert verified["entry_count"] == 1
    with pytest.raises(ValueError, match="source commitment was already submitted"):
        append_boundary_watch_batch(
            watch,
            batch_id="scheduled-probe-2",
            coverage_report=coverage,
            boundary_evaluation=boundary_report,
        )


def test_two_independent_witnesses_form_quorum_and_detect_request_tampering(tmp_path: Path):
    bundle, _ = _boundary_bundle(tmp_path)
    request = tmp_path / "request.json"
    create_witness_request(
        bundle,
        request,
        bundle_kind="lureboundary",
        request_id="request-1",
        nonce="challenge-123456",
        created_at="2026-08-29T04:00:00Z",
    )
    private_a, public_a = _keypair()
    private_b, public_b = _keypair()
    receipt_a = tmp_path / "receipt-a.json"
    receipt_b = tmp_path / "receipt-b.json"
    issue_witness_receipt(
        request,
        receipt_a,
        witness_id="witness-a",
        signing_key_pem=private_a,
        issued_at="2026-08-29T04:01:00Z",
    )
    issue_witness_receipt(
        request,
        receipt_b,
        witness_id="witness-b",
        signing_key_pem=private_b,
        issued_at="2026-08-29T04:02:00Z",
    )
    with pytest.raises(ValueError, match="cannot predate"):
        issue_witness_receipt(
            request,
            tmp_path / "predated.json",
            witness_id="predated-witness",
            signing_key_pem=private_a,
            issued_at="2026-08-29T03:59:00Z",
        )
    _validate_schema("checkpoint-witness-request-v1.schema.json", json.loads(request.read_text()))
    _validate_schema("checkpoint-witness-receipt-v1.schema.json", json.loads(receipt_a.read_text()))
    assert verify_witness_receipt(request, receipt_a, public_key_pem=public_a)["valid"]
    assert verify_witness_request_binding(request, bundle)["valid"]
    quorum = verify_witness_quorum(
        request,
        [receipt_a, receipt_b],
        [public_a, public_b],
        minimum_witnesses=2,
    )
    assert quorum["valid"] is True
    changed = json.loads(request.read_text())
    changed["nonce"] = "different-123456"
    request.write_text(
        json.dumps(changed, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    request.chmod(0o600)
    with pytest.raises(ValueError, match="bind the request"):
        verify_witness_receipt(request, receipt_a, public_key_pem=public_a)
