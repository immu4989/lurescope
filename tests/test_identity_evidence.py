from __future__ import annotations

import hashlib
import json
from pathlib import Path

import jsonschema
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from referencing import Registry, Resource

from lurescope.artifact import (
    CAMPAIGN_LIMITATIONS as ARTIFACT_CAMPAIGN_LIMITATIONS,
)
from lurescope.artifact import (
    IN_TOTO_STATEMENT_TYPE,
    SLSA_PREDICATE_TYPE,
    create_artifact_verification,
    derive_artifact_evaluation,
    derive_artifact_plan,
    reference_artifact_observation,
)
from lurescope.boundary import public_key_id
from lurescope.cli import main
from lurescope.identity import (
    BUNDLE_LIMITATIONS,
    BUNDLE_SCHEMA,
    EVALUATION_LIMITATIONS,
    EVALUATION_SCHEMA,
    INTERPRETATION,
    PLAN_LIMITATIONS,
    PLAN_SCHEMA,
    RUN_LIMITATIONS,
    RUN_SCHEMA,
    _evaluation_value,
    create_identity_bundle,
    export_identity_oscal,
    export_identity_sarif,
    validate_identity_evaluation,
    verify_identity_bundle,
)
from lurescope.identity_campaign import (
    CAMPAIGN_LIMITATIONS,
    CAMPAIGN_SCHEMA,
    create_identity_campaign_verification,
    derive_identity_campaign_plan,
)
from lurescope.identity_gate import (
    GATE_LIMITATIONS,
    GATE_SCHEMA,
    create_identity_deployment_gate,
    verify_identity_deployment_gate,
)
from lurescope.identity_otel import (
    ACCESS_EVENT,
    EXPORT_LIMITATIONS,
    LIFECYCLE_EVENT,
    _expected_projection,
    load_identity_otel_projection,
    validate_identity_otel_projection,
)
from lurescope.identity_topology import (
    _topology_value,
    validate_identity_topology_audit,
)
from lurescope.permit import PERMIT_LIMITATIONS, PERMIT_SCHEMA, _canonical, _write_new
from lurescope.runtime import PROFILE_LIMITATIONS, PROFILE_SCHEMA

ROOT = Path(__file__).parents[1]
RUNTIME_ACTIONS = [
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


def _digest(value: dict) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


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


def _identity_otel_projection(evaluation: dict) -> dict:
    plan = evaluation["plan"]
    run = evaluation["run"]
    origin = 1_788_393_600_000_000_000
    receiver = run["implementation"]
    probes = {item["probe_id"]: item for item in plan["probes"]}
    records = []
    for observation in run["event_observations"]:
        index = len(records) + 1
        timestamp = origin + observation["received_at_ms"] * 1_000_000
        records.append(
            {
                "Timestamp": timestamp,
                "ObservedTimestamp": timestamp + 10_000,
                "TraceId": f"{index:032x}",
                "SpanId": f"{index:016x}",
                "EventName": LIFECYCLE_EVENT,
                "Resource": {
                    "service.name": receiver["name"],
                    "service.instance.id": observation["node_id"],
                    "service.version": receiver["version"],
                },
                "Attributes": {
                    "observation_id": observation["observation_id"],
                    "event_id": observation["event_id"],
                    "node_id": observation["node_id"],
                    "event_sha256": observation["event_sha256"],
                    "disposition": observation["disposition"],
                },
            }
        )
    for observation in run["access_observations"]:
        index = len(records) + 1
        probe = probes[observation["probe_id"]]
        timestamp = origin + probe["attempted_at_ms"] * 1_000_000
        records.append(
            {
                "Timestamp": timestamp,
                "ObservedTimestamp": timestamp + 10_000,
                "TraceId": f"{index:032x}",
                "SpanId": f"{index:016x}",
                "EventName": ACCESS_EVENT,
                "Resource": {
                    "service.name": receiver["name"],
                    "service.instance.id": probe["node_id"],
                    "service.version": receiver["version"],
                },
                "Attributes": dict(observation),
            }
        )
    export = {
        "schema": "https://github.com/immu4989/lurebench/spec/lureidentity-otel-log-export/v1",
        "schema_version": 1,
        "export_id": "identity-otel-export",
        "generated_at": run["generated_at"],
        "time_origin_unix_nano": origin,
        "receiver": dict(receiver),
        "records": records,
        "limitations": list(EXPORT_LIMITATIONS),
    }
    return _expected_projection(
        plan,
        export,
        run_id=run["run_id"],
        producer_version=evaluation["implementation"]["version"],
    )


def _evaluation() -> dict:
    event = {
        "event_id": "delegation-off",
        "sequence": 1,
        "occurred_at_ms": 1_000,
        "event_type": "delegation_revoked",
        "target_principal_id": None,
        "target_edge_id": "delegation-alpha",
        "required_cut_actor_ids": ["agent-alpha", "workload-alpha"],
        "required_preserve_actor_ids": ["workload-control"],
        "source_event_sha256": "1" * 64,
    }
    event["event_sha256"] = _digest(event)
    plan = {
        "schema": PLAN_SCHEMA,
        "schema_version": 1,
        "plan_id": "identity-interoperability-vector",
        "created_at": "2026-09-03T00:00:00Z",
        "system_id": "synthetic-agent-system",
        "directory": {
            "issuer_id": "synthetic-directory",
            "tenant_id": "tenant-a",
            "profile": "ietf-scim-rfc7643-lifecycle-metadata-projection",
            "authentication_boundary": "externally_authenticated_and_authorized",
        },
        "principals": [
            {"principal_id": "group-ops", "kind": "group", "active": True, "spiffe_id": None},
            {
                "principal_id": "human-alice",
                "kind": "human",
                "active": True,
                "spiffe_id": None,
            },
            {
                "principal_id": "agent-alpha",
                "kind": "agent",
                "active": True,
                "spiffe_id": None,
            },
            {
                "principal_id": "workload-alpha",
                "kind": "workload",
                "active": True,
                "spiffe_id": "spiffe://example.invalid/agents/alpha",
            },
            {
                "principal_id": "workload-control",
                "kind": "workload",
                "active": True,
                "spiffe_id": "spiffe://example.invalid/agents/control",
            },
        ],
        "authority_edges": [
            {
                "edge_id": "membership-alice",
                "source_id": "group-ops",
                "target_id": "human-alice",
                "relationship": "member_of",
            },
            {
                "edge_id": "delegation-alpha",
                "source_id": "human-alice",
                "target_id": "agent-alpha",
                "relationship": "delegates_to",
            },
            {
                "edge_id": "runtime-alpha",
                "source_id": "agent-alpha",
                "target_id": "workload-alpha",
                "relationship": "runs_as",
            },
        ],
        "grants": [
            {
                "grant_id": "ops-read",
                "principal_id": "group-ops",
                "resource_id": "mock-registry",
                "action": "read",
            },
            {
                "grant_id": "control-read",
                "principal_id": "workload-control",
                "resource_id": "mock-registry",
                "action": "read",
            },
        ],
        "nodes": [{"node_id": "east-policy", "enforcement_point_id": "tool-gateway"}],
        "events": [event],
        "probes": [
            {
                "probe_id": "agent-before",
                "event_id": "delegation-off",
                "node_id": "east-policy",
                "attempted_at_ms": 950,
                "actor_id": "agent-alpha",
                "resource_id": "mock-registry",
                "action": "read",
            },
            {
                "probe_id": "agent-after",
                "event_id": "delegation-off",
                "node_id": "east-policy",
                "attempted_at_ms": 1_600,
                "actor_id": "agent-alpha",
                "resource_id": "mock-registry",
                "action": "read",
            },
            {
                "probe_id": "workload-before",
                "event_id": "delegation-off",
                "node_id": "east-policy",
                "attempted_at_ms": 950,
                "actor_id": "workload-alpha",
                "resource_id": "mock-registry",
                "action": "read",
            },
            {
                "probe_id": "workload-after",
                "event_id": "delegation-off",
                "node_id": "east-policy",
                "attempted_at_ms": 1_600,
                "actor_id": "workload-alpha",
                "resource_id": "mock-registry",
                "action": "read",
            },
            {
                "probe_id": "control-after",
                "event_id": "delegation-off",
                "node_id": "east-policy",
                "attempted_at_ms": 1_600,
                "actor_id": "workload-control",
                "resource_id": "mock-registry",
                "action": "read",
            },
        ],
        "acceptance": {
            "maximum_convergence_ms": 500,
            "maximum_deadline_miss_count": 0,
            "maximum_post_deadline_stale_allow_count": 0,
            "maximum_collateral_block_count": 0,
            "minimum_delivery_coverage_rate": 1.0,
            "minimum_cut_recall": 1.0,
            "minimum_pre_event_allow_rate": 1.0,
            "minimum_preserved_allow_rate": 1.0,
            "minimum_signal_disposition_accuracy": 1.0,
        },
        "limitations": list(PLAN_LIMITATIONS),
    }
    run = {
        "schema": RUN_SCHEMA,
        "schema_version": 1,
        "run_id": "interoperability-run",
        "generated_at": "2026-09-03T12:00:00Z",
        "implementation": {
            "name": "independent-receiver",
            "version": "1.0.0",
            "artifact_sha256": "2" * 64,
        },
        "plan_sha256": _digest(plan),
        "event_observations": [
            {
                "observation_id": "event-applied",
                "event_id": "delegation-off",
                "node_id": "east-policy",
                "received_at_ms": 1_100,
                "event_sha256": event["event_sha256"],
                "disposition": "applied",
            }
        ],
        "access_observations": [
            {"probe_id": "agent-before", "decision": "allow", "reason_code": "authority_active"},
            {"probe_id": "agent-after", "decision": "block", "reason_code": "authority_path_cut"},
            {
                "probe_id": "workload-before",
                "decision": "allow",
                "reason_code": "authority_active",
            },
            {
                "probe_id": "workload-after",
                "decision": "block",
                "reason_code": "authority_path_cut",
            },
            {
                "probe_id": "control-after",
                "decision": "allow",
                "reason_code": "authority_preserved",
            },
        ],
        "limitations": list(RUN_LIMITATIONS),
    }
    report = {
        "schema": EVALUATION_SCHEMA,
        "schema_version": 1,
        "generated_at": "2026-09-03T12:01:00Z",
        "implementation": {"name": "lurebench", "version": "0.11.0"},
        "plan": plan,
        "plan_sha256": _digest(plan),
        "run": run,
        "run_sha256": _digest(run),
        "summary": {
            "principal_count": 5,
            "authority_edge_count": 3,
            "grant_count": 2,
            "event_count": 1,
            "node_count": 1,
            "affected_authorization_count": 2,
            "required_delivery_count": 1,
            "applied_delivery_count": 1,
            "delivery_coverage_rate": 1.0,
            "maximum_convergence_ms": 100,
            "p95_convergence_ms": 100,
            "deadline_miss_count": 0,
            "post_deadline_stale_allow_count": 0,
            "collateral_block_count": 0,
            "cut_recall": 1.0,
            "pre_event_allow_rate": 1.0,
            "preserved_allow_rate": 1.0,
            "signal_disposition_accuracy": 1.0,
            "incorrect_decision_count": 0,
            "incorrect_reason_count": 0,
            "verdict": "pass",
        },
        "event_results": [
            {
                "event_id": "delegation-off",
                "event_type": "delegation_revoked",
                "affected_authorization_count": 2,
                "affected_authorizations": [
                    {"actor_id": "agent-alpha", "resource_id": "mock-registry", "action": "read"},
                    {
                        "actor_id": "workload-alpha",
                        "resource_id": "mock-registry",
                        "action": "read",
                    },
                ],
            }
        ],
        "delivery_results": [
            {
                "event_id": "delegation-off",
                "node_id": "east-policy",
                "applied_at_ms": 1_100,
                "convergence_ms": 100,
                "deadline_met": True,
            }
        ],
        "probe_results": [
            {
                "probe_id": "agent-before",
                "event_id": "delegation-off",
                "node_id": "east-policy",
                "actor_id": "agent-alpha",
                "resource_id": "mock-registry",
                "action": "read",
                "phase": "pre_event",
                "expected_decision": "allow",
                "submitted_decision": "allow",
                "expected_reason_code": "authority_active",
                "submitted_reason_code": "authority_active",
                "classification": "correct",
            },
            {
                "probe_id": "agent-after",
                "event_id": "delegation-off",
                "node_id": "east-policy",
                "actor_id": "agent-alpha",
                "resource_id": "mock-registry",
                "action": "read",
                "phase": "post_deadline",
                "expected_decision": "block",
                "submitted_decision": "block",
                "expected_reason_code": "authority_path_cut",
                "submitted_reason_code": "authority_path_cut",
                "classification": "correct",
            },
            {
                "probe_id": "workload-before",
                "event_id": "delegation-off",
                "node_id": "east-policy",
                "actor_id": "workload-alpha",
                "resource_id": "mock-registry",
                "action": "read",
                "phase": "pre_event",
                "expected_decision": "allow",
                "submitted_decision": "allow",
                "expected_reason_code": "authority_active",
                "submitted_reason_code": "authority_active",
                "classification": "correct",
            },
            {
                "probe_id": "workload-after",
                "event_id": "delegation-off",
                "node_id": "east-policy",
                "actor_id": "workload-alpha",
                "resource_id": "mock-registry",
                "action": "read",
                "phase": "post_deadline",
                "expected_decision": "block",
                "submitted_decision": "block",
                "expected_reason_code": "authority_path_cut",
                "submitted_reason_code": "authority_path_cut",
                "classification": "correct",
            },
            {
                "probe_id": "control-after",
                "event_id": "delegation-off",
                "node_id": "east-policy",
                "actor_id": "workload-control",
                "resource_id": "mock-registry",
                "action": "read",
                "phase": "unrelated_control",
                "expected_decision": "allow",
                "submitted_decision": "allow",
                "expected_reason_code": "authority_preserved",
                "submitted_reason_code": "authority_preserved",
                "classification": "correct",
            },
        ],
        "limitations": list(EVALUATION_LIMITATIONS),
    }
    return report


def _deployment_evaluation() -> dict:
    source = _evaluation()
    base_plan = source["plan"]
    for principal in base_plan["principals"]:
        if principal["kind"] == "workload":
            principal["spiffe_id"] = principal["spiffe_id"].replace(
                "example.invalid", "example.gov"
            )
    campaign = _identity_campaign(base_plan)
    plan = derive_identity_campaign_plan(campaign)
    event = plan["events"][0]
    access = []
    for probe in plan["probes"]:
        if probe["actor_id"] in event["required_preserve_actor_ids"]:
            decision, reason = "allow", "authority_preserved"
        elif probe["attempted_at_ms"] < event["occurred_at_ms"]:
            decision, reason = "allow", "authority_active"
        elif probe["attempted_at_ms"] < 1_100:
            decision, reason = "allow", "lifecycle_event_pending"
        else:
            decision, reason = "block", "authority_path_cut"
        access.append(
            {"probe_id": probe["probe_id"], "decision": decision, "reason_code": reason}
        )
    run = {
        "schema": RUN_SCHEMA,
        "schema_version": 1,
        "run_id": "interoperability-run",
        "generated_at": "2026-09-03T12:00:00Z",
        "implementation": {
            "name": "independent-receiver",
            "version": "1.0.0",
            "artifact_sha256": "2" * 64,
        },
        "plan_sha256": _digest(plan),
        "event_observations": [
            {
                "observation_id": "event-applied",
                "event_id": event["event_id"],
                "node_id": plan["nodes"][0]["node_id"],
                "received_at_ms": 1_100,
                "event_sha256": event["event_sha256"],
                "disposition": "applied",
            }
        ],
        "access_observations": access,
        "limitations": list(RUN_LIMITATIONS),
    }
    return _evaluation_value(
        {
            "generated_at": "2026-09-03T12:01:00Z",
            "implementation": {"name": "lurebench", "version": "0.11.0"},
            "plan": plan,
            "run": run,
        }
    )


def _identity_campaign(plan: dict) -> dict:
    return {
        "schema": CAMPAIGN_SCHEMA,
        "schema_version": 1,
        "campaign_id": plan["plan_id"],
        "created_at": plan["created_at"],
        "system_id": plan["system_id"],
        "directory": plan["directory"],
        "principals": plan["principals"],
        "authority_edges": plan["authority_edges"],
        "grants": plan["grants"],
        "nodes": plan["nodes"],
        "events": [
            {
                key: event[key]
                for key in (
                    "event_id",
                    "occurred_at_ms",
                    "event_type",
                    "target_principal_id",
                    "target_edge_id",
                    "source_event_sha256",
                )
            }
            for event in plan["events"]
        ],
        "acceptance": plan["acceptance"],
        "probe_schedule": {
            "pre_event_offset_ms": 50,
            "propagation_probe_offset_ms": 50,
            "post_deadline_offset_ms": 100,
        },
        "limitations": list(CAMPAIGN_LIMITATIONS),
    }


def _artifact_campaign(identity_plan: dict) -> dict:
    def digest(label: str) -> str:
        return hashlib.sha256(label.encode("utf-8")).hexdigest()

    workloads = []
    node_ids = sorted(item["node_id"] for item in identity_plan["nodes"])
    for principal in identity_plan["principals"]:
        if principal["kind"] != "workload" or principal["active"] is not True:
            continue
        workload_id = principal["principal_id"]
        artifact_specs = [
            ("ai-bom", "ai_sbom", "application/spdx+json", None, None),
            (
                "container",
                "container_image",
                "application/vnd.oci.image.manifest.v1+json",
                f"pkg:oci/example/{workload_id}@sha256:{digest(f'{workload_id}-container')}",
                None,
            ),
            (
                "model",
                "model_weights",
                "application/vnd.safetensors",
                f"pkg:huggingface/example/{workload_id}@0123456789abcdef",
                "safetensors",
            ),
            (
                "policy",
                "policy_bundle",
                "application/vnd.openpolicyagent.bundle",
                f"pkg:generic/example/{workload_id}-policy@1.0.0",
                None,
            ),
        ]
        artifacts = [
            {
                "artifact_id": f"{workload_id}-{suffix}",
                "role": role,
                "sha256": digest(f"{workload_id}-{suffix}"),
                "media_type": media_type,
                "package_url": package_url,
                "model_serialization": serialization_name,
                "model_embedded_code": False,
                "remote_code_required": False,
            }
            for suffix, role, media_type, package_url, serialization_name in artifact_specs
        ]
        by_role = {item["role"]: item for item in artifacts}
        attestations = []
        for role in ("container_image", "model_weights", "policy_bundle"):
            artifact = by_role[role]
            attestations.append(
                {
                    "attestation_id": f"{artifact['artifact_id']}-provenance",
                    "subject_artifact_id": artifact["artifact_id"],
                    "subject_sha256": artifact["sha256"],
                    "statement_sha256": digest(f"{artifact['artifact_id']}-statement"),
                    "statement_type": IN_TOTO_STATEMENT_TYPE,
                    "predicate_type": SLSA_PREDICATE_TYPE,
                    "builder_id": "urn:example:trusted-builder",
                    "build_type": "urn:example:hermetic-build:v1",
                    "source_sha256": digest(f"{artifact['artifact_id']}-source"),
                }
            )
        workloads.append(
            {
                "workload_principal_id": workload_id,
                "node_ids": node_ids,
                "artifacts": artifacts,
                "attestations": attestations,
                "ai_bom": {
                    "artifact_id": by_role["ai_sbom"]["artifact_id"],
                    "format": "spdx-3.0.1",
                    "document_sha256": by_role["ai_sbom"]["sha256"],
                    "subject_artifact_ids": [
                        by_role[role]["artifact_id"]
                        for role in ("container_image", "model_weights", "policy_bundle")
                    ],
                },
            }
        )
    return {
        "schema": "https://github.com/immu4989/lurebench/spec/lureartifact-campaign-v1",
        "schema_version": 1,
        "campaign_id": "identity-gate-artifacts",
        "created_at": "2026-09-03T12:00:30Z",
        "identity_plan_sha256": _digest(identity_plan),
        "workloads": workloads,
        "policy": {
            "required_artifact_roles": [
                "ai_sbom",
                "container_image",
                "model_weights",
                "policy_bundle",
            ],
            "provenance_required_for_roles": [
                "container_image",
                "model_weights",
                "policy_bundle",
            ],
            "sbom_subject_roles": [
                "container_image",
                "model_weights",
                "policy_bundle",
            ],
            "allowed_model_serializations": ["safetensors"],
            "approved_builder_ids": ["urn:example:trusted-builder"],
            "model_embedded_code_allowed": False,
            "remote_model_code_allowed": False,
        },
        "standards": {
            "statement_type": IN_TOTO_STATEMENT_TYPE,
            "provenance_predicate_type": SLSA_PREDICATE_TYPE,
            "supported_ai_bom_formats": [
                "cyclonedx-1.6",
                "cyclonedx-1.7",
                "spdx-3.0.1",
            ],
        },
        "limitations": list(ARTIFACT_CAMPAIGN_LIMITATIONS),
    }


def _artifact_verification(
    tmp_path: Path,
    identity_campaign_verification: Path,
    identity_plan: dict,
    *,
    prefix: str = "",
    fail_model: bool = False,
) -> Path:
    campaign = _artifact_campaign(identity_plan)
    plan = derive_artifact_plan(identity_plan, campaign)
    observation = reference_artifact_observation(
        plan,
        observation_id="identity-gate-artifact-observation",
        captured_at="2026-09-03T12:01:10Z",
    )
    if fail_model:
        deployment = observation["deployments"][0]
        model = next(
            item for item in deployment["artifacts"] if item["role"] == "model_weights"
        )
        model["sha256"] = "0" * 64
        model["model_serialization"] = "pickle"
        provenance = next(
            item
            for item in deployment["attestations"]
            if item["subject_artifact_id"] == model["artifact_id"]
        )
        provenance["subject_sha256"] = model["sha256"]
    evaluation = derive_artifact_evaluation(
        plan, observation, generated_at="2026-09-03T12:01:20Z"
    )
    campaign_path = tmp_path / f"{prefix}artifact-campaign.json"
    plan_path = tmp_path / f"{prefix}artifact-plan.json"
    observation_path = tmp_path / f"{prefix}artifact-observation.json"
    evaluation_path = tmp_path / f"{prefix}artifact-evaluation.json"
    output = tmp_path / f"{prefix}artifact-verification.json"
    for path, value in (
        (campaign_path, campaign),
        (plan_path, plan),
        (observation_path, observation),
        (evaluation_path, evaluation),
    ):
        _write_new(path, _canonical(value))
    create_artifact_verification(
        identity_campaign_verification,
        campaign_path,
        plan_path,
        observation_path,
        evaluation_path,
        output,
        verified_at="2026-09-03T12:02:30Z",
    )
    return output


def _identity_runtime_profile() -> dict:
    permit = {
        "schema": PERMIT_SCHEMA,
        "schema_version": 1,
        "permit_id": "identity-runtime-permit",
        "permit_version": "1.0.0",
        "system_id": "synthetic-agent-system",
        "run_id": "identity-runtime-run",
        "created_at": "2026-09-03T00:00:00Z",
        "subject": {
            "agent_id": "agent-alpha",
            "tenant_id": "tenant-a",
            "workload_identity": "workload-alpha",
        },
        "authorization": {
            "allowed_action_types": RUNTIME_ACTIONS,
            "allowed_resource_ids": ["mock-registry"],
            "allowed_capabilities": ["read"],
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
            "maximum_duration_ms": 60_000,
            "maximum_consecutive_failures": 3,
        },
        "monitoring": {"required_sensor_ids": ["identity-audit"]},
        "stop": {
            "shutdown_deadline_ms": 5_000,
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
        "profile_id": "identity-runtime-profile",
        "profile_version": "1.0.0",
        "created_at": "2026-09-03T00:30:00Z",
        "permit": permit,
        "permit_sha256": _digest(permit),
        "identity": {
            "allowed_spiffe_trust_domains": ["example.gov"],
            "require_workload_identity": True,
            "human_authority_action_types": ["high_impact_change"],
            "minimum_policy_generation": 2,
            "maximum_request_age_ms": 60_000,
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
                "action_types": RUNTIME_ACTIONS,
                "required_sensor_ids": ["identity-audit"],
            }
        ],
        "receipt_policy": {
            "chain_required": True,
            "replay_protection_required": True,
            "maximum_clock_skew_ms": 5_000,
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


def test_hand_computed_identity_vector_recomputes_without_lurebench_import():
    report = _evaluation()
    assert validate_identity_evaluation(report) == report
    verifier_source = Path("lurescope/identity.py").read_text(encoding="utf-8")
    assert "from lurebench" not in verifier_source
    assert "import lurebench" not in verifier_source

    changed = json.loads(json.dumps(report))
    changed["summary"]["affected_authorization_count"] = 1
    with pytest.raises(ValueError, match="independently recompute"):
        validate_identity_evaluation(changed)

    changed = json.loads(json.dumps(report))
    changed["plan"]["authority_edges"].append(
        {
            "edge_id": "alternate-alpha",
            "source_id": "human-alice",
            "target_id": "agent-alpha",
            "relationship": "delegates_to",
        }
    )
    with pytest.raises(ValueError, match="duplicate relationship"):
        validate_identity_evaluation(changed)


def test_signed_identity_bundle_schemas_tamper_exports_and_cli(tmp_path: Path):
    private, public = _keypair()
    source = tmp_path / "identity.json"
    _write_new(source, _canonical(_evaluation()))
    bundle = tmp_path / "identity.bundle"
    manifest = create_identity_bundle(
        bundle,
        bundle_id="identity-signed",
        environment="evaluation",
        evaluation=source,
        signer_public_key_pem=public,
        signing_key_pem=private,
        created_at="2026-09-03T12:02:00Z",
    )
    verified = verify_identity_bundle(bundle, public_key_pem=public)
    assert verified["authenticated"] is True
    assert verified["overall_status"] == "pass"
    assert manifest["schema"] == BUNDLE_SCHEMA
    assert manifest["limitations"] == BUNDLE_LIMITATIONS
    assert manifest["interpretation_boundary"] == INTERPRETATION
    _schema("lureidentity-evidence-bundle-v1.schema.json", manifest)
    _schema(
        "lureidentity-evidence-checkpoint-v1.schema.json",
        json.loads((bundle / "checkpoint.statement.json").read_text(encoding="utf-8")),
    )
    _schema(
        "lureidentity-evidence-dsse-v1.schema.json",
        json.loads((bundle / "checkpoint.dsse.json").read_text(encoding="utf-8")),
    )

    oscal = export_identity_oscal(
        bundle,
        tmp_path / "identity.oscal.json",
        assessment_plan_href="urn:example:assessment-plan:identity",
        public_key_pem=public,
    )
    _official_oscal_validator().validate(oscal)
    assert "findings" not in oscal["assessment-results"]["results"][0]
    sarif = export_identity_sarif(
        bundle, tmp_path / "identity.sarif.json", public_key_pem=public
    )
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"] == []

    public_path = tmp_path / "public.pem"
    _write_new(public_path, public)
    assert main(["identity", "verify", str(bundle), "--public-key", str(public_path)]) == 0

    evidence = bundle / "evidence/identity-evaluation.json"
    original = evidence.read_bytes()
    evidence.write_bytes(original.replace(b'"verdict":"pass"', b'"verdict":"fail"'))
    with pytest.raises(ValueError):
        verify_identity_bundle(bundle, public_key_pem=public)


def test_identity_failures_are_recomputed_and_exported_to_sarif(tmp_path: Path):
    report = _evaluation()
    report["run"]["access_observations"][1]["decision"] = "allow"
    report = _evaluation_value(report)
    assert report["summary"]["post_deadline_stale_allow_count"] == 1
    assert report["summary"]["verdict"] == "fail"
    source = tmp_path / "failed.json"
    _write_new(source, _canonical(report))
    bundle = tmp_path / "failed.bundle"
    create_identity_bundle(
        bundle,
        bundle_id="identity-failed",
        environment="evaluation",
        evaluation=source,
        created_at="2026-09-03T12:02:00Z",
    )
    sarif = export_identity_sarif(bundle, tmp_path / "failed.sarif.json")
    assert sarif["runs"][0]["results"][0]["ruleId"] == "LURE-IDENTITY-002"
    assert "locations" not in sarif["runs"][0]["results"][0]


def test_identity_topology_independently_recomputes_scope_and_trust():
    evaluation = _deployment_evaluation()
    profile = _identity_runtime_profile()
    topology = _topology_value(
        evaluation["plan"], profile, "2026-09-03T12:01:00Z", "0.11.0"
    )
    assert validate_identity_topology_audit(topology) == topology
    assert topology["summary"] == {
        "required_enforcement_point_count": 1,
        "covered_enforcement_point_count": 1,
        "missing_enforcement_point_count": 0,
        "unmapped_node_count": 0,
        "enforcement_point_coverage_rate": 1.0,
        "workload_identity_count": 2,
        "trusted_workload_identity_count": 2,
        "untrusted_workload_identity_count": 0,
        "workload_trust_domain_coverage_rate": 1.0,
        "verdict": "pass",
    }
    verifier_source = Path("lurescope/identity_topology.py").read_text(encoding="utf-8")
    assert "from lurebench" not in verifier_source
    assert "import lurebench" not in verifier_source

    changed = json.loads(json.dumps(topology))
    changed["summary"]["verdict"] = "fail"
    with pytest.raises(ValueError, match="independently recompute"):
        validate_identity_topology_audit(changed)

    untrusted_plan = json.loads(json.dumps(evaluation["plan"]))
    untrusted_plan["principals"][3]["spiffe_id"] = (
        "spiffe://untrusted.invalid/agents/alpha"
    )
    untrusted = _topology_value(
        untrusted_plan, profile, "2026-09-03T12:01:00Z", "0.11.0"
    )
    assert untrusted["summary"]["verdict"] == "fail"
    assert untrusted["untrusted_workload_principal_ids"] == ["workload-alpha"]


def test_identity_otel_projection_is_independent_private_and_exact(tmp_path: Path):
    projection = _identity_otel_projection(_deployment_evaluation())
    assert validate_identity_otel_projection(projection) == projection
    assert projection["run"]["access_observations"] == _deployment_evaluation()["run"][
        "access_observations"
    ]
    assert projection["privacy"]["body_accepted"] is False
    _schema("lureidentity-otel-projection-v1.schema.json", projection)
    _schema(
        "lureidentity-otel-log-export-v1.schema.json",
        projection["inputs"]["otel_log_export"],
    )
    path = tmp_path / "identity-otel.json"
    _write_new(path, _canonical(projection))
    assert load_identity_otel_projection(path) == projection
    assert main(["identity", "verify-otel", str(path)]) == 0
    assert path.stat().st_mode & 0o077 == 0

    verifier_source = Path("lurescope/identity_otel.py").read_text(encoding="utf-8")
    assert "from lurebench" not in verifier_source
    assert "import lurebench" not in verifier_source

    changed = json.loads(json.dumps(projection))
    changed["inputs"]["otel_log_export"]["records"][0]["Body"] = "secret"
    with pytest.raises(ValueError):
        validate_identity_otel_projection(changed)

    shifted = json.loads(json.dumps(projection))
    access_record = next(
        item
        for item in shifted["inputs"]["otel_log_export"]["records"]
        if item["EventName"] == ACCESS_EVENT
    )
    access_record["Timestamp"] += 1_000_000
    with pytest.raises(ValueError, match="planned probe"):
        validate_identity_otel_projection(shifted)


def test_identity_deployment_gate_binds_policy_topology_signature_and_evidence(
    tmp_path: Path,
):
    evaluation = _deployment_evaluation()
    campaign_path = tmp_path / "identity-campaign.json"
    plan_path = tmp_path / "identity-plan.json"
    campaign_verification_path = tmp_path / "identity-campaign-verification.json"
    _write_new(campaign_path, _canonical(_identity_campaign(evaluation["plan"])))
    _write_new(plan_path, _canonical(evaluation["plan"]))
    create_identity_campaign_verification(
        campaign_path,
        plan_path,
        campaign_verification_path,
        verified_at="2026-09-03T12:01:00Z",
    )
    artifact_verification_path = _artifact_verification(
        tmp_path, campaign_verification_path, evaluation["plan"]
    )
    source = tmp_path / "identity-evaluation.json"
    _write_new(source, _canonical(evaluation))
    topology = _topology_value(
        evaluation["plan"],
        _identity_runtime_profile(),
        "2026-09-03T12:01:00Z",
        "0.11.0",
    )
    topology_path = tmp_path / "identity-topology.json"
    _write_new(topology_path, _canonical(topology))
    projection = _identity_otel_projection(evaluation)
    projection_path = tmp_path / "identity-otel.json"
    _write_new(projection_path, _canonical(projection))
    private, public = _keypair()
    bundle = tmp_path / "identity.bundle"
    create_identity_bundle(
        bundle,
        bundle_id="identity-deployment-source",
        environment="evaluation",
        evaluation=source,
        signer_public_key_pem=public,
        signing_key_pem=private,
        created_at="2026-09-03T12:02:00Z",
    )
    gate_path = tmp_path / "identity-gate.json"
    key_id = public_key_id(public)
    policy = {
        "bundle_public_key_pem": public,
        "expected_bundle_key_id": key_id,
        "maximum_allowed_convergence_ms": 500,
        "minimum_run_generated_at": "2026-09-03T12:00:00Z",
        "expected_system_id": "synthetic-agent-system",
        "expected_environment": "evaluation",
        "expected_receiver_name": "independent-receiver",
        "expected_receiver_artifact_sha256": "2" * 64,
    }
    gate = create_identity_deployment_gate(
        campaign_verification_path,
        artifact_verification_path,
        topology_path,
        projection_path,
        bundle,
        gate_path,
        gate_id="identity-deployment-gate",
        created_at="2026-09-03T12:03:00Z",
        **policy,
    )
    assert gate["overall_status"] == "pass"
    assert gate["schema"] == GATE_SCHEMA
    assert gate["limitations"] == GATE_LIMITATIONS
    assert len(gate["checks"]) == 13
    assert gate["checks"][0] == {
        "check_id": "campaign_compilation_recomputed",
        "status": "pass",
    }
    assert gate["sources"]["campaign_verification"]["probe_count"] == 9
    assert gate["sources"]["artifact_verification"]["artifact_binding_count"] == 8
    assert gate["sources"]["topology_audit"]["covered_enforcement_point_count"] == 1
    assert gate["sources"]["topology_audit"]["trusted_workload_identity_count"] == 2
    _schema("lureidentity-deployment-gate-v1.schema.json", gate)
    assert gate["sources"]["otel_projection"]["record_count"] == 10
    verified = verify_identity_deployment_gate(
        gate_path,
        campaign_verification_path,
        artifact_verification_path,
        topology_path,
        projection_path,
        bundle,
        **policy,
    )
    assert verified["valid"] is True
    assert verified["authenticated_source_bundle"] is True

    failing_artifact_verification = _artifact_verification(
        tmp_path,
        campaign_verification_path,
        evaluation["plan"],
        prefix="failing-",
        fail_model=True,
    )
    failed_gate = create_identity_deployment_gate(
        campaign_verification_path,
        failing_artifact_verification,
        topology_path,
        projection_path,
        bundle,
        tmp_path / "failed-artifact-gate.json",
        gate_id="failed-artifact-gate",
        created_at="2026-09-03T12:03:00Z",
        **policy,
    )
    assert failed_gate["overall_status"] == "fail"
    assert failed_gate["checks"][3] == {
        "check_id": "workload_artifact_authorization_met",
        "status": "fail",
    }

    public_path = tmp_path / "public.pem"
    _write_new(public_path, public)
    assert main(["identity", "verify-topology", str(topology_path)]) == 0
    assert (
        main(
            [
                "identity",
                "verify-gate",
                str(gate_path),
                str(campaign_verification_path),
                str(artifact_verification_path),
                str(topology_path),
                str(projection_path),
                str(bundle),
                "--bundle-public-key",
                str(public_path),
                "--expected-bundle-key-id",
                key_id,
                "--maximum-allowed-convergence-ms",
                "500",
                "--minimum-run-generated-at",
                "2026-09-03T12:00:00Z",
                "--expected-system-id",
                "synthetic-agent-system",
                "--expected-environment",
                "evaluation",
                "--expected-receiver-name",
                "independent-receiver",
                "--expected-receiver-artifact-sha256",
                "2" * 64,
            ]
        )
        == 0
    )

    with pytest.raises(ValueError, match="signer"):
        create_identity_deployment_gate(
            campaign_verification_path,
            artifact_verification_path,
            topology_path,
            projection_path,
            bundle,
            tmp_path / "wrong-key-gate.json",
            gate_id="wrong-key-gate",
            created_at="2026-09-03T12:03:00Z",
            **{**policy, "expected_bundle_key_id": "0" * 64},
        )
    with pytest.raises(ValueError, match="deadline exceeds"):
        create_identity_deployment_gate(
            campaign_verification_path,
            artifact_verification_path,
            topology_path,
            projection_path,
            bundle,
            tmp_path / "weak-deadline-gate.json",
            gate_id="weak-deadline-gate",
            created_at="2026-09-03T12:03:00Z",
            **{**policy, "maximum_allowed_convergence_ms": 499},
        )


def test_identity_deployment_gate_rejects_a_noncompiled_plan(tmp_path: Path):
    evaluation = _evaluation()
    compiled_evaluation = _deployment_evaluation()
    campaign_path = tmp_path / "campaign.json"
    compiled_plan_path = tmp_path / "compiled-plan.json"
    campaign_verification_path = tmp_path / "campaign-verification.json"
    _write_new(
        campaign_path,
        _canonical(_identity_campaign(compiled_evaluation["plan"])),
    )
    _write_new(compiled_plan_path, _canonical(compiled_evaluation["plan"]))
    create_identity_campaign_verification(
        campaign_path,
        compiled_plan_path,
        campaign_verification_path,
        verified_at="2026-09-03T12:01:00Z",
    )
    artifact_verification_path = _artifact_verification(
        tmp_path, campaign_verification_path, compiled_evaluation["plan"]
    )
    profile = _identity_runtime_profile()
    profile["identity"]["allowed_spiffe_trust_domains"] = ["example.invalid"]
    topology = _topology_value(
        evaluation["plan"], profile, "2026-09-03T12:01:00Z", "0.11.0"
    )
    evaluation_path = tmp_path / "evaluation.json"
    topology_path = tmp_path / "topology.json"
    _write_new(evaluation_path, _canonical(evaluation))
    _write_new(topology_path, _canonical(topology))
    projection_path = tmp_path / "projection.json"
    _write_new(projection_path, _canonical(_identity_otel_projection(evaluation)))
    private, public = _keypair()
    bundle = tmp_path / "bundle"
    create_identity_bundle(
        bundle,
        bundle_id="identity-no-window",
        environment="evaluation",
        evaluation=evaluation_path,
        signer_public_key_pem=public,
        signing_key_pem=private,
        created_at="2026-09-03T12:02:00Z",
    )
    with pytest.raises(ValueError, match="same exact plan"):
        create_identity_deployment_gate(
            campaign_verification_path,
            artifact_verification_path,
            topology_path,
            projection_path,
            bundle,
            tmp_path / "gate.json",
            gate_id="identity-no-window-gate",
            bundle_public_key_pem=public,
            expected_bundle_key_id=public_key_id(public),
            maximum_allowed_convergence_ms=500,
            minimum_run_generated_at="2026-09-03T12:00:00Z",
            expected_system_id="synthetic-agent-system",
            expected_environment="evaluation",
            expected_receiver_name="independent-receiver",
            expected_receiver_artifact_sha256="2" * 64,
            created_at="2026-09-03T12:03:00Z",
        )
