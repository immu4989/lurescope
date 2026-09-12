"""Standards-based, content-free exports for independently verified LureMandate gates."""

from __future__ import annotations

import secrets
import uuid
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple

from . import __version__
from .mandate import _instant
from .mandate_gate import verify_mandate_deployment_gate
from .permit import _canonical, _read, _sha256, _strict, _timestamp, _timestamp_now, _write_new

OSCAL_SCHEMA = (
    "https://raw.githubusercontent.com/usnistgov/OSCAL/v1.2.2/json/schema/"
    "oscal_assessment-results_schema.json"
)
SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
OSCAL_NAMESPACE = "https://github.com/immu4989/lurescope/ns/oscal"
DOCUMENTATION_URI = (
    "https://github.com/immu4989/lurescope/blob/main/docs/LUREMANDATE_VERIFICATION.md"
)
EXPORT_INTERPRETATION = (
    "This artifact reports observation-only results from an independently reproduced "
    "LureMandate deployment gate. It contains typed statuses and cryptographic digests, not "
    "transaction bodies. A pass is not a control-satisfaction determination, compliance "
    "certification, safety finding, legal authority, or deployment authorization. Source "
    "completeness, trusted time, key-to-person identity, and complete mediation remain external."
)

CHECKS: Tuple[Tuple[str, str, str, str], ...] = (
    (
        "semantic_verification_recomputed",
        "LURE-MANDATE-001",
        "Semantic verification did not reproduce",
        "The exact plan, run, and producer evaluation were independently recomputed.",
    ),
    (
        "authenticated_approval_evidence_recomputed",
        "LURE-MANDATE-002",
        "Approval authentication did not reproduce",
        "Approval signatures and exact evidence coverage were independently re-authenticated.",
    ),
    (
        "body_free_telemetry_projection_recomputed",
        "LURE-MANDATE-003",
        "Telemetry projection did not reproduce",
        "The body-free lifecycle event projection was independently reconstructed.",
    ),
    (
        "telemetry_source_signature_authenticated",
        "LURE-MANDATE-004",
        "Telemetry source signature was not authenticated",
        "The canonical telemetry export was authenticated against the externally pinned key.",
    ),
    (
        "exact_plan_run_and_evaluation_binding",
        "LURE-MANDATE-005",
        "Evidence documents were not exactly bound",
        "Semantic, signature, and telemetry evidence bound the same exact plan and run.",
    ),
    (
        "preregistered_approver_key_policy",
        "LURE-MANDATE-006",
        "Approver-key policy was not preregistered",
        "The approver-key policy preceded and matched the evaluated campaign environment.",
    ),
    (
        "externally_pinned_approver_keys",
        "LURE-MANDATE-007",
        "Approval keys did not match external policy",
        "Distinct approval keys matched the independently supplied approver-key policy.",
    ),
    (
        "deployment_engine_identity_matches_policy",
        "LURE-MANDATE-008",
        "Deployment engine identity did not match policy",
        "The run and receiver identities matched the externally supplied deployment policy.",
    ),
    (
        "run_freshness_matches_policy",
        "LURE-MANDATE-009",
        "Run freshness did not match policy",
        "The evaluated run was no older than the externally supplied freshness boundary.",
    ),
    (
        "transaction_authority_acceptance_met",
        "LURE-MANDATE-010",
        "Transaction-authority acceptance was not met",
        "The independently reproduced transaction-authority acceptance conditions were met.",
    ),
)
_CHECK_BY_ID = {
    check_id: (rule_id, failure_title, observation)
    for check_id, rule_id, failure_title, observation in CHECKS
}


def _verified_gate(
    gate: Path,
    semantic_verification: Path,
    authenticated_verification: Path,
    otel_projection: Path,
    authenticated_otel_projection: Path,
    approver_key_policy: Path,
    *,
    minimum_run_started_at: str,
    expected_engine_id: str,
    expected_engine_version: str,
    expected_engine_artifact_sha256: str,
    expected_receiver_instance_id: str,
    expected_receiver_key_id: str,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    gate_payload = _read(Path(gate), private=True)
    gate_document = _strict(gate_payload, "LureMandate deployment gate")
    verified = verify_mandate_deployment_gate(
        Path(gate),
        Path(semantic_verification),
        Path(authenticated_verification),
        Path(otel_projection),
        Path(authenticated_otel_projection),
        Path(approver_key_policy),
        minimum_run_started_at=minimum_run_started_at,
        expected_engine_id=expected_engine_id,
        expected_engine_version=expected_engine_version,
        expected_engine_artifact_sha256=expected_engine_artifact_sha256,
        expected_receiver_instance_id=expected_receiver_instance_id,
        expected_receiver_key_id=expected_receiver_key_id,
    )
    if not secrets.compare_digest(verified["gate_sha256"], _sha256(gate_payload)):
        raise ValueError("LureMandate deployment gate changed during verification")
    return dict(gate_document), verified


def _oscal_uuid(kind: str, gate_sha256: str, suffix: str = "") -> str:
    seed = f"lurescope:luremandate:{kind}:{gate_sha256}:{suffix}"
    return str(uuid.uuid5(uuid.NAMESPACE_URL, seed))


def _oscal_prop(name: str, value: Any) -> Dict[str, str]:
    rendered = str(value).lower() if isinstance(value, bool) else str(value)
    return {"name": name, "ns": OSCAL_NAMESPACE, "value": rendered}


def _effective_generated_at(gate: Mapping[str, Any], generated_at: Optional[str]) -> str:
    candidate = _timestamp(generated_at or _timestamp_now(), "export generated_at")
    if _instant(candidate, "export generated_at") < _instant(
        gate["created_at"], "deployment gate created_at"
    ):
        raise ValueError("standards export cannot predate its verified deployment gate")
    return candidate


def _oscal_document(
    gate: Mapping[str, Any],
    verified: Mapping[str, Any],
    *,
    assessment_plan_href: str,
    generated_at: str,
) -> Dict[str, Any]:
    gate_sha256 = verified["gate_sha256"]
    observations = []
    for check in gate["checks"]:
        _, failure_title, observation = _CHECK_BY_ID[check["check_id"]]
        check_sha256 = _sha256(_canonical({"gate_sha256": gate_sha256, "check": dict(check)}))
        observations.append(
            {
                "uuid": _oscal_uuid("observation", gate_sha256, check["check_id"]),
                "title": failure_title.removesuffix(" did not reproduce")
                .removesuffix(" was not authenticated")
                .removesuffix(" were not exactly bound")
                .removesuffix(" was not preregistered")
                .removesuffix(" did not match external policy")
                .removesuffix(" did not match policy")
                .removesuffix(" was not met"),
                "description": observation,
                "props": [
                    _oscal_prop("check-id", check["check_id"]),
                    _oscal_prop("status", check["status"]),
                    _oscal_prop("check-sha256", check_sha256),
                ],
                "methods": ["TEST"],
                "types": ["control-objective"],
                "relevant-evidence": [
                    {
                        "href": f"urn:sha256:{gate_sha256}",
                        "description": "Digest of the exact independently verified gate.",
                    }
                ],
                "collected": generated_at,
                "remarks": EXPORT_INTERPRETATION,
            }
        )
    source_times = [
        source["verified_at"] if "verified_at" in source else source["generated_at"]
        for source in gate["sources"].values()
    ]
    started_at = min(source_times, key=lambda item: _instant(item, "gate source time"))
    return {
        "$schema": OSCAL_SCHEMA,
        "assessment-results": {
            "uuid": _oscal_uuid("document", gate_sha256),
            "metadata": {
                "title": "LureMandate deployment-gate observations",
                "last-modified": generated_at,
                "version": "1.0.0",
                "oscal-version": "1.2.2",
                "props": [
                    _oscal_prop("gate-sha256", gate_sha256),
                    _oscal_prop("overall-status", gate["overall_status"]),
                    _oscal_prop(
                        "engine-artifact-sha256",
                        gate["contract"]["engine"]["engine_artifact_sha256"],
                    ),
                    _oscal_prop("receiver-key-sha256", gate["policy"]["expected_receiver_key_id"]),
                ],
                "remarks": EXPORT_INTERPRETATION,
            },
            "import-ap": {"href": assessment_plan_href},
            "results": [
                {
                    "uuid": _oscal_uuid("result", gate_sha256),
                    "title": "Transaction-authority deployment-gate observations",
                    "description": (
                        "Observation-only results; no control-satisfaction determination is made."
                    ),
                    "start": started_at,
                    "end": generated_at,
                    "props": [
                        _oscal_prop("overall-status", gate["overall_status"]),
                        _oscal_prop("observation-count", len(observations)),
                    ],
                    "reviewed-controls": {
                        "control-selections": [
                            {
                                "description": (
                                    "Controls for which transaction-authority evidence may be "
                                    "relevant; inclusion is not a satisfaction determination."
                                ),
                                "include-controls": [
                                    {"control-id": control_id}
                                    for control_id in (
                                        "ac-2",
                                        "ac-3",
                                        "ac-5",
                                        "ac-6",
                                        "au-2",
                                        "au-10",
                                        "ca-7",
                                        "si-4",
                                    )
                                ],
                            }
                        ]
                    },
                    "observations": observations,
                    "remarks": EXPORT_INTERPRETATION,
                }
            ],
        },
    }


def _sarif_document(gate: Mapping[str, Any], verified: Mapping[str, Any]) -> Dict[str, Any]:
    gate_sha256 = verified["gate_sha256"]
    rule_index = {check_id: index for index, (check_id, *_rest) in enumerate(CHECKS)}
    results = []
    for check in gate["checks"]:
        if check["status"] == "pass":
            continue
        rule_id, failure_title, _ = _CHECK_BY_ID[check["check_id"]]
        results.append(
            {
                "ruleId": rule_id,
                "ruleIndex": rule_index[check["check_id"]],
                "level": "error",
                "message": {"text": f"{failure_title}."},
                "fingerprints": {
                    "gateCheckSha256": _sha256(
                        _canonical({"gate_sha256": gate_sha256, "check": dict(check)})
                    )
                },
                "properties": {
                    "checkId": check["check_id"],
                    "gateSha256": gate_sha256,
                },
            }
        )
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "LureScope LureMandate Gate",
                        "version": __version__,
                        "informationUri": DOCUMENTATION_URI,
                        "rules": [
                            {
                                "id": rule_id,
                                "name": "".join(
                                    word.capitalize() for word in failure_title.split()
                                ),
                                "shortDescription": {"text": failure_title},
                                "fullDescription": {
                                    "text": f"{observation} {EXPORT_INTERPRETATION}"
                                },
                                "defaultConfiguration": {"level": "error"},
                            }
                            for _, rule_id, failure_title, observation in CHECKS
                        ],
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "gateStatus": gate["overall_status"],
                            "gateSha256": gate_sha256,
                        },
                    }
                ],
                "results": results,
                "properties": {
                    "gateSha256": gate_sha256,
                    "overallStatus": gate["overall_status"],
                    "planSha256": gate["contract"]["plan_sha256"],
                    "runSha256": gate["contract"]["run_sha256"],
                    "evaluationSha256": gate["contract"]["evaluation_sha256"],
                    "engineArtifactSha256": gate["contract"]["engine"]["engine_artifact_sha256"],
                    "receiverKeySha256": gate["policy"]["expected_receiver_key_id"],
                    "interpretationBoundary": EXPORT_INTERPRETATION,
                },
            }
        ],
    }


def export_mandate_oscal(
    gate: Path,
    semantic_verification: Path,
    authenticated_verification: Path,
    otel_projection: Path,
    authenticated_otel_projection: Path,
    approver_key_policy: Path,
    output: Path,
    *,
    assessment_plan_href: str,
    minimum_run_started_at: str,
    expected_engine_id: str,
    expected_engine_version: str,
    expected_engine_artifact_sha256: str,
    expected_receiver_instance_id: str,
    expected_receiver_key_id: str,
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Export an observation-only OSCAL assessment-results document after strict rechecking."""
    if not isinstance(assessment_plan_href, str) or not assessment_plan_href.startswith(
        ("https://", "urn:")
    ):
        raise ValueError("assessment_plan_href must be an operator-controlled https: or urn: URI")
    gate_document, verified = _verified_gate(
        gate,
        semantic_verification,
        authenticated_verification,
        otel_projection,
        authenticated_otel_projection,
        approver_key_policy,
        minimum_run_started_at=minimum_run_started_at,
        expected_engine_id=expected_engine_id,
        expected_engine_version=expected_engine_version,
        expected_engine_artifact_sha256=expected_engine_artifact_sha256,
        expected_receiver_instance_id=expected_receiver_instance_id,
        expected_receiver_key_id=expected_receiver_key_id,
    )
    document = _oscal_document(
        gate_document,
        verified,
        assessment_plan_href=assessment_plan_href,
        generated_at=_effective_generated_at(gate_document, generated_at),
    )
    _write_new(Path(output), _canonical(document))
    return document


def export_mandate_sarif(
    gate: Path,
    semantic_verification: Path,
    authenticated_verification: Path,
    otel_projection: Path,
    authenticated_otel_projection: Path,
    approver_key_policy: Path,
    output: Path,
    *,
    minimum_run_started_at: str,
    expected_engine_id: str,
    expected_engine_version: str,
    expected_engine_artifact_sha256: str,
    expected_receiver_instance_id: str,
    expected_receiver_key_id: str,
) -> Dict[str, Any]:
    """Export location-free SARIF after independently rechecking the complete gate."""
    gate_document, verified = _verified_gate(
        gate,
        semantic_verification,
        authenticated_verification,
        otel_projection,
        authenticated_otel_projection,
        approver_key_policy,
        minimum_run_started_at=minimum_run_started_at,
        expected_engine_id=expected_engine_id,
        expected_engine_version=expected_engine_version,
        expected_engine_artifact_sha256=expected_engine_artifact_sha256,
        expected_receiver_instance_id=expected_receiver_instance_id,
        expected_receiver_key_id=expected_receiver_key_id,
    )
    document = _sarif_document(gate_document, verified)
    _write_new(Path(output), _canonical(document))
    return document
