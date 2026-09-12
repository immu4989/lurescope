"""Independent verification of LureMandate counterfactual guard pairs."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from . import __version__
from .mandate import _document, _encode, _instant, _now, _read, _sha256
from .mandate_conformance import validate_mandate_conformance_score
from .permit import _canonical, _exact, _id, _strict, _write_new

ASSURANCE_SCHEMA = (
    "https://github.com/immu4989/lurebench/spec/luremandate-counterfactual-assurance/v1"
)
VERIFICATION_SCHEMA = (
    "https://github.com/immu4989/lurescope/spec/luremandate-counterfactual-verification/v1"
)
COUNTERFACTUALS = (
    ("policy_unknown", ("policy_binding",)),
    ("tenant_mismatch", ("tenant_binding",)),
    ("run_binding_mismatch", ("run_binding",)),
    ("agent_identity_mismatch", ("agent_identity_binding",)),
    ("agent_policy_denied", ("agent_policy_assignment",)),
    ("requester_unknown", ("requester_registry_membership",)),
    ("impact_limit_exceeded", ("impact_within_limit",)),
    (
        "approval_count_insufficient",
        ("approval_count_sufficient", "required_security_role"),
    ),
    ("approval_binding_mismatch", ("mission_intent_binding",)),
    ("approval_denied", ("mission_decision_approve",)),
    ("self_approval", ("requester_separation",)),
    ("approver_unknown", ("mission_approver_registry_membership",)),
    ("approver_role_unauthorized", ("mission_role_assignment",)),
    ("approval_predates_intent", ("mission_not_before_intent",)),
    ("approval_after_decision", ("mission_not_after_decision",)),
    ("approval_expired", ("mission_unexpired_at_decision",)),
    ("approval_window_invalid", ("mission_ttl_within_policy",)),
    ("required_role_missing", ("required_security_role",)),
    (
        "approval_replay",
        (
            "mission_approval_fresh",
            "mission_intent_binding",
            "mission_not_before_intent",
            "mission_unexpired_at_decision",
        ),
    ),
    ("cumulative_limit_exceeded", ("cumulative_budget_available",)),
)
DIMENSION_IDS = (
    "policy_binding",
    "tenant_binding",
    "run_binding",
    "agent_identity_binding",
    "agent_policy_assignment",
    "requester_registry_membership",
    "impact_within_limit",
    "approval_count_sufficient",
    "mission_approval_fresh",
    "mission_intent_binding",
    "mission_decision_approve",
    "requester_separation",
    "mission_approver_registry_membership",
    "mission_role_assignment",
    "mission_not_before_intent",
    "mission_not_after_decision",
    "mission_unexpired_at_decision",
    "mission_ttl_within_policy",
    "required_security_role",
    "cumulative_budget_available",
)
LIMITATIONS = [
    "pairs_measure_declared_semantic_dimensions_not_source_code_conditions_or_formal_mcdc",
    "approval_count_and_replay_pairs_require_multiple_changed_dimensions_due_to_contract_dependencies",
    "reference_submission_tests_the_reference_semantics_not_an_external_gateway",
    "passing_does_not_establish_unrepresented_values_interactions_sequences_or_complete_mediation",
    "passing_is_not_compliance_certification_safety_legal_authority_or_deployment_authorization",
]
CHECKS = [
    "strict_counterfactual_report_and_embedded_score_reparsed",
    "canonical_score_binding_recomputed",
    "twenty_semantic_dimension_vectors_independently_derived",
    "twenty_valid_control_and_denial_mutant_pairs_reconstructed",
    "changed_and_expected_dimension_sets_compared_exactly",
    "gateway_score_and_all_guard_pair_pass_conjunction_recomputed",
]
VERIFICATION_LIMITATIONS = [
    "independent_recomputation_does_not_authenticate_the_submitting_gateway",
    "semantic_dimensions_are_contract_abstractions_not_source_code_conditions_or_formal_mcdc",
    "dependency_coupled_pairs_do_not_isolate_one_condition",
    "passing_does_not_establish_unrepresented_values_interactions_sequences_or_complete_mediation",
    "verification_is_not_compliance_certification_safety_legal_authority_or_deployment_authorization",
]
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_VERIFICATION_BYTES = 32 * 1024 * 1024


def _dimensions(
    transaction: Mapping[str, Any],
    plan: Mapping[str, Any],
    run_id: str,
    used_ids: set[str],
    used_nonces: set[str],
    reserved_by_requester: Mapping[str, int],
) -> Dict[str, bool]:
    intent = transaction["intent"]
    approvals = transaction["approvals"]
    mission = approvals[0]
    agents = {item["agent_id"]: item for item in plan["agents"]}
    people = {item["person_id"]: item for item in plan["people"]}
    policy = next(item for item in plan["policies"] if item["policy_id"] == "high-impact")
    agent = agents.get(intent["agent_id"])
    decision = _instant(transaction["decided_at"], "decided_at")
    proposed = _instant(intent["proposed_at"], "proposed_at")
    issued = _instant(mission["issued_at"], "mission issued_at")
    expires = _instant(mission["expires_at"], "mission expires_at")
    return {
        "policy_binding": intent["policy_id"] == "high-impact",
        "tenant_binding": intent["tenant_id"] == plan["environment"]["tenant_id"],
        "run_binding": intent["run_id"] == run_id,
        "agent_identity_binding": agent is not None
        and agent["workload_spiffe_id"] == intent["workload_spiffe_id"],
        "agent_policy_assignment": agent is not None
        and "high-impact" in agent["allowed_policy_ids"],
        "requester_registry_membership": intent["requester_id"] in people,
        "impact_within_limit": intent["impact_units"] <= policy["maximum_impact_units"],
        "approval_count_sufficient": len({item["approver_id"] for item in approvals})
        >= policy["minimum_distinct_approvers"],
        "mission_approval_fresh": mission["approval_id"] not in used_ids
        and mission["nonce"] not in used_nonces,
        "mission_intent_binding": mission["intent_sha256"] == transaction["intent_sha256"],
        "mission_decision_approve": mission["decision"] == "approve",
        "requester_separation": mission["approver_id"] != intent["requester_id"],
        "mission_approver_registry_membership": mission["approver_id"] in people,
        "mission_role_assignment": mission["approver_role"] == "mission-owner",
        "mission_not_before_intent": issued >= proposed,
        "mission_not_after_decision": issued <= decision,
        "mission_unexpired_at_decision": expires >= decision and expires > issued,
        "mission_ttl_within_policy": timedelta(0)
        < expires - issued
        <= timedelta(milliseconds=policy["approval_ttl_ms"]),
        "required_security_role": any(
            item["approver_role"] == "security-reviewer" for item in approvals
        ),
        "cumulative_budget_available": reserved_by_requester.get(intent["requester_id"], 0)
        + intent["impact_units"]
        <= policy["cumulative_limit_units"],
    }


def _producer_value(score_value: Mapping[str, Any]) -> Dict[str, Any]:
    score = validate_mandate_conformance_score(score_value)
    challenge = score["challenge"]
    if len(challenge["cases"]) != 40:
        raise ValueError("counterfactual campaign must contain exactly 40 ordered cases")
    plan = challenge["plan"]
    used_ids: set[str] = set()
    used_nonces: set[str] = set()
    reserved: Dict[str, int] = {}
    dimensions = []
    for case, result in zip(challenge["cases"], score["results"], strict=True):
        transaction = case["transaction"]
        dimensions.append(
            _dimensions(
                transaction,
                plan,
                challenge["execution"]["run_id"],
                used_ids,
                used_nonces,
                reserved,
            )
        )
        for approval in transaction["approvals"]:
            used_ids.add(approval["approval_id"])
            used_nonces.add(approval["nonce"])
        if result["expected_decision"] == "allow":
            requester = transaction["intent"]["requester_id"]
            reserved[requester] = reserved.get(requester, 0) + transaction["intent"]["impact_units"]
    pairs = []
    passed_pairs = single_dimension_pairs = 0
    for index, (reason, expected_changes) in enumerate(COUNTERFACTUALS):
        baseline_result = score["results"][index * 2]
        mutant_result = score["results"][index * 2 + 1]
        baseline_dimensions = dimensions[index * 2]
        mutant_dimensions = dimensions[index * 2 + 1]
        changed = [
            name for name in DIMENSION_IDS if baseline_dimensions[name] != mutant_dimensions[name]
        ]
        pair_passed = (
            all(baseline_dimensions.values())
            and baseline_result["expected_decision"] == "allow"
            and baseline_result["expected_reason_code"] == "authority_satisfied"
            and mutant_result["expected_decision"] == "block"
            and mutant_result["expected_reason_code"] == reason
            and changed == list(expected_changes)
            and baseline_result["status"] == "pass"
            and mutant_result["status"] == "pass"
        )
        passed_pairs += int(pair_passed)
        single_dimension_pairs += int(len(changed) == 1)
        pairs.append(
            {
                "pair_id": f"guard-pair-{index + 1:02d}",
                "guard_reason": reason,
                "baseline_case_id": baseline_result["case_id"],
                "mutant_case_id": mutant_result["case_id"],
                "changed_dimensions": changed,
                "expected_changed_dimensions": list(expected_changes),
                "baseline_expected_decision": baseline_result["expected_decision"],
                "mutant_expected_decision": mutant_result["expected_decision"],
                "baseline_submitted_decision": baseline_result["submitted_decision"],
                "mutant_submitted_decision": mutant_result["submitted_decision"],
                "status": "pass" if pair_passed else "fail",
            }
        )
    pair_count = len(pairs)
    return {
        "schema": ASSURANCE_SCHEMA,
        "schema_version": 1,
        "report_id": f"{score['score_id']}-counterfactual",
        "evaluated_at": score["evaluated_at"],
        "method": {
            "name": "adjacent-valid-control-guard-pairs",
            "dimension_ids": list(DIMENSION_IDS),
            "guard_reasons": [reason for reason, _ in COUNTERFACTUALS],
        },
        "score_sha256": _sha256(_canonical(score)),
        "score": score,
        "pairs": pairs,
        "summary": {
            "verdict": "pass"
            if score["summary"]["verdict"] == "pass" and passed_pairs == pair_count
            else "fail",
            "score_verdict": score["summary"]["verdict"],
            "case_count": len(score["results"]),
            "guard_pair_count": pair_count,
            "passed_guard_pair_count": passed_pairs,
            "single_dimension_pair_count": single_dimension_pairs,
            "dependency_coupled_pair_count": pair_count - single_dimension_pairs,
            "guard_reason_coverage_complete": passed_pairs == pair_count,
        },
        "limitations": list(LIMITATIONS),
    }


def validate_counterfactual_mandate_assurance(value: Any) -> Dict[str, Any]:
    report = _exact(
        value,
        "LureMandate counterfactual assurance",
        (
            "schema",
            "schema_version",
            "report_id",
            "evaluated_at",
            "method",
            "score_sha256",
            "score",
            "pairs",
            "summary",
            "limitations",
        ),
    )
    if report["schema"] != ASSURANCE_SCHEMA or report["schema_version"] != 1:
        raise ValueError("unsupported LureMandate counterfactual assurance schema")
    _id(report["report_id"], "counterfactual report_id")
    if report != _producer_value(report["score"]):
        raise ValueError("LureMandate counterfactual assurance does not independently reproduce")
    return dict(report)


def _verification_value(payload: bytes, *, verified_at: str) -> Dict[str, Any]:
    report = validate_counterfactual_mandate_assurance(
        _strict(payload, "LureMandate counterfactual assurance")
    )
    if _instant(verified_at, "verified_at") < _instant(
        report["evaluated_at"], "counterfactual evaluated_at"
    ):
        raise ValueError("counterfactual verification predates the producer report")
    summary = dict(report["summary"])
    summary.update({"source_document_reparsed": True, "producer_report_reproduced": True})
    return {
        "schema": VERIFICATION_SCHEMA,
        "schema_version": 1,
        "verification_id": f"{report['report_id']}-verification",
        "verified_at": verified_at,
        "engine": {
            "name": "lurescope-luremandate-counterfactual-independent",
            "version": __version__,
        },
        "document": {
            "document_sha256": _sha256(payload),
            "payload_base64": _encode(payload),
        },
        "producer_report": report,
        "checks": list(CHECKS),
        "summary": summary,
        "limitations": list(VERIFICATION_LIMITATIONS),
    }


def create_counterfactual_mandate_verification(
    report_path: Path,
    output_path: Path,
    *,
    verified_at: Optional[str] = None,
) -> Dict[str, Any]:
    payload = _read(report_path, "LureMandate counterfactual assurance", MAX_REPORT_BYTES)
    result = _verification_value(payload, verified_at=verified_at or _now())
    encoded = _canonical(validate_counterfactual_mandate_verification(result))
    if len(encoded) > MAX_VERIFICATION_BYTES:
        raise ValueError("counterfactual verification exceeds its size limit")
    _write_new(Path(output_path), encoded)
    return result


def validate_counterfactual_mandate_verification(value: Any) -> Dict[str, Any]:
    verification = _exact(
        value,
        "LureMandate counterfactual verification",
        (
            "schema",
            "schema_version",
            "verification_id",
            "verified_at",
            "engine",
            "document",
            "producer_report",
            "checks",
            "summary",
            "limitations",
        ),
    )
    if verification["schema"] != VERIFICATION_SCHEMA or verification["schema_version"] != 1:
        raise ValueError("unsupported LureMandate counterfactual verification schema")
    _id(verification["verification_id"], "counterfactual verification_id")
    if verification["engine"] != {
        "name": "lurescope-luremandate-counterfactual-independent",
        "version": __version__,
    }:
        raise ValueError("unsupported counterfactual verifier engine")
    if verification["checks"] != CHECKS or verification["limitations"] != VERIFICATION_LIMITATIONS:
        raise ValueError("counterfactual verification checks or limitations are incomplete")
    payload = _document(verification["document"], "embedded counterfactual report")
    expected = _verification_value(payload, verified_at=verification["verified_at"])
    if verification != expected:
        raise ValueError("LureMandate counterfactual verification does not reproduce")
    return dict(verification)


def load_counterfactual_mandate_verification(path: Path) -> Dict[str, Any]:
    return validate_counterfactual_mandate_verification(
        _strict(
            _read(
                path,
                "LureMandate counterfactual verification",
                MAX_VERIFICATION_BYTES,
            ),
            "LureMandate counterfactual verification",
        )
    )
