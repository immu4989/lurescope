"""Independent LureMandate strength-2 input-interaction verification."""

from __future__ import annotations

from datetime import timedelta
from itertools import combinations
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from . import __version__
from .mandate import _document, _encode, _instant, _now, _read, _sha256
from .mandate_conformance import validate_mandate_conformance_score
from .permit import _canonical, _exact, _id, _strict, _write_new

PAIRWISE_SCHEMA = "https://github.com/immu4989/lurebench/spec/luremandate-pairwise-assurance/v1"
VERIFICATION_SCHEMA = (
    "https://github.com/immu4989/lurescope/spec/luremandate-pairwise-verification/v1"
)
FACTOR_IDS = (
    "tenant_binding",
    "run_binding",
    "agent_workload_binding",
    "agent_policy_assignment",
    "requester_registry_membership",
    "impact_within_limit",
    "approval_intent_binding",
    "approval_decision",
    "requester_separation",
    "security_approver_registry_membership",
    "mission_role_assignment",
    "mission_issue_before_decision",
    "mission_unexpired_at_decision",
    "security_ttl_within_policy",
    "required_security_role",
)
COMBINATIONS = ("00", "01", "10", "11")
LIMITATIONS = [
    "binary_two_way_input_coverage_does_not_establish_three_way_or_higher_interaction_coverage",
    "factor_abstraction_and_feasible_value_domains_are_specific_to_the_reference_campaign",
    "reference_submission_tests_the_reference_semantics_not_an_external_gateway",
    "passing_does_not_prove_implementation_structure_unrepresented_behavior_or_complete_mediation",
    "passing_is_not_compliance_certification_safety_legal_authority_or_deployment_authorization",
]
CHECKS = [
    "strict_pairwise_report_and_embedded_score_reparsed",
    "canonical_score_binding_recomputed",
    "fifteen_factor_values_independently_derived_from_challenge_inputs",
    "all_one_hundred_five_factor_pairs_reenumerated",
    "all_four_hundred_twenty_binary_interactions_recomputed",
    "gateway_score_and_pairwise_pass_conjunction_recomputed",
]
VERIFICATION_LIMITATIONS = [
    "independent_recomputation_does_not_authenticate_the_submitting_gateway",
    "binary_strength_two_coverage_does_not_establish_higher_strength_or_production_domain_coverage",
    "factor_model_is_a_declared_abstraction_not_implementation_structural_coverage",
    "passing_does_not_prove_unrepresented_behavior_complete_mediation_safety_or_compliance",
    "verification_is_not_certification_legal_authority_or_deployment_authorization",
]
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_VERIFICATION_BYTES = 32 * 1024 * 1024


def _factor_values(challenge: Mapping[str, Any]) -> list[Dict[str, bool]]:
    plan = challenge["plan"]
    people = {item["person_id"]: item for item in plan["people"]}
    agents = {item["agent_id"]: item for item in plan["agents"]}
    policies = {item["policy_id"]: item for item in plan["policies"]}
    rows = []
    for case in challenge["cases"]:
        transaction = case["transaction"]
        intent = transaction["intent"]
        approvals = transaction["approvals"]
        if len(approvals) != 2 or intent["policy_id"] not in policies:
            raise ValueError("pairwise campaign requires two approvals and one known policy")
        mission, security = approvals
        agent = agents.get(intent["agent_id"])
        policy = policies[intent["policy_id"]]
        mission_person = people.get(mission["approver_id"])
        rows.append(
            {
                "tenant_binding": intent["tenant_id"] == plan["environment"]["tenant_id"],
                "run_binding": intent["run_id"] == challenge["execution"]["run_id"],
                "agent_workload_binding": agent is not None
                and agent["workload_spiffe_id"] == intent["workload_spiffe_id"],
                "agent_policy_assignment": agent is not None
                and intent["policy_id"] in agent["allowed_policy_ids"],
                "requester_registry_membership": intent["requester_id"] in people,
                "impact_within_limit": intent["impact_units"] <= policy["maximum_impact_units"],
                "approval_intent_binding": mission["intent_sha256"] == transaction["intent_sha256"],
                "approval_decision": mission["decision"] == "approve",
                "requester_separation": mission["approver_id"] != intent["requester_id"],
                "security_approver_registry_membership": security["approver_id"] in people,
                "mission_role_assignment": mission_person is not None
                and mission["approver_role"] in mission_person["roles"],
                "mission_issue_before_decision": _instant(mission["issued_at"], "mission issued_at")
                <= _instant(transaction["decided_at"], "decided_at"),
                "mission_unexpired_at_decision": _instant(
                    mission["expires_at"], "mission expires_at"
                )
                >= _instant(transaction["decided_at"], "decided_at"),
                "security_ttl_within_policy": timedelta(0)
                < _instant(security["expires_at"], "security expires_at")
                - _instant(security["issued_at"], "security issued_at")
                <= timedelta(milliseconds=policy["approval_ttl_ms"]),
                "required_security_role": security["approver_role"] == "security-reviewer",
            }
        )
    return rows


def _producer_value(score_value: Mapping[str, Any]) -> Dict[str, Any]:
    score = validate_mandate_conformance_score(score_value)
    rows = _factor_values(score["challenge"])
    pair_coverage = []
    covered_total = 0
    for factor_a, factor_b in combinations(FACTOR_IDS, 2):
        covered = sorted({f"{int(row[factor_a])}{int(row[factor_b])}" for row in rows})
        covered_total += len(covered)
        pair_coverage.append(
            {
                "factor_a": factor_a,
                "factor_b": factor_b,
                "covered_combinations": covered,
                "missing_combinations": [item for item in COMBINATIONS if item not in covered],
            }
        )
    required_total = len(pair_coverage) * len(COMBINATIONS)
    complete = covered_total == required_total
    return {
        "schema": PAIRWISE_SCHEMA,
        "schema_version": 1,
        "report_id": f"{score['score_id']}-pairwise",
        "evaluated_at": score["evaluated_at"],
        "method": {
            "name": "binary-pairwise-input-coverage",
            "strength": 2,
            "factor_ids": list(FACTOR_IDS),
            "required_value_combinations": list(COMBINATIONS),
        },
        "score_sha256": _sha256(_canonical(score)),
        "score": score,
        "factor_rows": [
            {"case_id": case["case_id"], "values": row}
            for case, row in zip(score["challenge"]["cases"], rows, strict=True)
        ],
        "pair_coverage": pair_coverage,
        "summary": {
            "verdict": "pass" if score["summary"]["verdict"] == "pass" and complete else "fail",
            "score_verdict": score["summary"]["verdict"],
            "case_count": len(rows),
            "factor_count": len(FACTOR_IDS),
            "factor_pair_count": len(pair_coverage),
            "required_interaction_count": required_total,
            "covered_interaction_count": covered_total,
            "interaction_coverage": covered_total / required_total,
            "pairwise_coverage_complete": complete,
        },
        "limitations": list(LIMITATIONS),
    }


def validate_pairwise_mandate_assurance(value: Any) -> Dict[str, Any]:
    report = _exact(
        value,
        "LureMandate pairwise assurance",
        (
            "schema",
            "schema_version",
            "report_id",
            "evaluated_at",
            "method",
            "score_sha256",
            "score",
            "factor_rows",
            "pair_coverage",
            "summary",
            "limitations",
        ),
    )
    if report["schema"] != PAIRWISE_SCHEMA or report["schema_version"] != 1:
        raise ValueError("unsupported LureMandate pairwise assurance schema")
    _id(report["report_id"], "pairwise report_id")
    if report != _producer_value(report["score"]):
        raise ValueError("LureMandate pairwise assurance does not independently reproduce")
    return dict(report)


def _verification_value(payload: bytes, *, verified_at: str) -> Dict[str, Any]:
    report = validate_pairwise_mandate_assurance(_strict(payload, "LureMandate pairwise assurance"))
    if _instant(verified_at, "verified_at") < _instant(
        report["evaluated_at"], "pairwise evaluated_at"
    ):
        raise ValueError("pairwise verification predates the producer report")
    summary = dict(report["summary"])
    summary.update({"source_document_reparsed": True, "producer_report_reproduced": True})
    return {
        "schema": VERIFICATION_SCHEMA,
        "schema_version": 1,
        "verification_id": f"{report['report_id']}-verification",
        "verified_at": verified_at,
        "engine": {
            "name": "lurescope-luremandate-pairwise-independent",
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


def create_pairwise_mandate_verification(
    report_path: Path,
    output_path: Path,
    *,
    verified_at: Optional[str] = None,
) -> Dict[str, Any]:
    payload = _read(report_path, "LureMandate pairwise assurance", MAX_REPORT_BYTES)
    result = _verification_value(payload, verified_at=verified_at or _now())
    encoded = _canonical(validate_pairwise_mandate_verification(result))
    if len(encoded) > MAX_VERIFICATION_BYTES:
        raise ValueError("pairwise verification exceeds its size limit")
    _write_new(Path(output_path), encoded)
    return result


def validate_pairwise_mandate_verification(value: Any) -> Dict[str, Any]:
    verification = _exact(
        value,
        "LureMandate pairwise verification",
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
        raise ValueError("unsupported LureMandate pairwise verification schema")
    _id(verification["verification_id"], "pairwise verification_id")
    if verification["engine"] != {
        "name": "lurescope-luremandate-pairwise-independent",
        "version": __version__,
    }:
        raise ValueError("unsupported pairwise verifier engine")
    if verification["checks"] != CHECKS or verification["limitations"] != VERIFICATION_LIMITATIONS:
        raise ValueError("pairwise verification checks or limitations are incomplete")
    payload = _document(verification["document"], "embedded pairwise report")
    expected = _verification_value(payload, verified_at=verification["verified_at"])
    if verification != expected:
        raise ValueError("LureMandate pairwise verification does not independently reproduce")
    return dict(verification)


def load_pairwise_mandate_verification(path: Path) -> Dict[str, Any]:
    return validate_pairwise_mandate_verification(
        _strict(
            _read(path, "LureMandate pairwise verification", MAX_VERIFICATION_BYTES),
            "LureMandate pairwise verification",
        )
    )
