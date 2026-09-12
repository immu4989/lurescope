"""Independent ordered strength-2 LureMandate operation verification."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from . import __version__
from .mandate import _document, _encode, _instant, _now, _read, _sha256
from .mandate_conformance import validate_mandate_conformance_score
from .permit import _canonical, _exact, _id, _strict, _write_new

ASSURANCE_SCHEMA = (
    "https://github.com/immu4989/lurebench/spec/luremandate-sequence-assurance/v1"
)
VERIFICATION_SCHEMA = (
    "https://github.com/immu4989/lurescope/spec/luremandate-sequence-verification/v1"
)
OPERATIONS = (
    "fresh-allow",
    "replay-block",
    "budget-boundary-allow",
    "budget-exceed-block",
    "expired-window-allow",
)
EXPECTED_REASONS = {
    "fresh-allow": "authority_satisfied",
    "replay-block": "approval_replay",
    "budget-boundary-allow": "authority_satisfied",
    "budget-exceed-block": "cumulative_limit_exceeded",
    "expired-window-allow": "authority_satisfied",
}
EXPECTED_DECISIONS = {
    operation: "block" if operation.endswith("block") else "allow" for operation in OPERATIONS
}
LIMITATIONS = [
    "ordered_strength_two_operation_coverage_does_not_establish_longer_sequence_coverage",
    "each_measured_operation_uses_an_isolated_requester_scope_to_keep_state_preconditions_stable",
    "reference_submission_tests_the_reference_semantics_not_an_external_gateway",
    "passing_does_not_establish_cross_subject_interference_unrepresented_operations_or_complete_mediation",
    "passing_is_not_compliance_certification_safety_legal_authority_or_deployment_authorization",
]
CHECKS = [
    "strict_sequence_report_and_embedded_score_reparsed",
    "canonical_score_binding_recomputed",
    "twenty_state_priming_cases_reconstructed",
    "twenty_six_measured_operations_derived_from_challenge_actions",
    "fixed_cyclic_de_bruijn_order_two_sequence_recomputed",
    "all_twenty_five_ordered_operation_pairs_reenumerated",
    "gateway_score_and_sequence_pass_conjunction_recomputed",
]
VERIFICATION_LIMITATIONS = [
    "independent_recomputation_does_not_authenticate_the_submitting_gateway",
    "ordered_strength_two_coverage_does_not_establish_longer_sequences",
    "isolated_requester_scopes_do_not_test_cross_subject_state_interference",
    "passing_does_not_establish_unrepresented_operations_complete_mediation_safety_or_compliance",
    "verification_is_not_certification_legal_authority_or_deployment_authorization",
]
MAX_REPORT_BYTES = 24 * 1024 * 1024
MAX_VERIFICATION_BYTES = 48 * 1024 * 1024


def _de_bruijn_order_two() -> list[str]:
    """Independently construct and linearize the fixed cyclic B(5, 2)."""
    alphabet_size = len(OPERATIONS)
    work = [0] * (alphabet_size * 2)
    output: list[int] = []

    def visit(position: int, period: int) -> None:
        if position > 2:
            if 2 % period == 0:
                output.extend(work[1 : period + 1])
            return
        work[position] = work[position - period]
        visit(position + 1, period)
        for value in range(work[position - period] + 1, alphabet_size):
            work[position] = value
            visit(position + 1, position)

    visit(1, 1)
    cycle = [OPERATIONS[index] for index in output]
    return cycle + cycle[:1]


def _producer_value(score_value: Mapping[str, Any]) -> Dict[str, Any]:
    score = validate_mandate_conformance_score(score_value)
    cases = score["challenge"]["cases"]
    results = score["results"]
    if len(cases) != 46:
        raise ValueError("sequence campaign must contain exactly 20 preamble and 26 measured cases")
    if any(
        case["transaction"]["intent"]["action"] != "state-prime" for case in cases[:20]
    ):
        raise ValueError("sequence campaign must begin with exactly 20 state-prime cases")

    measured = []
    for case, result in zip(cases[20:], results[20:], strict=True):
        action = case["transaction"]["intent"]["action"]
        if not action.startswith("sequence-"):
            raise ValueError("sequence campaign measured cases require sequence actions")
        operation = action.removeprefix("sequence-")
        if operation not in OPERATIONS:
            raise ValueError("sequence campaign contains an unsupported operation")
        measured.append((case, result, operation))

    expected_sequence = _de_bruijn_order_two()
    if [item[2] for item in measured] != expected_sequence:
        raise ValueError("sequence campaign does not match the fixed ordered covering sequence")
    requesters = [item[0]["transaction"]["intent"]["requester_id"] for item in measured]
    if len(set(requesters)) != len(expected_sequence):
        raise ValueError("sequence campaign measured cases require isolated requester scopes")

    operation_results = []
    passed_operations = 0
    for case, result, operation in measured:
        passed = (
            result["expected_decision"] == EXPECTED_DECISIONS[operation]
            and result["expected_reason_code"] == EXPECTED_REASONS[operation]
            and result["status"] == "pass"
        )
        passed_operations += int(passed)
        operation_results.append(
            {
                "case_id": case["case_id"],
                "operation": operation,
                "expected_decision": result["expected_decision"],
                "expected_reason_code": result["expected_reason_code"],
                "submitted_decision": result["submitted_decision"],
                "submitted_reason_code": result["submitted_reason_code"],
                "status": "pass" if passed else "fail",
            }
        )

    covered_pairs = sorted(
        {
            f"{left}>{right}"
            for left, right in zip(expected_sequence, expected_sequence[1:], strict=False)
        }
    )
    required_pairs = sorted(f"{left}>{right}" for left in OPERATIONS for right in OPERATIONS)
    missing_pairs = [item for item in required_pairs if item not in covered_pairs]
    complete = not missing_pairs and len(covered_pairs) == len(required_pairs)
    score_passed = score["summary"]["verdict"] == "pass"
    return {
        "schema": ASSURANCE_SCHEMA,
        "schema_version": 1,
        "report_id": f"{score['score_id']}-sequence",
        "evaluated_at": score["evaluated_at"],
        "method": {
            "name": "cyclic-de-bruijn-ordered-operation-coverage",
            "strength": 2,
            "operation_alphabet": list(OPERATIONS),
        },
        "score_sha256": _sha256(_canonical(score)),
        "score": score,
        "operation_results": operation_results,
        "ordered_pair_coverage": {
            "required_pairs": required_pairs,
            "covered_pairs": covered_pairs,
            "missing_pairs": missing_pairs,
        },
        "summary": {
            "verdict": "pass"
            if score_passed and passed_operations == len(measured) and complete
            else "fail",
            "score_verdict": score["summary"]["verdict"],
            "preamble_case_count": 20,
            "measured_case_count": len(measured),
            "passed_measured_case_count": passed_operations,
            "operation_count": len(OPERATIONS),
            "required_ordered_pair_count": len(required_pairs),
            "covered_ordered_pair_count": len(covered_pairs),
            "ordered_pair_coverage_complete": complete,
        },
        "limitations": list(LIMITATIONS),
    }


def validate_sequence_mandate_assurance(value: Any) -> Dict[str, Any]:
    report = _exact(
        value,
        "LureMandate sequence assurance",
        (
            "schema",
            "schema_version",
            "report_id",
            "evaluated_at",
            "method",
            "score_sha256",
            "score",
            "operation_results",
            "ordered_pair_coverage",
            "summary",
            "limitations",
        ),
    )
    if report["schema"] != ASSURANCE_SCHEMA or report["schema_version"] != 1:
        raise ValueError("unsupported LureMandate sequence assurance schema")
    _id(report["report_id"], "sequence report_id")
    if report != _producer_value(report["score"]):
        raise ValueError("LureMandate sequence assurance does not independently reproduce")
    return dict(report)


def _verification_value(payload: bytes, *, verified_at: str) -> Dict[str, Any]:
    report = validate_sequence_mandate_assurance(
        _strict(payload, "LureMandate sequence assurance")
    )
    if _instant(verified_at, "verified_at") < _instant(
        report["evaluated_at"], "sequence evaluated_at"
    ):
        raise ValueError("sequence verification predates the producer report")
    summary = dict(report["summary"])
    summary.update({"source_document_reparsed": True, "producer_report_reproduced": True})
    return {
        "schema": VERIFICATION_SCHEMA,
        "schema_version": 1,
        "verification_id": f"{report['report_id']}-verification",
        "verified_at": verified_at,
        "engine": {
            "name": "lurescope-luremandate-sequence-independent",
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


def create_sequence_mandate_verification(
    report_path: Path,
    output_path: Path,
    *,
    verified_at: Optional[str] = None,
) -> Dict[str, Any]:
    payload = _read(report_path, "LureMandate sequence assurance", MAX_REPORT_BYTES)
    result = _verification_value(payload, verified_at=verified_at or _now())
    encoded = _canonical(validate_sequence_mandate_verification(result))
    if len(encoded) > MAX_VERIFICATION_BYTES:
        raise ValueError("sequence verification exceeds its size limit")
    _write_new(Path(output_path), encoded)
    return result


def validate_sequence_mandate_verification(value: Any) -> Dict[str, Any]:
    verification = _exact(
        value,
        "LureMandate sequence verification",
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
        raise ValueError("unsupported LureMandate sequence verification schema")
    _id(verification["verification_id"], "sequence verification_id")
    if verification["engine"] != {
        "name": "lurescope-luremandate-sequence-independent",
        "version": __version__,
    }:
        raise ValueError("unsupported sequence verifier engine")
    if verification["checks"] != CHECKS or verification["limitations"] != VERIFICATION_LIMITATIONS:
        raise ValueError("sequence verification checks or limitations are incomplete")
    payload = _document(verification["document"], "embedded sequence report")
    expected = _verification_value(payload, verified_at=verification["verified_at"])
    if verification != expected:
        raise ValueError("LureMandate sequence verification does not independently reproduce")
    return dict(verification)


def load_sequence_mandate_verification(path: Path) -> Dict[str, Any]:
    return validate_sequence_mandate_verification(
        _strict(
            _read(path, "LureMandate sequence verification", MAX_VERIFICATION_BYTES),
            "LureMandate sequence verification",
        )
    )
