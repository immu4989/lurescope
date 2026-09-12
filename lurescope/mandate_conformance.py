"""Independent verification of answer-free LureMandate conformance scores."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from . import __version__
from .mandate import (
    LIMITATIONS as MANDATE_LIMITATIONS,
)
from .mandate import (
    PRIVACY,
    REASONS,
    RUN_SCHEMA,
    _bounded,
    _claims_boundary,
    _derive,
    _document,
    _encode,
    _instant,
    _now,
    _read,
    _sha256,
    validate_mandate_plan,
    validate_mandate_run,
)
from .permit import _canonical, _exact, _id, _strict, _write_new

CHALLENGE_SCHEMA = "https://github.com/immu4989/lurebench/spec/luremandate-conformance-challenge/v1"
SUBMISSION_SCHEMA = (
    "https://github.com/immu4989/lurebench/spec/luremandate-conformance-submission/v1"
)
SCORE_SCHEMA = "https://github.com/immu4989/lurebench/spec/luremandate-conformance-score/v1"
VERIFICATION_SCHEMA = (
    "https://github.com/immu4989/lurescope/spec/luremandate-conformance-verification/v1"
)
PRODUCER_VERSION = "1.0.0"
STATE_MODEL = "single_session_ordered_no_reset"
MAX_REPORT_BYTES = 32 * 1024 * 1024
CONFORMANCE_LIMITATIONS = [
    "challenge_omits_expected_decisions_and_reasons_but_does_not_prevent_input_inference",
    "cases_measure_only_declared_metadata_and_stateful_order_not_unrepresented_actions",
    "reference_submission_tests_the_reference_semantics_not_an_external_gateway",
    "engine_identity_and_submitted_results_are_claims_unless_authenticated_externally",
    "passing_is_not_complete_mediation_safety_compliance_or_deployment_authorization",
]
VERIFICATION_CHECKS = [
    "strict_challenge_submission_and_score_json_reparsed",
    "answer_free_challenge_shape_rechecked",
    "canonical_challenge_and_submission_bindings_recomputed",
    "complete_ordered_submission_coverage_rechecked",
    "single_session_replay_and_budget_state_recomputed",
    "every_expected_decision_and_reason_independently_derived",
    "invalid_allow_and_collateral_denial_counts_recomputed",
    "producer_conformance_score_reproduced",
]
VERIFICATION_LIMITATIONS = [
    "independent_recomputation_does_not_authenticate_the_submitting_engine",
    "answer_omission_does_not_prevent_a_knowledgeable_implementer_from_inferring_answers",
    "coverage_is_limited_to_submitted_ordered_cases_and_reported_reason_codes",
    "verification_does_not_establish_omitted_action_discovery_or_complete_mediation",
    "passing_is_not_compliance_certification_safety_or_deployment_authorization",
]


def _digest(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _engine(value: Any, field: str) -> Dict[str, Any]:
    engine = _exact(value, field, ("engine_id", "engine_version", "engine_artifact_sha256"))
    _id(engine["engine_id"], f"{field}.engine_id")
    _id(engine["engine_version"], f"{field}.engine_version")
    if engine["engine_artifact_sha256"] is not None:
        _digest(engine["engine_artifact_sha256"], f"{field}.engine_artifact_sha256")
    return dict(engine)


def _run_from_challenge(
    challenge: Mapping[str, Any],
    engine: Mapping[str, Any],
    answers: Optional[Mapping[str, Mapping[str, str]]] = None,
) -> Dict[str, Any]:
    transactions = []
    for case in challenge["cases"]:
        answer = (
            answers[case["case_id"]]
            if answers is not None
            else {"decision": "block", "reason_code": "policy_unknown"}
        )
        transaction = case["transaction"]
        transactions.append(
            {
                "transaction_id": transaction["transaction_id"],
                "sequence": case["sequence"],
                "intent": transaction["intent"],
                "intent_sha256": transaction["intent_sha256"],
                "approvals": transaction["approvals"],
                "decision": {
                    "decision_id": f"{case['case_id']}-decision",
                    "decided_at": transaction["decided_at"],
                    "decision": answer["decision"],
                    "reason_code": answer["reason_code"],
                },
                "outcome": {
                    "state": "not_attempted",
                    "observed_at": None,
                    "sensor_id": None,
                },
            }
        )
    execution = challenge["execution"]
    return {
        "schema": RUN_SCHEMA,
        "schema_version": 1,
        "run_id": execution["run_id"],
        "campaign_id": challenge["campaign_id"],
        "plan_sha256": challenge["plan_sha256"],
        "started_at": execution["started_at"],
        "completed_at": execution["completed_at"],
        "engine": dict(engine),
        "transactions": transactions,
        "privacy": dict(PRIVACY),
        "limitations": list(MANDATE_LIMITATIONS),
    }


def validate_mandate_conformance_challenge(value: Any) -> Dict[str, Any]:
    challenge = _exact(
        value,
        "LureMandate conformance challenge",
        (
            "schema",
            "schema_version",
            "challenge_id",
            "generated_at",
            "campaign_id",
            "plan_sha256",
            "plan",
            "execution",
            "cases",
            "privacy",
            "limitations",
        ),
    )
    if challenge["schema"] != CHALLENGE_SCHEMA or challenge["schema_version"] != 1:
        raise ValueError("unsupported LureMandate conformance challenge schema")
    _id(challenge["challenge_id"], "challenge_id")
    generated = _instant(challenge["generated_at"], "generated_at")
    _id(challenge["campaign_id"], "campaign_id")
    _digest(challenge["plan_sha256"], "plan_sha256")
    plan = validate_mandate_plan(challenge["plan"])
    if challenge["campaign_id"] != plan["campaign_id"] or challenge["plan_sha256"] != _sha256(
        _canonical(plan)
    ):
        raise ValueError("conformance challenge does not bind its embedded plan")
    execution = _exact(
        challenge["execution"],
        "challenge execution",
        ("run_id", "started_at", "completed_at", "state_model"),
    )
    _id(execution["run_id"], "execution.run_id")
    started = _instant(execution["started_at"], "execution.started_at")
    completed = _instant(execution["completed_at"], "execution.completed_at")
    if completed < started or generated < completed:
        raise ValueError("conformance challenge has an invalid execution chronology")
    if execution["state_model"] != STATE_MODEL:
        raise ValueError("conformance challenge requires one ordered stateful session")
    for index, item in enumerate(_bounded(challenge["cases"], "cases", 4096)):
        case = _exact(item, f"cases[{index}]", ("case_id", "sequence", "transaction"))
        if case["case_id"] != f"case-{index + 1:04d}" or case["sequence"] != index + 1:
            raise ValueError("conformance cases must use opaque contiguous order")
        transaction = _exact(
            case["transaction"],
            f"cases[{index}].transaction",
            (
                "transaction_id",
                "intent",
                "intent_sha256",
                "approvals",
                "decided_at",
            ),
        )
        _id(transaction["transaction_id"], "transaction_id")
        _digest(transaction["intent_sha256"], "intent_sha256")
        _instant(transaction["decided_at"], "decided_at")
    if challenge["privacy"] != PRIVACY:
        raise ValueError("conformance challenge changed the metadata-only privacy profile")
    _claims_boundary(challenge["limitations"], CONFORMANCE_LIMITATIONS, "challenge limitations")
    validate_mandate_run(
        _run_from_challenge(
            challenge,
            {
                "engine_id": "unscored-gateway",
                "engine_version": "0",
                "engine_artifact_sha256": None,
            },
        ),
        plan,
    )
    return dict(challenge)


def validate_mandate_conformance_submission(
    value: Any, challenge_value: Mapping[str, Any]
) -> Dict[str, Any]:
    challenge = validate_mandate_conformance_challenge(challenge_value)
    submission = _exact(
        value,
        "LureMandate conformance submission",
        (
            "schema",
            "schema_version",
            "submission_id",
            "submitted_at",
            "challenge_id",
            "challenge_sha256",
            "engine",
            "results",
            "limitations",
        ),
    )
    if submission["schema"] != SUBMISSION_SCHEMA or submission["schema_version"] != 1:
        raise ValueError("unsupported LureMandate conformance submission schema")
    _id(submission["submission_id"], "submission_id")
    if _instant(submission["submitted_at"], "submitted_at") < _instant(
        challenge["generated_at"], "challenge generated_at"
    ):
        raise ValueError("conformance submission predates its challenge")
    _id(submission["challenge_id"], "challenge_id")
    _digest(submission["challenge_sha256"], "challenge_sha256")
    if submission["challenge_id"] != challenge["challenge_id"] or submission[
        "challenge_sha256"
    ] != _sha256(_canonical(challenge)):
        raise ValueError("conformance submission does not bind the supplied challenge")
    _engine(submission["engine"], "submission engine")
    results = _bounded(submission["results"], "submission results", 4096)
    if len(results) != len(challenge["cases"]):
        raise ValueError("submission must cover every challenge case exactly once")
    for index, (item, case) in enumerate(zip(results, challenge["cases"], strict=True)):
        result = _exact(item, f"results[{index}]", ("case_id", "decision", "reason_code"))
        if result["case_id"] != case["case_id"]:
            raise ValueError("submission results must preserve challenge case order")
        if result["decision"] not in {"allow", "block"} or result["reason_code"] not in REASONS:
            raise ValueError("submission contains an unsupported decision or reason")
    _claims_boundary(submission["limitations"], CONFORMANCE_LIMITATIONS, "submission limitations")
    return dict(submission)


def _score_value(
    challenge_value: Mapping[str, Any],
    submission_value: Mapping[str, Any],
    *,
    evaluated_at: str,
) -> Dict[str, Any]:
    challenge = validate_mandate_conformance_challenge(challenge_value)
    submission = validate_mandate_conformance_submission(submission_value, challenge)
    if _instant(evaluated_at, "evaluated_at") < max(
        _instant(challenge["generated_at"], "challenge generated_at"),
        _instant(submission["submitted_at"], "submission submitted_at"),
    ):
        raise ValueError("conformance score predates its challenge or submission")
    answers = {item["case_id"]: item for item in submission["results"]}
    run = _run_from_challenge(challenge, submission["engine"], answers)
    evaluation = _derive(challenge["plan"], run, evaluated_at)
    results = []
    decision_matches = reason_matches = exact_matches = 0
    invalid_allows = collateral_denials = 0
    reason_counts: Dict[str, int] = {}
    for case, item in zip(challenge["cases"], evaluation["results"], strict=True):
        decision_match = item["submitted_decision"] == item["expected_decision"]
        reason_match = item["submitted_reason_code"] == item["expected_reason_code"]
        exact_match = decision_match and reason_match
        decision_matches += int(decision_match)
        reason_matches += int(reason_match)
        exact_matches += int(exact_match)
        invalid_allows += int(
            item["expected_decision"] == "block" and item["submitted_decision"] == "allow"
        )
        collateral_denials += int(
            item["expected_decision"] == "allow" and item["submitted_decision"] == "block"
        )
        reason_counts[item["expected_reason_code"]] = (
            reason_counts.get(item["expected_reason_code"], 0) + 1
        )
        results.append(
            {
                "case_id": case["case_id"],
                "sequence": case["sequence"],
                "expected_decision": item["expected_decision"],
                "expected_reason_code": item["expected_reason_code"],
                "submitted_decision": item["submitted_decision"],
                "submitted_reason_code": item["submitted_reason_code"],
                "decision_match": decision_match,
                "reason_match": reason_match,
                "status": "pass" if exact_match else "fail",
            }
        )
    case_count = len(results)
    summary = {
        "verdict": "pass" if exact_matches == case_count else "fail",
        "case_count": case_count,
        "exact_match_count": exact_matches,
        "decision_match_count": decision_matches,
        "reason_match_count": reason_matches,
        "invalid_allow_count": invalid_allows,
        "collateral_denial_count": collateral_denials,
        "covered_reason_count": len(reason_counts),
        "reason_universe_count": len(REASONS),
        "reason_coverage_complete": set(reason_counts) == REASONS,
    }
    return {
        "schema": SCORE_SCHEMA,
        "schema_version": 1,
        "score_id": f"{submission['submission_id']}-score",
        "evaluated_at": evaluated_at,
        "evaluator": {
            "name": "lurebench-luremandate-conformance",
            "version": PRODUCER_VERSION,
        },
        "challenge_sha256": _sha256(_canonical(challenge)),
        "submission_sha256": _sha256(_canonical(submission)),
        "challenge": challenge,
        "submission": submission,
        "results": results,
        "guard_coverage": [
            {"expected_reason_code": reason, "case_count": reason_counts.get(reason, 0)}
            for reason in sorted(REASONS)
        ],
        "summary": summary,
        "limitations": list(CONFORMANCE_LIMITATIONS),
    }


def validate_mandate_conformance_score(value: Any) -> Dict[str, Any]:
    score = _exact(
        value,
        "LureMandate conformance score",
        (
            "schema",
            "schema_version",
            "score_id",
            "evaluated_at",
            "evaluator",
            "challenge_sha256",
            "submission_sha256",
            "challenge",
            "submission",
            "results",
            "guard_coverage",
            "summary",
            "limitations",
        ),
    )
    if score["schema"] != SCORE_SCHEMA or score["schema_version"] != 1:
        raise ValueError("unsupported LureMandate conformance score schema")
    expected = _score_value(
        score["challenge"], score["submission"], evaluated_at=score["evaluated_at"]
    )
    if score != expected:
        raise ValueError("producer LureMandate conformance score does not independently reproduce")
    return dict(score)


def _verification_value(
    challenge_payload: bytes,
    submission_payload: bytes,
    score_payload: bytes,
    *,
    verified_at: str,
) -> Dict[str, Any]:
    challenge = validate_mandate_conformance_challenge(
        _strict(challenge_payload, "LureMandate conformance challenge")
    )
    submission = validate_mandate_conformance_submission(
        _strict(submission_payload, "LureMandate conformance submission"), challenge
    )
    score = validate_mandate_conformance_score(
        _strict(score_payload, "LureMandate conformance score")
    )
    if score["challenge"] != challenge or score["submission"] != submission:
        raise ValueError("conformance score does not embed the supplied challenge and submission")
    if _instant(verified_at, "verified_at") < _instant(score["evaluated_at"], "evaluated_at"):
        raise ValueError("conformance verification predates the producer score")
    summary = dict(score["summary"])
    summary.update(
        {
            "source_documents_reparsed": True,
            "producer_score_reproduced": True,
            "answer_free_challenge_rechecked": True,
        }
    )
    return {
        "schema": VERIFICATION_SCHEMA,
        "schema_version": 1,
        "verification_id": f"{score['score_id']}-verification",
        "verified_at": verified_at,
        "engine": {
            "name": "lurescope-luremandate-conformance-independent",
            "version": __version__,
        },
        "documents": {
            "challenge": {
                "document_sha256": _sha256(challenge_payload),
                "payload_base64": _encode(challenge_payload),
            },
            "submission": {
                "document_sha256": _sha256(submission_payload),
                "payload_base64": _encode(submission_payload),
            },
            "score": {
                "document_sha256": _sha256(score_payload),
                "payload_base64": _encode(score_payload),
            },
        },
        "producer_score": score,
        "checks": list(VERIFICATION_CHECKS),
        "summary": summary,
        "limitations": list(VERIFICATION_LIMITATIONS),
    }


def validate_mandate_conformance_verification(value: Any) -> Dict[str, Any]:
    verification = _exact(
        value,
        "LureMandate conformance verification",
        (
            "schema",
            "schema_version",
            "verification_id",
            "verified_at",
            "engine",
            "documents",
            "producer_score",
            "checks",
            "summary",
            "limitations",
        ),
    )
    if verification["schema"] != VERIFICATION_SCHEMA or verification["schema_version"] != 1:
        raise ValueError("unsupported LureMandate conformance verification schema")
    _id(verification["verification_id"], "verification_id")
    if _exact(verification["engine"], "engine", ("name", "version")) != {
        "name": "lurescope-luremandate-conformance-independent",
        "version": __version__,
    }:
        raise ValueError("unsupported LureMandate conformance verifier engine")
    if verification["checks"] != VERIFICATION_CHECKS:
        raise ValueError("LureMandate conformance verification check set is incomplete")
    _claims_boundary(
        verification["limitations"],
        VERIFICATION_LIMITATIONS,
        "verification limitations",
    )
    documents = _exact(verification["documents"], "documents", ("challenge", "submission", "score"))
    expected = _verification_value(
        _document(documents["challenge"], "embedded challenge"),
        _document(documents["submission"], "embedded submission"),
        _document(documents["score"], "embedded score"),
        verified_at=verification["verified_at"],
    )
    if verification != expected:
        raise ValueError("LureMandate conformance verification does not independently reproduce")
    return dict(verification)


def create_mandate_conformance_verification(
    challenge_path: Path,
    submission_path: Path,
    score_path: Path,
    output_path: Path,
    *,
    verified_at: Optional[str] = None,
) -> Dict[str, Any]:
    result = _verification_value(
        _read(challenge_path, "LureMandate conformance challenge"),
        _read(submission_path, "LureMandate conformance submission"),
        _read(score_path, "LureMandate conformance score"),
        verified_at=verified_at or _now(),
    )
    payload = _canonical(validate_mandate_conformance_verification(result))
    if len(payload) > MAX_REPORT_BYTES:
        raise ValueError("LureMandate conformance verification exceeds its size limit")
    _write_new(Path(output_path), payload)
    return result


def load_mandate_conformance_verification(path: Path) -> Dict[str, Any]:
    return validate_mandate_conformance_verification(
        _strict(
            _read(path, "LureMandate conformance verification", MAX_REPORT_BYTES),
            "LureMandate conformance verification",
        )
    )
