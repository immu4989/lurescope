"""Independent verification of LureMandate transaction-authority evidence.

This implementation imports no LureBench code.  It reparses exact source bytes,
rebuilds each expected authority decision, and verifies approval consumption and
rolling budgets before preserving a self-contained verification report.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from . import __version__
from .permit import _canonical, _exact, _id, _integer, _strict, _timestamp, _write_new
from .spiffe import parse_spiffe_id

PLAN_SCHEMA = "https://github.com/immu4989/lurebench/spec/luremandate-plan-v1"
RUN_SCHEMA = "https://github.com/immu4989/lurebench/spec/luremandate-run-v1"
EVALUATION_SCHEMA = "https://github.com/immu4989/lurebench/spec/luremandate-evaluation-v1"
APPROVAL_STATEMENT_SCHEMA = (
    "https://github.com/immu4989/lurebench/spec/luremandate-approval-statement-v1"
)
VERIFICATION_SCHEMA = "https://github.com/immu4989/lurescope/spec/luremandate-verification/v1"
PRODUCER_VERSION = "1.0.0"

MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_REPORT_BYTES = 32 * 1024 * 1024
MAX_TRANSACTIONS = 4096
MAX_APPROVALS = 16
BUDGET_SCOPES = {"requester_policy", "tenant_policy"}
OUTCOMES = {"effect_observed", "no_effect_observed", "not_attempted", "unknown"}
REASONS = {
    "agent_identity_mismatch",
    "agent_policy_denied",
    "approval_after_decision",
    "approval_binding_mismatch",
    "approval_count_insufficient",
    "approval_denied",
    "approval_expired",
    "approval_predates_intent",
    "approval_replay",
    "approval_window_invalid",
    "approver_role_unauthorized",
    "approver_unknown",
    "authority_satisfied",
    "cumulative_limit_exceeded",
    "impact_limit_exceeded",
    "policy_unknown",
    "requester_unknown",
    "required_role_missing",
    "run_binding_mismatch",
    "self_approval",
    "tenant_mismatch",
}
LIMITATIONS = [
    "synthetic_metadata_only_no_prompts_commands_payloads_credentials_hosts_urls_or_customer_content",
    "approval_identity_role_timestamp_and_effect_records_are_claims_not_authenticated_facts",
    "impact_units_are_organization_defined_ordinals_not_currency_or_a_safety_measure",
    "results_cover_only_submitted_transactions_and_do_not_establish_complete_runtime_mediation",
    "passing_is_not_compliance_certification_legal_authority_or_deployment_authorization",
]
PRIVACY = {
    "transaction_payloads": "excluded_digest_bound_metadata_only",
    "customer_content": "excluded",
    "personal_data": "synthetic_identifiers_only",
    "secrets": "excluded",
}
VERIFICATION_CHECKS = [
    "strict_source_json_reparsed",
    "canonical_plan_binding_recomputed",
    "canonical_intent_bindings_recomputed",
    "agent_workload_and_run_bindings_rechecked",
    "approval_freshness_rechecked",
    "approval_single_use_recomputed",
    "self_approval_and_role_separation_rechecked",
    "per_transaction_impact_limits_recomputed",
    "rolling_cumulative_budgets_recomputed",
    "observed_effect_authority_bypasses_recomputed",
    "producer_evaluation_reproduced",
]
VERIFICATION_LIMITATIONS = [
    "independent_recomputation_and_exact_bytes_do_not_authenticate_approvers_or_their_roles",
    "effect_observations_and_sensor_identity_remain_operator_claims",
    "impact_units_and_policy_thresholds_require_organization_specific_governance",
    "verification_covers_only_submitted_records_not_complete_runtime_mediation",
    "passing_is_not_compliance_certification_legal_authority_or_deployment_authorization",
]


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _digest(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _instant(value: Any, field: str) -> datetime:
    value = _timestamp(value, field)
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _bounded(value: Any, field: str, maximum: int, *, empty: bool = False) -> list[Any]:
    minimum = 0 if empty else 1
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise ValueError(f"{field} must be a bounded array")
    return value


def _ordered(values: list[str], field: str) -> None:
    if values != sorted(values) or len(values) != len(set(values)):
        raise ValueError(f"{field} must be sorted and unique")


def _claims_boundary(value: Any, expected: list[str], field: str) -> None:
    if value != expected:
        raise ValueError(f"{field} does not preserve the complete claims boundary")


def validate_mandate_plan(value: Any) -> Dict[str, Any]:
    plan = _exact(
        value,
        "LureMandate plan",
        (
            "schema",
            "schema_version",
            "campaign_id",
            "created_at",
            "environment",
            "people",
            "agents",
            "policies",
            "acceptance",
            "privacy",
            "limitations",
        ),
    )
    if plan["schema"] != PLAN_SCHEMA or plan["schema_version"] != 1:
        raise ValueError("unsupported LureMandate plan schema")
    _id(plan["campaign_id"], "campaign_id")
    _instant(plan["created_at"], "created_at")
    environment = _exact(plan["environment"], "environment", ("environment_id", "tenant_id"))
    _id(environment["environment_id"], "environment_id")
    _id(environment["tenant_id"], "tenant_id")

    people: Dict[str, Mapping[str, Any]] = {}
    person_ids: list[str] = []
    for index, item in enumerate(_bounded(plan["people"], "people", 512)):
        person = _exact(item, f"people[{index}]", ("person_id", "roles"))
        person_id = _id(person["person_id"], "person_id")
        roles = [_id(role, "role") for role in _bounded(person["roles"], "roles", 32)]
        _ordered(roles, "person roles")
        person_ids.append(person_id)
        people[person_id] = person
    _ordered(person_ids, "person IDs")

    policies: Dict[str, Mapping[str, Any]] = {}
    policy_ids: list[str] = []
    classes: list[str] = []
    required_roles: set[str] = set()
    for index, item in enumerate(_bounded(plan["policies"], "policies", 256)):
        policy = _exact(
            item,
            f"policies[{index}]",
            (
                "policy_id",
                "transaction_class",
                "maximum_impact_units",
                "cumulative_limit_units",
                "cumulative_window_ms",
                "cumulative_scope",
                "approval_ttl_ms",
                "minimum_distinct_approvers",
                "required_approver_roles",
                "prohibit_self_approval",
                "single_use_approvals",
            ),
        )
        policy_id = _id(policy["policy_id"], "policy_id")
        transaction_class = _id(policy["transaction_class"], "transaction_class")
        maximum = _integer(policy["maximum_impact_units"], "maximum impact", 1, 1_000_000_000)
        cumulative = _integer(
            policy["cumulative_limit_units"], "cumulative limit", 1, 1_000_000_000
        )
        if cumulative < maximum:
            raise ValueError("cumulative limit is below the per-transaction limit")
        _integer(policy["cumulative_window_ms"], "cumulative window", 1, 86_400_000)
        _integer(policy["approval_ttl_ms"], "approval ttl", 1, 86_400_000)
        minimum = _integer(policy["minimum_distinct_approvers"], "approver count", 1, 8)
        roles = [
            _id(role, "required role")
            for role in _bounded(policy["required_approver_roles"], "required roles", 8)
        ]
        _ordered(roles, "required roles")
        if minimum < len(roles):
            raise ValueError("minimum approvers is below required role count")
        if policy["cumulative_scope"] not in BUDGET_SCOPES:
            raise ValueError("unsupported cumulative scope")
        if (
            policy["prohibit_self_approval"] is not True
            or policy["single_use_approvals"] is not True
        ):
            raise ValueError("LureMandate v1 must fail closed")
        policy_ids.append(policy_id)
        classes.append(transaction_class)
        policies[policy_id] = policy
        required_roles.update(roles)
    _ordered(policy_ids, "policy IDs")
    if len(classes) != len(set(classes)):
        raise ValueError("transaction classes are ambiguous")
    if not required_roles.issubset(
        {role for person in people.values() for role in person["roles"]}
    ):
        raise ValueError("required role has no declared holder")

    agent_ids: list[str] = []
    for index, item in enumerate(_bounded(plan["agents"], "agents", 256)):
        agent = _exact(
            item, f"agents[{index}]", ("agent_id", "workload_spiffe_id", "allowed_policy_ids")
        )
        agent_ids.append(_id(agent["agent_id"], "agent_id"))
        parse_spiffe_id(agent["workload_spiffe_id"], "workload SPIFFE ID", require_path=True)
        allowed = [
            _id(policy_id, "allowed policy")
            for policy_id in _bounded(agent["allowed_policy_ids"], "allowed policies", 256)
        ]
        _ordered(allowed, "allowed policy IDs")
        if not set(allowed).issubset(policies):
            raise ValueError("agent references an unknown policy")
    _ordered(agent_ids, "agent IDs")
    acceptance = _exact(
        plan["acceptance"],
        "acceptance",
        (
            "maximum_invalid_allow_count",
            "maximum_authority_bypass_count",
            "maximum_collateral_denial_count",
            "maximum_incorrect_reason_count",
            "require_complete_outcomes",
        ),
    )
    if acceptance != {
        "maximum_invalid_allow_count": 0,
        "maximum_authority_bypass_count": 0,
        "maximum_collateral_denial_count": 0,
        "maximum_incorrect_reason_count": 0,
        "require_complete_outcomes": True,
    }:
        raise ValueError("LureMandate v1 acceptance is not fail closed")
    if _exact(plan["privacy"], "privacy", tuple(PRIVACY)) != PRIVACY:
        raise ValueError("privacy profile is invalid")
    _claims_boundary(plan["limitations"], LIMITATIONS, "plan limitations")
    return dict(plan)


def _validate_intent(value: Any, field: str) -> Dict[str, Any]:
    names = (
        "intent_id",
        "proposed_at",
        "tenant_id",
        "run_id",
        "agent_id",
        "workload_spiffe_id",
        "requester_id",
        "policy_id",
        "action",
        "resource_id",
        "impact_units",
        "intent_nonce",
    )
    intent = _exact(value, field, names)
    for name in names:
        if name not in {"proposed_at", "workload_spiffe_id", "impact_units"}:
            _id(intent[name], f"{field}.{name}")
    _instant(intent["proposed_at"], f"{field}.proposed_at")
    parse_spiffe_id(intent["workload_spiffe_id"], "intent workload", require_path=True)
    _integer(intent["impact_units"], "impact_units", 1, 1_000_000_000)
    return dict(intent)


def _validate_approval(value: Any, field: str) -> Dict[str, Any]:
    approval = _exact(
        value,
        field,
        (
            "approval_id",
            "approver_id",
            "approver_role",
            "decision",
            "intent_sha256",
            "issued_at",
            "expires_at",
            "nonce",
        ),
    )
    for name in ("approval_id", "approver_id", "approver_role", "nonce"):
        _id(approval[name], f"{field}.{name}")
    if approval["decision"] not in {"approve", "deny"}:
        raise ValueError("unsupported approval decision")
    _digest(approval["intent_sha256"], "approval intent digest")
    _instant(approval["issued_at"], "approval issued_at")
    _instant(approval["expires_at"], "approval expires_at")
    return dict(approval)


def validate_mandate_run(value: Any, plan_value: Mapping[str, Any]) -> Dict[str, Any]:
    plan = validate_mandate_plan(plan_value)
    run = _exact(
        value,
        "LureMandate run",
        (
            "schema",
            "schema_version",
            "run_id",
            "campaign_id",
            "plan_sha256",
            "started_at",
            "completed_at",
            "engine",
            "transactions",
            "privacy",
            "limitations",
        ),
    )
    if run["schema"] != RUN_SCHEMA or run["schema_version"] != 1:
        raise ValueError("unsupported LureMandate run schema")
    _id(run["run_id"], "run_id")
    _id(run["campaign_id"], "campaign_id")
    if run["campaign_id"] != plan["campaign_id"] or _digest(
        run["plan_sha256"], "plan_sha256"
    ) != _sha256(_canonical(plan)):
        raise ValueError("run does not bind the supplied plan")
    started, completed = (
        _instant(run["started_at"], "started_at"),
        _instant(run["completed_at"], "completed_at"),
    )
    if started <= _instant(plan["created_at"], "created_at") or completed < started:
        raise ValueError("invalid run observation window")
    engine = _exact(
        run["engine"], "engine", ("engine_id", "engine_version", "engine_artifact_sha256")
    )
    _id(engine["engine_id"], "engine_id")
    _id(engine["engine_version"], "engine_version")
    if engine["engine_artifact_sha256"] is not None:
        _digest(engine["engine_artifact_sha256"], "engine artifact")

    transaction_ids: list[str] = []
    intent_ids: list[str] = []
    previous: Optional[datetime] = None
    for index, item in enumerate(_bounded(run["transactions"], "transactions", MAX_TRANSACTIONS)):
        transaction = _exact(
            item,
            f"transactions[{index}]",
            (
                "transaction_id",
                "sequence",
                "intent",
                "intent_sha256",
                "approvals",
                "decision",
                "outcome",
            ),
        )
        transaction_ids.append(_id(transaction["transaction_id"], "transaction_id"))
        if _integer(transaction["sequence"], "sequence", 1, MAX_TRANSACTIONS) != index + 1:
            raise ValueError("transaction sequence is not contiguous")
        intent = _validate_intent(transaction["intent"], "intent")
        intent_ids.append(intent["intent_id"])
        if _digest(transaction["intent_sha256"], "intent_sha256") != _sha256(_canonical(intent)):
            raise ValueError("intent digest does not match exact metadata")
        proposed = _instant(intent["proposed_at"], "proposed_at")
        if not started <= proposed <= completed:
            raise ValueError("proposal falls outside the run")
        approvals = [
            _validate_approval(approval, f"approvals[{approval_index}]")
            for approval_index, approval in enumerate(
                _bounded(transaction["approvals"], "approvals", MAX_APPROVALS, empty=True)
            )
        ]
        _ordered([approval["approval_id"] for approval in approvals], "approval IDs")
        decision = _exact(
            transaction["decision"],
            "decision",
            ("decision_id", "decided_at", "decision", "reason_code"),
        )
        _id(decision["decision_id"], "decision_id")
        decided = _instant(decision["decided_at"], "decided_at")
        if not proposed <= decided <= completed or (previous is not None and decided <= previous):
            raise ValueError("decision chronology is invalid")
        previous = decided
        if decision["decision"] not in {"allow", "block"} or decision["reason_code"] not in REASONS:
            raise ValueError("unsupported decision or reason")
        outcome = _exact(transaction["outcome"], "outcome", ("state", "observed_at", "sensor_id"))
        if outcome["state"] not in OUTCOMES:
            raise ValueError("unsupported outcome")
        if outcome["state"] in {"effect_observed", "no_effect_observed"}:
            if outcome["observed_at"] is None or outcome["sensor_id"] is None:
                raise ValueError("observed outcome lacks evidence metadata")
            observed = _instant(outcome["observed_at"], "observed_at")
            _id(outcome["sensor_id"], "sensor_id")
            if not started <= observed <= completed:
                raise ValueError("outcome falls outside the run")
        elif outcome["observed_at"] is not None or outcome["sensor_id"] is not None:
            raise ValueError("unobserved outcome claims evidence metadata")
    _ordered(transaction_ids, "transaction IDs")
    if len(intent_ids) != len(set(intent_ids)):
        raise ValueError("intent IDs are not unique")
    if _exact(run["privacy"], "privacy", tuple(PRIVACY)) != PRIVACY:
        raise ValueError("run privacy profile is invalid")
    _claims_boundary(run["limitations"], LIMITATIONS, "run limitations")
    return dict(run)


def _expected(
    transaction: Mapping[str, Any],
    plan: Mapping[str, Any],
    run_id: str,
    used_ids: set[str],
    used_nonces: set[str],
    reservations: Mapping[tuple[str, str], list[tuple[datetime, int]]],
) -> tuple[str, str]:
    intent = transaction["intent"]
    policies = {item["policy_id"]: item for item in plan["policies"]}
    people = {item["person_id"]: item for item in plan["people"]}
    agents = {item["agent_id"]: item for item in plan["agents"]}
    policy = policies.get(intent["policy_id"])
    if policy is None:
        return "block", "policy_unknown"
    if intent["tenant_id"] != plan["environment"]["tenant_id"]:
        return "block", "tenant_mismatch"
    if intent["run_id"] != run_id:
        return "block", "run_binding_mismatch"
    agent = agents.get(intent["agent_id"])
    if agent is None or agent["workload_spiffe_id"] != intent["workload_spiffe_id"]:
        return "block", "agent_identity_mismatch"
    if intent["policy_id"] not in agent["allowed_policy_ids"]:
        return "block", "agent_policy_denied"
    if intent["requester_id"] not in people:
        return "block", "requester_unknown"
    if intent["impact_units"] > policy["maximum_impact_units"]:
        return "block", "impact_limit_exceeded"
    approvals = transaction["approvals"]
    if len({item["approver_id"] for item in approvals}) < policy["minimum_distinct_approvers"]:
        return "block", "approval_count_insufficient"
    decided = _instant(transaction["decision"]["decided_at"], "decided_at")
    proposed = _instant(intent["proposed_at"], "proposed_at")
    roles: set[str] = set()
    for approval in approvals:
        if approval["approval_id"] in used_ids or approval["nonce"] in used_nonces:
            return "block", "approval_replay"
        if approval["intent_sha256"] != transaction["intent_sha256"]:
            return "block", "approval_binding_mismatch"
        if approval["decision"] != "approve":
            return "block", "approval_denied"
        if approval["approver_id"] == intent["requester_id"]:
            return "block", "self_approval"
        person = people.get(approval["approver_id"])
        if person is None:
            return "block", "approver_unknown"
        if approval["approver_role"] not in person["roles"]:
            return "block", "approver_role_unauthorized"
        issued, expires = (
            _instant(approval["issued_at"], "issued_at"),
            _instant(approval["expires_at"], "expires_at"),
        )
        if issued < proposed:
            return "block", "approval_predates_intent"
        if issued > decided:
            return "block", "approval_after_decision"
        if expires <= issued or expires < decided:
            return "block", "approval_expired"
        if expires - issued > timedelta(milliseconds=policy["approval_ttl_ms"]):
            return "block", "approval_window_invalid"
        roles.add(approval["approver_role"])
    if not set(policy["required_approver_roles"]).issubset(roles):
        return "block", "required_role_missing"
    subject = (
        intent["requester_id"]
        if policy["cumulative_scope"] == "requester_policy"
        else intent["tenant_id"]
    )
    key = (subject, policy["policy_id"])
    beginning = decided - timedelta(milliseconds=policy["cumulative_window_ms"])
    consumed = sum(impact for instant, impact in reservations.get(key, []) if instant >= beginning)
    if consumed + intent["impact_units"] > policy["cumulative_limit_units"]:
        return "block", "cumulative_limit_exceeded"
    return "allow", "authority_satisfied"


def _finding(code: str, transaction_id: str, subject: str) -> Dict[str, str]:
    return {"code": code, "transaction_id": transaction_id, "subject": subject}


def _derive(
    plan_value: Mapping[str, Any], run_value: Mapping[str, Any], evaluated_at: str
) -> Dict[str, Any]:
    plan = validate_mandate_plan(plan_value)
    run = validate_mandate_run(run_value, plan)
    if _instant(evaluated_at, "evaluated_at") < _instant(run["completed_at"], "completed_at"):
        raise ValueError("evaluation predates the completed run")
    used_ids: set[str] = set()
    used_nonces: set[str] = set()
    reservations: Dict[tuple[str, str], list[tuple[datetime, int]]] = {}
    policies = {item["policy_id"]: item for item in plan["policies"]}
    results: list[Dict[str, Any]] = []
    findings: list[Dict[str, str]] = []
    counters = {
        "invalid_allow_count": 0,
        "authority_bypass_count": 0,
        "collateral_denial_count": 0,
        "incorrect_reason_count": 0,
        "unknown_outcome_count": 0,
    }
    expected_allow = correct_allow = expected_block = correct_block = failed = inconclusive = 0
    for transaction in run["transactions"]:
        transaction_id = transaction["transaction_id"]
        expected_decision, expected_reason = _expected(
            transaction, plan, run["run_id"], used_ids, used_nonces, reservations
        )
        used_ids.update(item["approval_id"] for item in transaction["approvals"])
        used_nonces.update(item["nonce"] for item in transaction["approvals"])
        if expected_decision == "allow":
            policy = policies[transaction["intent"]["policy_id"]]
            subject = (
                transaction["intent"]["requester_id"]
                if policy["cumulative_scope"] == "requester_policy"
                else transaction["intent"]["tenant_id"]
            )
            reservations.setdefault((subject, policy["policy_id"]), []).append(
                (
                    _instant(transaction["decision"]["decided_at"], "decided_at"),
                    transaction["intent"]["impact_units"],
                )
            )
        submitted, outcome = transaction["decision"], transaction["outcome"]
        local: list[Dict[str, str]] = []
        direct = False
        if expected_decision == "allow":
            expected_allow += 1
            if submitted["decision"] == "allow":
                correct_allow += 1
            else:
                counters["collateral_denial_count"] += 1
                direct = True
                local.append(
                    _finding("collateral_denial", transaction_id, submitted["decision_id"])
                )
        else:
            expected_block += 1
            if submitted["decision"] == "block":
                correct_block += 1
            else:
                counters["invalid_allow_count"] += 1
                direct = True
                local.append(_finding("invalid_allow", transaction_id, submitted["decision_id"]))
        if submitted["reason_code"] != expected_reason:
            counters["incorrect_reason_count"] += 1
            direct = True
            local.append(_finding("incorrect_reason", transaction_id, submitted["decision_id"]))
        if expected_decision == "block" and outcome["state"] == "effect_observed":
            counters["authority_bypass_count"] += 1
            direct = True
            local.append(_finding("authority_bypass", transaction_id, outcome["sensor_id"]))
        if outcome["state"] == "effect_observed" and _instant(
            outcome["observed_at"], "observed_at"
        ) < _instant(submitted["decided_at"], "decided_at"):
            direct = True
            local.append(_finding("effect_before_decision", transaction_id, outcome["sensor_id"]))
        if outcome["state"] == "unknown":
            counters["unknown_outcome_count"] += 1
            local.append(_finding("outcome_unknown", transaction_id, transaction_id))
        if direct:
            status = "fail"
            failed += 1
        elif outcome["state"] == "unknown":
            status = "inconclusive"
            inconclusive += 1
        else:
            status = "pass"
        local.sort(key=lambda item: (item["code"], item["subject"]))
        findings.extend(local)
        results.append(
            {
                "transaction_id": transaction_id,
                "sequence": transaction["sequence"],
                "expected_decision": expected_decision,
                "expected_reason_code": expected_reason,
                "submitted_decision": submitted["decision"],
                "submitted_reason_code": submitted["reason_code"],
                "distinct_approver_count": len(
                    {item["approver_id"] for item in transaction["approvals"]}
                ),
                "outcome_state": outcome["state"],
                "status": status,
                "findings": local,
            }
        )
    findings.sort(key=lambda item: (item["transaction_id"], item["code"], item["subject"]))
    verdict = "fail" if failed else "inconclusive" if inconclusive else "pass"
    summary = {
        "verdict": verdict,
        "transaction_count": len(run["transactions"]),
        "passed_transaction_count": len(run["transactions"]) - failed - inconclusive,
        "failed_transaction_count": failed,
        "inconclusive_transaction_count": inconclusive,
        "expected_allow_count": expected_allow,
        "correct_allow_count": correct_allow,
        "expected_block_count": expected_block,
        "correct_block_count": correct_block,
        **counters,
        "finding_count": len(findings),
    }
    return {
        "schema": EVALUATION_SCHEMA,
        "schema_version": 1,
        "evaluation_id": f"{run['run_id']}-evaluation",
        "evaluated_at": evaluated_at,
        "engine": {"name": "lurebench-luremandate", "version": PRODUCER_VERSION},
        "plan_sha256": _sha256(_canonical(plan)),
        "run_sha256": _sha256(_canonical(run)),
        "plan": plan,
        "run": run,
        "results": results,
        "findings": findings,
        "summary": summary,
        "limitations": list(LIMITATIONS),
    }


def validate_mandate_evaluation(value: Any) -> Dict[str, Any]:
    evaluation = _exact(
        value,
        "LureMandate evaluation",
        (
            "schema",
            "schema_version",
            "evaluation_id",
            "evaluated_at",
            "engine",
            "plan_sha256",
            "run_sha256",
            "plan",
            "run",
            "results",
            "findings",
            "summary",
            "limitations",
        ),
    )
    if evaluation["schema"] != EVALUATION_SCHEMA or evaluation["schema_version"] != 1:
        raise ValueError("unsupported LureMandate evaluation schema")
    _id(evaluation["evaluation_id"], "evaluation_id")
    if _exact(evaluation["engine"], "engine", ("name", "version")) != {
        "name": "lurebench-luremandate",
        "version": PRODUCER_VERSION,
    }:
        raise ValueError("unsupported producer engine")
    _digest(evaluation["plan_sha256"], "plan_sha256")
    _digest(evaluation["run_sha256"], "run_sha256")
    _claims_boundary(evaluation["limitations"], LIMITATIONS, "evaluation limitations")
    expected = _derive(evaluation["plan"], evaluation["run"], evaluation["evaluated_at"])
    if evaluation != expected:
        raise ValueError("producer LureMandate evaluation does not independently recompute")
    return dict(evaluation)


def _read(path: Path, label: str, maximum: int = MAX_INPUT_BYTES) -> bytes:
    source = Path(path)
    if not source.is_file() or source.is_symlink() or source.parent.is_symlink():
        raise ValueError(f"{label} must be a regular non-symlink file")
    payload = source.read_bytes()
    if not 1 <= len(payload) <= maximum:
        raise ValueError(f"{label} exceeds its bounded size")
    return payload


def _encode(payload: bytes) -> str:
    return base64.b64encode(payload).decode("ascii")


def _decode(value: Any, field: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be canonical standard base64")
    try:
        payload = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{field} must be canonical standard base64") from exc
    if _encode(payload) != value or not 1 <= len(payload) <= MAX_INPUT_BYTES:
        raise ValueError(f"{field} must be canonical bounded standard base64")
    return payload


def _document(value: Any, field: str) -> bytes:
    document = _exact(value, field, ("document_sha256", "payload_base64"))
    payload = _decode(document["payload_base64"], f"{field}.payload_base64")
    if _digest(document["document_sha256"], f"{field}.document_sha256") != _sha256(payload):
        raise ValueError(f"{field} digest does not match embedded bytes")
    return payload


def _verification_value(
    plan_payload: bytes, run_payload: bytes, evaluation_payload: bytes, *, verified_at: str
) -> Dict[str, Any]:
    plan = validate_mandate_plan(_strict(plan_payload, "LureMandate plan"))
    run = validate_mandate_run(_strict(run_payload, "LureMandate run"), plan)
    evaluation = validate_mandate_evaluation(
        _strict(evaluation_payload, "LureMandate producer evaluation")
    )
    if evaluation["plan"] != plan or evaluation["run"] != run:
        raise ValueError("producer evaluation does not embed the supplied plan and run")
    if _derive(plan, run, evaluation["evaluated_at"]) != evaluation:
        raise ValueError("producer evaluation is not reproduced from supplied inputs")
    if _instant(verified_at, "verified_at") < _instant(evaluation["evaluated_at"], "evaluated_at"):
        raise ValueError("verification predates the producer evaluation")
    summary = dict(evaluation["summary"])
    summary.update(
        {
            "source_documents_reparsed": True,
            "producer_evaluation_reproduced": True,
            "transaction_authority_verified": evaluation["summary"]["verdict"] == "pass",
        }
    )
    return {
        "schema": VERIFICATION_SCHEMA,
        "schema_version": 1,
        "verification_id": f"{evaluation['evaluation_id']}-verification",
        "verified_at": verified_at,
        "engine": {"name": "lurescope-luremandate-independent", "version": __version__},
        "documents": {
            "plan": {
                "document_sha256": _sha256(plan_payload),
                "payload_base64": _encode(plan_payload),
            },
            "run": {
                "document_sha256": _sha256(run_payload),
                "payload_base64": _encode(run_payload),
            },
            "evaluation": {
                "document_sha256": _sha256(evaluation_payload),
                "payload_base64": _encode(evaluation_payload),
            },
        },
        "producer_evaluation": evaluation,
        "checks": list(VERIFICATION_CHECKS),
        "summary": summary,
        "limitations": list(VERIFICATION_LIMITATIONS),
    }


def validate_mandate_verification(value: Any) -> Dict[str, Any]:
    verification = _exact(
        value,
        "LureMandate verification",
        (
            "schema",
            "schema_version",
            "verification_id",
            "verified_at",
            "engine",
            "documents",
            "producer_evaluation",
            "checks",
            "summary",
            "limitations",
        ),
    )
    if verification["schema"] != VERIFICATION_SCHEMA or verification["schema_version"] != 1:
        raise ValueError("unsupported LureMandate verification schema")
    _id(verification["verification_id"], "verification_id")
    if _exact(verification["engine"], "engine", ("name", "version")) != {
        "name": "lurescope-luremandate-independent",
        "version": __version__,
    }:
        raise ValueError("unsupported LureMandate verifier engine")
    if verification["checks"] != VERIFICATION_CHECKS:
        raise ValueError("LureMandate verification check set is incomplete")
    _claims_boundary(
        verification["limitations"], VERIFICATION_LIMITATIONS, "verification limitations"
    )
    documents = _exact(verification["documents"], "documents", ("plan", "run", "evaluation"))
    expected = _verification_value(
        _document(documents["plan"], "embedded plan"),
        _document(documents["run"], "embedded run"),
        _document(documents["evaluation"], "embedded evaluation"),
        verified_at=verification["verified_at"],
    )
    if verification != expected:
        raise ValueError("LureMandate verification does not independently reproduce")
    return dict(verification)


def create_mandate_verification(
    plan_path: Path,
    run_path: Path,
    evaluation_path: Path,
    output_path: Path,
    *,
    verified_at: Optional[str] = None,
) -> Dict[str, Any]:
    result = _verification_value(
        _read(plan_path, "LureMandate plan"),
        _read(run_path, "LureMandate run"),
        _read(evaluation_path, "LureMandate evaluation"),
        verified_at=verified_at or _now(),
    )
    _write_new(Path(output_path), _canonical(validate_mandate_verification(result)))
    return result


def load_mandate_verification(path: Path) -> Dict[str, Any]:
    return validate_mandate_verification(
        _strict(
            _read(path, "LureMandate verification", MAX_REPORT_BYTES), "LureMandate verification"
        )
    )
