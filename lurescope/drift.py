"""Tamper-evident longitudinal comparison for minimized SCuBA assurance evidence.

The drift ledger compares two already-verified Combined Email Assurance bundles.
It never reads ScubaGear's raw provider settings and never infers why a result
changed.  A transition is an imported source observation, not a compliance,
causality, remediation, risk-acceptance, or authorization decision.
"""

from __future__ import annotations

import copy
import html
import os
import re
import secrets
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from . import __version__
from .assurance import (
    OSCAL_AR_SCHEMA,
    OSCAL_VERSION,
    PROPERTY_NAMESPACE,
    _canonical_json,
    _property,
    _read_regular,
    _reviewed_controls,
    _sha256,
    _write_new,
)
from .scuba import (
    SCUBA_EVIDENCE_FILE,
    STATEMENT_TYPE,
    _load_bundle_json,
    _parse_timestamp,
    _sign_payload,
    _verify_dsse,
    validate_scuba_evidence,
    verify_scuba_assurance_bundle,
)

DRIFT_SCHEMA = "https://github.com/immu4989/lurescope/spec/scuba-assurance-drift/v1"
DRIFT_PREDICATE_TYPE = (
    "https://github.com/immu4989/lurescope/spec/scuba-assurance-drift-statement/v1"
)

DRIFT_FILE = "assurance-drift.json"
DRIFT_MARKDOWN_FILE = "assurance-drift.md"
DRIFT_HTML_FILE = "assurance-drift.html"
DRIFT_OSCAL_FILE = "oscal-assessment-results.json"
DRIFT_STATEMENT_FILE = "assurance-drift.statement.json"
DRIFT_DSSE_FILE = "assurance-drift.dsse.json"
BEFORE_EVIDENCE_FILE = "before-scuba-evidence.json"
AFTER_EVIDENCE_FILE = "after-scuba-evidence.json"

_MAX_DRIFT_FILE_BYTES = 32 * 1024 * 1024
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_TRANSITION_KINDS = (
    "added",
    "improved",
    "newly_failing",
    "non_comparable",
    "regressed",
    "removed",
    "unchanged",
)
_CANDIDATE_LIFECYCLES = (
    "new_candidate",
    "no_longer_observed",
    "not_candidate",
    "persistent_candidate",
)
_PRODUCT_ORDER = ("AAD", "Defender", "EXO")
_PRIVACY = {
    "minimized": True,
    "shareable_by_default": False,
    "security_posture_sensitive": True,
    "contains_tenant_identifiers": False,
    "contains_raw_provider_settings": False,
    "contains_free_text_details": False,
    "contains_message_content": False,
    "retained_control_fields": ["product", "control_id", "result", "criticality"],
}
_INTERPRETATION_BOUNDARY = (
    "This ledger reports differences between privacy-minimized observations imported "
    "from two independently trusted ScubaGear reports and records a separate aggregate "
    "LureScope Pilot Gate verdict change. It does not establish causality, determine "
    "control satisfaction or compliance, confirm remediation, accept risk, or grant an "
    "authorization to operate."
)
_LIMITATIONS = [
    "source_combined_assurance_bundles_must_be_independently_trusted",
    "configuration_results_are_imported_not_reperformed",
    "same_scubagear_release_contract_scope_and_assurance_plan_required",
    "trustworthy_synchronized_source_and_ledger_clocks_required",
    "changed_or_absent_observation_is_not_proof_of_remediation",
    "non_comparable_transitions_require_human_review",
    "scuba_control_ids_are_not_mapped_to_nist_controls",
    "candidate_lifecycle_is_not_an_approved_poam_lifecycle",
    "security_posture_evidence_requires_access_control",
]


def _timestamp_value(value: str) -> datetime:
    _parse_timestamp(value, "timestamp")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _control_set_sha256(evidence: Dict[str, Any]) -> str:
    controls = sorted(
        evidence["controls"],
        key=lambda item: (_PRODUCT_ORDER.index(item["product"]), item["control_id"]),
    )
    contract = {
        "controls": [
            {
                "product": item["product"],
                "control_id": item["control_id"],
                "criticality": item["criticality"],
            }
            for item in controls
        ]
    }
    return _sha256(_canonical_json(contract))


def _source_snapshot(
    directory: Path,
    *,
    public_key: Optional[Path] = None,
    require_signature: bool = False,
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    """Verify a source bundle around a bounded snapshot to close common TOCTOU gaps."""
    directory = Path(directory)
    first = verify_scuba_assurance_bundle(
        directory, public_key=public_key, require_signature=require_signature
    )
    evidence, evidence_raw = _load_bundle_json(directory / SCUBA_EVIDENCE_FILE)
    validate_scuba_evidence(evidence)
    gate, gate_raw = _load_bundle_json(directory / "pilot-gate.json")
    assessment_plan, assessment_plan_raw = _load_bundle_json(
        directory / "oscal-assessment-plan.json"
    )
    profile_raw = _read_regular(directory / "assurance-profile.json", maximum=_MAX_DRIFT_FILE_BYTES)
    statement, statement_raw = _load_bundle_json(directory / "combined-assurance.statement.json")
    second = verify_scuba_assurance_bundle(
        directory, public_key=public_key, require_signature=require_signature
    )
    if first != second or first["statement_sha256"] != _sha256(statement_raw):
        raise ValueError("combined assurance source changed while it was being snapshotted")
    subject_digests = {item["name"]: item["digest"]["sha256"] for item in statement["subject"]}
    snapshot_payloads = {
        SCUBA_EVIDENCE_FILE: evidence_raw,
        "pilot-gate.json": gate_raw,
        "oscal-assessment-plan.json": assessment_plan_raw,
        "assurance-profile.json": profile_raw,
    }
    if any(
        subject_digests.get(name) != _sha256(payload) for name, payload in snapshot_payloads.items()
    ):
        raise ValueError("combined assurance artifacts changed while being snapshotted")
    if first["assurance_profile_sha256"] != _sha256(profile_raw):
        raise ValueError("combined assurance profile changed while it was being snapshotted")
    if not isinstance(gate, dict) or gate.get("verdict") not in {
        "pass",
        "fail",
        "insufficient_evidence",
    }:
        raise ValueError("combined assurance Pilot Gate verdict is invalid")
    plan_body = assessment_plan.get("assessment-plan")
    if not isinstance(plan_body, dict) or not isinstance(plan_body.get("uuid"), str):
        raise ValueError("combined assurance assessment plan identity is invalid")

    descriptor = {
        "combined_statement_sha256": first["statement_sha256"],
        "source_authentication": {
            "authenticated": first["authenticated"],
            "key_ids": first["key_ids"],
        },
        "scuba_evidence_sha256": _sha256(_canonical_json(evidence)),
        "scubagear_report_sha256": evidence["source"]["report_sha256"],
        "scubagear_version": evidence["source"]["tool_version"],
        "scubagear_contract": evidence["source"]["contract"],
        "baseline_release": f"v{evidence['source']['tool_version']}",
        "control_set_sha256": _control_set_sha256(evidence),
        "report_timestamp": evidence["source"]["report_timestamp"],
        "scope": copy.deepcopy(evidence["scope"]),
        "pilot_gate_sha256": _sha256(gate_raw),
        "pilot_gate_verdict": gate["verdict"],
        "assurance_profile_sha256": first["assurance_profile_sha256"],
        "assessment_plan_sha256": _sha256(assessment_plan_raw),
        "assessment_plan_uuid": plan_body["uuid"],
    }
    return descriptor, evidence


def _validate_source_descriptor(
    descriptor: object, evidence: Dict[str, Any], *, label: str
) -> Dict[str, Any]:
    expected_keys = {
        "combined_statement_sha256",
        "source_authentication",
        "scuba_evidence_sha256",
        "scubagear_report_sha256",
        "scubagear_version",
        "scubagear_contract",
        "baseline_release",
        "control_set_sha256",
        "report_timestamp",
        "scope",
        "pilot_gate_sha256",
        "pilot_gate_verdict",
        "assurance_profile_sha256",
        "assessment_plan_sha256",
        "assessment_plan_uuid",
    }
    if not isinstance(descriptor, dict) or set(descriptor) != expected_keys:
        raise ValueError(f"{label} drift source descriptor violates the v1 allowlist")
    for field in (
        "combined_statement_sha256",
        "scuba_evidence_sha256",
        "scubagear_report_sha256",
        "control_set_sha256",
        "pilot_gate_sha256",
        "assurance_profile_sha256",
        "assessment_plan_sha256",
    ):
        if (
            not isinstance(descriptor[field], str)
            or _SHA256_PATTERN.fullmatch(descriptor[field]) is None
        ):
            raise ValueError(f"{label} drift source {field} is not a SHA-256 digest")
    authentication = descriptor["source_authentication"]
    if not isinstance(authentication, dict) or set(authentication) != {
        "authenticated",
        "key_ids",
    }:
        raise ValueError(f"{label} drift source authentication is invalid")
    key_ids = authentication["key_ids"]
    if (
        not isinstance(authentication["authenticated"], bool)
        or not isinstance(key_ids, list)
        or len(key_ids) > 16
        or any(
            not isinstance(item, str) or _SHA256_PATTERN.fullmatch(item) is None for item in key_ids
        )
        or len(key_ids) != len(set(key_ids))
        or (authentication["authenticated"] and not key_ids)
    ):
        raise ValueError(f"{label} drift source authentication is invalid")
    _parse_timestamp(descriptor["report_timestamp"], f"{label}.report_timestamp")
    try:
        parsed_uuid = uuid.UUID(descriptor["assessment_plan_uuid"])
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError(f"{label} assessment plan UUID is invalid") from exc
    if str(parsed_uuid) != descriptor["assessment_plan_uuid"].lower():
        raise ValueError(f"{label} assessment plan UUID is not canonical")
    if descriptor["pilot_gate_verdict"] not in {
        "pass",
        "fail",
        "insufficient_evidence",
    }:
        raise ValueError(f"{label} Pilot Gate verdict is invalid")
    expected = {
        "scuba_evidence_sha256": _sha256(_canonical_json(evidence)),
        "scubagear_report_sha256": evidence["source"]["report_sha256"],
        "scubagear_version": evidence["source"]["tool_version"],
        "scubagear_contract": evidence["source"]["contract"],
        "baseline_release": f"v{evidence['source']['tool_version']}",
        "control_set_sha256": _control_set_sha256(evidence),
        "report_timestamp": evidence["source"]["report_timestamp"],
        "scope": evidence["scope"],
    }
    if any(descriptor[key] != value for key, value in expected.items()):
        raise ValueError(f"{label} drift source does not reconcile with its evidence snapshot")
    return descriptor


def _compatibility(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    required_equal = (
        ("scubagear_contract", "ScubaGear contract"),
        ("scubagear_version", "ScubaGear version"),
        ("baseline_release", "baseline release"),
        ("scope", "selected product scope"),
        ("assurance_profile_sha256", "assurance profile"),
        ("assessment_plan_sha256", "assessment plan"),
        ("assessment_plan_uuid", "assessment plan UUID"),
    )
    for key, label in required_equal:
        if before[key] != after[key]:
            raise ValueError(f"drift comparison requires the same {label}")
    if _timestamp_value(after["report_timestamp"]) <= _timestamp_value(before["report_timestamp"]):
        raise ValueError("after SCuBA report timestamp must be later than before")
    return {
        "comparable": True,
        "basis": [
            "same-scubagear-contract",
            "same-scubagear-release",
            "same-email-product-scope",
            "same-assurance-profile",
            "strictly-increasing-report-time",
        ],
        "baseline": {
            "release": before["baseline_release"],
            "before_control_set_sha256": before["control_set_sha256"],
            "after_control_set_sha256": after["control_set_sha256"],
            "control_set_changed": before["control_set_sha256"] != after["control_set_sha256"],
        },
    }


def _is_candidate(state: Optional[Dict[str, str]]) -> bool:
    return bool(state is not None and state["result"] == "Fail" and state["criticality"] == "Shall")


def _candidate_lifecycle(before: Optional[Dict[str, str]], after: Optional[Dict[str, str]]) -> str:
    was_candidate = _is_candidate(before)
    is_candidate = _is_candidate(after)
    if not was_candidate and is_candidate:
        return "new_candidate"
    if was_candidate and is_candidate:
        return "persistent_candidate"
    if was_candidate and not is_candidate:
        return "no_longer_observed"
    return "not_candidate"


def _transition_kind(before: Optional[Dict[str, str]], after: Optional[Dict[str, str]]) -> str:
    if before is None:
        return "added"
    if after is None:
        return "removed"
    if before == after:
        return "unchanged"
    if before["criticality"] != after["criticality"]:
        return "non_comparable"
    if before["result"] == "Pass" and after["result"] == "Fail":
        return "regressed"
    if before["result"] == "Fail" and after["result"] == "Pass":
        return "improved"
    if before["result"] != "Fail" and after["result"] == "Fail":
        return "newly_failing"
    return "non_comparable"


def _state(control: Dict[str, str]) -> Dict[str, str]:
    return {"result": control["result"], "criticality": control["criticality"]}


def _transitions(
    before_evidence: Dict[str, Any], after_evidence: Dict[str, Any]
) -> list[Dict[str, Any]]:
    before = {
        (item["product"], item["control_id"]): _state(item) for item in before_evidence["controls"]
    }
    after = {
        (item["product"], item["control_id"]): _state(item) for item in after_evidence["controls"]
    }
    keys = sorted(
        set(before) | set(after),
        key=lambda item: (_PRODUCT_ORDER.index(item[0]), item[1]),
    )
    return [
        {
            "product": product,
            "control_id": control_id,
            "before": before.get((product, control_id)),
            "after": after.get((product, control_id)),
            "transition": _transition_kind(
                before.get((product, control_id)), after.get((product, control_id))
            ),
            "candidate_lifecycle": _candidate_lifecycle(
                before.get((product, control_id)), after.get((product, control_id))
            ),
        }
        for product, control_id in keys
    ]


def _build_drift(
    before_source: Dict[str, Any],
    after_source: Dict[str, Any],
    before_evidence: Dict[str, Any],
    after_evidence: Dict[str, Any],
    *,
    generated_at: str,
    previous_ledger: Optional[Dict[str, str]],
) -> Dict[str, Any]:
    compatibility = _compatibility(before_source, after_source)
    if _timestamp_value(generated_at) < _timestamp_value(after_source["report_timestamp"]):
        raise ValueError("drift generation time cannot precede the after SCuBA report")
    transitions = _transitions(before_evidence, after_evidence)
    transition_counts = {
        kind: sum(item["transition"] == kind for item in transitions) for kind in _TRANSITION_KINDS
    }
    lifecycle_counts = {
        kind: sum(item["candidate_lifecycle"] == kind for item in transitions)
        for kind in _CANDIDATE_LIFECYCLES
    }
    return {
        "schema": DRIFT_SCHEMA,
        "schema_version": 1,
        "generated_at": generated_at,
        "comparison": {"before": before_source, "after": after_source},
        "compatibility": compatibility,
        "previous_ledger": previous_ledger,
        "pilot_gate": {
            "before": before_source["pilot_gate_verdict"],
            "after": after_source["pilot_gate_verdict"],
            "changed": before_source["pilot_gate_verdict"] != after_source["pilot_gate_verdict"],
        },
        "summary": {
            "total_control_count": len(transitions),
            "changed_control_count": len(transitions) - transition_counts["unchanged"],
            "transitions": transition_counts,
            "candidate_lifecycle": lifecycle_counts,
        },
        "transitions": transitions,
        "privacy": _PRIVACY,
        "interpretation_boundary": _INTERPRETATION_BOUNDARY,
        "limitations": _LIMITATIONS,
    }


def validate_scuba_drift(
    drift: Dict[str, Any], before_evidence: Dict[str, Any], after_evidence: Dict[str, Any]
) -> None:
    """Validate and exactly reconstruct a v1 drift record from its evidence snapshots."""
    expected_keys = {
        "schema",
        "schema_version",
        "generated_at",
        "comparison",
        "compatibility",
        "previous_ledger",
        "pilot_gate",
        "summary",
        "transitions",
        "privacy",
        "interpretation_boundary",
        "limitations",
    }
    if not isinstance(drift, dict) or set(drift) != expected_keys:
        raise ValueError("SCuBA drift record violates the v1 field allowlist")
    if drift.get("schema") != DRIFT_SCHEMA or drift.get("schema_version") != 1:
        raise ValueError("SCuBA drift schema identifier is unsupported")
    if isinstance(drift.get("schema_version"), bool):
        raise ValueError("SCuBA drift schema version must be an integer")
    generated_at = _parse_timestamp(drift.get("generated_at"), "generated_at")
    validate_scuba_evidence(before_evidence)
    validate_scuba_evidence(after_evidence)
    comparison = drift.get("comparison")
    if not isinstance(comparison, dict) or set(comparison) != {"before", "after"}:
        raise ValueError("SCuBA drift comparison is invalid")
    before_source = _validate_source_descriptor(
        comparison["before"], before_evidence, label="before"
    )
    after_source = _validate_source_descriptor(comparison["after"], after_evidence, label="after")
    previous = drift.get("previous_ledger")
    if previous is not None:
        if (
            not isinstance(previous, dict)
            or set(previous) != {"statement_sha256"}
            or not isinstance(previous["statement_sha256"], str)
            or _SHA256_PATTERN.fullmatch(previous["statement_sha256"]) is None
        ):
            raise ValueError("SCuBA drift previous ledger binding is invalid")
    expected = _build_drift(
        before_source,
        after_source,
        before_evidence,
        after_evidence,
        generated_at=generated_at,
        previous_ledger=previous,
    )
    if _canonical_json(drift) != _canonical_json(expected):
        raise ValueError("SCuBA drift record does not exactly reconcile with its evidence")


def _display_state(state: Optional[Dict[str, str]]) -> str:
    if state is None:
        return "absent"
    return f"{state['result']} ({state['criticality']})"


def render_scuba_drift_markdown(drift: Dict[str, Any]) -> str:
    """Render the bounded, privacy-minimized human report deterministically."""
    summary = drift["summary"]
    before = drift["comparison"]["before"]
    after = drift["comparison"]["after"]
    lines = [
        "# SCuBA Assurance Drift Ledger",
        "",
        "> **Decision boundary:** This is imported change evidence, not a compliance, "
        "remediation, causality, risk-acceptance, or authorization decision.",
        "",
        "## Comparison",
        "",
        f"- Before report: `{before['report_timestamp']}`",
        f"- After report: `{after['report_timestamp']}`",
        f"- ScubaGear release: `{before['baseline_release']}`",
        f"- Products: `{', '.join(before['scope']['products'])}`",
        f"- Pilot Gate: `{drift['pilot_gate']['before']}` → `{drift['pilot_gate']['after']}`",
        f"- Changed controls: **{summary['changed_control_count']}** of "
        f"**{summary['total_control_count']}**",
        "",
        "## Transition summary",
        "",
        "| Transition | Count |",
        "|---|---:|",
    ]
    lines.extend(f"| `{kind}` | {summary['transitions'][kind]} |" for kind in _TRANSITION_KINDS)
    lines.extend(
        [
            "",
            "## Candidate POA&M lifecycle summary",
            "",
            "> Candidate lifecycle labels are triage aids. `no_longer_observed` does not "
            "mean remediated.",
            "",
            "| Candidate lifecycle | Count |",
            "|---|---:|",
        ]
    )
    lines.extend(
        f"| `{kind}` | {summary['candidate_lifecycle'][kind]} |" for kind in _CANDIDATE_LIFECYCLES
    )
    lines.extend(
        [
            "",
            "## Control transitions",
            "",
            "| Product | Control | Before | After | Transition | Candidate lifecycle |",
            "|---|---|---|---|---|---|",
        ]
    )
    for item in drift["transitions"]:
        lines.append(
            f"| {item['product']} | `{item['control_id']}` | "
            f"{_display_state(item['before'])} | {_display_state(item['after'])} | "
            f"`{item['transition']}` | `{item['candidate_lifecycle']}` |"
        )
    lines.extend(
        [
            "",
            "## Integrity bindings",
            "",
            f"- Before combined statement: `sha256:{before['combined_statement_sha256']}`",
            f"- After combined statement: `sha256:{after['combined_statement_sha256']}`",
            f"- Before source report: `sha256:{before['scubagear_report_sha256']}`",
            f"- After source report: `sha256:{after['scubagear_report_sha256']}`",
            "",
            "## Interpretation boundary",
            "",
            drift["interpretation_boundary"],
            "",
        ]
    )
    return "\n".join(lines)


def render_scuba_drift_html(drift: Dict[str, Any]) -> str:
    """Render a standalone accessible report without scripts or external assets."""
    summary = drift["summary"]
    before = drift["comparison"]["before"]
    after = drift["comparison"]["after"]
    transition_cards = "".join(
        (
            '<div class="metric"><strong>'
            f"{summary['transitions'][kind]}</strong><span>{html.escape(kind)}</span></div>"
        )
        for kind in _TRANSITION_KINDS
    )
    rows = []
    for item in drift["transitions"]:
        transition = html.escape(item["transition"])
        rows.append(
            "<tr>"
            f"<td>{html.escape(item['product'])}</td>"
            f"<td><code>{html.escape(item['control_id'])}</code></td>"
            f"<td>{html.escape(_display_state(item['before']))}</td>"
            f"<td>{html.escape(_display_state(item['after']))}</td>"
            f'<td><span class="pill {transition}">{transition}</span></td>'
            f"<td><code>{html.escape(item['candidate_lifecycle'])}</code></td>"
            "</tr>"
        )
    predecessor = drift["previous_ledger"]
    predecessor_text = (
        f"sha256:{predecessor['statement_sha256']}" if predecessor else "first ledger entry"
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark light">
  <meta http-equiv="Content-Security-Policy"
    content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
  <title>SCuBA Assurance Drift Ledger</title>
  <style>
    :root {{ color-scheme: dark; --bg:#08111f; --panel:#101d31; --line:#29405f;
      --text:#edf5ff; --muted:#9db0c9; --accent:#47d7ac; --warn:#ffcc66; --bad:#ff6b7a; }}
    * {{ box-sizing:border-box; }} body {{ margin:0; font:15px/1.55 ui-sans-serif,system-ui;
      background:radial-gradient(circle at 15% 0,#17345a 0,transparent 38%),var(--bg);
      color:var(--text); }} main {{ width:min(1180px,94vw); margin:auto; padding:56px 0 80px; }}
    h1 {{ font-size:clamp(2rem,5vw,4.2rem); line-height:1; max-width:850px; margin:.2em 0; }}
    h2 {{ margin-top:2.4rem; }} .eyebrow {{ color:var(--accent); text-transform:uppercase;
      letter-spacing:.16em; font-weight:800; }} .boundary {{ border:1px solid var(--warn);
      background:#2a2315; border-radius:16px; padding:16px 20px; max-width:920px; }}
    .meta,.metrics {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr));
      gap:12px; margin:24px 0; }} .meta div,.metric {{
      background:color-mix(in srgb,var(--panel) 92%,transparent);
      border:1px solid var(--line); border-radius:16px; padding:16px; }}
    .meta span,.metric span {{ color:var(--muted); display:block; font-size:.82rem; }}
    .meta strong,.metric strong {{ font-size:1.35rem; display:block; overflow-wrap:anywhere; }}
    .table-wrap {{ overflow:auto; border:1px solid var(--line); border-radius:16px; }}
    table {{ border-collapse:collapse; width:100%; background:var(--panel); }}
    th,td {{ text-align:left; padding:12px 14px; border-bottom:1px solid var(--line); }}
    th {{ position:sticky; top:0; background:#162741; }} code {{ overflow-wrap:anywhere; }}
    .pill {{ display:inline-block; border:1px solid var(--line); border-radius:999px;
      padding:2px 9px; }} .regressed,.newly_failing {{ color:var(--bad); }}
    .improved {{ color:var(--accent); }} .non_comparable {{ color:var(--warn); }}
    footer {{ color:var(--muted); margin-top:32px; overflow-wrap:anywhere; }}
    @media (prefers-color-scheme:light) {{ :root {{ color-scheme:light; --bg:#f5f8fc;
      --panel:#fff; --line:#cad6e5; --text:#102039; --muted:#52657c; }}
      body {{ background:radial-gradient(circle at 15% 0,#dcecff 0,transparent 38%),var(--bg); }}
      .boundary {{ background:#fff7df; }} th {{ background:#edf4fc; }} }}
  </style>
</head>
<body><main>
  <div class="eyebrow">LureScope · Continuous assurance evidence</div>
  <h1>SCuBA Assurance Drift Ledger</h1>
  <p class="boundary"><strong>Decision boundary:</strong>
    {html.escape(drift["interpretation_boundary"])}</p>
  <section class="meta" aria-label="Comparison metadata">
    <div><span>Before</span><strong>{html.escape(before["report_timestamp"])}</strong></div>
    <div><span>After</span><strong>{html.escape(after["report_timestamp"])}</strong></div>
    <div><span>Release</span><strong>{html.escape(before["baseline_release"])}</strong></div>
    <div><span>Pilot Gate</span><strong>{html.escape(drift["pilot_gate"]["before"])} →
      {html.escape(drift["pilot_gate"]["after"])}</strong></div>
  </section>
  <h2>Transition summary</h2><section class="metrics">{transition_cards}</section>
  <p><strong>{summary["changed_control_count"]}</strong> of
    <strong>{summary["total_control_count"]}</strong> controls changed classification.</p>
  <h2>Control transitions</h2>
  <div class="table-wrap"><table>
    <thead><tr><th>Product</th><th>Control</th><th>Before</th><th>After</th>
      <th>Transition</th><th>Candidate lifecycle</th></tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table></div>
  <footer>
    <p>Previous ledger: <code>{html.escape(predecessor_text)}</code></p>
    <p>Before statement: <code>sha256:{before["combined_statement_sha256"]}</code><br>
       After statement: <code>sha256:{after["combined_statement_sha256"]}</code></p>
    <p>Generated by LureScope {html.escape(__version__)} at
      {html.escape(drift["generated_at"])}. This security-posture evidence is not
      shareable by default.</p>
  </footer>
</main></body></html>
"""


def _drift_reviewed_controls() -> Dict[str, Any]:
    reviewed = copy.deepcopy(_reviewed_controls())
    reviewed["description"] = (
        "The referenced Assessment Plan's registered control selection is retained as "
        "assessment context. This drift result does not map SCuBA control identifiers "
        "to those controls or assert that they were assessed."
    )
    for selection in reviewed["control-selections"]:
        selection["description"] = (
            "Registered LureScope profile controls; listed for plan continuity only."
        )
        selection["remarks"] = _INTERPRETATION_BOUNDARY
    return reviewed


def _drift_oscal(drift: Dict[str, Any]) -> Dict[str, Any]:
    binding = _sha256(_canonical_json(drift))
    document_uuid = str(
        uuid.uuid5(uuid.NAMESPACE_URL, f"{PROPERTY_NAMESPACE}/drift-results/{binding}")
    )
    result_uuid = str(
        uuid.uuid5(uuid.NAMESPACE_URL, f"{PROPERTY_NAMESPACE}/drift-result/{binding}")
    )
    observations = []
    for item in drift["transitions"]:
        observation_uuid = str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"{PROPERTY_NAMESPACE}/drift-observation/{binding}:{item['control_id']}",
            )
        )
        observations.append(
            {
                "uuid": observation_uuid,
                "title": f"Imported SCuBA transition: {item['control_id']}",
                "description": (
                    f"The imported source observation changed from "
                    f"{_display_state(item['before'])} to {_display_state(item['after'])}; "
                    f"the deterministic transition class is {item['transition']}."
                ),
                "props": [
                    _property("source-tool", "ScubaGear"),
                    _property("source-product", item["product"]),
                    _property("source-control-id", item["control_id"]),
                    _property("before-state", _display_state(item["before"])),
                    _property("after-state", _display_state(item["after"])),
                    _property("transition", item["transition"]),
                    _property("candidate-lifecycle", item["candidate_lifecycle"]),
                ],
                "methods": ["EXAMINE"],
                "types": ["technical"],
                "relevant-evidence": [
                    {
                        "href": DRIFT_FILE,
                        "description": (
                            "Privacy-minimized transition evidence bound to both source "
                            "Combined Email Assurance statements."
                        ),
                    }
                ],
                "collected": drift["comparison"]["after"]["report_timestamp"],
                "remarks": (
                    "Imported change observation only; no causal, remediation, control "
                    "satisfaction, or compliance determination is asserted."
                ),
            }
        )
    before = drift["comparison"]["before"]
    after = drift["comparison"]["after"]
    return {
        "$schema": OSCAL_AR_SCHEMA,
        "assessment-results": {
            "uuid": document_uuid,
            "metadata": {
                "title": "LureScope SCuBA Assurance Drift Observations",
                "last-modified": drift["generated_at"],
                "version": "1.0",
                "oscal-version": OSCAL_VERSION,
                "props": [
                    _property("drift-ledger-sha256", binding),
                    _property(
                        "before-combined-statement-sha256",
                        before["combined_statement_sha256"],
                    ),
                    _property(
                        "after-combined-statement-sha256",
                        after["combined_statement_sha256"],
                    ),
                    _property("scuba-to-nist-control-crosswalk", "none"),
                    _property("lurescope-version", __version__),
                ],
                "remarks": _INTERPRETATION_BOUNDARY,
            },
            "import-ap": {"href": f"urn:uuid:{after['assessment_plan_uuid']}"},
            "results": [
                {
                    "uuid": result_uuid,
                    "title": "Imported longitudinal SCuBA observations",
                    "description": (
                        "Deterministic comparison of privacy-minimized observations from "
                        "two compatible ScubaGear assessments."
                    ),
                    "start": before["report_timestamp"],
                    "end": after["report_timestamp"],
                    "props": [
                        _property("observation-count", len(observations)),
                        _property(
                            "changed-control-count",
                            drift["summary"]["changed_control_count"],
                        ),
                        _property("scuba-to-nist-control-crosswalk", "none"),
                    ],
                    "reviewed-controls": _drift_reviewed_controls(),
                    "observations": observations,
                    "remarks": _INTERPRETATION_BOUNDARY,
                }
            ],
        },
    }


def _drift_statement(subjects: list[Dict[str, Any]], drift: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "_type": STATEMENT_TYPE,
        "subject": subjects,
        "predicateType": DRIFT_PREDICATE_TYPE,
        "predicate": {
            "spec": "scuba-assurance-drift-ledger",
            "spec_version": "1.0",
            "generated_at": drift["generated_at"],
            "before_combined_statement_sha256": drift["comparison"]["before"][
                "combined_statement_sha256"
            ],
            "after_combined_statement_sha256": drift["comparison"]["after"][
                "combined_statement_sha256"
            ],
            "previous_ledger_statement_sha256": (
                drift["previous_ledger"]["statement_sha256"]
                if drift["previous_ledger"] is not None
                else None
            ),
            "summary": copy.deepcopy(drift["summary"]),
            "privacy": _PRIVACY,
            "interpretation_boundary": _INTERPRETATION_BOUNDARY,
            "limitations": _LIMITATIONS,
        },
    }


def _subject(directory: Path, name: str) -> Dict[str, Any]:
    return {
        "name": name,
        "digest": {
            "sha256": _sha256(_read_regular(directory / name, maximum=_MAX_DRIFT_FILE_BYTES))
        },
    }


def create_scuba_drift_package(
    before_bundle: Path,
    after_bundle: Path,
    output_dir: Path,
    *,
    signing_key: Optional[Path] = None,
    source_public_key: Optional[Path] = None,
    before_source_public_key: Optional[Path] = None,
    after_source_public_key: Optional[Path] = None,
    require_source_signatures: bool = False,
    previous_drift: Optional[Path] = None,
) -> Dict[str, Any]:
    """Create a private no-overwrite drift package from two verified source bundles."""
    before_key = before_source_public_key or source_public_key
    after_key = after_source_public_key or source_public_key
    if require_source_signatures and (before_key is None or after_key is None):
        raise ValueError("source signature verification requires trusted keys for both sources")
    before_source, before_evidence = _source_snapshot(
        Path(before_bundle),
        public_key=before_key,
        require_signature=require_source_signatures,
    )
    after_source, after_evidence = _source_snapshot(
        Path(after_bundle),
        public_key=after_key,
        require_signature=require_source_signatures,
    )
    previous_binding = None
    if previous_drift is not None:
        previous_verification = verify_scuba_drift_package(Path(previous_drift))
        previous_record, _ = _load_bundle_json(Path(previous_drift) / DRIFT_FILE)
        if (
            previous_record["comparison"]["after"]["combined_statement_sha256"]
            != (before_source["combined_statement_sha256"])
        ):
            raise ValueError("previous drift after-source must equal the new drift before-source")
        previous_binding = {"statement_sha256": previous_verification["statement_sha256"]}

    generated_at = datetime.now().astimezone().isoformat(timespec="seconds")
    drift = _build_drift(
        before_source,
        after_source,
        before_evidence,
        after_evidence,
        generated_at=generated_at,
        previous_ledger=previous_binding,
    )
    validate_scuba_drift(drift, before_evidence, after_evidence)
    markdown = render_scuba_drift_markdown(drift).encode("utf-8")
    html_report = render_scuba_drift_html(drift).encode("utf-8")
    oscal = _drift_oscal(drift)

    target = Path(output_dir)
    if target.exists() or target.is_symlink():
        raise FileExistsError(target)
    target.mkdir(mode=0o700)
    created: list[Path] = []
    try:
        payloads = (
            (BEFORE_EVIDENCE_FILE, _canonical_json(before_evidence)),
            (AFTER_EVIDENCE_FILE, _canonical_json(after_evidence)),
            (DRIFT_FILE, _canonical_json(drift)),
            (DRIFT_MARKDOWN_FILE, markdown),
            (DRIFT_HTML_FILE, html_report),
            (DRIFT_OSCAL_FILE, _canonical_json(oscal)),
        )
        for name, payload in payloads:
            destination = target / name
            _write_new(destination, payload)
            created.append(destination)
        subject_names = [name for name, _ in payloads]
        statement = _drift_statement([_subject(target, name) for name in subject_names], drift)
        statement_payload = _canonical_json(statement)
        statement_path = target / DRIFT_STATEMENT_FILE
        _write_new(statement_path, statement_payload)
        created.append(statement_path)
        if signing_key is not None:
            key_payload = _read_regular(Path(signing_key), maximum=64 * 1024)
            envelope = _sign_payload(statement_payload, key_payload)
            envelope_path = target / DRIFT_DSSE_FILE
            _write_new(envelope_path, _canonical_json(envelope))
            created.append(envelope_path)
        verification = verify_scuba_drift_package(
            target,
            previous_drift=Path(previous_drift) if previous_drift is not None else None,
        )
        return {
            "drift": drift,
            "oscal": oscal,
            "statement": statement,
            "verification": verification,
        }
    except Exception:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        target.rmdir()
        raise


def _verify_drift_statement(
    statement: Dict[str, Any], directory: Path, drift: Dict[str, Any]
) -> Dict[str, Any]:
    if set(statement) != {"_type", "subject", "predicateType", "predicate"}:
        raise ValueError("drift statement violates the field allowlist")
    if (
        statement.get("_type") != STATEMENT_TYPE
        or statement.get("predicateType") != DRIFT_PREDICATE_TYPE
    ):
        raise ValueError("drift statement identity is invalid")
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not subjects:
        raise ValueError("drift statement requires subjects")
    observed_names = []
    for subject in subjects:
        if not isinstance(subject, dict) or set(subject) != {"name", "digest"}:
            raise ValueError("drift statement subject violates the field allowlist")
        name = subject.get("name")
        digest = subject.get("digest")
        if (
            not isinstance(name, str)
            or Path(name).name != name
            or not isinstance(digest, dict)
            or set(digest) != {"sha256"}
            or not isinstance(digest["sha256"], str)
            or _SHA256_PATTERN.fullmatch(digest["sha256"]) is None
        ):
            raise ValueError("drift statement subject binding is invalid")
        if name in observed_names:
            raise ValueError("drift statement contains duplicate subjects")
        observed_names.append(name)
        actual = _sha256(_read_regular(directory / name, maximum=_MAX_DRIFT_FILE_BYTES))
        if not secrets.compare_digest(actual, digest["sha256"]):
            raise ValueError(f"drift statement subject digest mismatch: {name}")
    predicate = statement.get("predicate")
    expected_keys = {
        "spec",
        "spec_version",
        "generated_at",
        "before_combined_statement_sha256",
        "after_combined_statement_sha256",
        "previous_ledger_statement_sha256",
        "summary",
        "privacy",
        "interpretation_boundary",
        "limitations",
    }
    if not isinstance(predicate, dict) or set(predicate) != expected_keys:
        raise ValueError("drift statement predicate violates the v1 allowlist")
    expected = _drift_statement(statement["subject"], drift)["predicate"]
    if _canonical_json(predicate) != _canonical_json(expected):
        raise ValueError("drift statement predicate does not reconcile with the drift record")
    return predicate


def _same_source_content(first: Dict[str, Any], second: Dict[str, Any]) -> bool:
    first_copy = copy.deepcopy(first)
    second_copy = copy.deepcopy(second)
    first_copy.pop("source_authentication")
    second_copy.pop("source_authentication")
    return _canonical_json(first_copy) == _canonical_json(second_copy)


def verify_scuba_drift_package(
    directory: Path,
    *,
    public_key: Optional[Path] = None,
    require_signature: bool = False,
    previous_drift: Optional[Path] = None,
    previous_public_key: Optional[Path] = None,
    require_chain: bool = False,
    before_bundle: Optional[Path] = None,
    after_bundle: Optional[Path] = None,
    source_public_key: Optional[Path] = None,
    before_source_public_key: Optional[Path] = None,
    after_source_public_key: Optional[Path] = None,
    require_source_signatures: bool = False,
) -> Dict[str, Any]:
    """Verify drift package semantics, digests, optional signatures, chain, and sources."""
    directory = Path(directory)
    if directory.is_symlink():
        raise ValueError("refusing symbolic-link drift directory")
    if not directory.is_dir():
        raise FileNotFoundError(directory)
    required = {
        BEFORE_EVIDENCE_FILE,
        AFTER_EVIDENCE_FILE,
        DRIFT_FILE,
        DRIFT_MARKDOWN_FILE,
        DRIFT_HTML_FILE,
        DRIFT_OSCAL_FILE,
        DRIFT_STATEMENT_FILE,
    }
    actual = {entry.name for entry in directory.iterdir()}
    optional = {DRIFT_DSSE_FILE}
    if not required <= actual or actual - required - optional:
        raise ValueError("drift directory contains an unexpected file set")
    if os.name == "posix":
        if directory.stat().st_mode & 0o077:
            raise ValueError("drift directory must not grant group or world access")
        for name in actual:
            path = directory / name
            if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
                raise ValueError(f"{name} must be a private regular file")

    before_evidence, before_raw = _load_bundle_json(directory / BEFORE_EVIDENCE_FILE)
    after_evidence, after_raw = _load_bundle_json(directory / AFTER_EVIDENCE_FILE)
    if before_raw != _canonical_json(before_evidence) or after_raw != _canonical_json(
        after_evidence
    ):
        raise ValueError("drift evidence snapshots must use canonical JSON")
    drift, drift_raw = _load_bundle_json(directory / DRIFT_FILE)
    if drift_raw != _canonical_json(drift):
        raise ValueError("drift record must use canonical JSON")
    validate_scuba_drift(drift, before_evidence, after_evidence)

    expected_markdown = render_scuba_drift_markdown(drift).encode("utf-8")
    if not secrets.compare_digest(
        _read_regular(directory / DRIFT_MARKDOWN_FILE, maximum=_MAX_DRIFT_FILE_BYTES),
        expected_markdown,
    ):
        raise ValueError("drift Markdown report does not exactly reconcile")
    expected_html = render_scuba_drift_html(drift).encode("utf-8")
    if not secrets.compare_digest(
        _read_regular(directory / DRIFT_HTML_FILE, maximum=_MAX_DRIFT_FILE_BYTES),
        expected_html,
    ):
        raise ValueError("drift HTML report does not exactly reconcile")
    oscal, oscal_raw = _load_bundle_json(directory / DRIFT_OSCAL_FILE)
    expected_oscal = _drift_oscal(drift)
    if oscal_raw != _canonical_json(oscal) or _canonical_json(oscal) != _canonical_json(
        expected_oscal
    ):
        raise ValueError("drift OSCAL Assessment Results does not exactly reconcile")
    result_sets = oscal.get("assessment-results", {}).get("results", [])
    if any("findings" in result for result in result_sets if isinstance(result, dict)):
        raise ValueError("drift OSCAL output must not create findings")

    statement, statement_raw = _load_bundle_json(directory / DRIFT_STATEMENT_FILE)
    expected_subject_names = [
        BEFORE_EVIDENCE_FILE,
        AFTER_EVIDENCE_FILE,
        DRIFT_FILE,
        DRIFT_MARKDOWN_FILE,
        DRIFT_HTML_FILE,
        DRIFT_OSCAL_FILE,
    ]
    _verify_drift_statement(statement, directory, drift)
    if [item["name"] for item in statement["subject"]] != expected_subject_names:
        raise ValueError("drift statement subject order or coverage is invalid")

    authenticated = False
    key_ids: list[str] = []
    if DRIFT_DSSE_FILE in actual:
        envelope, _ = _load_bundle_json(directory / DRIFT_DSSE_FILE)
        public_key_pem = (
            _read_regular(Path(public_key), maximum=64 * 1024) if public_key is not None else None
        )
        authenticated, key_ids = _verify_dsse(envelope, statement_raw, public_key_pem)
    elif require_signature:
        raise ValueError("authenticated drift verification requires a DSSE envelope")
    if require_signature and public_key is None:
        raise ValueError("authenticated drift verification requires a trusted public key")
    if require_signature and not authenticated:
        raise ValueError("an authenticated drift signature is required")

    predecessor = drift["previous_ledger"]
    chain_verified = predecessor is None
    if previous_drift is not None:
        if predecessor is None:
            raise ValueError("first drift entry must not be supplied a predecessor")
        previous_verification = verify_scuba_drift_package(
            Path(previous_drift),
            public_key=previous_public_key,
            require_signature=previous_public_key is not None,
        )
        if predecessor["statement_sha256"] != previous_verification["statement_sha256"]:
            raise ValueError("drift predecessor statement digest does not match")
        previous_record, _ = _load_bundle_json(Path(previous_drift) / DRIFT_FILE)
        if (
            previous_record["comparison"]["after"]["combined_statement_sha256"]
            != (drift["comparison"]["before"]["combined_statement_sha256"])
        ):
            raise ValueError("drift predecessor does not form a continuous source chain")
        chain_verified = True
    if require_chain and not chain_verified:
        raise ValueError("full drift-chain verification requires --previous-drift")

    source_bundles_reverified = False
    source_authenticated = False
    if (before_bundle is None) != (after_bundle is None):
        raise ValueError("source reverification requires both --before and --after")
    before_key = before_source_public_key or source_public_key
    after_key = after_source_public_key or source_public_key
    if require_source_signatures and (before_key is None or after_key is None):
        raise ValueError("source signature verification requires trusted keys for both sources")
    if require_source_signatures and before_bundle is None:
        raise ValueError("source signature verification requires source bundles")
    if before_bundle is not None and after_bundle is not None:
        before_source, current_before_evidence = _source_snapshot(
            Path(before_bundle),
            public_key=before_key,
            require_signature=require_source_signatures,
        )
        after_source, current_after_evidence = _source_snapshot(
            Path(after_bundle),
            public_key=after_key,
            require_signature=require_source_signatures,
        )
        if not _same_source_content(before_source, drift["comparison"]["before"]) or not (
            _same_source_content(after_source, drift["comparison"]["after"])
        ):
            raise ValueError("supplied source bundles do not match the drift bindings")
        if (
            _canonical_json(current_before_evidence) != before_raw
            or _canonical_json(current_after_evidence) != after_raw
        ):
            raise ValueError("supplied source evidence differs from the drift snapshots")
        source_bundles_reverified = True
        source_authenticated = bool(
            before_source["source_authentication"]["authenticated"]
            and after_source["source_authentication"]["authenticated"]
        )

    return {
        "valid": True,
        "authenticated": authenticated,
        "artifact_type": "dsse" if DRIFT_DSSE_FILE in actual else "statement",
        "statement_sha256": _sha256(statement_raw),
        "signature_count": len(key_ids),
        "key_ids": key_ids,
        "chain_bound": predecessor is not None,
        "chain_verified": chain_verified,
        "source_bundles_reverified": source_bundles_reverified,
        "source_bundles_authenticated": source_authenticated,
        "changed_control_count": drift["summary"]["changed_control_count"],
        "new_candidate_count": drift["summary"]["candidate_lifecycle"]["new_candidate"],
        "persistent_candidate_count": drift["summary"]["candidate_lifecycle"][
            "persistent_candidate"
        ],
    }
