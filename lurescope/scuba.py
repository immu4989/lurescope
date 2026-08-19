"""Offline bridge from CISA ScubaGear results to Federal Email Assurance evidence.

The importer accepts ScubaGear's consolidated JSON report, validates and reconciles
its public result structure, and deliberately excludes tenant identity, raw provider
settings, free-text details, requirements, comments, and remediation annotations from
the derived bundle.  It imports source observations; it does not rerun ScubaGear,
assess a tenant, or determine compliance.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import os
import re
import secrets
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import __version__
from .assurance import (
    OSCAL_AR_SCHEMA,
    OSCAL_PLAN_FILE,
    OSCAL_RESULTS_FILE,
    OSCAL_VERSION,
    PILOT_PLAN_FILE,
    PROFILE_FILE,
    PROPERTY_NAMESPACE,
    _assessment_results,
    _canonical_json,
    _load_json,
    _property,
    _read_regular,
    _reviewed_controls,
    _sha256,
    _validate_assessment_plan,
    _validate_profile,
    _write_new,
    export_assurance_results,
)
from .pilot import load_pilot_plan

SCUBA_EVIDENCE_SCHEMA = "https://github.com/immu4989/lurescope/spec/scuba-evidence/v1"
COMBINED_PREDICATE_TYPE = (
    "https://github.com/immu4989/lurescope/spec/combined-email-assurance/v1"
)
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
OSCAL_POAM_SCHEMA = "http://csrc.nist.gov/ns/oscal/1.2.2/oscal-poam-schema.json"

SCUBA_EVIDENCE_FILE = "scuba-evidence.json"
OSCAL_POAM_FILE = "oscal-poam-candidates.json"
STATEMENT_FILE = "combined-assurance.statement.json"
DSSE_FILE = "combined-assurance.dsse.json"
PILOT_GATE_FILE = "pilot-gate.json"

SCUBA_CONTRACT = "cisagov-scubagear-consolidated-json-1.8"
SCUBA_SUPPORTED_VERSION = re.compile(r"^1\.8\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
_CONTROL_ID = re.compile(
    r"^MS\.(AAD|DEFENDER|EXO|POWERPLATFORM|SHAREPOINT|TEAMS)\.\d+\.\d+v\d+$"
)
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_MAX_SCUBA_REPORT_BYTES = 32 * 1024 * 1024
_MAX_BUNDLE_FILE_BYTES = 16 * 1024 * 1024

_TOP_LEVEL_KEYS = {"MetaData", "Summary", "AnnotatedFailedPolicies", "Results", "Raw"}
_METADATA_KEYS = {
    "DisplayName",
    "DomainName",
    "ProductAbbreviationMapping",
    "ProductSuite",
    "ProductsAssessed",
    "ReportUUID",
    "TenantId",
    "TimestampZulu",
    "Tool",
    "ToolVersion",
}
_SUMMARY_KEYS = {
    "Manual",
    "Failures",
    "Warnings",
    "Errors",
    "Passes",
    "Omits",
    "IncorrectResults",
}
_GROUP_KEYS = {"GroupName", "GroupNumber", "GroupReferenceURL", "Controls"}
_CONTROL_KEYS = {
    "Control ID",
    "Requirement",
    "Result",
    "Criticality",
    "Details",
    "OmittedEvaluationResult",
    "OmittedEvaluationDetails",
    "IncorrectResult",
    "IncorrectResultDetails",
    "OriginalResult",
    "OriginalDetails",
    "Comments",
    "ResolutionDate",
}
_CONTROL_KEYS_ALTERNATE = (_CONTROL_KEYS - {"IncorrectResultDetails"}) | {
    "IncorrectDetails"
}
_PRODUCT_MAPPING = {
    "Azure Active Directory": "AAD",
    "Microsoft 365 Defender": "Defender",
    "Exchange Online": "EXO",
    "Microsoft Power Platform": "PowerPlatform",
    "SharePoint Online": "SharePoint",
    "Microsoft Teams": "Teams",
}
_PRODUCT_PREFIX = {
    "AAD": "AAD",
    "Defender": "DEFENDER",
    "EXO": "EXO",
    "PowerPlatform": "POWERPLATFORM",
    "SharePoint": "SHAREPOINT",
    "Teams": "TEAMS",
}
_EMAIL_PRODUCTS = ("AAD", "Defender", "EXO")
_RESULT_CATEGORY = {
    "Pass": "Passes",
    "Fail": "Failures",
    "Warning": "Warnings",
    "N/A": "Manual",
    "Omitted": "Omits",
    "Incorrect result": "IncorrectResults",
    "Error - Test results missing": "Errors",
    "Error": "Errors",
}
_CRITICALITIES = {
    "Shall",
    "Should",
    "Shall/Not-Implemented",
    "Should/Not-Implemented",
    "Shall/3rd Party",
    "Should/3rd Party",
    "-",
}
_PRIVACY = {
    "minimized": True,
    "shareable_by_default": False,
    "security_posture_sensitive": True,
    "contains_tenant_identifiers": False,
    "contains_raw_provider_settings": False,
    "contains_free_text_details": False,
    "excluded_source_fields": [
        "MetaData.DisplayName",
        "MetaData.DomainName",
        "MetaData.TenantId",
        "MetaData.ReportUUID",
        "Raw",
        "AnnotatedFailedPolicies",
        "Results.Requirement",
        "Results.Details",
        "Results.OriginalDetails",
        "Results.Comments",
        "Results.ResolutionDate",
    ],
}
_INTERPRETATION_BOUNDARY = (
    "This bundle imports configuration observations reported by CISA ScubaGear and "
    "outcome observations measured by LureScope. LureScope does not query Microsoft "
    "365, rerun SCuBA policies, determine control satisfaction, establish compliance, "
    "accept risk, or grant an authorization to operate."
)
_LIMITATIONS = [
    "scubagear_source_report_must_be_independently_trusted",
    "configuration_results_are_imported_not_reperformed",
    "selected_email_products_only",
    "poam_items_are_candidates_not_approved_remediation_records",
    "control_mapping_is_not_compliance_determination",
    "scuba_control_ids_are_not_mapped_to_nist_controls",
    "representative_sample_and_trustworthy_labels_required",
    "security_posture_evidence_requires_access_control",
    "human_assessor_and_authorizing_official_decisions_required",
]


def _timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _parse_timestamp(value: object, field: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        raise ValueError(f"{field} must be a bounded ISO 8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be a valid ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return value


def _bounded_text(value: object, field: str, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"{field} must be a non-empty string of at most {maximum} characters")
    if any(ord(character) < 0x20 and character not in "\r\n\t" for character in value):
        raise ValueError(f"{field} contains an unsupported control character")
    return value


def _nonnegative_integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON numeric constant is not allowed: {value}")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
    value: Dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key is not allowed: {key}")
        value[key] = item
    return value


def _parse_json_object(raw: bytes, label: str) -> Dict[str, Any]:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return value


def _uuid_text(value: object, field: str) -> str:
    text = _bounded_text(value, field, 64)
    try:
        parsed = uuid.UUID(text)
    except ValueError as exc:
        raise ValueError(f"{field} must be a UUID") from exc
    if str(parsed) != text.lower():
        raise ValueError(f"{field} must use canonical UUID text")
    return text


def _control_category(result: str) -> str:
    category = _RESULT_CATEGORY.get(result)
    if category is None:
        raise ValueError(f"unsupported ScubaGear control result: {result!r}")
    return category


def _validate_control(
    value: object,
    *,
    product: str,
    seen_ids: set[str],
) -> Dict[str, str]:
    if not isinstance(value, dict) or (
        set(value) != _CONTROL_KEYS and set(value) != _CONTROL_KEYS_ALTERNATE
    ):
        raise ValueError("ScubaGear control violates the supported 1.8 field allowlist")
    control_id = _bounded_text(value["Control ID"], "Control ID", 128)
    match = _CONTROL_ID.fullmatch(control_id)
    if match is None or match.group(1) != _PRODUCT_PREFIX[product]:
        raise ValueError(f"ScubaGear control ID does not match product {product}: {control_id}")
    if control_id in seen_ids:
        raise ValueError(f"duplicate ScubaGear control ID: {control_id}")
    seen_ids.add(control_id)

    result = _bounded_text(value["Result"], f"{control_id} Result", 128)
    _control_category(result)
    criticality = _bounded_text(value["Criticality"], f"{control_id} Criticality", 64)
    if criticality not in _CRITICALITIES:
        raise ValueError(f"unsupported ScubaGear criticality for {control_id}: {criticality}")
    for field in (
        "Requirement",
        "Details",
        "OmittedEvaluationResult",
        "OmittedEvaluationDetails",
        "IncorrectResult",
        "OriginalResult",
        "OriginalDetails",
    ):
        _bounded_text(value[field], f"{control_id} {field}", 256 * 1024)
    detail_key = (
        "IncorrectResultDetails"
        if "IncorrectResultDetails" in value
        else "IncorrectDetails"
    )
    _bounded_text(value[detail_key], f"{control_id} {detail_key}", 256 * 1024)
    comments = value["Comments"]
    if not isinstance(comments, list) or len(comments) > 100:
        raise ValueError(f"{control_id} Comments must be a bounded array")
    for index, comment in enumerate(comments):
        _bounded_text(comment, f"{control_id} Comments[{index}]", 16 * 1024)
    resolution = value["ResolutionDate"]
    if resolution is not None:
        _bounded_text(resolution, f"{control_id} ResolutionDate", 64)
    return {
        "product": product,
        "control_id": control_id,
        "result": result,
        "criticality": criticality,
    }


def ingest_scuba_report(report_path: Path) -> tuple[Dict[str, Any], bytes]:
    """Validate a ScubaGear 1.8 consolidated report and derive minimized evidence."""
    path = Path(report_path)
    raw = _read_regular(path, maximum=_MAX_SCUBA_REPORT_BYTES)
    report = _parse_json_object(raw, "ScubaGear report")
    if set(report) != _TOP_LEVEL_KEYS:
        raise ValueError("ScubaGear report violates the supported consolidated field allowlist")
    metadata = report["MetaData"]
    if not isinstance(metadata, dict) or set(metadata) != _METADATA_KEYS:
        raise ValueError("ScubaGear MetaData violates the supported 1.8 field allowlist")
    if metadata["Tool"] != "ScubaGear":
        raise ValueError("source report Tool must be ScubaGear")
    tool_version = _bounded_text(metadata["ToolVersion"], "ToolVersion", 64)
    if SCUBA_SUPPORTED_VERSION.fullmatch(tool_version) is None:
        raise ValueError("only the tested ScubaGear 1.8.x consolidated contract is supported")
    if metadata["ProductSuite"] != "Microsoft 365":
        raise ValueError("source report ProductSuite must be Microsoft 365")
    if metadata["ProductAbbreviationMapping"] != _PRODUCT_MAPPING:
        raise ValueError("ScubaGear product abbreviation mapping is unsupported")
    _bounded_text(metadata["DisplayName"], "DisplayName", 1024)
    _bounded_text(metadata["DomainName"], "DomainName", 1024)
    _uuid_text(metadata["TenantId"], "TenantId")
    _uuid_text(metadata["ReportUUID"], "ReportUUID")
    report_timestamp = _parse_timestamp(metadata["TimestampZulu"], "TimestampZulu")

    assessed = metadata["ProductsAssessed"]
    if (
        not isinstance(assessed, list)
        or not assessed
        or any(not isinstance(item, str) for item in assessed)
        or len(assessed) != len(set(assessed))
        or any(item not in _PRODUCT_MAPPING for item in assessed)
    ):
        raise ValueError("ProductsAssessed must be a unique supported product-name array")
    assessed_products = {_PRODUCT_MAPPING[item] for item in assessed}
    summaries = report["Summary"]
    results = report["Results"]
    if not isinstance(summaries, dict) or set(summaries) != assessed_products:
        raise ValueError("ScubaGear Summary products do not match ProductsAssessed")
    if not isinstance(results, dict) or set(results) != assessed_products:
        raise ValueError("ScubaGear Results products do not match ProductsAssessed")
    if not isinstance(report["Raw"], dict) or not isinstance(
        report["AnnotatedFailedPolicies"], dict
    ):
        raise ValueError("ScubaGear Raw and AnnotatedFailedPolicies must be objects")

    seen_ids: set[str] = set()
    controls_by_product: Dict[str, list[Dict[str, str]]] = {}
    for product in sorted(assessed_products):
        summary = summaries[product]
        if not isinstance(summary, dict) or set(summary) != _SUMMARY_KEYS:
            raise ValueError(f"ScubaGear {product} Summary violates the field allowlist")
        official_counts = {
            key: _nonnegative_integer(value, f"{product} Summary.{key}")
            for key, value in summary.items()
        }
        groups = results[product]
        if not isinstance(groups, list) or len(groups) > 1000:
            raise ValueError(f"ScubaGear {product} Results must be a bounded array")
        controls: list[Dict[str, str]] = []
        derived_counts = {key: 0 for key in _SUMMARY_KEYS}
        for group_index, group in enumerate(groups):
            if not isinstance(group, dict) or set(group) != _GROUP_KEYS:
                raise ValueError(f"ScubaGear {product} result group violates the allowlist")
            _bounded_text(group["GroupName"], f"{product} GroupName", 4096)
            _bounded_text(group["GroupNumber"], f"{product} GroupNumber", 64)
            _bounded_text(group["GroupReferenceURL"], f"{product} GroupReferenceURL", 4096)
            group_controls = group["Controls"]
            if not isinstance(group_controls, list) or not group_controls:
                raise ValueError(
                    f"ScubaGear {product} Results[{group_index}].Controls must not be empty"
                )
            for control in group_controls:
                minimized = _validate_control(control, product=product, seen_ids=seen_ids)
                controls.append(minimized)
                derived_counts[_control_category(minimized["result"])] += 1
        if len(controls) > 5000:
            raise ValueError(f"ScubaGear {product} exceeds the 5000-control safety limit")
        if official_counts != derived_counts:
            raise ValueError(f"ScubaGear {product} Summary does not reconcile with Results")
        controls_by_product[product] = controls

    selected_products = [product for product in _EMAIL_PRODUCTS if product in assessed_products]
    if not selected_products:
        raise ValueError("ScubaGear report contains no AAD, Defender, or EXO results")
    selected_controls = sorted(
        (
            control
            for product in selected_products
            for control in controls_by_product[product]
        ),
        key=lambda item: (_EMAIL_PRODUCTS.index(item["product"]), item["control_id"]),
    )
    selected_summary = []
    totals = {key: 0 for key in _SUMMARY_KEYS}
    for product in selected_products:
        counts = {key: summaries[product][key] for key in sorted(_SUMMARY_KEYS)}
        for key, value in counts.items():
            totals[key] += value
        selected_summary.append(
            {"product": product, "control_count": sum(counts.values()), "counts": counts}
        )
    candidate_count = sum(
        control["result"] == "Fail" and control["criticality"] == "Shall"
        for control in selected_controls
    )
    evidence = {
        "schema": SCUBA_EVIDENCE_SCHEMA,
        "schema_version": 1,
        "generated_at": _timestamp(),
        "source": {
            "tool": "ScubaGear",
            "tool_version": tool_version,
            "contract": SCUBA_CONTRACT,
            "product_suite": "Microsoft 365",
            "report_timestamp": report_timestamp,
            "report_sha256": _sha256(raw),
        },
        "scope": {
            "products": selected_products,
            "selection": "email-relevant-products-v1",
        },
        "privacy": _PRIVACY,
        "summary": {"products": selected_summary, "totals": totals},
        "controls": selected_controls,
        "integrity": {
            "source_summary_reconciled": True,
            "unique_control_ids": True,
            "control_count": len(selected_controls),
            "candidate_poam_count": candidate_count,
        },
        "interpretation_boundary": _INTERPRETATION_BOUNDARY,
        "limitations": _LIMITATIONS,
    }
    validate_scuba_evidence(evidence)
    return evidence, raw


def validate_scuba_evidence(evidence: Dict[str, Any]) -> None:
    """Fail-closed validation for the privacy-minimized evidence artifact."""
    if not isinstance(evidence, dict) or set(evidence) != {
        "schema",
        "schema_version",
        "generated_at",
        "source",
        "scope",
        "privacy",
        "summary",
        "controls",
        "integrity",
        "interpretation_boundary",
        "limitations",
    }:
        raise ValueError("SCuBA evidence violates the v1 field allowlist")
    if (
        evidence.get("schema") != SCUBA_EVIDENCE_SCHEMA
        or isinstance(evidence.get("schema_version"), bool)
        or evidence.get("schema_version") != 1
    ):
        raise ValueError("SCuBA evidence schema identifier is unsupported")
    _parse_timestamp(evidence.get("generated_at"), "generated_at")
    source = evidence.get("source")
    if not isinstance(source, dict) or set(source) != {
        "tool",
        "tool_version",
        "contract",
        "product_suite",
        "report_timestamp",
        "report_sha256",
    }:
        raise ValueError("SCuBA evidence source binding is invalid")
    if (
        source.get("tool") != "ScubaGear"
        or source.get("contract") != SCUBA_CONTRACT
        or source.get("product_suite") != "Microsoft 365"
        or not isinstance(source.get("tool_version"), str)
        or SCUBA_SUPPORTED_VERSION.fullmatch(source["tool_version"]) is None
        or not isinstance(source.get("report_sha256"), str)
        or _SHA256.fullmatch(source["report_sha256"]) is None
    ):
        raise ValueError("SCuBA evidence source identity is invalid")
    _parse_timestamp(source.get("report_timestamp"), "source.report_timestamp")
    scope = evidence.get("scope")
    if not isinstance(scope, dict) or set(scope) != {"products", "selection"}:
        raise ValueError("SCuBA evidence scope is invalid")
    products = scope.get("products")
    if (
        scope.get("selection") != "email-relevant-products-v1"
        or not isinstance(products, list)
        or not products
        or any(not isinstance(item, str) for item in products)
        or products != [item for item in _EMAIL_PRODUCTS if item in products]
        or len(products) != len(set(products))
    ):
        raise ValueError("SCuBA evidence product scope is invalid")
    if not isinstance(evidence.get("privacy"), dict) or _canonical_json(
        evidence["privacy"]
    ) != _canonical_json(_PRIVACY):
        raise ValueError("SCuBA evidence privacy boundary is invalid")
    if evidence.get("interpretation_boundary") != _INTERPRETATION_BOUNDARY:
        raise ValueError("SCuBA evidence interpretation boundary is invalid")
    if evidence.get("limitations") != _LIMITATIONS:
        raise ValueError("SCuBA evidence limitations are invalid")

    controls = evidence.get("controls")
    if not isinstance(controls, list) or not controls or len(controls) > 15000:
        raise ValueError("SCuBA evidence controls must be a bounded non-empty array")
    seen: set[str] = set()
    derived_by_product: Dict[str, Dict[str, int]] = {
        product: {key: 0 for key in _SUMMARY_KEYS} for product in products
    }
    candidates = 0
    for control in controls:
        if not isinstance(control, dict) or set(control) != {
            "product",
            "control_id",
            "result",
            "criticality",
        }:
            raise ValueError("SCuBA evidence control violates the v1 allowlist")
        product = control["product"]
        control_id = control["control_id"]
        if product not in products or not isinstance(control_id, str):
            raise ValueError("SCuBA evidence control product is out of scope")
        match = _CONTROL_ID.fullmatch(control_id)
        if match is None or match.group(1) != _PRODUCT_PREFIX[product] or control_id in seen:
            raise ValueError("SCuBA evidence contains an invalid or duplicate control ID")
        seen.add(control_id)
        result = control.get("result")
        criticality = control.get("criticality")
        if not isinstance(result, str) or not isinstance(criticality, str):
            raise ValueError("SCuBA evidence result and criticality must be strings")
        category = _control_category(result)
        if criticality not in _CRITICALITIES:
            raise ValueError("SCuBA evidence contains an unsupported criticality")
        derived_by_product[product][category] += 1
        candidates += result == "Fail" and criticality == "Shall"

    summary = evidence.get("summary")
    if not isinstance(summary, dict) or set(summary) != {"products", "totals"}:
        raise ValueError("SCuBA evidence summary is invalid")
    product_summaries = summary.get("products")
    if not isinstance(product_summaries, list) or len(product_summaries) != len(products):
        raise ValueError("SCuBA evidence product summary is incomplete")
    totals = {key: 0 for key in _SUMMARY_KEYS}
    for expected_product, product_summary in zip(products, product_summaries, strict=True):
        if not isinstance(product_summary, dict) or set(product_summary) != {
            "product",
            "control_count",
            "counts",
        }:
            raise ValueError("SCuBA evidence product summary violates the allowlist")
        counts = product_summary["counts"]
        if isinstance(product_summary.get("control_count"), bool) or not isinstance(
            product_summary.get("control_count"), int
        ):
            raise ValueError("SCuBA evidence product control count must be an integer")
        if isinstance(counts, dict):
            for key, value in counts.items():
                _nonnegative_integer(value, f"summary.{expected_product}.{key}")
        if (
            product_summary["product"] != expected_product
            or not isinstance(counts, dict)
            or set(counts) != _SUMMARY_KEYS
            or counts != derived_by_product[expected_product]
            or product_summary["control_count"] != sum(counts.values())
        ):
            raise ValueError("SCuBA evidence product summary does not reconcile")
        for key, value in counts.items():
            totals[key] += value
    if summary.get("totals") != totals:
        raise ValueError("SCuBA evidence total summary does not reconcile")
    integrity = evidence.get("integrity")
    if not isinstance(integrity, dict) or set(integrity) != {
        "source_summary_reconciled",
        "unique_control_ids",
        "control_count",
        "candidate_poam_count",
    }:
        raise ValueError("SCuBA evidence integrity record is invalid")
    _nonnegative_integer(integrity["control_count"], "integrity.control_count")
    _nonnegative_integer(integrity["candidate_poam_count"], "integrity.candidate_poam_count")
    if integrity != {
        "source_summary_reconciled": True,
        "unique_control_ids": True,
        "control_count": len(controls),
        "candidate_poam_count": candidates,
    }:
        raise ValueError("SCuBA evidence integrity record does not reconcile")


def _scuba_observation(
    control: Dict[str, str], *, result_uuid: str, collected: str
) -> Dict[str, Any]:
    observation_uuid = str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"{PROPERTY_NAMESPACE}/scuba-observation/{result_uuid}:{control['control_id']}",
        )
    )
    return {
        "uuid": observation_uuid,
        "title": f"Imported SCuBA observation: {control['control_id']}",
        "description": (
            f"The registered ScubaGear source reported {control['result']} for "
            f"{control['control_id']} with source criticality {control['criticality']}."
        ),
        "props": [
            _property("source-tool", "ScubaGear"),
            _property("source-product", control["product"]),
            _property("source-control-id", control["control_id"]),
            _property("source-result", control["result"]),
            _property("source-criticality", control["criticality"]),
        ],
        "methods": ["EXAMINE"],
        "types": ["technical"],
        "relevant-evidence": [
            {
                "href": SCUBA_EVIDENCE_FILE,
                "description": (
                    "Privacy-minimized imported SCuBA result bound to the source report "
                    "by SHA-256; raw provider data is not included."
                ),
            }
        ],
        "collected": collected,
        "remarks": (
            "Imported source observation only; LureScope did not execute the SCuBA "
            "policy or determine control satisfaction."
        ),
    }


def _combined_assessment_results(
    existing: Dict[str, Any],
    evidence: Dict[str, Any],
    *,
    existing_digest: str,
    evidence_digest: str,
    generated_at: str,
) -> Dict[str, Any]:
    if set(existing) != {"$schema", "assessment-results"} or existing.get(
        "$schema"
    ) != OSCAL_AR_SCHEMA:
        raise ValueError("existing OSCAL Assessment Results has an unsupported shape")
    combined = copy.deepcopy(existing)
    body = combined["assessment-results"]
    if not isinstance(body, dict) or not isinstance(body.get("results"), list) or not body[
        "results"
    ]:
        raise ValueError("existing OSCAL Assessment Results has no result set")
    binding = f"{existing_digest}:{evidence_digest}:{generated_at}"
    document_uuid = str(
        uuid.uuid5(uuid.NAMESPACE_URL, f"{PROPERTY_NAMESPACE}/combined-results/{binding}")
    )
    result_uuid = str(
        uuid.uuid5(uuid.NAMESPACE_URL, f"{PROPERTY_NAMESPACE}/scuba-result/{binding}")
    )
    observations = [
        _scuba_observation(
            control,
            result_uuid=result_uuid,
            collected=evidence["source"]["report_timestamp"],
        )
        for control in evidence["controls"]
    ]
    body["uuid"] = document_uuid
    metadata = body.get("metadata")
    if not isinstance(metadata, dict) or not isinstance(metadata.get("props"), list):
        raise ValueError("existing OSCAL Assessment Results metadata is invalid")
    metadata["title"] = "LureScope Combined Email Assurance Results"
    metadata["last-modified"] = generated_at
    metadata["props"].extend(
        [
            _property("combined-email-assurance", "true"),
            _property("scuba-evidence-sha256", evidence_digest),
            _property("source-scuba-report-sha256", evidence["source"]["report_sha256"]),
            _property("source-scubagear-version", evidence["source"]["tool_version"]),
        ]
    )
    metadata["remarks"] = _INTERPRETATION_BOUNDARY
    body["results"].append(
        {
            "uuid": result_uuid,
            "title": "Imported CISA SCuBA email-configuration observations",
            "description": (
                "Privacy-minimized AAD, Defender, and Exchange Online observations "
                "imported from a validated ScubaGear consolidated report."
            ),
            "start": evidence["source"]["report_timestamp"],
            "end": evidence["source"]["report_timestamp"],
            "props": [
                _property("source-tool", "ScubaGear"),
                _property("source-version", evidence["source"]["tool_version"]),
                _property("observation-count", len(observations)),
                _property(
                    "candidate-poam-count",
                    evidence["integrity"]["candidate_poam_count"],
                ),
                _property("scuba-to-nist-control-crosswalk", "none"),
            ],
            "reviewed-controls": _reviewed_controls(),
            "observations": observations,
            "remarks": _INTERPRETATION_BOUNDARY,
        }
    )
    return combined


def _candidate_poam(
    evidence: Dict[str, Any],
    *,
    ssp_href: str,
    evidence_digest: str,
    generated_at: str,
) -> Optional[Dict[str, Any]]:
    candidates = [
        control
        for control in evidence["controls"]
        if control["result"] == "Fail" and control["criticality"] == "Shall"
    ]
    if not candidates:
        return None
    binding = f"{evidence_digest}:{generated_at}"
    document_uuid = str(
        uuid.uuid5(uuid.NAMESPACE_URL, f"{PROPERTY_NAMESPACE}/candidate-poam/{binding}")
    )
    observations = []
    items = []
    for control in candidates:
        observation_uuid = str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"{PROPERTY_NAMESPACE}/poam-observation/{binding}:{control['control_id']}",
            )
        )
        item_uuid = str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"{PROPERTY_NAMESPACE}/poam-item/{binding}:{control['control_id']}",
            )
        )
        observations.append(
            {
                "uuid": observation_uuid,
                "title": f"Candidate source observation: {control['control_id']}",
                "description": (
                    f"ScubaGear reported Fail for SHALL control {control['control_id']}."
                ),
                "props": [
                    _property("source-product", control["product"]),
                    _property("source-control-id", control["control_id"]),
                    _property("source-result", "Fail"),
                    _property("source-criticality", "Shall"),
                ],
                "methods": ["EXAMINE"],
                "types": ["technical"],
                "relevant-evidence": [
                    {
                        "href": SCUBA_EVIDENCE_FILE,
                        "description": (
                            "Privacy-minimized imported SCuBA result bound to the "
                            "registered source report by SHA-256."
                        ),
                    }
                ],
                "collected": evidence["source"]["report_timestamp"],
                "remarks": "Imported source result; independent validation is required.",
            }
        )
        items.append(
            {
                "uuid": item_uuid,
                "title": f"Candidate remediation item: {control['control_id']}",
                "description": (
                    "Candidate generated from an imported failing SCuBA SHALL result. "
                    "The system owner must validate applicability, risk, ownership, "
                    "milestones, dates, and disposition before operational use."
                ),
                "props": [
                    _property("candidate-only", "true"),
                    _property("source-product", control["product"]),
                    _property("source-control-id", control["control_id"]),
                    _property("source-result", "Fail"),
                ],
                "related-observations": [{"observation-uuid": observation_uuid}],
                "remarks": (
                    "This is not an approved POA&M entry, risk acceptance, finding, "
                    "deadline, or remediation commitment."
                ),
            }
        )
    return {
        "$schema": OSCAL_POAM_SCHEMA,
        "plan-of-action-and-milestones": {
            "uuid": document_uuid,
            "metadata": {
                "title": "LureScope Candidate SCuBA POA&M Items",
                "last-modified": generated_at,
                "version": "1.0.0",
                "oscal-version": OSCAL_VERSION,
                "props": [
                    _property("candidate-only", "true"),
                    _property("scuba-evidence-sha256", evidence_digest),
                    _property("candidate-count", len(items)),
                    _property("lurescope-version", __version__),
                ],
                "remarks": _INTERPRETATION_BOUNDARY,
            },
            "import-ssp": {"href": ssp_href},
            "observations": observations,
            "poam-items": items,
        },
    }


def _statement(
    subjects: list[Dict[str, Any]],
    evidence: Dict[str, Any],
    gate: Dict[str, Any],
    *,
    generated_at: str,
) -> Dict[str, Any]:
    return {
        "_type": STATEMENT_TYPE,
        "subject": subjects,
        "predicateType": COMBINED_PREDICATE_TYPE,
        "predicate": {
            "spec": "combined-email-assurance",
            "spec_version": "1.0",
            "generated_at": generated_at,
            "source": {
                "scubagear_report_sha256": evidence["source"]["report_sha256"],
                "scubagear_version": evidence["source"]["tool_version"],
                "scubagear_contract": evidence["source"]["contract"],
            },
            "outcome": {
                "pilot_gate_verdict": gate["verdict"],
                "scuba_control_count": evidence["integrity"]["control_count"],
                "candidate_poam_count": evidence["integrity"]["candidate_poam_count"],
            },
            "privacy": {
                "minimized_scuba_evidence": True,
                "contains_tenant_identifiers": False,
                "contains_message_content": False,
                "shareable_by_default": False,
            },
            "interpretation_boundary": _INTERPRETATION_BOUNDARY,
            "limitations": _LIMITATIONS,
        },
    }


def _pae(payload_type: str, payload: bytes) -> bytes:
    type_bytes = payload_type.encode("utf-8")
    return b"DSSEv1 %d " % len(type_bytes) + type_bytes + b" %d " % len(payload) + payload


def _public_key_id(public_key: ec.EllipticCurvePublicKey) -> str:
    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()


def _sign_payload(payload: bytes, private_key_pem: bytes) -> Dict[str, Any]:
    try:
        key = serialization.load_pem_private_key(private_key_pem, password=None)
    except (TypeError, ValueError) as exc:
        raise ValueError("could not load an unencrypted PEM private key") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise ValueError("signing key must be an unencrypted ECDSA P-256 private key")
    signature = key.sign(_pae(DSSE_PAYLOAD_TYPE, payload), ec.ECDSA(hashes.SHA256()))
    key.public_key().verify(
        signature, _pae(DSSE_PAYLOAD_TYPE, payload), ec.ECDSA(hashes.SHA256())
    )
    return {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [
            {
                "keyid": _public_key_id(key.public_key()),
                "sig": base64.b64encode(signature).decode("ascii"),
            }
        ],
    }


def _copy_new(source: Path, destination: Path) -> None:
    _write_new(destination, _read_regular(source, maximum=_MAX_BUNDLE_FILE_BYTES))


def create_scuba_assurance_bundle(
    report_path: Path,
    shadow_bundle: Path,
    assurance_plan: Path,
    output_dir: Path,
    *,
    signing_key: Optional[Path] = None,
) -> Dict[str, Any]:
    """Create a private, no-overwrite combined assurance evidence directory."""
    target = Path(output_dir)
    if target.exists() or target.is_symlink():
        raise FileExistsError(target)
    evidence, source_raw = ingest_scuba_report(report_path)
    assurance = export_assurance_results(shadow_bundle, assurance_plan)
    gate = assurance["gate"]
    generated_at = _timestamp()
    target.mkdir(mode=0o700)
    created: list[Path] = []
    try:
        for name in (PILOT_PLAN_FILE, PROFILE_FILE, OSCAL_PLAN_FILE, PILOT_GATE_FILE):
            destination = target / name
            _copy_new(Path(shadow_bundle) / name, destination)
            created.append(destination)

        evidence_payload = _canonical_json(evidence)
        evidence_path = target / SCUBA_EVIDENCE_FILE
        _write_new(evidence_path, evidence_payload)
        created.append(evidence_path)
        evidence_digest = _sha256(evidence_payload)

        existing_path = Path(shadow_bundle) / OSCAL_RESULTS_FILE
        existing, existing_raw = _load_json(existing_path)
        combined = _combined_assessment_results(
            existing,
            evidence,
            existing_digest=_sha256(existing_raw),
            evidence_digest=evidence_digest,
            generated_at=generated_at,
        )
        combined_path = target / OSCAL_RESULTS_FILE
        _write_new(combined_path, _canonical_json(combined))
        created.append(combined_path)

        assessment_plan, _ = _load_json(target / OSCAL_PLAN_FILE)
        ssp_href = assessment_plan["assessment-plan"]["import-ssp"]["href"]
        poam = _candidate_poam(
            evidence,
            ssp_href=ssp_href,
            evidence_digest=evidence_digest,
            generated_at=generated_at,
        )
        if poam is not None:
            poam_path = target / OSCAL_POAM_FILE
            _write_new(poam_path, _canonical_json(poam))
            created.append(poam_path)

        subject_names = [
            PILOT_PLAN_FILE,
            PROFILE_FILE,
            OSCAL_PLAN_FILE,
            PILOT_GATE_FILE,
            SCUBA_EVIDENCE_FILE,
            OSCAL_RESULTS_FILE,
        ]
        if poam is not None:
            subject_names.append(OSCAL_POAM_FILE)
        subjects = [
            {
                "name": name,
                "digest": {
                    "sha256": _sha256(
                        _read_regular(target / name, maximum=_MAX_BUNDLE_FILE_BYTES)
                    )
                },
            }
            for name in subject_names
        ]
        statement = _statement(subjects, evidence, gate, generated_at=generated_at)
        statement_payload = _canonical_json(statement)
        statement_path = target / STATEMENT_FILE
        _write_new(statement_path, statement_payload)
        created.append(statement_path)

        if signing_key is not None:
            key_payload = _read_regular(Path(signing_key), maximum=64 * 1024)
            envelope = _sign_payload(statement_payload, key_payload)
            envelope_path = target / DSSE_FILE
            _write_new(envelope_path, _canonical_json(envelope))
            created.append(envelope_path)

        if not secrets.compare_digest(
            source_raw, _read_regular(Path(report_path), maximum=_MAX_SCUBA_REPORT_BYTES)
        ):
            raise ValueError("ScubaGear source report changed during import")
        verification = verify_scuba_assurance_bundle(target)
        return {
            "gate": gate,
            "evidence": evidence,
            "assessment_results": combined,
            "poam": poam,
            "statement": statement,
            "verification": verification,
        }
    except Exception:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        target.rmdir()
        raise


def _load_bundle_json(path: Path) -> tuple[Dict[str, Any], bytes]:
    raw = _read_regular(path, maximum=_MAX_BUNDLE_FILE_BYTES)
    return _parse_json_object(raw, path.name), raw


def _verify_statement(statement: Dict[str, Any], directory: Path) -> Dict[str, Any]:
    if set(statement) != {"_type", "subject", "predicateType", "predicate"}:
        raise ValueError("combined assurance statement violates the field allowlist")
    if statement.get("_type") != STATEMENT_TYPE or statement.get(
        "predicateType"
    ) != COMBINED_PREDICATE_TYPE:
        raise ValueError("combined assurance statement identity is invalid")
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not subjects:
        raise ValueError("combined assurance statement requires subjects")
    observed_names = []
    for subject in subjects:
        if not isinstance(subject, dict) or set(subject) != {"name", "digest"}:
            raise ValueError("combined assurance subject violates the field allowlist")
        name = subject.get("name")
        digest = subject.get("digest")
        if (
            not isinstance(name, str)
            or Path(name).name != name
            or not isinstance(digest, dict)
            or set(digest) != {"sha256"}
            or not isinstance(digest["sha256"], str)
            or _SHA256.fullmatch(digest["sha256"]) is None
        ):
            raise ValueError("combined assurance subject binding is invalid")
        if name in observed_names:
            raise ValueError("combined assurance statement contains duplicate subjects")
        observed_names.append(name)
        actual = _sha256(_read_regular(directory / name, maximum=_MAX_BUNDLE_FILE_BYTES))
        if not secrets.compare_digest(actual, digest["sha256"]):
            raise ValueError(f"combined assurance subject digest mismatch: {name}")
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict) or set(predicate) != {
        "spec",
        "spec_version",
        "generated_at",
        "source",
        "outcome",
        "privacy",
        "interpretation_boundary",
        "limitations",
    }:
        raise ValueError("combined assurance predicate violates the v1 allowlist")
    if (
        predicate.get("spec") != "combined-email-assurance"
        or predicate.get("spec_version") != "1.0"
        or predicate.get("interpretation_boundary") != _INTERPRETATION_BOUNDARY
        or predicate.get("limitations") != _LIMITATIONS
    ):
        raise ValueError("combined assurance predicate identity is invalid")
    _parse_timestamp(predicate.get("generated_at"), "predicate.generated_at")
    return predicate


def _verify_dsse(
    envelope: Dict[str, Any],
    expected_payload: bytes,
    public_key_pem: Optional[bytes],
) -> tuple[bool, list[str]]:
    if set(envelope) != {"payloadType", "payload", "signatures"}:
        raise ValueError("combined assurance DSSE envelope violates the field allowlist")
    if envelope.get("payloadType") != DSSE_PAYLOAD_TYPE:
        raise ValueError("combined assurance DSSE payload type is invalid")
    encoded = envelope.get("payload")
    signatures = envelope.get("signatures")
    if not isinstance(encoded, str) or not isinstance(signatures, list) or not signatures:
        raise ValueError("combined assurance DSSE payload or signatures are invalid")
    if len(signatures) > 16:
        raise ValueError("combined assurance DSSE exceeds the signature safety limit")
    try:
        payload = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("combined assurance DSSE payload is not valid base64") from exc
    if not secrets.compare_digest(payload, expected_payload):
        raise ValueError("combined assurance DSSE payload differs from the statement file")
    key_ids = []
    decoded_signatures: list[tuple[str, bytes]] = []
    for signature in signatures:
        if not isinstance(signature, dict) or set(signature) != {"keyid", "sig"}:
            raise ValueError("combined assurance DSSE signature shape is invalid")
        key_id = signature.get("keyid")
        if not isinstance(key_id, str) or _SHA256.fullmatch(key_id) is None:
            raise ValueError("combined assurance DSSE keyid is invalid")
        try:
            signature_bytes = base64.b64decode(signature.get("sig"), validate=True)
        except (TypeError, ValueError, binascii.Error) as exc:
            raise ValueError("combined assurance DSSE signature is not valid base64") from exc
        key_ids.append(key_id)
        decoded_signatures.append((key_id, signature_bytes))
    if public_key_pem is None:
        return False, key_ids
    try:
        key = serialization.load_pem_public_key(public_key_pem)
    except (TypeError, ValueError) as exc:
        raise ValueError("could not load the trusted PEM public key") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("verification key must be an ECDSA P-256 public key")
    trusted_key_id = _public_key_id(key)
    candidates = [value for key_id, value in decoded_signatures if key_id == trusted_key_id]
    if not candidates:
        raise ValueError("no combined assurance signature matches the trusted public key")
    for signature in candidates:
        try:
            key.verify(
                signature,
                _pae(DSSE_PAYLOAD_TYPE, payload),
                ec.ECDSA(hashes.SHA256()),
            )
            return True, key_ids
        except InvalidSignature:
            continue
    raise ValueError("combined assurance signature verification failed")


def _property_value(props: object, name: str) -> str:
    if not isinstance(props, list):
        raise ValueError("OSCAL properties must be an array")
    matches = [
        item.get("value")
        for item in props
        if isinstance(item, dict)
        and item.get("name") == name
        and item.get("ns") == PROPERTY_NAMESPACE
    ]
    if len(matches) != 1 or not isinstance(matches[0], str):
        raise ValueError(f"OSCAL property {name} is missing or duplicated")
    return matches[0]


def verify_scuba_assurance_bundle(
    directory: Path,
    *,
    public_key: Optional[Path] = None,
    require_signature: bool = False,
) -> Dict[str, Any]:
    """Verify package structure, cross-file digests, semantics, and optional DSSE."""
    directory = Path(directory)
    if directory.is_symlink():
        raise ValueError("refusing symbolic-link combined assurance directory")
    if not directory.is_dir():
        raise FileNotFoundError(directory)
    required = {
        PILOT_PLAN_FILE,
        PROFILE_FILE,
        OSCAL_PLAN_FILE,
        PILOT_GATE_FILE,
        SCUBA_EVIDENCE_FILE,
        OSCAL_RESULTS_FILE,
        STATEMENT_FILE,
    }
    actual = {entry.name for entry in directory.iterdir()}
    optional = {OSCAL_POAM_FILE, DSSE_FILE}
    if not required <= actual or actual - required - optional:
        raise ValueError("combined assurance directory contains an unexpected file set")
    if os.name == "posix":
        if directory.stat().st_mode & 0o077:
            raise ValueError("combined assurance directory must not grant group or world access")
        for name in actual:
            path = directory / name
            if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
                raise ValueError(f"{name} must be a private regular file")

    statement, statement_raw = _load_bundle_json(directory / STATEMENT_FILE)
    predicate = _verify_statement(statement, directory)
    subject_names = [item["name"] for item in statement["subject"]]
    expected_subjects = [
        PILOT_PLAN_FILE,
        PROFILE_FILE,
        OSCAL_PLAN_FILE,
        PILOT_GATE_FILE,
        SCUBA_EVIDENCE_FILE,
        OSCAL_RESULTS_FILE,
    ]
    if OSCAL_POAM_FILE in actual:
        expected_subjects.append(OSCAL_POAM_FILE)
    if subject_names != expected_subjects:
        raise ValueError("combined assurance statement subject order or coverage is invalid")

    evidence, _ = _load_bundle_json(directory / SCUBA_EVIDENCE_FILE)
    validate_scuba_evidence(evidence)
    source = predicate.get("source")
    outcome = predicate.get("outcome")
    privacy = predicate.get("privacy")
    if source != {
        "scubagear_report_sha256": evidence["source"]["report_sha256"],
        "scubagear_version": evidence["source"]["tool_version"],
        "scubagear_contract": evidence["source"]["contract"],
    }:
        raise ValueError("combined assurance statement source does not match SCuBA evidence")
    expected_privacy = {
        "minimized_scuba_evidence": True,
        "contains_tenant_identifiers": False,
        "contains_message_content": False,
        "shareable_by_default": False,
    }
    if not isinstance(privacy, dict) or _canonical_json(privacy) != _canonical_json(
        expected_privacy
    ):
        raise ValueError("combined assurance statement privacy boundary is invalid")

    profile, profile_raw = _load_bundle_json(directory / PROFILE_FILE)
    _validate_profile(profile)
    pilot = load_pilot_plan(directory / PILOT_PLAN_FILE)
    assessment_plan, ap_raw = _load_bundle_json(directory / OSCAL_PLAN_FILE)
    if _sha256(_read_regular(directory / PILOT_PLAN_FILE)) != profile["artifacts"][
        "pilot_plan"
    ]["sha256"]:
        raise ValueError("combined assurance pilot plan binding is invalid")
    if _sha256(ap_raw) != profile["artifacts"]["oscal_assessment_plan"]["sha256"]:
        raise ValueError("combined assurance assessment plan binding is invalid")
    _validate_assessment_plan(assessment_plan, profile, pilot)

    gate, _ = _load_bundle_json(directory / PILOT_GATE_FILE)
    if (
        not isinstance(gate.get("plan_binding"), dict)
        or gate["plan_binding"].get("sha256") != profile["artifacts"]["pilot_plan"]["sha256"]
        or gate.get("verdict") not in {"pass", "fail", "insufficient_evidence"}
        or gate.get("privacy")
        != {
            "aggregate_only": True,
            "contains_case_identifiers": False,
            "contains_message_content": False,
        }
    ):
        raise ValueError("combined assurance Pilot Gate binding is invalid")
    expected_outcome = {
        "pilot_gate_verdict": gate["verdict"],
        "scuba_control_count": evidence["integrity"]["control_count"],
        "candidate_poam_count": evidence["integrity"]["candidate_poam_count"],
    }
    if not isinstance(outcome, dict) or _canonical_json(outcome) != _canonical_json(
        expected_outcome
    ):
        raise ValueError("combined assurance statement outcome does not reconcile")

    combined, _ = _load_bundle_json(directory / OSCAL_RESULTS_FILE)
    if set(combined) != {"$schema", "assessment-results"} or combined.get(
        "$schema"
    ) != OSCAL_AR_SCHEMA:
        raise ValueError("combined OSCAL Assessment Results identity is invalid")
    body = combined["assessment-results"]
    if not isinstance(body, dict) or not isinstance(body.get("results"), list):
        raise ValueError("combined OSCAL Assessment Results shape is invalid")
    if any("findings" in result for result in body["results"] if isinstance(result, dict)):
        raise ValueError("combined OSCAL results must not create findings")
    evidence_digest = _sha256(_canonical_json(evidence))
    if _property_value(body.get("metadata", {}).get("props"), "scuba-evidence-sha256") != (
        evidence_digest
    ):
        raise ValueError("combined OSCAL results do not bind the SCuBA evidence")
    if _property_value(
        body.get("metadata", {}).get("props"), "source-scuba-report-sha256"
    ) != evidence["source"]["report_sha256"]:
        raise ValueError("combined OSCAL results do not bind the source report")

    expected_base = _assessment_results(gate, profile, _sha256(profile_raw))
    expected_combined = _combined_assessment_results(
        expected_base,
        evidence,
        existing_digest=_sha256(_canonical_json(expected_base)),
        evidence_digest=evidence_digest,
        generated_at=predicate["generated_at"],
    )
    if _canonical_json(combined) != _canonical_json(expected_combined):
        raise ValueError("combined OSCAL results do not exactly reconcile with their evidence")

    expected_candidates = evidence["integrity"]["candidate_poam_count"]
    if (OSCAL_POAM_FILE in actual) != (expected_candidates > 0):
        raise ValueError("candidate POA&M presence does not match the evidence")
    if OSCAL_POAM_FILE in actual:
        poam, _ = _load_bundle_json(directory / OSCAL_POAM_FILE)
        if set(poam) != {"$schema", "plan-of-action-and-milestones"} or poam.get(
            "$schema"
        ) != OSCAL_POAM_SCHEMA:
            raise ValueError("candidate OSCAL POA&M identity is invalid")
        poam_body = poam["plan-of-action-and-milestones"]
        if (
            not isinstance(poam_body, dict)
            or len(poam_body.get("poam-items", [])) != expected_candidates
            or "risks" in poam_body
            or "findings" in poam_body
        ):
            raise ValueError("candidate OSCAL POA&M semantics are invalid")
        if _property_value(poam_body.get("metadata", {}).get("props"), "candidate-only") != (
            "true"
        ):
            raise ValueError("candidate OSCAL POA&M lacks its candidate-only boundary")
        expected_poam = _candidate_poam(
            evidence,
            ssp_href=assessment_plan["assessment-plan"]["import-ssp"]["href"],
            evidence_digest=evidence_digest,
            generated_at=predicate["generated_at"],
        )
        if _canonical_json(poam) != _canonical_json(expected_poam):
            raise ValueError("candidate OSCAL POA&M does not exactly reconcile with evidence")

    authenticated = False
    key_ids: list[str] = []
    if DSSE_FILE in actual:
        envelope, _ = _load_bundle_json(directory / DSSE_FILE)
        public_key_pem = (
            _read_regular(Path(public_key), maximum=64 * 1024)
            if public_key is not None
            else None
        )
        authenticated, key_ids = _verify_dsse(envelope, statement_raw, public_key_pem)
    elif require_signature:
        raise ValueError("authenticated verification requires a DSSE envelope")
    if require_signature and public_key is None:
        raise ValueError("authenticated verification requires a trusted public key")
    if require_signature and not authenticated:
        raise ValueError("an authenticated combined assurance signature is required")
    return {
        "valid": True,
        "authenticated": authenticated,
        "artifact_type": "dsse" if DSSE_FILE in actual else "statement",
        "statement_sha256": _sha256(statement_raw),
        "signature_count": len(key_ids),
        "key_ids": key_ids,
        "pilot_gate_verdict": gate["verdict"],
        "scuba_control_count": evidence["integrity"]["control_count"],
        "candidate_poam_count": expected_candidates,
        "assurance_profile_sha256": _sha256(profile_raw),
    }
