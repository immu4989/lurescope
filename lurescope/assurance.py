"""Federal Email Assurance Profile and OSCAL assessment evidence.

The profile composes the existing pre-registered Pilot Gate with NIST OSCAL
Assessment Plan and Assessment Results artifacts.  It deliberately emits
observations, not compliance findings: a mailbox sample cannot establish that a
system satisfies a security control or deserves an authorization to operate.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import uuid
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

from . import __version__
from .pilot import create_pilot_plan, load_pilot_plan, pilot_plan_sha256, write_pilot_gate

ASSURANCE_PROFILE_SCHEMA = "https://github.com/immu4989/lurescope/spec/assurance-profile/v1"
FEDERAL_PROFILE_ID = "federal-email-assurance-v1"
FEDERAL_PROFILE_VERSION = "1.0.0"
OSCAL_VERSION = "1.2.2"
OSCAL_AP_SCHEMA = "http://csrc.nist.gov/ns/oscal/1.2.2/oscal-ap-schema.json"
OSCAL_AR_SCHEMA = "http://csrc.nist.gov/ns/oscal/1.2.2/oscal-ar-schema.json"
PROPERTY_NAMESPACE = "https://github.com/immu4989/lurescope/ns/oscal"

PILOT_PLAN_FILE = "pilot-plan.json"
OSCAL_PLAN_FILE = "oscal-assessment-plan.json"
PROFILE_FILE = "assurance-profile.json"
OSCAL_RESULTS_FILE = "oscal-assessment-results.json"

_MAX_PLAN_FILE_BYTES = 512 * 1024
_PROFILE_KEYS = {
    "schema",
    "schema_version",
    "profile_id",
    "profile_version",
    "created_at",
    "oscal_version",
    "controls",
    "artifacts",
    "privacy",
    "interpretation_boundary",
    "limitations",
}
_ARTIFACT_KEYS = {"pilot_plan", "oscal_assessment_plan"}
_ARTIFACT_VALUE_KEYS = {"file", "sha256"}
_AP_ARTIFACT_VALUE_KEYS = {"file", "sha256", "uuid"}
_PRIVACY = {
    "aggregate_only_results": True,
    "contains_case_identifiers": False,
    "contains_message_content": False,
    "network_required": False,
}
_INTERPRETATION_BOUNDARY = (
    "This profile records evidence relevant to selected controls. It does not determine "
    "control satisfaction, certify a product, grant an authorization to operate, or "
    "authorize autonomous email or payment enforcement."
)
_LIMITATIONS = [
    "control_mapping_is_not_compliance_determination",
    "oscal_output_is_not_authorization_package",
    "representative_sample_and_trustworthy_labels_required",
    "scuba_configuration_not_assessed",
    "message_content_and_case_identifiers_excluded",
    "human_authorizing_official_decision_required",
]
CONTROL_MAPPINGS = [
    {
        "control_id": "ca-7",
        "title": "Continuous Monitoring",
        "relationship": "evidence_relevant",
        "measurement": (
            "Pre-registered routing, error, workload, and resilience measurements over "
            "an operator-approved email sample."
        ),
    },
    {
        "control_id": "si-4",
        "title": "System Monitoring",
        "relationship": "evidence_relevant",
        "measurement": (
            "Aggregate detection, analyst-review, failure, and adversarial-resilience "
            "observations from a no-enforcement shadow run."
        ),
    },
    {
        "control_id": "si-8",
        "title": "Spam Protection",
        "relationship": "evidence_relevant",
        "measurement": (
            "Observed routing behavior for suspicious email under a registered detector "
            "and threshold; LureScope does not block, quarantine, or deliver messages."
        ),
    },
]

_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[45][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:[+-][0-9A-Za-z.-]+)?$")


def _canonical_json(value: Dict[str, Any]) -> bytes:
    return (json.dumps(value, allow_nan=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _read_regular(path: Path, *, maximum: int = _MAX_PLAN_FILE_BYTES) -> bytes:
    path = Path(path)
    if path.is_symlink():
        raise ValueError(f"refusing symbolic-link {path.name}")
    if not path.is_file():
        raise FileNotFoundError(path)
    if path.stat().st_size > maximum:
        raise ValueError(f"{path.name} exceeds the {maximum} byte safety limit")
    return path.read_bytes()


def _write_new(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _replace_private(path: Path, payload: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        _write_new(temporary, payload)
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


def _safe_identifier_href(value: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        raise ValueError("ssp_href must be a 1-2048 character URI")
    if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError("ssp_href cannot contain whitespace or control characters")
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise ValueError("ssp_href must be a valid URI") from exc
    if parsed.scheme not in {"https", "urn"}:
        raise ValueError("ssp_href must use a portable https: or urn: identifier")
    if parsed.scheme == "https" and (not parsed.netloc or parsed.username or parsed.password):
        raise ValueError("https ssp_href must have a host and cannot contain credentials")
    if parsed.scheme == "urn" and not parsed.path:
        raise ValueError("urn ssp_href must contain a namespace-specific identifier")
    return value


def _uuid5(purpose: str, binding: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{PROPERTY_NAMESPACE}/{purpose}/{binding}"))


def _property(name: str, value: object) -> Dict[str, str]:
    text = str(value)
    if not text or text != text.strip():
        raise ValueError(f"OSCAL property {name} has an invalid empty or padded value")
    return {"name": name, "ns": PROPERTY_NAMESPACE, "value": text}


def _reviewed_controls() -> Dict[str, Any]:
    return {
        "description": (
            "Controls selected for evidence collection by the LureScope Federal Email "
            "Assurance Profile. Selection does not assert that a control was fully assessed."
        ),
        "control-selections": [
            {
                "description": (
                    "The mailbox pilot produces limited evidence relevant to these controls."
                ),
                "include-controls": [
                    {"control-id": item["control_id"]} for item in CONTROL_MAPPINGS
                ],
                "remarks": _INTERPRETATION_BOUNDARY,
            }
        ],
    }


def _assessment_plan(
    pilot_plan: Dict[str, Any], pilot_digest: str, ssp_href: str
) -> Dict[str, Any]:
    plan_uuid = _uuid5("assessment-plan", f"{pilot_digest}:{ssp_href}")
    return {
        "$schema": OSCAL_AP_SCHEMA,
        "assessment-plan": {
            "uuid": plan_uuid,
            "metadata": {
                "title": f"LureScope Federal Email Assurance — {pilot_plan['plan_id']}",
                "last-modified": pilot_plan["created_at"],
                "version": FEDERAL_PROFILE_VERSION,
                "oscal-version": OSCAL_VERSION,
                "props": [
                    _property("profile-id", FEDERAL_PROFILE_ID),
                    _property("profile-schema", ASSURANCE_PROFILE_SCHEMA),
                    _property("pilot-plan-sha256", pilot_digest),
                    _property("lurescope-version", __version__),
                ],
                "remarks": _INTERPRETATION_BOUNDARY,
            },
            "import-ssp": {"href": ssp_href},
            "reviewed-controls": _reviewed_controls(),
        },
    }


def _profile(
    pilot_plan: Dict[str, Any], pilot_digest: str, ap: Dict[str, Any], ap_digest: str
) -> Dict[str, Any]:
    return {
        "schema": ASSURANCE_PROFILE_SCHEMA,
        "schema_version": 1,
        "profile_id": FEDERAL_PROFILE_ID,
        "profile_version": FEDERAL_PROFILE_VERSION,
        "created_at": pilot_plan["created_at"],
        "oscal_version": OSCAL_VERSION,
        "controls": CONTROL_MAPPINGS,
        "artifacts": {
            "pilot_plan": {"file": PILOT_PLAN_FILE, "sha256": pilot_digest},
            "oscal_assessment_plan": {
                "file": OSCAL_PLAN_FILE,
                "sha256": ap_digest,
                "uuid": ap["assessment-plan"]["uuid"],
            },
        },
        "privacy": _PRIVACY,
        "interpretation_boundary": _INTERPRETATION_BOUNDARY,
        "limitations": _LIMITATIONS,
    }


def create_assurance_plan(
    output_dir: Path,
    *,
    ssp_href: str,
    plan_id: str,
    min_processed_count: int,
    min_fraud_labels: int,
    min_benign_labels: int,
    max_uncertain_rate: float,
    max_processing_failure_rate: float,
    min_routing_recall_lower_bound: float,
    max_routing_false_positive_rate_upper_bound: float,
    max_routed_rate: float,
    max_routed_count: int,
    confidence: float = 0.95,
    labeling_protocol: str = "full_blinded_review",
    detector: str = "tfidf-logreg",
    threshold: float = 0.5,
    policy_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a private, no-overwrite assurance plan directory."""
    target = Path(output_dir)
    portable_ssp_href = _safe_identifier_href(ssp_href)
    if target.exists() or target.is_symlink():
        raise FileExistsError(target)
    target.mkdir(mode=0o700)
    created: list[Path] = []
    try:
        pilot_path = target / PILOT_PLAN_FILE
        pilot = create_pilot_plan(
            pilot_path,
            plan_id=plan_id,
            min_processed_count=min_processed_count,
            min_fraud_labels=min_fraud_labels,
            min_benign_labels=min_benign_labels,
            max_uncertain_rate=max_uncertain_rate,
            max_processing_failure_rate=max_processing_failure_rate,
            min_routing_recall_lower_bound=min_routing_recall_lower_bound,
            max_routing_false_positive_rate_upper_bound=(
                max_routing_false_positive_rate_upper_bound
            ),
            max_routed_rate=max_routed_rate,
            max_routed_count=max_routed_count,
            confidence=confidence,
            labeling_protocol=labeling_protocol,
            detector=detector,
            threshold=threshold,
            policy_id=policy_id,
        )
        created.append(pilot_path)
        pilot_digest = pilot_plan_sha256(pilot_path)
        ap = _assessment_plan(pilot, pilot_digest, portable_ssp_href)
        ap_payload = _canonical_json(ap)
        ap_path = target / OSCAL_PLAN_FILE
        _write_new(ap_path, ap_payload)
        created.append(ap_path)
        profile = _profile(pilot, pilot_digest, ap, _sha256(ap_payload))
        profile_path = target / PROFILE_FILE
        _write_new(profile_path, _canonical_json(profile))
        created.append(profile_path)
        load_assurance_plan(target)
        return profile
    except Exception:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        target.rmdir()
        raise


def _load_json(path: Path) -> tuple[Dict[str, Any], bytes]:
    raw = _read_regular(path)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path.name} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return value, raw


def _validate_profile(profile: Dict[str, Any]) -> None:
    if set(profile) != _PROFILE_KEYS:
        raise ValueError("assurance profile violates the v1 allowlist")
    if (
        profile.get("schema") != ASSURANCE_PROFILE_SCHEMA
        or profile.get("schema_version") != 1
        or profile.get("profile_id") != FEDERAL_PROFILE_ID
        or profile.get("profile_version") != FEDERAL_PROFILE_VERSION
        or profile.get("oscal_version") != OSCAL_VERSION
    ):
        raise ValueError("assurance profile identifier or version is unsupported")
    if profile.get("controls") != CONTROL_MAPPINGS:
        raise ValueError("assurance profile control mappings are unsupported")
    if profile.get("privacy") != _PRIVACY:
        raise ValueError("assurance profile privacy boundary is invalid")
    if profile.get("interpretation_boundary") != _INTERPRETATION_BOUNDARY:
        raise ValueError("assurance profile interpretation boundary is invalid")
    if profile.get("limitations") != _LIMITATIONS:
        raise ValueError("assurance profile limitations are invalid")
    artifacts = profile.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != _ARTIFACT_KEYS:
        raise ValueError("assurance profile artifact bindings are invalid")
    pilot = artifacts["pilot_plan"]
    ap = artifacts["oscal_assessment_plan"]
    if not isinstance(pilot, dict) or set(pilot) != _ARTIFACT_VALUE_KEYS:
        raise ValueError("pilot plan artifact binding is invalid")
    if not isinstance(ap, dict) or set(ap) != _AP_ARTIFACT_VALUE_KEYS:
        raise ValueError("OSCAL assessment plan artifact binding is invalid")
    if pilot.get("file") != PILOT_PLAN_FILE or ap.get("file") != OSCAL_PLAN_FILE:
        raise ValueError("assurance profile artifact filenames are invalid")
    for digest in (pilot.get("sha256"), ap.get("sha256")):
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise ValueError("assurance profile contains an invalid SHA-256 binding")
    if not isinstance(ap.get("uuid"), str) or not _UUID.fullmatch(ap["uuid"]):
        raise ValueError("assurance profile contains an invalid OSCAL UUID")


def _validate_assessment_plan(
    ap: Dict[str, Any], profile: Dict[str, Any], pilot: Dict[str, Any]
) -> None:
    if set(ap) != {"$schema", "assessment-plan"} or ap.get("$schema") != OSCAL_AP_SCHEMA:
        raise ValueError("OSCAL assessment plan has an unsupported document shape")
    body = ap.get("assessment-plan")
    if not isinstance(body, dict) or set(body) != {
        "uuid",
        "metadata",
        "import-ssp",
        "reviewed-controls",
    }:
        raise ValueError("OSCAL assessment plan violates the supported profile shape")
    if body.get("uuid") != profile["artifacts"]["oscal_assessment_plan"]["uuid"]:
        raise ValueError("OSCAL assessment plan UUID does not match the profile")
    metadata = body.get("metadata")
    if not isinstance(metadata, dict) or set(metadata) != {
        "title",
        "last-modified",
        "version",
        "oscal-version",
        "props",
        "remarks",
    }:
        raise ValueError("OSCAL assessment plan metadata is invalid")
    if metadata.get("last-modified") != pilot["created_at"]:
        raise ValueError("OSCAL assessment plan metadata does not match the pilot plan")
    if (
        metadata.get("title") != f"LureScope Federal Email Assurance — {pilot['plan_id']}"
        or metadata.get("version") != FEDERAL_PROFILE_VERSION
        or metadata.get("oscal-version") != OSCAL_VERSION
        or metadata.get("remarks") != _INTERPRETATION_BOUNDARY
    ):
        raise ValueError("OSCAL assessment plan version is unsupported")
    expected_props = [
        _property("profile-id", FEDERAL_PROFILE_ID),
        _property("profile-schema", ASSURANCE_PROFILE_SCHEMA),
        _property("pilot-plan-sha256", profile["artifacts"]["pilot_plan"]["sha256"]),
    ]
    props = metadata.get("props")
    if (
        not isinstance(props, list)
        or len(props) != 4
        or props[:3] != expected_props
        or not isinstance(props[3], dict)
        or set(props[3]) != {"name", "ns", "value"}
        or props[3].get("name") != "lurescope-version"
        or props[3].get("ns") != PROPERTY_NAMESPACE
        or not isinstance(props[3].get("value"), str)
        or not _SEMVER.fullmatch(props[3]["value"])
    ):
        raise ValueError("OSCAL assessment plan properties are invalid")
    imports = body.get("import-ssp")
    if not isinstance(imports, dict) or set(imports) != {"href"}:
        raise ValueError("OSCAL assessment plan import-ssp is invalid")
    _safe_identifier_href(imports["href"])
    expected_uuid = _uuid5(
        "assessment-plan",
        f"{profile['artifacts']['pilot_plan']['sha256']}:{imports['href']}",
    )
    if body["uuid"] != expected_uuid:
        raise ValueError("OSCAL assessment plan UUID is not bound to its plan and SSP")
    if body.get("reviewed-controls") != _reviewed_controls():
        raise ValueError("OSCAL assessment plan reviewed controls are unsupported")


def load_assurance_plan(directory: Path) -> Dict[str, Any]:
    """Load an immutable plan directory and verify every cross-artifact binding."""
    directory = Path(directory)
    if directory.is_symlink():
        raise ValueError("refusing symbolic-link assurance plan directory")
    if not directory.is_dir():
        raise FileNotFoundError(directory)
    expected = {PILOT_PLAN_FILE, OSCAL_PLAN_FILE, PROFILE_FILE}
    actual = {entry.name for entry in directory.iterdir()}
    if actual != expected:
        raise ValueError("assurance plan directory must contain exactly its three artifacts")
    if os.name == "posix" and directory.stat().st_mode & 0o077:
        raise ValueError("assurance plan directory must not grant group or world access")

    profile, _ = _load_json(directory / PROFILE_FILE)
    _validate_profile(profile)
    pilot_path = directory / PILOT_PLAN_FILE
    pilot = load_pilot_plan(pilot_path)
    ap, ap_raw = _load_json(directory / OSCAL_PLAN_FILE)
    if _sha256(_read_regular(pilot_path)) != profile["artifacts"]["pilot_plan"]["sha256"]:
        raise ValueError("pilot plan SHA-256 does not match the assurance profile")
    if _sha256(ap_raw) != profile["artifacts"]["oscal_assessment_plan"]["sha256"]:
        raise ValueError("OSCAL assessment plan SHA-256 does not match the profile")
    if profile["created_at"] != pilot["created_at"]:
        raise ValueError("assurance profile timestamp does not match the pilot plan")
    _validate_assessment_plan(ap, profile, pilot)
    if os.name == "posix":
        for name in expected:
            if (directory / name).stat().st_mode & 0o077:
                raise ValueError(f"{name} must not grant group or world access")
    return {"profile": profile, "pilot_plan": pilot, "assessment_plan": ap}


def _register_artifact(source: Path, destination: Path) -> None:
    source_bytes = _read_regular(source)
    if destination.exists() or destination.is_symlink():
        destination_bytes = _read_regular(destination)
        if not secrets.compare_digest(source_bytes, destination_bytes):
            raise ValueError(f"bundle is already bound to a different {destination.name}")
        return
    _write_new(destination, source_bytes)


def _observation_property(check: Dict[str, Any], key: str) -> str:
    value = check[key]
    return "not-evaluable" if value is None else str(value)


def _assessment_results(
    gate: Dict[str, Any], profile: Dict[str, Any], profile_digest: str
) -> Dict[str, Any]:
    gate_payload = _canonical_json(gate)
    gate_digest = _sha256(gate_payload)
    ap_binding = profile["artifacts"]["oscal_assessment_plan"]
    document_uuid = _uuid5("assessment-results-document", f"{ap_binding['sha256']}:{gate_digest}")
    result_uuid = _uuid5("assessment-result", f"{ap_binding['sha256']}:{gate_digest}")
    observations = []
    for check in gate["checks"]:
        check_uuid = _uuid5("observation", f"{result_uuid}:{check['id']}")
        observations.append(
            {
                "uuid": check_uuid,
                "title": f"Pilot Gate check: {check['id']}",
                "description": (
                    f"Observed {_observation_property(check, 'observed')} under rule "
                    f"{check['operator']} {check['threshold']}; check status is "
                    f"{check['status']}."
                ),
                "props": [
                    _property("check-id", check["id"]),
                    _property("check-group", check["group"]),
                    _property("check-status", check["status"]),
                    _property("observed", _observation_property(check, "observed")),
                    _property("operator", check["operator"]),
                    _property("threshold", check["threshold"]),
                ],
                "methods": ["TEST"],
                "types": ["control-objective"],
                "relevant-evidence": [
                    {
                        "href": "pilot-gate.json",
                        "description": (
                            "Aggregate-only LureScope Pilot Gate record bound by SHA-256 in "
                            "assessment-results metadata."
                        ),
                    }
                ],
                "collected": gate["generated_at"],
                "remarks": (
                    "This observation records a statistical check and is not a control "
                    "satisfaction determination."
                ),
            }
        )
    return {
        "$schema": OSCAL_AR_SCHEMA,
        "assessment-results": {
            "uuid": document_uuid,
            "metadata": {
                "title": (
                    f"LureScope Federal Email Assurance Results — {gate['plan_binding']['plan_id']}"
                ),
                "last-modified": gate["generated_at"],
                "version": FEDERAL_PROFILE_VERSION,
                "oscal-version": OSCAL_VERSION,
                "props": [
                    _property("profile-id", FEDERAL_PROFILE_ID),
                    _property("assurance-profile-sha256", profile_digest),
                    _property("pilot-gate-sha256", gate_digest),
                    _property("pilot-gate-verdict", gate["verdict"]),
                    _property("aggregate-only", "true"),
                    _property("lurescope-version", __version__),
                ],
                "remarks": _INTERPRETATION_BOUNDARY,
            },
            "import-ap": {"href": OSCAL_PLAN_FILE},
            "results": [
                {
                    "uuid": result_uuid,
                    "title": "Pre-registered Shadow Inbox pilot observations",
                    "description": (
                        "Aggregate observations generated from a no-enforcement mailbox pilot. "
                        "No message content or case identifier is included."
                    ),
                    "start": gate["run_binding"]["generated_at"],
                    "end": gate["generated_at"],
                    "props": [
                        _property("pilot-gate-verdict", gate["verdict"]),
                        _property("failed-check-count", len(gate["failed_checks"])),
                        _property("observation-count", len(observations)),
                    ],
                    "reviewed-controls": _reviewed_controls(),
                    "observations": observations,
                    "remarks": _INTERPRETATION_BOUNDARY,
                }
            ],
        },
    }


def export_assurance_results(bundle: Path, assurance_plan: Path) -> Dict[str, Any]:
    """Refresh the gate and write registered, aggregate-only OSCAL results."""
    bundle = Path(bundle)
    if bundle.is_symlink():
        raise ValueError("refusing symbolic-link Shadow Inbox bundle")
    if not bundle.is_dir():
        raise FileNotFoundError(bundle)
    if os.name == "posix" and bundle.stat().st_mode & 0o077:
        raise ValueError("Shadow Inbox bundle must not grant group or world access")
    loaded = load_assurance_plan(assurance_plan)
    profile = loaded["profile"]
    source_profile = Path(assurance_plan) / PROFILE_FILE
    source_ap = Path(assurance_plan) / OSCAL_PLAN_FILE
    for source, destination in (
        (source_profile, bundle / PROFILE_FILE),
        (source_ap, bundle / OSCAL_PLAN_FILE),
    ):
        if destination.exists() or destination.is_symlink():
            _register_artifact(source, destination)

    gate = write_pilot_gate(bundle, Path(assurance_plan) / PILOT_PLAN_FILE)
    _register_artifact(source_profile, bundle / PROFILE_FILE)
    _register_artifact(source_ap, bundle / OSCAL_PLAN_FILE)
    profile_digest = _sha256(_read_regular(bundle / PROFILE_FILE))
    results = _assessment_results(gate, profile, profile_digest)
    _replace_private(bundle / OSCAL_RESULTS_FILE, _canonical_json(results))
    return {"gate": gate, "assessment_results": results}
