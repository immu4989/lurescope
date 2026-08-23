"""Installable, offline operational-pilot kit over reviewed synthetic fixtures."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from .assurance import create_assurance_plan, export_assurance_results, load_assurance_plan
from .integrations import export_inbox_manifest, load_inbox_manifest, render_export
from .lureeval import create_lureeval_receipt, verify_lureeval_receipt
from .pilot import detector_artifact_sha256, load_pilot_gate, write_pilot_gate
from .proof import verify_proof
from .shadow import (
    append_analyst_label,
    build_shadow_report,
    load_analyst_labels,
    load_shadow_run,
    run_shadow_inbox,
)

RECEIPT_SCHEMA = "https://github.com/immu4989/lurescope/spec/operational-pilot-receipt/v1"
DEFAULT_FIXTURE_DIR = Path(__file__).with_name("data") / "pilot"
EXPECTED_DETECTOR_SHA256 = (
    "84c7254c464ff9faa3ede012691c13d53da08ab1f26223633af7b9377d60ed0b"
)
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024

FIXTURE_CONTRACT: Dict[str, Dict[str, str]] = {
    "01-qr-benefits.eml": {
        "sha256": "cf17047fcf1156e919cf308839c1ca42bda71c5c74d786a9b01d8aa69934e375",
        "label": "fraud",
        "reason": "confirmed_external",
    },
    "02-bec-bank-change.eml": {
        "sha256": "0b05cf78c50f99406d57770b55a661f290f81bbed0e339335e8a3612e15ed3ec",
        "label": "fraud",
        "reason": "confirmed_external",
    },
    "03-archive-attachment.eml": {
        "sha256": "11614dd3b316001c4388fc5aa06c136a47430524193965bb3ee8763ccf5e2009",
        "label": "fraud",
        "reason": "confirmed_external",
    },
    "04-multilingual-alert.eml": {
        "sha256": "4fe2747c9d2f030cd72a1246c0176177f02d85083d9d37b393c145302aa8dbee",
        "label": "fraud",
        "reason": "confirmed_external",
    },
    "05-benign-agenda.eml": {
        "sha256": "d520fde3cd07da43ce0af1ed3014e6adc5446d5d299e9424be00bc23f975e485",
        "label": "benign",
        "reason": "known_legitimate",
    },
    "06-duplicate-bec.eml": {
        "sha256": "0b05cf78c50f99406d57770b55a661f290f81bbed0e339335e8a3612e15ed3ec",
        "label": "fraud",
        "reason": "confirmed_external",
    },
}
EXPECTED_UNIQUE_FILES = set(FIXTURE_CONTRACT) - {"06-duplicate-bec.eml"}

ARTIFACT_ROLES = {
    "analyst-labels.jsonl": "analyst_labels",
    "assurance-profile.json": "assurance_profile",
    "lureeval-public.pem": "lureeval_public_key",
    "lureeval.dsse.json": "lureeval_receipt",
    "manifest.jsonl": "inbox_manifest",
    "oscal-assessment-plan.json": "oscal_assessment_plan",
    "oscal-assessment-results.json": "oscal_assessment_results",
    "pilot-gate.json": "pilot_gate",
    "pilot-gate.md": "pilot_gate_human_report",
    "pilot-plan.json": "pilot_plan",
    "shadow-report.json": "shadow_report",
    "shadow-report.md": "shadow_report_human_report",
    "shadow-run.json": "shadow_run",
    "siem-ocsf-1.8.json": "ocsf_export",
    "siem-sentinel.json": "sentinel_export",
    "siem-splunk-hec.jsonl": "splunk_hec_export",
    "summary.json": "inbox_summary",
}
EXPORTS = {
    "siem-ocsf-1.8.json": ("ocsf-1.8", True),
    "siem-sentinel.json": ("sentinel", False),
    "siem-splunk-hec.jsonl": ("splunk-hec", False),
}
LIMITATIONS = [
    "synthetic_fixture_not_representative",
    "demo_thresholds_not_for_deployment",
    "oscal_evidence_not_compliance_or_authorization",
    "siem_exports_are_files_not_delivered_events",
    "ephemeral_signing_key_authenticates_run_not_organization",
]
FORBIDDEN_FRAGMENTS = (
    b"example.invalid",
    b"lurescope/data/pilot",
    b"lurescope\\data\\pilot",
    b"Confidential bank change before today settlement",
    b"Urgently update the supplier bank account",
    b"verify.example.invalid",
    b"synthetic-remittance.zip",
    b"The planning meeting remains Tuesday at 10 AM",
)

_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_RECEIPT_KEYS = {
    "schema",
    "schema_version",
    "generated_at",
    "status",
    "workflow",
    "privacy",
    "artifacts",
    "verification",
    "limitations",
}


def _timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _write_new(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_regular(path: Path, maximum: int = MAX_ARTIFACT_BYTES) -> bytes:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"operational pilot artifact must be a regular file: {path.name}")
    if path.stat().st_size > maximum:
        raise ValueError(f"operational pilot artifact exceeds its size limit: {path.name}")
    return path.read_bytes()


def _strict_json(payload: bytes, label: str) -> Any:
    def no_duplicates(pairs: List[tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} contains a duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"{label} contains a non-standard JSON constant: {value}")

    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=no_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not strict UTF-8 JSON") from exc


def _validate_strict_serialization(path: Path, payload: bytes) -> None:
    if path.suffix == ".json":
        value = _strict_json(payload, path.name)
        if path.name == "lureeval.dsse.json":
            try:
                encoded = value["payload"]
                if not isinstance(encoded, str):
                    raise ValueError
                statement = base64.b64decode(encoded, validate=True)
            except (KeyError, TypeError, ValueError, binascii.Error) as exc:
                raise ValueError("lureeval.dsse.json payload is malformed") from exc
            _strict_json(statement, "lureeval.dsse.json decoded payload")
    elif path.suffix == ".jsonl":
        for line_number, line in enumerate(payload.splitlines(), start=1):
            if line.strip():
                _strict_json(line, f"{path.name} line {line_number}")


def _verify_fixtures(fixture_dir: Path) -> str:
    fixture_dir = Path(fixture_dir)
    if fixture_dir.is_symlink() or not fixture_dir.is_dir():
        raise ValueError("operational pilot fixture directory must be a regular directory")
    entries = sorted(fixture_dir.iterdir())
    for entry in entries:
        allowed_marker = entry.name == "__init__.py" and entry.is_file()
        allowed_cache = (
            entry.name == "__pycache__" and entry.is_dir() and not entry.is_symlink()
        )
        if entry.suffix != ".eml" and not allowed_marker and not allowed_cache:
            raise ValueError("operational pilot fixture directory contains unexpected files")
    files = [path for path in entries if path.suffix == ".eml"]
    if {path.name for path in files} != set(FIXTURE_CONTRACT):
        raise ValueError("operational pilot fixture set differs from the reviewed contract")
    identity = hashlib.sha256()
    for path in files:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"operational pilot fixture must be regular: {path.name}")
        digest = _sha256(path.read_bytes())
        if digest != FIXTURE_CONTRACT[path.name]["sha256"]:
            raise ValueError(f"operational pilot fixture digest changed: {path.name}")
        identity.update(f"{path.name}\0{digest}\n".encode("utf-8"))
    return identity.hexdigest()


def _ephemeral_keypair() -> tuple[bytes, bytes]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def _artifact_index(bundle: Path) -> List[Dict[str, Any]]:
    artifacts = []
    for filename, role in sorted(ARTIFACT_ROLES.items()):
        payload = _read_regular(bundle / filename)
        artifacts.append(
            {
                "file": filename,
                "role": role,
                "sha256": _sha256(payload),
                "bytes": len(payload),
            }
        )
    return artifacts


def _validate_receipt(receipt: Any) -> Dict[str, Any]:
    if not isinstance(receipt, dict) or set(receipt) != _RECEIPT_KEYS:
        raise ValueError("operational pilot receipt violates the v1 allowlist")
    if (
        receipt.get("schema") != RECEIPT_SCHEMA
        or receipt.get("schema_version") != 1
        or receipt.get("status") != "verified"
    ):
        raise ValueError("operational pilot receipt identity or status is unsupported")
    try:
        generated = datetime.fromisoformat(
            str(receipt["generated_at"]).replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise ValueError("operational pilot receipt generated_at is invalid") from exc
    if generated.tzinfo is None:
        raise ValueError("operational pilot receipt generated_at needs a UTC offset")
    expected_workflow = {
        "fixture_set_sha256",
        "candidate_count",
        "unique_count",
        "duplicate_count",
        "detector",
        "detector_artifact_sha256",
        "threshold",
        "pilot_gate_verdict",
    }
    workflow = receipt.get("workflow")
    if not isinstance(workflow, dict) or set(workflow) != expected_workflow:
        raise ValueError("operational pilot workflow violates the v1 allowlist")
    if (
        not isinstance(workflow["fixture_set_sha256"], str)
        or not _SHA256.fullmatch(workflow["fixture_set_sha256"])
        or workflow["candidate_count"] != 6
        or workflow["unique_count"] != 5
        or workflow["duplicate_count"] != 1
        or workflow["detector"] != "tfidf-logreg"
        or workflow["detector_artifact_sha256"] != EXPECTED_DETECTOR_SHA256
        or workflow["threshold"] != 0.5
        or workflow["pilot_gate_verdict"] != "pass"
    ):
        raise ValueError("operational pilot workflow values are unsupported")
    if receipt.get("privacy") != {
        "synthetic_only": True,
        "private_bundle": True,
        "contains_message_content": False,
        "contains_opaque_case_identifiers": True,
        "network_required": False,
        "private_key_persisted": False,
    }:
        raise ValueError("operational pilot privacy boundary is invalid")
    if receipt.get("verification") != {
        "fixture_integrity": True,
        "pilot_gate_passed": True,
        "lureeval_signature_authenticated": True,
        "oscal_generated": True,
        "siem_exports_generated": True,
        "private_permissions": True,
        "private_key_not_persisted": True,
    }:
        raise ValueError("operational pilot verification claims are invalid")
    artifacts = receipt.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != len(ARTIFACT_ROLES):
        raise ValueError("operational pilot receipt has an invalid artifact index")
    observed: Dict[str, Dict[str, Any]] = {}
    for item in artifacts:
        if not isinstance(item, dict) or set(item) != {"file", "role", "sha256", "bytes"}:
            raise ValueError("operational pilot artifact binding is malformed")
        filename = item["file"]
        if not isinstance(filename, str) or filename in observed:
            raise ValueError("operational pilot artifact filenames must be unique")
        if filename not in ARTIFACT_ROLES or item["role"] != ARTIFACT_ROLES[filename]:
            raise ValueError("operational pilot artifact filename or role is unsupported")
        if not isinstance(item["sha256"], str) or not _SHA256.fullmatch(item["sha256"]):
            raise ValueError("operational pilot artifact digest is invalid")
        if (
            isinstance(item["bytes"], bool)
            or not isinstance(item["bytes"], int)
            or not 0 < item["bytes"] <= MAX_ARTIFACT_BYTES
        ):
            raise ValueError("operational pilot artifact byte count is invalid")
        observed[filename] = item
    if set(observed) != set(ARTIFACT_ROLES):
        raise ValueError("operational pilot artifact set is incomplete")
    if receipt.get("limitations") != LIMITATIONS:
        raise ValueError("operational pilot limitations are invalid")
    return receipt


def _verify_oscal(bundle: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="lurescope-verify-assurance-") as temporary:
        plan = Path(temporary)
        plan.chmod(0o700)
        for name in (
            "pilot-plan.json",
            "assurance-profile.json",
            "oscal-assessment-plan.json",
        ):
            destination = plan / name
            _write_new(destination, _read_regular(bundle / name))
        load_assurance_plan(plan)

    results = _strict_json(
        _read_regular(bundle / "oscal-assessment-results.json"),
        "oscal-assessment-results.json",
    )
    try:
        metadata = results["assessment-results"]["metadata"]
        properties = {item["name"]: item["value"] for item in metadata["props"]}
    except (KeyError, TypeError) as exc:
        raise ValueError("OSCAL Assessment Results metadata is malformed") from exc
    expected = {
        "pilot-gate-sha256": _sha256(_read_regular(bundle / "pilot-gate.json")),
        "assurance-profile-sha256": _sha256(
            _read_regular(bundle / "assurance-profile.json")
        ),
    }
    if any(properties.get(key) != value for key, value in expected.items()):
        raise ValueError("OSCAL Assessment Results does not bind the current evidence")
    result_sets = results.get("assessment-results", {}).get("results", [])
    if not isinstance(result_sets, list) or len(result_sets) != 1:
        raise ValueError("OSCAL Assessment Results must contain exactly one result set")
    if "findings" in result_sets[0]:
        raise ValueError("operational pilot OSCAL output cannot assert findings")


def _verify_exports(bundle: Path, entries: List[Dict[str, Any]]) -> None:
    processed_ids = {
        entry["case_id"] for entry in entries if entry["status"] == "processed"
    }
    _, labels = load_analyst_labels(
        bundle / "analyst-labels.jsonl", allowed_case_ids=processed_ids
    )
    for filename, (output_format, reviewed) in EXPORTS.items():
        expected = render_export(entries, output_format, labels if reviewed else None)
        if not secrets.compare_digest(_read_regular(bundle / filename), expected):
            raise ValueError(f"{filename} is inconsistent with the minimized manifest")


def verify_operational_pilot(bundle: Path) -> Dict[str, Any]:
    """Reverify a complete pilot bundle without writing to it or using a network."""

    bundle = Path(bundle)
    if bundle.is_symlink() or not bundle.is_dir():
        raise ValueError("operational pilot bundle must be a regular local directory")
    if os.name == "posix" and stat.S_IMODE(bundle.stat().st_mode) != 0o700:
        raise ValueError("operational pilot bundle must be mode 0700")
    receipt = _validate_receipt(
        _strict_json(
            _read_regular(bundle / "operational-pilot-receipt.json"),
            "operational-pilot-receipt.json",
        )
    )
    bindings = {item["file"]: item for item in receipt["artifacts"]}
    for filename, item in bindings.items():
        payload = _read_regular(bundle / filename)
        if len(payload) != item["bytes"] or _sha256(payload) != item["sha256"]:
            raise ValueError(f"operational pilot artifact binding failed: {filename}")

    entries = load_inbox_manifest(bundle / "manifest.jsonl")
    proof_names = {
        entry["proof"]["file"] for entry in entries if entry["status"] == "processed"
    }
    expected_files = {
        *ARTIFACT_ROLES,
        *proof_names,
        "operational-pilot-receipt.json",
    }
    actual_files = set()
    for path in bundle.iterdir():
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"unexpected non-regular pilot artifact: {path.name}")
        if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise ValueError(f"operational pilot artifact must be mode 0600: {path.name}")
        payload = _read_regular(path)
        _validate_strict_serialization(path, payload)
        if b"PRIVATE KEY" in payload or any(
            fragment in payload for fragment in FORBIDDEN_FRAGMENTS
        ):
            raise ValueError(f"privacy or private-key regression detected in {path.name}")
        actual_files.add(path.name)
    if actual_files != expected_files:
        raise ValueError("operational pilot bundle contains missing or unexpected files")

    run = load_shadow_run(bundle)
    if (
        run["candidate_count"] != 6
        or run["unique_count"] != 5
        or run["duplicate_count"] != 1
    ):
        raise ValueError("operational pilot ingestion shape changed")
    saved_report = _strict_json(
        _read_regular(bundle / "shadow-report.json"), "shadow-report.json"
    )
    recomputed_report = build_shadow_report(bundle)
    recomputed_report["generated_at"] = saved_report.get("generated_at")
    if saved_report != recomputed_report:
        raise ValueError("shadow-report.json does not match current evidence")
    gate = load_pilot_gate(bundle)
    if gate["verdict"] != "pass" or gate["failed_checks"]:
        raise ValueError("operational pilot gate is not a complete pass")

    public_pem = _read_regular(bundle / "lureeval-public.pem")
    lureeval = verify_lureeval_receipt(
        bundle / "lureeval.dsse.json",
        public_key_pem=public_pem,
        require_signature=True,
    )
    if not lureeval["authenticated"]:
        raise ValueError("operational LureEval receipt did not authenticate")
    for entry in entries:
        if entry["status"] != "processed":
            continue
        proof = _strict_json(
            _read_regular(bundle / entry["proof"]["file"]), entry["proof"]["file"]
        )
        verified = verify_proof(proof)
        if not verified["valid"] or verified["statement_sha256"] != entry["proof"][
            "statement_sha256"
        ]:
            raise ValueError(f"LureProof binding failed: {entry['proof']['file']}")
    _verify_oscal(bundle)
    _verify_exports(bundle, entries)
    return receipt


def run_operational_pilot(
    output_dir: Path, *, fixture_dir: Path = DEFAULT_FIXTURE_DIR
) -> Dict[str, Any]:
    """Create and verify an atomic, private, synthetic operational evidence bundle."""

    output_dir = Path(output_dir)
    if output_dir.exists() or output_dir.is_symlink():
        raise FileExistsError(f"operational pilot output already exists: {output_dir}")
    parent = output_dir.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError("operational pilot output parent must be a regular directory")
    fixture_set_sha256 = _verify_fixtures(fixture_dir)
    detector_digest = detector_artifact_sha256("tfidf-logreg")
    if detector_digest != EXPECTED_DETECTOR_SHA256:
        raise ValueError("bundled detector artifact changed from the reviewed pilot contract")

    staging = parent / f".{output_dir.name}.{secrets.token_hex(8)}.tmp"
    try:
        with tempfile.TemporaryDirectory(prefix="lurescope-operational-plan-") as temporary:
            plan_dir = Path(temporary) / "assurance-plan"
            create_assurance_plan(
                plan_dir,
                ssp_href="urn:lurescope:synthetic-operational-pilot:ssp",
                plan_id="lurescope-operational-pilot-v1",
                min_processed_count=5,
                min_fraud_labels=4,
                min_benign_labels=1,
                max_uncertain_rate=0.0,
                max_processing_failure_rate=0.0,
                min_routing_recall_lower_bound=0.45,
                max_routing_false_positive_rate_upper_bound=0.96,
                max_routed_rate=0.8,
                max_routed_count=4,
                confidence=0.95,
                labeling_protocol="full_blinded_review",
                detector="tfidf-logreg",
                threshold=0.5,
            )
            run = run_shadow_inbox(
                [Path(fixture_dir)],
                staging,
                input_format="eml",
                detector_name="tfidf-logreg",
                threshold=0.5,
            )
            if (
                run.discovery.candidate_count != 6
                or run.discovery.duplicate_count != 1
                or run.inbox.summary["processed_count"] != 5
                or run.failed_count
            ):
                raise AssertionError("operational pilot ingestion shape changed")
            observed_sources = set()
            for item in run.inbox.items:
                if item.status != "processed":
                    raise AssertionError("reviewed operational fixture failed processing")
                name = Path(item.source).name
                if name not in EXPECTED_UNIQUE_FILES:
                    raise AssertionError("unexpected operational fixture survived deduplication")
                observed_sources.add(name)
                truth = FIXTURE_CONTRACT[name]
                append_analyst_label(
                    staging, item.case_id, truth["label"], truth["reason"]
                )
            if observed_sources != EXPECTED_UNIQUE_FILES:
                raise AssertionError("operational pilot fixture mapping changed")

            gate = write_pilot_gate(staging, plan_dir / "pilot-plan.json")
            if gate["verdict"] != "pass" or gate["failed_checks"]:
                raise AssertionError("operational pilot did not pass its registered gate")
            private_pem, public_pem = _ephemeral_keypair()
            _write_new(staging / "lureeval-public.pem", public_pem)
            create_lureeval_receipt(
                staging,
                staging / "lureeval.dsse.json",
                sampling="complete_population",
                minimum_slice_count=20,
                issuer="lurescope-synthetic-operational-pilot",
                signing_key_pem=private_pem,
                refresh_gate=False,
            )
            export_assurance_results(staging, plan_dir, refresh_gate=False)

        for filename, (output_format, reviewed) in EXPORTS.items():
            export_inbox_manifest(
                staging / "manifest.jsonl",
                staging / filename,
                output_format,
                labels_path=staging / "analyst-labels.jsonl" if reviewed else None,
            )
        receipt: Dict[str, Any] = {
            "schema": RECEIPT_SCHEMA,
            "schema_version": 1,
            "generated_at": _timestamp(),
            "status": "verified",
            "workflow": {
                "fixture_set_sha256": fixture_set_sha256,
                "candidate_count": 6,
                "unique_count": 5,
                "duplicate_count": 1,
                "detector": "tfidf-logreg",
                "detector_artifact_sha256": detector_digest,
                "threshold": 0.5,
                "pilot_gate_verdict": "pass",
            },
            "privacy": {
                "synthetic_only": True,
                "private_bundle": True,
                "contains_message_content": False,
                "contains_opaque_case_identifiers": True,
                "network_required": False,
                "private_key_persisted": False,
            },
            "artifacts": _artifact_index(staging),
            "verification": {
                "fixture_integrity": True,
                "pilot_gate_passed": True,
                "lureeval_signature_authenticated": True,
                "oscal_generated": True,
                "siem_exports_generated": True,
                "private_permissions": True,
                "private_key_not_persisted": True,
            },
            "limitations": LIMITATIONS,
        }
        _validate_receipt(receipt)
        receipt_bytes = (
            json.dumps(receipt, allow_nan=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        if b"case-" in receipt_bytes or b"example.invalid" in receipt_bytes:
            raise AssertionError("operational pilot receipt crossed its aggregate boundary")
        _write_new(staging / "operational-pilot-receipt.json", receipt_bytes)
        verify_operational_pilot(staging)
        os.replace(staging, output_dir)
        return receipt
    except Exception:
        if staging.is_dir() and not staging.is_symlink():
            shutil.rmtree(staging)
        raise
