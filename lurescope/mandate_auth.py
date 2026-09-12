"""Externally pinned P-256 DSSE authentication for LureMandate approvals."""

from __future__ import annotations

import base64
import binascii
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import __version__
from .mandate import (
    APPROVAL_STATEMENT_SCHEMA,
    _derive,
    validate_mandate_evaluation,
    validate_mandate_plan,
    validate_mandate_run,
)
from .permit import _canonical, _exact, _id, _strict, _timestamp, _write_new

AUTHENTICATION_SCHEMA = (
    "https://github.com/immu4989/lurescope/spec/luremandate-authenticated-verification/v1"
)
DSSE_PAYLOAD_TYPE = "application/vnd.luremandate.approval+json"
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_REPORT_BYTES = 32 * 1024 * 1024
MAX_ENVELOPE_BYTES = 2 * 1024 * 1024
MAX_KEY_BYTES = 64 * 1024
MAX_APPROVALS = 65_536

CHECKS = [
    "strict_source_json_reparsed",
    "producer_evaluation_independently_reproduced",
    "canonical_approval_statement_coverage_complete",
    "evidence_directory_exact",
    "externally_supplied_approver_keys_pinned",
    "distinct_key_per_approver_enforced",
    "dsse_payload_type_and_shape_rechecked",
    "canonical_statement_bytes_recomputed",
    "approval_claims_exactly_bound",
    "ecdsa_p256_signatures_authenticated",
]
LIMITATIONS = [
    "external_key_to_person_mapping_is_a_reviewer_input_not_directory_or_identity_proofing",
    "p256_dsse_authentication_does_not_verify_hardware_backing_kms_lifecycle_revocation_or_timestamp_authority",
    "authenticated_approval_metadata_does_not_establish_that_the_human_saw_or_understood_hidden_action_content",
    "effect_observations_and_complete_runtime_mediation_remain_external_claims",
    "impact_units_roles_thresholds_and_legal_authority_require_organization_specific_governance",
    "passing_is_not_compliance_certification_safety_or_deployment_authorization",
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


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _instant(value: Any, field: str) -> datetime:
    value = _timestamp(value, field)
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


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


def _decode(value: Any, field: str, maximum: int) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be canonical standard base64")
    try:
        payload = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{field} must be canonical standard base64") from exc
    if _encode(payload) != value or not 1 <= len(payload) <= maximum:
        raise ValueError(f"{field} must be canonical bounded standard base64")
    return payload


def _pae(payload: bytes) -> bytes:
    encoded_type = DSSE_PAYLOAD_TYPE.encode("utf-8")
    return b"DSSEv1 %d " % len(encoded_type) + encoded_type + b" %d " % len(payload) + payload


def _public_key(payload: bytes, field: str) -> tuple[str, ec.EllipticCurvePublicKey]:
    if not 1 <= len(payload) <= MAX_KEY_BYTES:
        raise ValueError(f"{field} exceeds the public-key byte limit")
    try:
        key = serialization.load_pem_public_key(payload)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} is not a valid PEM public key") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError(f"{field} must be an ECDSA P-256 public key")
    der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return _sha256(der), key


def _private_key(payload: bytes) -> ec.EllipticCurvePrivateKey:
    if not 1 <= len(payload) <= MAX_KEY_BYTES:
        raise ValueError("private key exceeds the key byte limit")
    try:
        key = serialization.load_pem_private_key(payload, password=None)
    except (TypeError, ValueError) as exc:
        raise ValueError("private key must be an unencrypted PEM key") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("private key must be ECDSA P-256")
    return key


def _approval(value: Any, field: str) -> Dict[str, Any]:
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
        raise ValueError(f"{field}.decision is unsupported")
    _digest(approval["intent_sha256"], f"{field}.intent_sha256")
    _instant(approval["issued_at"], f"{field}.issued_at")
    _instant(approval["expires_at"], f"{field}.expires_at")
    return dict(approval)


def validate_approval_statement(value: Any) -> Dict[str, Any]:
    statement = _exact(
        value,
        "approval statement",
        ("schema", "schema_version", "campaign_id", "plan_sha256", "approval"),
    )
    if statement["schema"] != APPROVAL_STATEMENT_SCHEMA or statement["schema_version"] != 1:
        raise ValueError("unsupported LureMandate approval statement schema")
    _id(statement["campaign_id"], "campaign_id")
    _digest(statement["plan_sha256"], "plan_sha256")
    _approval(statement["approval"], "approval")
    return dict(statement)


def _expected_statements(
    plan: Mapping[str, Any], run: Mapping[str, Any]
) -> Dict[str, Dict[str, Any]]:
    plan_digest = _sha256(_canonical(plan))
    approvals: Dict[str, Mapping[str, Any]] = {}
    for transaction in run["transactions"]:
        for approval in transaction["approvals"]:
            approval_id = approval["approval_id"]
            if approval_id in approvals and approvals[approval_id] != approval:
                raise ValueError("an approval ID is reused for conflicting claims")
            approvals[approval_id] = approval
    if not 1 <= len(approvals) <= MAX_APPROVALS:
        raise ValueError("authenticated approval count is unsupported")
    return {
        approval_id: validate_approval_statement(
            {
                "schema": APPROVAL_STATEMENT_SCHEMA,
                "schema_version": 1,
                "campaign_id": plan["campaign_id"],
                "plan_sha256": plan_digest,
                "approval": dict(approvals[approval_id]),
            }
        )
        for approval_id in sorted(approvals)
    }


def sign_approval_statement(
    statement_path: Path, private_key_path: Path, output_path: Path
) -> Dict[str, Any]:
    """Sign one canonical statement as a single-signature P-256 DSSE envelope."""

    payload = _read(statement_path, "approval statement")
    statement = validate_approval_statement(_strict(payload, "approval statement"))
    if payload != _canonical(statement):
        raise ValueError("approval statement must use canonical JSON bytes")
    key = _private_key(_read(private_key_path, "private key", MAX_KEY_BYTES))
    public = key.public_key()
    public_der = public.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = _sha256(public_der)
    signature = key.sign(_pae(payload), ec.ECDSA(hashes.SHA256()))
    envelope = {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": _encode(payload),
        "signatures": [{"keyid": fingerprint, "sig": _encode(signature)}],
    }
    _write_new(Path(output_path), _canonical(envelope))
    return envelope


def _verify_envelope(
    raw: bytes,
    expected: Mapping[str, Any],
    public_key: ec.EllipticCurvePublicKey,
    fingerprint: str,
) -> Dict[str, Any]:
    envelope = _exact(
        _strict(raw, "approval DSSE envelope"),
        "approval DSSE envelope",
        ("payloadType", "payload", "signatures"),
    )
    if envelope["payloadType"] != DSSE_PAYLOAD_TYPE:
        raise ValueError("approval DSSE payloadType is unsupported")
    signatures = envelope["signatures"]
    if not isinstance(signatures, list) or len(signatures) != 1:
        raise ValueError("approval DSSE requires exactly one signature")
    signature = _exact(signatures[0], "approval DSSE signature", ("keyid", "sig"))
    if signature["keyid"] != fingerprint:
        raise ValueError("approval DSSE key ID does not match the externally pinned key")
    payload = _decode(envelope["payload"], "approval DSSE payload", MAX_INPUT_BYTES)
    statement = validate_approval_statement(_strict(payload, "approval DSSE payload"))
    if statement != expected or payload != _canonical(expected):
        raise ValueError("authenticated approval statement does not exactly match the run")
    signature_bytes = _decode(signature["sig"], "approval DSSE signature", 512)
    try:
        public_key.verify(signature_bytes, _pae(payload), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise ValueError("approval DSSE signature verification failed") from exc
    approval = statement["approval"]
    return {
        "approval_id": approval["approval_id"],
        "approver_id": approval["approver_id"],
        "public_key_sha256": fingerprint,
        "statement_sha256": _sha256(payload),
        "envelope_sha256": _sha256(raw),
        "envelope_base64": _encode(raw),
    }


def _verification_value(
    plan_payload: bytes,
    run_payload: bytes,
    evaluation_payload: bytes,
    key_values: Mapping[str, bytes],
    envelope_values: Mapping[str, bytes],
    *,
    verified_at: str,
) -> Dict[str, Any]:
    plan = validate_mandate_plan(_strict(plan_payload, "LureMandate plan"))
    run = validate_mandate_run(_strict(run_payload, "LureMandate run"), plan)
    evaluation = validate_mandate_evaluation(_strict(evaluation_payload, "LureMandate evaluation"))
    if evaluation["plan"] != plan or evaluation["run"] != run:
        raise ValueError("producer evaluation does not embed the supplied plan and run")
    if _derive(plan, run, evaluation["evaluated_at"]) != evaluation:
        raise ValueError("producer evaluation is not independently reproduced")
    if _instant(verified_at, "verified_at") < _instant(evaluation["evaluated_at"], "evaluated_at"):
        raise ValueError("authenticated verification predates the producer evaluation")
    expected = _expected_statements(plan, run)
    approvers = sorted({item["approval"]["approver_id"] for item in expected.values()})
    if sorted(key_values) != approvers:
        raise ValueError("external key mapping must exactly cover every claimed approver")
    expected_files = {f"{approval_id}.dsse.json" for approval_id in expected}
    if set(envelope_values) != expected_files:
        raise ValueError("approval evidence directory does not exactly cover expected statements")

    parsed_keys: Dict[str, tuple[str, ec.EllipticCurvePublicKey]] = {}
    embedded_keys: list[Dict[str, str]] = []
    for approver_id in approvers:
        fingerprint, public_key = _public_key(key_values[approver_id], approver_id)
        parsed_keys[approver_id] = (fingerprint, public_key)
        embedded_keys.append(
            {
                "approver_id": approver_id,
                "public_key_sha256": fingerprint,
                "pem_sha256": _sha256(key_values[approver_id]),
                "pem_base64": _encode(key_values[approver_id]),
            }
        )
    fingerprints = [item["public_key_sha256"] for item in embedded_keys]
    if len(fingerprints) != len(set(fingerprints)):
        raise ValueError("each approver must be pinned to a distinct public key")

    authenticated: list[Dict[str, Any]] = []
    for approval_id, statement in expected.items():
        approver_id = statement["approval"]["approver_id"]
        fingerprint, key = parsed_keys[approver_id]
        authenticated.append(
            _verify_envelope(
                envelope_values[f"{approval_id}.dsse.json"],
                statement,
                key,
                fingerprint,
            )
        )
    summary = dict(evaluation["summary"])
    summary.update(
        {
            "unique_approval_count": len(expected),
            "authenticated_approval_count": len(authenticated),
            "approver_key_count": len(embedded_keys),
            "source_documents_reparsed": True,
            "producer_evaluation_reproduced": True,
            "approval_authentication_complete": len(authenticated) == len(expected),
            "distinct_approver_keys": True,
            "transaction_authority_evidence_authenticated": (
                evaluation["summary"]["verdict"] == "pass"
            ),
        }
    )
    return {
        "schema": AUTHENTICATION_SCHEMA,
        "schema_version": 1,
        "verification_id": f"{evaluation['evaluation_id']}-authenticated",
        "verified_at": verified_at,
        "engine": {"name": "lurescope-luremandate-dsse", "version": __version__},
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
        "public_keys": embedded_keys,
        "approval_envelopes": authenticated,
        "producer_evaluation": evaluation,
        "checks": list(CHECKS),
        "summary": summary,
        "limitations": list(LIMITATIONS),
    }


def _read_evidence_directory(path: Path, expected_names: set[str]) -> Dict[str, bytes]:
    directory = Path(path)
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError("approval evidence must be a regular non-symlink directory")
    entries = list(directory.iterdir())
    if any(item.is_symlink() or not item.is_file() for item in entries):
        raise ValueError("approval evidence directory may contain regular files only")
    names = {item.name for item in entries}
    if names != expected_names:
        raise ValueError("approval evidence directory does not exactly match expected files")
    return {
        name: _read(directory / name, f"approval evidence {name}", MAX_ENVELOPE_BYTES)
        for name in sorted(names)
    }


def create_authenticated_mandate_verification(
    plan_path: Path,
    run_path: Path,
    evaluation_path: Path,
    evidence_directory: Path,
    approver_public_key_paths: Mapping[str, Path],
    output_path: Path,
    *,
    verified_at: Optional[str] = None,
) -> Dict[str, Any]:
    plan_payload = _read(plan_path, "LureMandate plan")
    run_payload = _read(run_path, "LureMandate run")
    evaluation_payload = _read(evaluation_path, "LureMandate evaluation")
    plan = validate_mandate_plan(_strict(plan_payload, "LureMandate plan"))
    run = validate_mandate_run(_strict(run_payload, "LureMandate run"), plan)
    expected = _expected_statements(plan, run)
    evidence = _read_evidence_directory(
        evidence_directory, {f"{approval_id}.dsse.json" for approval_id in expected}
    )
    key_values = {
        _id(approver_id, "approver key mapping"): _read(
            path, f"public key for {approver_id}", MAX_KEY_BYTES
        )
        for approver_id, path in approver_public_key_paths.items()
    }
    result = _verification_value(
        plan_payload,
        run_payload,
        evaluation_payload,
        key_values,
        evidence,
        verified_at=verified_at or _now(),
    )
    payload = _canonical(validate_authenticated_mandate_verification(result))
    if len(payload) > MAX_REPORT_BYTES:
        raise ValueError("authenticated LureMandate verification exceeds the report limit")
    _write_new(Path(output_path), payload)
    return result


def _embedded_document(value: Any, field: str) -> bytes:
    document = _exact(value, field, ("document_sha256", "payload_base64"))
    payload = _decode(document["payload_base64"], f"{field}.payload_base64", MAX_INPUT_BYTES)
    if _digest(document["document_sha256"], f"{field}.document_sha256") != _sha256(payload):
        raise ValueError(f"{field} digest does not match embedded bytes")
    return payload


def validate_authenticated_mandate_verification(value: Any) -> Dict[str, Any]:
    verification = _exact(
        value,
        "authenticated LureMandate verification",
        (
            "schema",
            "schema_version",
            "verification_id",
            "verified_at",
            "engine",
            "documents",
            "public_keys",
            "approval_envelopes",
            "producer_evaluation",
            "checks",
            "summary",
            "limitations",
        ),
    )
    if verification["schema"] != AUTHENTICATION_SCHEMA or verification["schema_version"] != 1:
        raise ValueError("unsupported authenticated LureMandate verification schema")
    _id(verification["verification_id"], "verification_id")
    if _exact(verification["engine"], "engine", ("name", "version")) != {
        "name": "lurescope-luremandate-dsse",
        "version": __version__,
    }:
        raise ValueError("unsupported LureMandate authentication engine")
    if verification["checks"] != CHECKS or verification["limitations"] != LIMITATIONS:
        raise ValueError("authenticated LureMandate checks or limitations are incomplete")
    documents = _exact(verification["documents"], "documents", ("plan", "run", "evaluation"))
    plan_payload = _embedded_document(documents["plan"], "plan")
    run_payload = _embedded_document(documents["run"], "run")
    evaluation_payload = _embedded_document(documents["evaluation"], "evaluation")

    key_values: Dict[str, bytes] = {}
    key_records = verification["public_keys"]
    if not isinstance(key_records, list) or not 1 <= len(key_records) <= MAX_APPROVALS:
        raise ValueError("embedded public keys must be a bounded array")
    for item in key_records:
        record = _exact(
            item,
            "embedded public key",
            ("approver_id", "public_key_sha256", "pem_sha256", "pem_base64"),
        )
        approver_id = _id(record["approver_id"], "approver_id")
        pem = _decode(record["pem_base64"], "public key PEM", MAX_KEY_BYTES)
        fingerprint, _ = _public_key(pem, approver_id)
        if _digest(record["public_key_sha256"], "public key fingerprint") != fingerprint or _digest(
            record["pem_sha256"], "PEM digest"
        ) != _sha256(pem):
            raise ValueError("embedded public key binding is inconsistent")
        if approver_id in key_values:
            raise ValueError("embedded public key approver is duplicated")
        key_values[approver_id] = pem

    envelope_values: Dict[str, bytes] = {}
    envelope_records = verification["approval_envelopes"]
    if not isinstance(envelope_records, list) or not 1 <= len(envelope_records) <= MAX_APPROVALS:
        raise ValueError("embedded approval envelopes must be a bounded array")
    for item in envelope_records:
        record = _exact(
            item,
            "embedded approval envelope",
            (
                "approval_id",
                "approver_id",
                "public_key_sha256",
                "statement_sha256",
                "envelope_sha256",
                "envelope_base64",
            ),
        )
        approval_id = _id(record["approval_id"], "approval_id")
        _id(record["approver_id"], "approver_id")
        _digest(record["public_key_sha256"], "public_key_sha256")
        _digest(record["statement_sha256"], "statement_sha256")
        envelope = _decode(record["envelope_base64"], "approval envelope", MAX_ENVELOPE_BYTES)
        if _digest(record["envelope_sha256"], "envelope_sha256") != _sha256(envelope):
            raise ValueError("embedded approval envelope digest is inconsistent")
        filename = f"{approval_id}.dsse.json"
        if filename in envelope_values:
            raise ValueError("embedded approval envelope is duplicated")
        envelope_values[filename] = envelope
    expected = _verification_value(
        plan_payload,
        run_payload,
        evaluation_payload,
        key_values,
        envelope_values,
        verified_at=verification["verified_at"],
    )
    if verification != expected:
        raise ValueError("authenticated LureMandate verification does not reproduce")
    return dict(verification)


def load_authenticated_mandate_verification(path: Path) -> Dict[str, Any]:
    return validate_authenticated_mandate_verification(
        _strict(
            _read(path, "authenticated LureMandate verification", MAX_REPORT_BYTES),
            "authenticated LureMandate verification",
        )
    )
