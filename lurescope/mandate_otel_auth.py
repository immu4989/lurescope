"""P-256 DSSE source authentication for LureMandate OpenTelemetry exports."""

from __future__ import annotations

import base64
import binascii
import hashlib
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import __version__
from .mandate import _instant, validate_mandate_plan
from .mandate_otel import _validate_export, validate_mandate_otel_projection
from .permit import _canonical, _digest, _exact, _id, _strict, _timestamp, _write_new

AUTHENTICATION_SCHEMA = (
    "https://github.com/immu4989/lurescope/spec/"
    "luremandate-authenticated-otel-projection/v1"
)
PAYLOAD_TYPE = "application/vnd.luremandate.otel-log-export+json"
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_ENVELOPE_BYTES = 12 * 1024 * 1024
MAX_KEY_BYTES = 64 * 1024

CHECKS = [
    "projection_independently_recomputed",
    "canonical_export_payload_recomputed",
    "dsse_payload_type_and_shape_rechecked",
    "externally_supplied_receiver_key_pinned",
    "dsse_key_id_matches_public_key_fingerprint",
    "ecdsa_p256_export_signature_authenticated",
    "receiver_identity_bound_to_signed_export",
]
LIMITATIONS = [
    "external_key_to_receiver_mapping_is_a_reviewer_input_not_workload_identity_proof",
    "p256_dsse_authentication_does_not_verify_hardware_backing_kms_lifecycle_revocation_or_timestamp_authority",
    "signature_authenticates_the_submitted_canonical_export_not_telemetry_completeness_delivery_or_clock_sync",
    "receiver_signature_does_not_prove_instance_integrity_non_bypassable_instrumentation_or_complete_mediation",
    "effect_observations_sensor_identity_and_real_world_outcomes_remain_external_claims",
    "passing_is_not_compliance_certification_safety_legal_authority_or_deployment_authorization",
]


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _read(path: Path, label: str, maximum: int) -> bytes:
    target = Path(path)
    if target.is_symlink() or not target.is_file() or target.parent.is_symlink():
        raise ValueError(f"{label} must be a regular non-symlink file")
    payload = target.read_bytes()
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
    payload_type = PAYLOAD_TYPE.encode("utf-8")
    return b"DSSEv1 %d " % len(payload_type) + payload_type + b" %d " % len(payload) + payload


def _public_key(payload: bytes) -> tuple[str, ec.EllipticCurvePublicKey]:
    if not 1 <= len(payload) <= MAX_KEY_BYTES:
        raise ValueError("receiver public key exceeds its bounded size")
    try:
        key = serialization.load_pem_public_key(payload)
    except (TypeError, ValueError) as exc:
        raise ValueError("receiver public key is not valid PEM") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("receiver public key must be ECDSA P-256")
    der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return _sha256(der), key


def _private_key(payload: bytes) -> ec.EllipticCurvePrivateKey:
    if not 1 <= len(payload) <= MAX_KEY_BYTES:
        raise ValueError("receiver private key exceeds its bounded size")
    try:
        key = serialization.load_pem_private_key(payload, password=None)
    except (TypeError, ValueError) as exc:
        raise ValueError("receiver private key must be unencrypted PEM") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise ValueError("receiver private key must be ECDSA P-256")
    return key


def _envelope(
    payload: bytes,
    key: ec.EllipticCurvePrivateKey,
    key_id: str,
) -> Dict[str, Any]:
    signature = key.sign(_pae(payload), ec.ECDSA(hashes.SHA256()))
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": _encode(payload),
        "signatures": [{"keyid": key_id, "sig": _encode(signature)}],
    }


def sign_mandate_otel_export(
    plan_path: Path,
    export_path: Path,
    private_key_path: Path,
    output_path: Path,
) -> Dict[str, Any]:
    plan = validate_mandate_plan(
        _strict(_read(plan_path, "LureMandate plan", MAX_INPUT_BYTES), "LureMandate plan")
    )
    export = _validate_export(
        _strict(
            _read(export_path, "LureMandate OpenTelemetry export", MAX_INPUT_BYTES),
            "LureMandate OpenTelemetry export",
        ),
        plan,
    )
    key = _private_key(_read(private_key_path, "receiver private key", MAX_KEY_BYTES))
    public_der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    result = _envelope(_canonical(export), key, _sha256(public_der))
    _write_new(Path(output_path), _canonical(result))
    return result


def _verify_envelope(
    envelope_payload: bytes,
    expected_export: Mapping[str, Any],
    public_key: ec.EllipticCurvePublicKey,
    expected_key_id: str,
) -> Dict[str, Any]:
    envelope = _exact(
        _strict(envelope_payload, "LureMandate telemetry DSSE envelope"),
        "LureMandate telemetry DSSE envelope",
        ("payloadType", "payload", "signatures"),
    )
    if envelope_payload != _canonical(envelope):
        raise ValueError("LureMandate telemetry DSSE envelope must use canonical JSON bytes")
    if envelope["payloadType"] != PAYLOAD_TYPE:
        raise ValueError("LureMandate telemetry DSSE payload type is unsupported")
    signatures = envelope["signatures"]
    if not isinstance(signatures, list) or len(signatures) != 1:
        raise ValueError("LureMandate telemetry DSSE envelope must contain one signature")
    signature = _exact(signatures[0], "telemetry DSSE signature", ("keyid", "sig"))
    if not secrets.compare_digest(
        _digest(signature["keyid"], "telemetry DSSE key ID"), expected_key_id
    ):
        raise ValueError("telemetry DSSE key ID differs from the pinned receiver key")
    payload = _decode(envelope["payload"], "telemetry DSSE payload", MAX_INPUT_BYTES)
    expected_payload = _canonical(expected_export)
    if not secrets.compare_digest(payload, expected_payload):
        raise ValueError("telemetry DSSE payload differs from the projected canonical export")
    signature_bytes = _decode(signature["sig"], "telemetry DSSE signature", 1024)
    try:
        public_key.verify(signature_bytes, _pae(payload), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise ValueError("telemetry DSSE signature authentication failed") from exc
    return dict(envelope)


def _verification_value(
    projection_payload: bytes,
    public_key_payload: bytes,
    envelope_payload: bytes,
    *,
    verified_at: str,
    producer_version: str,
) -> Dict[str, Any]:
    projection = validate_mandate_otel_projection(
        _strict(projection_payload, "LureMandate OpenTelemetry projection")
    )
    _timestamp(verified_at, "telemetry authentication verified_at")
    _id(producer_version, "telemetry authentication producer version")
    if _instant(verified_at, "telemetry authentication verified_at") < _instant(
        projection["generated_at"], "projection generated_at"
    ):
        raise ValueError("telemetry authentication predates the projection")
    key_id, public_key = _public_key(public_key_payload)
    _verify_envelope(
        envelope_payload,
        projection["inputs"]["otel_log_export"],
        public_key,
        key_id,
    )
    receiver = projection["inputs"]["otel_log_export"]["receiver"]
    return {
        "schema": AUTHENTICATION_SCHEMA,
        "schema_version": 1,
        "verification_id": f"{projection['run']['run_id']}-otel-authentication",
        "verified_at": verified_at,
        "engine": {"name": "lurescope-luremandate-otel-dsse", "version": producer_version},
        "documents": {
            "projection": {
                "document_sha256": _sha256(projection_payload),
                "payload_base64": _encode(projection_payload),
            }
        },
        "receiver_public_key": {
            "public_key_sha256": key_id,
            "pem_sha256": _sha256(public_key_payload),
            "pem_base64": _encode(public_key_payload),
        },
        "export_envelope": {
            "envelope_sha256": _sha256(envelope_payload),
            "envelope_base64": _encode(envelope_payload),
            "payload_sha256": _sha256(_canonical(projection["inputs"]["otel_log_export"])),
            "key_id": key_id,
        },
        "projection": projection,
        "checks": list(CHECKS),
        "summary": {
            "verdict": "pass",
            "telemetry_source_authenticated": True,
            "record_count": len(projection["inputs"]["otel_log_export"]["records"]),
            "transaction_count": len(projection["run"]["transactions"]),
            "receiver": dict(receiver),
            "receiver_public_key_sha256": key_id,
        },
        "limitations": list(LIMITATIONS),
    }


def create_authenticated_mandate_otel_projection(
    projection_path: Path,
    envelope_path: Path,
    receiver_public_key_path: Path,
    output_path: Path,
    *,
    expected_receiver_key_id: str,
    verified_at: Optional[str] = None,
) -> Dict[str, Any]:
    projection_payload = _read(
        projection_path, "LureMandate OpenTelemetry projection", MAX_INPUT_BYTES
    )
    envelope_payload = _read(
        envelope_path, "LureMandate telemetry DSSE envelope", MAX_ENVELOPE_BYTES
    )
    public_key_payload = _read(
        receiver_public_key_path, "receiver public key", MAX_KEY_BYTES
    )
    key_id, _ = _public_key(public_key_payload)
    if not secrets.compare_digest(
        key_id, _digest(expected_receiver_key_id, "expected receiver key ID")
    ):
        raise ValueError("receiver public key differs from the externally pinned key ID")
    result = _verification_value(
        projection_payload,
        public_key_payload,
        envelope_payload,
        verified_at=verified_at or _now(),
        producer_version=__version__,
    )
    payload = _canonical(validate_authenticated_mandate_otel_projection(result))
    if len(payload) > MAX_REPORT_BYTES:
        raise ValueError("authenticated LureMandate telemetry report exceeds its size limit")
    _write_new(Path(output_path), payload)
    return result


def _embedded(value: Any, field: str, maximum: int) -> bytes:
    document = _exact(value, field, ("document_sha256", "payload_base64"))
    payload = _decode(document["payload_base64"], f"{field}.payload_base64", maximum)
    if not secrets.compare_digest(
        _digest(document["document_sha256"], f"{field}.document_sha256"), _sha256(payload)
    ):
        raise ValueError(f"{field} digest does not match embedded bytes")
    return payload


def validate_authenticated_mandate_otel_projection(value: Any) -> Dict[str, Any]:
    report = _exact(
        value,
        "authenticated LureMandate telemetry projection",
        (
            "schema",
            "schema_version",
            "verification_id",
            "verified_at",
            "engine",
            "documents",
            "receiver_public_key",
            "export_envelope",
            "projection",
            "checks",
            "summary",
            "limitations",
        ),
    )
    if report["schema"] != AUTHENTICATION_SCHEMA or report["schema_version"] != 1:
        raise ValueError("unsupported authenticated LureMandate telemetry schema")
    _id(report["verification_id"], "telemetry authentication verification_id")
    engine = _exact(report["engine"], "telemetry authentication engine", ("name", "version"))
    if engine["name"] != "lurescope-luremandate-otel-dsse":
        raise ValueError("unsupported LureMandate telemetry authentication engine")
    if report["checks"] != CHECKS or report["limitations"] != LIMITATIONS:
        raise ValueError("telemetry authentication checks or limitations are incomplete")
    documents = _exact(report["documents"], "telemetry documents", ("projection",))
    projection_payload = _embedded(
        documents["projection"], "embedded telemetry projection", MAX_INPUT_BYTES
    )
    key_record = _exact(
        report["receiver_public_key"],
        "embedded receiver public key",
        ("public_key_sha256", "pem_sha256", "pem_base64"),
    )
    public_key_payload = _decode(key_record["pem_base64"], "receiver key PEM", MAX_KEY_BYTES)
    key_id, _ = _public_key(public_key_payload)
    if not secrets.compare_digest(
        _digest(key_record["public_key_sha256"], "receiver public key fingerprint"), key_id
    ) or not secrets.compare_digest(
        _digest(key_record["pem_sha256"], "receiver PEM digest"),
        _sha256(public_key_payload),
    ):
        raise ValueError("embedded receiver public key binding is inconsistent")
    envelope_record = _exact(
        report["export_envelope"],
        "embedded telemetry envelope",
        ("envelope_sha256", "envelope_base64", "payload_sha256", "key_id"),
    )
    envelope_payload = _decode(
        envelope_record["envelope_base64"], "embedded telemetry envelope", MAX_ENVELOPE_BYTES
    )
    if not secrets.compare_digest(
        _digest(envelope_record["envelope_sha256"], "telemetry envelope digest"),
        _sha256(envelope_payload),
    ) or not secrets.compare_digest(
        _digest(envelope_record["key_id"], "telemetry envelope key ID"), key_id
    ):
        raise ValueError("embedded telemetry envelope binding is inconsistent")
    expected = _verification_value(
        projection_payload,
        public_key_payload,
        envelope_payload,
        verified_at=report["verified_at"],
        producer_version=engine["version"],
    )
    if report != expected:
        raise ValueError("authenticated LureMandate telemetry report does not reproduce")
    return dict(report)


def load_authenticated_mandate_otel_projection(path: Path) -> Dict[str, Any]:
    return validate_authenticated_mandate_otel_projection(
        _strict(
            _read(path, "authenticated LureMandate telemetry report", MAX_REPORT_BYTES),
            "authenticated LureMandate telemetry report",
        )
    )
