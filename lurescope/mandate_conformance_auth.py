"""P-256 DSSE authentication for LureMandate black-box gateway submissions."""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import __version__
from .mandate import _instant
from .mandate_conformance import (
    validate_mandate_conformance_challenge,
    validate_mandate_conformance_submission,
    validate_mandate_conformance_verification,
)
from .permit import _canonical, _digest, _exact, _id, _strict, _write_new

AUTHENTICATION_SCHEMA = (
    "https://github.com/immu4989/lurescope/spec/"
    "luremandate-authenticated-conformance-verification/v1"
)
PAYLOAD_TYPE = "application/vnd.luremandate.conformance-submission+json"
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_VERIFICATION_BYTES = 32 * 1024 * 1024
MAX_ENVELOPE_BYTES = 12 * 1024 * 1024
MAX_REPORT_BYTES = 48 * 1024 * 1024
MAX_KEY_BYTES = 64 * 1024
CHECKS = [
    "conformance_verification_independently_recomputed",
    "canonical_gateway_submission_payload_recomputed",
    "dsse_payload_type_and_shape_rechecked",
    "externally_supplied_gateway_key_pinned",
    "dsse_key_id_matches_public_key_fingerprint",
    "ecdsa_p256_gateway_submission_signature_authenticated",
]
LIMITATIONS = [
    "external_key_to_gateway_mapping_is_a_reviewer_input_not_workload_identity_proof",
    "signature_authenticates_the_canonical_submission_not_gateway_runtime_or_complete_mediation",
    "p256_dsse_does_not_verify_hardware_backing_kms_lifecycle_revocation_or_timestamp_authority",
    "challenge_answers_may_be_inferred_and_case_coverage_does_not_establish_unrepresented_behavior",
    "passing_is_not_compliance_certification_safety_legal_authority_or_deployment_authorization",
]


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _read(path: Path, label: str, maximum: int, *, private: bool = False) -> bytes:
    target = Path(path)
    if target.is_symlink() or not target.is_file() or target.parent.is_symlink():
        raise ValueError(f"{label} must be a regular non-symlink file")
    payload = target.read_bytes()
    if not 1 <= len(payload) <= maximum:
        raise ValueError(f"{label} exceeds its bounded size")
    if private and os.name == "posix" and target.stat().st_mode & 0o077:
        raise ValueError(f"{label} must not grant group or world access")
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
        raise ValueError("gateway public key exceeds its bounded size")
    try:
        key = serialization.load_pem_public_key(payload)
    except (TypeError, ValueError) as exc:
        raise ValueError("gateway public key is not valid PEM") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("gateway public key must be ECDSA P-256")
    der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return _sha256(der), key


def _private_key(payload: bytes) -> ec.EllipticCurvePrivateKey:
    if not 1 <= len(payload) <= MAX_KEY_BYTES:
        raise ValueError("gateway private key exceeds its bounded size")
    try:
        key = serialization.load_pem_private_key(payload, password=None)
    except (TypeError, ValueError) as exc:
        raise ValueError("gateway private key must be unencrypted PEM") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("gateway private key must be ECDSA P-256")
    return key


def _envelope(payload: bytes, key: ec.EllipticCurvePrivateKey, key_id: str) -> Dict[str, Any]:
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": _encode(payload),
        "signatures": [
            {
                "keyid": key_id,
                "sig": _encode(key.sign(_pae(payload), ec.ECDSA(hashes.SHA256()))),
            }
        ],
    }


def sign_mandate_conformance_submission(
    challenge_path: Path,
    submission_path: Path,
    private_key_path: Path,
    output_path: Path,
) -> Dict[str, Any]:
    challenge = validate_mandate_conformance_challenge(
        _strict(
            _read(challenge_path, "LureMandate conformance challenge", MAX_INPUT_BYTES),
            "LureMandate conformance challenge",
        )
    )
    submission = validate_mandate_conformance_submission(
        _strict(
            _read(submission_path, "LureMandate conformance submission", MAX_INPUT_BYTES),
            "LureMandate conformance submission",
        ),
        challenge,
    )
    key = _private_key(_read(private_key_path, "gateway private key", MAX_KEY_BYTES, private=True))
    public_der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    result = _envelope(_canonical(submission), key, _sha256(public_der))
    _write_new(Path(output_path), _canonical(result))
    return result


def _verify_envelope(
    envelope_payload: bytes,
    expected_submission: Mapping[str, Any],
    public_key: ec.EllipticCurvePublicKey,
    expected_key_id: str,
) -> Dict[str, Any]:
    envelope = _exact(
        _strict(envelope_payload, "LureMandate submission DSSE envelope"),
        "LureMandate submission DSSE envelope",
        ("payloadType", "payload", "signatures"),
    )
    if envelope_payload != _canonical(envelope):
        raise ValueError("LureMandate submission DSSE envelope must use canonical JSON bytes")
    if envelope["payloadType"] != PAYLOAD_TYPE:
        raise ValueError("LureMandate submission DSSE payload type is unsupported")
    if not isinstance(envelope["signatures"], list) or len(envelope["signatures"]) != 1:
        raise ValueError("LureMandate submission DSSE envelope must contain one signature")
    signature = _exact(envelope["signatures"][0], "submission signature", ("keyid", "sig"))
    if not secrets.compare_digest(
        _digest(signature["keyid"], "submission key ID"), expected_key_id
    ):
        raise ValueError("submission key ID differs from the pinned gateway key")
    payload = _decode(envelope["payload"], "submission DSSE payload", MAX_INPUT_BYTES)
    if not secrets.compare_digest(payload, _canonical(expected_submission)):
        raise ValueError("submission DSSE payload differs from the verified gateway submission")
    signature_bytes = _decode(signature["sig"], "submission DSSE signature", 1024)
    try:
        public_key.verify(signature_bytes, _pae(payload), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise ValueError("gateway submission signature authentication failed") from exc
    return dict(envelope)


def _verification_value(
    verification_payload: bytes,
    public_key_payload: bytes,
    envelope_payload: bytes,
    *,
    verified_at: str,
    producer_version: str,
) -> Dict[str, Any]:
    verification = validate_mandate_conformance_verification(
        _strict(verification_payload, "LureMandate conformance verification")
    )
    _id(producer_version, "authentication producer version")
    if _instant(verified_at, "authentication verified_at") < _instant(
        verification["verified_at"], "conformance verification verified_at"
    ):
        raise ValueError("submission authentication predates conformance verification")
    key_id, public_key = _public_key(public_key_payload)
    submission = verification["producer_score"]["submission"]
    _verify_envelope(envelope_payload, submission, public_key, key_id)
    summary = dict(verification["summary"])
    summary.update(
        {
            "gateway_submission_authenticated": True,
            "gateway_public_key_sha256": key_id,
        }
    )
    return {
        "schema": AUTHENTICATION_SCHEMA,
        "schema_version": 1,
        "verification_id": f"{verification['verification_id']}-authenticated",
        "verified_at": verified_at,
        "engine": {
            "name": "lurescope-luremandate-conformance-dsse",
            "version": producer_version,
        },
        "documents": {
            "conformance_verification": {
                "document_sha256": _sha256(verification_payload),
                "payload_base64": _encode(verification_payload),
            }
        },
        "gateway_public_key": {
            "public_key_sha256": key_id,
            "pem_sha256": _sha256(public_key_payload),
            "pem_base64": _encode(public_key_payload),
        },
        "submission_envelope": {
            "envelope_sha256": _sha256(envelope_payload),
            "envelope_base64": _encode(envelope_payload),
            "payload_sha256": _sha256(_canonical(submission)),
            "key_id": key_id,
        },
        "conformance_verification": verification,
        "checks": list(CHECKS),
        "summary": summary,
        "limitations": list(LIMITATIONS),
    }


def create_authenticated_mandate_conformance_verification(
    verification_path: Path,
    envelope_path: Path,
    gateway_public_key_path: Path,
    output_path: Path,
    *,
    expected_gateway_key_id: str,
    verified_at: Optional[str] = None,
) -> Dict[str, Any]:
    verification_payload = _read(
        verification_path,
        "LureMandate conformance verification",
        MAX_VERIFICATION_BYTES,
    )
    envelope_payload = _read(
        envelope_path, "LureMandate submission DSSE envelope", MAX_ENVELOPE_BYTES
    )
    public_key_payload = _read(gateway_public_key_path, "gateway public key", MAX_KEY_BYTES)
    key_id, _ = _public_key(public_key_payload)
    if not secrets.compare_digest(
        key_id, _digest(expected_gateway_key_id, "expected gateway key ID")
    ):
        raise ValueError("gateway public key differs from the externally pinned key ID")
    result = _verification_value(
        verification_payload,
        public_key_payload,
        envelope_payload,
        verified_at=verified_at or _now(),
        producer_version=__version__,
    )
    payload = _canonical(validate_authenticated_mandate_conformance_verification(result))
    if len(payload) > MAX_REPORT_BYTES:
        raise ValueError("authenticated conformance report exceeds its size limit")
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


def validate_authenticated_mandate_conformance_verification(value: Any) -> Dict[str, Any]:
    report = _exact(
        value,
        "authenticated LureMandate conformance verification",
        (
            "schema",
            "schema_version",
            "verification_id",
            "verified_at",
            "engine",
            "documents",
            "gateway_public_key",
            "submission_envelope",
            "conformance_verification",
            "checks",
            "summary",
            "limitations",
        ),
    )
    if report["schema"] != AUTHENTICATION_SCHEMA or report["schema_version"] != 1:
        raise ValueError("unsupported authenticated conformance schema")
    _id(report["verification_id"], "authentication verification_id")
    engine = _exact(report["engine"], "authentication engine", ("name", "version"))
    if engine["name"] != "lurescope-luremandate-conformance-dsse":
        raise ValueError("unsupported conformance authentication engine")
    if report["checks"] != CHECKS or report["limitations"] != LIMITATIONS:
        raise ValueError("conformance authentication checks or limitations are incomplete")
    documents = _exact(
        report["documents"], "authentication documents", ("conformance_verification",)
    )
    verification_payload = _embedded(
        documents["conformance_verification"],
        "embedded conformance verification",
        MAX_VERIFICATION_BYTES,
    )
    key_record = _exact(
        report["gateway_public_key"],
        "embedded gateway public key",
        ("public_key_sha256", "pem_sha256", "pem_base64"),
    )
    public_key_payload = _decode(key_record["pem_base64"], "gateway key PEM", MAX_KEY_BYTES)
    key_id, _ = _public_key(public_key_payload)
    if not secrets.compare_digest(
        _digest(key_record["public_key_sha256"], "gateway public key fingerprint"), key_id
    ) or not secrets.compare_digest(
        _digest(key_record["pem_sha256"], "gateway PEM digest"),
        _sha256(public_key_payload),
    ):
        raise ValueError("embedded gateway public key binding is inconsistent")
    envelope_record = _exact(
        report["submission_envelope"],
        "embedded submission envelope",
        ("envelope_sha256", "envelope_base64", "payload_sha256", "key_id"),
    )
    envelope_payload = _decode(
        envelope_record["envelope_base64"],
        "embedded submission envelope",
        MAX_ENVELOPE_BYTES,
    )
    if not secrets.compare_digest(
        _digest(envelope_record["envelope_sha256"], "submission envelope digest"),
        _sha256(envelope_payload),
    ) or not secrets.compare_digest(
        _digest(envelope_record["key_id"], "submission envelope key ID"), key_id
    ):
        raise ValueError("embedded submission envelope binding is inconsistent")
    expected = _verification_value(
        verification_payload,
        public_key_payload,
        envelope_payload,
        verified_at=report["verified_at"],
        producer_version=engine["version"],
    )
    if (
        not secrets.compare_digest(
            _digest(envelope_record["payload_sha256"], "submission payload digest"),
            expected["submission_envelope"]["payload_sha256"],
        )
        or report != expected
    ):
        raise ValueError("authenticated conformance verification does not reproduce")
    return dict(report)


def load_authenticated_mandate_conformance_verification(path: Path) -> Dict[str, Any]:
    return validate_authenticated_mandate_conformance_verification(
        _strict(
            _read(
                path,
                "authenticated LureMandate conformance verification",
                MAX_REPORT_BYTES,
            ),
            "authenticated LureMandate conformance verification",
        )
    )
