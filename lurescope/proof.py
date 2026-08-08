"""LureProof: strict, privacy-minimized fraud-control evidence and DSSE signing.

The unsigned form is an in-toto Statement whose schema and internal invariants can
be validated. The authenticated form is the exact statement bytes inside a DSSE
envelope signed with an externally trusted ECDSA P-256 public key.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import platform
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from lurebench import __version__ as lurebench_version
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from sklearn import __version__ as sklearn_version

from . import __version__, service
from .triage import MAX_SCORE_TEXT, parse_email, triage_email

SPEC_VERSION = "0.2"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://github.com/immu4989/lurescope/spec/lureproof/v0.2"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
LOCAL_ATTACKS = ("homoglyph", "leet", "zero-width", "whitespace")
DEFENSE = "normalize"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class _Subject(_StrictModel):
    name: Literal["email-message"]
    digest: Dict[str, str]

    @field_validator("digest")
    @classmethod
    def valid_digest(cls, value: Dict[str, str]) -> Dict[str, str]:
        if len(value) != 1:
            raise ValueError("subject.digest must contain exactly one algorithm")
        algorithm, digest = next(iter(value.items()))
        if algorithm not in {"sha256", "lureproof-salted-sha256"}:
            raise ValueError("unsupported subject digest algorithm")
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError("subject digest must be 64 lowercase hex characters")
        return value


class _Privacy(_StrictModel):
    profile: Literal["salted-commitment", "correlatable"]
    commitment_salt: Optional[str]


class _Input(_StrictModel):
    media_type: Literal["message/rfc822"]
    byte_length: int = Field(ge=1, le=5 * 1024 * 1024)
    parser: Literal["python-email-policy-default"]
    scored_character_count: int = Field(ge=1, le=MAX_SCORE_TEXT)
    truncated: bool


class _Assessment(_StrictModel):
    detector: str = Field(min_length=1, max_length=100)
    detector_model: str = Field(min_length=1, max_length=500)
    detector_artifact_sha256: Optional[str] = Field(
        pattern=r"^[a-f0-9]{64}$"
    )
    fraud_probability: float = Field(ge=0.0, le=1.0)
    label: Literal["fraud", "benign"]
    risk_tier: Literal["high", "review", "low"]
    threshold: float = Field(ge=0.0, le=1.0)
    threshold_source: str = Field(min_length=1, max_length=100)
    policy_id: Optional[str] = Field(max_length=500)
    evidence_codes: List[str]
    url_count: int = Field(ge=0)
    attachment_count: int = Field(ge=0)

    @field_validator("evidence_codes")
    @classmethod
    def unique_evidence_codes(cls, value: List[str]) -> List[str]:
        if len(value) != len(set(value)):
            raise ValueError("evidence_codes must be unique")
        if len(value) > 32 or any(not item or len(item) > 100 for item in value):
            raise ValueError("evidence_codes exceed the documented size limits")
        return value


class _Outcome(_StrictModel):
    attack: Literal["homoglyph", "leet", "zero-width", "whitespace"]
    attacked_probability: float = Field(ge=0.0, le=1.0)
    attacked_flagged: bool
    evaded: bool
    defense: Literal["normalize"]
    defended_probability: float = Field(ge=0.0, le=1.0)
    defended_flagged: bool
    defense_recovered: bool
    defended_evaded: bool


class _Resilience(_StrictModel):
    clean_flagged: bool
    attack_count: int = Field(ge=0)
    eligible_attack_count: int = Field(ge=0)
    evasion_count: int = Field(ge=0)
    defense_recovery_count: int = Field(ge=0)
    outcomes: List[_Outcome]


class _Implementation(_StrictModel):
    name: Literal["lurescope"]
    version: str = Field(min_length=1, max_length=100)
    attack_source: Literal["lurebench"]
    attack_source_version: str = Field(min_length=1, max_length=100)
    python_version: str = Field(min_length=1, max_length=100)
    sklearn_version: str = Field(min_length=1, max_length=100)


class _FrameworkMappings(_StrictModel):
    nist_ai_rmf_functions: List[Literal["MEASURE", "MANAGE"]]
    mitre_attack_techniques: List[Literal["T1566"]]


class _Predicate(_StrictModel):
    spec: Literal["lureproof"]
    spec_version: Literal["0.2"]
    generated_at: str
    issuer: Optional[str] = Field(max_length=200)
    nonce: Optional[str] = Field(min_length=8, max_length=256)
    privacy: _Privacy
    input: _Input
    assessment: _Assessment
    resilience: _Resilience
    implementation: _Implementation
    framework_mappings: _FrameworkMappings
    limitations: List[str]

    @field_validator("generated_at")
    @classmethod
    def timestamp_has_timezone(cls, value: str) -> str:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("generated_at must be an ISO 8601 timestamp") from exc
        if parsed.tzinfo is None:
            raise ValueError("generated_at must include a timezone")
        return value


class _Statement(_StrictModel):
    type_: Literal[STATEMENT_TYPE] = Field(alias="_type")
    subject: List[_Subject] = Field(min_length=1, max_length=1)
    predicate_type: Literal[PREDICATE_TYPE] = Field(alias="predicateType")
    predicate: _Predicate


def _json_bytes(value: Dict[str, Any]) -> bytes:
    """Stable creation encoding; DSSE verifies these bytes without re-encoding."""
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _model_digest(detector_name: str) -> Optional[str]:
    if detector_name != "tfidf-logreg":
        return None
    model_path = Path(__file__).with_name("models") / "tfidf-logreg-fraud.joblib"
    return _sha256(model_path.read_bytes())


def _subject(raw: bytes, privacy_profile: str, salt: Optional[bytes]) -> tuple[dict, dict]:
    if privacy_profile == "correlatable":
        if salt is not None:
            raise ValueError("subject_salt is only valid with the salted-commitment profile")
        return (
            {"name": "email-message", "digest": {"sha256": _sha256(raw)}},
            {"profile": "correlatable", "commitment_salt": None},
        )
    if privacy_profile != "salted-commitment":
        raise ValueError("privacy_profile must be 'salted-commitment' or 'correlatable'")
    resolved_salt = secrets.token_bytes(32) if salt is None else salt
    if len(resolved_salt) < 16:
        raise ValueError("subject_salt must contain at least 16 bytes")
    return (
        {
            "name": "email-message",
            "digest": {"lureproof-salted-sha256": _sha256(resolved_salt + raw)},
        },
        {
            "profile": "salted-commitment",
            "commitment_salt": base64.b64encode(resolved_salt).decode("ascii"),
        },
    )


def _validate_statement(statement: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    try:
        parsed = _Statement.model_validate(statement)
    except ValidationError as exc:
        return [
            f"{'.'.join(str(part) for part in item['loc'])}: {item['msg']}"
            for item in exc.errors(include_url=False)
        ]

    subject = parsed.subject[0]
    privacy = parsed.predicate.privacy
    algorithm = next(iter(subject.digest))
    if privacy.profile == "salted-commitment":
        if algorithm != "lureproof-salted-sha256" or not privacy.commitment_salt:
            errors.append("salted-commitment profile requires a salted subject commitment")
        else:
            try:
                salt = base64.b64decode(privacy.commitment_salt, validate=True)
                if len(salt) < 16:
                    errors.append("commitment_salt must decode to at least 16 bytes")
            except (ValueError, binascii.Error):
                errors.append("commitment_salt must be valid base64")
    elif algorithm != "sha256" or privacy.commitment_salt is not None:
        errors.append("correlatable profile requires an unsalted sha256 subject digest")

    assessment, resilience = parsed.predicate.assessment, parsed.predicate.resilience
    expected_clean = assessment.fraud_probability >= assessment.threshold
    if resilience.clean_flagged != expected_clean:
        errors.append("resilience.clean_flagged conflicts with assessment probability")
    if assessment.label != ("fraud" if expected_clean else "benign"):
        errors.append("assessment.label conflicts with probability and threshold")
    if [item.attack for item in resilience.outcomes] != list(LOCAL_ATTACKS):
        errors.append("resilience outcomes must contain each required attack once, in order")
    for item in resilience.outcomes:
        if item.evaded != (expected_clean and not item.attacked_flagged):
            errors.append(f"{item.attack}: evaded flag is inconsistent")
        if item.defense_recovered != (item.evaded and item.defended_flagged):
            errors.append(f"{item.attack}: defense_recovered flag is inconsistent")
        if item.defended_evaded != (expected_clean and not item.defended_flagged):
            errors.append(f"{item.attack}: defended_evaded flag is inconsistent")
    expected = {
        "attack_count": len(resilience.outcomes),
        "eligible_attack_count": len(resilience.outcomes) if expected_clean else 0,
        "evasion_count": sum(item.evaded for item in resilience.outcomes),
        "defense_recovery_count": sum(item.defense_recovered for item in resilience.outcomes),
    }
    for field, value in expected.items():
        if getattr(resilience, field) != value:
            errors.append(f"resilience.{field} does not match outcomes")
    mappings = parsed.predicate.framework_mappings
    if mappings.nist_ai_rmf_functions != ["MEASURE", "MANAGE"]:
        errors.append("framework mapping must contain MEASURE then MANAGE")
    if mappings.mitre_attack_techniques != ["T1566"]:
        errors.append("framework mapping must contain T1566")
    return errors


def create_email_proof(
    raw: bytes,
    detector_name: str = service.DEFAULT_DETECTOR,
    threshold: Optional[float] = None,
    engine: Optional[str] = None,
    model: Optional[str] = None,
    created_at: Optional[str] = None,
    privacy_profile: str = "salted-commitment",
    nonce: Optional[str] = None,
    issuer: Optional[str] = None,
    signing_key_pem: Optional[bytes] = None,
    subject_salt: Optional[bytes] = None,
) -> Dict[str, Any]:
    """Create a strict statement; optionally return it in a signed DSSE envelope."""
    if detector_name not in service.ALWAYS_ON:
        raise ValueError(
            "the reference LureProof producer accepts deterministic local detectors only"
        )
    if engine is not None or model is not None:
        raise ValueError("engine and model overrides are not valid for local LureProof detectors")
    parsed = parse_email(raw)
    triage = triage_email(raw, detector_name, threshold, engine, model)
    score_text = "\n\n".join(item for item in (parsed.subject, parsed.body) if item).strip()
    scored_text = score_text[:MAX_SCORE_TEXT]

    outcomes: List[Dict[str, Any]] = []
    for attack_name in LOCAL_ATTACKS:
        result = service.attack(
            scored_text,
            attack_name,
            detector_name=detector_name,
            threshold=triage.threshold,
            defense=DEFENSE,
        )
        outcomes.append({
            "attack": attack_name,
            "attacked_probability": result.attacked_probability,
            "attacked_flagged": result.attacked_flagged,
            "evaded": result.evaded,
            "defense": DEFENSE,
            "defended_probability": result.defended_probability,
            "defended_flagged": result.defended_flagged,
            "defense_recovered": bool(result.defense_recovered),
            "defended_evaded": bool(result.defended_evaded),
        })

    clean_flagged = triage.content_probability >= triage.threshold
    subject, privacy = _subject(raw, privacy_profile, subject_salt)
    statement: Dict[str, Any] = {
        "_type": STATEMENT_TYPE,
        "subject": [subject],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "spec": "lureproof",
            "spec_version": SPEC_VERSION,
            "generated_at": created_at or _timestamp(),
            "issuer": issuer,
            "nonce": nonce,
            "privacy": privacy,
            "input": {
                "media_type": "message/rfc822",
                "byte_length": len(raw),
                "parser": "python-email-policy-default",
                "scored_character_count": len(scored_text),
                "truncated": len(score_text) > MAX_SCORE_TEXT,
            },
            "assessment": {
                "detector": triage.detector,
                "detector_model": (
                    "tfidf-logreg-fraud.joblib"
                    if detector_name == "tfidf-logreg"
                    else "builtin-rules"
                ),
                "detector_artifact_sha256": _model_digest(detector_name),
                "fraud_probability": triage.content_probability,
                "label": triage.content_label,
                "risk_tier": triage.risk_tier,
                "threshold": triage.threshold,
                "threshold_source": triage.threshold_source,
                "policy_id": triage.policy_id,
                "evidence_codes": [item.code for item in triage.evidence],
                "url_count": len(triage.urls),
                "attachment_count": len(triage.attachments),
            },
            "resilience": {
                "clean_flagged": clean_flagged,
                "attack_count": len(outcomes),
                "eligible_attack_count": len(outcomes) if clean_flagged else 0,
                "evasion_count": sum(bool(item["evaded"]) for item in outcomes),
                "defense_recovery_count": sum(
                    bool(item["defense_recovered"]) for item in outcomes
                ),
                "outcomes": outcomes,
            },
            "implementation": {
                "name": "lurescope",
                "version": __version__,
                "attack_source": "lurebench",
                "attack_source_version": lurebench_version,
                "python_version": platform.python_version(),
                "sklearn_version": sklearn_version,
            },
            "framework_mappings": {
                "nist_ai_rmf_functions": ["MEASURE", "MANAGE"],
                "mitre_attack_techniques": ["T1566"],
            },
            "limitations": [
                "Unsigned statements are not authenticated.",
                "Results cover deterministic text attacks, not every fraud tactic.",
                "A salted commitment can still confirm a guessed message.",
            ],
        },
    }
    errors = _validate_statement(statement)
    if errors:
        raise ValueError("invalid generated LureProof: " + "; ".join(errors))
    return sign_statement(statement, signing_key_pem) if signing_key_pem else statement


def _pae(payload_type: str, payload: bytes) -> bytes:
    type_bytes = payload_type.encode("utf-8")
    return b"DSSEv1 %d " % len(type_bytes) + type_bytes + b" %d " % len(payload) + payload


def _public_key_id(public_key: ec.EllipticCurvePublicKey) -> str:
    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return _sha256(der)


def sign_statement(statement: Dict[str, Any], private_key_pem: bytes) -> Dict[str, Any]:
    """Wrap a validated statement in a DSSE envelope signed with ECDSA P-256."""
    errors = _validate_statement(statement)
    if errors:
        raise ValueError("cannot sign invalid LureProof: " + "; ".join(errors))
    try:
        key = serialization.load_pem_private_key(private_key_pem, password=None)
    except (TypeError, ValueError) as exc:
        raise ValueError("could not load an unencrypted PEM private key") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise ValueError("signing key must be an unencrypted ECDSA P-256 private key")
    payload = _json_bytes(statement)
    signature = key.sign(_pae(DSSE_PAYLOAD_TYPE, payload), ec.ECDSA(hashes.SHA256()))
    return {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [{
            "keyid": _public_key_id(key.public_key()),
            "sig": base64.b64encode(signature).decode("ascii"),
        }],
    }


def _decode_envelope(proof: Dict[str, Any]) -> tuple[Optional[Dict[str, Any]], bytes, List[str]]:
    errors: List[str] = []
    if set(proof) != {"payloadType", "payload", "signatures"}:
        errors.append("DSSE envelope must contain only payloadType, payload, and signatures")
    if proof.get("payloadType") != DSSE_PAYLOAD_TYPE:
        errors.append(f"payloadType must be {DSSE_PAYLOAD_TYPE!r}")
    signatures = proof.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        errors.append("signed DSSE envelope requires at least one signature")
    elif len(signatures) > 16:
        errors.append("DSSE envelope exceeds the 16-signature safety limit")
    elif any(
        not isinstance(item, dict)
        or set(item) != {"keyid", "sig"}
        or not isinstance(item.get("keyid"), str)
        or not isinstance(item.get("sig"), str)
        for item in signatures
    ):
        errors.append("each signature requires only string keyid and sig fields")
    else:
        for item in signatures:
            keyid = item["keyid"]
            if len(keyid) != 64 or any(char not in "0123456789abcdef" for char in keyid):
                errors.append("signature keyid must be 64 lowercase hex characters")
            try:
                base64.b64decode(item["sig"], validate=True)
            except (ValueError, binascii.Error):
                errors.append("signature sig must be valid base64")
    try:
        encoded = proof.get("payload")
        if not isinstance(encoded, str):
            raise ValueError
        if len(encoded) > 2 * 1024 * 1024:
            return None, b"", [*errors, "payload exceeds the 2 MB safety limit"]
        payload = base64.b64decode(encoded, validate=True)
        statement = json.loads(payload)
        if not isinstance(statement, dict):
            raise ValueError
    except (ValueError, json.JSONDecodeError, binascii.Error):
        return None, b"", [*errors, "payload must be base64-encoded JSON object bytes"]
    return statement, payload, errors


def verify_proof(
    proof: Dict[str, Any],
    public_key_pem: Optional[bytes] = None,
    require_signature: bool = False,
) -> Dict[str, Any]:
    """Validate a statement and authenticate a DSSE signature against a trust key."""
    errors: List[str] = []
    warnings: List[str] = []
    authenticated = False
    is_envelope = "payloadType" in proof or "payload" in proof or "signatures" in proof

    if is_envelope:
        statement, payload, envelope_errors = _decode_envelope(proof)
        errors.extend(envelope_errors)
        signature_count = len(proof.get("signatures", [])) if isinstance(
            proof.get("signatures"), list
        ) else 0
    else:
        statement, payload = proof, _json_bytes(proof)
        signature_count = 0

    if statement is not None:
        errors.extend(_validate_statement(statement))
    statement_digest = _sha256(payload) if payload else ""

    if is_envelope and public_key_pem is not None and not envelope_errors:
        try:
            key = serialization.load_pem_public_key(public_key_pem)
            if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
                key.curve, ec.SECP256R1
            ):
                raise ValueError("verification key must be an ECDSA P-256 public key")
            trusted_keyid = _public_key_id(key)
            candidates = [
                item for item in proof["signatures"] if item["keyid"] == trusted_keyid
            ]
            if not candidates:
                errors.append("no signature matches the trusted public key")
            for candidate in candidates:
                try:
                    signature = base64.b64decode(candidate["sig"], validate=True)
                    key.verify(
                        signature,
                        _pae(proof["payloadType"], payload),
                        ec.ECDSA(hashes.SHA256()),
                    )
                    authenticated = True
                    break
                except (InvalidSignature, ValueError, binascii.Error):
                    continue
            if candidates and not authenticated:
                errors.append("signature verification failed")
        except (ValueError, TypeError) as exc:
            errors.append(str(exc))
    elif is_envelope:
        warnings.append("signature present but not authenticated: provide a trusted public key")
    else:
        warnings.append("unsigned statement: schema validity does not authenticate its issuer")

    if require_signature and not authenticated:
        if public_key_pem is None:
            errors.append("authenticated verification requires a trusted public key")
        else:
            errors.append("an authenticated signature is required")

    key_ids = []
    if is_envelope and isinstance(proof.get("signatures"), list):
        key_ids = [
            item.get("keyid", "") for item in proof["signatures"] if isinstance(item, dict)
        ]
    return {
        "valid": not errors,
        "schema_valid": statement is not None and not _validate_statement(statement),
        "authenticated": authenticated,
        "artifact_type": "dsse" if is_envelope else "statement",
        "statement_sha256": statement_digest,
        "signature_count": signature_count,
        "key_ids": key_ids,
        "errors": errors,
        "warnings": warnings,
    }


def generate_keypair(private_path: Path, public_path: Path) -> str:
    """Generate a P-256 keypair without overwriting files; private mode is 0600."""
    if private_path.exists() or public_path.exists():
        raise FileExistsError("refusing to overwrite an existing key file")
    key = ec.generate_private_key(ec.SECP256R1())
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    created: List[Path] = []
    try:
        for path, content, mode in (
            (private_path, private_pem, 0o600),
            (public_path, public_pem, 0o644),
        ):
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
            created.append(path)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
    except Exception:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return _public_key_id(key.public_key())


def dumps_proof(proof: Dict[str, Any]) -> str:
    return json.dumps(proof, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
