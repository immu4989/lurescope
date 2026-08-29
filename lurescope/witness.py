"""Offline external witnesses for LureBoundary and LureWatch checkpoints.

Witness receipts close the local hash-chain tail-deletion gap by proving that an
independent key observed a particular checkpoint.  The portable format uses an
in-toto statement in DSSE and can be exchanged in air-gapped environments.  It
is SCITT-aligned evidence, not an implementation of an RFC 9943 Transparency
Service or a claim of registration in one.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from .boundary import (
    _private_key,
    _private_key_id,
    _sign_statement,
    _verify_envelope,
    public_key_id,
    verify_boundary_bundle,
)
from .watch import verify_monitor_bundle

REQUEST_SCHEMA = "https://github.com/immu4989/lurescope/spec/checkpoint-witness-request/v1"
RECEIPT_SCHEMA = "https://github.com/immu4989/lurescope/spec/checkpoint-witness-receipt/v1"
PREDICATE_TYPE = "https://github.com/immu4989/lurescope/spec/checkpoint-witness/v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
_PRIVACY = {
    "contains_event_content": False,
    "contains_prompts_commands_payloads_credentials_or_reasoning": False,
    "checkpoint_digest_only": True,
}
_LIMITATIONS = [
    "receipt_proves_observation_by_a_key_not_log_inclusion_or_organization_identity",
    "witness_independence_key_custody_and_timestamp_accuracy_require_external_governance",
    "offline_receipt_is_scitt_aligned_but_not_an_rfc9943_transparency_service_receipt",
    "checkpoint_integrity_is_not_proof_of_containment_safety_compliance_or_authorization",
]
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+/-]{0,199}$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")


def _timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _canonical(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _strict(payload: bytes, label: str) -> Any:
    def no_duplicates(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} contains duplicate key {key!r}")
            result[key] = value
        return result

    def no_constants(value: str) -> None:
        raise ValueError(f"{label} contains non-standard JSON constant {value}")

    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=no_duplicates,
            parse_constant=no_constants,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not strict UTF-8 JSON") from exc


def _read(path: Path, *, private: bool = False) -> bytes:
    target = Path(path)
    if target.is_symlink() or not target.is_file():
        raise ValueError(f"{target} must be a regular local JSON file")
    if target.stat().st_size > MAX_ARTIFACT_BYTES:
        raise ValueError(f"{target.name} exceeds the 2 MiB limit")
    if private and os.name == "posix" and target.stat().st_mode & 0o077:
        raise ValueError(f"{target.name} must not grant group or world access")
    return target.read_bytes()


def _write_new(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _exact(value: Any, field: str, keys: Sequence[str]) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError(f"{field} violates its field allowlist")
    return value


def _parse_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be ISO 8601")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be ISO 8601") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a UTC offset")
    return parsed


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ValueError(f"{field} must be a portable 1-200 character identifier")
    return value


def _validate_request(value: Any) -> Dict[str, Any]:
    request = _exact(
        value,
        "witness request",
        (
            "schema",
            "schema_version",
            "request_id",
            "created_at",
            "bundle_kind",
            "plan_sha256",
            "checkpoint_sequence",
            "checkpoint_statement_sha256",
            "status",
            "nonce",
            "privacy",
            "limitations",
        ),
    )
    if request["schema"] != REQUEST_SCHEMA or request["schema_version"] != 1:
        raise ValueError("unsupported witness request")
    _parse_timestamp(request["created_at"], "witness request created_at")
    if request["bundle_kind"] not in {"lureboundary", "lurewatch"}:
        raise ValueError("witness request bundle_kind is unsupported")
    for key in ("plan_sha256", "checkpoint_statement_sha256"):
        value_digest = request[key]
        if not isinstance(value_digest, str) or _DIGEST.fullmatch(value_digest) is None:
            raise ValueError(f"witness request {key} must be a SHA-256 digest")
    if (
        isinstance(request["checkpoint_sequence"], bool)
        or not isinstance(request["checkpoint_sequence"], int)
        or request["checkpoint_sequence"] < 1
    ):
        raise ValueError("witness request checkpoint_sequence must be positive")
    _identifier(request["request_id"], "witness request request_id")
    expected_statuses = (
        {"pass", "breach"} if request["bundle_kind"] == "lureboundary" else {"monitoring", "breach"}
    )
    if request["status"] not in expected_statuses:
        raise ValueError("witness request status is invalid for its bundle kind")
    if (
        not isinstance(request["nonce"], str)
        or not 8 <= len(request["nonce"]) <= 200
        or re.fullmatch(r"[A-Za-z0-9._:@+/-]+", request["nonce"]) is None
    ):
        raise ValueError("witness request nonce must contain 8 to 200 characters")
    if request["privacy"] != _PRIVACY or request["limitations"] != _LIMITATIONS:
        raise ValueError("witness request interpretation boundary is invalid")
    return dict(request)


def _load_request(path: Path, *, private: bool = False) -> tuple[Dict[str, Any], bytes]:
    raw = _read(path, private=private)
    request = _validate_request(_strict(raw, path.name))
    if raw != _canonical(request):
        raise ValueError("witness request must use canonical JSON")
    return request, raw


def _binding(bundle: Path, kind: str, public_key_pem: Optional[bytes]) -> Dict[str, Any]:
    if kind == "lureboundary":
        result = verify_boundary_bundle(bundle, public_key_pem=public_key_pem)
        status = result["boundary_status"]
    elif kind == "lurewatch":
        result = verify_monitor_bundle(bundle, public_key_pem=public_key_pem)
        status = result["family_status"]
    else:
        raise ValueError("bundle kind must be lureboundary or lurewatch")
    if result["latest_sequence"] < 1 or result["latest_statement_sha256"] is None:
        raise ValueError("witnessing requires at least one checkpoint")
    return {
        "plan_sha256": result["plan_sha256"],
        "checkpoint_sequence": result["latest_sequence"],
        "checkpoint_statement_sha256": result["latest_statement_sha256"],
        "status": status,
    }


def create_witness_request(
    bundle: Path,
    output: Path,
    *,
    bundle_kind: str,
    public_key_pem: Optional[bytes] = None,
    request_id: Optional[str] = None,
    nonce: Optional[str] = None,
    created_at: Optional[str] = None,
) -> Dict[str, Any]:
    binding = _binding(Path(bundle), bundle_kind, public_key_pem)
    request = {
        "schema": REQUEST_SCHEMA,
        "schema_version": 1,
        "request_id": request_id or f"witness-{secrets.token_hex(12)}",
        "created_at": created_at or _timestamp(),
        "bundle_kind": bundle_kind,
        **binding,
        "nonce": nonce or secrets.token_hex(16),
        "privacy": dict(_PRIVACY),
        "limitations": list(_LIMITATIONS),
    }
    request = _validate_request(request)
    _write_new(Path(output), _canonical(request))
    return request


def _statement(request: Mapping[str, Any], request_sha: str, witness_id: str, issued_at: str):
    return {
        "_type": STATEMENT_TYPE,
        "subject": [
            {
                "name": f"{request['bundle_kind']}-checkpoint-{request['checkpoint_sequence']}",
                "digest": {"sha256": request["checkpoint_statement_sha256"]},
            }
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "request_id": request["request_id"],
            "request_sha256": request_sha,
            "bundle_kind": request["bundle_kind"],
            "plan_sha256": request["plan_sha256"],
            "checkpoint_sequence": request["checkpoint_sequence"],
            "checkpoint_statement_sha256": request["checkpoint_statement_sha256"],
            "status": request["status"],
            "nonce": request["nonce"],
            "witness_id": witness_id,
            "issued_at": issued_at,
            "limitations": list(_LIMITATIONS),
        },
    }


def issue_witness_receipt(
    request_path: Path,
    output: Path,
    *,
    witness_id: str,
    signing_key_pem: bytes,
    issued_at: Optional[str] = None,
) -> Dict[str, Any]:
    request, request_raw = _load_request(Path(request_path))
    _identifier(witness_id, "witness_id")
    key = _private_key(signing_key_pem)
    receipt_time = issued_at or _timestamp()
    if _parse_timestamp(receipt_time, "witness receipt issued_at") < _parse_timestamp(
        request["created_at"], "witness request created_at"
    ):
        raise ValueError("witness receipt cannot predate its request")
    statement = _statement(request, _sha256(request_raw), witness_id, receipt_time)
    statement_raw = _canonical(statement)
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "schema_version": 1,
        "witness": {"witness_id": witness_id, "key_id": _private_key_id(key)},
        "statement": statement,
        "dsse": _sign_statement(statement_raw, key),
        "limitations": list(_LIMITATIONS),
    }
    _write_new(Path(output), _canonical(receipt))
    return receipt


def verify_witness_request_binding(
    request_path: Path,
    bundle: Path,
    *,
    public_key_pem: Optional[bytes] = None,
) -> Dict[str, Any]:
    """Confirm that a witness request names the bundle's current checkpoint."""

    request, _ = _load_request(Path(request_path), private=True)
    current = _binding(Path(bundle), request["bundle_kind"], public_key_pem)
    expected = {
        "plan_sha256": request["plan_sha256"],
        "checkpoint_sequence": request["checkpoint_sequence"],
        "checkpoint_statement_sha256": request["checkpoint_statement_sha256"],
        "status": request["status"],
    }
    if current != expected:
        raise ValueError(
            "witness request does not match the bundle's current checkpoint; "
            "the bundle may have advanced, been truncated, or been replaced"
        )
    return {"valid": True, **current, "bundle_kind": request["bundle_kind"]}


def verify_witness_receipt(
    request_path: Path,
    receipt_path: Path,
    *,
    public_key_pem: bytes,
) -> Dict[str, Any]:
    request, request_raw = _load_request(Path(request_path), private=True)
    receipt_raw = _read(Path(receipt_path), private=True)
    receipt = _strict(receipt_raw, Path(receipt_path).name)
    if receipt_raw != _canonical(receipt):
        raise ValueError("witness receipt must use canonical JSON")
    receipt = _exact(
        receipt,
        "witness receipt",
        ("schema", "schema_version", "witness", "statement", "dsse", "limitations"),
    )
    if receipt["schema"] != RECEIPT_SCHEMA or receipt["schema_version"] != 1:
        raise ValueError("unsupported witness receipt")
    witness = _exact(receipt["witness"], "witness", ("witness_id", "key_id"))
    _identifier(witness["witness_id"], "witness receipt witness_id")
    key_id = public_key_id(public_key_pem)
    if witness["key_id"] != key_id:
        raise ValueError("witness public key is not the receipt signer")
    statement = receipt["statement"]
    predicate = statement.get("predicate") if isinstance(statement, dict) else None
    if not isinstance(predicate, dict):
        raise ValueError("witness statement predicate is invalid")
    issued = _parse_timestamp(predicate.get("issued_at"), "witness receipt issued_at")
    requested = _parse_timestamp(request["created_at"], "witness request created_at")
    if issued < requested:
        raise ValueError("witness receipt cannot predate its request")
    expected = _statement(
        request,
        _sha256(request_raw),
        witness["witness_id"],
        predicate.get("issued_at"),
    )
    if statement != expected:
        raise ValueError("witness statement does not bind the request")
    statement_raw = _canonical(statement)
    verified_key = _verify_envelope(receipt["dsse"], statement_raw, public_key_pem)
    if receipt["limitations"] != _LIMITATIONS:
        raise ValueError("witness receipt interpretation boundary is invalid")
    return {
        "valid": True,
        "request_id": request["request_id"],
        "witness_id": witness["witness_id"],
        "key_id": verified_key,
        "checkpoint_statement_sha256": request["checkpoint_statement_sha256"],
        "issued_at": predicate["issued_at"],
        "receipt_sha256": _sha256(receipt_raw),
    }


def verify_witness_quorum(
    request_path: Path,
    receipt_paths: Sequence[Path],
    public_keys_pem: Sequence[bytes],
    *,
    minimum_witnesses: int,
) -> Dict[str, Any]:
    if len(receipt_paths) != len(public_keys_pem):
        raise ValueError("each witness receipt requires exactly one public key")
    if (
        isinstance(minimum_witnesses, bool)
        or not isinstance(minimum_witnesses, int)
        or not 1 <= minimum_witnesses <= len(receipt_paths)
    ):
        raise ValueError("minimum_witnesses must be between one and receipt count")
    verified = [
        verify_witness_receipt(request_path, receipt, public_key_pem=key)
        for receipt, key in zip(receipt_paths, public_keys_pem, strict=True)
    ]
    key_ids = {item["key_id"] for item in verified}
    witness_ids = {item["witness_id"] for item in verified}
    if len(key_ids) != len(verified) or len(witness_ids) != len(verified):
        raise ValueError("witness quorum requires distinct witness ids and signing keys")
    return {
        "valid": len(verified) >= minimum_witnesses,
        "minimum_witnesses": minimum_witnesses,
        "verified_witnesses": len(verified),
        "witness_ids": sorted(witness_ids),
        "key_ids": sorted(key_ids),
        "checkpoint_statement_sha256": verified[0]["checkpoint_statement_sha256"],
        "limitations": list(_LIMITATIONS),
    }
