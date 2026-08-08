"""LureProof schema, privacy, DSSE authentication, provenance, API-facing semantics."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest

pytest.importorskip("sklearn")

from lurescope.cli import main
from lurescope.proof import (
    DSSE_PAYLOAD_TYPE,
    create_email_proof,
    generate_keypair,
    sign_statement,
    verify_proof,
)

RAW = (
    b"From: Payroll <payroll@example.org>\n"
    b"Reply-To: collect@other.example\n"
    b"To: employee@example.org\n"
    b"Message-ID: <secret-123@example.org>\n"
    b"Subject: Urgent payroll verification\n\n"
    b"Verify your account at http://192.0.2.10/payroll within 24 hours.\n"
)
FIXED_SALT = bytes(range(32))


def _statement(**kwargs):
    return create_email_proof(
        RAW,
        created_at="2026-08-08T12:00:00Z",
        subject_salt=FIXED_SALT,
        **kwargs,
    )


def test_unsigned_statement_is_strict_minimized_and_explicitly_unauthenticated():
    proof = _statement()
    serialized = json.dumps(proof)
    result = verify_proof(proof)
    assert result["valid"] is True
    assert result["schema_valid"] is True
    assert result["authenticated"] is False
    assert result["artifact_type"] == "statement"
    assert result["warnings"]
    for secret in (
        "Urgent payroll verification", "payroll@example.org", "employee@example.org",
        "192.0.2.10", "secret-123", "Verify your account",
    ):
        assert secret not in serialized
    predicate = proof["predicate"]
    assert predicate["privacy"]["profile"] == "salted-commitment"
    assert len(predicate["resilience"]["outcomes"]) == 4
    assert all("attacked_text" not in item for item in predicate["resilience"]["outcomes"])
    assert predicate["assessment"]["detector_artifact_sha256"]
    assert predicate["implementation"]["attack_source_version"]


def test_default_salted_commitments_change_between_proofs():
    first = create_email_proof(RAW, created_at="2026-08-08T12:00:00Z")
    second = create_email_proof(RAW, created_at="2026-08-08T12:00:00Z")
    assert first["subject"][0]["digest"] != second["subject"][0]["digest"]


def test_fixed_salt_and_timestamp_are_reproducible():
    assert _statement() == _statement()


def test_correlatable_profile_is_explicit_opt_in():
    proof = create_email_proof(
        RAW, created_at="2026-08-08T12:00:00Z", privacy_profile="correlatable"
    )
    assert set(proof["subject"][0]["digest"]) == {"sha256"}
    assert proof["predicate"]["privacy"] == {
        "profile": "correlatable", "commitment_salt": None
    }


def test_schema_rejects_unknown_fields_and_inconsistent_counters():
    proof = _statement()
    proof["predicate"]["assessment"]["surprise"] = True
    result = verify_proof(proof)
    assert result["valid"] is False
    assert any("surprise" in error for error in result["errors"])

    proof = _statement()
    proof["predicate"]["resilience"]["evasion_count"] = 99
    result = verify_proof(proof)
    assert result["valid"] is False
    assert any("evasion_count" in error for error in result["errors"])

    proof = _statement()
    code = proof["predicate"]["assessment"]["evidence_codes"][0]
    proof["predicate"]["assessment"]["evidence_codes"].append(code)
    result = verify_proof(proof)
    assert result["valid"] is False
    assert any("unique" in error for error in result["errors"])


def test_reference_producer_rejects_nonlocal_model_overrides():
    with pytest.raises(ValueError, match="overrides"):
        create_email_proof(RAW, model="untracked-model")


def test_published_json_schemas_accept_reference_artifacts(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    root = Path(__file__).parents[1]
    statement = _statement()
    statement_schema = json.loads((root / "spec/lureproof.schema.json").read_text())
    jsonschema.Draft202012Validator(statement_schema).validate(statement)

    private_path, public_path = tmp_path / "issuer.pem", tmp_path / "issuer.pub.pem"
    generate_keypair(private_path, public_path)
    envelope = sign_statement(statement, private_path.read_bytes())
    envelope_schema = json.loads((root / "spec/lureproof-dsse.schema.json").read_text())
    jsonschema.Draft202012Validator(envelope_schema).validate(envelope)


def test_signed_dsse_authenticates_and_detects_payload_replacement(tmp_path):
    private_path, public_path = tmp_path / "issuer.pem", tmp_path / "issuer.pub.pem"
    key_id = generate_keypair(private_path, public_path)
    envelope = sign_statement(_statement(), private_path.read_bytes())
    assert envelope["payloadType"] == DSSE_PAYLOAD_TYPE
    assert envelope["signatures"][0]["keyid"] == key_id

    verified = verify_proof(envelope, public_path.read_bytes(), require_signature=True)
    assert verified["valid"] is True
    assert verified["authenticated"] is True

    payload = json.loads(base64.b64decode(envelope["payload"]))
    payload["predicate"]["assessment"]["fraud_probability"] = 0.0
    envelope["payload"] = base64.b64encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).decode()
    tampered = verify_proof(envelope, public_path.read_bytes(), require_signature=True)
    assert tampered["valid"] is False
    assert tampered["authenticated"] is False


def test_wrong_trust_key_fails_authentication(tmp_path):
    private_path, public_path = tmp_path / "issuer.pem", tmp_path / "issuer.pub.pem"
    other_private, other_public = tmp_path / "other.pem", tmp_path / "other.pub.pem"
    generate_keypair(private_path, public_path)
    generate_keypair(other_private, other_public)
    envelope = sign_statement(_statement(), private_path.read_bytes())
    result = verify_proof(envelope, other_public.read_bytes(), require_signature=True)
    assert result["valid"] is False
    assert result["authenticated"] is False
    assert any("trusted public key" in error for error in result["errors"])


def test_malformed_dsse_signature_is_rejected_without_a_public_key(tmp_path):
    private_path, public_path = tmp_path / "issuer.pem", tmp_path / "issuer.pub.pem"
    generate_keypair(private_path, public_path)
    envelope = sign_statement(_statement(), private_path.read_bytes())
    envelope["signatures"][0]["sig"] = "not-base64!"
    result = verify_proof(envelope)
    assert result["valid"] is False
    assert any("valid base64" in error for error in result["errors"])


def test_keygen_refuses_overwrite_and_uses_private_permissions(tmp_path):
    private_path, public_path = tmp_path / "issuer.pem", tmp_path / "issuer.pub.pem"
    generate_keypair(private_path, public_path)
    assert os.stat(private_path).st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        generate_keypair(private_path, public_path)


def test_cli_signed_create_and_required_verify(tmp_path, capsys):
    source = tmp_path / "message.eml"
    output = tmp_path / "message.lureproof.dsse.json"
    private_path, public_path = tmp_path / "issuer.pem", tmp_path / "issuer.pub.pem"
    source.write_bytes(RAW)
    assert main([
        "keygen", "--private-out", str(private_path), "--public-out", str(public_path)
    ]) == 0
    capsys.readouterr()
    assert main([
        "proof", str(source), "--out", str(output), "--signing-key", str(private_path),
        "--issuer", "Example SOC", "--nonce", "challenge-12345",
    ]) == 0
    capsys.readouterr()
    assert main([
        "verify", str(output), "--public-key", str(public_path), "--require-signature",
    ]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["authenticated"] is True
