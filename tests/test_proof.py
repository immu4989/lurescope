"""LureProof schema, privacy, DSSE authentication, provenance, API-facing semantics."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("sklearn")

from lurescope.cli import main
from lurescope.proof import (
    DSSE_PAYLOAD_TYPE,
    MAX_PROOF_BYTES,
    create_email_proof,
    generate_keypair,
    load_proof,
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


def test_local_email_proof_never_imports_model_frameworks():
    code = '''
import sys
class Block:
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'pickle', 'joblib', 'sklearn', 'numpy', 'torch'}:
            raise ImportError('model framework forbidden')
        return None
sys.meta_path.insert(0, Block())
sys.path.insert(0, sys.argv[1])
from lurescope.proof import create_email_proof, verify_proof
statement = create_email_proof(b'Subject: Team notes\\n\\nPlease review notes.',
    created_at='2026-10-02T00:00:00Z', subject_salt=bytes(range(32)))
assert verify_proof(statement)['valid']
print('proof valid without model framework imports')
'''
    root = str(Path(__file__).resolve().parents[1])
    result = subprocess.run([sys.executable, "-I", "-c", code, root],
                            check=True, capture_output=True, text=True, timeout=30)
    assert "proof valid" in result.stdout


def test_missing_sklearn_distribution_is_explicit_metadata(monkeypatch):
    import lurescope.proof as module

    def missing(name):
        raise module.PackageNotFoundError(name)

    monkeypatch.setattr(module, "version", missing)
    statement = _statement()
    assert statement["predicate"]["implementation"]["sklearn_version"] == "not-installed"
    assert verify_proof(statement)["valid"]


@pytest.mark.parametrize("options", [
    {"threshold": True}, {"threshold": float("nan")}, {"detector_name": []},
    {"privacy_profile": "unknown"}, {"privacy_profile": []},
    {"nonce": "short"}, {"nonce": "1234567\n"}, {"nonce": 12345678},
    {"issuer": "unpaired\ud800"}, {"issuer": "x" * 201}, {"issuer": False},
    {"subject_salt": "x" * 32}, {"subject_salt": b"x" * 15},
    {"subject_salt": b"x" * 1025},
    {"privacy_profile": "correlatable", "subject_salt": b"x" * 32},
    {"signing_key_pem": b""}, {"signing_key_pem": b"not a key"},
    {"signing_key_pem": "not bytes"}, {"signing_key_pem": b"x" * 16385},
])
def test_invalid_producer_settings_fail_before_message_parsing(monkeypatch, options):
    import lurescope.proof as module

    def forbidden(*args, **kwargs):
        pytest.fail("message parsing or scoring began before option validation")

    monkeypatch.setattr(module, "parse_email", forbidden)
    monkeypatch.setattr(module, "triage_email", forbidden)
    with pytest.raises(ValueError):
        create_email_proof(RAW, **options)


def test_oversized_private_key_is_rejected_before_crypto_parser(monkeypatch):
    import lurescope.proof as module

    statement = _statement()
    monkeypatch.setattr(module.serialization, "load_pem_private_key",
                        lambda *a, **kw: pytest.fail("unbounded key reached crypto parser"))
    with pytest.raises(ValueError, match="bounded PEM"):
        sign_statement(statement, b"x" * (module.MAX_PRIVATE_KEY_BYTES + 1))


@pytest.mark.parametrize("value", ["", False, 0, [], {}, "2026-01-01T00:00:00"])
def test_explicit_bad_creation_time_fails_before_scoring(monkeypatch, value):
    import lurescope.proof as module

    monkeypatch.setattr(module, "triage_email", lambda *a: pytest.fail("scoring started"))
    with pytest.raises(ValueError):
        create_email_proof(RAW, created_at=value)


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


def test_valid_signature_cannot_make_duplicate_key_payload_acceptable(tmp_path):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from lurescope.proof import _pae

    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    generate_keypair(private, public)
    envelope = sign_statement(_statement(), private.read_bytes())
    original = base64.b64decode(envelope["payload"])
    payload = original.replace(b'"spec":"lureproof"', b'"spec":"other","spec":"lureproof"')
    assert payload != original
    key = serialization.load_pem_private_key(private.read_bytes(), password=None)
    signature = key.sign(_pae(DSSE_PAYLOAD_TYPE, payload), ec.ECDSA(hashes.SHA256()))
    envelope["payload"] = base64.b64encode(payload).decode()
    envelope["signatures"][0]["sig"] = base64.b64encode(signature).decode()
    result = verify_proof(envelope, public.read_bytes(), require_signature=True)
    assert not result["valid"] and not result["schema_valid"] and not result["authenticated"]


@pytest.mark.parametrize("payload", [b'{"x":NaN}', b'{"x":1e999}', b'{"x":1,"x":2}',
                                      b'[' * 130 + b'0' + b']' * 130, b'\xff'])
def test_proof_loader_rejects_ambiguous_or_non_utf8_bytes(tmp_path, payload):
    path = tmp_path / "proof.json"
    path.write_bytes(payload)
    with pytest.raises(ValueError):
        load_proof(path)


@pytest.mark.parametrize("value", [None, [], 1, {"x": float("nan")}, {"x": "\ud800"},
                                    {"x": "a" * MAX_PROOF_BYTES}])
def test_direct_verifier_invalid_objects_return_bounded_failure(value):
    result = verify_proof(value)
    assert not result["valid"] and not result["authenticated"]
    assert len(json.dumps(result)) < 1000


@pytest.mark.parametrize("option", [0, 1, "false", None])
def test_direct_verifier_signature_requirement_cannot_be_coerced(option):
    with pytest.raises(ValueError, match="boolean"):
        verify_proof({}, require_signature=option)


def test_proof_loader_rejects_symlink_and_oversized_file(tmp_path):
    path = tmp_path / "proof.json"
    path.write_text("{}")
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(ValueError):
        load_proof(link)
    with path.open("wb") as handle:
        handle.truncate(MAX_PROOF_BYTES + 1)
    with pytest.raises(ValueError):
        load_proof(path)


def test_api_malformed_signature_ids_do_not_crash_or_echo_fields(monkeypatch):
    from fastapi.testclient import TestClient

    from lurescope.app import app

    monkeypatch.delenv("LURESCOPE_PUBLIC_MODE", raising=False)
    monkeypatch.delenv("LURESCOPE_API_KEY_SCRYPT", raising=False)
    envelope = {"payloadType": DSSE_PAYLOAD_TYPE,
                "payload": base64.b64encode(b"{}").decode(),
                "signatures": [{"keyid": {"PRIVATE_SENTINEL": True}, "sig": ""}]}
    response = TestClient(app).post("/proof/verify", json={"proof": envelope})
    assert response.status_code == 200
    assert response.json()["valid"] is False
    assert response.json()["key_ids"] == []
    assert "PRIVATE_SENTINEL" not in response.text
