from __future__ import annotations

import ast
import base64
import copy
import hashlib
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from lurescope.cli import main
from lurescope.mandate_conformance_auth import (
    create_authenticated_mandate_conformance_verification,
    load_authenticated_mandate_conformance_verification,
    sign_mandate_conformance_submission,
    validate_authenticated_mandate_conformance_verification,
)
from lurescope.permit import _canonical

ROOT = Path(__file__).parents[1]
VECTOR = ROOT / "conformance" / "luremandate-v1"
KEY_ID = "278fb7473fae2b6b4213d916f3bf481d7ae209fe8c08443f84367e7bc9d1f1df"


def _load(name: str) -> dict:
    return json.loads((VECTOR / name).read_text(encoding="utf-8"))


def _registry() -> Registry:
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def _keys(tmp_path: Path, stem: str = "gateway") -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    private_path = tmp_path / f"{stem}.private.pem"
    public_path = tmp_path / f"{stem}.public.pem"
    private_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private_path.chmod(0o600)
    public_path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_path, public_path


def test_public_gateway_signature_reauthenticates_and_validates_schema():
    report = _load("authenticated-conformance-verification.json")
    assert validate_authenticated_mandate_conformance_verification(report) == report
    assert (
        load_authenticated_mandate_conformance_verification(
            VECTOR / "authenticated-conformance-verification.json"
        )
        == report
    )
    assert report["summary"]["verdict"] == "pass"
    assert report["summary"]["exact_match_count"] == 25
    assert report["summary"]["covered_reason_count"] == 21
    assert report["summary"]["reason_coverage_complete"] is True
    assert report["summary"]["gateway_submission_authenticated"] is True
    assert report["summary"]["gateway_public_key_sha256"] == KEY_ID

    schema = json.loads(
        (
            ROOT / "spec" / "luremandate-authenticated-conformance-verification-v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(
        schema,
        registry=_registry(),
        format_checker=FormatChecker(),
    ).validate(report)


def test_reference_sign_and_authenticate_are_private_and_non_overwriting(tmp_path: Path):
    private_key, public_key = _keys(tmp_path)
    envelope_path = tmp_path / "submission.dsse.json"
    envelope = sign_mandate_conformance_submission(
        VECTOR / "challenge.json",
        VECTOR / "submission.json",
        private_key,
        envelope_path,
    )
    key_id = envelope["signatures"][0]["keyid"]
    report_path = tmp_path / "authenticated.json"
    report = create_authenticated_mandate_conformance_verification(
        VECTOR / "conformance-verification.json",
        envelope_path,
        public_key,
        report_path,
        expected_gateway_key_id=key_id,
        verified_at="2026-09-05T15:30:00Z",
    )
    assert report["summary"]["gateway_public_key_sha256"] == key_id
    assert load_authenticated_mandate_conformance_verification(report_path) == report
    if os.name == "posix":
        assert envelope_path.stat().st_mode & 0o777 == 0o600
        assert report_path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        sign_mandate_conformance_submission(
            VECTOR / "challenge.json",
            VECTOR / "submission.json",
            private_key,
            envelope_path,
        )
    with pytest.raises(FileExistsError):
        create_authenticated_mandate_conformance_verification(
            VECTOR / "conformance-verification.json",
            envelope_path,
            public_key,
            report_path,
            expected_gateway_key_id=key_id,
            verified_at="2026-09-05T15:30:00Z",
        )


def test_submission_payload_signature_and_embedded_report_tampering_fail_closed():
    report = _load("authenticated-conformance-verification.json")

    changed_summary = copy.deepcopy(report)
    changed_summary["summary"]["exact_match_count"] = 24
    with pytest.raises(ValueError, match="does not reproduce"):
        validate_authenticated_mandate_conformance_verification(changed_summary)

    changed_payload = copy.deepcopy(report)
    envelope = json.loads(
        base64.b64decode(changed_payload["submission_envelope"]["envelope_base64"], validate=True)
    )
    submission = json.loads(base64.b64decode(envelope["payload"], validate=True))
    submission["engine"]["engine_id"] = "substituted-gateway"
    envelope["payload"] = base64.b64encode(_canonical(submission)).decode("ascii")
    envelope_payload = _canonical(envelope)
    changed_payload["submission_envelope"]["envelope_base64"] = base64.b64encode(
        envelope_payload
    ).decode("ascii")
    changed_payload["submission_envelope"]["envelope_sha256"] = hashlib.sha256(
        envelope_payload
    ).hexdigest()
    with pytest.raises(ValueError, match="differs from the verified gateway submission"):
        validate_authenticated_mandate_conformance_verification(changed_payload)

    tampered_signature = copy.deepcopy(report)
    envelope = json.loads(
        base64.b64decode(
            tampered_signature["submission_envelope"]["envelope_base64"], validate=True
        )
    )
    signature = bytearray(base64.b64decode(envelope["signatures"][0]["sig"], validate=True))
    signature[-1] ^= 1
    envelope["signatures"][0]["sig"] = base64.b64encode(signature).decode("ascii")
    envelope_payload = _canonical(envelope)
    tampered_signature["submission_envelope"]["envelope_base64"] = base64.b64encode(
        envelope_payload
    ).decode("ascii")
    tampered_signature["submission_envelope"]["envelope_sha256"] = hashlib.sha256(
        envelope_payload
    ).hexdigest()
    with pytest.raises(ValueError, match="signature authentication failed"):
        validate_authenticated_mandate_conformance_verification(tampered_signature)


def test_external_gateway_key_pin_and_private_key_permissions_fail_closed(tmp_path: Path):
    _, unrelated_public_key = _keys(tmp_path, "unrelated")
    with pytest.raises(ValueError, match="externally pinned key ID"):
        create_authenticated_mandate_conformance_verification(
            VECTOR / "conformance-verification.json",
            VECTOR / "submission.dsse.json",
            unrelated_public_key,
            tmp_path / "wrong-key-report.json",
            expected_gateway_key_id=KEY_ID,
            verified_at="2026-09-05T15:30:00Z",
        )

    if os.name == "posix":
        private_key, _ = _keys(tmp_path, "open")
        private_key.chmod(0o644)
        with pytest.raises(ValueError, match="group or world access"):
            sign_mandate_conformance_submission(
                VECTOR / "challenge.json",
                VECTOR / "submission.json",
                private_key,
                tmp_path / "must-not-exist.json",
            )


def test_cli_reauthenticates_and_repository_contains_no_private_gateway_key(capsys):
    assert (
        main(
            [
                "mandate",
                "check-conformance-auth",
                str(VECTOR / "authenticated-conformance-verification.json"),
            ]
        )
        == 0
    )
    assert "GATEWAY SUBMISSION AUTHENTICATED: PASS" in capsys.readouterr().out
    for path in VECTOR.rglob("*.pem"):
        assert b"PRIVATE KEY" not in path.read_bytes()
    tree = ast.parse(
        (ROOT / "lurescope" / "mandate_conformance_auth.py").read_text(encoding="utf-8")
    )
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module and not node.level
    )
    assert not any(name == "lurebench" or name.startswith("lurebench.") for name in imports)
