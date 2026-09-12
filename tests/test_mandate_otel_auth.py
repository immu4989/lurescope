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
from lurescope.mandate_otel_auth import (
    create_authenticated_mandate_otel_projection,
    load_authenticated_mandate_otel_projection,
    sign_mandate_otel_export,
    validate_authenticated_mandate_otel_projection,
)
from lurescope.permit import _canonical

ROOT = Path(__file__).parents[1]
VECTOR = ROOT / "conformance" / "luremandate-v1"
KEY_ID = "23b870f8eb429486d3ebab388918350ca0a9b8d5b735c18de5d2ed4ebd6c7211"


def _load(name: str) -> dict:
    return json.loads((VECTOR / name).read_text(encoding="utf-8"))


def _registry() -> Registry:
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def _keys(tmp_path: Path) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    private_path = tmp_path / "receiver.private.pem"
    public_path = tmp_path / "receiver.public.pem"
    private_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_path, public_path


def test_public_receiver_signature_reauthenticates_and_validates_schema():
    report = _load("authenticated-otel-projection.json")
    assert validate_authenticated_mandate_otel_projection(report) == report
    assert (
        load_authenticated_mandate_otel_projection(VECTOR / "authenticated-otel-projection.json")
        == report
    )
    assert report["summary"]["telemetry_source_authenticated"] is True
    assert report["summary"]["record_count"] == 67
    assert report["summary"]["transaction_count"] == 16
    assert report["summary"]["receiver_public_key_sha256"] == KEY_ID

    schema = json.loads(
        (ROOT / "spec" / "luremandate-authenticated-otel-projection-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(
        schema,
        registry=_registry(),
        format_checker=FormatChecker(),
    ).validate(report)


def test_reference_sign_and_authenticate_are_private_and_non_overwriting(tmp_path: Path):
    private_key, public_key = _keys(tmp_path)
    envelope_path = tmp_path / "export.dsse.json"
    envelope = sign_mandate_otel_export(
        VECTOR / "plan.json",
        VECTOR / "otel-log-export.json",
        private_key,
        envelope_path,
    )
    key_id = envelope["signatures"][0]["keyid"]
    report_path = tmp_path / "authenticated.json"
    report = create_authenticated_mandate_otel_projection(
        VECTOR / "otel-projection.json",
        envelope_path,
        public_key,
        report_path,
        expected_receiver_key_id=key_id,
        verified_at="2026-09-05T15:20:30Z",
    )
    assert report["summary"]["receiver_public_key_sha256"] == key_id
    assert load_authenticated_mandate_otel_projection(report_path) == report
    if os.name == "posix":
        assert envelope_path.stat().st_mode & 0o777 == 0o600
        assert report_path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        sign_mandate_otel_export(
            VECTOR / "plan.json",
            VECTOR / "otel-log-export.json",
            private_key,
            envelope_path,
        )
    with pytest.raises(FileExistsError):
        create_authenticated_mandate_otel_projection(
            VECTOR / "otel-projection.json",
            envelope_path,
            public_key,
            report_path,
            expected_receiver_key_id=key_id,
            verified_at="2026-09-05T15:20:30Z",
        )


def test_export_payload_signature_and_embedded_report_tampering_fail_closed(tmp_path: Path):
    report = _load("authenticated-otel-projection.json")

    changed_summary = copy.deepcopy(report)
    changed_summary["summary"]["record_count"] = 66
    with pytest.raises(ValueError, match="does not reproduce"):
        validate_authenticated_mandate_otel_projection(changed_summary)

    envelope = json.loads(
        base64.b64decode(report["export_envelope"]["envelope_base64"], validate=True)
    )
    export = json.loads(base64.b64decode(envelope["payload"], validate=True))
    export["export_id"] = "attacker-export"
    envelope["payload"] = base64.b64encode(_canonical(export)).decode("ascii")
    envelope_payload = _canonical(envelope)
    changed_payload = copy.deepcopy(report)
    changed_payload["export_envelope"]["envelope_base64"] = base64.b64encode(
        envelope_payload
    ).decode("ascii")
    changed_payload["export_envelope"]["envelope_sha256"] = hashlib.sha256(
        envelope_payload
    ).hexdigest()
    with pytest.raises(ValueError, match="differs from the projected canonical export"):
        validate_authenticated_mandate_otel_projection(changed_payload)

    tampered_signature = copy.deepcopy(report)
    envelope = json.loads(
        base64.b64decode(tampered_signature["export_envelope"]["envelope_base64"], validate=True)
    )
    signature = bytearray(base64.b64decode(envelope["signatures"][0]["sig"], validate=True))
    signature[-1] ^= 1
    envelope["signatures"][0]["sig"] = base64.b64encode(signature).decode("ascii")
    envelope_payload = _canonical(envelope)
    tampered_signature["export_envelope"]["envelope_base64"] = base64.b64encode(
        envelope_payload
    ).decode("ascii")
    tampered_signature["export_envelope"]["envelope_sha256"] = hashlib.sha256(
        envelope_payload
    ).hexdigest()
    with pytest.raises(ValueError, match="signature authentication failed"):
        validate_authenticated_mandate_otel_projection(tampered_signature)


def test_external_receiver_key_pin_rejects_substitution(tmp_path: Path):
    _, unrelated_public_key = _keys(tmp_path)
    with pytest.raises(ValueError, match="externally pinned key ID"):
        create_authenticated_mandate_otel_projection(
            VECTOR / "otel-projection.json",
            VECTOR / "otel-log-export.dsse.json",
            unrelated_public_key,
            tmp_path / "wrong-key-report.json",
            expected_receiver_key_id=KEY_ID,
            verified_at="2026-09-05T15:20:30Z",
        )


def test_cli_reauthenticates_and_repository_contains_no_private_receiver_key():
    assert (
        main(
            [
                "mandate",
                "check-otel-auth",
                str(VECTOR / "authenticated-otel-projection.json"),
            ]
        )
        == 0
    )
    for path in VECTOR.rglob("*.pem"):
        assert b"PRIVATE KEY" not in path.read_bytes()
    tree = ast.parse((ROOT / "lurescope" / "mandate_otel_auth.py").read_text(encoding="utf-8"))
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
