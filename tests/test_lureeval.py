"""Cross-repository LureEval receipt production and authentication tests."""

from __future__ import annotations

import importlib.resources
import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

pytest.importorskip("sklearn")

from lurebench.receipts import validate_receipt_statement

from lurescope.cli import main
from lurescope.lureeval import create_lureeval_receipt, verify_lureeval_receipt
from scripts.run_golden_pilot import run_golden_pilot


def _golden_bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / "golden-pilot"
    receipt = run_golden_pilot(bundle)
    assert receipt["outcome"]["verdict"] == "pass"
    return bundle


def _receipt_schema() -> dict:
    resource = importlib.resources.files("lurebench") / "spec/lureeval-receipt-v1.schema.json"
    if resource.is_file():
        return json.loads(resource.read_text(encoding="utf-8"))
    source_checkout = Path(__file__).parents[2] / "lurebench/spec/lureeval-receipt-v1.schema.json"
    return json.loads(source_checkout.read_text(encoding="utf-8"))


def test_create_receipt_from_current_pilot_gate_is_private_and_schema_valid(tmp_path):
    bundle = _golden_bundle(tmp_path)
    output = tmp_path / "site-receipt.json"

    artifact = create_lureeval_receipt(
        bundle,
        output,
        sampling="complete_population",
        minimum_slice_count=10,
        issuer="Synthetic Golden Pilot",
    )

    validate_receipt_statement(artifact)
    Draft202012Validator(_receipt_schema(), format_checker=FormatChecker()).validate(artifact)
    predicate = artifact["predicate"]
    assert predicate["producer"]["name"] == "lurescope"
    assert predicate["cohort"]["source_type"] == "shadow_inbox"
    assert predicate["cohort"]["processed_count"] == 5
    assert predicate["cohort"]["evaluated_count"] == 5
    assert predicate["outcome"]["pilot_gate"]["verdict"] == "pass"
    assert predicate["privacy"]["suppressed_slice_count"] == 4
    assert predicate["slices"] == []
    assert os.stat(output).st_mode & 0o777 == 0o600

    serialized = output.read_text(encoding="utf-8")
    for forbidden in (
        "case-",
        "example.invalid",
        "Benefits enrollment",
        "bank account",
        str(bundle),
    ):
        assert forbidden not in serialized
    with pytest.raises(FileExistsError):
        create_lureeval_receipt(bundle, output, minimum_slice_count=10)


def test_signed_receipt_authenticates_and_tampering_fails(tmp_path):
    cryptography = pytest.importorskip("cryptography")
    assert cryptography
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    private = ec.generate_private_key(ec.SECP256R1())
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    bundle = _golden_bundle(tmp_path)
    output = tmp_path / "site-receipt.dsse.json"
    create_lureeval_receipt(
        bundle,
        output,
        minimum_slice_count=10,
        signing_key_pem=private_pem,
    )

    verified = verify_lureeval_receipt(output, public_key_pem=public_pem, require_signature=True)
    assert verified["valid"] is True
    assert verified["signed"] is True
    assert verified["authenticated"] is True
    assert len(verified["key_ids"]) == 1

    envelope = json.loads(output.read_text())
    envelope["signatures"][0]["sig"] = "AAAA"
    output.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(ValueError, match="no DSSE signature"):
        verify_lureeval_receipt(output, public_key_pem=public_pem, require_signature=True)


def test_cli_creates_and_verifies_unsigned_receipt(tmp_path, capsys):
    bundle = _golden_bundle(tmp_path)
    output = tmp_path / "site-receipt.json"

    assert (
        main(
            [
                "lureeval",
                "create",
                str(bundle),
                "--out",
                str(output),
                "--sampling",
                "consecutive_sample",
                "--minimum-slice-count",
                "10",
            ]
        )
        == 0
    )
    assert "unsigned statement" in capsys.readouterr().out
    assert main(["lureeval", "verify", str(output)]) == 0
    verification = json.loads(capsys.readouterr().out)
    assert verification["valid"] is True
    assert verification["signed"] is False
