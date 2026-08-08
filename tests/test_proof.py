"""LureProof privacy, integrity, reproducibility, and CLI tests."""

from __future__ import annotations

import json

import pytest

pytest.importorskip("sklearn")

from lurescope.cli import main
from lurescope.proof import create_email_proof, verify_proof

RAW = (
    b"From: Payroll <payroll@example.org>\n"
    b"Reply-To: collect@other.example\n"
    b"To: employee@example.org\n"
    b"Message-ID: <secret-123@example.org>\n"
    b"Subject: Urgent payroll verification\n\n"
    b"Verify your account at http://192.0.2.10/payroll within 24 hours.\n"
)


def test_proof_is_minimized_and_verifiable():
    proof = create_email_proof(RAW, created_at="2026-08-08T12:00:00Z")
    serialized = json.dumps(proof)
    assert verify_proof(proof)["valid"] is True
    for secret in (
        "Urgent payroll verification", "payroll@example.org", "employee@example.org",
        "192.0.2.10", "secret-123", "Verify your account",
    ):
        assert secret not in serialized
    assert proof["privacy_profile"] == "shareable-minimized"
    assert len(proof["resilience"]["outcomes"]) == 4
    assert all("attacked" not in item for item in proof["resilience"]["outcomes"])


def test_proof_is_reproducible_with_fixed_timestamp():
    first = create_email_proof(RAW, created_at="2026-08-08T12:00:00Z")
    second = create_email_proof(RAW, created_at="2026-08-08T12:00:00Z")
    assert first == second


def test_tampering_is_detected():
    proof = create_email_proof(RAW, created_at="2026-08-08T12:00:00Z")
    proof["assessment"]["fraud_probability"] = 0.0
    result = verify_proof(proof)
    assert result["valid"] is False
    assert "digest mismatch" in result["errors"]


def test_cli_create_and_verify(tmp_path, capsys):
    source = tmp_path / "message.eml"
    output = tmp_path / "message.lureproof.json"
    source.write_bytes(RAW)
    assert main(["proof", str(source), "--out", str(output)]) == 0
    assert output.exists()
    capsys.readouterr()
    assert main(["verify", str(output)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["valid"] is True
