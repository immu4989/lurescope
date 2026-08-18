"""Locked synthetic Golden Pilot end-to-end and tamper-resistance tests."""

from __future__ import annotations

import hashlib
import json
import shutil
import socket
from datetime import datetime

import pytest

pytest.importorskip("sklearn")

from scripts import run_golden_pilot as golden


def test_golden_pilot_is_offline_private_schema_valid_and_passes(
    tmp_path, monkeypatch, capsys
):
    def network_forbidden(*args, **kwargs):
        raise AssertionError("golden pilot attempted a network connection")

    monkeypatch.setattr(socket, "socket", network_forbidden)
    output = tmp_path / "golden-pilot"

    assert golden.main(["--out", str(output)]) == 0
    stdout = capsys.readouterr().out
    assert "GOLDEN PILOT VERIFIED: PASS" in stdout
    receipt_path = output / "golden-pilot-receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    gate = json.loads((output / "pilot-gate.json").read_text(encoding="utf-8"))
    plan = json.loads((output / "pilot-plan.json").read_text(encoding="utf-8"))
    run = json.loads((output / "shadow-run.json").read_text(encoding="utf-8"))

    assert receipt["status"] == "verified"
    assert receipt["outcome"]["verdict"] == "pass"
    assert receipt["verification"] == {
        "fixture_integrity": True,
        "ingestion_shape": True,
        "ground_truth_applied": True,
        "schemas_valid": True,
        "privacy_scan_passed": True,
        "registered_gate_passed": True,
    }
    assert gate["verdict"] == "pass"
    assert all(item["status"] == "pass" for item in gate["checks"])
    assert len((output / "analyst-labels.jsonl").read_text().splitlines()) == 5
    assert receipt["bindings"]["gate_sha256"] == hashlib.sha256(
        (output / "pilot-gate.json").read_bytes()
    ).hexdigest()
    assert "case-" not in json.dumps(receipt)
    assert "example.invalid" not in json.dumps(receipt)
    assert datetime.fromisoformat(plan["created_at"]) <= datetime.fromisoformat(
        run["generated_at"]
    )

    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (golden.ROOT / "spec/golden-pilot-receipt-v1.schema.json").read_text()
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    )
    validator.validate(receipt)
    receipt_with_free_text = {**receipt, "unexpected": "free text"}
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(receipt_with_free_text)

    original_receipt = receipt_path.read_bytes()
    assert golden.main(["--out", str(output)]) == 2
    assert "output already exists" in capsys.readouterr().err
    assert receipt_path.read_bytes() == original_receipt


def test_golden_pilot_rejects_fixture_tampering_before_creating_output(tmp_path):
    fixture_copy = tmp_path / "fixtures"
    shutil.copytree(golden.DEFAULT_FIXTURE_DIR, fixture_copy)
    target = fixture_copy / "05-benign-agenda.eml"
    target.write_bytes(target.read_bytes() + b"\nchanged after review\n")
    output = tmp_path / "must-not-exist"

    with pytest.raises(ValueError, match="fixture digest changed"):
        golden.run_golden_pilot(output, fixture_dir=fixture_copy)
    assert not output.exists()
