"""One-command operational pilot packaging, evidence, and tamper tests."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import socket
from datetime import datetime
from pathlib import Path

import jsonschema
import pytest

pytest.importorskip("sklearn")

from lurescope.cli import main
from lurescope.operational_pilot import (
    DEFAULT_FIXTURE_DIR,
    run_operational_pilot,
    verify_operational_pilot,
)

ROOT = Path(__file__).parents[1]


def _property(document: dict, name: str) -> str:
    properties = document["assessment-results"]["metadata"]["props"]
    matches = [item["value"] for item in properties if item["name"] == name]
    assert len(matches) == 1
    return matches[0]


def test_packaged_fixtures_are_byte_identical_to_reviewed_source_examples():
    source = ROOT / "examples" / "shadow-pilot" / "eml"
    assert {item.name for item in source.iterdir()} == {
        item.name for item in DEFAULT_FIXTURE_DIR.glob("*.eml")
    }
    for path in source.iterdir():
        assert path.read_bytes() == (DEFAULT_FIXTURE_DIR / path.name).read_bytes()


def test_one_command_pilot_is_offline_private_cross_bound_and_schema_valid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    def network_forbidden(*args, **kwargs):
        raise AssertionError("operational pilot attempted a network connection")

    monkeypatch.setattr(socket, "socket", network_forbidden)
    output = tmp_path / "operational-pilot"
    assert main(["pilot", "run", "--out", str(output)]) == 0
    assert "OPERATIONAL PILOT CREATED: PASS" in capsys.readouterr().out
    receipt_path = output / "operational-pilot-receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))

    schema = json.loads(
        (ROOT / "spec" / "operational-pilot-receipt-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    ).validate(receipt)
    assert receipt["status"] == "verified"
    assert receipt["workflow"]["pilot_gate_verdict"] == "pass"
    assert len(receipt["artifacts"]) == 17
    assert "case-" not in json.dumps(receipt)
    assert "example.invalid" not in json.dumps(receipt)
    assert os.stat(output).st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in output.iterdir())
    assert all(b"PRIVATE KEY" not in path.read_bytes() for path in output.iterdir())

    plan = json.loads((output / "pilot-plan.json").read_text(encoding="utf-8"))
    run = json.loads((output / "shadow-run.json").read_text(encoding="utf-8"))
    gate = json.loads((output / "pilot-gate.json").read_text(encoding="utf-8"))
    assert datetime.fromisoformat(plan["created_at"]) <= datetime.fromisoformat(
        run["generated_at"]
    )
    assert datetime.fromisoformat(run["generated_at"]) <= datetime.fromisoformat(
        gate["generated_at"]
    )

    gate_digest = hashlib.sha256((output / "pilot-gate.json").read_bytes()).hexdigest()
    envelope = json.loads((output / "lureeval.dsse.json").read_text(encoding="utf-8"))
    statement = json.loads(base64.b64decode(envelope["payload"], validate=True))
    assert statement["predicate"]["cohort"]["gate_sha256"] == gate_digest
    oscal = json.loads(
        (output / "oscal-assessment-results.json").read_text(encoding="utf-8")
    )
    assert _property(oscal, "pilot-gate-sha256") == gate_digest
    assert "findings" not in oscal["assessment-results"]["results"][0]
    assert {
        "siem-ocsf-1.8.json",
        "siem-sentinel.json",
        "siem-splunk-hec.jsonl",
    } <= {path.name for path in output.iterdir()}

    assert main(["pilot", "verify", str(output)]) == 0
    assert "OPERATIONAL PILOT VERIFIED: PASS" in capsys.readouterr().out
    original = receipt_path.read_bytes()
    assert main(["pilot", "run", "--out", str(output)]) == 2
    assert "already exists" in capsys.readouterr().err
    assert receipt_path.read_bytes() == original


def test_operational_pilot_detects_export_tampering_without_rewriting(tmp_path: Path):
    output = tmp_path / "operational-pilot"
    run_operational_pilot(output)
    target = output / "siem-sentinel.json"
    original = target.read_bytes()
    target.write_bytes(original + b"\n")

    with pytest.raises(ValueError, match="artifact binding failed"):
        verify_operational_pilot(output)
    assert target.read_bytes() == original + b"\n"


def test_operational_pilot_refuses_fixture_tampering_before_output(tmp_path: Path):
    fixture_copy = tmp_path / "fixtures"
    shutil.copytree(DEFAULT_FIXTURE_DIR, fixture_copy)
    target = fixture_copy / "05-benign-agenda.eml"
    target.write_bytes(target.read_bytes() + b"\nchanged\n")
    output = tmp_path / "must-not-exist"

    with pytest.raises(ValueError, match="fixture digest changed"):
        run_operational_pilot(output, fixture_dir=fixture_copy)
    assert not output.exists()
