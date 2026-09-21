from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from lurescope.cli import main
from lurescope.mandate import _sha256
from lurescope.mandate_conformance import _score_value
from lurescope.mandate_sequence import (
    create_sequence_mandate_verification,
    validate_sequence_mandate_assurance,
    validate_sequence_mandate_verification,
)
from lurescope.permit import _canonical

ROOT = Path(__file__).parents[1]
VECTOR = ROOT / "conformance/luremandate-sequence-v1"


def load(name):
    return json.loads((VECTOR / name).read_text())


def test_public_sequence_reproduces_and_satisfies_schema():
    report = load("sequence-assurance.json")
    verification = load("sequence-verification.json")
    assert validate_sequence_mandate_assurance(report) == report
    assert validate_sequence_mandate_verification(verification) == verification
    assert verification["summary"]["passed_measured_case_count"] == 26
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        schema = json.loads(path.read_text())
        if "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema)))
    registry = Registry().with_resources(resources)
    for suffix, value in (("assurance", report), ("verification", verification)):
        schema = json.loads(
            (ROOT / "spec" / f"luremandate-sequence-{suffix}-v1.schema.json").read_text()
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, registry=registry, format_checker=FormatChecker()).validate(
            value
        )


@pytest.mark.parametrize("field", ["summary", "ordered_pair_coverage", "operation_results"])
def test_forged_sequence_claims_rejected(field):
    report = load("sequence-assurance.json")
    if field == "summary":
        report[field]["passed_measured_case_count"] = 25
    elif field == "ordered_pair_coverage":
        report[field]["covered_pairs"].pop()
    else:
        report[field][0]["operation"] = "replay-block"
    with pytest.raises(ValueError, match="independently reproduce"):
        validate_sequence_mandate_assurance(report)


def test_cli_roundtrip_and_output_protection(tmp_path, capsys):
    output = tmp_path / "verified.json"
    assert (
        main(
            [
                "mandate",
                "verify-sequence",
                str(VECTOR / "sequence-assurance.json"),
                "--verified-at",
                "2026-09-05T16:13:00Z",
                "--out",
                str(output),
            ]
        )
        == 0
    )
    assert json.loads(output.read_text()) == load("sequence-verification.json")
    assert output.stat().st_mode & 0o777 == 0o600
    assert main(["mandate", "check-sequence", str(output)]) == 0
    assert "SEQUENCE INDEPENDENTLY VERIFIED: PASS" in capsys.readouterr().out
    with pytest.raises(FileExistsError):
        create_sequence_mandate_verification(
            VECTOR / "sequence-assurance.json", output, verified_at="2026-09-05T16:13:00Z"
        )
    altered = copy.deepcopy(load("sequence-verification.json"))
    altered["summary"]["verdict"] = "fail"
    with pytest.raises(ValueError, match="independently reproduce"):
        validate_sequence_mandate_verification(altered)


def test_verification_cannot_predate_report(tmp_path):
    with pytest.raises(ValueError, match="predates"):
        create_sequence_mandate_verification(
            VECTOR / "sequence-assurance.json",
            tmp_path / "bad.json",
            verified_at="2026-09-05T16:11:00Z",
        )
    assert not (tmp_path / "bad.json").exists()


@pytest.mark.parametrize(
    "operation,impact",
    [
        ("sequence-budget-boundary-allow", 49),
        ("sequence-expired-window-allow", 40),
    ],
)
def test_valid_scores_with_false_state_labels_are_rejected(operation, impact):
    report = load("sequence-assurance.json")
    score = report["score"]
    challenge = score["challenge"]
    transaction = next(
        case["transaction"]
        for case in challenge["cases"]
        if case["transaction"]["intent"]["action"] == operation
    )
    transaction["intent"]["impact_units"] = impact
    transaction["intent_sha256"] = _sha256(_canonical(transaction["intent"]))
    for approval in transaction["approvals"]:
        approval["intent_sha256"] = transaction["intent_sha256"]
    score["submission"]["challenge_sha256"] = _sha256(_canonical(challenge))
    rescored = _score_value(challenge, score["submission"], evaluated_at=score["evaluated_at"])
    assert rescored["summary"]["verdict"] == "pass"
    report["score"] = rescored
    report["score_sha256"] = _sha256(_canonical(rescored))
    with pytest.raises(ValueError, match="operation"):
        validate_sequence_mandate_assurance(report)
