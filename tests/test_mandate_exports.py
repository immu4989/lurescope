from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import jsonschema
import pytest

from lurescope.cli import main
from lurescope.mandate_export import (
    _sarif_document,
    export_mandate_oscal,
    export_mandate_sarif,
)
from lurescope.permit import _canonical, _sha256

ROOT = Path(__file__).parents[1]
VECTOR = ROOT / "conformance" / "luremandate-v1"
POLICY = {
    "minimum_run_started_at": "2026-09-05T15:00:00Z",
    "expected_engine_id": "luremandate-reference",
    "expected_engine_version": "1.0.0",
    "expected_engine_artifact_sha256": "a" * 64,
    "expected_receiver_instance_id": "authority-gateway-instance-1",
    "expected_receiver_key_id": (
        "23b870f8eb429486d3ebab388918350ca0a9b8d5b735c18de5d2ed4ebd6c7211"
    ),
}


def _sources(output: Path) -> tuple[Path, ...]:
    return (
        VECTOR / "deployment-gate.json",
        VECTOR / "verification.json",
        VECTOR / "authenticated-verification.json",
        VECTOR / "otel-projection.json",
        VECTOR / "authenticated-otel-projection.json",
        VECTOR / "approver-key-policy.json",
        output,
    )


def _official_oscal_validator():
    schema = json.loads(
        (ROOT / "tests/vendor/oscal-1.2.2/oscal_assessment-results_schema.json").read_text(
            encoding="utf-8"
        )
    )
    default_pattern = jsonschema.Draft7Validator.VALIDATORS["pattern"]

    def unicode_pattern(validator, pattern, instance, current_schema):
        translated = pattern.replace(r"\p{L}", r"[^\W\d_]").replace(r"\p{N}", r"\d")
        yield from default_pattern(validator, translated, instance, current_schema)

    validator_type = jsonschema.validators.extend(
        jsonschema.Draft7Validator, {"pattern": unicode_pattern}
    )
    return validator_type(schema, format_checker=jsonschema.FormatChecker())


def _official_sarif_validator():
    schema = json.loads(
        (ROOT / "tests/vendor/sarif-2.1.0/sarif-schema-2.1.0.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft4Validator.check_schema(schema)
    return jsonschema.Draft4Validator(schema, format_checker=jsonschema.FormatChecker())


def _assert_no_locations(value) -> None:
    if isinstance(value, dict):
        assert "locations" not in value
        assert "artifacts" not in value
        for child in value.values():
            _assert_no_locations(child)
    elif isinstance(value, list):
        for child in value:
            _assert_no_locations(child)


def test_public_gate_exports_validate_without_transaction_content(tmp_path: Path):
    oscal_path = tmp_path / "luremandate.oscal.json"
    oscal = export_mandate_oscal(
        *_sources(oscal_path),
        assessment_plan_href="urn:example:assessment-plan:luremandate",
        generated_at="2026-09-05T15:22:00Z",
        **POLICY,
    )
    assert oscal == json.loads(
        (VECTOR / "oscal-assessment-results.json").read_text(encoding="utf-8")
    )
    _official_oscal_validator().validate(oscal)
    result = oscal["assessment-results"]["results"][0]
    assert "findings" not in result
    assert "risks" not in result
    assert len(result["observations"]) == 10
    assert {item["props"][1]["value"] for item in result["observations"]} == {"pass"}

    sarif_path = tmp_path / "luremandate.sarif.json"
    sarif = export_mandate_sarif(*_sources(sarif_path), **POLICY)
    assert sarif == json.loads((VECTOR / "mandate-gate.sarif.json").read_text(encoding="utf-8"))
    _official_sarif_validator().validate(sarif)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is True
    assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 10
    _assert_no_locations(sarif)

    serialized = oscal_path.read_text(encoding="utf-8") + sarif_path.read_text(encoding="utf-8")
    for prohibited in (
        "transaction_id",
        "approval_id",
        "requester_id",
        "parameters_sha256",
        "decision_reason",
        "event.body",
    ):
        assert prohibited not in serialized
    if os.name == "posix":
        assert oscal_path.stat().st_mode & 0o777 == 0o600
        assert sarif_path.stat().st_mode & 0o777 == 0o600


def test_sarif_failure_results_are_stable_and_location_free():
    gate = json.loads((VECTOR / "deployment-gate.json").read_text(encoding="utf-8"))
    failed = copy.deepcopy(gate)
    failed["checks"][-1]["status"] = "fail"
    failed["overall_status"] = "fail"
    document = _sarif_document(failed, {"gate_sha256": _sha256(_canonical(failed))})
    _official_sarif_validator().validate(document)
    result = document["runs"][0]["results"][0]
    assert result["ruleId"] == "LURE-MANDATE-010"
    assert result["level"] == "error"
    assert "locations" not in result
    assert document["runs"][0]["invocations"][0]["executionSuccessful"] is True


def test_exports_fail_closed_before_writing(tmp_path: Path):
    bad_href = tmp_path / "bad-href.json"
    with pytest.raises(ValueError, match="operator-controlled"):
        export_mandate_oscal(
            *_sources(bad_href),
            assessment_plan_href="file:///private/assessment-plan.json",
            generated_at="2026-09-05T15:22:00Z",
            **POLICY,
        )
    assert not bad_href.exists()

    old_export = tmp_path / "old.json"
    with pytest.raises(ValueError, match="cannot predate"):
        export_mandate_oscal(
            *_sources(old_export),
            assessment_plan_href="urn:example:assessment-plan:luremandate",
            generated_at="2026-09-05T15:20:59Z",
            **POLICY,
        )
    assert not old_export.exists()

    tampered = json.loads((VECTOR / "deployment-gate.json").read_text(encoding="utf-8"))
    tampered["contract"]["run_sha256"] = "0" * 64
    tampered_path = tmp_path / "tampered-gate.json"
    tampered_path.write_bytes(_canonical(tampered))
    tampered_path.chmod(0o600)
    blocked = tmp_path / "blocked.sarif.json"
    source_paths = list(_sources(blocked))
    source_paths[0] = tampered_path
    with pytest.raises(ValueError, match="does not independently reproduce"):
        export_mandate_sarif(*source_paths, **POLICY)
    assert not blocked.exists()


def test_exports_refuse_overwrite_and_cli_reverifies(tmp_path: Path, capsys):
    oscal_path = tmp_path / "cli.oscal.json"
    common = [str(item) for item in _sources(oscal_path)[:-1]] + [
        "--minimum-run-started-at",
        POLICY["minimum_run_started_at"],
        "--expected-engine-id",
        POLICY["expected_engine_id"],
        "--expected-engine-version",
        POLICY["expected_engine_version"],
        "--expected-engine-artifact-sha256",
        POLICY["expected_engine_artifact_sha256"],
        "--expected-receiver-instance-id",
        POLICY["expected_receiver_instance_id"],
        "--expected-receiver-key-id",
        POLICY["expected_receiver_key_id"],
    ]
    assert (
        main(
            [
                "mandate",
                "export-oscal",
                *common,
                "--assessment-plan-href",
                "urn:example:assessment-plan:luremandate",
                "--generated-at",
                "2026-09-05T15:22:00Z",
                "--out",
                str(oscal_path),
            ]
        )
        == 0
    )
    assert "LUREMANDATE OSCAL 1.2.2 EXPORTED: PASS" in capsys.readouterr().out
    with pytest.raises(FileExistsError):
        export_mandate_oscal(
            *_sources(oscal_path),
            assessment_plan_href="urn:example:assessment-plan:luremandate",
            generated_at="2026-09-05T15:22:00Z",
            **POLICY,
        )
