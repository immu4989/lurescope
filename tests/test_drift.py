"""SCuBA Assurance Drift compatibility, chain, signature, OSCAL, and CLI tests."""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import jsonschema
import pytest

from lurescope.assurance import create_assurance_plan
from lurescope.cli import main
from lurescope.drift import (
    AFTER_EVIDENCE_FILE,
    BEFORE_EVIDENCE_FILE,
    DRIFT_DSSE_FILE,
    DRIFT_FILE,
    DRIFT_HTML_FILE,
    DRIFT_MARKDOWN_FILE,
    DRIFT_OSCAL_FILE,
    DRIFT_STATEMENT_FILE,
    create_scuba_drift_package,
    verify_scuba_drift_package,
)
from lurescope.integrations import load_inbox_manifest
from lurescope.proof import generate_keypair
from lurescope.scuba import create_scuba_assurance_bundle
from lurescope.shadow import append_analyst_label, run_shadow_inbox

ROOT = Path(__file__).parents[1]
EMAIL_FIXTURES = ROOT / "examples" / "shadow-pilot" / "eml"
SCUBA_FIXTURE = ROOT / "examples" / "scuba-bridge" / "ScubaResults_synthetic.json"
VENDORED = ROOT / "tests" / "vendor" / "oscal-1.2.2"
SSP_URN = "urn:uuid:11111111-1111-4111-8111-111111111111"
RESULT_CATEGORY = {
    "Pass": "Passes",
    "Fail": "Failures",
    "Warning": "Warnings",
    "N/A": "Manual",
    "Omitted": "Omits",
    "Incorrect result": "IncorrectResults",
    "Error - Test results missing": "Errors",
    "Error": "Errors",
}


def _official_validator(name: str):
    schema = json.loads((VENDORED / name).read_text(encoding="utf-8"))
    default_pattern = jsonschema.Draft7Validator.VALIDATORS["pattern"]

    def unicode_pattern(validator, pattern, instance, current_schema):
        translated = pattern.replace(r"\p{L}", r"[^\W\d_]").replace(r"\p{N}", r"\d")
        yield from default_pattern(validator, translated, instance, current_schema)

    validator_type = jsonschema.validators.extend(
        jsonschema.Draft7Validator, {"pattern": unicode_pattern}
    )
    return validator_type(schema, format_checker=jsonschema.FormatChecker())


def _validate_public_schema(instance: dict, name: str) -> None:
    schema = json.loads((ROOT / "spec" / name).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(
        instance
    )


def _reviewed_pilot(tmp_path: Path) -> tuple[Path, Path]:
    plan = tmp_path / "plan"
    create_assurance_plan(
        plan,
        ssp_href=SSP_URN,
        plan_id="drift-synthetic-pilot",
        min_processed_count=5,
        min_fraud_labels=4,
        min_benign_labels=1,
        max_uncertain_rate=0,
        max_processing_failure_rate=0,
        min_routing_recall_lower_bound=0.45,
        max_routing_false_positive_rate_upper_bound=0.96,
        max_routed_rate=0.8,
        max_routed_count=4,
        threshold=0.5,
    )
    bundle = tmp_path / "shadow-bundle"
    run_shadow_inbox([EMAIL_FIXTURES], bundle, threshold=0.5)
    processed = [
        item
        for item in load_inbox_manifest(bundle / "manifest.jsonl")
        if item["status"] == "processed"
    ]
    for item in processed:
        fraud = item["input_index"] <= 4
        append_analyst_label(
            bundle,
            item["case_id"],
            "fraud" if fraud else "benign",
            "confirmed_external" if fraud else "known_legitimate",
        )
    return plan, bundle


def _source() -> dict:
    return json.loads(SCUBA_FIXTURE.read_text(encoding="utf-8"))


def _control(source: dict, control_id: str) -> tuple[str, dict]:
    for product, groups in source["Results"].items():
        for group in groups:
            for control in group["Controls"]:
                if control["Control ID"] == control_id:
                    return product, control
    raise AssertionError(control_id)


def _change_result(source: dict, control_id: str, result: str) -> None:
    product, control = _control(source, control_id)
    old = control["Result"]
    source["Summary"][product][RESULT_CATEGORY[old]] -= 1
    source["Summary"][product][RESULT_CATEGORY[result]] += 1
    control["Result"] = result


def _write_source(tmp_path: Path, name: str, source: dict) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(source), encoding="utf-8")
    return path


def _after_source(timestamp: str) -> dict:
    source = _source()
    source["MetaData"]["TimestampZulu"] = timestamp
    source["MetaData"]["ReportUUID"] = "44444444-4444-4444-8444-444444444444"
    _change_result(source, "MS.AAD.1.1v1", "Fail")
    _change_result(source, "MS.AAD.2.1v1", "Pass")
    _change_result(source, "MS.DEFENDER.1.1v1", "Fail")
    _, exo = _control(source, "MS.EXO.1.1v2")
    exo["Criticality"] = "Should"
    return source


def test_drift_package_is_private_reconciled_signed_and_chainable(tmp_path, monkeypatch, capsys):
    def network_forbidden(*args, **kwargs):
        raise AssertionError("drift processing attempted a network connection")

    monkeypatch.setattr(socket, "socket", network_forbidden)
    plan, pilot = _reviewed_pilot(tmp_path)
    ledger_private_key = tmp_path / "ledger-private.pem"
    ledger_public_key = tmp_path / "ledger-public.pem"
    ledger_key_id = generate_keypair(ledger_private_key, ledger_public_key)
    before_private_key = tmp_path / "before-source-private.pem"
    before_public_key = tmp_path / "before-source-public.pem"
    generate_keypair(before_private_key, before_public_key)
    after_private_key = tmp_path / "after-source-private.pem"
    after_public_key = tmp_path / "after-source-public.pem"
    generate_keypair(after_private_key, after_public_key)

    before_source = _source()
    before_source["MetaData"]["TimestampZulu"] = "2026-08-17T12:00:00Z"
    before_source["MetaData"]["ReportUUID"] = "33333333-3333-4333-8333-333333333334"
    before_report = _write_source(tmp_path, "ScubaResults_before.json", before_source)
    after_source = _after_source("2026-08-18T12:00:00Z")
    after_report = _write_source(tmp_path, "ScubaResults_after.json", after_source)
    third_source = json.loads(json.dumps(after_source))
    third_source["MetaData"]["TimestampZulu"] = "2026-08-18T18:00:00Z"
    third_source["MetaData"]["ReportUUID"] = "55555555-5555-4555-8555-555555555555"
    _change_result(third_source, "MS.AAD.1.1v1", "Pass")
    for group in third_source["Results"]["EXO"]:
        for index, control in enumerate(group["Controls"]):
            if control["Control ID"] == "MS.EXO.1.1v2":
                replacement = json.loads(json.dumps(control))
                replacement["Control ID"] = "MS.EXO.9.9v1"
                group["Controls"][index] = replacement
                break
    third_report = _write_source(tmp_path, "ScubaResults_third.json", third_source)

    before_bundle = tmp_path / "before-combined"
    after_bundle = tmp_path / "after-combined"
    third_bundle = tmp_path / "third-combined"
    create_scuba_assurance_bundle(
        before_report, pilot, plan, before_bundle, signing_key=before_private_key
    )
    create_scuba_assurance_bundle(
        after_report, pilot, plan, after_bundle, signing_key=after_private_key
    )
    create_scuba_assurance_bundle(
        third_report, pilot, plan, third_bundle, signing_key=after_private_key
    )

    output = tmp_path / "drift-1"
    result = create_scuba_drift_package(
        before_bundle,
        after_bundle,
        output,
        signing_key=ledger_private_key,
        before_source_public_key=before_public_key,
        after_source_public_key=after_public_key,
        require_source_signatures=True,
    )
    drift = result["drift"]
    assert drift["summary"]["changed_control_count"] == 4
    assert drift["summary"]["transitions"] == {
        "added": 0,
        "improved": 1,
        "newly_failing": 1,
        "non_comparable": 1,
        "regressed": 1,
        "removed": 0,
        "unchanged": 1,
    }
    assert drift["summary"]["candidate_lifecycle"] == {
        "new_candidate": 1,
        "no_longer_observed": 1,
        "not_candidate": 2,
        "persistent_candidate": 1,
    }
    assert drift["previous_ledger"] is None
    assert set(item.name for item in output.iterdir()) == {
        BEFORE_EVIDENCE_FILE,
        AFTER_EVIDENCE_FILE,
        DRIFT_FILE,
        DRIFT_MARKDOWN_FILE,
        DRIFT_HTML_FILE,
        DRIFT_OSCAL_FILE,
        DRIFT_STATEMENT_FILE,
        DRIFT_DSSE_FILE,
    }
    if os.name == "posix":
        assert output.stat().st_mode & 0o777 == 0o700
        assert all(item.stat().st_mode & 0o777 == 0o600 for item in output.iterdir())

    _validate_public_schema(drift, "scuba-assurance-drift-v1.schema.json")
    _validate_public_schema(result["statement"], "scuba-assurance-drift-statement-v1.schema.json")
    envelope = json.loads((output / DRIFT_DSSE_FILE).read_text(encoding="utf-8"))
    _validate_public_schema(envelope, "scuba-assurance-drift-dsse-v1.schema.json")
    _official_validator("oscal_assessment-results_schema.json").validate(result["oscal"])
    assert all("findings" not in item for item in result["oscal"]["assessment-results"]["results"])

    serialized = "".join(item.read_text(encoding="utf-8") for item in output.iterdir()).lower()
    for forbidden in (
        "synthetic-tenant.example.invalid",
        "22222222-2222-4222-8222-222222222222",
        "raw-provider-setting-that-must-never-be-exported",
        "sensitive synthetic failure context",
    ):
        assert forbidden not in serialized

    verification = verify_scuba_drift_package(
        output,
        public_key=ledger_public_key,
        require_signature=True,
        before_bundle=before_bundle,
        after_bundle=after_bundle,
        before_source_public_key=before_public_key,
        after_source_public_key=after_public_key,
        require_source_signatures=True,
    )
    assert verification["authenticated"] is True
    assert verification["key_ids"] == [ledger_key_id]
    assert verification["source_bundles_reverified"] is True
    assert verification["source_bundles_authenticated"] is True

    output_2 = tmp_path / "drift-2"
    second_result = create_scuba_drift_package(
        after_bundle,
        third_bundle,
        output_2,
        signing_key=ledger_private_key,
        previous_drift=output,
    )
    assert second_result["drift"]["summary"]["transitions"]["added"] == 1
    assert second_result["drift"]["summary"]["transitions"]["removed"] == 1
    chained = verify_scuba_drift_package(
        output_2,
        public_key=ledger_public_key,
        require_signature=True,
        previous_drift=output,
        previous_public_key=ledger_public_key,
        require_chain=True,
    )
    assert chained["chain_bound"] is True
    assert chained["chain_verified"] is True
    with pytest.raises(ValueError, match="requires --previous-drift"):
        verify_scuba_drift_package(output_2, require_chain=True)

    cli_output = tmp_path / "cli-drift"
    assert (
        main(
            [
                "assurance",
                "drift",
                str(before_bundle),
                str(after_bundle),
                "--out",
                str(cli_output),
            ]
        )
        == 0
    )
    assert "SCuBA Assurance Drift: 4 of 5 controls changed" in capsys.readouterr().out
    assert (
        main(
            [
                "assurance",
                "verify-drift",
                str(cli_output),
                "--before",
                str(before_bundle),
                "--after",
                str(after_bundle),
            ]
        )
        == 0
    )
    cli_verification = json.loads(capsys.readouterr().out)
    assert cli_verification["valid"] is True
    assert cli_verification["source_bundles_reverified"] is True


def test_drift_rejects_incompatible_release_reverse_time_and_tampering(tmp_path):
    plan, pilot = _reviewed_pilot(tmp_path)
    before_bundle = tmp_path / "before"
    after_bundle = tmp_path / "after"
    before_source = _source()
    before_source["MetaData"]["TimestampZulu"] = "2026-08-17T12:00:00Z"
    before_source["MetaData"]["ReportUUID"] = "33333333-3333-4333-8333-333333333334"
    before_report = _write_source(tmp_path, "before.json", before_source)
    after_report = _write_source(tmp_path, "after.json", _after_source("2026-08-18T12:00:00Z"))
    create_scuba_assurance_bundle(before_report, pilot, plan, before_bundle)
    create_scuba_assurance_bundle(after_report, pilot, plan, after_bundle)

    with pytest.raises(ValueError, match="timestamp must be later"):
        create_scuba_drift_package(after_bundle, before_bundle, tmp_path / "reverse")

    future = _after_source("2099-01-01T00:00:00Z")
    future["MetaData"]["ReportUUID"] = "66666666-6666-4666-8666-666666666666"
    future_report = _write_source(tmp_path, "future.json", future)
    future_bundle = tmp_path / "future"
    create_scuba_assurance_bundle(future_report, pilot, plan, future_bundle)
    with pytest.raises(ValueError, match="generation time cannot precede"):
        create_scuba_drift_package(before_bundle, future_bundle, tmp_path / "future-drift")

    incompatible = _after_source("2026-08-18T18:00:00Z")
    incompatible["MetaData"]["ToolVersion"] = "1.8.1"
    for groups in incompatible["Results"].values():
        for group in groups:
            group["GroupReferenceURL"] = group["GroupReferenceURL"].replace("/v1.8.0/", "/v1.8.1/")
    incompatible_report = _write_source(tmp_path, "incompatible.json", incompatible)
    incompatible_bundle = tmp_path / "incompatible"
    create_scuba_assurance_bundle(incompatible_report, pilot, plan, incompatible_bundle)
    with pytest.raises(ValueError, match="same ScubaGear version"):
        create_scuba_drift_package(
            before_bundle, incompatible_bundle, tmp_path / "release-mismatch"
        )

    output = tmp_path / "valid-drift"
    create_scuba_drift_package(before_bundle, after_bundle, output)
    drift_path = output / DRIFT_FILE
    tampered = json.loads(drift_path.read_text(encoding="utf-8"))
    tampered["transitions"][0]["transition"] = "unchanged"
    drift_path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(ValueError, match="canonical JSON|digest mismatch"):
        verify_scuba_drift_package(output)


def test_drift_schema_files_are_valid():
    for name in (
        "scuba-assurance-drift-v1.schema.json",
        "scuba-assurance-drift-statement-v1.schema.json",
        "scuba-assurance-drift-dsse-v1.schema.json",
    ):
        schema = json.loads((ROOT / "spec" / name).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
