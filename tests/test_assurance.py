"""Federal Email Assurance Profile integrity and OSCAL conformance tests."""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
from pathlib import Path

import jsonschema
import pytest

from lurescope.assurance import (
    ASSURANCE_PROFILE_SCHEMA,
    OSCAL_AP_SCHEMA,
    OSCAL_AR_SCHEMA,
    create_assurance_plan,
    export_assurance_results,
    load_assurance_plan,
)
from lurescope.cli import main
from lurescope.integrations import load_inbox_manifest
from lurescope.shadow import append_analyst_label, run_shadow_inbox

ROOT = Path(__file__).parents[1]
FIXTURES = ROOT / "examples" / "shadow-pilot" / "eml"
VENDORED = ROOT / "tests" / "vendor" / "oscal-1.2.2"
SSP_URN = "urn:uuid:11111111-1111-4111-8111-111111111111"

OFFICIAL_SCHEMA_SHA256 = {
    "oscal_assessment-plan_schema.json": (
        "ba265f05982969142cbc3c6ed6bb99e0880081ceb366c152e44fe7e2b08aa125"
    ),
    "oscal_assessment-results_schema.json": (
        "d4e1e7e17c6662814882810ad64075266964ee1a575759ce3955302fd74edcd9"
    ),
}


def _create_plan(path: Path):
    return create_assurance_plan(
        path,
        ssp_href=SSP_URN,
        plan_id="federal-synthetic-pilot",
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


def _official_validator(name: str):
    """Use Python's Unicode classes for two ECMA-262 property escapes.

    NIST's official Draft 7 schema uses ``\\p{L}`` and ``\\p{N}`` in its
    TokenDatatype pattern. Python's standard ``re`` engine does not implement
    those ECMA-262 escapes, so this narrow adapter preserves the intended Unicode
    letter/number semantics instead of disabling pattern validation.
    """
    schema = json.loads((VENDORED / name).read_text(encoding="utf-8"))
    default_pattern = jsonschema.Draft7Validator.VALIDATORS["pattern"]

    def unicode_pattern(validator, pattern, instance, current_schema):
        translated = pattern.replace(r"\p{L}", r"[^\W\d_]").replace(r"\p{N}", r"\d")
        yield from default_pattern(validator, translated, instance, current_schema)

    validator_type = jsonschema.validators.extend(
        jsonschema.Draft7Validator, {"pattern": unicode_pattern}
    )
    return validator_type(schema, format_checker=jsonschema.FormatChecker())


def _property(props: list[dict], name: str) -> str:
    matches = [item["value"] for item in props if item["name"] == name]
    assert len(matches) == 1
    return matches[0]


def test_assurance_plan_is_private_bound_and_official_oscal_valid(tmp_path):
    plan_dir = tmp_path / "assurance-plan"
    profile = _create_plan(plan_dir)
    loaded = load_assurance_plan(plan_dir)

    assert set(item.name for item in plan_dir.iterdir()) == {
        "assurance-profile.json",
        "oscal-assessment-plan.json",
        "pilot-plan.json",
    }
    if os.name == "posix":
        assert plan_dir.stat().st_mode & 0o777 == 0o700
        assert all(path.stat().st_mode & 0o777 == 0o600 for path in plan_dir.iterdir())

    pilot_bytes = (plan_dir / "pilot-plan.json").read_bytes()
    ap_bytes = (plan_dir / "oscal-assessment-plan.json").read_bytes()
    assert profile["artifacts"]["pilot_plan"]["sha256"] == hashlib.sha256(pilot_bytes).hexdigest()
    assert (
        profile["artifacts"]["oscal_assessment_plan"]["sha256"]
        == hashlib.sha256(ap_bytes).hexdigest()
    )
    ap = loaded["assessment_plan"]
    assert ap["$schema"] == OSCAL_AP_SCHEMA
    assert ap["assessment-plan"]["import-ssp"] == {"href": SSP_URN}
    assert [
        item["control-id"]
        for item in ap["assessment-plan"]["reviewed-controls"]["control-selections"][0][
            "include-controls"
        ]
    ] == ["ca-7", "si-4", "si-8"]
    _official_validator("oscal_assessment-plan_schema.json").validate(ap)

    profile_schema = json.loads((ROOT / "spec" / "assurance-profile-v1.schema.json").read_text())
    assert profile_schema["$id"] == ASSURANCE_PROFILE_SCHEMA
    validator = jsonschema.Draft202012Validator(
        profile_schema, format_checker=jsonschema.FormatChecker()
    )
    jsonschema.Draft202012Validator.check_schema(profile_schema)
    validator.validate(profile)
    with pytest.raises(jsonschema.ValidationError):
        validator.validate({**profile, "compliant": True})


def test_end_to_end_assurance_export_is_aggregate_only_and_official_oscal_valid(
    tmp_path, monkeypatch
):
    def network_forbidden(*args, **kwargs):
        raise AssertionError("assurance workflow attempted a network connection")

    monkeypatch.setattr(socket, "socket", network_forbidden)
    plan_dir = tmp_path / "assurance-plan"
    _create_plan(plan_dir)
    bundle = tmp_path / "shadow-bundle"
    run_shadow_inbox([FIXTURES], bundle, threshold=0.5)
    entries = load_inbox_manifest(bundle / "manifest.jsonl")
    processed = [entry for entry in entries if entry["status"] == "processed"]
    assert [entry["input_index"] for entry in processed] == [1, 2, 3, 4, 5]
    for entry in processed:
        fraud = entry["input_index"] <= 4
        append_analyst_label(
            bundle,
            entry["case_id"],
            "fraud" if fraud else "benign",
            "confirmed_external" if fraud else "known_legitimate",
        )

    result = export_assurance_results(bundle, plan_dir)
    gate = result["gate"]
    document = result["assessment_results"]
    body = document["assessment-results"]
    result_set = body["results"][0]

    assert gate["verdict"] == "pass"
    assert document["$schema"] == OSCAL_AR_SCHEMA
    assert body["uuid"] != result_set["uuid"]
    assert body["import-ap"] == {"href": "oscal-assessment-plan.json"}
    assert len(result_set["observations"]) == 10
    assert "findings" not in result_set
    assert all(item["methods"] == ["TEST"] for item in result_set["observations"])
    assert all(
        "not a control satisfaction determination" in item["remarks"]
        for item in result_set["observations"]
    )

    serialized = json.dumps(document)
    for forbidden in (
        "case-",
        "example.invalid",
        ".eml",
        "bank-change",
        "benefits",
        "agenda",
    ):
        assert forbidden not in serialized.lower()
    for name in (
        "assurance-profile.json",
        "oscal-assessment-plan.json",
        "oscal-assessment-results.json",
        "pilot-gate.json",
    ):
        assert (bundle / name).is_file()
        if os.name == "posix":
            assert (bundle / name).stat().st_mode & 0o777 == 0o600

    metadata_props = body["metadata"]["props"]
    assert (
        _property(metadata_props, "pilot-gate-sha256")
        == hashlib.sha256((bundle / "pilot-gate.json").read_bytes()).hexdigest()
    )
    assert (
        _property(metadata_props, "assurance-profile-sha256")
        == hashlib.sha256((bundle / "assurance-profile.json").read_bytes()).hexdigest()
    )
    validator = _official_validator("oscal_assessment-results_schema.json")
    validator.validate(document)
    invalid = json.loads(json.dumps(document))
    invalid["assessment-results"]["results"][0]["certified"] = True
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(invalid)


def test_assurance_rejects_overwrite_unsafe_ssp_tampering_and_bundle_rebinding(tmp_path, capsys):
    plan_dir = tmp_path / "assurance-plan"
    _create_plan(plan_dir)
    with pytest.raises(FileExistsError):
        _create_plan(plan_dir)
    with pytest.raises(ValueError, match="portable https: or urn:"):
        create_assurance_plan(
            tmp_path / "unsafe",
            ssp_href="/private/system-security-plan.json",
            plan_id="unsafe",
            min_processed_count=2,
            min_fraud_labels=1,
            min_benign_labels=1,
            max_uncertain_rate=0,
            max_processing_failure_rate=0,
            min_routing_recall_lower_bound=0.1,
            max_routing_false_positive_rate_upper_bound=0.99,
            max_routed_rate=1,
            max_routed_count=2,
        )

    rebound_bundle = tmp_path / "rebound-bundle"
    rebound_bundle.mkdir()
    rebound_bundle.chmod(0o700)
    (rebound_bundle / "assurance-profile.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="different assurance-profile.json"):
        export_assurance_results(rebound_bundle, plan_dir)

    if os.name == "posix":
        public_bundle = tmp_path / "public-bundle"
        public_bundle.mkdir()
        public_bundle.chmod(0o755)
        with pytest.raises(ValueError, match="group or world access"):
            export_assurance_results(public_bundle, plan_dir)

    ap_path = plan_dir / "oscal-assessment-plan.json"
    ap = json.loads(ap_path.read_text())
    ap["assessment-plan"]["metadata"]["remarks"] = "This system is compliant."
    ap_path.write_text(json.dumps(ap), encoding="utf-8")
    with pytest.raises(ValueError, match="SHA-256"):
        load_assurance_plan(plan_dir)

    assert main(["assurance", "export", str(tmp_path / "missing"), "--plan", str(plan_dir)]) == 2
    assert re.search(r"missing|SHA-256", capsys.readouterr().err)


def test_assurance_cli_init_prints_all_registration_digests(tmp_path, capsys):
    plan_dir = tmp_path / "cli-plan"
    assert (
        main(
            [
                "assurance",
                "init",
                "--out",
                str(plan_dir),
                "--plan-id",
                "cli-registration",
                "--ssp-href",
                SSP_URN,
                "--min-processed",
                "5",
                "--min-fraud-labels",
                "1",
                "--min-benign-labels",
                "1",
                "--max-uncertain-rate",
                "0",
                "--max-failure-rate",
                "0",
                "--min-recall-lower",
                "0.05",
                "--max-fpr-upper",
                "0.99",
                "--max-routed-rate",
                "1",
                "--max-routed-count",
                "5",
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert "OSCAL AP " in output
    assert output.count("register ") == 3
    assert len(re.findall(r"sha256:[a-f0-9]{64}", output)) == 3


def test_vendored_official_schema_digests_are_locked():
    for name, expected in OFFICIAL_SCHEMA_SHA256.items():
        assert hashlib.sha256((VENDORED / name).read_bytes()).hexdigest() == expected
