"""CISA SCuBA Evidence Bridge contract, privacy, integrity, and OSCAL tests."""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
from pathlib import Path

import jsonschema
import pytest

from lurescope.assurance import create_assurance_plan
from lurescope.cli import main
from lurescope.integrations import load_inbox_manifest
from lurescope.proof import generate_keypair
from lurescope.scuba import (
    DSSE_FILE,
    OSCAL_POAM_FILE,
    SCUBA_EVIDENCE_FILE,
    STATEMENT_FILE,
    create_scuba_assurance_bundle,
    ingest_scuba_report,
    validate_scuba_evidence,
    verify_scuba_assurance_bundle,
)
from lurescope.shadow import append_analyst_label, run_shadow_inbox

ROOT = Path(__file__).parents[1]
EMAIL_FIXTURES = ROOT / "examples" / "shadow-pilot" / "eml"
SCUBA_FIXTURE = ROOT / "examples" / "scuba-bridge" / "ScubaResults_synthetic.json"
VENDORED = ROOT / "tests" / "vendor" / "oscal-1.2.2"
SSP_URN = "urn:uuid:11111111-1111-4111-8111-111111111111"
POAM_SCHEMA_SHA256 = "c8f2ce52b3c71299bb0c9e1cd950d48dc79d9f52920c543ac30b3c3f08c2e152"


def _official_validator(name: str):
    """Adapt two ECMA-262 Unicode property escapes to Python's regex engine."""
    schema = json.loads((VENDORED / name).read_text(encoding="utf-8"))
    default_pattern = jsonschema.Draft7Validator.VALIDATORS["pattern"]

    def unicode_pattern(validator, pattern, instance, current_schema):
        translated = pattern.replace(r"\p{L}", r"[^\W\d_]").replace(r"\p{N}", r"\d")
        yield from default_pattern(validator, translated, instance, current_schema)

    validator_type = jsonschema.validators.extend(
        jsonschema.Draft7Validator, {"pattern": unicode_pattern}
    )
    return validator_type(schema, format_checker=jsonschema.FormatChecker())


def _reviewed_pilot(tmp_path: Path) -> tuple[Path, Path]:
    plan = tmp_path / "plan"
    create_assurance_plan(
        plan,
        ssp_href=SSP_URN,
        plan_id="scuba-synthetic-pilot",
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
    assert [item["input_index"] for item in processed] == [1, 2, 3, 4, 5]
    for item in processed:
        fraud = item["input_index"] <= 4
        append_analyst_label(
            bundle,
            item["case_id"],
            "fraud" if fraud else "benign",
            "confirmed_external" if fraud else "known_legitimate",
        )
    return plan, bundle


def _load_source() -> dict:
    return json.loads(SCUBA_FIXTURE.read_text(encoding="utf-8"))


def _validate_public_schema(instance: dict, name: str) -> None:
    schema = json.loads((ROOT / "spec" / name).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    ).validate(instance)


def _write_source(tmp_path: Path, source: dict, name: str = "ScubaResults_test.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(source), encoding="utf-8")
    return path


def test_scuba_import_is_reconciled_minimized_and_offline(monkeypatch):
    def network_forbidden(*args, **kwargs):
        raise AssertionError("SCuBA import attempted a network connection")

    monkeypatch.setattr(socket, "socket", network_forbidden)
    evidence, source_raw = ingest_scuba_report(SCUBA_FIXTURE)

    assert evidence["integrity"] == {
        "source_summary_reconciled": True,
        "unique_control_ids": True,
        "control_count": 5,
        "candidate_poam_count": 2,
    }
    assert evidence["scope"]["products"] == ["AAD", "Defender", "EXO"]
    assert evidence["source"]["report_sha256"] == hashlib.sha256(source_raw).hexdigest()
    assert all(
        set(control) == {"product", "control_id", "result", "criticality"}
        for control in evidence["controls"]
    )

    _validate_public_schema(evidence, "scuba-evidence-v1.schema.json")

    boolean_version = json.loads(json.dumps(evidence))
    boolean_version["schema_version"] = True
    with pytest.raises(ValueError, match="schema identifier"):
        validate_scuba_evidence(boolean_version)
    boolean_count = json.loads(json.dumps(evidence))
    boolean_count["summary"]["products"][0]["counts"]["Failures"] = True
    with pytest.raises(ValueError, match="non-negative integer"):
        validate_scuba_evidence(boolean_count)

    serialized = json.dumps(evidence).lower()
    for forbidden in (
        "synthetic-tenant.example.invalid",
        "22222222-2222-4222-8222-222222222222",
        "33333333-3333-4333-8333-333333333333",
        "raw-provider-setting-that-must-never-be-exported",
        "synthetic shall requirement",
        "sensitive synthetic failure context",
        "synthetic analyst comment",
    ):
        assert forbidden not in serialized


def test_combined_bundle_is_private_bound_and_official_oscal_valid(tmp_path, monkeypatch):
    def network_forbidden(*args, **kwargs):
        raise AssertionError("SCuBA bridge attempted a network connection")

    monkeypatch.setattr(socket, "socket", network_forbidden)
    plan, pilot = _reviewed_pilot(tmp_path)
    output = tmp_path / "combined"
    result = create_scuba_assurance_bundle(SCUBA_FIXTURE, pilot, plan, output)

    assert result["gate"]["verdict"] == "pass"
    assert result["verification"]["valid"] is True
    assert result["verification"]["authenticated"] is False
    assert set(item.name for item in output.iterdir()) == {
        "pilot-plan.json",
        "assurance-profile.json",
        "oscal-assessment-plan.json",
        "pilot-gate.json",
        SCUBA_EVIDENCE_FILE,
        "oscal-assessment-results.json",
        OSCAL_POAM_FILE,
        STATEMENT_FILE,
    }
    if os.name == "posix":
        assert output.stat().st_mode & 0o777 == 0o700
        assert all(item.stat().st_mode & 0o777 == 0o600 for item in output.iterdir())

    combined = result["assessment_results"]
    assert len(combined["assessment-results"]["results"]) == 2
    imported = combined["assessment-results"]["results"][1]
    assert len(imported["observations"]) == 5
    assert all(item["methods"] == ["EXAMINE"] for item in imported["observations"])
    assert all("findings" not in item for item in combined["assessment-results"]["results"])
    _official_validator("oscal_assessment-results_schema.json").validate(combined)

    poam = result["poam"]
    assert poam is not None
    poam_body = poam["plan-of-action-and-milestones"]
    assert len(poam_body["poam-items"]) == 2
    assert "risks" not in poam_body and "findings" not in poam_body
    assert all(
        any(prop["name"] == "candidate-only" and prop["value"] == "true" for prop in item["props"])
        for item in poam_body["poam-items"]
    )
    _official_validator("oscal_poam_schema.json").validate(poam)

    statement = result["statement"]
    _validate_public_schema(statement, "combined-assurance-statement-v1.schema.json")
    assert [subject["name"] for subject in statement["subject"]][-3:] == [
        SCUBA_EVIDENCE_FILE,
        "oscal-assessment-results.json",
        OSCAL_POAM_FILE,
    ]
    for subject in statement["subject"]:
        assert subject["digest"]["sha256"] == hashlib.sha256(
            (output / subject["name"]).read_bytes()
        ).hexdigest()

    # An unsigned statement can be rewritten with a modified artifact digest. The
    # verifier must still reject the package because semantic reconstruction is
    # independent of that self-asserted digest.
    combined_path = output / "oscal-assessment-results.json"
    tampered = json.loads(combined_path.read_text(encoding="utf-8"))
    tampered["assessment-results"]["results"][1]["title"] = "Rewritten assertion"
    combined_path.write_text(json.dumps(tampered), encoding="utf-8")
    statement_path = output / STATEMENT_FILE
    rewritten_statement = json.loads(statement_path.read_text(encoding="utf-8"))
    for subject in rewritten_statement["subject"]:
        if subject["name"] == combined_path.name:
            subject["digest"]["sha256"] = hashlib.sha256(combined_path.read_bytes()).hexdigest()
    statement_path.write_text(json.dumps(rewritten_statement), encoding="utf-8")
    with pytest.raises(ValueError, match="exactly reconcile"):
        verify_scuba_assurance_bundle(output)


def test_signed_bundle_authenticates_and_detects_tampering(tmp_path):
    plan, pilot = _reviewed_pilot(tmp_path)
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    key_id = generate_keypair(private_key, public_key)
    output = tmp_path / "signed-combined"
    create_scuba_assurance_bundle(
        SCUBA_FIXTURE, pilot, plan, output, signing_key=private_key
    )

    verification = verify_scuba_assurance_bundle(
        output, public_key=public_key, require_signature=True
    )
    assert verification["authenticated"] is True
    assert verification["signature_count"] == 1
    assert verification["key_ids"] == [key_id]
    assert (output / DSSE_FILE).is_file()
    envelope = json.loads((output / DSSE_FILE).read_text(encoding="utf-8"))
    _validate_public_schema(envelope, "combined-assurance-dsse-v1.schema.json")
    with pytest.raises(ValueError, match="trusted public key"):
        verify_scuba_assurance_bundle(output, require_signature=True)
    wrong_private = tmp_path / "wrong-private.pem"
    wrong_public = tmp_path / "wrong-public.pem"
    generate_keypair(wrong_private, wrong_public)
    with pytest.raises(ValueError, match="matches the trusted public key"):
        verify_scuba_assurance_bundle(output, public_key=wrong_public)

    evidence_path = output / SCUBA_EVIDENCE_FILE
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["controls"][0]["result"] = "Warning"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    with pytest.raises(ValueError, match="digest mismatch"):
        verify_scuba_assurance_bundle(output, public_key=public_key)


def test_import_rejects_contract_drift_and_inconsistent_summary(tmp_path):
    bad_version = _load_source()
    bad_version["MetaData"]["ToolVersion"] = "1.9.0"
    with pytest.raises(ValueError, match=r"1\.8\.x"):
        ingest_scuba_report(_write_source(tmp_path, bad_version, "version.json"))

    unknown_field = _load_source()
    unknown_field["MetaData"]["UnexpectedTenantField"] = "must fail closed"
    with pytest.raises(ValueError, match="allowlist"):
        ingest_scuba_report(_write_source(tmp_path, unknown_field, "unknown.json"))

    inconsistent = _load_source()
    inconsistent["Summary"]["AAD"]["Failures"] = 0
    with pytest.raises(ValueError, match="does not reconcile"):
        ingest_scuba_report(_write_source(tmp_path, inconsistent, "summary.json"))

    duplicate = _load_source()
    duplicate["Results"]["EXO"][0]["Controls"][0]["Control ID"] = "MS.AAD.1.1v1"
    with pytest.raises(ValueError, match="does not match product|duplicate"):
        ingest_scuba_report(_write_source(tmp_path, duplicate, "duplicate.json"))

    duplicate_key = SCUBA_FIXTURE.read_text(encoding="utf-8").replace(
        '"Tool": "ScubaGear",',
        '"Tool": "ScubaGear", "Tool": "Counterfeit",',
        1,
    )
    duplicate_path = tmp_path / "duplicate-key.json"
    duplicate_path.write_text(duplicate_key, encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON object key"):
        ingest_scuba_report(duplicate_path)

    nonstandard_number = SCUBA_FIXTURE.read_text(encoding="utf-8").replace(
        '"Raw": {', '"Raw": {"NonStandard": NaN,', 1
    )
    nonstandard_path = tmp_path / "nan.json"
    nonstandard_path.write_text(nonstandard_number, encoding="utf-8")
    with pytest.raises(ValueError, match="non-standard JSON numeric constant"):
        ingest_scuba_report(nonstandard_path)

    invalid_products = _load_source()
    invalid_products["MetaData"]["ProductsAssessed"][0] = {"not": "a string"}
    with pytest.raises(ValueError, match="ProductsAssessed"):
        ingest_scuba_report(_write_source(tmp_path, invalid_products, "products.json"))

    spoofed_baseline = _load_source()
    spoofed_baseline["Results"]["AAD"][0]["GroupReferenceURL"] = (
        "https://example.invalid/counterfeit-baseline.md"
    )
    with pytest.raises(ValueError, match="reported v1.8.0 CISA baseline"):
        ingest_scuba_report(_write_source(tmp_path, spoofed_baseline, "spoofed.json"))


def test_import_accepts_official_bom_and_discards_supplemental_raw_metadata(tmp_path):
    configured = _load_source()
    configured["Raw"]["ScubaConfig"] = {
        "OrgName": "Sensitive Department Name",
        "OrgUnitName": "Sensitive Program Office",
    }
    path = tmp_path / "configured.json"
    path.write_bytes(b"\xef\xbb\xbf" + json.dumps(configured).encode("utf-8"))
    evidence, _ = ingest_scuba_report(path)
    serialized = json.dumps(evidence)
    assert "Sensitive Department Name" not in serialized
    assert "Sensitive Program Office" not in serialized


def test_bundle_refuses_overwrite_and_omits_empty_candidate_poam(tmp_path):
    plan, pilot = _reviewed_pilot(tmp_path)
    output = tmp_path / "already-there"
    output.mkdir()
    marker = output / "keep.txt"
    marker.write_text("preserve", encoding="utf-8")
    with pytest.raises(FileExistsError):
        create_scuba_assurance_bundle(SCUBA_FIXTURE, pilot, plan, output)
    assert marker.read_text(encoding="utf-8") == "preserve"

    no_candidates = _load_source()
    for product in ("AAD", "EXO"):
        summary = no_candidates["Summary"][product]
        summary["Passes"] += summary["Failures"]
        summary["Failures"] = 0
        for group in no_candidates["Results"][product]:
            for control in group["Controls"]:
                if control["Result"] == "Fail":
                    control["Result"] = "Pass"
    source_path = _write_source(tmp_path, no_candidates, "no-candidates.json")
    empty_output = tmp_path / "no-candidates"
    result = create_scuba_assurance_bundle(source_path, pilot, plan, empty_output)
    assert result["poam"] is None
    assert not (empty_output / OSCAL_POAM_FILE).exists()
    assert verify_scuba_assurance_bundle(empty_output)["candidate_poam_count"] == 0


def test_scuba_cli_ingest_and_authenticated_verify(tmp_path, capsys):
    plan, pilot = _reviewed_pilot(tmp_path)
    private_key = tmp_path / "cli-private.pem"
    public_key = tmp_path / "cli-public.pem"
    generate_keypair(private_key, public_key)
    output = tmp_path / "cli-combined"

    assert main(
        [
            "assurance",
            "ingest-scuba",
            str(SCUBA_FIXTURE),
            "--bundle",
            str(pilot),
            "--plan",
            str(plan),
            "--out",
            str(output),
            "--signing-key",
            str(private_key),
        ]
    ) == 0
    stdout = capsys.readouterr().out
    assert "Combined Email Assurance: pass" in stdout
    assert re.search(r"source ScubaGear report sha256:[a-f0-9]{64}", stdout)

    assert main(
        [
            "assurance",
            "verify-scuba",
            str(output),
            "--public-key",
            str(public_key),
            "--require-signature",
        ]
    ) == 0
    verification = json.loads(capsys.readouterr().out)
    assert verification["valid"] is True
    assert verification["authenticated"] is True
    assert verification["candidate_poam_count"] == 2


def test_vendored_official_poam_schema_digest_is_locked():
    assert hashlib.sha256((VENDORED / "oscal_poam_schema.json").read_bytes()).hexdigest() == (
        POAM_SCHEMA_SHA256
    )
