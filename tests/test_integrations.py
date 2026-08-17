"""Privacy-minimized inbox manifest export tests."""

from __future__ import annotations

import json
import os
from copy import deepcopy
from uuid import UUID

import pytest

from lurescope.cli import main
from lurescope.inbox import INBOX_SCHEMA
from lurescope.integrations import load_inbox_manifest, render_export


def _entry(status="processed"):
    base = {
        "schema": INBOX_SCHEMA,
        "schema_version": 1,
        "generated_at": "2026-08-12T12:00:00+00:00",
        "case_id": "case-1234567890abcdef",
        "input_index": 1,
        "status": status,
    }
    if status == "error":
        return {**base, "error_type": "ValueError"}
    return {
        **base,
        "risk_tier": "high",
        "recommended_action": "quarantine_and_review",
        "assessment": {
            "detector": "tfidf-logreg",
            "detector_model": "tfidf-logreg-fraud.joblib",
            "detector_artifact_sha256": "a" * 64,
            "fraud_probability": 0.93,
            "label": "fraud",
            "threshold": 0.5,
            "threshold_source": "default",
            "policy_id": None,
            "evidence_codes": ["reply_to_domain_mismatch"],
            "url_count": 1,
            "attachment_count": 0,
        },
        "resilience": {
            "clean_flagged": True,
            "attack_count": 4,
            "eligible_attack_count": 4,
            "evasion_count": 1,
            "defense_recovery_count": 1,
        },
        "proof": {
            "file": "case-1234567890abcdef.lureproof.json",
            "artifact_type": "statement",
            "statement_sha256": "b" * 64,
            "signature_count": 0,
            "key_ids": [],
        },
    }


def _analyst_label(case_id, label):
    return {
        "schema": "https://github.com/immu4989/lurescope/spec/shadow-label/v1",
        "schema_version": 1,
        "labeled_at": "2026-08-12T13:00:00+00:00",
        "case_id": case_id,
        "label": label,
        "reason_code": "confirmed_external",
    }


def test_render_splunk_hec_wraps_each_event_as_ndjson():
    payload = render_export([_entry(), _entry("error")], "splunk-hec").decode()
    lines = [json.loads(line) for line in payload.splitlines()]
    assert len(lines) == 2
    assert lines[0]["sourcetype"] == "lurescope:inbox:v1"
    assert lines[0]["event"]["risk_tier"] == "high"
    assert lines[1]["event"]["error_type"] == "ValueError"


def test_render_sentinel_flattens_operational_fields():
    records = json.loads(render_export([_entry()], "sentinel"))
    assert records[0]["CaseId"] == "case-1234567890abcdef"
    assert records[0]["FraudProbability"] == 0.93
    assert records[0]["EvidenceCodes"] == ["reply_to_domain_mismatch"]
    assert records[0]["ProofStatementSha256"] == "b" * 64


def test_loader_rejects_mixed_schema_and_invalid_json(tmp_path):
    wrong = tmp_path / "wrong.jsonl"
    wrong.write_text('{"schema":"other","schema_version":1,"status":"processed"}\n')
    with pytest.raises(ValueError, match="not an inbox-manifest"):
        load_inbox_manifest(wrong)
    malformed = tmp_path / "malformed.jsonl"
    malformed.write_text("not-json\n")
    with pytest.raises(ValueError, match="not valid JSON"):
        load_inbox_manifest(malformed)


def test_export_rejects_fields_outside_the_privacy_schema(tmp_path):
    top_level = _entry()
    top_level["raw_subject"] = "sensitive subject"
    with pytest.raises(ValueError, match="unexpected keys: raw_subject"):
        render_export([top_level], "splunk-hec")

    nested = _entry()
    nested["assessment"]["source_path"] = "/sensitive/mailbox/message.eml"
    with pytest.raises(ValueError, match="unexpected keys: source_path"):
        render_export([nested], "sentinel")


def test_export_rejects_invalid_values_and_inconsistent_counters():
    probability = _entry()
    probability["assessment"]["fraud_probability"] = float("nan")
    with pytest.raises(ValueError, match="fraud_probability"):
        render_export([probability], "ocsf-1.8")

    routing = _entry()
    routing["recommended_action"] = "continue_normal_controls"
    with pytest.raises(ValueError, match="risk routing"):
        render_export([routing], "ecs-9.4")

    resilience = _entry()
    resilience["resilience"]["defense_recovery_count"] = 2
    with pytest.raises(ValueError, match="resilience counts"):
        render_export([resilience], "stix-2.1")


def test_cli_export_refuses_overwrite(tmp_path, capsys):
    manifest = tmp_path / "manifest.jsonl"
    manifest.write_text(json.dumps(_entry()) + "\n")
    output = tmp_path / "sentinel.json"
    assert main([
        "export", str(manifest), "--format", "sentinel", "--out", str(output)
    ]) == 0
    assert os.stat(output).st_mode & 0o777 == 0o600
    assert "exported 1 events" in capsys.readouterr().out
    assert main([
        "export", str(manifest), "--format", "sentinel", "--out", str(output)
    ]) == 2
    assert "File exists" in capsys.readouterr().err


def test_render_ocsf_18_detection_finding_uses_required_class_fields():
    entry = _entry()
    labels = {entry["case_id"]: _analyst_label(entry["case_id"], "fraud")}
    records = json.loads(render_export([entry, _entry("error")], "ocsf-1.8", labels))

    assert len(records) == 1
    record = records[0]
    assert record["category_uid"] == 2
    assert record["class_uid"] == 2004
    assert record["activity_id"] == 1
    assert record["type_uid"] == 200401
    assert record["metadata"]["version"] == "1.8.0"
    assert record["finding_info"]["uid"] == entry["case_id"]
    assert record["is_alert"] is True
    assert record["unmapped"]["lurescope"]["analyst_label"] == "fraud"


def test_render_ecs_94_is_ndjson_and_downgrades_analyst_benign_alert():
    entry = _entry()
    labels = {entry["case_id"]: _analyst_label(entry["case_id"], "benign")}
    payload = render_export([entry], "ecs-9.4", labels).decode()
    records = [json.loads(line) for line in payload.splitlines()]

    assert len(records) == 1
    record = records[0]
    assert record["@timestamp"] == "2026-08-12T12:00:00.000Z"
    assert record["ecs"]["version"] == "9.4.0"
    assert record["event"]["kind"] == "event"
    assert record["event"]["category"] == ["email", "intrusion_detection"]
    assert record["labels"]["lurescope_analyst_label"] == "benign"
    assert "message" not in record
    assert "email" not in record


def test_render_stix_21_emits_only_actionable_or_confirmed_incidents():
    high = _entry()
    benign_labels = {
        high["case_id"]: _analyst_label(high["case_id"], "benign")
    }
    benign_bundle = json.loads(render_export([high], "stix-2.1", benign_labels))
    assert [item["type"] for item in benign_bundle["objects"]] == ["identity"]

    low_confirmed = deepcopy(high)
    low_confirmed["case_id"] = "case-fedcba0987654321"
    low_confirmed["proof"]["file"] = "case-fedcba0987654321.lureproof.json"
    low_confirmed["risk_tier"] = "low"
    low_confirmed["recommended_action"] = "continue_normal_controls"
    low_confirmed["assessment"]["fraud_probability"] = 0.1
    fraud_labels = {
        low_confirmed["case_id"]: _analyst_label(low_confirmed["case_id"], "fraud")
    }
    first = json.loads(render_export([low_confirmed], "stix-2.1", fraud_labels))
    assert first["type"] == "bundle"
    assert [item["type"] for item in first["objects"]] == ["identity", "incident"]
    incident = first["objects"][1]
    assert incident["spec_version"] == "2.1"
    assert incident["labels"] == ["fraud-lure", "risk-low", "analyst-fraud"]
    assert "objects" not in incident
    for value in (first["id"], first["objects"][0]["id"], incident["id"]):
        assert UUID(value.split("--", 1)[1]).version == 4


def test_standard_exports_reject_invalid_analyst_label_shape():
    entry = _entry()
    label = _analyst_label(entry["case_id"], "fraud")
    label["notes"] = "sensitive free text"
    with pytest.raises(ValueError, match="privacy allowlist"):
        render_export([entry], "ocsf-1.8", {entry["case_id"]: label})


def test_legacy_exports_reject_ignored_analyst_labels():
    entry = _entry()
    label = _analyst_label(entry["case_id"], "fraud")
    with pytest.raises(ValueError, match="supported only"):
        render_export([entry], "sentinel", {entry["case_id"]: label})


def test_cli_standard_export_applies_latest_shadow_label(tmp_path, capsys):
    manifest = tmp_path / "manifest.jsonl"
    entry = _entry()
    manifest.write_text(json.dumps(entry) + "\n")
    labels = tmp_path / "analyst-labels.jsonl"
    labels.write_text(json.dumps(_analyst_label(entry["case_id"], "benign")) + "\n")
    output = tmp_path / "ocsf.json"

    assert main([
        "export", str(manifest), "--format", "ocsf-1.8", "--labels", str(labels),
        "--out", str(output),
    ]) == 0
    assert json.loads(output.read_text())[0]["is_alert"] is False
    assert "exported 1 events" in capsys.readouterr().out
