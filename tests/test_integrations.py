"""Privacy-minimized inbox manifest export tests."""

from __future__ import annotations

import json
import os

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
