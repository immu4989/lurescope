"""Offline Defender pairing, privacy, schema, and comparison tests."""

from __future__ import annotations

import csv
import json
from email.message import EmailMessage
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

pytest.importorskip("sklearn")

from lurescope.cli import main
from lurescope.defender import (
    build_defender_report,
    import_defender_shadow,
    load_defender_csv,
    load_defender_import,
)
from lurescope.shadow import append_analyst_label


def _email(subject: str, body: str, internet_id: str, network_id: str) -> bytes:
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = "highly.sensitive.sender@example.invalid"
    message["To"] = "protected.recipient@example.invalid"
    message["Message-ID"] = internet_id
    message["X-MS-Exchange-Organization-Network-Message-Id"] = network_id
    message.set_content(body)
    return message.as_bytes()


def _write_csv(path: Path, rows: list[dict]) -> None:
    fields = [
        "NetworkMessageId",
        "InternetMessageId",
        "RecipientEmailAddress",
        "Subject",
        "ThreatTypes",
        "DeliveryAction",
        "DeliveryLocation",
        "LatestDeliveryAction",
        "LatestDeliveryLocation",
        "UserLevelAction",
    ]
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _fixture(tmp_path: Path):
    messages = tmp_path / "tenant-export"
    messages.mkdir()
    fraud_id = "11111111-1111-1111-1111-111111111111"
    benign_id = "22222222-2222-2222-2222-222222222222"
    unmatched_id = "33333333-3333-3333-3333-333333333333"
    (messages / "01-fraud.eml").write_bytes(
        _email(
            "Confidential payroll redirect",
            "Urgent: verify the new wire payment account within 24 hours.",
            "<fraud-secret@example.invalid>",
            fraud_id,
        )
    )
    (messages / "02-benign.eml").write_bytes(
        _email(
            "Private board agenda",
            "The ordinary team planning agenda is attached for next week.",
            "<benign-secret@example.invalid>",
            benign_id,
        )
    )
    (messages / "03-no-event.eml").write_bytes(
        _email(
            "Unmatched confidential note",
            "A routine status note that has no exported EmailEvents row.",
            "<unmatched-secret@example.invalid>",
            "44444444-4444-4444-4444-444444444444",
        )
    )
    export = tmp_path / "EmailEvents-sensitive.csv"
    _write_csv(
        export,
        [
            {
                "NetworkMessageId": fraud_id,
                "InternetMessageId": "<fraud-secret@example.invalid>",
                "RecipientEmailAddress": "victim-one@example.invalid",
                "Subject": "Confidential payroll redirect",
                "ThreatTypes": "Phish",
                "DeliveryAction": "Blocked",
                "DeliveryLocation": "Quarantine",
                "LatestDeliveryAction": "Blocked",
                "LatestDeliveryLocation": "Quarantine",
                "UserLevelAction": "",
            },
            {
                "NetworkMessageId": benign_id,
                "InternetMessageId": "<benign-secret@example.invalid>",
                "RecipientEmailAddress": "victim-two@example.invalid",
                "Subject": "Private board agenda",
                "ThreatTypes": "",
                "DeliveryAction": "Delivered",
                "DeliveryLocation": "Inbox/Folder",
                "LatestDeliveryAction": "Delivered",
                "LatestDeliveryLocation": "Inbox/Folder",
                "UserLevelAction": "",
            },
            {
                "NetworkMessageId": unmatched_id,
                "InternetMessageId": "<csv-only-secret@example.invalid>",
                "RecipientEmailAddress": "victim-three@example.invalid",
                "Subject": "CSV only private subject",
                "ThreatTypes": "Malware",
                "DeliveryAction": "Blocked",
                "DeliveryLocation": "Quarantine",
                "LatestDeliveryAction": "Blocked",
                "LatestDeliveryLocation": "Quarantine",
                "UserLevelAction": "",
            },
        ],
    )
    return export, messages


def _validate(root: Path, schema_name: str, value: object) -> None:
    schema = json.loads((root / "spec" / schema_name).read_text(encoding="utf-8"))
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)


def test_offline_import_pairs_in_memory_and_persists_only_minimized_signals(tmp_path):
    export, messages = _fixture(tmp_path)
    bundle = tmp_path / "paired-pilot"

    result = import_defender_shadow(export, [messages], bundle)

    imported = result["import"]
    assert imported["source_row_count"] == 3
    assert imported["matched_source_row_count"] == 2
    assert imported["message_count"] == 3
    assert imported["matched_message_count"] == 2
    assert result["report"]["cohort"]["evaluated_matched_messages"] == 0

    root = Path(__file__).parents[1]
    _validate(root, "defender-import-v1.schema.json", imported)
    _validate(root, "defender-report-v1.schema.json", result["report"])
    case_schema = json.loads((root / "spec/defender-case-v1.schema.json").read_text())
    case_validator = Draft202012Validator(case_schema)
    for line in (bundle / "defender-cases.jsonl").read_text().splitlines():
        case_validator.validate(json.loads(line))

    persisted = "\n".join(
        path.read_text(encoding="utf-8") for path in bundle.iterdir() if path.is_file()
    )
    for secret in (
        str(export),
        str(messages),
        "fraud-secret",
        "benign-secret",
        "csv-only-secret",
        "victim-one",
        "Confidential payroll redirect",
        "Private board agenda",
        "verify the new wire",
    ):
        assert secret not in persisted


def test_paired_report_compares_only_matched_adjudicated_messages(tmp_path):
    export, messages = _fixture(tmp_path)
    bundle = tmp_path / "paired-pilot"
    result = import_defender_shadow(export, [messages], bundle)

    for item in result["run"].inbox.items:
        if "01-fraud" in item.source:
            append_analyst_label(bundle, item.case_id, "fraud", "confirmed_external")
        else:
            append_analyst_label(bundle, item.case_id, "benign", "known_legitimate")

    report = build_defender_report(bundle)
    assert report["cohort"]["latest_label_count"] == 3
    assert report["cohort"]["evaluated_matched_messages"] == 2
    assert report["native_attention"]["confusion"] == {
        "true_positive": 1,
        "false_positive": 0,
        "true_negative": 1,
        "false_negative": 0,
    }
    assert report["native_attention"]["performance"]["recall_estimate"] == 1.0
    assert report["native_attention"]["performance"]["false_positive_rate_estimate"] == 0.0
    refreshed = json.loads((bundle / "defender-report.json").read_text())
    assert refreshed["cohort"]["evaluated_matched_messages"] == 2


def test_csv_and_bundle_validation_fail_closed(tmp_path):
    duplicate_headers = tmp_path / "duplicate.csv"
    duplicate_headers.write_text(
        "NetworkMessageId,NetworkMessageId,ThreatTypes,DeliveryAction,DeliveryLocation\n"
        "id,id,Phish,Blocked,Quarantine\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate column"):
        load_defender_csv(duplicate_headers)

    export, messages = _fixture(tmp_path)
    bundle = tmp_path / "paired-pilot"
    import_defender_shadow(export, [messages], bundle)
    import_path = bundle / "defender-import.json"
    imported = json.loads(import_path.read_text())
    imported["RecipientEmailAddress"] = "should never be accepted"
    import_path.write_text(json.dumps(imported), encoding="utf-8")
    with pytest.raises(ValueError, match="privacy allowlist"):
        load_defender_import(bundle)


def test_ambiguous_event_match_is_rejected_before_bundle_creation(tmp_path):
    shared = "55555555-5555-5555-5555-555555555555"
    messages = tmp_path / "messages"
    messages.mkdir()
    (messages / "one.eml").write_bytes(
        _email("One", "First distinct body", "<one@example.invalid>", shared)
    )
    (messages / "two.eml").write_bytes(
        _email("Two", "Second distinct body", "<two@example.invalid>", shared)
    )
    export = tmp_path / "EmailEvents.csv"
    _write_csv(
        export,
        [
            {
                "NetworkMessageId": shared,
                "InternetMessageId": "",
                "RecipientEmailAddress": "recipient@example.invalid",
                "Subject": "One",
                "ThreatTypes": "Phish",
                "DeliveryAction": "Blocked",
                "DeliveryLocation": "Quarantine",
                "LatestDeliveryAction": "Blocked",
                "LatestDeliveryLocation": "Quarantine",
                "UserLevelAction": "",
            }
        ],
    )
    bundle = tmp_path / "must-not-exist"

    with pytest.raises(ValueError, match="ambiguously matches"):
        import_defender_shadow(export, [messages], bundle)
    assert not bundle.exists()


def test_defender_cli_import_and_report(tmp_path, capsys):
    export, messages = _fixture(tmp_path)
    bundle = tmp_path / "paired-pilot"

    assert main(["defender", "import", str(export), str(messages), "--out", str(bundle)]) == 0
    assert "paired 2/3 messages" in capsys.readouterr().out
    assert main(["defender", "report", str(bundle)]) == 0
    assert "refreshed paired report" in capsys.readouterr().out
