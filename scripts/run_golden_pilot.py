"""Run LureScope's locked, synthetic-only Shadow Inbox reference pilot.

This script is intentionally not a generic auto-labeler. It accepts no mailbox
input from the CLI and refuses fixtures whose names or SHA-256 digests differ from
the reviewed repository contract.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from lurescope.pilot import (
    create_pilot_plan,
    detector_artifact_sha256,
    write_pilot_gate,
)
from lurescope.shadow import append_analyst_label, run_shadow_inbox

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURE_DIR = ROOT / "examples" / "shadow-pilot" / "eml"
RECEIPT_SCHEMA = "https://github.com/immu4989/lurescope/spec/golden-pilot-receipt/v1"
EXPECTED_DETECTOR_SHA256 = (
    "84c7254c464ff9faa3ede012691c13d53da08ab1f26223633af7b9377d60ed0b"
)

FIXTURE_CONTRACT: Dict[str, Dict[str, str]] = {
    "01-qr-benefits.eml": {
        "sha256": "cf17047fcf1156e919cf308839c1ca42bda71c5c74d786a9b01d8aa69934e375",
        "label": "fraud",
        "reason": "confirmed_external",
    },
    "02-bec-bank-change.eml": {
        "sha256": "0b05cf78c50f99406d57770b55a661f290f81bbed0e339335e8a3612e15ed3ec",
        "label": "fraud",
        "reason": "confirmed_external",
    },
    "03-archive-attachment.eml": {
        "sha256": "11614dd3b316001c4388fc5aa06c136a47430524193965bb3ee8763ccf5e2009",
        "label": "fraud",
        "reason": "confirmed_external",
    },
    "04-multilingual-alert.eml": {
        "sha256": "4fe2747c9d2f030cd72a1246c0176177f02d85083d9d37b393c145302aa8dbee",
        "label": "fraud",
        "reason": "confirmed_external",
    },
    "05-benign-agenda.eml": {
        "sha256": "d520fde3cd07da43ce0af1ed3014e6adc5446d5d299e9424be00bc23f975e485",
        "label": "benign",
        "reason": "known_legitimate",
    },
    "06-duplicate-bec.eml": {
        "sha256": "0b05cf78c50f99406d57770b55a661f290f81bbed0e339335e8a3612e15ed3ec",
        "label": "fraud",
        "reason": "confirmed_external",
    },
}

EXPECTED_UNIQUE_FILES = set(FIXTURE_CONTRACT) - {"06-duplicate-bec.eml"}
FORBIDDEN_OUTPUT_FRAGMENTS = (
    "examples/shadow-pilot/eml",
    "examples\\shadow-pilot\\eml",
    "chief.executive@example.invalid",
    "settlement@external-payments.invalid",
    "synthetic-bec-002@example.invalid",
    "Confidential bank change before today settlement",
    "Urgently update the supplier bank account",
    "verify.example.invalid",
    "synthetic-remittance.zip",
    "The planning meeting remains Tuesday at 10 AM",
)


def _timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_new(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _verify_fixtures(fixture_dir: Path) -> str:
    fixture_dir = Path(fixture_dir)
    if fixture_dir.is_symlink() or not fixture_dir.is_dir():
        raise ValueError("golden fixture directory must be a regular local directory")
    files = sorted(fixture_dir.iterdir())
    names = {path.name for path in files}
    if names != set(FIXTURE_CONTRACT):
        missing = sorted(set(FIXTURE_CONTRACT) - names)
        extra = sorted(names - set(FIXTURE_CONTRACT))
        raise ValueError(f"golden fixture set changed (missing={missing}, extra={extra})")

    identity = hashlib.sha256()
    for path in files:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"golden fixture must be a regular file: {path.name}")
        digest = _sha256(path.read_bytes())
        expected = FIXTURE_CONTRACT[path.name]["sha256"]
        if digest != expected:
            raise ValueError(f"golden fixture digest changed: {path.name}")
        identity.update(f"{path.name}\0{digest}\n".encode("utf-8"))
    return identity.hexdigest()


def _validate_schema(instance: Dict[str, Any], schema_path: Path) -> None:
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover - CI and the documented dev install include it
        raise RuntimeError("golden pilot schema validation requires the dev dependencies") from exc
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    ).validate(instance)


def _verify_private_bundle(bundle: Path) -> None:
    if stat.S_IMODE(bundle.stat().st_mode) != 0o700:
        raise AssertionError("golden pilot directory is not mode 0700")
    forbidden = [value.encode("utf-8") for value in FORBIDDEN_OUTPUT_FRAGMENTS]
    for path in bundle.iterdir():
        if not path.is_file() or path.is_symlink():
            raise AssertionError(f"unexpected non-regular golden pilot artifact: {path.name}")
        if stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise AssertionError(f"golden pilot artifact is not mode 0600: {path.name}")
        payload = path.read_bytes()
        if any(fragment in payload for fragment in forbidden):
            raise AssertionError(f"privacy regression detected in {path.name}")


def run_golden_pilot(
    output_dir: Path,
    *,
    fixture_dir: Path = DEFAULT_FIXTURE_DIR,
) -> Dict[str, Any]:
    """Run the locked synthetic pilot and return its aggregate verification receipt."""
    output_dir = Path(output_dir)
    fixture_dir = Path(fixture_dir)
    if output_dir.exists() or output_dir.is_symlink():
        raise FileExistsError(f"golden pilot output already exists: {output_dir}")

    fixture_set_sha256 = _verify_fixtures(fixture_dir)
    artifact_digest = detector_artifact_sha256("tfidf-logreg")
    if artifact_digest != EXPECTED_DETECTOR_SHA256:
        raise ValueError("bundled detector artifact changed from the golden pilot contract")

    with tempfile.TemporaryDirectory(prefix="lurescope-golden-plan-") as temporary:
        plan_path = Path(temporary) / "pilot-plan.json"
        create_pilot_plan(
            plan_path,
            plan_id="lurescope-golden-v1",
            detector="tfidf-logreg",
            threshold=0.5,
            min_processed_count=5,
            min_fraud_labels=4,
            min_benign_labels=1,
            max_uncertain_rate=0.0,
            max_processing_failure_rate=0.0,
            min_routing_recall_lower_bound=0.45,
            max_routing_false_positive_rate_upper_bound=0.96,
            max_routed_rate=0.8,
            max_routed_count=4,
            confidence=0.95,
            labeling_protocol="full_blinded_review",
        )
        run = run_shadow_inbox(
            [fixture_dir],
            output_dir,
            input_format="eml",
            detector_name="tfidf-logreg",
            threshold=0.5,
        )

        if (
            run.discovery.candidate_count != 6
            or run.discovery.duplicate_count != 1
            or run.inbox.summary["processed_count"] != 5
            or run.failed_count != 0
        ):
            raise AssertionError("golden pilot ingestion shape changed")

        observed_sources = set()
        for item in run.inbox.items:
            if item.status != "processed":
                raise AssertionError(f"golden fixture failed processing: {item.source}")
            name = Path(item.source).name
            if name not in EXPECTED_UNIQUE_FILES:
                raise AssertionError(f"unexpected deduplicated source survived: {name}")
            observed_sources.add(name)
            truth = FIXTURE_CONTRACT[name]
            append_analyst_label(
                output_dir,
                item.case_id,
                truth["label"],
                truth["reason"],
            )
        if observed_sources != EXPECTED_UNIQUE_FILES:
            raise AssertionError("golden pilot unique source mapping changed")

        gate = write_pilot_gate(output_dir, plan_path)

    if gate["verdict"] != "pass" or gate["failed_checks"]:
        raise AssertionError(f"golden pilot did not pass: {gate['failed_checks']}")
    if any(item["status"] != "pass" for item in gate["checks"]):
        raise AssertionError("golden pilot contains a non-passing registered check")

    metrics = gate["metrics"]
    expected_metrics = {
        "processed_count": 5,
        "failed_count": 0,
        "latest_label_count": 5,
        "fraud_label_count": 4,
        "benign_label_count": 1,
        "uncertain_label_count": 0,
        "routed_count": 4,
    }
    if any(metrics[key] != value for key, value in expected_metrics.items()):
        raise AssertionError("golden pilot aggregate metrics changed")
    if metrics["confusion"] != {
        "true_positive": 4,
        "false_positive": 0,
        "true_negative": 1,
        "false_negative": 0,
    }:
        raise AssertionError("golden pilot routing confusion changed")

    plan = json.loads((output_dir / "pilot-plan.json").read_text(encoding="utf-8"))
    _validate_schema(plan, ROOT / "spec" / "pilot-plan-v1.schema.json")
    _validate_schema(gate, ROOT / "spec" / "pilot-gate-v1.schema.json")
    _verify_private_bundle(output_dir)

    gate_bytes = (output_dir / "pilot-gate.json").read_bytes()
    receipt: Dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "schema_version": 1,
        "generated_at": _timestamp(),
        "status": "verified",
        "privacy": {
            "aggregate_only": True,
            "contains_case_identifiers": False,
            "contains_message_content": False,
        },
        "fixture_contract": {
            "version": 1,
            "fixture_set_sha256": fixture_set_sha256,
            "candidate_count": 6,
            "unique_count": 5,
            "duplicate_count": 1,
        },
        "control": {
            "detector": "tfidf-logreg",
            "detector_artifact_sha256": artifact_digest,
            "threshold": 0.5,
        },
        "bindings": {
            "plan_sha256": gate["plan_binding"]["sha256"],
            "manifest_sha256": gate["run_binding"]["manifest_sha256"],
            "labels_sha256": gate["run_binding"]["labels_sha256"],
            "gate_sha256": _sha256(gate_bytes),
        },
        "outcome": {
            "verdict": "pass",
            "processed_count": metrics["processed_count"],
            "fraud_label_count": metrics["fraud_label_count"],
            "benign_label_count": metrics["benign_label_count"],
            "routed_count": metrics["routed_count"],
            "routed_rate": metrics["routed_rate"],
            "routing_recall_lower_bound": metrics["routing_recall_lower_bound"],
            "routing_false_positive_rate_upper_bound": (
                metrics["routing_false_positive_rate_upper_bound"]
            ),
        },
        "verification": {
            "fixture_integrity": True,
            "ingestion_shape": True,
            "ground_truth_applied": True,
            "schemas_valid": True,
            "privacy_scan_passed": True,
            "registered_gate_passed": True,
        },
        "limitations": [
            "synthetic_fixture_not_representative",
            "demo_thresholds_not_for_deployment",
            "no_external_plan_registration",
        ],
    }
    _validate_schema(receipt, ROOT / "spec" / "golden-pilot-receipt-v1.schema.json")
    _write_new(
        output_dir / "golden-pilot-receipt.json",
        (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    _verify_private_bundle(output_dir)
    return receipt


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the locked, offline LureScope synthetic golden pilot."
    )
    parser.add_argument("--out", required=True, help="new private output directory")
    args = parser.parse_args(argv)
    try:
        receipt = run_golden_pilot(Path(args.out))
    except (
        AssertionError,
        FileExistsError,
        FileNotFoundError,
        OSError,
        RuntimeError,
        ValueError,
    ) as exc:
        print(f"! golden pilot failed: {exc}", file=sys.stderr)
        return 2
    print(f"GOLDEN PILOT VERIFIED: {receipt['outcome']['verdict'].upper()}")
    print(f"receipt: {Path(args.out) / 'golden-pilot-receipt.json'}")
    print("boundary: synthetic workflow verification only; not deployment evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
