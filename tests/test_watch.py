"""LureWatch statistical validity, privacy, integrity, and CLI tests."""

from __future__ import annotations

import hashlib
import itertools
import json
import math
import os
from pathlib import Path

import jsonschema
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from lurescope.cli import main
from lurescope.watch import (
    CHECKPOINTS_DIRECTORY,
    ENTRIES_DIRECTORY,
    PLAN_FILE,
    MonitorCount,
    MonitorSpec,
    append_monitor_batch,
    canonical_json,
    confusion_counts,
    create_monitor_bundle,
    default_monitors,
    mixture_log_e_value,
    verify_monitor_bundle,
)

ROOT = Path(__file__).parents[1]
CREATED = "2026-08-27T12:00:00Z"


def _keypair() -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private, public


def _create(path: Path, *, public_key: bytes | None = None):
    return create_monitor_bundle(
        path,
        plan_id="agency-fraud-monitor-v1",
        detector="tfidf-logreg",
        detector_artifact_sha256="a" * 64,
        threshold=0.5,
        policy_id="risk-policy-v2",
        policy_sha256="b" * 64,
        monitors=default_monitors(0.05, 0.10),
        family_alpha=0.05,
        sampling="random_sample",
        labeling_protocol="dual-review-v1",
        signer_public_key_pem=public_key,
        created_at=CREATED,
    )


def _append(
    path: Path,
    batch_id: str,
    *,
    tp: int,
    fp: int,
    tn: int,
    fn: int,
    private_key: bytes | None = None,
    source_commitment: str | None = None,
):
    return append_monitor_batch(
        path,
        batch_id=batch_id,
        counts=confusion_counts(
            true_positive=tp,
            false_positive=fp,
            true_negative=tn,
            false_negative=fn,
        ),
        observed_at=CREATED,
        generated_at=CREATED,
        source_commitment_sha256=source_commitment
        or hashlib.sha256(batch_id.encode()).hexdigest(),
        signing_key_pem=private_key,
    )


def test_mixture_eprocess_has_exact_anytime_false_alarm_control():
    """Enumerate every Bernoulli path; no Monte Carlo or flaky tolerance is used."""

    risk_limit = 0.20
    alpha = 0.20
    horizon = 12
    false_alarm_probability = 0.0
    for path in itertools.product((0, 1), repeat=horizon):
        events = 0
        crossed = False
        for trials, outcome in enumerate(path, start=1):
            events += outcome
            if mixture_log_e_value(events, trials, risk_limit) >= -math.log(alpha):
                crossed = True
                break
        if crossed:
            total_events = sum(path)
            false_alarm_probability += (
                risk_limit**total_events
                * (1.0 - risk_limit) ** (horizon - total_events)
            )
    assert false_alarm_probability <= alpha + 1e-12
    assert false_alarm_probability == pytest.approx(0.016167276544)

    # The same fixed family has useful power against material deterioration.
    assert mixture_log_e_value(20, 100, 0.05) > -math.log(0.025)
    assert mixture_log_e_value(30, 100, 0.10) > -math.log(0.025)
    assert mixture_log_e_value(0, 0, 0.05) == 0
    with pytest.raises(ValueError, match="events cannot exceed trials"):
        mixture_log_e_value(2, 1, 0.05)


def test_unsigned_bundle_recomputes_chain_schemas_and_sticky_breach(tmp_path):
    bundle = tmp_path / "watch"
    plan = _create(bundle)
    initial = verify_monitor_bundle(bundle)
    assert initial["entry_count"] == 0
    assert initial["authenticated"] is False

    first = _append(bundle, "week-001", tp=95, fp=1, tn=99, fn=5)
    assert first["family_status"] == "monitoring"
    second = _append(bundle, "week-002", tp=60, fp=30, tn=70, fn=40)
    assert second["family_status"] == "breach"
    breached = {
        state["monitor_id"] for state in second["states"] if state["status"] == "breach"
    }
    assert breached == {"overall-fnr", "overall-fpr"}

    # Once the anytime alarm crossed, a later favorable batch cannot erase history.
    third = _append(bundle, "week-003", tp=1000, fp=0, tn=1000, fn=0)
    assert third["family_status"] == "breach"
    assert all(state["status"] == "breach" for state in third["states"])
    result = verify_monitor_bundle(bundle)
    assert result["valid"] is True
    assert result["entry_count"] == 3
    assert result["family_status"] == "breach"
    assert result["latest_statement_sha256"] == hashlib.sha256(
        (bundle / CHECKPOINTS_DIRECTORY / "00000003.statement.json").read_bytes()
    ).hexdigest()

    schemas = {
        "lurewatch-plan-v1.schema.json": plan,
        "lurewatch-entry-v1.schema.json": third,
        "lurewatch-checkpoint-v1.schema.json": json.loads(
            (bundle / CHECKPOINTS_DIRECTORY / "00000003.statement.json").read_text()
        ),
    }
    for name, artifact in schemas.items():
        schema = json.loads((ROOT / "spec" / name).read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.FormatChecker()
        ).validate(artifact)

    serialized = b"".join(path.read_bytes() for path in bundle.rglob("*.json"))
    for forbidden in (b"sender@example", b"message body", b"case-001", b"per-user"):
        assert forbidden not in serialized.lower()
    if os.name == "posix":
        assert bundle.stat().st_mode & 0o777 == 0o700
        assert (bundle / ENTRIES_DIRECTORY).stat().st_mode & 0o777 == 0o700
        assert (bundle / CHECKPOINTS_DIRECTORY).stat().st_mode & 0o777 == 0o700
        assert all(path.stat().st_mode & 0o777 == 0o600 for path in bundle.rglob("*.json"))


def test_signed_bundle_authenticates_every_checkpoint_and_rejects_wrong_key(tmp_path):
    private, public = _keypair()
    wrong_private, wrong_public = _keypair()
    bundle = tmp_path / "signed-watch"
    _create(bundle, public_key=public)

    with pytest.raises(ValueError, match="requires a signing key"):
        _append(bundle, "week-001", tp=95, fp=1, tn=99, fn=5)
    with pytest.raises(ValueError, match="does not match"):
        _append(
            bundle,
            "week-001",
            tp=95,
            fp=1,
            tn=99,
            fn=5,
            private_key=wrong_private,
        )
    _append(bundle, "week-001", tp=95, fp=1, tn=99, fn=5, private_key=private)
    verified = verify_monitor_bundle(bundle, public_key_pem=public)
    assert verified["authenticated"] is True
    assert len(verified["key_ids"]) == 1
    with pytest.raises(ValueError, match="external public key"):
        verify_monitor_bundle(bundle)
    with pytest.raises(ValueError, match="not the signer"):
        verify_monitor_bundle(bundle, public_key_pem=wrong_public)

    envelope_path = bundle / CHECKPOINTS_DIRECTORY / "00000001.dsse.json"
    envelope = json.loads(envelope_path.read_text())
    envelope["signatures"][0]["sig"] = envelope["signatures"][0]["sig"][:-4] + "AAAA"
    envelope_path.write_bytes(canonical_json(envelope))
    with pytest.raises(ValueError, match="signature"):
        verify_monitor_bundle(bundle, public_key_pem=public)


def test_monitor_fails_closed_on_tampering_duplicates_and_plan_changes(tmp_path):
    bundle = tmp_path / "watch"
    _create(bundle)
    _append(bundle, "week-001", tp=95, fp=1, tn=99, fn=5)
    with pytest.raises(ValueError, match="already submitted"):
        _append(bundle, "week-001", tp=95, fp=1, tn=99, fn=5)
    with pytest.raises(ValueError, match="source commitment was already submitted"):
        _append(
            bundle,
            "week-002",
            tp=95,
            fp=1,
            tn=99,
            fn=5,
            source_commitment=hashlib.sha256(b"week-001").hexdigest(),
        )
    assert verify_monitor_bundle(bundle)["entry_count"] == 1

    entry_path = bundle / ENTRIES_DIRECTORY / "00000001.json"
    entry = json.loads(entry_path.read_text())
    entry["batch"]["counts"][0]["events"] += 1
    entry_path.write_bytes(canonical_json(entry))
    with pytest.raises(ValueError, match="does not recompute"):
        verify_monitor_bundle(bundle)

    clean = tmp_path / "plan-tamper"
    _create(clean)
    plan_path = clean / PLAN_FILE
    altered = json.loads(plan_path.read_text())
    altered["compliant"] = True
    plan_path.write_bytes(canonical_json(altered))
    with pytest.raises(ValueError, match="allowlist"):
        verify_monitor_bundle(clean)

    gap = tmp_path / "gap"
    _create(gap)
    _append(gap, "week-001", tp=95, fp=1, tn=99, fn=5)
    (gap / CHECKPOINTS_DIRECTORY / "00000001.statement.json").rename(
        gap / CHECKPOINTS_DIRECTORY / "00000002.statement.json"
    )
    with pytest.raises(ValueError, match="gap"):
        verify_monitor_bundle(gap)

    duplicate = tmp_path / "duplicate-json"
    _create(duplicate)
    plan_path = duplicate / PLAN_FILE
    plan_path.write_bytes(b'{"schema":"first","schema":"second"}\n')
    with pytest.raises(ValueError, match="duplicate key"):
        verify_monitor_bundle(duplicate)

    nonfinite = tmp_path / "nonfinite"
    _create(nonfinite)
    _append(nonfinite, "week-001", tp=95, fp=1, tn=99, fn=5)
    state_path = nonfinite / ENTRIES_DIRECTORY / "00000001.json"
    state_raw = state_path.read_text()
    state_path.write_text(state_raw.replace('"log_e_value":-0.', '"log_e_value":NaN,"x":-0.', 1))
    state_path.chmod(0o600)
    with pytest.raises(ValueError, match="non-standard JSON constant"):
        verify_monitor_bundle(nonfinite)

    unexpected = tmp_path / "unexpected"
    _create(unexpected)
    extra = unexpected / "telemetry.csv"
    extra.write_text("should not be here", encoding="utf-8")
    extra.chmod(0o600)
    with pytest.raises(ValueError, match="unexpected artifacts"):
        verify_monitor_bundle(unexpected)

    if os.name == "posix":
        permissions = tmp_path / "permissions"
        _create(permissions)
        (permissions / PLAN_FILE).chmod(0o644)
        with pytest.raises(ValueError, match="group or world access"):
            verify_monitor_bundle(permissions)

        symlinked = tmp_path / "symlinked"
        _create(symlinked)
        source = tmp_path / "outside.json"
        source.write_text("{}", encoding="utf-8")
        source.chmod(0o600)
        (symlinked / PLAN_FILE).unlink()
        (symlinked / PLAN_FILE).symlink_to(source)
        with pytest.raises(ValueError, match="symbolic-link"):
            verify_monitor_bundle(symlinked)


def test_generic_slice_family_and_count_contract(tmp_path):
    bundle = tmp_path / "slices"
    monitors = [
        MonitorSpec("fnr.language.es", "false_negative_rate", 0.15, "language", "es"),
        MonitorSpec("fpr.overall", "false_positive_rate", 0.02),
    ]
    create_monitor_bundle(
        bundle,
        plan_id="slice-monitor",
        detector="heuristic-v0",
        threshold=0.5,
        monitors=monitors,
        family_alpha=0.04,
        created_at=CREATED,
    )
    entry = append_monitor_batch(
        bundle,
        batch_id="slice-week-1",
        counts=[
            MonitorCount("fpr.overall", 1, 100),
            MonitorCount("fnr.language.es", 3, 40),
        ],
        observed_at=CREATED,
        generated_at=CREATED,
    )
    assert [state["monitor_id"] for state in entry["states"]] == [
        "fnr.language.es",
        "fpr.overall",
    ]
    assert all(state["per_monitor_alpha"] == 0.02 for state in entry["states"])
    with pytest.raises(ValueError, match="each predeclared monitor"):
        append_monitor_batch(
            bundle,
            batch_id="incomplete",
            counts=[MonitorCount("fpr.overall", 0, 1)],
            observed_at=CREATED,
            generated_at=CREATED,
        )


def test_plan_rejects_numerically_unsafe_and_duplicate_monitor_declarations(tmp_path):
    with pytest.raises(ValueError, match="risk_limit must be between"):
        mixture_log_e_value(0, 1, 1e-10)
    with pytest.raises(ValueError, match="family_alpha must be between"):
        create_monitor_bundle(
            tmp_path / "unsafe-alpha",
            plan_id="unsafe-alpha",
            detector="test-detector",
            threshold=0.5,
            monitors=default_monitors(0.05, 0.10),
            family_alpha=1e-10,
            created_at=CREATED,
        )
    with pytest.raises(ValueError, match="each metric and slice population"):
        create_monitor_bundle(
            tmp_path / "duplicate-population",
            plan_id="duplicate-population",
            detector="test-detector",
            threshold=0.5,
            monitors=[
                MonitorSpec(
                    "fpr.overall.primary",
                    "false_positive_rate",
                    0.05,
                ),
                MonitorSpec(
                    "fpr.overall.secondary",
                    "false_positive_rate",
                    0.10,
                ),
            ],
            created_at=CREATED,
        )


def test_monitor_cli_happy_path_and_breach_exit_code(tmp_path, capsys):
    bundle = tmp_path / "cli-watch"
    assert (
        main(
            [
                "monitor",
                "init",
                "--out",
                str(bundle),
                "--plan-id",
                "cli-monitor",
                "--fpr-limit",
                "0.05",
                "--fnr-limit",
                "0.10",
            ]
        )
        == 0
    )
    assert "LUREWATCH PLAN CREATED" in capsys.readouterr().out
    assert (
        main(
            [
                "monitor",
                "append",
                str(bundle),
                "--batch-id",
                "week-001",
                "--true-positive",
                "70",
                "--false-positive",
                "20",
                "--true-negative",
                "80",
                "--false-negative",
                "30",
            ]
        )
        == 1
    )
    assert "BREACH" in capsys.readouterr().out
    assert main(["monitor", "verify", str(bundle), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["valid"] is True
    assert result["family_status"] == "breach"

    assert (
        main(
            [
                "monitor",
                "append",
                str(bundle),
                "--batch-id",
                "bad",
                "--true-positive",
                "1",
                "--false-positive",
                "2",
                "--true-negative",
                "-1",
                "--false-negative",
                "0",
            ]
        )
        == 2
    )
    assert "LureWatch failed" in capsys.readouterr().err
