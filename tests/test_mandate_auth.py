from __future__ import annotations

import base64
import copy
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

import lurescope.mandate_auth as mandate_auth
from lurescope.cli import main
from lurescope.mandate import _derive
from lurescope.mandate_auth import (
    AUTHENTICATION_SCHEMA,
    _expected_statements,
    create_authenticated_mandate_verification,
    load_authenticated_mandate_verification,
    sign_approval_statement,
    validate_authenticated_mandate_verification,
)
from lurescope.permit import _canonical

ROOT = Path(__file__).parents[1]
VECTOR = ROOT / "conformance" / "luremandate-v1"


def _load(name: str) -> dict:
    return json.loads((VECTOR / name).read_text(encoding="utf-8"))


def _registry() -> Registry:
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def _keys(tmp_path: Path, approvers: list[str]) -> tuple[dict[str, Path], dict[str, Path]]:
    private_paths, public_paths = {}, {}
    for approver_id in approvers:
        key = ec.generate_private_key(ec.SECP256R1())
        private_path = tmp_path / f"{approver_id}.private.pem"
        public_path = tmp_path / f"{approver_id}.public.pem"
        private_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        public_path.write_bytes(
            key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        private_paths[approver_id] = private_path
        public_paths[approver_id] = public_path
    return private_paths, public_paths


def _signed_evidence(tmp_path: Path) -> tuple[Path, dict[str, Path], dict[str, Path]]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    plan, run = _load("plan.json"), _load("run.json")
    statements = _expected_statements(plan, run)
    approvers = sorted({item["approval"]["approver_id"] for item in statements.values()})
    private_paths, public_paths = _keys(tmp_path, approvers)
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    statement_dir = tmp_path / "statements"
    statement_dir.mkdir()
    for approval_id, statement in statements.items():
        statement_path = statement_dir / f"{approval_id}.statement.json"
        statement_path.write_bytes(_canonical(statement))
        sign_approval_statement(
            statement_path,
            private_paths[statement["approval"]["approver_id"]],
            evidence / f"{approval_id}.dsse.json",
        )
    return evidence, private_paths, public_paths


def test_external_keys_authenticate_every_unique_approval_and_self_contain(tmp_path: Path):
    evidence, _, public_paths = _signed_evidence(tmp_path)
    output = tmp_path / "authenticated.json"
    result = create_authenticated_mandate_verification(
        VECTOR / "plan.json",
        VECTOR / "run.json",
        VECTOR / "evaluation.json",
        evidence,
        public_paths,
        output,
        verified_at="2026-09-05T15:19:00Z",
    )
    assert result["schema"] == AUTHENTICATION_SCHEMA
    assert result["summary"]["verdict"] == "pass"
    assert result["summary"]["authenticated_approval_count"] == 18
    assert result["summary"]["unique_approval_count"] == 18
    assert result["summary"]["approver_key_count"] == 4
    assert result["summary"]["distinct_approver_keys"] is True
    assert result["summary"]["transaction_authority_evidence_authenticated"] is True
    assert load_authenticated_mandate_verification(output) == result
    if os.name == "posix":
        assert output.stat().st_mode & 0o777 == 0o600

    schema = json.loads(
        (ROOT / "spec" / "luremandate-authenticated-verification-v1.schema.json").read_text()
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, registry=_registry(), format_checker=FormatChecker()).validate(
        result
    )


def test_public_authenticated_vector_reproduces_exactly(tmp_path: Path):
    key_directory = VECTOR / "keys"
    public_paths = {
        "approver-mission": key_directory / "approver-mission.public.pem",
        "approver-operator": key_directory / "approver-operator.public.pem",
        "approver-security": key_directory / "approver-security.public.pem",
        "requester-a": key_directory / "requester-a.public.pem",
    }
    result = create_authenticated_mandate_verification(
        VECTOR / "plan.json",
        VECTOR / "run.json",
        VECTOR / "evaluation.json",
        VECTOR / "evidence",
        public_paths,
        tmp_path / "authenticated.json",
        verified_at="2026-09-05T15:19:00Z",
    )
    assert result == _load("authenticated-verification.json")
    assert (
        load_authenticated_mandate_verification(VECTOR / "authenticated-verification.json")
        == result
    )


def test_signature_tampering_wrong_key_mapping_and_missing_evidence_fail_closed(tmp_path: Path):
    evidence, _, public_paths = _signed_evidence(tmp_path)
    envelope_path = sorted(evidence.iterdir())[0]
    envelope = json.loads(envelope_path.read_text())
    signature = bytearray(base64.b64decode(envelope["signatures"][0]["sig"]))
    signature[-1] ^= 1
    envelope["signatures"][0]["sig"] = base64.b64encode(signature).decode()
    envelope_path.write_bytes(_canonical(envelope))
    with pytest.raises(ValueError, match="signature verification failed"):
        create_authenticated_mandate_verification(
            VECTOR / "plan.json",
            VECTOR / "run.json",
            VECTOR / "evaluation.json",
            evidence,
            public_paths,
            tmp_path / "tampered.json",
            verified_at="2026-09-05T15:19:00Z",
        )

    evidence, _, public_paths = _signed_evidence(tmp_path / "fresh")
    public_paths["approver-security"] = public_paths["approver-mission"]
    with pytest.raises(ValueError, match="distinct public key"):
        create_authenticated_mandate_verification(
            VECTOR / "plan.json",
            VECTOR / "run.json",
            VECTOR / "evaluation.json",
            evidence,
            public_paths,
            tmp_path / "same-key.json",
            verified_at="2026-09-05T15:19:00Z",
        )

    public_paths = _signed_evidence(tmp_path / "missing")[2]
    missing_evidence = tmp_path / "missing" / "evidence"
    sorted(missing_evidence.iterdir())[0].unlink()
    with pytest.raises(ValueError, match="does not exactly match"):
        create_authenticated_mandate_verification(
            VECTOR / "plan.json",
            VECTOR / "run.json",
            VECTOR / "evaluation.json",
            missing_evidence,
            public_paths,
            tmp_path / "missing.json",
            verified_at="2026-09-05T15:19:00Z",
        )


def test_authenticated_semantic_failure_remains_failure(tmp_path: Path):
    evidence, _, public_paths = _signed_evidence(tmp_path)
    plan, run = _load("plan.json"), _load("run.json")
    transaction = run["transactions"][9]
    transaction["decision"]["decision"] = "allow"
    transaction["outcome"] = {
        "state": "effect_observed",
        "observed_at": "2026-09-05T15:09:30Z",
        "sensor_id": "authority-effect-sensor",
    }
    evaluation = _derive(plan, run, "2026-09-05T15:17:00Z")
    run_path, evaluation_path = tmp_path / "changed-run.json", tmp_path / "changed-eval.json"
    run_path.write_bytes(_canonical(run))
    evaluation_path.write_bytes(_canonical(evaluation))
    result = create_authenticated_mandate_verification(
        VECTOR / "plan.json",
        run_path,
        evaluation_path,
        evidence,
        public_paths,
        tmp_path / "failed-authenticated.json",
        verified_at="2026-09-05T15:19:00Z",
    )
    assert result["summary"]["approval_authentication_complete"] is True
    assert result["summary"]["verdict"] == "fail"
    assert result["summary"]["transaction_authority_evidence_authenticated"] is False


def test_self_contained_key_envelope_and_summary_tampering_is_rejected(tmp_path: Path):
    evidence, _, public_paths = _signed_evidence(tmp_path)
    output = tmp_path / "authenticated.json"
    result = create_authenticated_mandate_verification(
        VECTOR / "plan.json",
        VECTOR / "run.json",
        VECTOR / "evaluation.json",
        evidence,
        public_paths,
        output,
        verified_at="2026-09-05T15:19:00Z",
    )
    changed = copy.deepcopy(result)
    changed["summary"]["authenticated_approval_count"] = 17
    with pytest.raises(ValueError, match="does not reproduce"):
        validate_authenticated_mandate_verification(changed)

    changed = copy.deepcopy(result)
    pem = bytearray(base64.b64decode(changed["public_keys"][0]["pem_base64"]))
    pem[-2] ^= 1
    changed["public_keys"][0]["pem_base64"] = base64.b64encode(pem).decode()
    with pytest.raises(ValueError, match="PEM public key|binding is inconsistent"):
        validate_authenticated_mandate_verification(changed)


def test_oversized_generated_report_is_rejected_before_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    evidence, _, public_paths = _signed_evidence(tmp_path)
    output = tmp_path / "oversized.json"
    monkeypatch.setattr(mandate_auth, "MAX_REPORT_BYTES", 128)
    with pytest.raises(ValueError, match="exceeds the report limit"):
        create_authenticated_mandate_verification(
            VECTOR / "plan.json",
            VECTOR / "run.json",
            VECTOR / "evaluation.json",
            evidence,
            public_paths,
            output,
            verified_at="2026-09-05T15:19:00Z",
        )
    assert not output.exists()


def test_cli_sign_authenticate_check_and_overwrite_refusal(tmp_path: Path):
    plan, run = _load("plan.json"), _load("run.json")
    statements = _expected_statements(plan, run)
    approvers = sorted({item["approval"]["approver_id"] for item in statements.values()})
    private_paths, public_paths = _keys(tmp_path, approvers)
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    for approval_id, statement in statements.items():
        statement_path = tmp_path / f"{approval_id}.statement.json"
        statement_path.write_bytes(_canonical(statement))
        args = [
            "mandate",
            "sign",
            str(statement_path),
            "--private-key",
            str(private_paths[statement["approval"]["approver_id"]]),
            "--out",
            str(evidence / f"{approval_id}.dsse.json"),
        ]
        assert main(args) == 0
    output = tmp_path / "authenticated.json"
    args = [
        "mandate",
        "authenticate",
        str(VECTOR / "plan.json"),
        str(VECTOR / "run.json"),
        str(VECTOR / "evaluation.json"),
        str(evidence),
    ]
    for approver_id, path in public_paths.items():
        args.extend(["--approver-key", f"{approver_id}={path}"])
    args.extend(["--verified-at", "2026-09-05T15:19:00Z", "--out", str(output)])
    assert main(args) == 0
    assert main(["mandate", "check-auth", str(output)]) == 0
    assert main(args) == 2
