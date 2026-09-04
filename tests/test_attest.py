from __future__ import annotations

import ast
import base64
import copy
import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from lurescope.attest import (
    VERIFICATION_SCHEMA,
    compose_attest_plan,
    create_attest_verification,
    load_attest_verification,
    validate_attest_verification,
)
from lurescope.cli import main
from lurescope.permit import _canonical

ROOT = Path(__file__).parents[1]
VECTOR = ROOT / "conformance" / "lureattest-v1"


def _load(name: str) -> dict:
    return json.loads((VECTOR / name).read_text(encoding="utf-8"))


def _write(path: Path, value: dict) -> None:
    path.write_bytes(_canonical(value))


def _registry() -> Registry:
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def _verify(tmp_path: Path | None = None) -> dict:
    output = None if tmp_path is None else tmp_path / "verification.json"
    return create_attest_verification(
        VECTOR / "artifact-plan.json",
        VECTOR / "trust-policy.json",
        VECTOR / "plan.json",
        VECTOR / "evidence",
        [VECTOR / "trusted-public-key.pem"],
        output,
        verified_at="2026-09-04T16:02:00Z",
    )


def test_public_vector_authenticates_all_provenance_and_report_recomputes(tmp_path: Path):
    report = _verify(tmp_path)
    assert report["schema"] == VERIFICATION_SCHEMA
    assert report["summary"] == {
        "workload_count": 1,
        "attestation_count": 3,
        "authenticated_attestation_count": 3,
        "expectation_match_count": 3,
        "minimum_policy_slsa_build_level": 2,
        "finding_count": 0,
        "verdict": "pass",
    }
    assert len(report["checks"]) == 12
    assert all(item["status"] == "pass" for item in report["checks"])
    assert validate_attest_verification(report) == report
    assert load_attest_verification(tmp_path / "verification.json") == report
    if os.name == "posix":
        assert (tmp_path / "verification.json").stat().st_mode & 0o777 == 0o600


def test_report_and_shared_sources_validate_against_draft_2020_12_schema():
    report = _verify()
    schema = json.loads(
        (ROOT / "spec" / "lureattest-verification-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(
        schema, registry=_registry(), format_checker=FormatChecker()
    ).validate(report)


def test_signature_payload_and_key_tampering_fail_closed(tmp_path: Path):
    evidence = tmp_path / "evidence"
    shutil.copytree(VECTOR / "evidence", evidence)
    path = next(evidence.iterdir())
    envelope = json.loads(path.read_text(encoding="utf-8"))
    signature = bytearray(base64.b64decode(envelope["signatures"][0]["sig"]))
    signature[-1] ^= 1
    envelope["signatures"][0]["sig"] = base64.b64encode(signature).decode("ascii")
    _write(path, envelope)
    with pytest.raises(ValueError, match="signature verification failed"):
        create_attest_verification(
            VECTOR / "artifact-plan.json",
            VECTOR / "trust-policy.json",
            VECTOR / "plan.json",
            evidence,
            [VECTOR / "trusted-public-key.pem"],
            verified_at="2026-09-04T16:02:00Z",
        )

    wrong = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    wrong_path = tmp_path / "wrong.pem"
    wrong_path.write_bytes(wrong)
    with pytest.raises(ValueError, match="exactly match"):
        create_attest_verification(
            VECTOR / "artifact-plan.json",
            VECTOR / "trust-policy.json",
            VECTOR / "plan.json",
            VECTOR / "evidence",
            [wrong_path],
            verified_at="2026-09-04T16:02:00Z",
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("external_parameters_sha256", "0" * 64, "externalParameters"),
        ("source_uri", "https://github.com/example/wrong-source", "source URI"),
    ],
)
def test_authenticated_payload_must_meet_source_and_parameter_expectations(
    tmp_path: Path, field: str, value: str, message: str
):
    artifact_plan = _load("artifact-plan.json")
    policy = _load("trust-policy.json")
    policy["attestation_expectations"][0][field] = value
    plan = compose_attest_plan(artifact_plan, policy)
    policy_path = tmp_path / "policy.json"
    plan_path = tmp_path / "plan.json"
    _write(policy_path, policy)
    _write(plan_path, plan)
    with pytest.raises(ValueError, match=message):
        create_attest_verification(
            VECTOR / "artifact-plan.json",
            policy_path,
            plan_path,
            VECTOR / "evidence",
            [VECTOR / "trusted-public-key.pem"],
            verified_at="2026-09-04T16:02:00Z",
        )


def test_statement_digest_builder_and_build_type_are_not_self_asserted(tmp_path: Path):
    for field, value, message in (
        ("statement_sha256", "0" * 64, "statement bytes"),
        ("builder_id", "https://builder.example.invalid", "expected builder"),
        ("build_type", "https://builder.example.invalid/build/v2", "buildType"),
    ):
        artifact_plan = _load("artifact-plan.json")
        policy = _load("trust-policy.json")
        if field == "builder_id":
            for attestation in artifact_plan["workloads"][0]["attestations"]:
                attestation[field] = value
            artifact_plan["policy"]["approved_builder_ids"] = [value]
            policy["trusted_builders"][0]["builder_id"] = value
        else:
            artifact_plan["workloads"][0]["attestations"][0][field] = value
        policy["artifact_plan_sha256"] = hashlib.sha256(_canonical(artifact_plan)).hexdigest()
        plan = compose_attest_plan(artifact_plan, policy)
        artifact_path = tmp_path / f"artifact-{field}.json"
        policy_path = tmp_path / f"policy-{field}.json"
        plan_path = tmp_path / f"plan-{field}.json"
        _write(artifact_path, artifact_plan)
        _write(policy_path, policy)
        _write(plan_path, plan)
        with pytest.raises(ValueError, match=message):
            create_attest_verification(
                artifact_path,
                policy_path,
                plan_path,
                VECTOR / "evidence",
                [VECTOR / "trusted-public-key.pem"],
                verified_at="2026-09-04T16:02:00Z",
            )


def test_evidence_directory_is_exact_and_symlinks_are_rejected(tmp_path: Path):
    evidence = tmp_path / "evidence"
    shutil.copytree(VECTOR / "evidence", evidence)
    (evidence / "unexpected.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="more files|exactly"):
        create_attest_verification(
            VECTOR / "artifact-plan.json",
            VECTOR / "trust-policy.json",
            VECTOR / "plan.json",
            evidence,
            [VECTOR / "trusted-public-key.pem"],
            verified_at="2026-09-04T16:02:00Z",
        )
    (evidence / "unexpected.json").unlink()
    target = next(evidence.iterdir())
    original = target.read_bytes()
    target.unlink()
    external = tmp_path / "external.json"
    external.write_bytes(original)
    target.symlink_to(external)
    with pytest.raises(ValueError, match="non-symlink"):
        create_attest_verification(
            VECTOR / "artifact-plan.json",
            VECTOR / "trust-policy.json",
            VECTOR / "plan.json",
            evidence,
            [VECTOR / "trusted-public-key.pem"],
            verified_at="2026-09-04T16:02:00Z",
        )


def test_dsse_keyid_is_only_a_hint_and_urlsafe_base64_is_supported(tmp_path: Path):
    evidence = tmp_path / "evidence"
    shutil.copytree(VECTOR / "evidence", evidence)
    for path in evidence.iterdir():
        envelope = json.loads(path.read_text(encoding="utf-8"))
        envelope["signatures"][0]["keyid"] = "deliberately-untrusted-hint"
        envelope["payload"] = base64.urlsafe_b64encode(
            base64.b64decode(envelope["payload"])
        ).decode("ascii")
        envelope["signatures"][0]["sig"] = base64.urlsafe_b64encode(
            base64.b64decode(envelope["signatures"][0]["sig"])
        ).decode("ascii")
        _write(path, envelope)
    report = create_attest_verification(
        VECTOR / "artifact-plan.json",
        VECTOR / "trust-policy.json",
        VECTOR / "plan.json",
        evidence,
        [VECTOR / "trusted-public-key.pem"],
        verified_at="2026-09-04T16:02:00Z",
    )
    assert report["overall_status"] == "pass"


def test_report_tampering_and_predated_verification_are_rejected(tmp_path: Path):
    report = _verify()
    tampered = copy.deepcopy(report)
    tampered["summary"]["attestation_count"] = 2
    with pytest.raises(ValueError, match="does not independently recompute"):
        validate_attest_verification(tampered)

    with pytest.raises(ValueError, match="predates"):
        create_attest_verification(
            VECTOR / "artifact-plan.json",
            VECTOR / "trust-policy.json",
            VECTOR / "plan.json",
            VECTOR / "evidence",
            [VECTOR / "trusted-public-key.pem"],
            verified_at="2026-09-04T15:59:59Z",
        )


def test_cli_verifies_and_refuses_report_overwrite(tmp_path: Path):
    output = tmp_path / "verification.json"
    args = [
        "attest",
        "verify",
        str(VECTOR / "artifact-plan.json"),
        str(VECTOR / "trust-policy.json"),
        str(VECTOR / "plan.json"),
        str(VECTOR / "evidence"),
        "--public-key",
        str(VECTOR / "trusted-public-key.pem"),
        "--verified-at",
        "2026-09-04T16:02:00Z",
        "--out",
        str(output),
    ]
    assert main(args) == 0
    assert main(args) == 2
    assert main(["attest", "check", str(output)]) == 0


def test_cli_prints_key_and_external_parameter_commitments(tmp_path: Path, capsys):
    assert main(["attest", "key-id", str(VECTOR / "trusted-public-key.pem")]) == 0
    assert (
        capsys.readouterr().out.strip()
        == "f002e49a5d224087f173025d9c42a5329e0dc922ef561b118c6173a565a48769"
    )
    parameters = tmp_path / "parameters.json"
    parameters.write_text('{"b":2,"a":1}\n', encoding="utf-8")
    assert main(["attest", "commit-external-parameters", str(parameters)]) == 0
    expected = hashlib.sha256(b'{"a":1,"b":2}\n').hexdigest()
    assert capsys.readouterr().out.strip() == expected


def test_independent_verifier_imports_no_lurebench_code():
    tree = ast.parse((ROOT / "lurescope" / "attest.py").read_text(encoding="utf-8"))
    imports = [
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    ]
    assert not any(name == "lurebench" or name.startswith("lurebench.") for name in imports)
