from __future__ import annotations

import ast
import base64
import hashlib
import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from lurescope.bom import (
    VERIFICATION_SCHEMA,
    create_bom_verification,
    load_bom_verification,
    project_bom,
    reconcile_boms,
    validate_bom_verification,
)
from lurescope.cli import main

ROOT = Path(__file__).parents[1]
VECTOR = ROOT / "conformance" / "lurebom-v1"


def _load(name: str) -> dict:
    return json.loads((VECTOR / name).read_text(encoding="utf-8"))


def _bytes(name: str) -> bytes:
    return (VECTOR / name).read_bytes()


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def _registry() -> Registry:
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def test_public_verification_vector_reparses_bytes_and_validates_schema(tmp_path: Path):
    expected = _load("verification.json")
    output = tmp_path / "verification.json"
    actual = create_bom_verification(
        VECTOR / "artifact-plan.json",
        VECTOR / "manifest.json",
        VECTOR / "evaluation.json",
        VECTOR / "cyclonedx-1.7.json",
        VECTOR / "spdx-3.0.1.json",
        output,
        verified_at="2026-09-05T00:04:00Z",
    )
    assert actual == expected
    assert load_bom_verification(output) == expected
    assert expected["summary"]["raw_documents_reparsed"] is True
    assert expected["summary"]["producer_evaluation_reproduced"] is True
    assert expected["summary"]["semantic_parity"] is True
    if os.name == "posix":
        assert output.stat().st_mode & 0o777 == 0o600

    schema = json.loads(
        (ROOT / "spec" / "lurebom-verification-v1.schema.json").read_text(encoding="utf-8")
    )
    assert schema["$id"] == VERIFICATION_SCHEMA
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, registry=_registry(), format_checker=FormatChecker()).validate(
        expected
    )


def test_independent_projection_matches_published_source_projections():
    evaluation = _load("evaluation.json")
    assert (
        project_bom(_bytes("cyclonedx-1.7.json"), "cyclonedx-1.7")
        == evaluation["projections"]["cyclonedx"]
    )
    assert project_bom(_bytes("spdx-3.0.1.json"), "spdx-3.0.1") == evaluation["projections"]["spdx"]


def test_non_sha256_hashes_are_disclosed_as_projection_loss():
    cyclonedx = _load("cyclonedx-1.7.json")
    cyclonedx["components"][0]["hashes"].append({"alg": "SHA-1", "content": "1" * 40})
    projection = project_bom(_json_bytes(cyclonedx), "cyclonedx-1.7")
    assert "$.components[0].hashes[1]" in projection["ignored_field_paths"]

    spdx = _load("spdx-3.0.1.json")
    package_index = next(
        index
        for index, element in enumerate(spdx["@graph"])
        if element.get("type") == "ai_AIPackage"
    )
    spdx["@graph"][package_index]["verifiedUsing"].append(
        {"type": "Hash", "algorithm": "sha1", "hashValue": "1" * 40}
    )
    projection = project_bom(_json_bytes(spdx), "spdx-3.0.1")
    assert f"$.@graph[{package_index}].verifiedUsing[1]" in projection["ignored_field_paths"]


def test_source_byte_tampering_cannot_be_hidden_by_the_producer(tmp_path: Path):
    cyclonedx = _load("cyclonedx-1.7.json")
    cyclonedx["components"][0]["name"] = "tampered-name"
    cyclonedx_path = tmp_path / "cyclonedx.json"
    cyclonedx_path.write_bytes(_json_bytes(cyclonedx))
    output = tmp_path / "verification.json"
    with pytest.raises(ValueError, match="reviewed document"):
        create_bom_verification(
            VECTOR / "artifact-plan.json",
            VECTOR / "manifest.json",
            VECTOR / "evaluation.json",
            cyclonedx_path,
            VECTOR / "spdx-3.0.1.json",
            output,
            verified_at="2026-09-05T00:04:00Z",
        )
    assert not output.exists()


def test_producer_projection_or_summary_tampering_is_rejected(tmp_path: Path):
    evaluation = _load("evaluation.json")
    evaluation["summary"]["ignored_field_count"] -= 1
    evaluation_path = tmp_path / "evaluation.json"
    _write(evaluation_path, evaluation)
    with pytest.raises(ValueError, match="does not independently reconcile"):
        create_bom_verification(
            VECTOR / "artifact-plan.json",
            VECTOR / "manifest.json",
            evaluation_path,
            VECTOR / "cyclonedx-1.7.json",
            VECTOR / "spdx-3.0.1.json",
            tmp_path / "verification.json",
            verified_at="2026-09-05T00:04:00Z",
        )


def test_self_contained_report_rejects_embedded_payload_tampering():
    verification = _load("verification.json")
    payload = bytearray(base64.b64decode(verification["documents"]["cyclonedx"]["payload_base64"]))
    payload[-2] ^= 1
    verification["documents"]["cyclonedx"]["payload_base64"] = base64.b64encode(payload).decode()
    with pytest.raises(ValueError, match="digest does not match"):
        validate_bom_verification(verification)

    verification = _load("verification.json")
    verification["documents"]["spdx"]["payload_base64"] += "="
    with pytest.raises(ValueError, match="base64"):
        validate_bom_verification(verification)


def test_valid_semantic_drift_is_preserved_as_a_verified_failure(tmp_path: Path):
    artifact_plan = _load("artifact-plan.json")
    manifest = _load("manifest.json")
    cyclonedx = _load("cyclonedx-1.7.json")
    cyclonedx["components"][3]["hashes"][0]["content"] = "8" * 64
    cyclonedx_payload = _json_bytes(cyclonedx)
    manifest["cyclonedx_document_sha256"] = hashlib.sha256(cyclonedx_payload).hexdigest()
    evaluation = reconcile_boms(
        artifact_plan,
        manifest,
        cyclonedx_payload,
        _bytes("spdx-3.0.1.json"),
        evaluated_at="2026-09-05T00:03:00Z",
    )
    assert evaluation["summary"]["verdict"] == "fail"

    plan_path = tmp_path / "plan.json"
    manifest_path = tmp_path / "manifest.json"
    evaluation_path = tmp_path / "evaluation.json"
    cyclonedx_path = tmp_path / "cyclonedx.json"
    _write(plan_path, artifact_plan)
    _write(manifest_path, manifest)
    _write(evaluation_path, evaluation)
    cyclonedx_path.write_bytes(cyclonedx_payload)
    report = create_bom_verification(
        plan_path,
        manifest_path,
        evaluation_path,
        cyclonedx_path,
        VECTOR / "spdx-3.0.1.json",
        tmp_path / "verification.json",
        verified_at="2026-09-05T00:04:00Z",
    )
    assert report["summary"]["semantic_parity"] is False
    assert report["summary"]["verdict"] == "fail"
    assert report["producer_evaluation"]["findings"] == [
        {"code": "sha256_mismatch", "subject": "alpha-base-model"}
    ]


def test_cli_verify_and_check_are_private_and_refuse_overwrite(tmp_path: Path):
    output = tmp_path / "verification.json"
    args = [
        "bom",
        "verify",
        str(VECTOR / "artifact-plan.json"),
        str(VECTOR / "manifest.json"),
        str(VECTOR / "evaluation.json"),
        str(VECTOR / "cyclonedx-1.7.json"),
        str(VECTOR / "spdx-3.0.1.json"),
        "--verified-at",
        "2026-09-05T00:04:00Z",
        "--out",
        str(output),
    ]
    assert main(args) == 0
    assert main(args) == 2
    assert main(["bom", "check", str(output)]) == 0


def test_verifier_imports_no_lurebench_network_or_model_runtime():
    tree = ast.parse((ROOT / "lurescope" / "bom.py").read_text(encoding="utf-8"))
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module and not node.level
    )
    assert not any(name == "lurebench" or name.startswith("lurebench.") for name in imports)
    assert not any(
        name.split(".")[0] in {"requests", "socket", "urllib", "transformers", "torch"}
        for name in imports
    )
