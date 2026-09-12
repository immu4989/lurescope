from __future__ import annotations

import ast
import base64
import copy
import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from lurescope.cli import main
from lurescope.mandate import (
    VERIFICATION_SCHEMA,
    _derive,
    create_mandate_verification,
    load_mandate_verification,
    validate_mandate_evaluation,
    validate_mandate_verification,
)
from lurescope.permit import _canonical

ROOT = Path(__file__).parents[1]
VECTOR = ROOT / "conformance" / "luremandate-v1"


def _load(name: str) -> dict:
    return json.loads((VECTOR / name).read_text(encoding="utf-8"))


def _write(path: Path, value: object) -> None:
    path.write_bytes(_canonical(value))


def _registry() -> Registry:
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def test_independent_evaluator_reproduces_all_sixteen_producer_results():
    expected = _load("evaluation.json")
    actual = _derive(_load("plan.json"), _load("run.json"), expected["evaluated_at"])
    assert actual == expected
    assert validate_mandate_evaluation(expected) == expected
    assert actual["summary"]["expected_block_count"] == 12
    assert actual["summary"]["correct_allow_count"] == 4


def test_self_contained_verification_reparses_sources_and_validates_schema(tmp_path: Path):
    output = tmp_path / "verification.json"
    result = create_mandate_verification(
        VECTOR / "plan.json",
        VECTOR / "run.json",
        VECTOR / "evaluation.json",
        output,
        verified_at="2026-09-05T15:18:00Z",
    )
    assert result == _load("verification.json")
    assert result["schema"] == VERIFICATION_SCHEMA
    assert result["summary"]["source_documents_reparsed"] is True
    assert result["summary"]["producer_evaluation_reproduced"] is True
    assert result["summary"]["transaction_authority_verified"] is True
    assert load_mandate_verification(output) == result
    if os.name == "posix":
        assert output.stat().st_mode & 0o777 == 0o600

    schema = json.loads(
        (ROOT / "spec" / "luremandate-verification-v1.schema.json").read_text(encoding="utf-8")
    )
    assert schema["$id"] == VERIFICATION_SCHEMA
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, registry=_registry(), format_checker=FormatChecker()).validate(
        result
    )


def test_invalid_allow_and_observed_effect_are_preserved_as_verified_failure(tmp_path: Path):
    plan, run = _load("plan.json"), _load("run.json")
    transaction = run["transactions"][9]
    transaction["decision"]["decision"] = "allow"
    transaction["outcome"] = {
        "state": "effect_observed",
        "observed_at": "2026-09-05T15:09:30Z",
        "sensor_id": "authority-effect-sensor",
    }
    evaluation = _derive(plan, run, "2026-09-05T15:17:00Z")
    assert evaluation["summary"]["verdict"] == "fail"
    assert evaluation["summary"]["authority_bypass_count"] == 1
    paths = [tmp_path / name for name in ("plan.json", "run.json", "evaluation.json")]
    for path, value in zip(paths, (plan, run, evaluation), strict=True):
        _write(path, value)
    result = create_mandate_verification(
        *paths,
        tmp_path / "verification.json",
        verified_at="2026-09-05T15:18:00Z",
    )
    assert result["summary"]["verdict"] == "fail"
    assert result["summary"]["transaction_authority_verified"] is False


def test_unknown_effect_evidence_remains_inconclusive(tmp_path: Path):
    plan, run = _load("plan.json"), _load("run.json")
    run["transactions"][0]["outcome"] = {
        "state": "unknown",
        "observed_at": None,
        "sensor_id": None,
    }
    result = _derive(plan, run, "2026-09-05T15:17:00Z")
    assert result["summary"]["verdict"] == "inconclusive"
    assert result["summary"]["unknown_outcome_count"] == 1


def test_producer_summary_source_and_embedded_byte_tampering_are_rejected(tmp_path: Path):
    changed = _load("evaluation.json")
    changed["summary"]["correct_block_count"] -= 1
    with pytest.raises(ValueError, match="does not independently recompute"):
        validate_mandate_evaluation(changed)

    verification = _load("verification.json")
    altered = copy.deepcopy(verification)
    payload = bytearray(base64.b64decode(altered["documents"]["run"]["payload_base64"]))
    payload[-2] ^= 1
    altered["documents"]["run"]["payload_base64"] = base64.b64encode(payload).decode()
    with pytest.raises(ValueError, match="digest does not match"):
        validate_mandate_verification(altered)

    run = _load("run.json")
    run["completed_at"] = "2026-09-05T15:16:01Z"
    changed_run = tmp_path / "run.json"
    _write(changed_run, run)
    with pytest.raises(ValueError, match="does not embed the supplied plan and run"):
        create_mandate_verification(
            VECTOR / "plan.json",
            changed_run,
            VECTOR / "evaluation.json",
            tmp_path / "out.json",
            verified_at="2026-09-05T15:18:00Z",
        )


def test_cli_verifies_rechecks_and_refuses_overwrite(tmp_path: Path):
    output = tmp_path / "verification.json"
    args = [
        "mandate",
        "verify",
        str(VECTOR / "plan.json"),
        str(VECTOR / "run.json"),
        str(VECTOR / "evaluation.json"),
        "--verified-at",
        "2026-09-05T15:18:00Z",
        "--out",
        str(output),
    ]
    assert main(args) == 0
    assert main(args) == 2
    assert main(["mandate", "check", str(output)]) == 0


def test_verifier_imports_no_lurebench_network_model_or_process_runtime():
    tree = ast.parse((ROOT / "lurescope" / "mandate.py").read_text(encoding="utf-8"))
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
        name.split(".")[0]
        in {"requests", "socket", "subprocess", "torch", "transformers", "openai"}
        for name in imports
    )
