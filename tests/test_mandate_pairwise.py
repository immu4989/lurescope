from __future__ import annotations

import ast
import copy
import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from lurescope.cli import main
from lurescope.mandate_pairwise import (
    create_pairwise_mandate_verification,
    load_pairwise_mandate_verification,
    validate_pairwise_mandate_assurance,
    validate_pairwise_mandate_verification,
)

ROOT = Path(__file__).parents[1]
VECTOR = ROOT / "conformance" / "luremandate-pairwise-v1"
PRODUCER = ROOT.parent / "lurebench" / "conformance" / "luremandate-pairwise-v1"


def _load(name: str) -> dict:
    return json.loads((VECTOR / name).read_text(encoding="utf-8"))


def _registry() -> Registry:
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def test_public_pairwise_sources_match_producer_and_recompute_independently():
    for name in (
        "plan.json",
        "run.json",
        "challenge.json",
        "submission.json",
        "score.json",
        "pairwise-assurance.json",
    ):
        assert (VECTOR / name).read_bytes() == (PRODUCER / name).read_bytes()
    report = _load("pairwise-assurance.json")
    verification = _load("pairwise-verification.json")
    assert validate_pairwise_mandate_assurance(report) == report
    assert validate_pairwise_mandate_verification(verification) == verification
    assert verification["summary"]["verdict"] == "pass"
    assert verification["summary"]["case_count"] == 16
    assert verification["summary"]["factor_count"] == 15
    assert verification["summary"]["factor_pair_count"] == 105
    assert verification["summary"]["covered_interaction_count"] == 420
    assert verification["summary"]["pairwise_coverage_complete"] is True


def test_public_pairwise_schemas_validate():
    registry = _registry()
    for schema_name, artifact_name in (
        ("luremandate-pairwise-assurance-v1.schema.json", "pairwise-assurance.json"),
        ("luremandate-pairwise-verification-v1.schema.json", "pairwise-verification.json"),
    ):
        schema = json.loads((ROOT / "spec" / schema_name).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(
            schema,
            registry=registry,
            format_checker=FormatChecker(),
        ).validate(_load(artifact_name))


def test_pairwise_verification_is_private_non_overwriting_and_cli_rechecks(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    output = tmp_path / "verification.json"
    result = create_pairwise_mandate_verification(
        VECTOR / "pairwise-assurance.json",
        output,
        verified_at="2026-09-05T15:04:00Z",
    )
    assert result == _load("pairwise-verification.json")
    assert load_pairwise_mandate_verification(output) == result
    assert main(["mandate", "check-pairwise", str(output)]) == 0
    assert "PAIRWISE INDEPENDENTLY VERIFIED: PASS" in capsys.readouterr().out
    if os.name == "posix":
        assert output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        create_pairwise_mandate_verification(
            VECTOR / "pairwise-assurance.json",
            output,
            verified_at="2026-09-05T15:04:00Z",
        )


def test_pairwise_tampering_fails_and_verifier_imports_no_lurebench(tmp_path: Path):
    report = _load("pairwise-assurance.json")
    report["summary"]["covered_interaction_count"] = 419
    changed = tmp_path / "changed.json"
    changed.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(ValueError, match="does not independently reproduce"):
        create_pairwise_mandate_verification(
            changed,
            tmp_path / "blocked.json",
            verified_at="2026-09-05T15:04:00Z",
        )

    verification = _load("pairwise-verification.json")
    altered = copy.deepcopy(verification)
    altered["summary"]["interaction_coverage"] = 0.99
    with pytest.raises(ValueError, match="does not independently reproduce"):
        validate_pairwise_mandate_verification(altered)

    tree = ast.parse((ROOT / "lurescope" / "mandate_pairwise.py").read_text(encoding="utf-8"))
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
