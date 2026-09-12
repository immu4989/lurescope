from __future__ import annotations

import ast
import copy
import json
import os
from pathlib import Path

import jsonschema
import pytest
from referencing import Registry, Resource

from lurescope.cli import main
from lurescope.mandate_conformance import (
    create_mandate_conformance_verification,
    load_mandate_conformance_verification,
    validate_mandate_conformance_challenge,
    validate_mandate_conformance_score,
    validate_mandate_conformance_submission,
    validate_mandate_conformance_verification,
)

ROOT = Path(__file__).parents[1]
VECTOR = ROOT / "conformance/luremandate-v1"
PRODUCER = ROOT.parent / "lurebench"


def _load(name: str) -> dict:
    return json.loads((VECTOR / name).read_text(encoding="utf-8"))


def _registry() -> Registry:
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def test_public_conformance_sources_are_exact_producer_copies_and_recompute():
    challenge = _load("challenge.json")
    submission = _load("submission.json")
    score = _load("conformance-score.json")
    verification = _load("conformance-verification.json")
    for name in (
        "conformance-plan.json",
        "conformance-run.json",
        "challenge.json",
        "submission.json",
        "conformance-score.json",
    ):
        assert (VECTOR / name).read_bytes() == (
            PRODUCER / "conformance/luremandate-v1" / name
        ).read_bytes()
    assert validate_mandate_conformance_challenge(challenge) == challenge
    assert validate_mandate_conformance_submission(submission, challenge) == submission
    assert validate_mandate_conformance_score(score) == score
    assert validate_mandate_conformance_verification(verification) == verification
    assert verification["summary"]["verdict"] == "pass"
    assert verification["summary"]["exact_match_count"] == 25
    assert verification["summary"]["covered_reason_count"] == 21
    assert verification["summary"]["reason_universe_count"] == 21
    assert verification["summary"]["reason_coverage_complete"] is True
    assert verification["summary"]["answer_free_challenge_rechecked"] is True


def test_public_schemas_validate_all_conformance_artifacts():
    registry = _registry()
    for schema_name, artifact_name in (
        ("luremandate-conformance-challenge-v1.schema.json", "challenge.json"),
        ("luremandate-conformance-submission-v1.schema.json", "submission.json"),
        ("luremandate-conformance-score-v1.schema.json", "conformance-score.json"),
        (
            "luremandate-conformance-verification-v1.schema.json",
            "conformance-verification.json",
        ),
    ):
        schema = json.loads((ROOT / "spec" / schema_name).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(
            schema,
            registry=registry,
            format_checker=jsonschema.FormatChecker(),
        ).validate(_load(artifact_name))


def test_verification_is_private_non_overwriting_and_cli_rechecks(tmp_path: Path, capsys):
    output = tmp_path / "verification.json"
    result = create_mandate_conformance_verification(
        VECTOR / "challenge.json",
        VECTOR / "submission.json",
        VECTOR / "conformance-score.json",
        output,
        verified_at="2026-09-05T15:29:00Z",
    )
    assert result == _load("conformance-verification.json")
    assert load_mandate_conformance_verification(output) == result
    assert main(["mandate", "check-conformance", str(output)]) == 0
    assert "CONFORMANCE INDEPENDENTLY VERIFIED: PASS" in capsys.readouterr().out
    with pytest.raises(FileExistsError):
        create_mandate_conformance_verification(
            VECTOR / "challenge.json",
            VECTOR / "submission.json",
            VECTOR / "conformance-score.json",
            output,
            verified_at="2026-09-05T15:29:00Z",
        )
    if os.name == "posix":
        assert output.stat().st_mode & 0o777 == 0o600


def test_source_and_self_contained_report_tampering_fail_closed(tmp_path: Path):
    score = _load("conformance-score.json")
    score["summary"]["exact_match_count"] -= 1
    score_path = tmp_path / "tampered-score.json"
    score_path.write_text(json.dumps(score), encoding="utf-8")
    with pytest.raises(ValueError, match="does not independently reproduce"):
        create_mandate_conformance_verification(
            VECTOR / "challenge.json",
            VECTOR / "submission.json",
            score_path,
            tmp_path / "blocked.json",
            verified_at="2026-09-05T15:29:00Z",
        )

    verification = _load("conformance-verification.json")
    changed = copy.deepcopy(verification)
    changed["summary"]["covered_reason_count"] += 1
    with pytest.raises(ValueError, match="does not independently reproduce"):
        validate_mandate_conformance_verification(changed)


def test_conformance_verifier_has_independent_runtime_boundary():
    tree = ast.parse((ROOT / "lurescope/mandate_conformance.py").read_text(encoding="utf-8"))
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
