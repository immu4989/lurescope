"""Shared-state golden cases must agree with the separate verifier."""

import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from lurescope.mandate_conformance import (
    create_mandate_conformance_verification,
    validate_mandate_conformance_verification,
)

ROOT = Path(__file__).parents[1]
VECTOR = ROOT / "conformance/luremandate-transitions-v1"


def test_transition_evidence_independently_reproduces(tmp_path):
    expected = json.loads((VECTOR / "verification.json").read_text())
    result = create_mandate_conformance_verification(
        VECTOR / "challenge.json",
        VECTOR / "submission.json",
        VECTOR / "score.json",
        tmp_path / "verification.json",
        verified_at="2026-09-06T04:03:00Z",
    )
    assert result == expected
    assert validate_mandate_conformance_verification(result) == result
    assert result["summary"]["verdict"] == "pass"
    assert result["summary"]["exact_match_count"] == 41


def test_transition_documents_satisfy_existing_contract_schemas():
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        schema = json.loads(path.read_text())
        if "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema)))
    registry = Registry().with_resources(resources)
    for name in ("challenge", "submission", "score", "verification"):
        schema = json.loads(
            (ROOT / "spec" / f"luremandate-conformance-{name}-v1.schema.json").read_text()
        )
        Draft202012Validator(schema, registry=registry, format_checker=FormatChecker()).validate(
            json.loads((VECTOR / f"{name}.json").read_text())
        )
