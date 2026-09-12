from __future__ import annotations

import ast
import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from lurescope.cli import main
from lurescope.mandate_otel import (
    OUTCOME_EVENT,
    load_mandate_otel_projection,
    validate_mandate_otel_projection,
)

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


def test_public_projection_independently_reconstructs_exact_run_and_validates_schemas():
    projection = _load("otel-projection.json")
    assert validate_mandate_otel_projection(projection) == projection
    assert load_mandate_otel_projection(VECTOR / "otel-projection.json") == projection
    assert projection["run"] == _load("run.json")
    assert len(projection["inputs"]["otel_log_export"]["records"]) == 67
    assert projection["privacy"]["body_accepted"] is False
    assert projection["clock_boundary"]["observed_timestamp_used_for_benchmark_timing"] is False

    registry = _registry()
    for filename, value in (
        ("luremandate-otel-log-export-v1.schema.json", _load("otel-log-export.json")),
        ("luremandate-otel-projection-v1.schema.json", projection),
    ):
        schema = json.loads((ROOT / "spec" / filename).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(
            schema,
            registry=registry,
            format_checker=FormatChecker(),
        ).validate(value)


def test_projection_tampering_body_timestamp_missing_event_and_digest_fail_closed():
    projection = _load("otel-projection.json")

    body = copy.deepcopy(projection)
    body["inputs"]["otel_log_export"]["records"][0]["Body"] = "secret"
    with pytest.raises(ValueError, match="field allowlist"):
        validate_mandate_otel_projection(body)

    rebound = copy.deepcopy(projection)
    rebound["inputs"]["otel_log_export"]["records"][0]["Timestamp"] += 1_000_000
    with pytest.raises(ValueError, match="declared lifecycle time"):
        validate_mandate_otel_projection(rebound)

    missing = copy.deepcopy(projection)
    records = missing["inputs"]["otel_log_export"]["records"]
    missing["inputs"]["otel_log_export"]["records"] = [
        item
        for item in records
        if not (
            item["EventName"] == OUTCOME_EVENT
            and item["Attributes"]["luremandate.transaction.id"] == "tx-01"
        )
    ]
    with pytest.raises(ValueError, match="lacks exact intent, decision, or outcome"):
        validate_mandate_otel_projection(missing)

    digest = copy.deepcopy(projection)
    digest["inputs"]["otel_log_export_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="does not independently reproduce"):
        validate_mandate_otel_projection(digest)


def test_independent_cli_and_no_lurebench_runtime_import():
    assert main(["mandate", "verify-otel", str(VECTOR / "otel-projection.json")]) == 0
    tree = ast.parse((ROOT / "lurescope" / "mandate_otel.py").read_text(encoding="utf-8"))
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
