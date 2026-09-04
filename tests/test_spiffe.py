from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from lurescope.spiffe import parse_spiffe_id, validate_spiffe_trust_domain

ROOT = Path(__file__).parents[1]
VECTORS = json.loads(
    (ROOT / "conformance/spiffe-id-v1/vectors.json").read_text(encoding="utf-8")
)


@pytest.mark.parametrize(
    ("value", "domain"),
    [(item["value"], item["trust_domain"]) for item in VECTORS["valid_ids"]],
)
def test_independent_spiffe_parser_accepts_normative_forms(value: str, domain: str):
    item = next(candidate for candidate in VECTORS["valid_ids"] if candidate["value"] == value)
    assert parse_spiffe_id(value, "identity", require_path=item["require_path"]) == (
        value,
        domain,
    )
    assert validate_spiffe_trust_domain(domain, "domain") == domain


@pytest.mark.parametrize(
    "item",
    VECTORS["invalid_ids"],
    ids=[item["reason"] for item in VECTORS["invalid_ids"]],
)
def test_independent_spiffe_parser_rejects_ambiguous_forms(item: dict):
    with pytest.raises(ValueError):
        parse_spiffe_id(item["value"], "identity", require_path=item["require_path"])


def test_spiffe_verifier_is_implementation_independent():
    source = Path("lurescope/spiffe.py").read_text(encoding="utf-8")
    assert "from lurebench" not in source
    assert "import lurebench" not in source


def test_public_spiffe_vectors_and_boundaries_are_schema_valid():
    schema = json.loads(
        (ROOT / "spec/spiffe-id-conformance-v1.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(VECTORS)
    for domain in VECTORS["valid_trust_domains"]:
        assert validate_spiffe_trust_domain(domain, "domain") == domain
    for domain in VECTORS["invalid_trust_domains"]:
        with pytest.raises(ValueError):
            validate_spiffe_trust_domain(domain, "domain")
    assert parse_spiffe_id(
        f"spiffe://{'a' * 255}/service", "identity", require_path=True
    )[1] == "a" * 255
    with pytest.raises(ValueError):
        validate_spiffe_trust_domain("a" * 256, "domain")
    with pytest.raises(ValueError):
        parse_spiffe_id(f"spiffe://example.com/{'a' * 2_030}", "identity")
