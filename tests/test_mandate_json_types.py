"""Ensure evidence verification preserves JSON types during recomputation."""

import json
from pathlib import Path

import pytest

from lurescope.mandate import validate_mandate_plan, validate_mandate_verification
from lurescope.mandate_conformance import validate_mandate_conformance_verification
from lurescope.mandate_counterfactual import validate_counterfactual_mandate_verification
from lurescope.mandate_pairwise import validate_pairwise_mandate_verification
from lurescope.mandate_sequence import validate_sequence_mandate_verification

ROOT = Path(__file__).parents[1] / "conformance"
CASES = [
    ("luremandate-v1/verification.json", validate_mandate_verification),
    ("luremandate-v1/conformance-verification.json", validate_mandate_conformance_verification),
    ("luremandate-pairwise-v1/pairwise-verification.json", validate_pairwise_mandate_verification),
    (
        "luremandate-counterfactual-v1/counterfactual-verification.json",
        validate_counterfactual_mandate_verification,
    ),
    ("luremandate-sequence-v1/sequence-verification.json", validate_sequence_mandate_verification),
]


@pytest.mark.parametrize("path,validator", CASES)
@pytest.mark.parametrize("replacement", [True, 1.0])
def test_verification_schema_versions_require_integers(path, validator, replacement):
    value = json.loads((ROOT / path).read_text())
    value["schema_version"] = replacement
    with pytest.raises(ValueError):
        validator(value)


@pytest.mark.parametrize("path,validator", CASES)
def test_counts_cannot_be_replaced_with_equal_floats(path, validator):
    value = json.loads((ROOT / path).read_text())
    field = next(key for key, item in value["summary"].items() if type(item) is int)
    value["summary"][field] = float(value["summary"][field])
    with pytest.raises(ValueError):
        validator(value)


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("maximum_invalid_allow_count", False),
        ("require_complete_outcomes", 1),
    ],
)
def test_acceptance_types_are_strict(field, replacement):
    plan = json.loads((ROOT / "luremandate-v1/plan.json").read_text())
    plan["acceptance"][field] = replacement
    with pytest.raises(ValueError):
        validate_mandate_plan(plan)
