"""Portable contract fixtures: no adjacent source checkout is required."""

import hashlib
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]


@pytest.fixture
def assert_producer_copy():
    manifest = json.loads((ROOT / "tests/producer-contract.json").read_text())

    def check(relative):
        relative = str(relative)
        expected = manifest["files"][relative]
        actual = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        assert actual == expected, (
            f"{relative} differs from producer commit {manifest['commit']}; "
            "review the producer change before updating its digest pin"
        )

    return check
