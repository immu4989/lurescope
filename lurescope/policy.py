"""Strict loading of versioned decision policies exported by LureBench."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional


@dataclass(frozen=True)
class DecisionPolicy:
    policy_id: str
    detector: str
    task: str
    threshold: float
    objective: str
    validation_records: int
    validation_sha256: str
    schema_version: int = 1
    target_fpr: Optional[float] = None
    created_at: str = ""


@lru_cache(maxsize=8)
def load_policy(path: str) -> DecisionPolicy:
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)
    policy = DecisionPolicy(**payload)
    if policy.schema_version != 1:
        raise ValueError(f"unsupported policy schema {policy.schema_version}")
    if policy.task != "fraud":
        raise ValueError("LureScope only serves fraud decision policies")
    if not 0 <= policy.threshold <= 1:
        raise ValueError("policy threshold must be in [0, 1]")
    if policy.validation_records < 1 or len(policy.validation_sha256) != 64:
        raise ValueError("policy has invalid validation provenance")
    return policy


def configured_policy() -> Optional[DecisionPolicy]:
    path = os.environ.get("LURESCOPE_POLICY_PATH")
    return load_policy(os.path.abspath(path)) if path else None
