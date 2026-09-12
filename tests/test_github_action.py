from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
ACTION = ROOT / ".github" / "actions" / "verify-lurerevoke-gate" / "action.yml"
MANDATE_ACTION = ROOT / ".github" / "actions" / "verify-luremandate-gate" / "action.yml"
SECURITY_CRITICAL_INPUTS = {
    "gate",
    "topology-audit",
    "otel-projection",
    "evidence-bundle",
    "bundle-public-key",
    "expected-bundle-key-id",
    "maximum-allowed-convergence-ms",
    "minimum-run-generated-at",
    "expected-system-id",
    "expected-environment",
    "expected-receiver-name",
    "expected-receiver-artifact-sha256",
}
MANDATE_SECURITY_CRITICAL_INPUTS = {
    "gate",
    "semantic-verification",
    "authenticated-verification",
    "otel-projection",
    "authenticated-otel-projection",
    "approver-key-policy",
    "minimum-run-started-at",
    "expected-engine-id",
    "expected-engine-version",
    "expected-engine-artifact-sha256",
    "expected-receiver-instance-id",
    "expected-receiver-key-id",
}


def test_revocation_gate_action_is_pinned_and_fail_closed():
    action = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
    assert action["runs"]["using"] == "composite"
    steps = action["runs"]["steps"]
    setup = steps[0]
    assert re.fullmatch(r"actions/setup-python@[a-f0-9]{40}", setup["uses"])
    assert "continue-on-error" not in ACTION.read_text(encoding="utf-8")
    assert steps[-1]["shell"] == "bash"
    assert "verify-gate" in steps[-1]["run"]
    assert "--json" in steps[-1]["run"]


def test_revocation_gate_action_never_interpolates_user_inputs_in_shell():
    action = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
    for step in action["runs"]["steps"]:
        assert "${{ inputs." not in step.get("run", "")
    verifier_environment = action["runs"]["steps"][-1]["env"]
    assert set(verifier_environment) == {
        "LURESCOPE_GATE",
        "LURESCOPE_TOPOLOGY_AUDIT",
        "LURESCOPE_OTEL_PROJECTION",
        "LURESCOPE_EVIDENCE_BUNDLE",
        "LURESCOPE_BUNDLE_PUBLIC_KEY",
        "LURESCOPE_EXPECTED_BUNDLE_KEY_ID",
        "LURESCOPE_MAXIMUM_ALLOWED_CONVERGENCE_MS",
        "LURESCOPE_MINIMUM_RUN_GENERATED_AT",
        "LURESCOPE_EXPECTED_SYSTEM_ID",
        "LURESCOPE_EXPECTED_ENVIRONMENT",
        "LURESCOPE_EXPECTED_RECEIVER_NAME",
        "LURESCOPE_EXPECTED_RECEIVER_ARTIFACT_SHA256",
    }


def test_revocation_gate_action_keeps_security_policy_inputs_mandatory():
    action = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
    inputs = action["inputs"]
    assert SECURITY_CRITICAL_INPUTS <= set(inputs)
    for name in SECURITY_CRITICAL_INPUTS:
        assert inputs[name]["required"] is True
        assert "default" not in inputs[name]


def test_mandate_gate_action_is_pinned_fail_closed_and_non_interpolating():
    action = yaml.safe_load(MANDATE_ACTION.read_text(encoding="utf-8"))
    assert action["runs"]["using"] == "composite"
    steps = action["runs"]["steps"]
    assert re.fullmatch(r"actions/setup-python@[a-f0-9]{40}", steps[0]["uses"])
    assert "continue-on-error" not in MANDATE_ACTION.read_text(encoding="utf-8")
    assert steps[-1]["shell"] == "bash"
    assert "mandate verify-gate" in steps[-1]["run"]
    assert "--json" in steps[-1]["run"]
    for step in steps:
        assert "${{ inputs." not in step.get("run", "")


def test_mandate_gate_action_keeps_external_policy_inputs_mandatory():
    action = yaml.safe_load(MANDATE_ACTION.read_text(encoding="utf-8"))
    inputs = action["inputs"]
    assert MANDATE_SECURITY_CRITICAL_INPUTS <= set(inputs)
    for name in MANDATE_SECURITY_CRITICAL_INPUTS:
        assert inputs[name]["required"] is True
        assert "default" not in inputs[name]
    assert set(action["runs"]["steps"][-1]["env"]) == {
        "LURESCOPE_MANDATE_GATE",
        "LURESCOPE_MANDATE_SEMANTIC",
        "LURESCOPE_MANDATE_AUTHENTICATED",
        "LURESCOPE_MANDATE_OTEL",
        "LURESCOPE_MANDATE_AUTHENTICATED_OTEL",
        "LURESCOPE_MANDATE_KEY_POLICY",
        "LURESCOPE_MANDATE_MINIMUM_RUN",
        "LURESCOPE_MANDATE_ENGINE_ID",
        "LURESCOPE_MANDATE_ENGINE_VERSION",
        "LURESCOPE_MANDATE_ENGINE_SHA256",
        "LURESCOPE_MANDATE_RECEIVER_INSTANCE",
        "LURESCOPE_MANDATE_RECEIVER_KEY_ID",
    }
