import importlib
from pathlib import Path

import pytest

from lurescope import mandate_export

ROOT = Path(__file__).parents[1]
VECTOR = ROOT / "conformance/luremandate-v1"
NOW = "2026-09-22T00:00:00Z"
KINDS = ["mandate", "mandate_auth", "mandate_conformance", "mandate_conformance_auth",
         "mandate_otel_auth", "mandate_sequence", "mandate_pairwise", "mandate_counterfactual"]


def create(kind, output, value):
    module = importlib.import_module(f"lurescope.{kind}")
    if kind == "mandate":
        return module.create_mandate_verification(
            VECTOR / "plan.json", VECTOR / "run.json", VECTOR / "evaluation.json", output,
            verified_at=value,
        )
    if kind == "mandate_auth":
        keys = {name: VECTOR / "keys" / f"{name}.public.pem" for name in (
            "approver-mission", "approver-operator", "approver-security", "requester-a",
        )}
        return module.create_authenticated_mandate_verification(
            VECTOR / "plan.json", VECTOR / "run.json", VECTOR / "evaluation.json",
            VECTOR / "evidence", keys, output, verified_at=value,
        )
    if kind == "mandate_conformance":
        return module.create_mandate_conformance_verification(
            VECTOR / "challenge.json", VECTOR / "submission.json",
            VECTOR / "conformance-score.json", output, verified_at=value,
        )
    if kind == "mandate_conformance_auth":
        return module.create_authenticated_mandate_conformance_verification(
            VECTOR / "conformance-verification.json", VECTOR / "submission.dsse.json",
            VECTOR / "keys/gateway-conformance.public.pem", output,
            expected_gateway_key_id="278fb7473fae2b6b4213d916f3bf481d7ae209fe8c08443f84367e7bc9d1f1df",
            verified_at=value,
        )
    if kind == "mandate_otel_auth":
        return module.create_authenticated_mandate_otel_projection(
            VECTOR / "otel-projection.json", VECTOR / "otel-log-export.dsse.json",
            VECTOR / "keys/receiver-telemetry.public.pem", output,
            expected_receiver_key_id="23b870f8eb429486d3ebab388918350ca0a9b8d5b735c18de5d2ed4ebd6c7211",
            verified_at=value,
        )
    profile = kind.removeprefix("mandate_")
    return getattr(module, f"create_{profile}_mandate_verification")(
        ROOT / f"conformance/luremandate-{profile}-v1/{profile}-assurance.json",
        output, verified_at=value,
    )


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("value", ["", False, 0, [], {}])
def test_invalid_explicit_timestamp_rejected_without_default_or_output(
    tmp_path, monkeypatch, kind, value,
):
    def forbidden_clock():
        raise AssertionError("explicit timestamps must not request a default clock")

    module = importlib.import_module(f"lurescope.{kind}")
    monkeypatch.setattr(module, "_now", forbidden_clock)
    output = tmp_path / "verification.json"
    with pytest.raises(ValueError):
        create(kind, output, value)
    assert not output.exists()


@pytest.mark.parametrize("kind", KINDS)
def test_only_none_requests_a_default_timestamp(tmp_path, monkeypatch, kind):
    module = importlib.import_module(f"lurescope.{kind}")
    monkeypatch.setattr(module, "_now", lambda: NOW)
    assert create(kind, tmp_path / "default.json", None)["verified_at"] == NOW
    explicit = "2026-09-23T00:00:00Z"
    assert create(kind, tmp_path / "explicit.json", explicit)["verified_at"] == explicit


@pytest.mark.parametrize("value", ["", False, 0, [], {}])
def test_standards_export_rejects_explicit_falsy_timestamp(monkeypatch, value):
    def forbidden_clock():
        raise AssertionError("explicit timestamps must not request a default clock")

    monkeypatch.setattr(mandate_export, "_timestamp_now", forbidden_clock)
    with pytest.raises(ValueError):
        mandate_export._effective_generated_at({"created_at": NOW}, value)
