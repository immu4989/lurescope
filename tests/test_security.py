"""Deterministic tests for deployment budgets and rate limiting."""

import json
import os

import pytest
from fastapi import HTTPException

from lurescope.cli import main
from lurescope.security import (
    DailyBudget,
    SlidingWindowLimiter,
    _provider_call_cost,
    _reset_for_tests,
    create_api_key_verifier,
    enforce_request_policy,
)


def test_sliding_window_limiter_expires_old_events():
    limiter = SlidingWindowLimiter()
    assert limiter.check("client", 2, now=100).remaining == 1
    assert limiter.check("client", 2, now=101).remaining == 0
    blocked = limiter.check("client", 2, now=102)
    assert blocked.allowed is False
    assert blocked.retry_after >= 1
    assert limiter.check("client", 2, now=161).allowed is True


def test_daily_budget_does_not_charge_rejected_reservations():
    budget = DailyBudget()
    accepted, remaining, _ = budget.consume(2, 3)
    assert accepted is True
    assert remaining == 1
    rejected, remaining, retry_after = budget.consume(2, 3)
    assert rejected is False
    assert remaining == 1
    assert retry_after >= 1
    assert budget.consume(1, 3)[:2] == (True, 0)


def test_provider_cost_reserves_every_expected_call():
    assert _provider_call_cost("tfidf-logreg", None, "none") == 0
    assert _provider_call_cost("llm-judge", None, "none") == 1
    assert _provider_call_cost("tfidf-logreg", "llm-paraphrase", "none") == 1
    assert _provider_call_cost("llm-judge", "llm-paraphrase", "normalize") == 4


def test_allowlisted_provider_call_exhausts_explicit_budget(monkeypatch):
    key = "test-key-with-at-least-thirty-two-characters"
    monkeypatch.setenv("LURESCOPE_PUBLIC_MODE", "true")
    monkeypatch.setenv("LURESCOPE_API_KEY_SCRYPT", create_api_key_verifier(key))
    monkeypatch.setenv("LURESCOPE_ALLOWED_DETECTORS", "llm-judge")
    monkeypatch.setenv("LURESCOPE_LLM_ENGINE", "openrouter")
    monkeypatch.setenv("LURESCOPE_ALLOWED_ENGINES", "openrouter")
    monkeypatch.setenv("LURESCOPE_ALLOWED_MODELS", "openai/gpt-4o-mini")
    monkeypatch.setenv("LURESCOPE_PROVIDER_DAILY_LIMIT", "1")
    _reset_for_tests()

    enforce_request_policy(detector="llm-judge")
    with pytest.raises(HTTPException) as caught:
        enforce_request_policy(detector="llm-judge")
    assert caught.value.status_code == 429
    assert caught.value.headers["X-Provider-Budget-Remaining"] == "0"


def test_api_key_cli_creates_private_scrypt_material_and_refuses_overwrite(
    tmp_path, monkeypatch
):
    output = tmp_path / "api-key.json"
    assert main(["api-key", "--out", str(output)]) == 0
    assert os.stat(output).st_mode & 0o777 == 0o600
    payload = json.loads(output.read_text())
    key = payload["client_api_key"]
    verifier = payload["lurescope_api_key_scrypt"]
    monkeypatch.setenv("LURESCOPE_PUBLIC_MODE", "true")
    monkeypatch.setenv("LURESCOPE_API_KEY_SCRYPT", verifier)
    from lurescope.security import SecuritySettings, _credential_identity

    settings = SecuritySettings.from_env()
    assert _credential_identity(key, settings.api_key_verifiers)
    assert main(["api-key", "--out", str(output)]) == 2


def test_api_key_cli_creates_independent_rotation_material(tmp_path):
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    assert main(["api-key", "--out", str(first)]) == 0
    assert main(["api-key", "--out", str(second)]) == 0
    old = json.loads(first.read_text())
    new = json.loads(second.read_text())
    assert old["client_api_key"] != new["client_api_key"]
    assert old["lurescope_api_key_scrypt"] != new["lurescope_api_key_scrypt"]
