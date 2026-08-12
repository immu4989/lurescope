"""API + service tests using FastAPI's TestClient."""

from __future__ import annotations

import pytest

pytest.importorskip("sklearn")  # tfidf detector needs scikit-learn

from fastapi.testclient import TestClient

from lurescope.app import app
from lurescope.security import _reset_for_tests, create_api_key_verifier

client = TestClient(app)

LURE = (
    "Dear customer, we detected unusual activity on your account. Please verify your "
    "identity within 24 hours by clicking the secure link, or your account will be suspended."
)
BENIGN = "Hey, are we still on for lunch tomorrow? Let me know what time works."

_SECURITY_ENV = (
    "LURESCOPE_PUBLIC_MODE",
    "LURESCOPE_API_KEY_SCRYPT",
    "LURESCOPE_RATE_LIMIT_PER_MINUTE",
    "LURESCOPE_PROVIDER_DAILY_LIMIT",
    "LURESCOPE_ALLOWED_DETECTORS",
    "LURESCOPE_ALLOWED_ATTACKS",
    "LURESCOPE_ALLOWED_ENGINES",
    "LURESCOPE_ALLOWED_MODELS",
    "LURESCOPE_LLM_ENGINE",
)
_TEST_API_KEY = "test-key-with-at-least-thirty-two-characters"
_TEST_SALT = bytes.fromhex("11" * 16)


@pytest.fixture(autouse=True)
def clean_deployment_security(monkeypatch):
    for name in _SECURITY_ENV:
        monkeypatch.delenv(name, raising=False)
    _reset_for_tests()
    yield
    _reset_for_tests()


def _public_mode(monkeypatch, *, rate: int = 60) -> dict:
    verifier = create_api_key_verifier(_TEST_API_KEY, _TEST_SALT)
    monkeypatch.setenv("LURESCOPE_PUBLIC_MODE", "true")
    monkeypatch.setenv("LURESCOPE_API_KEY_SCRYPT", verifier)
    monkeypatch.setenv("LURESCOPE_RATE_LIMIT_PER_MINUTE", str(rate))
    return {"Authorization": f"Bearer {_TEST_API_KEY}"}


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_public_mode_fails_closed_without_a_key_configuration(monkeypatch):
    monkeypatch.setenv("LURESCOPE_PUBLIC_MODE", "true")
    assert client.get("/health").status_code == 503
    response = client.post("/score", json={"text": LURE})
    assert response.status_code == 503
    assert "requires LURESCOPE_API_KEY_SCRYPT" in response.json()["detail"]


def test_public_mode_requires_valid_bearer_or_api_key_header(monkeypatch):
    headers = _public_mode(monkeypatch)
    missing = client.post("/score", json={"text": LURE})
    wrong = client.post(
        "/score", json={"text": LURE}, headers={"Authorization": "Bearer wrong"}
    )
    valid = client.post("/score", json={"text": LURE}, headers=headers)
    alternate = client.post(
        "/score", json={"text": LURE}, headers={"X-API-Key": _TEST_API_KEY}
    )
    assert missing.status_code == 401
    assert missing.headers["www-authenticate"] == "Bearer"
    assert wrong.status_code == 401
    assert valid.status_code == 200
    assert alternate.status_code == 200
    assert valid.headers["x-ratelimit-limit"] == "60"


def test_public_mode_rate_limits_each_credential(monkeypatch):
    headers = _public_mode(monkeypatch, rate=2)
    assert client.post("/score", json={"text": LURE}, headers=headers).status_code == 200
    second = client.post("/score", json={"text": LURE}, headers=headers)
    blocked = client.post("/score", json={"text": LURE}, headers=headers)
    assert second.status_code == 200
    assert second.headers["x-ratelimit-remaining"] == "0"
    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) >= 1


def test_public_mode_blocks_provider_spending_until_explicitly_budgeted(monkeypatch):
    headers = _public_mode(monkeypatch)
    monkeypatch.setenv("LURESCOPE_ALLOWED_DETECTORS", "tfidf-logreg,llm-judge")
    monkeypatch.setenv("LURESCOPE_LLM_ENGINE", "openrouter")
    monkeypatch.setenv("LURESCOPE_ALLOWED_ENGINES", "openrouter")
    monkeypatch.setenv("LURESCOPE_ALLOWED_MODELS", "openai/gpt-4o-mini")
    response = client.post(
        "/score", json={"text": LURE, "detector": "llm-judge"}, headers=headers
    )
    assert response.status_code == 403
    assert "provider-backed operations are disabled" in response.json()["detail"]


def test_security_status_discloses_posture_but_not_credentials(monkeypatch):
    _public_mode(monkeypatch, rate=17)
    response = client.get("/security")
    assert response.status_code == 200
    data = response.json()
    assert data["mode"] == "public"
    assert data["authentication_required"] is True
    assert data["rate_limit_per_minute"] == 17
    assert data["provider_daily_limit"] == 0
    assert _TEST_API_KEY not in response.text
    verifier = create_api_key_verifier(_TEST_API_KEY, _TEST_SALT)
    assert verifier not in response.text


def test_openapi_marks_content_routes_as_bearer_protected():
    schema = client.get("/openapi.json").json()
    assert schema["components"]["securitySchemes"]["HTTPBearer"]["scheme"] == "bearer"
    assert schema["paths"]["/score"]["post"]["security"] == [{"HTTPBearer": []}]


def test_capabilities_lists_detectors_and_attacks():
    c = client.get("/capabilities").json()
    assert "tfidf-logreg" in c["detectors"]
    assert "homoglyph" in c["attacks"]
    assert c["default_detector"] == "tfidf-logreg"
    assert "email-triage" in c["workflows"]
    assert "lureproof" in c["workflows"]
    assert "risk-controlled-policy" in c["workflows"]


def test_policy_endpoint_is_explicit_when_unconfigured(monkeypatch):
    monkeypatch.delenv("LURESCOPE_POLICY_PATH", raising=False)
    result = client.get("/policy")
    assert result.status_code == 200
    assert result.json()["configured"] is False
    assert result.json()["assurance_status"] == "none"


def test_score_flags_a_lure_higher_than_benign():
    lure = client.post("/score", json={"text": LURE}).json()
    benign = client.post("/score", json={"text": BENIGN}).json()
    assert 0.0 <= benign["fraud_probability"] <= 1.0
    assert lure["fraud_probability"] > benign["fraud_probability"]
    assert lure["label"] == "fraud"


def test_score_returns_signal_words():
    d = client.post("/score", json={"text": LURE}).json()
    # signals must actually be words present in the text
    assert all(s in LURE.lower() for s in d["signals"])


def test_score_identifies_default_threshold_provenance():
    d = client.post("/score", json={"text": LURE}).json()
    assert d["threshold"] == 0.5
    assert d["threshold_source"] == "default"
    assert d["policy_id"] is None


def test_score_rejects_unknown_detector():
    r = client.post("/score", json={"text": LURE, "detector": "nope"})
    assert r.status_code == 400


def test_homoglyph_attack_evades_the_keyword_detector():
    r = client.post(
        "/attack", json={"text": LURE, "attack": "homoglyph", "detector": "heuristic-v0"}
    )
    d = r.json()
    assert d["clean_flagged"] is True      # keyword detector catches the clean lure
    assert d["attacked_flagged"] is False  # homoglyphs defeat it
    assert d["evaded"] is True
    assert d["original"] != d["attacked"]


def test_attack_rejects_unknown_attack():
    r = client.post("/attack", json={"text": LURE, "attack": "nope"})
    assert r.status_code == 400


def test_llm_attack_without_provider_is_a_clean_400():
    r = client.post("/attack", json={"text": LURE, "attack": "llm-paraphrase"})
    assert r.status_code == 400
    assert "provider" in r.json()["detail"].lower()


def test_capabilities_advertises_extended_detectors_and_defenses():
    c = client.get("/capabilities").json()
    # Always-on set stays the safe default; the gated content-safety / LLM detectors
    # are still advertised in the catalog with the requirement spelled out.
    assert set(c["detectors"]) == {"tfidf-logreg", "heuristic-v0"}
    catalog = {d["name"]: d for d in c["detector_catalog"]}
    assert catalog["tfidf-logreg"]["always_on"] is True
    assert catalog["llm-judge"]["always_on"] is False
    assert catalog["llm-judge"]["requires"]  # non-empty guidance string
    for name in ("openai-moderation", "llama-guard-3", "binoculars"):
        assert name in catalog
    assert "normalize" in c["defenses"]


def test_gated_detector_without_key_is_a_clean_400_not_500():
    # llm-judge needs a provider; with none configured the request must fail cleanly.
    r = client.post("/score", json={"text": LURE, "detector": "llm-judge"})
    assert r.status_code == 400
    assert "llm-judge" in r.json()["detail"]


def test_normalize_defense_recovers_a_homoglyph_evasion():
    r = client.post(
        "/attack",
        json={
            "text": LURE,
            "attack": "homoglyph",
            "detector": "heuristic-v0",
            "defense": "normalize",
        },
    )
    d = r.json()
    assert d["evaded"] is True                 # homoglyphs defeat the raw detector
    assert d["defense"] == "normalize"
    assert d["defended_flagged"] is True       # normalization restores detection
    assert d["defense_recovered"] is True
    assert d["defended_evaded"] is False


def test_attack_rejects_unknown_defense():
    r = client.post(
        "/attack", json={"text": LURE, "attack": "homoglyph", "defense": "magic"}
    )
    assert r.status_code == 400


def test_defense_defaults_to_none_and_stays_backward_compatible():
    d = client.post(
        "/attack", json={"text": LURE, "attack": "homoglyph", "detector": "heuristic-v0"}
    ).json()
    assert d["defense"] == "none"
    assert d["defended_probability"] is None


def test_demo_page_served_at_root():
    r = client.get("/")
    assert r.status_code == 200
    assert "LureScope" in r.text


def test_email_triage_endpoint_returns_structured_evidence():
    raw = (
        "From: Security <alerts@example.org>\n"
        "Reply-To: collect@other.example\n"
        "To: user@example.org\n"
        "Subject: Urgent account verification\n\n"
        "Verify your account at http://192.0.2.10/login within 24 hours."
    )
    response = client.post("/triage/email", json={"raw_email": raw})
    assert response.status_code == 200
    data = response.json()
    assert data["schema_version"] == 1
    assert data["risk_tier"] == "high"
    assert {item["code"] for item in data["evidence"]} >= {
        "reply_to_domain_mismatch", "ip_literal_url"
    }
    assert data["content_probability"] >= 0


def test_email_triage_rejects_unreadable_message():
    response = client.post("/triage/email", json={"raw_email": "From: empty@example.org\n\n"})
    assert response.status_code == 400


def test_lureproof_create_and_verify_endpoints():
    raw = (
        "From: Security <alerts@example.org>\n"
        "Reply-To: collect@other.example\n"
        "Subject: Urgent account verification\n\n"
        "Verify your account at http://192.0.2.10/login within 24 hours."
    )
    created = client.post("/proof/email", json={"raw_email": raw})
    assert created.status_code == 200
    proof = created.json()
    assert proof["predicate"]["spec"] == "lureproof"
    assert proof["predicate"]["privacy"]["profile"] == "salted-commitment"
    assert "Urgent account verification" not in created.text
    verified = client.post("/proof/verify", json={"proof": proof})
    assert verified.status_code == 200
    assert verified.json()["valid"] is True
    assert verified.json()["authenticated"] is False
