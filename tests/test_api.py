"""API + service tests using FastAPI's TestClient."""

from __future__ import annotations

import pytest

pytest.importorskip("sklearn")  # tfidf detector needs scikit-learn

from fastapi.testclient import TestClient

from lurescope.app import app

client = TestClient(app)

LURE = (
    "Dear customer, we detected unusual activity on your account. Please verify your "
    "identity within 24 hours by clicking the secure link, or your account will be suspended."
)
BENIGN = "Hey, are we still on for lunch tomorrow? Let me know what time works."


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_capabilities_lists_detectors_and_attacks():
    c = client.get("/capabilities").json()
    assert "tfidf-logreg" in c["detectors"]
    assert "homoglyph" in c["attacks"]
    assert c["default_detector"] == "tfidf-logreg"


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
