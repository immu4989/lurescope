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


def test_demo_page_served_at_root():
    r = client.get("/")
    assert r.status_code == 200
    assert "LureScope" in r.text
