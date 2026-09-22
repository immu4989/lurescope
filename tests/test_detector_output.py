import math

import pytest

from lurescope import service


@pytest.mark.parametrize("value", [None, True, False, "0.5", [], {}, math.nan,
                                  math.inf, -math.inf, -0.01, 1.01, 10**400])
def test_invalid_scores_never_become_benign(value):
    with pytest.raises(service.DetectorOutputError):
        service._probability(value)


@pytest.mark.parametrize("value", [0, 0.0, 0.5, 1, 1.0])
def test_probability_boundaries_remain_valid(value):
    assert service._probability(value) == float(value)


class SequenceDetector:
    def __init__(self, values):
        self.values = iter(values)

    def score(self, lure):
        return next(self.values)


def test_score_abstention_has_no_result(monkeypatch):
    monkeypatch.setattr(service, "_detector", lambda *args: SequenceDetector([None]))
    with pytest.raises(service.DetectorOutputError, match="abstained"):
        service.score("synthetic text", detector_name="heuristic-v0")


def test_clean_abstention_prevents_attack_generation(monkeypatch):
    monkeypatch.setattr(service, "_detector", lambda *args: SequenceDetector([None]))

    class NoGeneration:
        def apply(self, text):
            raise AssertionError("must not generate an attack without a valid clean score")

    monkeypatch.setattr(service, "_build_attack", lambda *args: NoGeneration())
    with pytest.raises(service.DetectorOutputError, match="abstained"):
        service.attack("synthetic text", "homoglyph", detector_name="heuristic-v0")


@pytest.mark.parametrize("scores", [[0.9, None], [0.9, 0.1, None], [0.9, 0.1, math.nan]])
def test_attacked_or_defended_abstention_never_claims_evasion_or_recovery(monkeypatch, scores):
    detector = SequenceDetector(scores)
    monkeypatch.setattr(service, "_detector", lambda *args: detector)

    class SyntheticAttack:
        def apply(self, text):
            return text + " changed"

    monkeypatch.setattr(service, "_build_attack", lambda *args: SyntheticAttack())
    monkeypatch.setattr(service, "apply_defense", lambda *args: "normalized synthetic text")
    with pytest.raises(service.DetectorOutputError):
        service.attack("synthetic text", "homoglyph", detector_name="heuristic-v0",
                       defense="normalize")


@pytest.mark.parametrize("name,engine", [("llm-judge", "test-engine"), ("llama-guard-3", None)])
def test_detector_construction_error_is_not_republished(monkeypatch, name, engine):
    secret = "SENTINEL_PROVIDER_KEY_AND_PRIVATE_MESSAGE"

    def fail(*args, **kwargs):
        raise RuntimeError(secret)

    service._detector.cache_clear()
    monkeypatch.setattr(service, "get_detector", fail)
    with pytest.raises(service.DetectorUnavailable) as caught:
        service._detector(name, engine)
    assert secret not in str(caught.value)
    service._detector.cache_clear()
