"""Core scoring + attack service.

LureScope is the deployable companion to LureBench. LureBench answers "how good is
this detector on a benchmark"; LureScope wraps a detector behind an API so you can
score a single message and — the differentiator — watch an attacker try to evade it
in real time. All detection and attack logic is reused from the ``lurebench`` package
so the service and the benchmark can never drift apart.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import List, Optional

from lurebench.attacks import available as attack_names
from lurebench.attacks import get_attack
from lurebench.detectors import get_detector
from lurebench.schema import Lure

_MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
_DEFAULT_TFIDF = os.path.join(_MODEL_DIR, "tfidf-logreg-fraud.joblib")
_TOKEN = re.compile(r"[a-z0-9']+")

# Detectors we expose. tfidf-logreg is the strong default (bundled trained model);
# heuristic-v0 is the dependency-free keyword baseline, kept because its dramatic
# collapse under attack is the clearest illustration of the robustness gap.
DEFAULT_DETECTOR = "tfidf-logreg"
EXPOSED_DETECTORS = ("tfidf-logreg", "heuristic-v0")


def _as_lure(text: str) -> Lure:
    # Scoring only reads ``.text``; the other fields are valid placeholders.
    return Lure(id="scope-0", text=text, label=0, source="human", typology="benign")


@lru_cache(maxsize=None)
def _detector(name: str):
    if name == "tfidf-logreg":
        return get_detector("tfidf-logreg", model_path=_DEFAULT_TFIDF)
    return get_detector(name)


def available_detectors() -> List[str]:
    return list(EXPOSED_DETECTORS)


def available_attacks() -> List[str]:
    # Character-level attacks run with no key; LLM attacks need a provider key and are
    # only offered when one is configured (see ``attack`` for the guard).
    return attack_names()


@dataclass
class ScoreResult:
    text: str
    detector: str
    fraud_probability: float
    label: str
    threshold: float
    signals: List[str]


@dataclass
class AttackResult:
    detector: str
    attack: str
    original: str
    attacked: str
    clean_probability: float
    attacked_probability: float
    threshold: float
    clean_flagged: bool
    attacked_flagged: bool
    evaded: bool


def _top_signals(detector, text: str, top_k: int = 6) -> List[str]:
    """Words in ``text`` that are among the detector's most fraud-predictive terms."""
    extract = getattr(detector, "top_positive_features", None)
    if not callable(extract):
        return []
    try:
        predictive = [w for w in extract(200) if " " not in w]  # unigrams only
    except Exception:  # noqa: BLE001
        return []
    predictive_set = set(predictive)
    seen, out = set(), []
    for tok in _TOKEN.findall(text.lower()):
        if tok in predictive_set and tok not in seen:
            seen.add(tok)
            out.append(tok)
        if len(out) >= top_k:
            break
    return out


def score(text: str, detector_name: str = DEFAULT_DETECTOR, threshold: float = 0.5) -> ScoreResult:
    det = _detector(detector_name)
    prob = det.score(_as_lure(text))
    prob = 0.0 if prob is None else float(prob)
    return ScoreResult(
        text=text,
        detector=detector_name,
        fraud_probability=prob,
        label="fraud" if prob >= threshold else "benign",
        threshold=threshold,
        signals=_top_signals(det, text),
    )


def _build_attack(attack_name: str, detector, complete_fn=None):
    if attack_name == "llm-keyword-evasion":
        from lurebench.attacks.llm import LLMKeywordEvasionAttack

        extract = getattr(detector, "top_positive_features", None)
        words = list(extract(25)) if callable(extract) else ["verify", "urgent", "account"]
        return LLMKeywordEvasionAttack(complete_fn, words)
    if attack_name == "llm-paraphrase":
        from lurebench.attacks.llm import LLMParaphraseAttack

        return LLMParaphraseAttack(complete_fn)
    return get_attack(attack_name)


def attack(
    text: str,
    attack_name: str,
    detector_name: str = DEFAULT_DETECTOR,
    threshold: float = 0.5,
    engine: Optional[str] = None,
    model: Optional[str] = None,
) -> AttackResult:
    """Score ``text``, apply ``attack_name``, and re-score to see if it now evades."""
    det = _detector(detector_name)

    complete_fn = None
    if attack_name.startswith("llm-"):
        engine = engine or os.environ.get("LURESCOPE_LLM_ENGINE")
        if not engine:
            raise ValueError(
                f"{attack_name} needs an LLM provider; set engine (and that provider's "
                "API key) or use a character-level attack."
            )
        from lurebench.attacks.llm import provider_complete_fn

        complete_fn = provider_complete_fn(engine, model)

    atk = _build_attack(attack_name, det, complete_fn)
    attacked_text = atk.apply(text)

    clean_p = det.score(_as_lure(text))
    clean_p = 0.0 if clean_p is None else float(clean_p)
    att_p = det.score(_as_lure(attacked_text))
    att_p = 0.0 if att_p is None else float(att_p)

    clean_flag = clean_p >= threshold
    att_flag = att_p >= threshold
    return AttackResult(
        detector=detector_name,
        attack=attack_name,
        original=text,
        attacked=attacked_text,
        clean_probability=clean_p,
        attacked_probability=att_p,
        threshold=threshold,
        clean_flagged=clean_flag,
        attacked_flagged=att_flag,
        evaded=clean_flag and not att_flag,  # was caught, now slips through
    )
