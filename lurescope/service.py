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

from .defense import apply_defense, available_defenses

_MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
_DEFAULT_TFIDF = os.path.join(_MODEL_DIR, "tfidf-logreg-fraud.joblib")
_TOKEN = re.compile(r"[a-z0-9']+")

DEFAULT_DETECTOR = "tfidf-logreg"

# Always-on detectors: no key, no heavy deps, run anywhere (including the fully
# client-side HF Space). tfidf-logreg is the strong bundled baseline and the
# default; heuristic-v0 is the keyword detector kept because its collapse under a
# single homoglyph swap is the clearest illustration of the robustness gap.
ALWAYS_ON = ("tfidf-logreg", "heuristic-v0")

# Extended detectors reused straight from LureBench. These are the models a team
# actually deploys — an LLM-as-classifier and content-safety systems — so the
# interesting question is whether *they* survive the same attacks. They need a
# provider key or heavy local weights, so they are advertised as requestable but
# only construct when their requirement is met; otherwise the request 400s with a
# clear reason (mirroring the LLM-attack gate). The headline benchmark finding —
# Llama Guard scoring 0% true-positive on romance-baiting lures — lives in
# LureBench; LureScope lets you probe these detectors on a single message.
EXTENDED = ("llm-judge", "openai-moderation", "llama-guard-3", "binoculars")

# name -> (one-line kind, requirement string or None for always-on).
DETECTOR_INFO = {
    "tfidf-logreg": ("trained TF-IDF + logistic-regression baseline", None),
    "heuristic-v0": ("dependency-free keyword rules", None),
    "llm-judge": (
        "LLM-as-classifier (reads meaning, not tokens)",
        "an OpenAI-compatible provider: set LURESCOPE_LLM_ENGINE (e.g. deepseek, "
        "mistral) and that provider's API key",
    ),
    "openai-moderation": (
        "content-safety moderation API (a fraud proxy, not a fraud model)",
        "OPENAI_API_KEY and the 'openai' package",
    ),
    "llama-guard-3": (
        "Meta Llama Guard 3 content-safety model",
        "torch/transformers and gated access to meta-llama/Llama-Guard-3-8B",
    ),
    "binoculars": (
        "perplexity-based AI-generated-text detector",
        "torch/transformers and the reference model weights",
    ),
}


class DetectorUnavailable(ValueError):
    """A known detector was requested but its key/dependency is not configured."""


def _as_lure(text: str) -> Lure:
    # Scoring only reads ``.text``; the other fields are valid placeholders.
    return Lure(id="scope-0", text=text, label=0, source="human", typology="benign")


@lru_cache(maxsize=None)
def _detector(name: str, engine: Optional[str] = None, model: Optional[str] = None):
    if name == "tfidf-logreg":
        return get_detector("tfidf-logreg", model_path=_DEFAULT_TFIDF)
    if name == "llm-judge":
        engine = engine or os.environ.get("LURESCOPE_LLM_ENGINE")
        if not engine:
            raise DetectorUnavailable(_needs(name))
        try:
            return get_detector("llm-judge", engine=engine, model=model)
        except DetectorUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001 - missing key/dep -> clean 400
            raise DetectorUnavailable(f"{_needs(name)} ({type(exc).__name__}: {exc})") from exc
    if name in EXTENDED:
        try:
            return get_detector(name)
        except Exception as exc:  # noqa: BLE001 - missing key/dep -> clean 400
            raise DetectorUnavailable(f"{_needs(name)} ({type(exc).__name__}: {exc})") from exc
    return get_detector(name)


def _needs(name: str) -> str:
    kind, requires = DETECTOR_INFO.get(name, (name, None))
    if not requires:
        return f"{name} is available"
    return f"detector {name!r} ({kind}) needs {requires}"


def available_detectors() -> List[str]:
    """Always-on detectors, safe to advertise everywhere (used as the demo default)."""
    return list(ALWAYS_ON)


def all_detectors() -> List[str]:
    """Every requestable detector, including the key/dep-gated extended ones."""
    return list(ALWAYS_ON) + list(EXTENDED)


def detector_catalog() -> List[dict]:
    """Rich listing for /capabilities: name, kind, always-on vs its requirement."""
    out = []
    for name in all_detectors():
        kind, requires = DETECTOR_INFO.get(name, (name, None))
        out.append({"name": name, "kind": kind, "always_on": requires is None,
                    "requires": requires})
    return out


def available_defenses_() -> List[str]:
    return available_defenses()


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
    # Defense: populated when a defense other than "none" is applied. The defense
    # normalizes the *attacked* text before the detector re-scores it.
    defense: str = "none"
    defended_text: Optional[str] = None
    defended_probability: Optional[float] = None
    defended_flagged: Optional[bool] = None
    defense_recovered: Optional[bool] = None  # attack evaded, but the defense caught it back
    defended_evaded: Optional[bool] = None    # caught clean, still slips past even defended


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


def score(
    text: str,
    detector_name: str = DEFAULT_DETECTOR,
    threshold: float = 0.5,
    engine: Optional[str] = None,
    model: Optional[str] = None,
) -> ScoreResult:
    det = _detector(detector_name, engine, model)
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
    defense: str = "none",
) -> AttackResult:
    """Score ``text``, apply ``attack_name``, re-score, and optionally re-score once
    more after a ``defense`` normalizes the attacked text."""
    det = _detector(detector_name, engine, model)

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

    def _p(t: str) -> float:
        p = det.score(_as_lure(t))
        return 0.0 if p is None else float(p)

    clean_p = _p(text)
    att_p = _p(attacked_text)
    clean_flag = clean_p >= threshold
    att_flag = att_p >= threshold
    evaded = clean_flag and not att_flag  # was caught, now slips through

    result = AttackResult(
        detector=detector_name,
        attack=attack_name,
        original=text,
        attacked=attacked_text,
        clean_probability=clean_p,
        attacked_probability=att_p,
        threshold=threshold,
        clean_flagged=clean_flag,
        attacked_flagged=att_flag,
        evaded=evaded,
        defense=defense,
    )

    if defense and defense != "none":
        defended_text = apply_defense(defense, attacked_text)
        def_p = _p(defended_text)
        def_flag = def_p >= threshold
        result.defended_text = defended_text
        result.defended_probability = def_p
        result.defended_flagged = def_flag
        # The defense earns its keep only where the attack actually evaded.
        result.defense_recovered = evaded and def_flag
        result.defended_evaded = clean_flag and not def_flag

    return result
