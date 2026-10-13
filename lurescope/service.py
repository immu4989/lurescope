"""Core scoring + attack service.

LureScope is the deployable companion to LureBench. LureBench answers "how good is
this detector on a benchmark"; LureScope wraps a detector behind an API so you can
score a single message and — the differentiator — watch an attacker try to evade it
in real time. Attacks and extended detectors reuse ``lurebench``. The default
bundled classifier uses a data-only inference profile, tested against its original
LureBench/scikit-learn model to an absolute probability tolerance of 1e-12.
"""

from __future__ import annotations

import math
import os
import re
import threading
from contextlib import ExitStack
from dataclasses import dataclass
from numbers import Real
from typing import List, Optional

from lurebench.attacks import available as attack_names
from lurebench.attacks import get_attack
from lurebench.detectors import get_detector
from lurebench.schema import Lure

from .defense import apply_defense, available_defenses
from .policy import configured_policy
from .portable_tfidf import PortableTfidfDetector

_MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
_DEFAULT_TFIDF = os.path.join(_MODEL_DIR, "tfidf-logreg-fraud.json")
_DEFAULT_TFIDF_SHA256 = "12b30fae44d49f77c748c669552117ba25400cd9439bf4c9871bae31a8b16055"
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

# Fixed cardinality: request-supplied engine/model strings never become keys.
# Separate locks keep cold optional weights from blocking the default detector.
_LOCAL_DETECTOR_LOCKS = {
    name: threading.Lock() for name in (*ALWAYS_ON, "llama-guard-3")
}
_LOCAL_DETECTORS = {}

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
        "provenance-only AI-generated-text ranking proxy, not a fraud detector",
        "offline provenance evaluation in LureBench; disabled on LureScope fraud endpoints",
    ),
}


class DetectorUnavailable(ValueError):
    """A known detector was requested but its key/dependency is not configured."""


class DetectorOutputError(RuntimeError):
    """A detector abstained or violated the finite probability contract."""


def _probability(value) -> float:
    if value is None:
        raise DetectorOutputError("detector abstained; no risk decision is available")
    if isinstance(value, bool) or not isinstance(value, Real):
        raise DetectorOutputError("detector did not return a finite probability in [0, 1]")
    try:
        result = float(value)
    except (OverflowError, TypeError, ValueError) as exc:
        raise DetectorOutputError("detector probability cannot be represented") from exc
    if not math.isfinite(result) or not 0 <= result <= 1:
        raise DetectorOutputError("detector did not return a finite probability in [0, 1]")
    return result


def _as_lure(text: str) -> Lure:
    # Scoring only reads ``.text``; the other fields are valid placeholders.
    return Lure(id="scope-0", text=text, label=0, source="human", typology="benign")


def _detector(name: str, engine: Optional[str] = None, model: Optional[str] = None):
    if name not in DETECTOR_INFO:
        raise KeyError("detector is not served by LureScope")
    if name == "binoculars":
        # Do not load upstream models or relabel P(ai)-like scores as fraud risk.
        raise DetectorUnavailable(_needs(name))
    if name in _LOCAL_DETECTOR_LOCKS:
        # A thread-safe cache alone does not prevent duplicate construction on
        # concurrent misses. Hold this name's lock through successful publication.
        with _LOCAL_DETECTOR_LOCKS[name]:
            if name not in _LOCAL_DETECTORS:
                if name == "tfidf-logreg":
                    detector = PortableTfidfDetector(
                        _DEFAULT_TFIDF, expected_sha256=_DEFAULT_TFIDF_SHA256,
                    )
                elif name == "llama-guard-3":
                    try:
                        detector = get_detector(name)
                    except Exception as exc:  # noqa: BLE001
                        raise DetectorUnavailable(_needs(name)) from exc
                else:
                    detector = get_detector(name)
                _LOCAL_DETECTORS[name] = detector
            return _LOCAL_DETECTORS[name]
    # Provider constructors capture credentials and configuration. Do not retain
    # them across service operations or put secrets/fingerprints into cache keys.
    # One attack operation still reuses its own detector for all scoring steps.
    if name == "llm-judge":
        engine = engine or os.environ.get("LURESCOPE_LLM_ENGINE")
        if not engine:
            raise DetectorUnavailable(_needs(name))
        try:
            return get_detector("llm-judge", engine=engine, model=model)
        except DetectorUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001 - missing key/dep -> clean 400
            raise DetectorUnavailable(_needs(name)) from exc
    if name in EXTENDED:
        try:
            return get_detector(name)
        except Exception as exc:  # noqa: BLE001 - missing key/dep -> clean 400
            raise DetectorUnavailable(_needs(name)) from exc
    raise KeyError("detector is not served by LureScope")


def _clear_detector_cache():
    """Drop local cache references after any in-progress constructors finish.

    Existing scoring operations keep their references. This is not a model
    cancellation, GPU-memory reclamation, or live configuration reload API.
    """
    with ExitStack() as stack:
        for lock in _LOCAL_DETECTOR_LOCKS.values():
            stack.enter_context(lock)
        _LOCAL_DETECTORS.clear()


# Preserve the existing private test/operator reset hook, without an unbounded
# decorator around raw request controls. There is no HTTP cache-reset endpoint.
_detector.cache_clear = _clear_detector_cache


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
    policy_id: Optional[str] = None
    threshold_source: str = "default"


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
    threshold: Optional[float] = None,
    engine: Optional[str] = None,
    model: Optional[str] = None,
) -> ScoreResult:
    if threshold is not None:
        threshold = _decision_threshold(threshold)
    policy = configured_policy()
    if threshold is not None:
        resolved_threshold = threshold
        policy_id = None
        threshold_source = "request"
    elif policy is not None and policy.detector == detector_name:
        resolved_threshold = policy.threshold
        policy_id = policy.policy_id
        threshold_source = "validated_policy"
    else:
        resolved_threshold = 0.5
        policy_id = None
        threshold_source = "default"
    det = _detector(detector_name, engine, model)
    prob = _probability(det.score(_as_lure(text)))
    return ScoreResult(
        text=text,
        detector=detector_name,
        fraud_probability=prob,
        label="fraud" if prob >= resolved_threshold else "benign",
        threshold=resolved_threshold,
        signals=_top_signals(det, text),
        policy_id=policy_id,
        threshold_source=threshold_source,
    )


def _decision_threshold(value) -> float:
    try:
        return _probability(value)
    except DetectorOutputError as exc:
        raise ValueError("decision threshold must be a finite probability in [0, 1]") from exc


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
    threshold = _decision_threshold(threshold)
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
    def _p(t: str) -> float:
        return _probability(det.score(_as_lure(t)))

    clean_p = _p(text)
    # Do not generate an attack (which may spend provider credit) if the clean
    # detector has no valid decision. Never turn abstention into a benign score.
    attacked_text = atk.apply(text)
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
