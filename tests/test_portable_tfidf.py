"""Data-only serving must preserve the trusted reference model's behavior."""

import hashlib
import json
import random
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from lurescope.portable_tfidf import PROFILE, PortableTfidfDetector

ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / "lurescope/models/tfidf-logreg-fraud.json"
PIN = "12b30fae44d49f77c748c669552117ba25400cd9439bf4c9871bae31a8b16055"


@pytest.fixture(scope="module")
def portable():
    return PortableTfidfDetector(MODEL, expected_sha256=PIN)


def test_reference_parity(portable):
    # Only the already bundled, trusted reference is deserialized in this test.
    import joblib

    pipe = joblib.load(MODEL.with_suffix(".joblib"))["pipeline"]
    rng = random.Random(814)
    vocab = list(pipe.named_steps["tfidf"].vocabulary_)
    texts = ["", " ", "a I x", "😀💰", "Pay NOW!", "résumé İSTANBUL Straße Σ ς",
             "bank\u200baccount bank account", "verify " * 1000,
             "x" * 100_000, "\x00password\x00money\x00", "銀行 振込 至急"]
    texts += [" ".join(rng.choices(vocab, k=rng.randrange(1, 80))) for _ in range(1000)]
    texts += [p.read_text() for p in (ROOT / "lurescope/data/pilot").glob("*.eml")]
    expected = pipe.predict_proba(texts)[:, 1]
    for text, probability in zip(texts, expected, strict=True):
        assert portable.score(SimpleNamespace(text=text)) == pytest.approx(
            probability, abs=1e-12, rel=0,
        )
    coef = pipe.named_steps["clf"].coef_[0]
    terms = pipe.named_steps["tfidf"].get_feature_names_out()
    order = sorted(range(len(coef)), key=lambda i: coef[i], reverse=True)
    assert portable.top_positive_features(500) == [str(terms[i]) for i in order[:500]]


def _write(tmp_path, model):
    raw = json.dumps(model).encode()
    path = tmp_path / "model.json"
    path.write_bytes(raw)
    return path, hashlib.sha256(raw).hexdigest()


def _minimal():
    return {"profile": PROFILE, "source_sha256": "a" * 64,
            "intercept": 0, "features": [["bank", 1, 2]]}


@pytest.mark.parametrize("field,value", [
    ("profile", "custom-code"), ("source_sha256", "not-a-digest"),
    ("intercept", True), ("intercept", float("nan")), ("intercept", 1e7),
    ("features", []), ("features", [["bank", True, 1]]),
    ("features", [["bank", 0, 1]]), ("features", [["bank", 1, False]]),
    ("features", [["bank", 1, 1], ["bank", 1, 2]]),
    ("features", [["bank account now", 1, 1]]),
    ("features", [["BANK", 1, 1]]), ("features", [["a", 1, 1]]),
    ("features", [["bank", 1, 1, 1]]), ("unknown", "code"),
])
def test_rejects_unsupported_models(tmp_path, field, value):
    model = _minimal()
    model[field] = value
    path, pin = _write(tmp_path, model)
    with pytest.raises(ValueError):
        PortableTfidfDetector(path, expected_sha256=pin)


def test_pin_checked_before_parse(tmp_path):
    path = tmp_path / "bad.json"
    path.write_bytes(b"not JSON")
    with pytest.raises(ValueError, match="digest mismatch"):
        PortableTfidfDetector(path, expected_sha256="0" * 64)


@pytest.mark.parametrize("text", [None, 1, b"bank", "x" * 100_001])
def test_input_bound(portable, text):
    with pytest.raises(ValueError):
        portable.score(SimpleNamespace(text=text))


def test_extreme_valid_logits_are_stable(tmp_path):
    for intercept, expected in [(1e6, 1), (-1e6, 0)]:
        model = _minimal()
        model["intercept"] = intercept
        path, pin = _write(tmp_path, model)
        detector = PortableTfidfDetector(path, expected_sha256=pin)
        assert detector.score(SimpleNamespace(text="")) == expected


def test_inference_does_not_import_executable_model_frameworks():
    code = '''
import sys
from types import SimpleNamespace
class Deny:
    def find_spec(self, fullname, *args):
        if fullname.split('.')[0] in {'joblib', 'pickle', 'sklearn', 'numpy', 'torch'}:
            raise AssertionError('forbidden model dependency: ' + fullname)
sys.meta_path.insert(0, Deny())
from lurescope.portable_tfidf import PortableTfidfDetector
detector = PortableTfidfDetector(sys.argv[1], expected_sha256=sys.argv[2])
assert 0 <= detector.score(SimpleNamespace(text='verify your bank account')) <= 1
'''
    subprocess.run([sys.executable, "-c", code, str(MODEL), PIN], check=True, cwd=ROOT)


def test_export_reproducible_and_exclusive(tmp_path):
    from scripts.export_portable_tfidf import export

    out = tmp_path / "export.json"
    source_pin = "84c7254c464ff9faa3ede012691c13d53da08ab1f26223633af7b9377d60ed0b"
    with pytest.raises(ValueError, match="digest mismatch"):
        export(MODEL.with_suffix(".joblib"), "0" * 64, out)
    assert not out.exists()
    assert export(MODEL.with_suffix(".joblib"), source_pin, out) == PIN
    assert out.read_bytes() == MODEL.read_bytes()
    with pytest.raises(FileExistsError):
        export(MODEL.with_suffix(".joblib"), source_pin, out)


def test_service_and_new_evidence_bind_loaded_json(portable):
    from lurescope.pilot import detector_artifact_sha256
    from lurescope.proof import create_email_proof
    from lurescope.service import _detector

    assert isinstance(_detector("tfidf-logreg"), PortableTfidfDetector)
    assert detector_artifact_sha256("tfidf-logreg") == PIN
    statement = create_email_proof(b"Subject: bank verification\n\nPlease verify your account.")
    assessment = statement["predicate"]["assessment"]
    assert assessment["detector_model"] == MODEL.name
    assert assessment["detector_artifact_sha256"] == PIN == portable.artifact_sha256


def test_pilot_receipt_accepts_only_reviewed_old_and_new_pins(tmp_path):
    import copy

    import jsonschema

    from lurescope.operational_pilot import (
        LEGACY_DETECTOR_SHA256,
        _validate_receipt,
        run_operational_pilot,
    )

    receipt = run_operational_pilot(tmp_path / "pilot")
    schema = json.loads((ROOT / "spec/operational-pilot-receipt-v1.schema.json").read_text())
    for pin in (LEGACY_DETECTOR_SHA256, PIN):
        candidate = copy.deepcopy(receipt)
        candidate["workflow"]["detector_artifact_sha256"] = pin
        _validate_receipt(candidate)
        jsonschema.validate(candidate, schema)
    for pin in ("0" * 64, [], True):
        candidate = copy.deepcopy(receipt)
        candidate["workflow"]["detector_artifact_sha256"] = pin
        with pytest.raises(ValueError):
            _validate_receipt(candidate)
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(candidate, schema)
