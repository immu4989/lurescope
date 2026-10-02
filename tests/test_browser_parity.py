"""Cross-language scoring regressions using synthetic text, never provider calls."""

import itertools
import json
import math
import random
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from lurebench.detectors.heuristic import HeuristicDetector

from lurescope import service

ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="Node needed for cross-language parity")


def browser_scores(texts, detector):
    code = """
const fs = require('node:fs');
const engine = require(process.argv[1] + '/lurescope/static/browser-engine.js');
const weights = process.argv[1] + '/lurescope/static/model.json';
engine.setModel(JSON.parse(fs.readFileSync(weights, 'utf8')));
const texts = JSON.parse(fs.readFileSync(0, 'utf8'));
const scores = texts.map(t => engine.scoreMessage(t, process.argv[2]).fraud_probability);
process.stdout.write(JSON.stringify(scores));
"""
    result = subprocess.run([NODE, "-e", code, str(ROOT), detector],
                            input=json.dumps(texts), capture_output=True, text=True,
                            check=True, timeout=30)
    return json.loads(result.stdout)


def test_unicode_heuristic_matches_python_on_2048_boundary_cases():
    phrases = ["urgent", "within ٢ hours", "ſign in", "İnvoice", "ınvoice",
               "your banK", "keep this confidential", "verify your account"]
    neighbors = ["", " ", "а", "中", "²", "_", "\u0301", "📄"]
    texts = [left + transform(phrase) + right
             for phrase, left, right, transform in itertools.product(
                 phrases, neighbors, neighbors, [str, str.upper, str.lower, str.title])]
    assert len(texts) == 2048
    reference = HeuristicDetector()
    for text, actual in zip(texts, browser_scores(texts, "heuristic-v0"), strict=True):
        expected = reference.score(SimpleNamespace(text=text))
        assert math.isclose(actual, expected, rel_tol=0, abs_tol=1e-14), repr(text)


def test_rounded_browser_tfidf_matches_portable_with_explicit_tolerance():
    detector = service._detector("tfidf-logreg")
    rng = random.Random(20261002)
    vocabulary = sorted(term for term in detector._features if " " not in term and term.isascii())
    texts = [" ".join(rng.choices(vocabulary, k=rng.randint(1, 60))) for _ in range(256)]
    texts += ["__proto__ constructor", "Please verify your bank account",
              "Cafe\u0301 📄 notes", "urgentа within ٢ hours", "İnvoice ınvoice ſign in"]
    for text, actual in zip(texts, browser_scores(texts, "tfidf-logreg"), strict=True):
        expected = detector.score(SimpleNamespace(text=text))
        assert math.isclose(actual, expected, rel_tol=0, abs_tol=1e-5), repr(text)


def test_numeric_html_email_references_match_python_scoring_and_links():
    from lurescope.triage import triage_email

    phrases = ["Urgent verify your account", "Sign in within 24 hours", "Please review 📄 notes",
               "аurgentа", "İnvoice ınvoice ſign in", "within ٢ hours", "your banK", "A < B & C"]
    encoders = [lambda c: f"&#{ord(c)};", lambda c: f"&#x{ord(c):x};",
                lambda c: f"&#{ord(c)}", lambda c: f"&#X{ord(c):X}"]
    messages = [
        'Content-Type: text/html; charset=utf-8\r\n\r\n<p>' +
        "".join(encode(c) for c in phrase) + '</p><a href="&#104;ttps://127.0.0.1/?a=1&amp;b=2">Portal</a>'
        for phrase, encode in itertools.product(phrases, encoders)
    ]
    code = """
const fs = require('node:fs');
const engine = require(process.argv[1] + '/lurescope/static/browser-engine.js');
const messages = JSON.parse(fs.readFileSync(0, 'utf8'));
process.stdout.write(JSON.stringify(messages.map(m => engine.triageEmail(m, 'heuristic-v0'))));
"""
    result = subprocess.run([NODE, "-e", code, str(ROOT)], input=json.dumps(messages),
                            capture_output=True, text=True, check=True, timeout=30)
    for message, actual in zip(messages, json.loads(result.stdout), strict=True):
        expected = triage_email(message.encode(), "heuristic-v0")
        assert math.isclose(actual["content_probability"], expected.content_probability,
                            rel_tol=0, abs_tol=1e-14)
        assert actual["urls"] == expected.urls
        assert {item["code"] for item in actual["evidence"]} == {
            item.code for item in expected.evidence
        }
