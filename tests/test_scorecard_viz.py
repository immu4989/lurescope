"""Real optional PNG rendering with synthetic data, no providers or model loads.

Explicit opt-in must fail on missing/broken dependencies, never silently skip.
Default API tests do not require an image-processing stack.
"""

import copy
import os
import socket
from importlib.metadata import version

import pytest
from packaging.version import Version

pytestmark = pytest.mark.skipif(
    os.environ.get("LURESCOPE_TEST_VIZ") != "1",
    reason="explicit optional-visualization verification is not enabled",
)


@pytest.fixture
def plotting(monkeypatch, tmp_path):
    monkeypatch.setenv("MPLCONFIGDIR", str(tmp_path / "matplotlib"))
    monkeypatch.setenv("MPLBACKEND", "Agg")

    def no_network(*args, **kwargs):
        raise AssertionError("synthetic PNG rendering must not contact a network")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    assert Version(version("pillow")) >= Version("13.0.0")
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from PIL import Image

    from scripts import llm_scorecard, robustness_scorecard

    def no_evaluation(*args, **kwargs):
        raise AssertionError("rendering must not invoke a detector or provider")

    monkeypatch.setattr(robustness_scorecard, "_detector", no_evaluation)
    monkeypatch.setattr(llm_scorecard, "build_detectors", no_evaluation)
    monkeypatch.setattr(llm_scorecard, "build_attacker", no_evaluation)
    try:
        yield plt, Image, robustness_scorecard, llm_scorecard
    finally:
        plt.close("all")


def card_for(kind):
    from lurescope.scorecard_metrics import clean_summary, summarize_attacked

    attacks = ["synthetic-A", "synthetic-B"]
    _, caught = clean_summary([0.9, 0.9, 0.1, 0.1], 0.5)
    header = {"measurement_version": "scorecard-outcomes-v2", "threshold": 0.5, "n_fraud": 4}
    evaded = summarize_attacked([0.1, 0.1], 0.5)
    held = summarize_attacked([0.9, 0.9], 0.5)
    half = summarize_attacked([0.1, 0.9], 0.5)
    if kind == "robustness":
        return {**header, "detectors": {"synthetic": {**caught, "attacks": {
                attacks[0]: {"evasion_raw": 1.0, "evasion_normalized": 0.0,
                             "raw": evaded, "normalized": held},
                attacks[1]: {"evasion_raw": 0.5, "evasion_normalized": 0.5,
                             "raw": half, "normalized": dict(half)},
            },
        }}}
    _, blind = clean_summary([0.1] * 4, 0.5)
    return {**header, "attacks": attacks, "detectors": {
        "synthetic-caught": {**caught, "attacks": {
            attacks[0]: evaded, attacks[1]: held,
        }},
        "synthetic-blind": {**blind, "attacks": {
            attack: summarize_attacked([], 0.5) for attack in attacks
        }},
    }}


@pytest.mark.parametrize("kind", ["robustness", "cross-model"])
def test_real_png_round_trip_preserves_data_and_closes_figures(plotting, tmp_path, kind):
    plt, Image, robustness, cross_model = plotting
    renderer = robustness if kind == "robustness" else cross_model
    card = card_for(kind)
    original = copy.deepcopy(card)
    path = tmp_path / (kind + ".png")
    before = plt.get_fignums()
    assert renderer.to_png(card, str(path), "Synthetic compatibility fixture") is True
    assert path.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
    with Image.open(path) as image:
        assert image.format == "PNG" and image.mode in {"RGB", "RGBA"}
        assert 400 <= image.width <= 2000 and 200 <= image.height <= 1500
        image.verify()
    with Image.open(path) as image:
        image.load()
        assert any(low < high for low, high in image.convert("RGB").getextrema())
    assert card == original
    assert plt.get_fignums() == before


def test_missing_rates_are_masked_not_rendered_as_zero(plotting, tmp_path, monkeypatch):
    plt, _, _, renderer = plotting
    from matplotlib.axes import Axes

    imshow = Axes.imshow
    arrays = []

    def observe(self, *args, **kwargs):
        image = imshow(self, *args, **kwargs)
        arrays.append(image.get_array().copy())
        return image

    monkeypatch.setattr(Axes, "imshow", observe)
    renderer.to_png(card_for("cross-model"), str(tmp_path / "missing.png"), "Synthetic")
    assert len(arrays) == 1
    assert arrays[0].mask.tolist() == [[False, False], [True, True]]
    assert arrays[0][0].tolist() == [1.0, 0.0]
    assert not plt.get_fignums()


@pytest.mark.parametrize("kind", ["robustness", "cross-model"])
def test_inconclusive_rates_are_gray_with_bounds_and_coverage(
        plotting, tmp_path, monkeypatch, kind):
    plt, _, robustness, cross_model = plotting
    from matplotlib.axes import Axes

    from lurescope.scorecard_metrics import summarize_attacked

    renderer = robustness if kind == "robustness" else cross_model
    card = card_for(kind)
    card["measurement_version"] = "scorecard-outcomes-v2"
    metrics = summarize_attacked([0.1, None, 0.9], 0.5)
    row = next(iter(card["detectors"].values()))
    row.update(n_caught=3, clean_recall=0.75, clean_recall_upper=0.75)
    for cell in row["attacks"].values():
        if kind == "robustness":
            cell.update(evasion_raw=None, evasion_normalized=None,
                        raw=dict(metrics), normalized=dict(metrics))
        else:
            cell.update(metrics)
    observed = []
    imshow = Axes.imshow

    def observe(self, *args, **kwargs):
        image = imshow(self, *args, **kwargs)
        observed.append((image.get_array().copy(), self))
        return image

    monkeypatch.setattr(Axes, "imshow", observe)
    assert renderer.to_png(card, str(tmp_path / "inconclusive.png"), "Synthetic")
    data, axes = observed[0]
    assert data.mask[0].tolist() == [True, True]
    labels = [item.get_text() for item in axes.texts]
    assert any("[33%, 67%]" in label and "2/3 scored" in label for label in labels)
    assert not plt.get_fignums()
