"""Offline identity, replay and persistence tests for the cross-model scorecard."""

import hashlib
import json
import os
import socket
import threading
from types import SimpleNamespace

import pytest

from lurescope import scorecard_cache as storage
from scripts import llm_scorecard as script

CONTEXT = "a" * 64


def caches():
    return storage.envelope("scores", CONTEXT), storage.envelope("paraphrases", CONTEXT)


def test_real_baselines_load_portable_json_without_joblib(monkeypatch):
    original = script.get_detector

    def detector(name, **kwargs):
        if name == "llm-judge":
            return SimpleNamespace(score=lambda record: .8)
        return original(name, **kwargs)

    monkeypatch.setattr(script, "get_detector", detector)
    dets = script.build_detectors(["synthetic/model"])
    assert 0 <= dets["tfidf-logreg"]("Synthetic ordinary meeting notes") <= 1
    assert 0 <= dets["heuristic-v0"]("Synthetic ordinary meeting notes") <= 1
    assert dets["judge:synthetic/model"]("Synthetic notes") == .8


def test_duplicate_texts_and_identical_variants_share_one_score(monkeypatch):
    noop = SimpleNamespace(apply=lambda text: text)
    monkeypatch.setattr(script, "get_attack", lambda _: noop)
    calls = []
    results = script.run([{"text": "same"}] * 2,
                         {"d": lambda text: calls.append(text) or .9},
                         noop, {}, {}, 2, threading.Lock())
    assert calls == ["same"]
    assert len(results["d"]) == 2


@pytest.mark.parametrize("value", [None, "", "  ", True, 1, "\ud800"])
def test_invalid_paraphrases_fail_before_any_scoring(value):
    def forbidden(text):
        pytest.fail("invalid paraphrase reached scoring")

    with pytest.raises(ValueError, match="paraphrase"):
        script.run([{"text": "synthetic"}], {"d": forbidden},
                   SimpleNamespace(apply=lambda text: value), {}, {}, 1, threading.Lock())


@pytest.mark.parametrize("value", [None, "", " \n", True, 1, "\ud800"])
def test_real_attack_adapter_does_not_turn_failed_generation_into_original_text(monkeypatch, value):
    monkeypatch.setattr(script, "get_generator", lambda *a, **kw:
                        SimpleNamespace(complete=lambda system, text: value))
    with pytest.raises(ValueError, match="paraphrase"):
        script.build_attacker("synthetic/model").apply("synthetic original")


@pytest.mark.parametrize("value", [0, .9, None])
def test_bound_roundtrip_replays_scores_and_abstentions_without_calls(monkeypatch, value):
    scores, paraphrases = caches()
    calls = []
    noop = SimpleNamespace(apply=lambda text: calls.append("attack") or text)
    monkeypatch.setattr(script, "get_attack", lambda _: SimpleNamespace(apply=lambda text: text))
    records = [{"text": "synthetic"}] * 3
    first = script.run(records, {"d": lambda text: calls.append("score") or value}, noop,
                       scores, paraphrases, 3, threading.Lock(), cache_context=CONTEXT)
    assert calls == ["attack", "score"]
    snapshot = json.dumps([scores, paraphrases], sort_keys=True)
    replay = script.run(records, {"d": None}, None, scores, paraphrases, 3,
                        threading.Lock(), cache_context=CONTEXT, cache_only=True)
    assert first == replay and len(replay["d"]) == 3
    assert json.dumps([scores, paraphrases], sort_keys=True) == snapshot


@pytest.mark.parametrize("kind", ["scores", "paraphrases"])
@pytest.mark.parametrize("change", ["context", "version", "kind", "entries", "key", "extra"])
def test_invalid_bound_cache_fails_before_any_callback(kind, change):
    scores, paraphrases = caches()
    target = scores if kind == "scores" else paraphrases
    if change == "key":
        target["entries"]["bad-key"] = .9 if kind == "scores" else "text"
    elif change == "entries":
        target["entries"] = []
    else:
        target[change] = "wrong"

    def forbidden(*args):
        pytest.fail("bad cache reached paid work")

    with pytest.raises(ValueError, match="cache"):
        script.run([{"text": "synthetic"}], {"d": forbidden},
                   SimpleNamespace(apply=forbidden), scores, paraphrases, 1,
                   threading.Lock(), cache_context=CONTEXT)


@pytest.mark.parametrize("kind,value", [("scores", True), ("scores", "0.9"),
                                        ("scores", float("nan")), ("scores", 2),
                                        ("paraphrases", None), ("paraphrases", ""),
                                        ("paraphrases", "\ud800")])
def test_every_cached_value_is_validated_even_when_not_selected(kind, value):
    scores, paraphrases = caches()
    target = scores if kind == "scores" else paraphrases
    target["entries"]["f" * 64] = value

    def forbidden(*args):
        pytest.fail("invalid unused entry reached a callback")

    with pytest.raises(ValueError):
        script.run([{"text": "synthetic"}], {"d": forbidden},
                   SimpleNamespace(apply=forbidden), scores, paraphrases, 1,
                   threading.Lock(), cache_context=CONTEXT)


@pytest.mark.parametrize("missing", ["paraphrase", "scores"])
def test_incomplete_replay_cannot_fall_back_to_live_work(missing):
    scores, paraphrases = caches()
    if missing == "scores":
        paraphrases["entries"][storage.paraphrase_key("synthetic")] = "synthetic rewrite"
    with pytest.raises(ValueError, match="cache-only"):
        script.run([{"text": "synthetic"}], {"d": None}, None, scores, paraphrases,
                   1, threading.Lock(), cache_context=CONTEXT, cache_only=True)


def test_nonempty_ephemeral_cache_cannot_be_silently_reused():
    with pytest.raises(ValueError, match="explicit experiment context"):
        script.run([{"text": "x"}], {"d": None}, None, {"old": .9}, {}, 1, threading.Lock())


@pytest.mark.parametrize("workers", [0, -1, True, 1.5, 129])
def test_invalid_worker_bound_prevents_callbacks(workers):
    with pytest.raises(ValueError, match="workers"):
        script.run([{"text": "x"}], {"d": None}, None, {}, {}, workers, threading.Lock())


def test_parallel_failure_does_not_admit_remaining_work():
    started, consumed = [], []

    def inputs():
        for i in range(100):
            consumed.append(i)
            yield i

    def fail(i):
        started.append(i)
        raise ValueError("synthetic failure")

    with pytest.raises(ValueError, match="synthetic failure"):
        script._parallel(fail, inputs(), 3)
    assert len(started) <= 3 and consumed == [0, 1, 2]


def test_failed_bound_run_does_not_publish_partial_cache_mutations():
    scores, paraphrases = caches()
    before = json.dumps([scores, paraphrases], sort_keys=True)
    with pytest.raises(ValueError, match="probability"):
        script.run([{"text": "synthetic"}], {"d": lambda text: True},
                   SimpleNamespace(apply=lambda text: text), scores, paraphrases, 1,
                   threading.Lock(), cache_context=CONTEXT)
    assert json.dumps([scores, paraphrases], sort_keys=True) == before


@pytest.mark.parametrize("kind,value", [("scores", None), ("scores", 0),
                                        ("paraphrases", "café 東京")])
def test_cache_file_roundtrip_is_strict_and_private(tmp_path, kind, value):
    path = tmp_path / "cache.json"
    cache = storage.CacheFile(path, kind, CONTEXT)
    assert not path.exists()
    cache.value["entries"]["f" * 64] = value
    cache.flush()
    assert storage.CacheFile(path, kind, CONTEXT).value == cache.value
    assert not list(tmp_path.glob(".scorecard-cache-*"))
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("payload", [b"", b"{}", b"[]", b'{"legacy":0.9}',
                                     b'{"private":0,"private":1}',
                                     b'{"private":NaN}', b'{"private":1e999}', b'\xff'])
def test_bad_existing_cache_never_silently_starts_over(tmp_path, payload):
    path = tmp_path / "cache.json"
    path.write_bytes(payload)
    with pytest.raises(ValueError) as error:
        storage.CacheFile(path, "scores", CONTEXT)
    assert "private" not in str(error.value)
    assert path.read_bytes() == payload


@pytest.mark.parametrize("failure", ["fsync", "replace", "changed", "size"])
def test_failed_publication_preserves_prior_bytes_and_cleans_staging(
        tmp_path, monkeypatch, failure):
    path = tmp_path / "cache.json"
    cache = storage.CacheFile(path, "scores", CONTEXT)
    cache.flush()
    before = path.read_bytes()
    cache.value["entries"]["b" * 64] = .9
    if failure == "changed":
        before = b"changed concurrently"
        path.write_bytes(before)
    elif failure == "size":
        monkeypatch.setattr(storage, "MAX_CACHE_BYTES", 10)
    else:
        def broken(*args):
            raise OSError("synthetic persistence failure")
        monkeypatch.setattr(storage.os, "fsync" if failure == "fsync" else "replace", broken)
    with pytest.raises((OSError, ValueError)):
        cache.flush()
    assert path.read_bytes() == before
    assert not list(tmp_path.glob(".scorecard-cache-*"))


@pytest.mark.parametrize("kind", ["symlink", "fifo", "directory"])
def test_cache_file_rejects_nonregular_sources(tmp_path, kind):
    path = tmp_path / "cache"
    if kind == "symlink":
        path.symlink_to(tmp_path / "missing")
    elif kind == "directory":
        path.mkdir()
    else:
        if not hasattr(os, "mkfifo"):
            pytest.skip("POSIX FIFO required")
        os.mkfifo(path)
    with pytest.raises(ValueError, match="regular|symlink"):
        storage.CacheFile(path, "scores", CONTEXT)


def test_alias_paths_are_refused_including_hard_links(tmp_path):
    source = tmp_path / "source"
    source.write_text("unchanged")
    alias = tmp_path / "alias"
    os.link(source, alias)
    for other in (source, tmp_path / "." / "source", alias):
        with pytest.raises(ValueError, match="distinct"):
            storage.distinct_paths([source, other])


@pytest.mark.parametrize("mutation", ["judge", "attacker", "epoch", "prompt", "attack_prompt",
                                       "endpoint", "runtime", "implementation"])
def test_experiment_identity_changes_for_measurement_configuration(monkeypatch, mutation):
    from lurebench.attacks import llm as attacks
    from lurebench.detectors import llm
    from lurebench.generate import PROVIDERS

    judges, attacker, epoch = ["synthetic/judge"], "synthetic/attacker", "epoch"
    before = script.experiment_identity(judges, attacker, epoch)
    if mutation == "judge":
        judges = ["synthetic/other"]
    elif mutation == "attacker":
        attacker = "synthetic/other"
    elif mutation == "epoch":
        epoch = "different epoch"
    elif mutation == "prompt":
        monkeypatch.setattr(llm.LLMJudgeDetector, "system_prompt", "different prompt")
    elif mutation == "attack_prompt":
        monkeypatch.setattr(attacks, "_PARAPHRASE_SYS", "different prompt")
    elif mutation == "endpoint":
        monkeypatch.setitem(PROVIDERS, "openrouter", {**PROVIDERS["openrouter"],
                                                     "base_url": "https://example.invalid/v1"})
    elif mutation == "runtime":
        monkeypatch.setattr(script.platform, "python_version", lambda: "changed")
    else:
        original = script.read_regular_file

        def changed(path, **kwargs):
            value = original(path, **kwargs)
            return value + b"\n# synthetic change\n" if path.name == "llm.py" else value

        monkeypatch.setattr(script, "read_regular_file", changed)
    after = script.experiment_identity(judges, attacker, epoch)
    assert before["sha256"] != after["sha256"]
    assert storage.fingerprint(after["configuration"]) == after["sha256"]
    assert len(after["configuration"]["portable_runtime_sha256"]) == 64


def test_experiment_identity_does_not_read_or_store_provider_secret(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "private-secret-never-in-cache")
    first = script.experiment_identity(["synthetic/judge"], "synthetic/attacker")
    monkeypatch.delenv("OPENROUTER_API_KEY")
    assert script.experiment_identity(["synthetic/judge"], "synthetic/attacker") == first
    assert "private-secret" not in json.dumps(first)


def test_cli_matching_replay_needs_no_key_factories_network_or_cache_writes(
        tmp_path, monkeypatch, capsys):
    source, scores, paraphrases, output = [
        tmp_path / name for name in ("input.jsonl", "scores.json", "para.json", "result.json")]
    source.write_text(json.dumps({"text": "synthetic message", "label": 1}) + "\n")
    panel = ["tfidf-logreg", "heuristic-v0", "judge:synthetic/judge"]
    monkeypatch.setenv("OPENROUTER_API_KEY", "synthetic-not-a-key")
    monkeypatch.setattr(script, "build_detectors", lambda _: dict.fromkeys(panel, lambda text: .9))
    monkeypatch.setattr(script, "build_attacker",
                        lambda _: SimpleNamespace(apply=lambda text: text))
    args = ["--data", str(source), "--cache", str(scores), "--para-cache", str(paraphrases),
            "--judges", "synthetic/judge", "--attacker", "synthetic/attacker",
            "--out-json", str(output)]
    assert script.main(args) == 0
    original = json.loads(output.read_text())
    snapshots = [(p.read_bytes(), p.stat().st_mtime_ns) for p in (scores, paraphrases)]
    monkeypatch.delenv("OPENROUTER_API_KEY")

    def forbidden(*args, **kwargs):
        pytest.fail("cache-only replay reached a factory, network or cache write")

    monkeypatch.setattr(script, "build_detectors", forbidden)
    monkeypatch.setattr(script, "build_attacker", forbidden)
    monkeypatch.setattr(storage.CacheFile, "flush", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    assert script.main(args + ["--cache-only"]) == 0
    replay = json.loads(output.read_text())
    assert replay["replay_only"] is True and original["replay_only"] is False
    assert replay["detectors"] == original["detectors"]
    markdown = script.to_markdown(replay, "synthetic", ["synthetic/judge"], "synthetic/attacker")
    assert "cache-only replay" in markdown and "not new independent evidence" in markdown
    assert snapshots == [(p.read_bytes(), p.stat().st_mtime_ns) for p in (scores, paraphrases)]
    previous = output.read_bytes()
    with pytest.raises(ValueError, match="context mismatch"):
        script.main(args + ["--experiment-context", "changed"])
    assert output.read_bytes() == previous
    assert "synthetic-not-a-key" not in capsys.readouterr().out


def test_cli_legacy_cache_rejection_precedes_key_check_or_factories(tmp_path, monkeypatch):
    source, cache = tmp_path / "input.jsonl", tmp_path / "cache.json"
    source.write_text('{"text":"synthetic","label":1}\n')
    cache.write_text('{"old-key":0.9}')
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setattr(script, "build_detectors", lambda _: pytest.fail("factory called"))
    with pytest.raises(ValueError, match="legacy"):
        script.main(["--data", str(source), "--cache", str(cache)])
    assert cache.read_text() == '{"old-key":0.9}'


def test_score_and_paraphrase_keys_use_unambiguous_sha256_framing():
    assert storage.score_key("d\ntext", "a") != storage.score_key("d", "text\na")
    assert storage.score_key("d", "a") != storage.paraphrase_key("a")
    expected = hashlib.sha256(b'["score","d","a"]').hexdigest()
    assert storage.score_key("d", "a") == expected
