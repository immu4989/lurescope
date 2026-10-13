"""Detector reuse must not multiply local weights or retain provider credentials."""

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from lurescope import service
from lurescope.app import app


@pytest.fixture(autouse=True)
def isolated_cache(monkeypatch):
    service._detector.cache_clear()
    for name in ("LURESCOPE_PUBLIC_MODE", "LURESCOPE_API_KEY_SCRYPT",
                 "LURESCOPE_ALLOWED_DETECTORS", "LURESCOPE_ALLOWED_ATTACKS",
                 "LURESCOPE_PROVIDER_DAILY_LIMIT", "LURESCOPE_POLICY_PATH",
                 "LURESCOPE_LLM_ENGINE"):
        monkeypatch.delenv(name, raising=False)
    yield
    service._detector.cache_clear()


@pytest.mark.parametrize("name", ["tfidf-logreg", "heuristic-v0", "llama-guard-3"])
def test_ignored_options_do_not_multiply_local_instances(monkeypatch, name):
    created = []

    def construct(*args, **kwargs):
        detector = SimpleNamespace(score=lambda r: .25)
        created.append(detector)
        return detector

    monkeypatch.setattr(service, "PortableTfidfDetector", construct)
    monkeypatch.setattr(service, "get_detector", construct)
    first = service._detector(name)
    for index in range(100):
        assert service._detector(name, f"engine-{index}", f"model-{index}") is first
    assert len(created) == 1


def test_default_engine_is_resolved_for_each_provider_request(monkeypatch):
    monkeypatch.setattr(service, "get_detector", lambda name, **kw: SimpleNamespace(**kw))
    monkeypatch.setenv("LURESCOPE_LLM_ENGINE", "mistral")
    assert service._detector("llm-judge").engine == "mistral"
    monkeypatch.setenv("LURESCOPE_LLM_ENGINE", "deepseek")
    assert service._detector("llm-judge").engine == "deepseek"
    assert service._detector("llm-judge", "explicit").engine == "explicit"
    monkeypatch.delenv("LURESCOPE_LLM_ENGINE")
    with pytest.raises(service.DetectorUnavailable):
        service._detector("llm-judge")


@pytest.mark.parametrize("name,env", [("llm-judge", "MISTRAL_API_KEY"),
                                      ("openai-moderation", "OPENAI_API_KEY")])
def test_provider_clients_are_not_retained_between_requests(monkeypatch, name, env):
    created = []

    def construct(*args, **kwargs):
        detector = SimpleNamespace(credential=os.environ.get(env))
        created.append(detector)
        if detector.credential is None:
            raise RuntimeError("synthetic missing credential")
        return detector

    monkeypatch.setattr(service, "get_detector", construct)
    monkeypatch.setenv(env, "synthetic-first")
    first = service._detector(name, "mistral")
    assert service._detector(name, "mistral") is not first
    monkeypatch.setenv(env, "synthetic-rotated")
    assert service._detector(name, "mistral").credential == "synthetic-rotated"
    monkeypatch.delenv(env)
    with pytest.raises(service.DetectorUnavailable):
        service._detector(name, "mistral")
    assert len(created) == 4


def test_real_judge_constructor_observes_rotation_and_preset_change(monkeypatch):
    from lurebench.generate import PROVIDERS

    monkeypatch.setenv("MISTRAL_API_KEY", "synthetic-first")
    first = service._detector("llm-judge", "mistral")
    generator = first._complete.__self__
    assert generator._api_key == "synthetic-first"
    monkeypatch.setenv("MISTRAL_API_KEY", "synthetic-rotated")
    monkeypatch.setitem(PROVIDERS, "mistral", {
        "base_url": "https://provider.example.test/v1",
        "api_key_env": "MISTRAL_API_KEY", "default_model": "synthetic-new-model",
    })
    second = service._detector("llm-judge", "mistral")._complete.__self__
    assert second._api_key == "synthetic-rotated"
    assert second.endpoint == "https://provider.example.test/v1/chat/completions"
    assert second.model == "synthetic-new-model"
    assert second is not generator
    monkeypatch.delenv("MISTRAL_API_KEY")
    with pytest.raises(service.DetectorUnavailable):
        service._detector("llm-judge", "mistral")


def test_api_option_variation_reuses_local_model(monkeypatch):
    created = []

    def construct(*args, **kwargs):
        created.append(True)
        return SimpleNamespace(score=lambda r: .25)

    monkeypatch.setattr(service, "PortableTfidfDetector", construct)
    client = TestClient(app)
    for index in range(12):
        response = client.post("/score", json={"text": "Synthetic notes",
                               "engine": f"unused-{index}", "model": f"unused-{index}"})
        assert response.status_code == 200
        assert response.json()["fraud_probability"] == .25
    assert len(created) == 1


def test_public_policy_and_later_request_use_new_default_engine(monkeypatch):
    from dataclasses import replace

    from lurebench.generate import PROVIDERS

    from lurescope import security

    scored = []

    def construct(name, **kwargs):
        def score(lure):
            scored.append(kwargs["engine"])
            return .25

        return SimpleNamespace(score=score)

    monkeypatch.setattr(service, "get_detector", construct)
    monkeypatch.setenv("LURESCOPE_LLM_ENGINE", "mistral")
    service.score("Synthetic notes", "llm-judge")
    settings = replace(security.SecuritySettings.from_env(), public_mode=True,
                       allowed_detectors=frozenset({"llm-judge"}),
                       allowed_engines=frozenset({"deepseek"}),
                       allowed_models=frozenset({PROVIDERS["deepseek"]["default_model"]}))
    monkeypatch.setattr(security, "_settings_or_503", lambda: settings)
    # Isolate policy/dispatch from authentication, covered by the auth suite.
    monkeypatch.setitem(app.dependency_overrides, security.require_api_access, lambda: "test")
    monkeypatch.setenv("LURESCOPE_LLM_ENGINE", "deepseek")
    client = TestClient(app)
    request = {"text": "Synthetic notes", "detector": "llm-judge"}
    response = client.post("/score", json=request)
    assert response.status_code == 200
    assert scored == ["mistral", "deepseek"]
    denied = client.post("/score", json={**request, "engine": "mistral"})
    assert denied.status_code == 403
    assert scored == ["mistral", "deepseek"]


@pytest.mark.parametrize("options", [(), ("ignored", "ignored")])
def test_parallel_cold_local_requests_construct_once(monkeypatch, options):
    started = threading.Event()
    second_entered = threading.Event()
    release = threading.Event()
    created = []

    def construct(*args, **kwargs):
        created.append(True)
        started.set()
        assert release.wait(5)
        return object()

    class ObservedLock:
        def __init__(self):
            self.lock = threading.Lock()

        def __enter__(self):
            if started.is_set():
                second_entered.set()
            self.lock.acquire()

        def __exit__(self, *args):
            self.lock.release()

    monkeypatch.setattr(service, "get_detector", construct)
    monkeypatch.setitem(service._LOCAL_DETECTOR_LOCKS, "heuristic-v0", ObservedLock())
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(service._detector, "heuristic-v0")
        try:
            assert started.wait(5)
            second = pool.submit(service._detector, "heuristic-v0", *options)
            assert second_entered.wait(5)
        finally:
            release.set()
        assert first.result(timeout=5) is second.result(timeout=5)
    assert len(created) == 1


def test_optional_model_initialization_does_not_lock_default_model(monkeypatch):
    started = threading.Event()
    release = threading.Event()
    default = object()

    def slow_optional(*args, **kwargs):
        started.set()
        assert release.wait(5)
        return object()

    monkeypatch.setattr(service, "get_detector", slow_optional)
    monkeypatch.setattr(service, "PortableTfidfDetector", lambda *a, **kw: default)
    with ThreadPoolExecutor(max_workers=2) as pool:
        optional = pool.submit(service._detector, "llama-guard-3")
        try:
            assert started.wait(5)
            request = pool.submit(service._detector, "tfidf-logreg")
            assert request.result(timeout=2) is default
        finally:
            release.set()
        optional.result(timeout=5)


def test_cache_cardinality_is_fixed_across_all_request_controls(monkeypatch):
    monkeypatch.setattr(service, "get_detector", lambda *a, **kw: object())
    monkeypatch.setattr(service, "PortableTfidfDetector", lambda *a, **kw: object())
    for index in range(100):
        for name in ("tfidf-logreg", "heuristic-v0", "llama-guard-3",
                     "llm-judge", "openai-moderation"):
            service._detector(name, f"engine-{index}", f"model-{index}")
    assert set(service._LOCAL_DETECTORS) == {"tfidf-logreg", "heuristic-v0", "llama-guard-3"}


def test_attack_reuses_one_provider_detector_within_operation(monkeypatch):
    created, scored = [], []

    def construct(*args, **kwargs):
        created.append(True)

        def score(lure):
            scored.append(lure.text)
            return .75

        return SimpleNamespace(score=score)

    monkeypatch.setattr(service, "get_detector", construct)
    result = service.attack("Synthetic text", "homoglyph", "llm-judge",
                            engine="synthetic", defense="normalize")
    assert len(created) == 1
    assert len(scored) == 3
    assert result.clean_probability == result.attacked_probability == .75
    assert result.defended_probability == .75


def test_provider_instance_has_no_retained_service_reference(monkeypatch):
    import gc
    import weakref

    class Detector:
        pass

    monkeypatch.setattr(service, "get_detector", lambda *a, **kw: Detector())
    detector = service._detector("llm-judge", "synthetic")
    reference = weakref.ref(detector)
    del detector
    gc.collect()
    assert reference() is None


def test_clear_waits_for_construction_without_stale_publication(monkeypatch):
    started = threading.Event()
    clearing = threading.Event()
    release = threading.Event()

    class ObservedLock:
        def __init__(self):
            self.lock = threading.Lock()

        def __enter__(self):
            if started.is_set():
                clearing.set()
            self.lock.acquire()

        def __exit__(self, *args):
            self.lock.release()

    def construct(*args, **kwargs):
        started.set()
        assert release.wait(5)
        return object()

    monkeypatch.setattr(service, "get_detector", construct)
    monkeypatch.setitem(service._LOCAL_DETECTOR_LOCKS, "heuristic-v0", ObservedLock())
    with ThreadPoolExecutor(max_workers=2) as pool:
        pending = pool.submit(service._detector, "heuristic-v0")
        try:
            assert started.wait(5)
            cleared = pool.submit(service._detector.cache_clear)
            assert clearing.wait(5)
            assert not cleared.done()
        finally:
            release.set()
        pending.result(timeout=5)
        cleared.result(timeout=5)
    assert service._LOCAL_DETECTORS == {}


def test_failed_construction_does_not_poison_retry(monkeypatch):
    calls = []

    def construct(*args, **kwargs):
        calls.append(True)
        if len(calls) == 1:
            raise RuntimeError("synthetic private diagnostic")
        return object()

    monkeypatch.setattr(service, "get_detector", construct)
    with pytest.raises(service.DetectorUnavailable) as error:
        service._detector("llama-guard-3")
    assert "private diagnostic" not in str(error.value)
    detector = service._detector("llama-guard-3")
    assert service._detector("llama-guard-3") is detector
    assert len(calls) == 2


@pytest.mark.parametrize("name", ["unknown", "llm-judge-provenance", "binoculars"])
def test_unserved_names_never_construct_or_enter_cache(monkeypatch, name):
    created = []
    monkeypatch.setattr(service, "get_detector", lambda *a, **kw: created.append(True))
    with pytest.raises((KeyError, service.DetectorUnavailable)):
        service._detector(name)
    assert created == []


def test_clear_releases_cached_references(monkeypatch):
    monkeypatch.setattr(service, "get_detector", lambda *a, **kw: object())
    first = service._detector("heuristic-v0")
    service._detector.cache_clear()
    assert service._detector("heuristic-v0") is not first
