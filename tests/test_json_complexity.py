"""Bound independent evidence parsing and HTTP admission before allocation."""

import asyncio
import json

import pytest

from lurescope import boundary, permit, watch, witness
from lurescope.http_boundary import RequestBodyLimit


def limited_parse(payload, nodes):
    return permit._strict(payload, "test artifact", max_nodes=nodes)


@pytest.mark.parametrize("payload,nodes", [
    (b'null', 1), (b'true', 1), (b'-1.25e+2', 1), (b'{}', 1), (b'[]', 1),
    (b'{"a":0}', 3), (b'[{"a":[true,null,"x"]},{}]', 8),
    (b'{"a\\u0062":"[,{}]","escaped":"\\\\\\\"","n":1}', 7),
])
def test_exact_node_boundary(payload, nodes):
    expected = json.loads(payload)
    assert limited_parse(payload, nodes) == expected
    if nodes > 1:
        with pytest.raises(ValueError, match="node"):
            limited_parse(payload, nodes - 1)


@pytest.mark.parametrize("limit", [True, False, 0, -1, 1.5, "2", None])
def test_invalid_node_budgets(limit):
    with pytest.raises(ValueError, match="node limit"):
        limited_parse(b'0', limit)


def test_numeric_token_boundary_and_long_strings():
    token = b'0.' + b'0' * 4093 + b'1'
    assert len(token) == 4096
    assert limited_parse(token, 1) == 0.
    with pytest.raises(ValueError, match="token"):
        limited_parse(token + b'1', 1)
    # Strings are byte/field bounded by callers, not numeric token length.
    value = '[{,:"\\\\\\\"' * 10000
    assert limited_parse(json.dumps(value).encode(), 1) == value


def test_seeded_structures_preserve_types_and_exact_node_count():
    import random

    rng = random.Random(4989)

    def make(depth):
        if depth == 0 or rng.random() < .5:
            return rng.choice([None, True, False, -123, 1.25, "", "é", '\\\\"[{,}'])
        if rng.random() < .5:
            return [make(depth - 1) for _ in range(rng.randrange(6))]
        return {str(i) + rng.choice(["", "\\", "é", '"']): make(depth - 1)
                for i in range(rng.randrange(6))}

    def count(value):
        if isinstance(value, dict):
            return 1 + len(value) + sum(count(item) for item in value.values())
        if isinstance(value, list):
            return 1 + sum(count(item) for item in value)
        return 1

    for _ in range(400):
        value = make(5)
        payload = json.dumps(value, ensure_ascii=rng.choice([True, False])).encode()
        nodes = count(value)
        assert limited_parse(payload, nodes) == value
        if nodes > 1:
            with pytest.raises(ValueError, match="node"):
                limited_parse(payload, nodes - 1)


@pytest.mark.parametrize("payload", [
    b'{"a":1,"a":2}', b'{"a":1,"\\u0061":2}', b'[NaN]', b'{"a":1e999}',
    b'{"a":[}', b'0 0', b'{"a":}', b'"unterminated', b'[] garbage', b'\xff',
])
def test_structure_scan_does_not_replace_strict_syntax_validation(payload):
    with pytest.raises(ValueError):
        limited_parse(payload, 100)


@pytest.mark.parametrize("parser", [permit._strict, boundary._strict_json,
                                    watch._strict_json, witness._strict])
@pytest.mark.parametrize("payload,reason", [
    (b'[' + b'{},' * 1000000 + b'{}]', "node"),
    (b'[0.' + b'0' * 5000 + b'1]', "token"),
    (b'[' * 129 + b'0' + b']' * 129, "nesting"),
], ids=["breadth", "numeric-token", "depth"])
def test_evidence_rejected_before_decoder(monkeypatch, parser, payload, reason):
    monkeypatch.setattr(json, "loads", lambda *a, **kw: pytest.fail("decoder entered"))
    with pytest.raises(ValueError, match=reason):
        parser(payload, "test artifact")


@pytest.mark.parametrize("content_type", [None, b'application/json', b'application/lure+json'])
def test_http_rejects_wide_json_without_decoding_or_routing(monkeypatch, content_type):
    payload = b'[' + b'{},' * 100000 + b'{}]'
    sent = []

    async def receive():
        return {"type": "http.request", "body": payload, "more_body": False}

    async def send(message):
        sent.append(message)

    async def downstream(*args):
        pytest.fail("application entered")

    with monkeypatch.context() as patch:
        patch.setattr(json, "loads", lambda *a, **kw: pytest.fail("decoder entered"))
        asyncio.run(RequestBodyLimit(downstream)(
            {"type": "http", "headers": [(b"content-type", content_type)] if content_type else []},
            receive, send,
        ))
    assert sent[0]["status"] == 422
    assert json.loads(sent[1]["body"]) == {"detail": "request validation failed"}


@pytest.mark.parametrize("extra,expected_status", [(0, 200), (1, 422)])
@pytest.mark.parametrize("content_type", [None, b'application/json', b'application/lure+json'])
def test_http_exact_node_boundary_survives_chunking(extra, expected_status, content_type):
    from lurescope.http_boundary import MAX_REQUEST_JSON_NODES

    # One node for the array, one per number. Chunk boundaries are not nodes.
    payload = b'[' + b'0,' * (MAX_REQUEST_JSON_NODES - 2 + extra) + b'0]'
    messages = iter([
        {"type": "http.request", "body": payload[:101], "more_body": True},
        {"type": "http.request", "body": b'', "more_body": True},
        {"type": "http.request", "body": payload[101:]},
    ])
    sent = []

    async def receive():
        return next(messages)

    async def send(message):
        sent.append(message)

    async def downstream(scope, receive, send):
        assert extra == 0
        assert (await receive())["body"] == payload
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b''})

    asyncio.run(RequestBodyLimit(downstream)(
        {"type": "http", "headers": [(b"content-type", content_type)] if content_type else []},
        receive, send,
    ))
    assert sent[0]["status"] == expected_status


@pytest.mark.parametrize("parser", [permit._strict, boundary._strict_json,
                                    watch._strict_json, witness._strict])
@pytest.mark.parametrize("token", [b'1e999', b'-1e999', b'NaN', b'Infinity'])
def test_all_evidence_decoders_reject_nonfinite_values(parser, token):
    with pytest.raises(ValueError):
        parser(b'{"nested":[' + token + b']}', "test artifact")


def test_maximum_portable_feature_table_remains_loadable(tmp_path):
    import hashlib

    from lurescope.portable_tfidf import PROFILE, PortableTfidfDetector

    model = {"profile": PROFILE, "source_sha256": "a" * 64, "intercept": 0.,
             "features": [[f"word{i}", 1., .1] for i in range(50000)]}
    payload = json.dumps(model, separators=(",", ":")).encode()
    target = tmp_path / "model.json"
    target.write_bytes(payload)
    detector = PortableTfidfDetector(target, expected_sha256=hashlib.sha256(payload).hexdigest())
    assert len(detector.top_positive_features(50000)) == 50000
