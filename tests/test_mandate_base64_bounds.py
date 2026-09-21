import base64
import importlib

import pytest


@pytest.fixture(params=["mandate", "mandate_auth", "mandate_otel_auth", "mandate_conformance_auth"])
def decoder(request, monkeypatch):
    module = importlib.import_module(f"lurescope.{request.param}")
    if request.param == "mandate":
        monkeypatch.setattr(module, "MAX_INPUT_BYTES", 4)
        return lambda value: module._decode(value, "test")
    return lambda value: module._decode(value, "test", 4)


def test_encoded_bound_is_checked_before_allocation(decoder, monkeypatch):
    def unexpected_decode(*args, **kwargs):
        pytest.fail("oversized encoded value must not reach the decoder")

    monkeypatch.setattr(base64, "b64decode", unexpected_decode)
    with pytest.raises(ValueError, match="encoded size bound"):
        decoder("A" * 12)


def test_exact_decoded_bound_is_accepted(decoder):
    assert decoder(base64.b64encode(b"abcd").decode("ascii")) == b"abcd"


def test_padding_bucket_does_not_allow_extra_decoded_bytes(decoder):
    # Four and five bytes both occupy eight base64 characters.
    with pytest.raises(ValueError, match="bounded"):
        decoder(base64.b64encode(b"abcde").decode("ascii"))


@pytest.mark.parametrize("value", ["YWJjZA==\n", "YWJjZA", "YWJjZB==", "!!!!", "éééé"])
def test_noncanonical_base64_is_rejected(decoder, value):
    with pytest.raises(ValueError):
        decoder(value)
