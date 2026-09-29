"""Preflight-to-read consistency without constructing a detector."""

import io
import os
from types import SimpleNamespace

import pytest

from lurescope import local_io
from lurescope.cli import _input_messages


@pytest.mark.parametrize("option", ["max_messages", "max_total_bytes"])
@pytest.mark.parametrize("value", [True, 1.0, "1", 0, -1])
def test_limits_require_positive_integers(tmp_path, option, value):
    with pytest.raises(ValueError):
        _input_messages([str(tmp_path / "missing")], False, **{option: value})


@pytest.mark.parametrize("mutation", ["grow", "shrink", "replace"])
def test_changes_since_batch_preflight_are_rejected(tmp_path, monkeypatch, mutation):
    source = tmp_path / "input.eml"
    source.write_bytes(b"initial")
    original = local_io.read_regular_prefix

    def change(path, **kwargs):
        if mutation == "grow":
            source.write_bytes(b"initial with new content")
        elif mutation == "shrink":
            source.write_bytes(b"i")
        else:
            alternate = tmp_path / "alternate"
            alternate.write_bytes(b"initial")
            alternate.replace(source)
        return original(path, **kwargs)

    monkeypatch.setattr(local_io, "read_regular_prefix", change)
    with pytest.raises(ValueError, match="preflight"):
        _input_messages([str(source)], False)


@pytest.mark.parametrize("directory", [False, True])
def test_symlink_messages_never_follow_targets(tmp_path, directory):
    real = tmp_path / "real"
    real.write_bytes(b"private")
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    link = inbox / "message.eml"
    link.symlink_to(real)
    with pytest.raises(ValueError, match="link"):
        _input_messages([str(inbox if directory else link)], False)


def test_oversized_prefix_is_preserved_for_per_message_failure(tmp_path, monkeypatch):
    from lurescope import triage

    monkeypatch.setattr(triage, "MAX_EMAIL_BYTES", 4)
    source = tmp_path / "large.eml"
    source.write_bytes(b"123456789")
    assert _input_messages([str(source)], False, max_total_bytes=5) == [(str(source), b"12345")]
    with pytest.raises(ValueError, match="batch limit"):
        _input_messages([str(source)], False, max_total_bytes=4)


def test_empty_and_stdin_are_bounded_without_coercion(tmp_path, monkeypatch):
    from lurescope import cli, triage

    monkeypatch.setattr(triage, "MAX_EMAIL_BYTES", 4)
    monkeypatch.setattr(cli.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b"123456789")))
    source = tmp_path / "empty.eml"
    source.write_bytes(b"")
    assert _input_messages([str(source), "-"], False, max_total_bytes=5) == [
        (str(source), b""), ("stdin", b"12345"),
    ]


def test_prefix_checks_mutation_during_read_and_limits_allocation(tmp_path, monkeypatch):
    source = tmp_path / "large.eml"
    source.write_bytes(b"123456789")
    snapshot = source.lstat()
    fdopen = os.fdopen
    amounts = []

    class Stream:
        def __init__(self, fd, mode):
            self.stream = fdopen(fd, mode)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def fileno(self):
            return self.stream.fileno()

        def read(self, amount):
            amounts.append(amount)
            payload = self.stream.read(amount)
            source.write_bytes(b"changed beyond prefix")
            return payload

    monkeypatch.setattr(local_io.os, "fdopen", Stream)
    with pytest.raises(ValueError, match="changed"):
        local_io.read_regular_prefix(source, maximum=5, expected=snapshot)
    assert amounts == [5]


def test_replacement_with_fifo_is_rejected_before_open(tmp_path, monkeypatch):
    if not hasattr(os, "mkfifo"):
        pytest.skip("POSIX FIFO")
    source = tmp_path / "message.eml"
    source.write_bytes(b"initial")
    original = local_io.read_regular_prefix

    def change(path, **kwargs):
        source.unlink()
        os.mkfifo(source)
        return original(path, **kwargs)

    monkeypatch.setattr(local_io, "read_regular_prefix", change)
    with pytest.raises(ValueError, match="regular"):
        _input_messages([str(source)], False)
