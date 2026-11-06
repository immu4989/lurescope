"""Strict local replay envelopes; configuration identity is not authentication.

Trusted parent directories and one writer are required. Atomic replacement is
per file, not a multi-file transaction or a cross-process compare-and-swap.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path

from .json_limits import check_json_structure, finite_json_float
from .local_io import read_regular_file
from .scorecard_metrics import validate_score

VERSION = "lurescope-scorecard-cache-v1"
MAX_CACHE_BYTES = 64 * 1024 * 1024
MAX_PARAPHRASE_BYTES = 1024 * 1024
_HEX = re.compile(r"[0-9a-f]{64}")


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def score_key(detector, text):
    return fingerprint(["score", detector, text])


def paraphrase_key(text):
    return fingerprint(["paraphrase", text])


def validate_paraphrase(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("paraphrase must be nonempty UTF-8 text")
    try:
        if len(value.encode("utf-8")) > MAX_PARAPHRASE_BYTES:
            raise ValueError("paraphrase exceeds the byte limit")
    except UnicodeEncodeError:
        raise ValueError("paraphrase must be nonempty UTF-8 text") from None
    return value


def envelope(kind, context, entries=None):
    if kind not in ("scores", "paraphrases"):
        raise ValueError("unknown scorecard cache kind")
    if not isinstance(context, str) or _HEX.fullmatch(context) is None:
        raise ValueError("cache context must be a SHA-256 identity")
    return {"version": VERSION, "kind": kind, "context": context,
            "entries": {} if entries is None else dict(entries)}


def admit(value, kind, context):
    expected = envelope(kind, context)
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError("legacy or invalid scorecard cache; preserve it and choose a new path")
    if any(value[key] != expected[key] for key in ("version", "kind", "context")):
        raise ValueError("scorecard cache context mismatch; preserve it and choose a new path")
    if not isinstance(value["entries"], dict):
        raise ValueError("cache entries must be an object")
    validate = validate_score if kind == "scores" else validate_paraphrase
    result = {}
    for key, entry in value["entries"].items():
        if not isinstance(key, str) or _HEX.fullmatch(key) is None:
            raise ValueError("cache entry key must be a SHA-256 identity")
        result[key] = validate(entry)
    return result


def _no_duplicates(pairs):
    value = {}
    for key, entry in pairs:
        if key in value:
            raise ValueError("duplicate cache key")
        value[key] = entry
    return value


def _no_constant(value):
    raise ValueError("nonstandard cache constant")


def _decode(raw):
    try:
        text = raw.decode("utf-8")
        check_json_structure(text)
        return json.loads(text, object_pairs_hook=_no_duplicates,
                          parse_constant=_no_constant, parse_float=finite_json_float)
    except (ValueError, TypeError, RecursionError):
        raise ValueError("cache is not strict bounded UTF-8 JSON; preserve it") from None


class CacheFile:
    """Load a whole validated envelope before work; publish only on explicit flush.

    Missing paths start empty; malformed/legacy files never silently start over.
    Failed evaluations are not checkpointed. Separate cache files commit separately.
    """

    def __init__(self, path, kind, context):
        self.path = Path(path) if path is not None else None
        self.kind, self.context = kind, context
        self.value = envelope(kind, context)
        raw = self._read()
        self._before = None if raw is None else hashlib.sha256(raw).hexdigest()
        if raw is not None:
            entries = admit(_decode(raw), kind, context)
            self.value = envelope(kind, context, entries)

    def _read(self):
        if self.path is None:
            return None
        if self.path.parent.is_symlink():
            raise ValueError("cache parent must not be a symlink")
        try:
            self.path.lstat()
        except FileNotFoundError:
            return None
        return read_regular_file(self.path, maximum=MAX_CACHE_BYTES, label="scorecard cache")

    def flush(self):
        entries = admit(self.value, self.kind, self.context)
        if self.path is None:
            return
        raw = (json.dumps(envelope(self.kind, self.context, entries),
                          sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n").encode()
        if len(raw) > MAX_CACHE_BYTES:
            raise ValueError("cache output exceeds the byte limit")
        _decode(raw)  # A successful save must be restart-readable under the same bounds.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="wb", dir=self.path.parent,
                                             prefix=".scorecard-cache-", delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            current = self._read()
            observed = None if current is None else hashlib.sha256(current).hexdigest()
            if observed != self._before:
                raise ValueError("cache changed since admission; refusing to overwrite it")
            os.replace(temporary, self.path)
            temporary = None
            self._before = hashlib.sha256(raw).hexdigest()
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)


def distinct_paths(paths):
    """Reject observed aliases among input, caches and output artifacts before work."""
    checked = []
    for value in paths:
        if value is None:
            continue
        path = Path(value)
        for previous in checked:
            if path.resolve() == previous.resolve() or (
                    path.exists() and previous.exists() and path.samefile(previous)):
                raise ValueError("input, cache and output paths must be distinct")
        checked.append(path)
