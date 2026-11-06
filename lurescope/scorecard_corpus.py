"""Bounded, whole-file admission and reproducible research cohort selection.

This is a lightweight scorecard input contract, not the full Lure schema or
authentication of source/labels. Trusted parent directories are required.
"""

from __future__ import annotations

import hashlib
import io
import json
from collections import defaultdict
from pathlib import Path

from .json_limits import check_json_structure, finite_json_float
from .local_io import read_regular_file

CONTRACT = "scorecard-cohort-v1"
MAX_SOURCE_BYTES = 256 * 1024 * 1024
MAX_LINE_BYTES = 32 * 1024 * 1024
MAX_RECORDS = 100_000
MAX_RECORD_NODES = 100_000


def _nonnegative(value, label):
    if type(value) is not int or value < 0:
        raise ValueError(f"{label} must be a nonnegative integer")


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _no_constant(value):
    raise ValueError("nonstandard JSON constant")


def _record(text):
    check_json_structure(text, max_nodes=MAX_RECORD_NODES)
    value = json.loads(text, object_pairs_hook=_no_duplicates,
                       parse_constant=_no_constant, parse_float=finite_json_float)
    if not isinstance(value, dict):
        raise ValueError("expected an object")
    # All strings, including unknown metadata keys/values, must be UTF-8 encodable.
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            item.encode("utf-8")
        elif isinstance(item, dict):
            pending.extend(item)
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    if type(value.get("label")) is not int or value["label"] not in (0, 1):
        raise ValueError("label must be the integer 0 or 1")
    if not isinstance(value.get("text"), str) or not value["text"].strip():
        raise ValueError("text must be nonempty")
    for key in ("id", "typology"):
        if key in value and (not isinstance(value[key], str) or not value[key].strip()):
            raise ValueError("selection fields must be nonempty strings")
    if value.get("typology") == "benign" and value["label"] != 0:
        raise ValueError("benign typology requires label 0")
    if (value.get("typology") in {"phishing", "bec", "romance", "pig_butchering"}
            and value["label"] != 1):
        raise ValueError("fraud typology requires label 1")
    return value


def load_cohort(path, *, limit=0, phishing_cap=None):
    """Return selected record dictionaries and a path/text-free manifest.

    Validate every record before sampling, even after a limit or cap is filled.
    None selects source order; an integer phishing_cap selects the historical
    typology-cap/id-order policy. Zero limit means all, but zero cap means none
    from phishing. Duplicate IDs/texts remain separate positional observations.
    """
    _nonnegative(limit, "limit")
    if phishing_cap is not None:
        _nonnegative(phishing_cap, "phishing_cap")
    payload = read_regular_file(Path(path), maximum=MAX_SOURCE_BYTES,
                                label="scorecard corpus", allow_empty=True)
    entries = []
    record_count = 0
    with io.BytesIO(payload) as stream:
        lineno = 0
        while raw := stream.readline(MAX_LINE_BYTES + 1):
            lineno += 1
            if len(raw) > MAX_LINE_BYTES:
                raise ValueError(f"corpus line {lineno} exceeds the byte limit")
            try:
                text = raw.decode("utf-8").strip(" \t\r\n")
                if not text or text.startswith("//"):
                    continue
                value = _record(text)
            except (ValueError, TypeError, RecursionError):
                # Never echo private texts, keys, IDs or nested decoder diagnostics.
                raise ValueError(f"corpus line {lineno} is not a valid scorecard record") from None
            record_count += 1
            if record_count > MAX_RECORDS:
                raise ValueError("corpus exceeds the record limit")
            if value["label"] == 1:
                entries.append((record_count - 1, raw, value))
    fraud_count = len(entries)
    if phishing_cap is not None:
        by_typology = defaultdict(list)
        for entry in entries:
            by_typology[entry[2].get("typology", "other")].append(entry)
        entries = []
        for typology, group in sorted(by_typology.items()):
            entries.extend(group[:phishing_cap] if typology == "phishing" else group)
        entries.sort(key=lambda entry: entry[2].get("id", ""))
    if limit:
        entries = entries[:limit]
    digest = hashlib.sha256((CONTRACT + "\n").encode("ascii"))
    for ordinal, raw, _ in entries:
        digest.update(ordinal.to_bytes(8, "big"))
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    manifest = {
        "contract": CONTRACT, "source_sha256": hashlib.sha256(payload).hexdigest(),
        "source_bytes": len(payload), "record_count": record_count,
        "fraud_count": fraud_count, "benign_count": record_count - fraud_count,
        "selected_count": len(entries), "selected_sha256": digest.hexdigest(),
        "selection": {"method": ("fraud-source-order-v1" if phishing_cap is None else
                                   "fraud-typology-cap-id-order-v1"),
                      "limit": limit, "phishing_cap": phishing_cap},
    }
    return [entry[2] for entry in entries], manifest


def manifest_markdown(card):
    """Describe only manifests generated by the CLI; a digest is not validation."""
    manifest = card.get("corpus")
    if manifest is None:
        return []
    selection = manifest["selection"]
    return [
        f"Input manifest: `{manifest['contract']}`; {manifest['record_count']} validated "
        f"records ({manifest['fraud_count']} fraud, {manifest['benign_count']} benign), "
        f"{manifest['selected_count']} selected. Selection: `{selection['method']}`; "
        f"limit={selection['limit']}, phishing_cap={selection['phishing_cap']}.",
        f"Source SHA-256: `{manifest['source_sha256']}`. "
        f"Ordered selection SHA-256: `{manifest['selected_sha256']}`.",
        "These commitments identify consumed bytes and selection, not label correctness, "
        "source authenticity, representativeness or privacy protection.",
        "",
    ]
