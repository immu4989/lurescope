"""Verify checkpoint byte equality against an externally pinned preflight report.

No producer imports, model loads, network calls, or independent claims about
tensor semantics. Trust in the pinned report's structural inspection is external.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import stat
from pathlib import Path
from typing import Any

from .mandate import _read
from .permit import _strict

REPORT_SCHEMA = "https://github.com/immu4989/lurebench/spec/checkpoint-preflight/v1"
SCHEMA = "https://github.com/immu4989/lurescope/spec/checkpoint-byte-verification/v1"
INDEX = "model.safetensors.index.json"
REPORT_LIMITATIONS = [
    "bounded_sharded_safetensors_profile_not_all_valid_safetensors_encodings",
    "tensor_bytes_hashed_not_interpreted_or_checked_for_model_behavior",
    "config_tokenizer_code_provenance_and_unreferenced_files_not_inspected",
    "inspection_does_not_authenticate_a_publisher_or_patch_model_loading_libraries",
    "mutable_directories_and_later_loaders_require_separate_integrity_controls",
    "passing_is_not_model_safety_compliance_or_deployment_authorization",
]
LIMITATIONS = [
    "report_digest_trust_must_be_established_outside_the_checkpoint_delivery_channel",
    "byte_equality_to_pinned_report_not_independent_tensor_structure_validation",
    "producer_inspection_quality_and_publisher_identity_are_external_trust_assumptions",
    "mutable_directories_and_later_loaders_require_separate_integrity_controls",
    "unreferenced_files_config_tokenizer_and_custom_code_are_not_inspected",
    "passing_is_not_model_safety_compliance_or_deployment_authorization",
]


def _fields(value: Any, names: str) -> dict:
    if not isinstance(value, dict) or set(value) != set(names.split()):
        raise ValueError("checkpoint report has unexpected fields")
    return value


def _integer(value: Any, lower: int, upper: int) -> int:
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError("checkpoint report count is outside its integer bounds")
    return value


def _digest(value: Any) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("checkpoint digest must be 64 lowercase hexadecimal characters")
    return value


def validate_report(report: Any) -> dict:
    """Validate the producer contract and arithmetic, not its structural claims."""
    report = _fields(
        report, "schema schema_version profile index shards summary limits limitations"
    )
    if (
        report["schema"] != REPORT_SCHEMA
        or type(report["schema_version"]) is not int or report["schema_version"] != 1
        or report["profile"] != "sharded-safetensors-byte-aligned-v1"
        or report["limitations"] != REPORT_LIMITATIONS
    ):
        raise ValueError("unsupported checkpoint report profile")
    index = _fields(report["index"], "name file_sha256")
    if index["name"] != INDEX:
        raise ValueError("unexpected checkpoint index name")
    _digest(index["file_sha256"])
    limits = _fields(report["limits"],
                     "maximum_total_shard_bytes maximum_header_bytes maximum_shards")
    maximum = _integer(limits["maximum_total_shard_bytes"], 1, 1024**4)
    if (
        _integer(limits["maximum_header_bytes"], 1, 8 * 1024**2) != 8 * 1024**2
        or _integer(limits["maximum_shards"], 1, 1024) != 1024
    ):
        raise ValueError("unsupported checkpoint profile limits")
    shards = report["shards"]
    if not isinstance(shards, list) or not 1 <= len(shards) <= 1024:
        raise ValueError("checkpoint report must contain bounded shards")
    names = []
    total_bytes = tensor_bytes = tensor_count = 0
    for shard in shards:
        _fields(shard,
                "name file_bytes file_sha256 header_bytes header_sha256 tensor_count tensor_bytes")
        name = shard["name"]
        if (
            not isinstance(name, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,180}\.safetensors", name) is None
            or ".." in name
            or name.split(".")[0].upper() in {
                "CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                *(f"LPT{i}" for i in range(1, 10)),
            }
        ):
            raise ValueError("checkpoint shard name is not a portable basename")
        names.append(name)
        _digest(shard["file_sha256"])
        _digest(shard["header_sha256"])
        size = _integer(shard["file_bytes"], 10, maximum)
        header = _integer(shard["header_bytes"], 2, 8 * 1024**2)
        data = _integer(shard["tensor_bytes"], 0, maximum)
        tensor_count += _integer(shard["tensor_count"], 1, 100_000)
        if size != 8 + header + data:
            raise ValueError("checkpoint report byte accounting is inconsistent")
        total_bytes += size
        tensor_bytes += data
    if names != sorted(names) or len({n.casefold() for n in names}) != len(names):
        raise ValueError("checkpoint shard names must be sorted and unambiguous")
    if total_bytes > maximum or tensor_count > 100_000:
        raise ValueError("checkpoint report exceeds aggregate bounds")
    summary = _fields(report["summary"], "status shard_count tensor_count file_bytes tensor_bytes")
    expected = {"status": "pass", "shard_count": len(shards), "tensor_count": tensor_count,
                "file_bytes": total_bytes, "tensor_bytes": tensor_bytes}
    for name in ("shard_count", "tensor_count", "file_bytes", "tensor_bytes"):
        _integer(summary[name], 0, 1024**4)
    if summary != expected:
        raise ValueError("checkpoint report summary disagrees with shard records")
    return report


def _identity(info: os.stat_result) -> tuple:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _hash_file(root: int, name: str, maximum: int, expected: dict | None) -> tuple[str, tuple]:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 1 <= info.st_size <= maximum:
            raise ValueError("checkpoint source must be a bounded regular file")
        if expected is not None and info.st_size != expected["file_bytes"]:
            raise ValueError("checkpoint shard size does not match pinned report")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            digest = hashlib.sha256()
            consumed = 0
            if expected is not None:
                prefix = stream.read(8)
                if len(prefix) != 8 or int.from_bytes(prefix, "little") != expected["header_bytes"]:
                    raise ValueError("checkpoint header length does not match pinned report")
                header = stream.read(expected["header_bytes"])
                if (
                    len(header) != expected["header_bytes"]
                    or hashlib.sha256(header).hexdigest() != expected["header_sha256"]
                ):
                    raise ValueError("checkpoint header bytes do not match pinned report")
                digest.update(prefix)
                digest.update(header)
                consumed = 8 + len(header)
            while consumed < info.st_size:
                chunk = stream.read(min(1024**2, info.st_size - consumed))
                if not chunk:
                    raise ValueError("checkpoint file was truncated")
                digest.update(chunk)
                consumed += len(chunk)
            if stream.read(1) or _identity(os.fstat(stream.fileno())) != _identity(info):
                raise ValueError("checkpoint file changed during verification")
        if _identity(os.stat(name, dir_fd=root, follow_symlinks=False)) != _identity(info):
            raise ValueError("checkpoint file path changed during verification")
        return digest.hexdigest(), _identity(info)
    finally:
        if fd >= 0:
            os.close(fd)


def verify_checkpoint(
    directory: Path, report_path: Path, *, expected_report_sha256: str,
    max_total_bytes: int = 32 * 1024**3,
) -> dict:
    """Compare files with a report whose exact bytes were approved externally."""
    pinned = _digest(expected_report_sha256)
    _integer(max_total_bytes, 1, 1024**4)
    payload = _read(Path(report_path), "checkpoint report", 4 * 1024**2)
    if not hmac.compare_digest(hashlib.sha256(payload).hexdigest(), pinned):
        raise ValueError("checkpoint report does not match externally pinned digest")
    report = validate_report(_strict(payload, "checkpoint report"))
    if report["summary"]["file_bytes"] > max_total_bytes:
        raise ValueError("checkpoint exceeds verifier byte budget")
    if os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("checkpoint verification requires POSIX no-follow directory opens")
    root = os.open(Path(directory), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        actual, identity = _hash_file(root, INDEX, 4 * 1024**2, None)
        if actual != report["index"]["file_sha256"]:
            raise ValueError("checkpoint index bytes do not match pinned report")
        identities = {INDEX: identity}
        for shard in report["shards"]:
            actual, identity = _hash_file(root, shard["name"], shard["file_bytes"], shard)
            if actual != shard["file_sha256"]:
                raise ValueError("checkpoint shard bytes do not match pinned report")
            identities[shard["name"]] = identity
        for name, identity in identities.items():
            if _identity(os.stat(name, dir_fd=root, follow_symlinks=False)) != identity:
                raise ValueError("checkpoint changed before verification completed")
    finally:
        os.close(root)
    return {
        "schema": SCHEMA, "schema_version": 1, "report_sha256": pinned,
        "summary": {**report["summary"], "status": "byte_match"},
        "limitations": list(LIMITATIONS),
    }
