import copy
import hashlib
import json
import os

import pytest

from lurescope import checkpoint
from lurescope.cli import main

pytestmark = pytest.mark.skipif(
    os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"),
    reason="checkpoint profile requires POSIX no-follow directory opens",
)


def fixture(root):
    directory = root / "checkpoint"
    directory.mkdir()
    header = b'{"x":{"dtype":"U8","shape":[4],"data_offsets":[0,4]}}'
    payload = len(header).to_bytes(8, "little") + header + b"1234"
    name = "model-1.safetensors"
    index = json.dumps({"metadata": {"total_size": 4}, "weight_map": {"x": name}}).encode()
    (directory / name).write_bytes(payload)
    (directory / checkpoint.INDEX).write_bytes(index)
    report = {
        "schema": checkpoint.REPORT_SCHEMA, "schema_version": 1,
        "profile": "sharded-safetensors-byte-aligned-v1",
        "index": {"name": checkpoint.INDEX, "file_sha256": hashlib.sha256(index).hexdigest()},
        "shards": [{"name": name, "file_bytes": len(payload),
                    "file_sha256": hashlib.sha256(payload).hexdigest(),
                    "header_bytes": len(header),
                    "header_sha256": hashlib.sha256(header).hexdigest(),
                    "tensor_count": 1, "tensor_bytes": 4}],
        "summary": {"status": "pass", "shard_count": 1, "tensor_count": 1,
                    "file_bytes": len(payload), "tensor_bytes": 4},
        "limits": {"maximum_total_shard_bytes": 32 * 1024**3,
                   "maximum_header_bytes": 8 * 1024**2, "maximum_shards": 1024},
        "limitations": list(checkpoint.REPORT_LIMITATIONS),
    }
    report_path = root / "report.json"
    report_path.write_text(json.dumps(report))
    digest = hashlib.sha256(report_path.read_bytes()).hexdigest()
    return directory, report_path, digest, report


def test_valid_pinned_evidence(tmp_path):
    directory, path, digest, report = fixture(tmp_path)
    result = checkpoint.verify_checkpoint(directory, path, expected_report_sha256=digest)
    assert result["summary"] == {**report["summary"], "status": "byte_match"}
    assert result["report_sha256"] == digest
    assert "not_independent_tensor_structure" in " ".join(result["limitations"])


def test_report_pin_checked_before_parse_or_checkpoint_access(tmp_path, monkeypatch):
    directory, path, digest, _ = fixture(tmp_path)
    path.write_text("malformed")

    def forbidden(*args):
        raise AssertionError("must not parse unpinned report")

    monkeypatch.setattr(checkpoint, "validate_report", forbidden)
    with pytest.raises(ValueError, match="pinned digest"):
        checkpoint.verify_checkpoint(directory, path, expected_report_sha256=digest)


@pytest.mark.parametrize("target", ["shard", "index", "header"])
def test_changed_checkpoint_rejected(tmp_path, target):
    directory, path, digest, _ = fixture(tmp_path)
    source = directory / (checkpoint.INDEX if target == "index" else "model-1.safetensors")
    data = bytearray(source.read_bytes())
    data[9 if target == "header" else -1] ^= 1
    source.write_bytes(data)
    with pytest.raises(ValueError, match="match"):
        checkpoint.verify_checkpoint(directory, path, expected_report_sha256=digest)


@pytest.mark.parametrize("field", ["schema_version", "shard_count", "tensor_count",
                                  "file_bytes", "tensor_bytes"])
@pytest.mark.parametrize("replacement", [True, 1.0])
def test_integer_fields_reject_bool_and_float(tmp_path, field, replacement):
    _, _, _, report = fixture(tmp_path)
    container = report if field == "schema_version" else report["summary"]
    container[field] = replacement
    with pytest.raises(ValueError):
        checkpoint.validate_report(report)


@pytest.mark.parametrize("name", ["../x.safetensors", "/tmp/x.safetensors", "CON.safetensors",
                                 "x\\y.safetensors", "a..safetensors", "méta.safetensors"])
def test_pinned_unsafe_names_still_rejected(tmp_path, name):
    _, _, _, report = fixture(tmp_path)
    report["shards"][0]["name"] = name
    with pytest.raises(ValueError, match="basename"):
        checkpoint.validate_report(report)


@pytest.mark.parametrize("mutation", ["summary", "size", "duplicate", "limits", "digest",
                                     "limitations", "unknown"])
def test_report_contract_is_not_just_a_digest_check(tmp_path, mutation):
    _, _, _, report = fixture(tmp_path)
    if mutation == "summary":
        report["summary"]["tensor_count"] += 1
    elif mutation == "size":
        report["shards"][0]["tensor_bytes"] += 1
    elif mutation == "duplicate":
        report["shards"].append(copy.deepcopy(report["shards"][0]))
    elif mutation == "limits":
        report["limits"]["maximum_header_bytes"] = 100_000_000
    elif mutation == "digest":
        report["shards"][0]["file_sha256"] = "x" * 64
    elif mutation == "limitations":
        report["limitations"] = []
    else:
        report["trusted"] = True
    with pytest.raises(ValueError):
        checkpoint.validate_report(report)


@pytest.mark.parametrize("kind", ["fifo", "symlink", "directory"])
def test_nonregular_source_rejected(tmp_path, kind):
    directory, path, digest, _ = fixture(tmp_path)
    shard = directory / "model-1.safetensors"
    shard.unlink()
    if kind == "fifo":
        os.mkfifo(shard)
    elif kind == "symlink":
        shard.symlink_to(path)
    else:
        shard.mkdir()
    with pytest.raises((OSError, ValueError)):
        checkpoint.verify_checkpoint(directory, path, expected_report_sha256=digest)


def test_caller_byte_budget_is_independent_of_report_limit(tmp_path):
    directory, path, digest, report = fixture(tmp_path)
    with pytest.raises(ValueError, match="budget"):
        checkpoint.verify_checkpoint(directory, path, expected_report_sha256=digest,
                                     max_total_bytes=report["summary"]["file_bytes"] - 1)


def test_change_after_hashing_rejected(tmp_path, monkeypatch):
    directory, path, digest, _ = fixture(tmp_path)
    original = checkpoint._hash_file

    def replace(root, name, maximum, expected):
        result = original(root, name, maximum, expected)
        if name.endswith(".safetensors"):
            (directory / name).write_bytes(b"changed")
        return result

    monkeypatch.setattr(checkpoint, "_hash_file", replace)
    with pytest.raises(ValueError, match="changed"):
        checkpoint.verify_checkpoint(directory, path, expected_report_sha256=digest)


def test_cli_private_output_and_no_overwrite(tmp_path, capsys):
    directory, path, digest, _ = fixture(tmp_path)
    output = tmp_path / "verified.json"
    args = ["checkpoint-verify", str(directory), "--report", str(path),
            "--expected-report-sha256", digest, "--out", str(output), "--json"]
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["status"] == "byte_match"
    assert output.stat().st_mode & 0o777 == 0o600
    before = output.read_bytes()
    assert main(args) == 2
    assert output.read_bytes() == before
    assert str(directory) not in capsys.readouterr().err
