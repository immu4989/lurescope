"""CLI private-key input must not bypass the common evidence file boundary."""

import ast
import os
from pathlib import Path

import pytest

import lurescope.cli as cli


def test_no_key_is_optional_but_empty_path_is_not_unsigned_fallback():
    assert cli._read_signing_key(None) is None
    with pytest.raises(ValueError):
        cli._read_signing_key("")


def test_private_regular_key_read_and_oversize_rejection(tmp_path):
    path = tmp_path / "synthetic-key.pem"
    path.write_bytes(b"synthetic test bytes, not a real credential")
    path.chmod(0o600)
    assert cli._read_signing_key(str(path)) == path.read_bytes()
    with path.open("wb") as stream:
        stream.truncate(64 * 1024 + 1)
    with pytest.raises(ValueError, match="bounded size"):
        cli._read_signing_key(str(path))


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission checks")
@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644, 0o660])
def test_exposed_private_keys_rejected_before_content_read(tmp_path, monkeypatch, mode):
    path = tmp_path / "synthetic-key.pem"
    path.write_bytes(b"synthetic")
    path.chmod(mode)
    monkeypatch.setattr(os, "fdopen", lambda *a: pytest.fail("key read before permission check"))
    with pytest.raises(ValueError, match="group or world"):
        cli._read_signing_key(str(path))


def test_symlink_key_rejected(tmp_path):
    path = tmp_path / "synthetic-key.pem"
    path.write_bytes(b"synthetic")
    path.chmod(0o600)
    link = tmp_path / "key-link.pem"
    link.symlink_to(path)
    with pytest.raises(ValueError, match="non-symlink"):
        cli._read_signing_key(str(link))


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO")
def test_fifo_key_rejected_without_waiting(tmp_path):
    path = tmp_path / "key.fifo"
    os.mkfifo(path)
    with pytest.raises(ValueError, match="regular"):
        cli._read_signing_key(str(path))


def test_cli_has_no_direct_private_key_read_bytes_calls():
    tree = ast.parse(Path(cli.__file__).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "read_bytes":
                assert not any(isinstance(child, ast.Attribute)
                               and child.attr in {"signing_key", "registry_signing_key"}
                               for child in ast.walk(node))


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission checks")
def test_proof_cli_rejects_exposed_key_without_creating_output(tmp_path, capsys):
    source = tmp_path / "synthetic.eml"
    source.write_bytes(b"Subject: Synthetic test\n\nTest message.")
    key = tmp_path / "synthetic.pem"
    key.write_bytes(b"synthetic")
    key.chmod(0o644)
    output = tmp_path / "proof.json"
    assert cli.main(["proof", str(source), "--out", str(output), "--signing-key", str(key)]) == 2
    assert "group or world" in capsys.readouterr().err
    assert not output.exists()
