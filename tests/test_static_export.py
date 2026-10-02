"""Browser export derives from data-only weights, never deserialized estimators."""

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "static_export", ROOT / "scripts/export_static_model.py"
)
exporter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(exporter)


def test_both_artifacts_match_pinned_portable_source_without_writes():
    before = {path: path.read_bytes() for path in exporter.OUTPUTS}
    assert exporter.main(["--check"]) == 0
    assert {path: path.read_bytes() for path in exporter.OUTPUTS} == before


def test_changed_source_pin_is_rejected():
    with pytest.raises(ValueError, match="digest mismatch"):
        exporter.render(expected_sha256="0" * 64)


def test_atomic_public_weights_preserve_old_output_on_failure(tmp_path, monkeypatch):
    target = tmp_path / "model.json"
    target.write_bytes(b"old")

    def fail(*args):
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(exporter.os, "replace", fail)
    with pytest.raises(OSError):
        exporter.write_atomic(target, b"new")
    assert target.read_bytes() == b"old"
    assert list(tmp_path.iterdir()) == [target]


def test_export_refuses_output_symlinks_and_keeps_weights_publicly_readable(tmp_path):
    target = tmp_path / "model.json"
    exporter.write_atomic(target, b"public weights")
    if os.name == "posix":
        assert target.stat().st_mode & 0o777 == 0o644
    alias = tmp_path / "alias.json"
    alias.symlink_to(target)
    with pytest.raises(ValueError, match="non-symlink"):
        exporter.write_atomic(alias, b"replacement")
    assert target.read_bytes() == b"public weights"


def test_export_check_runs_with_executable_model_frameworks_blocked():
    code = '''
import runpy, sys
class Block:
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'pickle', 'joblib', 'sklearn', 'numpy', 'torch'}:
            raise ImportError('executable model dependency forbidden')
        return None
sys.meta_path.insert(0, Block())
root = sys.argv[1]
sys.path.insert(0, root)
sys.argv = [root + '/scripts/export_static_model.py', '--check']
runpy.run_path(sys.argv[0], run_name='__main__')
'''
    completed = subprocess.run([sys.executable, "-I", "-c", code, str(ROOT)],
                               capture_output=True, text=True, timeout=30, check=True)
    assert "verified both browser models" in completed.stdout
