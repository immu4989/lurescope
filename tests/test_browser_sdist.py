"""Source-archive browser contract rejects omission, drift and nonregular members."""

import importlib.util
import io
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "browser_sdist", ROOT / "scripts/check_browser_sdist.py"
)
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


@pytest.mark.parametrize("kind", ["valid", "missing", "stale", "symlink", "duplicate"])
def test_browser_source_archive_contract(tmp_path, monkeypatch, kind):
    monkeypatch.setattr(checker, "REQUIRED", ("asset.js",))
    (tmp_path / "asset.js").write_bytes(b"reviewed")
    archive_path = tmp_path / "source.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        member = tarfile.TarInfo("package/other.js" if kind == "missing" else "package/asset.js")
        payload = b"modified" if kind == "stale" else b"reviewed"
        member.size = len(payload)
        if kind == "symlink":
            member.type, member.linkname, member.size = tarfile.SYMTYPE, "/outside", 0
        archive.addfile(member, io.BytesIO(payload))
        if kind == "duplicate":
            archive.addfile(member, io.BytesIO(payload))
    if kind == "valid":
        checker.verify(archive_path, tmp_path)
    else:
        with pytest.raises((ValueError, KeyError)):
            checker.verify(archive_path, tmp_path)
