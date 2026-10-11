"""CLI proof publication must preserve existing evidence and private permissions."""

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from lurescope import proof
from lurescope.cli import main


@pytest.fixture
def statement():
    return proof.create_email_proof(
        b"Subject: Notes\n\nProject notes.", detector_name="heuristic-v0",
        created_at="2026-10-10T00:00:00Z", subject_salt=bytes(range(32)),
    )


def test_cli_refuses_existing_output_before_scoring(tmp_path, monkeypatch, capsys):
    from lurescope import local_io

    source, output = tmp_path / "source.eml", tmp_path / "proof.json"
    source.write_bytes(b"Subject: Notes\n\nProject notes.")
    output.write_bytes(b"existing evidence")
    monkeypatch.setattr(proof, "create_email_proof",
                        lambda *a, **k: pytest.fail("scoring started for an existing destination"))
    monkeypatch.setattr(local_io, "read_regular_file",
                        lambda *a, **k: pytest.fail("input read for an existing destination"))
    assert main(["proof", str(source), "--out", str(output)]) == 2
    assert output.read_bytes() == b"existing evidence"
    assert "created" not in capsys.readouterr().out


@pytest.mark.skipif(os.name != "posix", reason="POSIX owner-only mode")
def test_new_cli_proof_is_owner_only_even_under_permissive_umask(tmp_path):
    source, output = tmp_path / "source.eml", tmp_path / "proof.json"
    source.write_bytes(b"Subject: Notes\n\nProject notes.")
    previous = os.umask(0)
    try:
        assert main(["proof", str(source), "--detector", "heuristic-v0", "--out", str(output)]) == 0
    finally:
        os.umask(previous)
    assert output.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("kind", ["file", "directory", "symlink", "dangling", "fifo"])
def test_existing_paths_are_preserved_without_staging(tmp_path, monkeypatch, statement, kind):
    output, target = tmp_path / "output", tmp_path / "target"
    target.write_bytes(b"previous target")
    if kind == "file":
        output.write_bytes(b"previous proof")
    elif kind == "directory":
        output.mkdir()
    elif kind in {"symlink", "dangling"}:
        output.symlink_to(target if kind == "symlink" else tmp_path / "missing")
    else:
        if not hasattr(os, "mkfifo"):
            pytest.skip("FIFO unavailable")
        os.mkfifo(output)
    before = output.lstat()
    monkeypatch.setattr(proof.tempfile, "NamedTemporaryFile",
                        lambda **k: pytest.fail("existing output reached staging"))
    with pytest.raises(FileExistsError):
        proof.write_proof(output, statement)
    assert output.lstat().st_ino == before.st_ino
    assert target.read_bytes() == b"previous target"
    if kind == "file":
        assert output.read_bytes() == b"previous proof"


@pytest.mark.parametrize("kind", ["symlink", "missing", "file"])
def test_invalid_immediate_parent_rejected(tmp_path, statement, kind):
    parent = tmp_path / "parent"
    if kind == "symlink":
        parent.symlink_to(tmp_path, target_is_directory=True)
    elif kind == "file":
        parent.write_bytes(b"parent sentinel")
    with pytest.raises((ValueError, FileNotFoundError)):
        proof.write_proof(parent / "out.json", statement)
    assert not (tmp_path / "out.json").exists()
    assert not list(tmp_path.glob(".lureproof-*.tmp"))


def test_cli_cannot_replace_its_input_email(tmp_path, monkeypatch):
    source = tmp_path / "email.eml"
    raw = b"Subject: Notes\n\nOriginal email."
    source.write_bytes(raw)
    monkeypatch.setattr(proof, "create_email_proof",
                        lambda *a, **k: pytest.fail("self-overwrite reached scoring"))
    assert main(["proof", str(source), "--out", str(source)]) == 2
    assert source.read_bytes() == raw


@pytest.mark.parametrize("value", [None, [], {}, {"secret": float("nan")},
                                    {"secret": "\ud800"}, {"secret": {1, 2}}])
def test_invalid_proofs_do_not_create_files(tmp_path, monkeypatch, value):
    monkeypatch.setattr(proof.tempfile, "NamedTemporaryFile",
                        lambda **k: pytest.fail("invalid artifact reached staging"))
    with pytest.raises(ValueError, match="bounded valid") as error:
        proof.write_proof(tmp_path / "output.json", value)
    assert "secret" not in str(error.value)
    assert error.value.__suppress_context__
    assert list(tmp_path.iterdir()) == []


def test_exact_pretty_serialized_byte_limit(tmp_path, monkeypatch, statement):
    raw = proof.dumps_proof(statement).encode()
    monkeypatch.setattr(proof, "MAX_PROOF_BYTES", len(raw))
    output = tmp_path / "exact.json"
    result = proof.write_proof(output, statement)
    assert output.read_bytes() == raw and result["valid"]
    monkeypatch.setattr(proof, "MAX_PROOF_BYTES", len(raw) - 1)
    with pytest.raises(ValueError):
        proof.write_proof(tmp_path / "over.json", statement)
    assert not (tmp_path / "over.json").exists()


@pytest.mark.parametrize("failure", ["fsync", "link", "unsupported-link"])
def test_prepublication_failures_leave_no_partial_output(tmp_path, monkeypatch, statement, failure):
    output = tmp_path / "proof.json"

    def fail(*args, **kwargs):
        raise (NotImplementedError if failure == "unsupported-link" else OSError)("injected")

    monkeypatch.setattr(proof.os, "fsync" if failure == "fsync" else "link", fail)
    with pytest.raises(OSError):
        proof.write_proof(output, statement)
    assert list(tmp_path.iterdir()) == []


def test_stage_complete_private_and_synced_before_publish(tmp_path, monkeypatch, statement):
    output = tmp_path / "proof.json"
    actual_link, actual_fsync = proof.os.link, proof.os.fsync
    synced = []

    def fsync(fd):
        actual_fsync(fd)
        synced.append(True)

    def link(source, destination):
        assert synced == [True] and not output.exists()
        assert Path(source).parent == output.parent
        assert Path(source).read_bytes() == proof.dumps_proof(statement).encode()
        assert proof.verify_proof(proof.load_proof(Path(source)))["valid"]
        if os.name == "posix":
            assert Path(source).stat().st_mode & 0o077 == 0
        actual_link(source, destination)

    monkeypatch.setattr(proof.os, "fsync", fsync)
    monkeypatch.setattr(proof.os, "link", link)
    result = proof.write_proof(output, statement)
    assert result == proof.verify_proof(proof.load_proof(output))
    assert list(tmp_path.iterdir()) == [output]


@pytest.mark.parametrize("kind", ["file", "symlink"])
def test_destination_created_at_publication_is_not_overwritten(
    tmp_path, monkeypatch, statement, kind,
):
    output, target = tmp_path / "proof.json", tmp_path / "target"
    target.write_bytes(b"preserved target")
    actual_link = proof.os.link

    def race(source, destination):
        if kind == "file":
            output.write_bytes(b"concurrent evidence")
        else:
            output.symlink_to(target)
        actual_link(source, destination)

    monkeypatch.setattr(proof.os, "link", race)
    with pytest.raises(FileExistsError):
        proof.write_proof(output, statement)
    assert target.read_bytes() == b"preserved target"
    expected = b"concurrent evidence" if kind == "file" else b"preserved target"
    assert output.read_bytes() == expected
    assert not list(tmp_path.glob(".lureproof-*.tmp"))


def test_concurrent_publishers_have_exactly_one_winner(tmp_path, monkeypatch, statement):
    output = tmp_path / "proof.json"
    actual_link = proof.os.link
    ready = threading.Barrier(2)

    def link(source, destination):
        ready.wait(timeout=3)
        actual_link(source, destination)

    monkeypatch.setattr(proof.os, "link", link)
    with ThreadPoolExecutor(max_workers=2) as pool:
        jobs = [pool.submit(proof.write_proof, output, statement) for _ in range(2)]
        outcomes = []
        for job in jobs:
            try:
                outcomes.append(job.result(timeout=5)["valid"])
            except FileExistsError:
                outcomes.append(False)
    assert sorted(outcomes) == [False, True]
    assert proof.load_proof(output) == statement
    assert list(tmp_path.iterdir()) == [output]


def test_signed_output_survives_publication_and_authenticates(tmp_path, statement):
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    proof.generate_keypair(private, public)
    envelope = proof.sign_statement(statement, private.read_bytes())
    output = tmp_path / "proof.json"
    result = proof.write_proof(output, envelope)
    assert result["valid"] and not result["authenticated"]
    loaded = proof.load_proof(output)
    assert loaded == envelope
    assert proof.verify_proof(loaded, public.read_bytes(), require_signature=True)["authenticated"]


def test_cli_invalid_generated_proof_does_not_publish(tmp_path, monkeypatch, capsys):
    source, output = tmp_path / "source.eml", tmp_path / "proof.json"
    source.write_bytes(b"Subject: Notes\n\nNotes")
    monkeypatch.setattr(proof, "create_email_proof", lambda *a, **k: {"invalid": "private"})
    assert main(["proof", str(source), "--out", str(output)]) == 2
    assert not output.exists()
    assert "created" not in capsys.readouterr().out


@pytest.mark.parametrize("failure", ["write", "short-write", "flush", "close", "interrupt"])
def test_staging_failures_and_interruptions_remove_partial_temporary(
    tmp_path, monkeypatch, statement, failure,
):
    original = proof.tempfile.NamedTemporaryFile

    class Stream:
        def __init__(self, **kwargs):
            self.stream = original(**kwargs)
            self.name = self.stream.name

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()
            if failure == "close":
                raise OSError("injected close failure")

        def write(self, value):
            if failure in {"write", "short-write", "interrupt"}:
                self.stream.write(value[:1])
                if failure == "short-write":
                    return 1
                if failure == "interrupt":
                    raise KeyboardInterrupt
                raise OSError("injected partial write")
            return self.stream.write(value)

        def flush(self):
            if failure == "flush":
                raise OSError("injected flush failure")
            self.stream.flush()

        def fileno(self):
            return self.stream.fileno()

    monkeypatch.setattr(proof.tempfile, "NamedTemporaryFile", Stream)
    with pytest.raises(KeyboardInterrupt if failure == "interrupt" else OSError):
        proof.write_proof(tmp_path / "proof.json", statement)
    assert list(tmp_path.iterdir()) == []


def test_cleanup_failure_reports_that_complete_output_was_published(
    tmp_path, monkeypatch, statement,
):
    output = tmp_path / "proof.json"
    original = Path.unlink

    def fail(path, *args, **kwargs):
        if path.name.startswith(".lureproof-"):
            raise OSError("injected cleanup failure")
        return original(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "unlink", fail)
        with pytest.raises(OSError, match="proof was published"):
            proof.write_proof(output, statement)
    assert proof.load_proof(output) == statement
    leftovers = list(tmp_path.glob(".lureproof-*.tmp"))
    assert len(leftovers) == 1 and leftovers[0].read_bytes() == output.read_bytes()
    leftovers[0].unlink()
    assert proof.load_proof(output) == statement


def test_publication_uses_the_validated_serialized_snapshot(tmp_path, monkeypatch, statement):
    expected = proof.dumps_proof(statement).encode()
    original = proof.verify_proof

    def validate(snapshot):
        assert snapshot is not statement
        result = original(snapshot)
        statement["predicate"]["assessment"]["risk_tier"] = "invalid-after-serialization"
        return result

    monkeypatch.setattr(proof, "verify_proof", validate)
    output = tmp_path / "proof.json"
    result = proof.write_proof(output, statement)
    assert result["valid"] and output.read_bytes() == expected
