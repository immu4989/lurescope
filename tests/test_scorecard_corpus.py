"""Research scorecards must admit the whole input before selecting observations."""

import hashlib
import json
import os
from pathlib import Path

import pytest

from lurescope import scorecard_corpus as corpus
from scripts import llm_scorecard as cross
from scripts import robustness_scorecard as character


def record(**changes):
    value = {"id": "synthetic", "text": "synthetic message", "label": 1,
             "typology": "phishing"}
    value.update(changes)
    return value


def line(value):
    return json.dumps(value, ensure_ascii=True).encode() + b"\n"


@pytest.fixture(params=["character", "cross"])
def load(request):
    if request.param == "character":
        return lambda path, limit=0: character.load_fraud_lures(path, limit)
    return lambda path, limit=0: cross.load_fraud_lures(path, limit, phishing_cap=50)


@pytest.mark.parametrize("label", [True, False, 1.0, 0.0, "1", "0", None, 2, -1])
def test_labels_are_exact_binary_integers_even_on_excluded_records(tmp_path, load, label):
    path = tmp_path / "data.jsonl"
    path.write_bytes(line(record()) + line(record(label=label)))
    with pytest.raises(ValueError, match="line 2"):
        load(path)


@pytest.mark.parametrize("bad", [
    {"text": ""}, {"text": "  "}, {"text": 4}, {"text": "\ud800"},
    {"id": True}, {"id": ""}, {"typology": None}, {"typology": 1},
])
def test_selection_fields_are_validated_on_benign_records_too(tmp_path, load, bad):
    path = tmp_path / "data.jsonl"
    path.write_bytes(line(record(label=0, typology="benign", **bad))
                     if "typology" not in bad else line(record(label=0, **bad)))
    with pytest.raises(ValueError, match="line 1"):
        load(path)


@pytest.mark.parametrize("limit", [-1, True, False, 1.0, "1"])
def test_bad_limit_fails_before_filesystem_read(tmp_path, load, limit):
    with pytest.raises(ValueError, match="limit"):
        load(tmp_path / "missing.jsonl", limit)


@pytest.mark.parametrize("payload", [
    b'{"label":0,"label":1,"text":"private sentinel"}\n',
    line(record(meta={"private sentinel": float("nan")})),
    line(record(meta={"private sentinel": float("inf")})),
    line(record()).replace(b'"label": 1', b'"label": 1e999'),
    b'{"label":1,"text":"private sentinel","meta":{"x":1,"x":2}}\n',
    b'{"label":1,"text":"private sentinel","meta":' + b'[' * 130 + b'0' + b']' * 130 + b'}\n',
])
def test_ambiguous_or_excessive_json_is_rejected_with_redacted_error(tmp_path, load, payload):
    path = tmp_path / "data.jsonl"
    path.write_bytes(payload)
    with pytest.raises(ValueError, match="line 1") as error:
        load(path)
    assert "private sentinel" not in str(error.value)
    assert error.value.__suppress_context__


def test_character_limit_cannot_hide_malformed_trailing_input(tmp_path):
    path = tmp_path / "data.jsonl"
    path.write_bytes(line(record()) + b'{"private sentinel":')
    with pytest.raises(ValueError, match="line 2"):
        character.load_fraud_lures(path, limit=1)


@pytest.mark.parametrize("cap", [-1, True, False, 1.0, "1", None])
def test_bad_phishing_cap_fails_before_filesystem_read(tmp_path, cap):
    with pytest.raises(ValueError, match="phishing_cap"):
        cross.load_fraud_lures(tmp_path / "missing.jsonl", 0, cap)


@pytest.mark.parametrize("bad", [b'[]', b'null', b'42', b'{}', b'\xff', b'// \xff',
                                   b'\xef\xbb\xbf' + line(record()),
                                   line(record(meta={"x": "\ud800"}))])
def test_invalid_records_and_encoding_fail_after_limit(tmp_path, load, bad):
    path = tmp_path / "data.jsonl"
    path.write_bytes(line(record()) + bad)
    with pytest.raises(ValueError, match="line 2"):
        load(path, limit=1)


@pytest.mark.parametrize("changes", [{"typology": "benign", "label": 1},
                                      {"typology": "phishing", "label": 0}])
def test_explicit_known_typology_label_contradiction_fails(tmp_path, load, changes):
    path = tmp_path / "data.jsonl"
    path.write_bytes(line(record(**changes)))
    with pytest.raises(ValueError):
        load(path)


def test_minimal_records_extensions_and_duplicate_ids_are_preserved(tmp_path):
    path = tmp_path / "data.jsonl"
    records = [{"label": 1, "text": "café 東京", "extension": {"x": True}},
               record(text="one"), record(text="two"), record(text="two")]
    path.write_bytes(b" // comment\r\n\n" + b"".join(line(value) for value in records))
    loaded, manifest = corpus.load_cohort(path)
    assert loaded == records
    assert manifest["record_count"] == manifest["selected_count"] == 4
    assert character.load_fraud_lures(path) == [value["text"] for value in records]


def test_historical_stratified_policy_preserves_source_cap_and_stable_id_ties(tmp_path):
    path = tmp_path / "data.jsonl"
    records = [record(id="z", text="phishing first"), record(id="a", text="phishing excluded"),
               record(id="same", text="bec first", typology="bec"),
               record(id="same", text="romance second", typology="romance"),
               record(id="same", text="bec second", typology="bec"),
               record(id="0", text="benign", label=0, typology="benign")]
    path.write_bytes(b"".join(line(value) for value in records))
    selected, manifest = corpus.load_cohort(path, limit=3, phishing_cap=1)
    assert [value["text"] for value in selected] == ["bec first", "bec second", "romance second"]
    assert manifest["fraud_count"] == 5 and manifest["benign_count"] == 1
    assert manifest["selection"] == {"method": "fraud-typology-cap-id-order-v1",
                                      "limit": 3, "phishing_cap": 1}
    assert selected == cross.load_fraud_lures(path, 3, 1)
    assert corpus.load_cohort(path, phishing_cap=0)[0] == records[2:3] + records[4:5] + records[3:4]


@pytest.mark.parametrize("ending", [b"\n", b"\r\n", b""])
def test_manifest_commits_exact_bytes_and_framed_ordered_occurrences(tmp_path, ending):
    path = tmp_path / "private-source-name.jsonl"
    first = line(record(id="z", text="private message z"))
    benign = line(record(id="negative", label=0, typology="benign"))
    last = line(record(id="a", text="private message a")).rstrip(b"\n") + ending
    raw = b"// private source comment\r\n\n" + first + benign + last
    path.write_bytes(raw)
    _, manifest = corpus.load_cohort(path, phishing_cap=10)
    commitment = b"scorecard-cohort-v1\n"
    for ordinal, payload in [(2, last), (0, first)]:
        commitment += ordinal.to_bytes(8, "big") + len(payload).to_bytes(8, "big") + payload
    assert manifest["source_sha256"] == hashlib.sha256(raw).hexdigest()
    assert manifest["selected_sha256"] == hashlib.sha256(commitment).hexdigest()
    assert manifest["source_bytes"] == len(raw)
    assert manifest["record_count"] == 3 and manifest["selected_count"] == 2
    serialized = json.dumps(manifest)
    assert "private" not in serialized and str(path) not in serialized
    _, limited = corpus.load_cohort(path, limit=1, phishing_cap=10)
    assert limited["selected_sha256"] != manifest["selected_sha256"]
    assert limited["source_sha256"] == manifest["source_sha256"]


def test_duplicate_occurrences_affect_selection_commitment(tmp_path):
    path = tmp_path / "data.jsonl"
    path.write_bytes(line(record()) * 2)
    one, first = corpus.load_cohort(path, limit=1)
    both, second = corpus.load_cohort(path)
    assert both == one * 2
    assert first["selected_sha256"] != second["selected_sha256"]


def test_hash_and_selection_use_one_consumed_buffer_not_a_reopened_file(tmp_path, monkeypatch):
    path = tmp_path / "data.jsonl"
    original = line(record(text="original"))
    path.write_bytes(original)
    read = corpus.read_regular_file
    calls = []

    def replace_after_read(*args, **kwargs):
        calls.append(args[0])
        result = read(*args, **kwargs)
        path.write_bytes(line(record(text="replacement")))
        return result

    monkeypatch.setattr(corpus, "read_regular_file", replace_after_read)
    records, manifest = corpus.load_cohort(path)
    assert len(calls) == 1 and records[0]["text"] == "original"
    assert manifest["source_sha256"] == hashlib.sha256(original).hexdigest()
    assert path.read_bytes() != original


@pytest.mark.parametrize("bound", ["MAX_SOURCE_BYTES", "MAX_LINE_BYTES"])
def test_exact_byte_limit_and_one_byte_over(tmp_path, monkeypatch, bound):
    path = tmp_path / "data.jsonl"
    raw = line(record())
    path.write_bytes(raw)
    monkeypatch.setattr(corpus, bound, len(raw))
    assert corpus.load_cohort(path)[1]["selected_count"] == 1
    monkeypatch.setattr(corpus, bound, len(raw) - 1)
    with pytest.raises(ValueError, match="limit|bounded size"):
        corpus.load_cohort(path)


def test_comments_also_obey_line_budget(tmp_path, monkeypatch):
    path = tmp_path / "data.jsonl"
    path.write_bytes(b"//" + b"x" * 100 + b"\n" + line(record()))
    monkeypatch.setattr(corpus, "MAX_LINE_BYTES", 100)
    with pytest.raises(ValueError, match="line 1"):
        corpus.load_cohort(path)


def test_record_budget_counts_benign_records_after_selection_limit(tmp_path, monkeypatch):
    path = tmp_path / "data.jsonl"
    path.write_bytes(line(record()) + line(record(label=0, typology="benign")))
    monkeypatch.setattr(corpus, "MAX_RECORDS", 1)
    with pytest.raises(ValueError, match="record limit"):
        corpus.load_cohort(path, limit=1)


def test_node_budget_is_checked_before_json_decoder(tmp_path, monkeypatch):
    path = tmp_path / "data.jsonl"
    path.write_bytes(line(record(meta=list(range(20)))))
    monkeypatch.setattr(corpus, "MAX_RECORD_NODES", 10)
    monkeypatch.setattr(corpus.json, "loads", lambda *a, **kw: pytest.fail("decoder reached"))
    with pytest.raises(ValueError, match="line 1"):
        corpus.load_cohort(path)


@pytest.mark.parametrize("kind", ["directory", "symlink", "parent_symlink", "fifo"])
def test_nonregular_or_symlink_inputs_are_rejected_without_content_read(tmp_path, kind):
    path = tmp_path / "data"
    if kind == "directory":
        path.mkdir()
    elif kind == "fifo":
        if not hasattr(os, "mkfifo"):
            pytest.skip("POSIX FIFO required")
        os.mkfifo(path)
    else:
        real = tmp_path / "real"
        real.mkdir()
        (real / "input").write_bytes(line(record()))
        path.symlink_to(real if kind == "parent_symlink" else real / "input")
        if kind == "parent_symlink":
            path /= "input"
    with pytest.raises(ValueError, match="regular|symlink"):
        corpus.load_cohort(path)


@pytest.mark.parametrize("module", [character, cross])
def test_offline_preflight_needs_no_key_or_provider_and_preserves_outputs(
        tmp_path, monkeypatch, capsys, module):
    path, output = tmp_path / "data.jsonl", tmp_path / "result.json"
    path.write_bytes(line(record()))
    output.write_text("existing output")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)

    def forbidden(*args, **kwargs):
        pytest.fail("corpus preflight reached evaluation or cache access")

    for name in ("compute", "build_detectors", "build_attacker", "run", "_load_cache"):
        if hasattr(module, name):
            monkeypatch.setattr(module, name, forbidden)
    assert module.main(["--data", str(path), "--validate-corpus", "--out-json", str(output)]) == 0
    manifest = json.loads(capsys.readouterr().out)
    assert manifest["selected_count"] == 1 and manifest["contract"] == corpus.CONTRACT
    assert output.read_text() == "existing output"


@pytest.mark.parametrize("module", [character, cross])
def test_late_input_failure_prevents_evaluation_and_output_changes(tmp_path, monkeypatch, module):
    path, output = tmp_path / "data.jsonl", tmp_path / "result.json"
    path.write_bytes(line(record()) + line(record(label=True)))
    output.write_text("existing output")

    def forbidden(*args, **kwargs):
        pytest.fail("bad corpus reached evaluation")

    for name in ("compute", "build_detectors", "build_attacker", "run"):
        if hasattr(module, name):
            monkeypatch.setattr(module, name, forbidden)
    with pytest.raises(ValueError, match="line 2"):
        module.main(["--data", str(path), "--limit", "1", "--out-json", str(output)])
    assert output.read_text() == "existing output"


@pytest.mark.parametrize("module", [character, cross])
def test_generated_reports_include_the_admitted_manifest(tmp_path, monkeypatch, module):
    path, output, markdown = (tmp_path / name for name in
                              ("data.jsonl", "result.json", "result.md"))
    path.write_bytes(line(record()))
    monkeypatch.setenv("OPENROUTER_API_KEY", "synthetic-not-a-key")
    if module is character:
        monkeypatch.setattr(module, "_scorer", lambda _: lambda text: .9)
    else:
        monkeypatch.setattr(module, "build_detectors", lambda judges: dict.fromkeys(
            ["tfidf-logreg", "heuristic-v0"] + [f"judge:{m}" for m in judges], lambda text: .9))

        class Attacker:
            def apply(self, text):
                return text + " synthetic rewrite"

        monkeypatch.setattr(module, "build_attacker", lambda _: Attacker())
    assert module.main(["--data", str(path), "--out-json", str(output),
                        "--out-md", str(markdown)]) == 0
    card = json.loads(output.read_text())
    assert card["n_fraud"] == card["corpus"]["selected_count"] == 1
    assert card["corpus"]["source_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    text = markdown.read_text()
    assert card["corpus"]["source_sha256"] in text and "not label correctness" in text
    assert str(path) not in text


def test_empty_comment_only_file_retains_exact_source_identity(tmp_path):
    path = tmp_path / "data.jsonl"
    raw = b"// comment\n\r\n"
    path.write_bytes(raw)
    records, manifest = corpus.load_cohort(path)
    assert records == [] and manifest["record_count"] == manifest["selected_count"] == 0
    assert manifest["source_sha256"] == hashlib.sha256(raw).hexdigest()


def test_bundled_sample_is_admitted_without_losing_records():
    records, manifest = corpus.load_cohort(Path(character.DEFAULT_DATA))
    assert len(records) == 10
    assert manifest["record_count"] == 16 and manifest["benign_count"] == 6
