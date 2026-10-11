"""Header budgets apply before recursive structured-header interpretation."""

import base64
import json
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from email import policy
from pathlib import Path

import pytest

from lurescope import service
from lurescope.proof import create_email_proof
from lurescope.triage import (
    MAX_EMAIL_HEADER_BYTES,
    MAX_EMAIL_HEADER_NESTING,
    MAX_EMAIL_HEADERS,
    MAX_EMAIL_TOTAL_HEADER_BYTES,
    EmailTooComplex,
    parse_email,
    triage_email,
)


def nested_header(depth, name=b"From", newline=b"\n"):
    prefix = b"" if name == b"From" else b"text/plain; "
    suffix = b" <sender@example.test>" if name == b"From" else b""
    return (name + b": " + prefix + b"(" * depth + b"private-comment" + b")" * depth
            + suffix + newline + b"Subject: Private subject" + newline * 2 + b"Notes")


def header_bytes(size, *, prefix=b"X-Padding: ", newline=b"\n"):
    return prefix + b"x" * (size - len(prefix) - len(newline)) + newline


def oversized_headers():
    return header_bytes(MAX_EMAIL_HEADER_BYTES + 1) + b"\nNotes"


def excessive_count():
    return b"X-Trace: n\n" * (MAX_EMAIL_HEADERS + 1) + b"\nNotes"


def excessive_total():
    return (header_bytes(MAX_EMAIL_HEADER_BYTES) * 16 + b"X-Trace: n\n\nNotes")


def test_documented_header_limits():
    assert MAX_EMAIL_HEADER_BYTES == 16 * 1024
    assert MAX_EMAIL_TOTAL_HEADER_BYTES == 256 * 1024
    assert MAX_EMAIL_HEADERS == 1024
    assert MAX_EMAIL_HEADER_NESTING == 32


@pytest.mark.parametrize("name", [b"From", b"Content-Type"])
@pytest.mark.parametrize("newline", [b"\n", b"\r\n", b"\r"])
def test_nesting_boundary_and_small_recursion_reproducer(name, newline):
    assert parse_email(nested_header(MAX_EMAIL_HEADER_NESTING, name, newline)).body == "Notes"
    for depth in (MAX_EMAIL_HEADER_NESTING + 1, 1200):
        raw = nested_header(depth, name, newline)
        assert len(raw) < 3_000
        with pytest.raises(EmailTooComplex, match="header nesting"):
            parse_email(raw)


@pytest.mark.parametrize("newline", [b"\n", b"\r\n", b"\r"])
def test_field_budget_counts_original_bytes_and_line_endings(newline):
    raw = header_bytes(MAX_EMAIL_HEADER_BYTES, newline=newline) + newline + b"Notes"
    assert parse_email(raw).body == "Notes"
    with pytest.raises(EmailTooComplex, match="header field"):
        parse_email(header_bytes(MAX_EMAIL_HEADER_BYTES + 1, newline=newline) + newline + b"Notes")


def test_non_ascii_source_octets_are_not_counted_as_decoded_characters():
    prefix = b"X-Padding: " + "é".encode() * 1000
    raw = header_bytes(MAX_EMAIL_HEADER_BYTES, prefix=prefix) + b"\nNotes"
    assert parse_email(raw).body == "Notes"
    with pytest.raises(EmailTooComplex, match="header field"):
        parse_email(header_bytes(MAX_EMAIL_HEADER_BYTES + 1, prefix=prefix) + b"\nNotes")


def test_folded_lines_share_one_field_budget_before_source_join(monkeypatch):
    observed = []
    original = policy.EmailPolicy.header_source_parse

    def tracked(self, lines):
        observed.append(lines[0].split(":")[0])
        return original(self, lines)

    monkeypatch.setattr(policy.EmailPolicy, "header_source_parse", tracked)
    with pytest.raises(EmailTooComplex, match="header field"):
        parse_email(b"X-Padding: " + b"x" * 9000 + b"\n " + b"x" * 9000 + b"\n\nNotes")
    assert observed == []


def test_excessive_nesting_never_reaches_structured_header_parser(monkeypatch):
    def forbidden(*args):
        pytest.fail("over-nested header reached structured interpretation")

    monkeypatch.setattr(policy.EmailPolicy, "header_fetch_parse", forbidden)
    with pytest.raises(EmailTooComplex, match="header nesting"):
        parse_email(nested_header(1200))


def test_unforeseen_header_recursion_is_a_controlled_rejection(monkeypatch):
    original = policy.EmailPolicy.header_fetch_parse

    def recurse(self, name, value):
        if name.lower() == "subject":
            raise RecursionError("synthetic interpreter failure")
        return original(self, name, value)

    monkeypatch.setattr(policy.EmailPolicy, "header_fetch_parse", recurse)
    with pytest.raises(EmailTooComplex, match="header interpretation exceeded parser capacity"):
        parse_email(b"Subject: Private subject\n\nNotes")


def test_exact_total_header_budget_is_shared_across_fields():
    accepted = header_bytes(MAX_EMAIL_HEADER_BYTES) * 16
    assert len(accepted) == MAX_EMAIL_TOTAL_HEADER_BYTES
    assert parse_email(accepted + b"\nNotes").body == "Notes"
    with pytest.raises(EmailTooComplex, match="total headers"):
        parse_email(excessive_total())


def test_exact_field_count_budget_counts_fields_not_folded_lines():
    assert parse_email(b"X-Trace: n\n" * MAX_EMAIL_HEADERS + b"\nNotes").body == "Notes"
    with pytest.raises(EmailTooComplex, match="header count"):
        parse_email(excessive_count())
    assert parse_email(b"X-Trace: n\n" + b" n\n" * MAX_EMAIL_HEADERS + b"\nNotes").body == "Notes"


def test_header_budget_includes_attachment_descendants():
    raw = (b"Subject: Notes\nContent-Type: multipart/mixed; boundary=outer\n\n"
           b"--outer\nContent-Type: text/plain\n\nNotes\n"
           b"--outer\nContent-Disposition: attachment; filename=private.eml\n"
           b"Content-Type: message/rfc822\n\n" + excessive_count() + b"\n--outer--\n")
    with pytest.raises(EmailTooComplex, match="header count"):
        parse_email(raw)


@pytest.mark.parametrize("display", [
    b'"' + b"(" * 40 + b"literal" + b")" * 40 + b'"',
    b"(" + b"\\(" * 40 + b"literal" + b"\\)" * 40 + b")",
    b'"escaped \\" quote ' + b"(" * 40 + b'"',
    b"(comment with literal quote \" and (nested comment))",
    b"(folded\\\r\n (nested))",
])
def test_quotes_escapes_and_folding_preserve_ordinary_address_interpretation(display):
    parsed = parse_email(b"From: " + display + b" <sender@example.test>\r\n\r\nNotes")
    assert parsed.from_address == "sender@example.test"
    assert parsed.body == "Notes"


def test_parentheses_in_body_are_not_a_header_budget():
    body = "(" * 1200 + "Notes" + ")" * 1200
    assert parse_email(b"Subject: Notes\n\n" + body.encode()).body == body


@pytest.mark.parametrize("value", [
    b'("' + b"(" * 33 + b")" * 34,
    b"\\" + b"(" * 33 + b")" * 33,
    b"(" + b"\r\n (" * 32 + b")" * 33,
])
def test_quotes_in_comments_and_folding_cannot_hide_nesting(value):
    with pytest.raises(EmailTooComplex, match="header nesting"):
        parse_email(b"From: " + value + b" <sender@example.test>\n\nNotes")


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js not installed")
def test_browser_python_acceptance_agrees_on_supported_header_budget_fixtures():
    fixtures = [
        header_bytes(MAX_EMAIL_HEADER_BYTES) + b"\nNotes",
        oversized_headers(),
        b"X-Trace: n\n" * MAX_EMAIL_HEADERS + b"\nNotes",
        excessive_count(),
        header_bytes(MAX_EMAIL_HEADER_BYTES) * 16 + b"\nNotes",
        excessive_total(),
        nested_header(32), nested_header(33), nested_header(1200),
        b'X-Note: "' + b"(" * 40 + b")" * 40 + b'"\n\nNotes',
        b"X-Note: (" + b"\\(" * 40 + b"\\)" * 40 + b")\n\nNotes",
        b'X-Note: ("' + b"(" * 33 + b")" * 34 + b"\n\nNotes",
        b'X"Note: ' + b"(" * 33 + b")" * 33 + b"\n\nNotes",
    ]
    fixtures = [raw.replace(b"\n", newline) for raw in fixtures for newline in (b"\n", b"\r\n")]
    expected = []
    for raw in fixtures:
        try:
            triage_email(raw, "heuristic-v0")
        except EmailTooComplex:
            expected.append(False)
        else:
            expected.append(True)
    script = """
const fs = require('node:fs');
const engine = require('./lurescope/static/browser-engine.js');
const results = JSON.parse(fs.readFileSync(0, 'utf8')).map(raw => {
  try { engine.triageEmail(raw, 'heuristic-v0'); return true; }
  catch (error) { return false; }
});
process.stdout.write(JSON.stringify(results));
"""
    output = subprocess.run([shutil.which("node"), "-e", script],
                            input=json.dumps([raw.decode() for raw in fixtures]),
                            capture_output=True, text=True, check=True, timeout=10,
                            cwd=Path(__file__).resolve().parents[1])
    assert json.loads(output.stdout) == expected


@pytest.mark.parametrize("make_raw", [oversized_headers, excessive_count, excessive_total,
                                      lambda: nested_header(1200)])
@pytest.mark.parametrize("operation", [triage_email, create_email_proof])
def test_header_rejection_precedes_scoring_and_proof_creation(monkeypatch, make_raw, operation):
    def forbidden(*args, **kwargs):
        pytest.fail("over-limit headers reached detector scoring")

    monkeypatch.setattr(service, "score", forbidden)
    with pytest.raises(EmailTooComplex):
        operation(make_raw(), "heuristic-v0")


@pytest.mark.parametrize("endpoint", ["/triage/email", "/proof/email"])
@pytest.mark.parametrize("as_base64", [False, True])
def test_api_returns_private_input_error(endpoint, as_base64):
    from fastapi.testclient import TestClient

    from lurescope.app import app

    raw = nested_header(1200)
    representation = ({"raw_email_base64": base64.b64encode(raw).decode()} if as_base64
                      else {"raw_email": raw.decode()})
    with TestClient(app) as client:
        response = client.post(endpoint, json={**representation, "detector": "heuristic-v0"})
    assert response.status_code == 400
    assert set(response.json()) == {"detail"}
    assert "rejected input" in response.json()["detail"]
    assert "private" not in response.text.lower()


def test_per_input_budgets_reset_after_rejection_and_across_threads():
    def run(index):
        with pytest.raises(EmailTooComplex):
            parse_email(excessive_count())
        return parse_email(b"X-Trace: n\n" * MAX_EMAIL_HEADERS + b"\nNotes").body

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(run, range(8))) == ["Notes"] * 8


def test_inbox_continues_without_storing_private_rejected_header(tmp_path):
    from lurescope.inbox import process_inbox

    output = tmp_path / "cases"
    run = process_inbox([
        ("private-path.eml", nested_header(1200)),
        ("good.eml", b"Subject: Notes\n\nOrdinary project notes."),
    ], output, detector_name="heuristic-v0")
    assert run.failed_count == 1
    rows = [json.loads(line) for line in (output / "manifest.jsonl").read_text().splitlines()]
    assert rows[0]["error_type"] == "EmailTooComplex"
    assert "risk_tier" not in rows[0]
    assert rows[1]["status"] == "processed"
    assert len(list(output.glob("*.lureproof.json"))) == 1
    for artifact in output.iterdir():
        assert "private" not in artifact.read_text().lower()
