# Source-branch hardening: deployment migration

These changes are **unreleased**, not part of published PyPI 0.11.0. No production
deployment or paid-provider experiment is implied by the offline verification.

## Default scoring model

The default detector name remains `tfidf-logreg`, but serving now uses pinned,
full-precision JSON weights with a fixed inference profile. It does not unpickle
the bundled model. Over 1,000 test inputs must match the trusted original within
1e-12 absolute probability; feature rankings are also checked.

See [portable model](PORTABLE_MODEL.md) for the exact artifact pins, conversion
procedure, numerical limitations, and trusted-source requirements. Original
joblib/training dependencies remain available for reproducibility. The rounded
browser model is unchanged. This is not a claim of improved fraud accuracy.

New LureProofs and pilot plans bind the JSON bytes actually loaded. New operational
pilots require the new pin; historical receipt validation recognizes both reviewed
model pins. Old preregistered plans are not silently rewritten to match a new
artifact. Review and register a new plan before evaluating the changed deployment.

## API clients

Requests now reject unknown fields, coerced thresholds/signature options,
duplicate JSON keys, nonfinite values, and excessive nesting. Validation failures
return a fixed redacted `422` response. All HTTP bodies are capped at 8 MiB before
routing; see [deployment boundaries](PUBLIC_DEPLOYMENT.md). LureProof verification
uses strict bounded payload decoding even for cryptographically signed bytes;
CLI proof/key intake now uses bounded non-symlink regular-file reads.

CLI signing-key inputs across legacy commands now require regular, non-symlink
files of at most 64 KiB and owner-only permissions on POSIX. Review ownership
and use `chmod 600` on the intended private file if appropriate; do not change
permissions on unrelated files or publish keys. Only an omitted key option means
unsigned output; an explicitly empty path is an error. Direct Python byte-input
signing APIs cannot inspect the permissions of a file they were not given.

Detector abstentions and invalid/non-finite scores no longer become zero-risk
benign results. Score/triage/proof calls fail without issuing a decision or proof.
Provider exception content is redacted from HTTP error responses. Clients should
route unavailable decisions to explicit handling/review, not turn an error into
an allow decision. See [public deployment](PUBLIC_DEPLOYMENT.md).

Direct Python service calls validate thresholds before detector work. Explicit
invalid creation timestamps are rejected instead of being replaced with now.

## Policies and evidence files

Policy loading uses bounded strict JSON and content-based validation caching.
Optional `LURESCOPE_POLICY_SHA256` binds an operator-approved artifact; a changed
file fails before scoring. Without a pin, changed bytes are revalidated. Review
the [policy configuration guide](RISK_CONTROLLED_POLICY.md) before deployment.

Legacy local-evidence readers now reject nonregular/symlink files, oversized reads,
and observed changes during reading. Parent directories must remain trusted.
The new [checkpoint byte verifier](CHECKPOINT_VERIFICATION.md) independently checks
a pinned preflight report's byte bindings without loading a model; it is not an
independent tensor parser or publisher-authentication service.

## Offline verification

```sh
python -m pytest -q
ruff check lurescope tests scripts
node --test tests/browser_engine.test.cjs tests/evidence_explorer.test.cjs
python scripts/check_producer_contract.py
python scripts/verify_mandate_independence.py
python -m build --no-isolation
```

CI also installs the wheel outside the checkout, verifies ten authority profiles,
and runs `scripts/check_installed_model.py --installed-root PATH` in a fresh
interpreter with pickle/joblib/sklearn/NumPy/Torch imports blocked. This verifies
the packaged default model path, not every optional detector or deployment.

Local wheels still named 0.11.0 are test artifacts: do not upload them over an
existing release. Versioning, protected-branch review, live CI, and publishing are
separate release steps. No government certification, procurement approval, model
safety guarantee, or production-readiness claim follows from passing these tests.
# Inbox input consistency (unreleased)

Inbox CLI message files must now be regular non-symlink files. Copy mail exports
into a trusted directory before processing; symbolic-link aliases are rejected.
Count and total-prefix-byte limits are checked before content reads, and each
read must match its preflight device, inode, size, and modification/change times.
Observed mutations fail the batch rather than silently scoring a partial message.
This is not an atomic filesystem snapshot: trust ancestor directories and avoid
concurrent writers. Stable oversized messages still use a bounded size-rejection
prefix, never a successful assessment of the truncated content. Standard input
has a byte bound but no filesystem identity guarantee.

## Email scoring coverage

Python triage now reports incomplete inspection separately from its content label.
Unsupported inline body formats, embedded bodies, undecodable text, parser
defects, repeated singleton headers, and subject-only assessments produce medium
review cues. A benign content label cannot override these cues into a low-risk
decision. Valid declared legacy charsets remain supported; unknown charsets are
not guessed, and undecodable parts are omitted instead of replaced with guessed
characters. A message with neither subject nor readable body still fails without
a decision.

The codes are `uninspected_body_part`, `body_decoding_uncertain`,
`mime_parse_defect`, `ambiguous_email_headers`, `no_readable_body`, and
`html_body_differs`. The last cue reports extracted HTML text that differs from
the plain text selected for scoring after whitespace is collapsed. It does not
assert malicious intent or visual equivalence; ordinary alternative renderings
can legitimately differ. Neither a second model call nor a second content score
is added. Existing
triage evidence fields and minimized proof evidence-code lists carry them, so
API and inbox consumers should route by `risk_tier`, not the content label alone.
The score still concerns only extracted subject/body text, not opaque content.
These conservative cues may increase review volume for ordinary encrypted,
signed, malformed, or subject-only mail; they are not fraud findings. Inventory
their frequency in a controlled pilot before changing operational routing.

Python's default [text content handler](https://docs.python.org/3/library/email.contentmanager.html#email.contentmanager.get_content)
replaces decoding errors unless strict decoding is requested. The
[parser defect mechanism](https://docs.python.org/3/library/email.errors.html)
also records recoverable MIME problems rather than necessarily raising them.
LureScope surfaces these uncertainties but does not audit attachment descendants
or implement a complete mail-client renderer. The browser rejects unsupported
structures, rejects malformed header lines, and adds review cues for subject-only
or repeated-singleton-header input. Historical proofs are not re-scored.

New Python triage and LureProof generation reject subject-plus-readable-body text
over 20,000 characters **before any detector call**. Earlier versions scored only
the prefix; historical proofs with a disclosed `truncated` flag remain readable,
but are not reinterpreted as full-message assessments. Over-limit messages require
manual review rather than being labeled low risk. The original 5 MiB email-byte
limit still applies separately. Attachments and external resources are not scanned.

Body extraction now stops at attachment dispositions, filename-bearing parts
(including inline files), and `message/*` parts. Their children are not decoded
for scoring, link extraction, image cues, or nested attachment-name reporting.
Ordinary nested multipart bodies remain readable. This prevents attached mail
from being mistaken for the outer message, but it can reduce the reported text
and evidence compared with older versions. Inspect attachments separately in a
controlled workflow.

Python MIME tree construction is now limited to **256 message nodes** and
**32 levels**, counting the root as one node at level one. Embedded messages,
attachment subtrees, and delivery-status header blocks count even when their
contents are excluded from scoring. The parser checks the part budget before
creating another node and the depth budget before descending into a child,
using a per-input [message factory](https://docs.python.org/3/library/email.parser.html).
These are application limits, not email-format requirements.

Header parsing also enforces the following budgets:

| Dimension | Limit | What counts |
| --- | --- | --- |
| One header field | 16 KiB | Original name, separator, value, folded lines, and line endings |
| Total headers | 256 KiB | All parsed header fields across the MIME tree |
| Header count | 1,024 | Fields, not physical continuation lines; repeated fields count separately |
| Header nesting | 32 levels | Unquoted/unescaped parentheses in each unfolded header value |

Python applies those budgets to attachment and embedded-message headers as well,
without decoding their bodies for scoring. The nesting check is conservative,
including for unstructured fields: exceeding it does not establish invalid email
syntax or malicious intent. Quoted parentheses and quoted-pairs in strings/comments
do not increase the counter. These checks precede structured header interpretation
through Python's [email policy hooks](https://docs.python.org/3/library/email.policy.html).
Unexpected recursion during structured header fetch also becomes a controlled
`EmailTooComplex` rejection rather than a partial assessment.

Exceeding a structural or header limit raises `EmailTooComplex` (a `ValueError`)
without producing a score or proof. The triage and proof APIs return HTTP 400 with their existing
generic rejection message. Inbox bundles record only the error class and continue
with later messages; CLI triage reports the failure and returns a nonzero status.
Send such messages to a separately controlled review workflow rather than
removing parts to obtain an apparently complete assessment. Legitimate large
digests may also exceed these limits. No HTTP request can raise the limits.

The byte, tree, and header caps do not bound every header/HTML parsing operation,
process memory, or wall-clock time. Run untrusted-mail workflows with process isolation,
external resource limits, and maintained Python dependencies; these checks are
not a parser sandbox or attachment inspection.

Browser preview also rejects over-limit text (its counter uses JavaScript UTF-16
code units). Its deliberately limited MIME profile supports direct plain/HTML
text and one-level mixed/alternative/related multipart with at most 128 parts.
The same header budgets are shared across the root and the MIME parts the browser
visits; attachment descendants are not parsed or counted there. LF and CRLF header
framing are supported; bare CR requires the full local API, which supports it.
Twenty-six synthetic cases check browser/Python acceptance at supported header
boundaries, not general mail-client equivalence.
It rejects nested bodies, unsupported inline types/charsets, duplicate structural
headers, malformed transfer encodings, and missing closing boundaries. Delimiters
are recognized at line boundaries rather than inside arbitrary body text, following
the framing rule in [RFC 2046](https://www.rfc-editor.org/rfc/rfc2046).
Named inline files are excluded from body scoring. Extended MIME filename
parameters require the full API. HTML preview decodes valid numeric character
references and a small semicolon-terminated named set (`amp`, `lt`, `gt`, `quot`,
`apos`, `nbsp`, plus HTML-defined uppercase aliases) exactly once in text and
quoted links. Other named references, ambiguous bare ampersand words, invalid
Unicode references, and legacy control-code mappings require the API. The full
Python parser uses the broader [HTML character-reference rules](https://docs.python.org/3/library/html.html#html.unescape).
Thirty-two synthetic numeric-reference email cases check browser/Python scoring
and link extraction; this is not complete HTML5 parsing or visual-rendering parity.
Use the full local parser for unsupported MIME, and manual review for over-limit
content; neither route supplies a guarantee against fraud. No output is a safety
or compliance certification.

The browser model now ships inside the Python package. CI verifies installed
browser scoring without fetching assets from the checkout. The static Space copy
must match exactly. `python scripts/export_static_model.py` derives both copies
from the SHA-256-pinned, data-only serving artifact without importing pickle,
joblib, or model frameworks. `--check` verifies both outputs without writing.
Export preserves the existing rounded weights, not full-precision Python parity.
Each output replacement is atomic, but the two-file update is not a transaction;
CI rejects mismatched copies. A schema/weight
check prevents malformed model arithmetic; it does not authenticate model origin.

Browser heuristic patterns now follow Unicode word boundaries and decimal-digit
matching instead of JavaScript's ASCII-oriented defaults, with explicit handling
for dotted/dotless I under Python's
[case-insensitive matching rules](https://docs.python.org/3/library/re.html#re.IGNORECASE).
Cross-language tests cover 2,048 synthetic cases against the Python heuristic,
and 261 TF-IDF cases with absolute probability tolerance `1e-5` for rounded
weights. This does not establish universal runtime/Unicode-version parity or
multilingual detection quality. Browser scoring still has a UTF-16 input bound.

The workbench invalidates displayed results when their inputs change. Request
versions suppress delayed responses and file reads from older selections; proof
downloads bind the triaged message, filename, and detector. This is a UI consistency
guarantee, not cancellation of an already-started server request or provider charge.

## Proof producer preflight

New proof creation rejects invalid detector, threshold, privacy profile, nonce,
issuer, salt, or signing-key settings before parsing or scoring the message.
Inbox batches run the same shared-settings check before creating the output
directory. Per-message failures still remain individual case errors; a successful
preflight does not promise all messages will parse, nor does it validate the
deployment policy or guarantee subsequent filesystem writes.

Private signing keys must be unencrypted P-256 PEM bytes, at most 16 KiB. New
caller-supplied salts must contain 16–1,024 bytes. Issuer and nonce retain their
existing length limits but reject controls and lone surrogates. These restrictions
apply to creation, not retroactively to the historical verification contract.

Local email-to-proof generation uses the data-only serving path without importing
pickle, joblib, NumPy, scikit-learn, or Torch. The legacy `sklearn_version` field
now reads installed package metadata; `not-installed` is explicit when absent.
It is not a statement that scikit-learn performed inference. Package dependencies
have not been removed, and trusted model reproduction may still use them. The
isolated installed-wheel smoke test exercises both scoring and proof verification
with those imports blocked; this is not a process sandbox or an authenticity claim.
