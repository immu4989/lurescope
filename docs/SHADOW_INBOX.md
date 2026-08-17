# Shadow Inbox: measure safely before enforcement

`lurescope shadow` evaluates exported mail without connecting to a live mailbox,
changing message state, or sending content to a provider. It is designed for a
time-bounded pilot: ingest an approved export, remove byte-equivalent duplicates,
create minimized case evidence, collect fixed-vocabulary analyst decisions, and
measure routing quality before anyone considers enforcement.

This is decision support, not an autonomous mail control.

## Start with the synthetic pack

```bash
python -m pip install -e '.[dev]'

lurescope shadow run examples/shadow-pilot/eml \
  --format eml --out ./shadow-pilot
```

The included pack has six synthetic candidates and one exact duplicate. It contains
no real people, accounts, credentials, domains, or live links. Expected risk tiers
are deliberately not frozen: model or policy changes should be allowed to change a
prediction while the workflow and privacy contracts remain stable.

## Run an approved exported-mail pilot

Shadow Inbox accepts individual `.eml` files, directories of `.eml` files, Maildir
roots, and mbox files:

```bash
# Auto-detect a Maildir root or .mbox/.mbx file
lurescope shadow run /approved/export/Maildir --out ./shadow-pilot

# Recursively discover .eml plus .mbox/.mbx containers
lurescope shadow run /approved/export --recursive --out ./shadow-pilot

# Make an ambiguous input explicit
lurescope shadow run /approved/export/archive --format mbox --out ./shadow-pilot
```

The output directory must be new. It is created with mode `0700`; files use `0600`:

```text
shadow-pilot/
├── analyst-labels.jsonl
├── case-<random>.lureproof.json
├── manifest.jsonl
├── shadow-report.json
├── shadow-report.md
├── shadow-run.json
└── summary.json
```

The source-to-case mapping appears only in the local command's in-memory result.
Shadow Inbox does not write source paths into the bundle. Avoid redirecting terminal
output into centrally collected logs if local filenames are sensitive.

### Bounded parsing and deduplication

- Symbolic-link inputs are rejected.
- Candidate count and a 64 MiB on-disk batch budget are checked before `.eml` or
  Maildir message bodies are read.
- A run accepts at most 1,000 candidates; each parsed message is capped at 5 MiB.
- Deduplication normalizes line endings and trailing final newlines, then compares
  an in-memory SHA-256 digest. The digest is not persisted.
- Deduplication is intentionally conservative. It does not merge similar content or
  trust a repeated `Message-ID`.
- HTML is reduced to visible text. Scripts and styles are ignored; links are never
  followed; attachment payloads are never opened or extracted.
- Inline-image plus QR/scan language and image-dominant HTML can trigger deterministic
  review evidence. LureScope does **not** decode pixels or claim that an image is a QR
  code.

For mbox, the container may be scanned to identify message boundaries before the
limits pass, but no message object is retained. The complete mbox file counts toward
the batch disk budget once.

## Record analyst decisions

Find a random case ID in `manifest.jsonl`, then append a decision:

```bash
jq -r 'select(.status == "processed") | [.case_id, .risk_tier] | @tsv' \
  ./shadow-pilot/manifest.jsonl

lurescope shadow label ./shadow-pilot case-0123456789abcdef fraud \
  --reason confirmed_external
```

Labels are `fraud`, `benign`, or `uncertain`. Reason codes are:

- `confirmed_external` — verified through an independent trusted source;
- `known_legitimate` — matched to an authorized, known business communication;
- `insufficient_evidence` — the reviewer cannot decide safely;
- `policy_exception` — an organization-approved exception applies;
- `other` — none of the fixed categories fits.

There is no free-text field, reducing the chance that a reviewer copies message
content into the bundle. `analyst-labels.jsonl` is append-only: corrections add a
new event, and the latest decision for each case controls the report. The log is an
audit trail, not cryptographic authentication. Protect the directory with normal
access control and retention policy.

Rebuild the aggregate report at any time:

```bash
lurescope shadow report ./shadow-pilot
```

## Read the report correctly

`shadow-report.json` and `shadow-report.md` contain aggregate counts only—no case
IDs. They report:

- candidate, unique, duplicate, processed, and failed volume;
- high/review/low routing workload and mean model probability;
- frequency of deterministic evidence codes;
- eligible adversarial checks, evasions, and normalization recoveries;
- analyst-label coverage, revisions, confusion counts, recall, precision, and
  false-positive rate.

For performance metrics, `high` and `review` mean “routed”; `low` means “not routed.”
Unlabeled and `uncertain` cases are excluded from performance denominators. A pilot
with low label coverage or few fraud/benign decisions cannot support a deployment
claim. Define acceptance criteria, sampling, review protocol, and confidence
intervals before seeing the final result; use LureBench for corpus-level statistical
evaluation.

## Export minimized events

Every export is a local file transform. LureScope does not read credentials, call a
SIEM, or transmit an event.

```bash
# OCSF 1.8 Detection Finding JSON array
lurescope export ./shadow-pilot/manifest.jsonl \
  --labels ./shadow-pilot/analyst-labels.jsonl \
  --format ocsf-1.8 --out ./shadow-pilot/ocsf-1.8.json

# ECS 9.4 newline-delimited JSON
lurescope export ./shadow-pilot/manifest.jsonl \
  --labels ./shadow-pilot/analyst-labels.jsonl \
  --format ecs-9.4 --out ./shadow-pilot/ecs-9.4.ndjson

# STIX 2.1 bundle
lurescope export ./shadow-pilot/manifest.jsonl \
  --labels ./shadow-pilot/analyst-labels.jsonl \
  --format stix-2.1 --out ./shadow-pilot/stix-2.1.json
```

### Mapping boundaries

| Output | Mapping | Deliberate boundary |
|---|---|---|
| OCSF 1.8 | Findings category, Detection Finding class (`class_uid=2004`), Create activity (`type_uid=200401`) | LureScope-specific minimized fields stay under `unmapped.lurescope`; processing errors are excluded |
| ECS 9.4 | `event.kind`, email/intrusion-detection categories, observer and rule fields, plus `lurescope.*` | One NDJSON event per processed case; processing errors are excluded |
| STIX 2.1 | One producer Identity plus privacy-minimized Incident SDOs | Analyst-benign and low unlabeled cases are excluded; no Indicator is invented because original observables are deliberately absent |

An analyst `benign` decision suppresses alert status in OCSF/ECS. Confirmed `fraud`
can create a STIX Incident even when the original risk tier was low; otherwise STIX
includes unlabeled/uncertain high or review cases. These are documented application
mappings, not certification or endorsement by the standards organizations. Validate
against the receiving product's profile before production use.

Reference definitions:

- [OCSF 1.8 Detection Finding](https://schema.ocsf.io/1.8.0/classes/detection_finding)
- [Elastic Common Schema field reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference)
- [OASIS STIX 2.1 specification](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)

The original Splunk HEC, Microsoft Sentinel custom-log, and JSON-array transforms
remain available; see [Inbox to LureProof](INBOX_TO_LUREPROOF.md).

## Privacy and operational boundary

The manifest, proofs, and standards exports contain random case IDs, timestamps,
scores, thresholds, detector provenance, evidence codes, counts, routing actions,
and proof digests. They exclude source paths, subjects, bodies, addresses, message
IDs, URL values, attachment names, transformed lure text, and raw-message hashes.
The aggregate reports exclude case IDs too.

This is minimization, not anonymity. Rare timestamps, score combinations, evidence
codes, or organizational context can still identify an event. A salted LureProof
commitment prevents direct equality matching across independent proofs but can
confirm a guessed original message. Keep the bundle private, limit retention, do
not attach real exports to public issues, and obtain legal/privacy approval before
using employee or customer communications.

Shadow Inbox never connects to Microsoft 365, Google Workspace, IMAP, or a mail
gateway; never moves, deletes, quarantines, or marks a message; and never replaces
secure-email-gateway, sandbox, endpoint, authentication, reporting, and human-review
controls. A low result is not proof of safety.
