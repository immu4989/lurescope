# Scorecard corpus admission (unreleased)

The character and cross-model research CLIs validate the entire local input
before choosing a fraud cohort or constructing detectors/attacker generators.
A sample limit cannot hide an invalid trailing record. A filename is no longer
the only identifier of the data used: generated JSON and Markdown include a
`scorecard-cohort-v1` manifest. Historical scorecards and caches are unchanged.

## Preview the cohort without paid work

From the source checkout, with its reviewed dependencies installed:

```bash
python scripts/robustness_scorecard.py --validate-corpus
python scripts/llm_scorecard.py --data /path/to/corpus.jsonl \
  --limit 120 --phishing-cap 50 --validate-corpus
```

The flag prints only the input/selection manifest to standard output. It needs
no provider key, performs no model calls or cache access, and does not write
`--out-md`, `--out-json` or `--out-png` paths even when supplied. This is corpus
preflight, not validation of provider availability, caches, cost or model behavior.
Empty selected cohorts stop with an error. Remove the flag only when you intend
to run an evaluation; fresh cross-model observations may incur provider charges.

## Input contract and resource limits

Input is UTF-8 JSONL with LF or CRLF line endings. Blank lines and lines beginning
with `//` after ASCII whitespace are allowed. Each non-comment line must be an
object with a nonempty string `text` and an exact integer `label` of `0` or `1`.
Boolean, floating-point and string labels are not coerced or silently skipped.
Optional `id` and `typology` must be nonempty strings. Explicit known fraud
typologies require label 1; `benign` requires 0. Missing typology means `other`
for selection. Unknown typologies and extension metadata are allowed.

This is a lightweight research input contract, **not full Lure schema validation**.
Fields not used by the scorecard, such as `source`, are not required. Duplicate
JSON keys at any nesting level, nonstandard/non-finite numeric literals, invalid
UTF-8 and lone Unicode surrogates are rejected, including in extension metadata.
Benign and cap/limit-excluded records receive the same admission checks as selected
records. Errors identify the physical line, without echoing record text or keys.

Current bounds are 256 MiB per source, 32 MiB per physical line (including comments
and line endings), 100,000 records, and 100,000 JSON structure nodes per record.
The shared JSON preflight also caps nesting at 128 and unquoted numeric-token
length at 4,096 characters. These are admission limits, not a hard process-memory
or time guarantee. The source is read into a bounded byte buffer before parsing;
decoded records and retained lines require additional memory.

The reader requires a regular non-symlink file and rejects a directly symlinked
parent, observed file/path changes, oversized files and special files such as
FIFOs. Parent directories must remain trusted. This does not detect every ancestor
alias or provide an atomic filesystem snapshot. Copy a trusted Hub-cache symlink
to a regular local file before using this stricter research boundary. Ordinary
LureBench Hub loading retains its own documented symlink-compatible contract.

## Selection is explicit, deterministic and positional

- Character scorecard: filter label 1 in source order, then take `limit` if nonzero.
- Cross-model: group fraud by typology; retain the first `phishing_cap` phishing
  records in source order and all other fraud records; concatenate groups in
  lexicographic typology order; stable-sort by `id` (missing ID sorts as `""`);
  then take `limit` if nonzero. This preserves the historical selection policy.
- `limit=0` means all selected candidates. `phishing_cap=0` means no phishing,
  not unlimited phishing. Both must be nonnegative non-boolean integers.
- Duplicate IDs and duplicate text remain separate positional observations.
  The loader neither collapses nor silently deduplicates them. Keeping an
  occurrence does not establish that it is statistically independent.

Deterministic prefix/cap selection is **not random or population-representative**.
Source ordering and ID choices can change a limited cohort. Review sampling,
train/test leakage, label quality, duplicate weighting and operational relevance
separately. Strict parsing cannot establish those properties.

## Manifest and digest definition

`corpus` in a newly generated aggregate contains:

| Field | Meaning |
|---|---|
| `contract` | `scorecard-cohort-v1` |
| `source_sha256`, `source_bytes` | SHA-256 and length of the exact consumed file bytes |
| `record_count`, `fraud_count`, `benign_count` | Counts over all admitted non-comment records |
| `selected_count`, `selected_sha256` | Count and ordered occurrence commitment after selection |
| `selection.method` | `fraud-source-order-v1` or `fraud-typology-cap-id-order-v1` |
| `selection.limit`, `selection.phishing_cap` | Requested parameters; cap is null for source-order mode |

The source digest includes comments, blank lines, unknown fields, whitespace and
original line endings. Both parsing and hashing use the same consumed byte buffer,
not separate path opens. Replacement after that read does not change the data
already admitted; the digest describes consumed bytes, not a later file state.

For `selected_sha256`, initialize SHA-256 with ASCII `scorecard-cohort-v1` followed
by LF. For each selected occurrence in evaluation order, append its zero-based
ordinal among **all** non-comment records as an unsigned 8-byte big-endian integer,
then its raw physical line length as an unsigned 8-byte big-endian integer, then
the raw line bytes, including any original line ending. Empty selections hash only
the prefix. This framing commits order, multiplicity, source position and exact
record representation without ambiguous concatenation or JSON reserialization.

The manifest contains no paths, raw records, IDs or per-record hashes, but **is not
an anonymization mechanism**. Counts can disclose cohort properties, and unsalted
digests can confirm guessed/public inputs. Review the data owner's sharing policy
before publishing a manifest. SHA-256 is not a signature or proof of source
authenticity, label correctness, execution, model identity or detector performance.
PNGs are visual summaries, not self-verifying evidence; keep their JSON manifest.

The direct Python aggregation helpers accept caller-supplied observations and do
not automatically claim this file admission contract. A manifest copied onto an
arbitrary aggregate does not verify it. Outcome semantics remain described in
[the measurement contract](SCORECARD_MEASUREMENT.md); provider cache identity is
handled separately by the [versioned cache workflow](SCORECARD_CACHE.md).

## Reference and verification

[RFC 8259](https://www.rfc-editor.org/rfc/rfc8259.html) explains interoperability
problems with duplicate object names and permits parser resource limits. This
project chooses strict rejection and additional domain-specific label checks;
JSON syntax alone cannot decide whether a record belongs in a fraud cohort.
Offline tests cover malformed late records, ambiguity, bounded reads, stable
selection and independently constructed commitment bytes. No provider calls or
historical benchmark recomputation are required for these checks.
