# LureProof 0.2

LureProof is an experimental open evidence format for one operational question:
**what did this fraud control decide, and did that decision survive basic
adversarial manipulation?**

It is not a new phishing-alert format. It is a narrowly scoped appraisal artifact:
an [in-toto Statement](https://github.com/in-toto/attestation) carrying strict
fraud-control semantics, optionally authenticated in a
[DSSE envelope](https://github.com/secure-systems-lab/dsse).

## Fast path

Create schema-valid evidence without establishing an issuer identity:

```bash
lurescope proof suspicious.eml -o suspicious.lureproof.json
lurescope verify suspicious.lureproof.json
# valid: true; authenticated: false
```

Create an authenticated artifact with an organization-controlled P-256 key:

```bash
lurescope keygen --private-out issuer.pem --public-out issuer.pub.pem

lurescope proof suspicious.eml \
  --issuer "Example SOC" \
  --nonce "challenge-from-verifier-2026-08-08" \
  --signing-key issuer.pem \
  --out suspicious.lureproof.dsse.json

lurescope verify suspicious.lureproof.dsse.json \
  --public-key issuer.pub.pem \
  --require-signature
# valid: true; authenticated: true
```

The private key is created with mode `0600`, is never embedded in a proof, and is
never accepted through the HTTP API. Production deployments should use their
existing KMS/HSM and certificate policy rather than treating the local key helper
as a complete PKI.

## Security semantics

### Private output publication

In the unreleased source branch, `lurescope proof --out` requires an absent
destination in an existing directory. Files, directories, and symlinks, including
dangling symlinks, are refused before input reading or scoring. Choose a new
filename for each result; an existing output is never silently replaced, even
when another writer creates it after the initial check. This also prevents using
the input email as its own output path.

The Python `write_proof(path, proof)` helper validates the serialized artifact,
including its 2 MiB output limit, before creating a temporary file beside the
destination. The staged file has owner-only POSIX permissions (mode `0600`,
subject to a more restrictive umask). After a complete write and fsync, the
writer publishes it using a hard link and removes the temporary name. Python's
[`os.link`](https://docs.python.org/3/library/os.html#os.link) provides the hard-link
operation; filesystems without that support fail rather than falling back to an
overwriting or partially visible destination write.

Trust all parent directories; the immediate parent may not be a symlink. This
does not protect against hostile parent-directory replacement, prove issuer
identity, or guarantee durability after power loss. Windows access controls need
separate review; POSIX mode checks do not establish a Windows ACL policy.

An error before publication leaves no new destination, and cleanup is attempted
for temporary files. If cleanup fails after publication, the error explicitly
says the proof was published: inspect and verify the complete destination before
retrying. A process crash can leave a private temporary file; review it locally
before cleanup. These guarantees apply to `write_proof` and the standalone proof
CLI, not every repository output writer or an HTTP client's download behavior.

### Original email bytes in the web lab

The unreleased API-backed web lab reads `.eml` files as bytes and submits
`raw_email_base64` to both `/triage/email` and `/proof/email`. These endpoints
accept exactly one non-null representation: canonical base64 for original bytes,
or legacy `raw_email` text encoded as UTF-8. Both are bounded to 5 MiB decoded.
Use the byte representation for saved mail, especially non-UTF-8 headers/bodies
or binary content. Base64 is transport encoding, not encryption or redaction.

Older browser versions used UTF-8 text decoding, which could replace invalid
sequences before hashing. Existing proofs still bind the bytes actually submitted,
not necessarily the original uploaded file. They must not be relabeled as byte-exact
file evidence. Browser-only preview now rejects invalid UTF-8 and directs the
operator to the local API; it still does not create strict proofs itself.

### Authentication boundaries

The unsigned form establishes only that a statement matches LureProof's strict
schema and internal invariants. Anyone can create or replace it.

The signed form authenticates the exact statement bytes and DSSE payload type
against an externally trusted ECDSA P-256 public key. DSSE's pre-authentication
encoding binds the media type and avoids making JSON canonicalization part of the
security boundary. The verifier rejects malformed envelopes, unknown fields,
wrong keys, altered payloads, contradictory flags, invalid counters, and missing
required attacks.

An `issuer` label is meaningful only after signature authentication. A verifier-
supplied `nonce` can bind a proof to a challenge and reduce replay risk; the
relying party must still compare it to the nonce it issued. The timestamp is a
signed claim, not independently trusted time.

## Privacy profiles

Both profiles omit body, subject, addresses, message ID, URL values, attachment
names, model signal words, and transformed lure text.

| Profile | Subject identifier | Trade-off |
|---|---|---|
| `salted-commitment` (default) | `SHA-256(random 32-byte salt || raw email)` | Prevents direct subject-hash matching across separately generated proofs; other values may still fingerprint an artifact, and a party that can guess the entire message can test the commitment because the salt is public. |
| `correlatable` (opt-in) | Raw email SHA-256 | Enables incident deduplication and evidence custody, but links identical artifacts across organizations. |

Use `--privacy correlatable` only where that linkage is intentional. Neither
profile makes a weak or predictable message impossible to guess.

## Recorded evidence

- detector name and bundled-model SHA-256;
- LureScope, LureBench, Python, and scikit-learn versions;
- score, threshold, threshold source, and validated policy ID when configured;
- parser identity, input length, scored character count, and truncation status;
- context-evidence codes and URL/attachment counts without identifying values;
- ordered outcomes for homoglyph, leet, zero-width, and whitespace attacks;
- whether normalization recovered each evasion;
- optional signed issuer and verifier challenge;
- explicit limitations and non-conformance framework mappings.

`evidence_codes` lists each observed category once, in first-seen order; it is
not a histogram of findings. Repeated link or attachment cues remain separate
in local triage details. The proof retains the unique extracted URL count and
collected filename count without exposing their values. This projection does
not change scores or risk routing and does not imply attachments were scanned.

The reference producer deliberately accepts only the two deterministic local
detectors. It never incurs provider charges or records a nondeterministic LLM run
as reproducible evidence.

## Schemas and API

- [`lureproof.schema.json`](../spec/lureproof.schema.json): strict in-toto Statement
- [`lureproof-dsse.schema.json`](../spec/lureproof-dsse.schema.json): DSSE envelope
- `POST /proof/email`: create an unsigned statement for download or later signing
- `POST /proof/verify`: validate and optionally authenticate against supplied
  public-key PEM

The HTTP API deliberately does not load a private key or accept one through a
request. This prevents a public deployment from becoming an unauthenticated
organizational signing oracle. Sign reviewed statements through the CLI or an
access-controlled KMS/HSM integration. The endpoint defaults to
`salted-commitment`.

## Relationship to existing work

LureProof complements established formats instead of replacing them:

| Existing work | What it represents | LureProof's narrower role |
|---|---|---|
| [IETF ARF (RFC 5965)](https://www.rfc-editor.org/rfc/rfc5965) | Email abuse feedback that normally encloses the original message or headers | Minimized fraud-control appraisal |
| [STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html) / [MISP](https://github.com/MISP/misp-objects) | Threat objects, observables, indicators, and forensic evidence | Decision and adversarial behavior at a named threshold |
| [OCSF](https://github.com/ocsf/ocsf-schema) | Normalized security events | Portable appraisal evidence rather than an event |
| [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) | Risk-management and TEVV guidance | A concrete, repeatable measurement artifact |
| [in-toto](https://github.com/in-toto/attestation) / [DSSE](https://github.com/secure-systems-lab/dsse) | General statement and authentication envelopes | Fraud-control-specific predicate semantics |
| [IETF EAT (RFC 9711)](https://www.rfc-editor.org/rfc/rfc9711) | Attested claims about entities and devices | Software appraisal of one communication artifact |

Our dated landscape review found these adjacent systems, but no open predicate
combining minimized message commitment, decision-policy provenance, and
per-message attack/defense outcomes. This is a bounded observation—not an
unprovable “first ever” claim.

## Public value and limitations

LureProof can support SOC case handoffs, regulator or auditor evidence requests,
vendor evaluations, cross-agency exercises, critical-infrastructure drills, and
privacy-conscious research aggregation. It does not prove that a producer ran
honest code, establish legal chain of custody by itself, certify a model, replace
ARF/STIX/OCSF, or claim endorsement by NIST, MITRE, IETF, OASIS, CISA, or any
government agency.
