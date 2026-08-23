# SCuBA Assurance Drift Ledger

The SCuBA Assurance Drift Ledger turns a sequence of independently trusted
Combined Email Assurance bundles into privacy-minimized, tamper-evident change
evidence. It is designed for scheduled assessments and continuous monitoring,
where the operational question is not only “what failed?” but “what changed since
the last accepted assessment?”

This feature is included beginning with tagged release `0.9.0`.

## What the ledger does

For every selected AAD, Defender, and Exchange Online control, the ledger records:

- the previous and current ScubaGear result and source criticality;
- a deterministic transition class;
- a candidate POA&M lifecycle label; and
- the product and SCuBA control identifier.

It separately records whether the aggregate LureScope Pilot Gate verdict changed.
It does not combine a configuration transition and a pilot outcome into a causal
claim.

Each package contains:

| File | Purpose |
|---|---|
| `before-scuba-evidence.json` | Canonical minimized earlier snapshot |
| `after-scuba-evidence.json` | Canonical minimized later snapshot |
| `assurance-drift.json` | Strict machine-readable comparison |
| `assurance-drift.md` | Human review report |
| `assurance-drift.html` | Standalone accessible review report |
| `oscal-assessment-results.json` | OSCAL 1.2.2 observations, never findings |
| `assurance-drift.statement.json` | in-toto Statement binding all six artifacts |
| `assurance-drift.dsse.json` | Optional exact-payload P-256 DSSE envelope |

Output directories and files are private on POSIX systems. Existing output paths
are never overwritten.

## Compatibility gate

LureScope refuses a comparison unless both source bundles have:

1. the same supported ScubaGear consolidated-report contract;
2. the same exact ScubaGear release and version-bound official baseline identity;
3. the same selected email-product scope;
4. the same registered LureScope assurance profile and OSCAL Assessment Plan; and
5. strictly increasing source-report timestamps.

The ledger generation timestamp must not precede the later source report. This
requires trustworthy synchronized clocks in the assessment and ledger environments.

The control-set digest is recorded for each side. Controls may be added or removed
within an otherwise compatible comparison, but a different release is never
silently treated as tenant drift. Cross-release migration needs an explicit future
mapping contract and is not supported by v1.

Before ingestion, the SCuBA bridge also requires every result-group reference to
point to the official `cisagov/ScubaGear` baseline path for the report's declared
release. Arbitrary or cross-version baseline links fail closed.

## Transition semantics

The classifier intentionally avoids inventing a total risk ordering for
`Warning`, `Omitted`, manual, incorrect, and error states.

| Before | After | Transition |
|---|---|---|
| absent | present | `added` |
| present | absent | `removed` |
| identical result and criticality | identical | `unchanged` |
| `Pass` | `Fail` at the same criticality | `regressed` |
| `Fail` | `Pass` at the same criticality | `improved` |
| another non-fail state | `Fail` at the same criticality | `newly_failing` |
| criticality changed or any other result change | — | `non_comparable` |

`non_comparable` means a human must interpret the source evidence. It does not mean
neutral, safe, or acceptable.

A candidate is narrowly defined exactly as in the SCuBA bridge: source result
`Fail` and source criticality `Shall`.

| Previous candidate | Current candidate | Lifecycle label |
|---|---|---|
| no | yes | `new_candidate` |
| yes | yes | `persistent_candidate` |
| yes | no | `no_longer_observed` |
| no | no | `not_candidate` |

`no_longer_observed` is deliberately not called “remediated.” Configuration drift,
tool behavior, approved omissions, evidence errors, and other causes require human
assessment. These labels are triage aids, not an approved POA&M lifecycle.

## Create the first entry

Create and verify the two source bundles using the
[SCuBA Evidence Bridge](SCUBA_BRIDGE.md), then run:

```bash
lurescope assurance drift ./combined-2026-07 ./combined-2026-08 \
  --out ./drift-2026-08
lurescope assurance verify-drift ./drift-2026-08 \
  --before ./combined-2026-07 --after ./combined-2026-08
```

The source directories are optional during ordinary package verification because
the package carries both minimized snapshots. Supplying `--before` and `--after`
adds semantic reverification against the complete originals and their combined
statement bindings.

## Authenticate sources and the new entry

Use a trusted public key to require both source bundles to authenticate, and a
private key to authenticate the new ledger statement:

```bash
lurescope assurance drift ./combined-2026-07 ./combined-2026-08 \
  --source-public-key source.pub.pem --require-source-signatures \
  --signing-key ledger.pem --out ./drift-2026-08

lurescope assurance verify-drift ./drift-2026-08 \
  --public-key ledger.pub.pem --require-signature \
  --before ./combined-2026-07 --after ./combined-2026-08 \
  --source-public-key source.pub.pem --require-source-signatures
```

SHA-256 bindings detect modification. Only a signature checked against an
independently trusted public key authenticates who made the statement.

When the source signing key rotated between assessments, omit the shared
`--source-public-key` and provide both
`--before-source-public-key old-source.pub.pem` and
`--after-source-public-key new-source.pub.pem`. The same per-source options are
available on `verify-drift`.

## Extend and verify the chain

The predecessor's `after` source must be byte-identical in identity to the new
entry's `before` source. The new statement binds the predecessor statement digest:

```bash
lurescope assurance drift ./combined-2026-08 ./combined-2026-09 \
  --previous-drift ./drift-2026-08 \
  --signing-key ledger.pem --out ./drift-2026-09

lurescope assurance verify-drift ./drift-2026-09 \
  --public-key ledger.pub.pem --require-signature \
  --previous-drift ./drift-2026-08 \
  --previous-public-key ledger.pub.pem --require-chain
```

`chain_bound` says the current statement names a predecessor digest.
`chain_verified` says the supplied predecessor matches that digest and ends at the
current entry's starting source. Verify older entries recursively according to the
organization's retention and trust policy.

## Scheduled operation

A safe scheduled workflow should:

1. run ScubaGear using organization-approved unattended authentication;
2. retain and protect the original ScubaGear report under the organization's
   evidence policy;
3. create and authenticate a new Combined Email Assurance bundle;
4. compare it with the last accepted source bundle;
5. verify the new drift package and predecessor chain;
6. alert only on organization-defined transition or candidate-lifecycle classes;
7. require a human to interpret `non_comparable` and `no_longer_observed`; and
8. move accepted evidence into access-controlled immutable storage.

LureScope performs no network call in the drift path. It does not schedule or run
ScubaGear, query Microsoft 365, approve an alert, or provide immutable storage.

## Privacy and decision boundary

The source snapshots retain only product, control ID, result, criticality, source
release/timestamp, cryptographic bindings, summaries, and explicit limitations.
Tenant IDs, domains, organization names, raw provider settings, requirements,
details, comments, remediation annotations, message content, and case identifiers
are excluded.

The remaining output exposes security posture and is **not shareable by default**.
Treat it as controlled assessment evidence.

The ledger may support an organization's continuous-monitoring process. It does
not by itself satisfy federal event-logging, incident-response, authorization,
control-assessment, BOD, or records-retention requirements. OSCAL output contains
observations only, has no findings, and declares that no SCuBA-to-NIST control
crosswalk is present.

LureScope is an independent open-source project. CISA and NIST do not endorse or
certify this bridge or ledger.

## Authoritative references

- [CISA ScubaGear execution guidance](https://github.com/cisagov/ScubaGear/blob/main/docs/execution/execution.md)
- [CISA ScubaGear report contract](https://github.com/cisagov/ScubaGear/blob/main/docs/execution/reports.md)
- [CISA ScubaGear cached execution](https://github.com/cisagov/ScubaGear/blob/main/docs/execution/scubacached.md)
- [NIST SP 800-137, Information Security Continuous Monitoring](https://csrc.nist.gov/pubs/sp/800/137/final)
- [NIST OSCAL Assessment Results model](https://pages.nist.gov/OSCAL/learn/concepts/layer/assessment/assessment-results/)
- [in-toto Attestation Framework](https://github.com/in-toto/attestation)
