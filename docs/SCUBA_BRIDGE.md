# CISA SCuBA Evidence Bridge

The SCuBA Evidence Bridge joins two different kinds of evidence without overstating
either one:

- CISA ScubaGear reports Microsoft 365 configuration-policy results; and
- LureScope's pre-registered Shadow Inbox pilot measures observed email-control
  outcomes, statistical uncertainty, processing reliability, resilience, and analyst
  workload.

The bridge creates one private, internally bound evidence package for an assessor or
system owner. It does not connect to Microsoft 365, execute ScubaGear, reinterpret a
baseline, determine control satisfaction, accept risk, or grant an authorization to
operate.

> This capability is included beginning with tagged release `0.9.0`. Install it
> with `python -m pip install lurescope==0.9.0` or use a reviewed source checkout.

## Supported input

The importer accepts the consolidated `ScubaResults_<UUID>.json` structure emitted by
the tested ScubaGear `1.8.x` contract. It fails closed rather than guessing when the
contract changes. Validation requires:

- the exact top-level, metadata, summary, result-group, and control field allowlists;
- `Tool=ScubaGear`, `ProductSuite=Microsoft 365`, the known product mapping, canonical
  report and tenant UUIDs, and a timezone-bearing report timestamp;
- supported product/control ID relationships and unique control IDs;
- an official `github.com/cisagov/ScubaGear` result-group baseline URL whose
  release and product path exactly match the report's declared tool version;
- a recognized result and criticality for every control; and
- exact reconciliation of every reported summary category to underlying controls.

The command accepts only AAD, Defender, and Exchange Online into the derived email
evidence. Other assessed products are validated and reconciled but excluded from the
bridge output. A 32 MiB input limit, bounded arrays and strings, regular-file checks,
and symlink rejection constrain hostile or accidental input.

The official PowerShell JSON form may include a UTF-8 byte-order mark. Config-file
supplemental fields such as organization or unit names remain inside the `Raw`
provider payload; the importer accepts that bounded object but never traverses or
copies any of its values. Unknown fields in the consolidated report, metadata,
summary, result-group, or control contracts still fail closed.

## Run the bridge

First complete the pre-registration, pilot, independent labeling, and OSCAL setup in
the [Federal Email Assurance Profile guide](FEDERAL_EMAIL_ASSURANCE.md). Obtain the
consolidated JSON report through your organization's approved ScubaGear process, then:

```bash
lurescope assurance ingest-scuba ./ScubaResults_<UUID>.json \
  --bundle ./agency-email-pilot \
  --plan ./federal-email-plan \
  --out ./combined-email-assurance
```

The new output directory is mode `0700` and every artifact is mode `0600` on POSIX.
Existing output is never overwritten. Exit codes retain the Pilot Gate meaning:

| Exit | Meaning |
|---:|---|
| `0` | The registered Pilot Gate passed and the bridge was created |
| `1` | The Pilot Gate failed or had insufficient evidence; the reviewable bridge was still created |
| `2` | Invalid, inconsistent, unsafe, changed, or operationally unusable input |

SCuBA failures do not control the process exit code. They are imported configuration
observations and, for failing `Shall` results, candidate remediation records—not a
second deployment gate invented by LureScope.

## Output contract

| Artifact | Purpose |
|---|---|
| `pilot-plan.json` | Exact pre-registered pilot criteria |
| `assurance-profile.json` | Federal profile, boundaries, and plan bindings |
| `oscal-assessment-plan.json` | Registered NIST OSCAL Assessment Plan |
| `pilot-gate.json` | Aggregate statistical outcome |
| `scuba-evidence.json` | Strict, minimized SCuBA observations and reconciled counts |
| `oscal-assessment-results.json` | Combined `TEST` pilot and technical `EXAMINE` SCuBA observations; no findings |
| `oscal-poam-candidates.json` | Present only for failing `Shall` controls; candidate-only records |
| `combined-assurance.statement.json` | in-toto Statement binding every artifact by SHA-256 |
| `combined-assurance.dsse.json` | Optional ECDSA P-256 DSSE authentication envelope |

The Assessment Results and POA&M documents are tested offline against unmodified,
byte-locked official NIST OSCAL 1.2.2 schemas. LureScope also publishes strict Draft
2020-12 schemas for the [minimized evidence](../spec/scuba-evidence-v1.schema.json),
[in-toto statement](../spec/combined-assurance-statement-v1.schema.json), and
[DSSE envelope](../spec/combined-assurance-dsse-v1.schema.json).

The Assessment Results document retains the NIST controls selected by the
pre-registered LureScope Assessment Plan. It does not map any `MS.AAD`,
`MS.DEFENDER`, or `MS.EXO` source control ID to a NIST control. Such a crosswalk
requires a separately governed mapping and assessment methodology.

## Privacy boundary

`scuba-evidence.json` retains only:

- ScubaGear version, report timestamp, source-report SHA-256, and contract identity;
- selected product, control ID, result, and source criticality;
- reconciled aggregate counts; and
- explicit interpretation and privacy limitations.

It excludes display name, domain, tenant ID, report UUID, raw provider settings,
annotated failed policies, requirements, details, original details, comments, and
resolution dates. The source report is never copied into the output package.

This is minimization, not anonymization. Control results reveal security posture, and
the report digest can correlate copies of the same source. The schema therefore marks
the evidence `security_posture_sensitive` and `shareable_by_default: false`. Keep both
source and derived packages inside the approved evidence boundary.

## Candidate POA&M semantics

For each selected control whose exact source result is `Fail` and exact criticality is
`Shall`, LureScope creates a candidate OSCAL POA&M item linked to an imported
observation. It deliberately assigns no owner, deadline, milestone, risk, finding,
accepted-risk decision, or remediation commitment. A system owner must validate
applicability and disposition before moving any candidate into an operational POA&M.

## Authenticate and verify

An unsigned statement binds the package internally but does not prove who produced it.
For authenticated provenance, sign during creation with an externally controlled key:

```bash
# Development helper; production programs should use their approved key lifecycle.
lurescope keygen --private-out issuer.pem --public-out issuer.pub.pem

lurescope assurance ingest-scuba ./ScubaResults_<UUID>.json \
  --bundle ./agency-email-pilot --plan ./federal-email-plan \
  --out ./combined-email-assurance --signing-key issuer.pem

lurescope assurance verify-scuba ./combined-email-assurance \
  --public-key issuer.pub.pem --require-signature
```

Verification checks the exact private file set and permissions, statement subject
coverage and SHA-256 digests, profile/AP/plan/gate bindings, minimized evidence
semantics, source and outcome reconciliation, no-findings boundary, candidate POA&M
presence and count, exact DSSE payload bytes, key ID, and P-256 signature.

Without `--require-signature`, successful verification establishes package
self-consistency only. A public key must come through a trusted channel; a key stored
beside the package cannot establish independent identity.

## Test with synthetic data

The repository fixture is intentionally not operational data:

```bash
uv run --frozen --extra dev pytest -q tests/test_scuba.py
```

The tests disable network sockets, verify that sentinel tenant/raw/detail/comment
values cannot escape, reject contract drift and inconsistent counts, check private
permissions and no-overwrite behavior, authenticate DSSE, detect tampering, and
validate both generated OSCAL documents against official NIST schemas. See the
[synthetic fixture contract](../examples/scuba-bridge/README.md).

To compare successive verified bridge outputs, continue with the
[SCuBA Assurance Drift Ledger](SCUBA_DRIFT.md).

## Authoritative references

- [CISA ScubaGear repository](https://github.com/cisagov/ScubaGear)
- [CISA ScubaGear report documentation](https://github.com/cisagov/ScubaGear/blob/main/docs/execution/reports.md)
- [CISA ScubaGear configuration documentation](https://github.com/cisagov/ScubaGear/blob/main/docs/configuration/configuration.md)
- [NIST OSCAL 1.2.2 model reference](https://pages.nist.gov/OSCAL-Reference/models/v1.2.2/)
- [NIST OSCAL Assessment Results model](https://pages.nist.gov/OSCAL/learn/concepts/layer/assessment/assessment-results/)
- [NIST OSCAL Plan of Action and Milestones model](https://pages.nist.gov/OSCAL/learn/concepts/layer/assessment/poam/)
- [in-toto Attestation Framework](https://github.com/in-toto/attestation)
