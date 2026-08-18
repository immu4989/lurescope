# Federal Email Assurance Profile

LureScope can turn a pre-registered, independently labeled Shadow Inbox pilot into
machine-readable NIST OSCAL 1.2.2 Assessment Plan and Assessment Results artifacts.
The purpose is to help an agency or supplier answer a narrow, useful question:

> Did this exact email control collect enough evidence to meet the acceptance and
> analyst-capacity limits approved before the pilot?

This workflow is local, no-enforcement, and aggregate-only. It does not connect to a
mailbox, send message content to a provider, or decide that a NIST control is satisfied.

## What the profile adds

The `federal-email-assurance-v1` profile binds four pieces of evidence:

| Artifact | Purpose |
|---|---|
| `pilot-plan.json` | Immutable detector, threshold, sample, performance, and workload criteria |
| `oscal-assessment-plan.json` | OSCAL AP that imports the operator's System Security Plan (SSP) by portable identifier |
| `assurance-profile.json` | Strict profile, privacy boundary, limitations, and SHA-256 cross-artifact bindings |
| `oscal-assessment-results.json` | Aggregate OSCAL AR observations for every Pilot Gate check; no findings or control verdicts |

The AP and AR are tested against the unmodified official NIST OSCAL 1.2.2 JSON
Schemas. The official schemas are byte-locked in the test suite by published source
URL and SHA-256 digest. LureScope's smaller profile schema is additionally fail-closed:
unknown fields and unsupported claims are rejected.

## 1. Establish the authorization boundary

Before using the command, the system owner and security team must:

- identify the system's operator-controlled OSCAL SSP with a stable `urn:` or
  credential-free `https:` URI;
- approve the sampling frame, review protocol, acceptance limits, owner, and dates;
- define who establishes ground truth and how reviewers remain blind to model output;
- specify what a pass permits, who accepts residual risk, and how rollback works; and
- keep raw email, source-to-case mappings, and reviewer records in the approved
  restricted system.

LureScope references the SSP. It does not create, retrieve, validate, or approve it.
A URN is only an identifier unless the organization maintains a trusted resolution and
registration process.

## 2. Create the plan before the run

The values below demonstrate the interface; they are not universal federal deployment
criteria. The organization must choose them from its own costs, prevalence, capacity,
sampling design, and risk tolerance.

```bash
lurescope assurance init --out ./federal-email-plan \
  --plan-id agency-email-pilot-2026q3 \
  --ssp-href urn:uuid:11111111-1111-4111-8111-111111111111 \
  --detector tfidf-logreg --threshold 0.5 \
  --min-processed 400 \
  --min-fraud-labels 100 --min-benign-labels 300 \
  --max-uncertain-rate 0.02 --max-failure-rate 0.01 \
  --min-recall-lower 0.90 --max-fpr-upper 0.01 \
  --max-routed-rate 0.25 --max-routed-count 100 \
  --confidence 0.95
```

The command creates a new mode-`0700` directory containing exactly three mode-`0600`
files, refuses overwrite, and prints the SHA-256 digest of each artifact. Register the
three files or printed digests in an append-only ticket, signed approval,
version-controlled protocol, or transparency log before processing the sample. A local
timestamp and digest provide integrity binding, not identity or independent proof of
when approval occurred.

## 3. Run and review the approved sample

Run the exact registered detector and threshold:

```bash
lurescope shadow run /approved/mail-export --recursive \
  --detector tfidf-logreg --threshold 0.5 \
  --out ./agency-email-pilot
```

Record one fixed-vocabulary decision for every processed case. Reviewers should not see
the model score or route until ground truth is final:

```bash
# Replace this example with a case_id from manifest.jsonl.
lurescope shadow label ./agency-email-pilot case-0123456789abcdef fraud \
  --reason confirmed_external
```

The repository's locked six-message Golden Pilot verifies that this software path works
offline. Its synthetic sample and permissive thresholds are not deployment evidence.

## 4. Export OSCAL observations

```bash
lurescope assurance export ./agency-email-pilot \
  --plan ./federal-email-plan
```

Exit codes are automation-safe:

| Exit | Meaning |
|---:|---|
| `0` | Every evidence, performance, and workload check passed |
| `1` | Evidence was insufficient or at least one registered criterion failed |
| `2` | Artifact tampering, rebinding, control mismatch, unsafe path, or operational error |

The export refreshes Pilot Gate, copies the exact registered AP and profile into the
private bundle, and writes `oscal-assessment-results.json`. Each gate check becomes an
OSCAL `observation` using the `TEST` method. The exporter intentionally creates no
OSCAL `finding`, attestation, risk acceptance, or control-satisfaction status.

Re-running after an approved label correction refreshes the gate and results. Their
content-bound UUIDs and SHA-256 properties change with the evidence. Exporting against
a bundle already bound to a different plan or profile fails closed.

## NIST SP 800-53 relationship

The profile selects three NIST SP 800-53 Rev. 5 controls only as evidence-relevant:

| Control | Narrow relationship to this workflow |
|---|---|
| CA-7, Continuous Monitoring | Pre-registered routing, error, workload, and resilience measurements |
| SI-4, System Monitoring | Aggregate detection, analyst-review, failure, and adversarial observations |
| SI-8, Spam Protection | Observed suspicious-email routing under a named detector and threshold |

These mappings are not assessment objectives and do not cover every part of any
control. The agency's approved control implementation, SSP, assessment procedures,
assessor independence, inherited controls, and authorization process remain authoritative.

## Federal policy relationship

The workflow can support evidence collection for fit-for-purpose evaluation, ongoing
performance monitoring, reuse, open machine-readable formats, and human risk acceptance.
Those properties are useful when applying OMB M-25-21 and M-25-22 to an AI-enabled email
control. They do not establish that every requirement in either memorandum applies or
has been met.

The OSCAL results are assessment evidence, not operational event logs. LureScope's
offline OCSF, ECS, Splunk, and Sentinel transforms can support integration design, but
they do not by themselves meet M-26-14 requirements for log source coverage, trusted
timestamps, access, searchability, retention, or agency SOC availability.

Software supply-chain review under M-26-05 and accessibility evaluation under Section
508 are separate workstreams. A federal deployer must independently review the release
attestations, SBOM, dependencies, deployment boundary, support model, web and non-web
accessibility, and agency-specific requirements. LureScope does not currently publish a
VPAT or Accessibility Conformance Report.

## Security and privacy boundary

- Results exclude message content, filenames, addresses, URLs, attachment names, and
  random case identifiers.
- The workflow makes no network connection; a test replaces the process socket and
  fails on any connection attempt.
- Local files are private on POSIX systems and existing plan directories are never
  overwritten.
- SHA-256 detects changed bytes but does not authenticate who created or approved them.
  Use the existing DSSE signing workflow for per-message LureProof authentication and an
  organization-approved signing or registration service for the aggregate package.
- LureScope never quarantines, deletes, forwards, or delivers email and never initiates
  or approves a payment.

## Explicit non-claims

This profile is not FedRAMP authorization, FISMA compliance, a Security Assessment
Report, an Authority to Operate, CISA or NIST endorsement, a Section 508 conformance
statement, or approval for autonomous enforcement. It does not inspect tenant settings
against CISA SCuBA baselines. A representative sample, trustworthy labels, qualified
assessors, and a human authorizing official remain necessary.

## Authoritative references

- [NIST OSCAL 1.2.2 model reference](https://pages.nist.gov/OSCAL-Reference/models/v1.2.2/)
- [NIST OSCAL Assessment Results model](https://pages.nist.gov/OSCAL/learn/concepts/layer/assessment/assessment-results/)
- [NIST SP 800-53 Rev. 5.1 OSCAL-derived publication](https://csrc.nist.gov/CSRC/media/Projects/risk-management/800-53%20Downloads/800-53r5/SP_800-53_v5_1-derived-OSCAL.pdf)
- [CISA, NSA, FBI, and MS-ISAC phishing guidance](https://www.cisa.gov/sites/default/files/2023-10/Phishing%20Guidance%20-%20Stopping%20the%20Attack%20Cycle%20at%20Phase%20One_508c.pdf)
- [OMB M-25-21](https://www.whitehouse.gov/wp-content/uploads/2025/02/M-25-21-Accelerating-Federal-Use-of-AI-through-Innovation-Governance-and-Public-Trust.pdf)
- [OMB M-25-22](https://www.whitehouse.gov/wp-content/uploads/2025/02/M-25-22-Driving-Efficient-Acquisition-of-Artificial-Intelligence-in-Government.pdf)
- [OMB M-26-05](https://www.whitehouse.gov/wp-content/uploads/2026/01/M-26-05-Adopting-a-Risk-based-Approach-to-Software-and-Hardware-Security.pdf)
- [OMB M-26-14](https://www.whitehouse.gov/wp-content/uploads/2026/05/M-26-14-Ensuring-Effective-and-Efficient-Agency-Logging-and-Network-Visibility-to-Defend-Against-Evolving-Cyber-Threats.pdf)
- [GSA Section 508 software and website guidance](https://www.section508.gov/develop/software-websites/)
