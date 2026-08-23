# One-command operational pilot

The operational pilot is an installable, offline proof that LureScope can carry
one reviewed synthetic cohort through ingestion, deduplication, fixed-vocabulary
adjudication, a pre-registered statistical gate, signed LureEval evidence, NIST
OSCAL observations, and three SIEM formats.

It is a workflow conformance exercise—not a detector benchmark, agency
authorization package, compliance result, or deployment recommendation.

## Run and reverify

```bash
python -m pip install "lurescope==0.10.0"
lurescope pilot run --out ./lurescope-operational-pilot
lurescope pilot verify ./lurescope-operational-pilot
```

The run accepts no mailbox path, API key, provider credential, or destination
URL. It uses six byte-locked synthetic `.eml` files packaged in the wheel, removes
one exact duplicate, applies reviewed synthetic labels to five unique cases, and
requires all ten pre-registered Pilot Gate checks to pass.

Creation is atomic: work happens in a new private sibling directory, every
binding is reverified, and only then is the directory renamed to the requested
path. Existing outputs are never overwritten. On POSIX systems the directory is
mode `0700` and every artifact is mode `0600`.

## Evidence produced

| Artifact | Purpose | Important boundary |
|---|---|---|
| `pilot-plan.json` / `pilot-gate.json` | Pre-run criteria and exact statistical decision | A pass applies only to the synthetic cohort |
| `lureeval.dsse.json` / `lureeval-public.pem` | Signed, aggregate LureEval receipt | Ephemeral key authenticates this run, not an organization |
| `oscal-assessment-plan.json` | OSCAL 1.2.2 plan for CA-7, SI-4, and SI-8 evidence collection | Mapping is not a control assessment |
| `oscal-assessment-results.json` | Aggregate observations bound to the exact Pilot Gate | Contains no OSCAL findings and grants no ATO |
| `siem-splunk-hec.jsonl` | Local Splunk HEC-shaped events | File only; nothing is transmitted |
| `siem-sentinel.json` | Local Microsoft Sentinel-shaped records | File only; nothing is transmitted |
| `siem-ocsf-1.8.json` | Reviewed OCSF 1.8 Detection Findings | Contains opaque synthetic case IDs |
| `operational-pilot-receipt.json` | Digests, byte counts, statuses, privacy boundary, and limitations | Local integrity index, not a third-party attestation |

One Pilot Gate is created and then consumed read-only. Both the signed LureEval
receipt and OSCAL Assessment Results bind the SHA-256 digest of those exact gate
bytes. Reverification checks the plan, minimized manifest, append-only labels,
gate semantics, every fixed artifact digest, every LureProof, the LureEval
signature, OSCAL cross-bindings, SIEM renderings, permissions, fixture privacy
scan, and absence of persisted private-key material.

## Why the key is ephemeral

The synthetic workflow needs to prove that signing and trusted-key verification
work without asking a first-time user to manage secrets. The private P-256 key is
held in process memory and never written; only its public key is stored. This
shows byte-level authentication within the exercise. It does not establish an
agency, company, or person as the issuer.

For real evidence, use an organization-managed signing key, establish key
identity out of band, and follow the [LureEval operator guide](LUREEVAL.md).

## Move from synthetic proof to a real pilot

Do not reuse the synthetic thresholds or auto-apply its labels. For an authorized
real-world pilot:

1. obtain approval for a bounded mailbox export and retention plan;
2. pre-register organization-specific sampling, minimum class counts, error
   bounds, uncertainty, workload, and labeling protocol;
3. run `lurescope shadow run` over the approved export with no enforcement;
4. have qualified reviewers label every case using the fixed vocabulary;
5. evaluate the registered Pilot Gate and investigate any failure or insufficient
   evidence result;
6. create a receipt with an organization-managed signing key;
7. export OSCAL or SIEM files only to approved systems through existing operator
   controls; and
8. repeat on later cohorts to measure drift before making procurement or policy
   claims.

See [Federal Email Assurance](FEDERAL_EMAIL_ASSURANCE.md),
[Shadow Inbox](SHADOW_INBOX.md), and [Pilot Gate](PILOT_GATE.md) for the full
operational boundaries.
