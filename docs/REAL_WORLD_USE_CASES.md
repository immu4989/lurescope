# Real-world workflows

LureScope is useful when it helps someone make a safer decision, not when it only
produces another model score. Its privacy-first email workflows support individuals,
help desks, and security teams without making autonomous enforcement claims.

## 1. Inspect a suspicious email without opening its contents

Save the message as `.eml`, then use the web lab's **Choose .eml file** action or:

```bash
lurescope triage suspicious-message.eml
```

LureScope reports two evidence channels separately:

- the fraud-content model's probability, threshold, and contributing terms;
- deterministic context such as a mismatched Reply-To domain, explicit
  reported SPF/DKIM/DMARC failures, punycode or IP-address links, and risky
  attachment filename extensions. Authentication results are review evidence—not
  proof—until the deployment identifies which receiving gateway is trusted.

It does not visit links, resolve domains, extract archives, save attachments, or
execute active content. HTML is converted to visible text with script, style, and
head content ignored. Inline-image plus QR/scan language and image-dominant HTML
can trigger a review cue, but LureScope does not decode image pixels.

The output routes messages to `low`, `review`, or `high`. It intentionally does
not claim that a low result proves safety. CISA advises users to report suspicious
messages and verify requests through trusted channels; LureScope's recommended
actions preserve that human review step.

## 2. Triage a help-desk queue

For a quick local view, process a directory and emit newline-delimited JSON:

```bash
lurescope triage ./reported-emails --recursive --json > triage-results.jsonl
```

One malformed message does not abort the batch. It produces an error object for
that source and a non-zero exit status, while valid messages still receive results.
For an operational evidence bundle, use the dedicated inbox workflow:

```bash
lurescope inbox ./reported-emails --recursive --out ./lurescope-cases
```

It emits random case IDs, one LureProof per successfully processed message, a
privacy-minimized manifest, and a summary. Source filenames, subjects, addresses,
message IDs, URL values, attachment names, and message content are not persisted
in that bundle. One malformed message does not suppress valid cases. No email
content is sent to a model provider; the LureProof reference producer accepts
deterministic local detectors only. See [Inbox to LureProof](INBOX_TO_LUREPROOF.md).

## 3. Measure a mailbox export before enforcement

Use Shadow Inbox to evaluate approved `.eml`, Maildir, or mbox exports without a
live mailbox connection:

```bash
# Verify the complete software path with locked synthetic data first.
uv run --frozen --extra dev python scripts/run_golden_pilot.py \
  --out ./golden-shadow-pilot
```

Then create separately approved criteria for the representative organizational
sample:

```bash
lurescope shadow plan --out ./pilot-plan.json --plan-id approved-pilot \
  --min-processed 400 --min-fraud-labels 100 --min-benign-labels 300 \
  --max-uncertain-rate 0.02 --max-failure-rate 0.01 \
  --min-recall-lower 0.90 --max-fpr-upper 0.01 \
  --max-routed-rate 0.25 --max-routed-count 100
lurescope shadow run /approved/export --recursive --threshold 0.5 \
  --out ./shadow-pilot
```

The pilot deduplicates conservatively, creates minimized case evidence, records
fixed-vocabulary analyst labels, and generates aggregate routing, false-positive,
workload, and resilience metrics. After complete independent review, `lurescope
shadow gate` emits a fail-closed decision with exact one-sided confidence bounds.
See [Pilot Gate](PILOT_GATE.md) for pre-registration and interpretation, and
[Shadow Inbox](SHADOW_INBOX.md) for the privacy boundary and OCSF/ECS/STIX mappings.

## 4. Produce reviewable federal assessment evidence

An agency, integrator, or email-security supplier can bind the approved Pilot Gate
criteria to an operator-controlled OSCAL System Security Plan and export aggregate
OSCAL 1.2.2 Assessment Results:

```bash
lurescope assurance init --out ./federal-email-plan \
  --plan-id agency-email-pilot \
  --ssp-href urn:uuid:11111111-1111-4111-8111-111111111111 \
  --min-processed 400 --min-fraud-labels 100 --min-benign-labels 300 \
  --max-uncertain-rate 0.02 --max-failure-rate 0.01 \
  --min-recall-lower 0.90 --max-fpr-upper 0.01 \
  --max-routed-rate 0.25 --max-routed-count 100
lurescope assurance export ./shadow-pilot --plan ./federal-email-plan
```

This gives system owners and assessors portable observations about evidence sufficiency,
routing performance, processing failures, adversarial resilience, and analyst workload.
It can reduce manual evidence translation and vendor lock-in without exposing mailbox
content. It does not decide control satisfaction, produce a complete authorization
package, or replace qualified assessors and authorizing officials. See
[Federal Email Assurance Profile](FEDERAL_EMAIL_ASSURANCE.md).

## 5. Add evidence to a SOC or SOAR workflow

The same operation is available over the local API:

```bash
curl -s http://127.0.0.1:8000/triage/email \
  -H 'content-type: application/json' \
  -d "$(jq -n --rawfile email suspicious.eml '{raw_email: $email}')"
```

The stable `schema_version`, evidence codes, risk tier, threshold provenance, URL
values, and attachment names are machine-readable in the direct triage response.
The privacy-minimized inbox manifest excludes URL values and attachment names.
Offline export mappings are available for OCSF 1.8 Detection Finding, ECS 9.4,
STIX 2.1, Splunk HEC, and Microsoft Sentinel. These documented application
mappings are not standards certification.

## 6. Evaluate a proposed email control before deployment

Use LureScope for a single-message failure investigation, then LureBench for the
corpus-level claim:

1. Reproduce the miss in LureScope.
2. Apply deterministic and semantic attacks.
3. Verify whether normalization recovers the message.
4. Implement the detector or defense in LureBench.
5. Measure clean performance, false positives, calibration, multilingual behavior,
   and adversarial robustness with confidence intervals.

That sequence prevents an appealing anecdote from being presented as a validated
security control.

## Safety boundary

LureScope is decision support, not an autonomous deletion or blocking system.
Header evidence can be missing, forged, or injected before a message reaches the
trusted gateway; benign mailing systems can legitimately use a different Reply-To
domain; and filename extensions do not establish file contents. Keep existing
secure-email-gateway, sandboxing, authentication, and human reporting controls in
place.

References:

- [CISA phishing guidance](https://www.cisa.gov/sites/default/files/2023-10/Phishing%20Guidance%20-%20Stopping%20the%20Attack%20Cycle%20at%20Phase%20One_508c.pdf)
- [OCSF schema](https://github.com/ocsf/ocsf-schema)
- [AWS Security Lake and OCSF](https://docs.aws.amazon.com/security-lake/latest/userguide/open-cybersecurity-schema-framework.html)
