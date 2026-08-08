# Real-world workflows

LureScope is useful when it helps someone make a safer decision, not when it only
produces another model score. Version 0.4 adds a privacy-first email-triage path
for individuals, help desks, and security teams.

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
head content ignored.

The output routes messages to `low`, `review`, or `high`. It intentionally does
not claim that a low result proves safety. CISA advises users to report suspicious
messages and verify requests through trusted channels; LureScope's recommended
actions preserve that human review step.

## 2. Triage a help-desk queue

Process a directory and emit newline-delimited JSON for a ticketing or analytics
pipeline:

```bash
lurescope triage ./reported-emails --recursive --json > triage-results.jsonl
```

One malformed message does not abort the batch. It produces an error object for
that source and a non-zero exit status, while valid messages still receive results.
No email content is sent to a model provider unless the operator explicitly
selects the key-gated `llm-judge`; the default bundled detector runs locally.

## 3. Add evidence to a SOC or SOAR workflow

The same operation is available over the local API:

```bash
curl -s http://127.0.0.1:8000/triage/email \
  -H 'content-type: application/json' \
  -d "$(jq -n --rawfile email suspicious.eml '{raw_email: $email}')"
```

The stable `schema_version`, evidence codes, risk tier, threshold provenance, URL
names, and attachment names are machine-readable. This makes the result suitable
for enrichment and routing. It is not advertised as OCSF-conformant yet: OCSF has
an Email Activity class and is appropriate for security-lake interoperability,
but claiming conformance requires a versioned mapping and schema validation.

## 4. Evaluate a proposed email control before deployment

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
