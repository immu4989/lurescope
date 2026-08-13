# Inbox to LureProof

`lurescope inbox` turns a directory of user-reported RFC 5322 messages into an
operational case bundle without copying the messages into that bundle. Parsing,
scoring, deterministic attacks, normalization, proof creation, and optional
signing all run locally.

## Five-minute workflow

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .

lurescope inbox examples --recursive --out ./lurescope-cases
```

The command prints the source-to-case mapping to the local terminal and writes:

```text
lurescope-cases/
├── case-<random>.lureproof.json
├── manifest.jsonl
└── summary.json
```

The terminal is the only place the source path and case ID appear together.
Redirecting or centrally collecting terminal output can therefore retain local
filenames even though the case bundle does not.

The output directory is created with mode `0700`; files use `0600`. LureScope
refuses an existing output directory and never merges a new run into old cases.
Each email is capped at 5 MiB, the inbox defaults to at most 1,000 messages, and
the complete bounded input is capped at 64 MiB in memory. Discovery and size
checks finish before any message is read. One malformed message becomes a safe
error event while the rest continue.

## What the manifest carries

Each successful JSONL event contains:

- a random case ID and processing timestamp;
- risk tier and a machine-readable recommended action;
- detector, artifact digest, probability, threshold, and policy provenance;
- evidence *codes* plus URL and attachment counts;
- attack eligibility, evasion, and normalization-recovery counts;
- the proof filename, statement digest, artifact type, and signing-key IDs.

It intentionally excludes source paths, subjects, bodies, sender and recipient
addresses, message IDs, URL values, attachment names, and transformed lure text.
An error event contains only a random case ID, input order, timestamp, and error
class. The schemas are [inbox event v1](../spec/inbox-event-v1.schema.json) and
[inbox summary v1](../spec/inbox-summary-v1.schema.json).

This is privacy minimization, not anonymity. Counts, timestamps, detector output,
and evidence combinations can still be identifying. A LureProof salted commitment
prevents direct equality matching between independently generated proofs, but its
published salt still permits confirmation of a guessed original message.

## Authenticate the evidence

Generate a local ECDSA P-256 keypair once, protect the private key, and sign the
batch. A verifier-supplied nonce is optional but useful for a specific exercise:

```bash
lurescope keygen --private-out issuer.pem --public-out issuer.pub.pem
lurescope inbox ./reported-emails --recursive --out ./signed-cases \
  --signing-key issuer.pem --issuer "Example SOC" \
  --nonce "verifier-challenge-123"
```

Every successful case is then a DSSE envelope. Verify one against the trusted
public key:

```bash
lurescope verify ./signed-cases/case-<random>.lureproof.dsse.json \
  --public-key issuer.pub.pem --require-signature
```

Do not invent a nonce on behalf of a verifier: a nonce demonstrates freshness
only when the verifier supplied and tracks it.

## Splunk HEC

Create newline-delimited packets for Splunk's JSON event endpoint:

```bash
lurescope export ./lurescope-cases/manifest.jsonl \
  --format splunk-hec --out ./lurescope-cases/splunk-hec.jsonl
```

Each line has an `event` object plus `source=lurescope` and
`sourcetype=lurescope:inbox:v1`. Submit the file with your existing authenticated
HEC client and require it to act on non-success response codes. Splunk documents
the event envelope and endpoint in its
[HEC event-format guide](https://help.splunk.com/en/splunk-enterprise/get-data-in/get-started-with-getting-data-in/9.0/get-data-with-http-event-collector/format-events-for-http-event-collector).
The export command itself performs no network call and reads no HEC token.

## Microsoft Sentinel / Azure Monitor

Create a JSON array flattened to stable custom-log columns:

```bash
lurescope export ./lurescope-cases/manifest.jsonl \
  --format sentinel --out ./lurescope-cases/sentinel.json
```

Configure a Data Collection Rule stream whose columns match the generated keys,
then submit the array with the Azure Monitor Logs Ingestion API or official client
library. Microsoft requires the request body to be a JSON array matching the DCR
stream declaration; see the
[Logs Ingestion API overview](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview).
The export is named `sentinel` for the common destination, but transport occurs
through Azure Monitor and remains the operator's authenticated responsibility.

## Generic webhook or SOAR

Convert the JSONL stream into one conventional JSON array:

```bash
lurescope export ./lurescope-cases/manifest.jsonl \
  --format json-array --out ./lurescope-cases/events.json
```

Send `events.json` only to an authenticated endpoint you control. LureScope does
not ship a generic network sender because retry, authentication, TLS trust,
idempotency, and dead-letter behavior belong to the receiving organization.

## Safety boundary

Routing remains decision support. A low result is not proof of safety, header
authentication fields are evidence only when a trusted gateway supplied them,
and LureScope never opens attachments, dereferences links, resolves domains, or
deletes messages. Keep secure-email-gateway, sandboxing, endpoint protection,
reporting, and analyst-review controls in place.
