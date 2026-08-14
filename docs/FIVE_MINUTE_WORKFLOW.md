# Five-minute reported-email workflow

This walkthrough starts from the public PyPI package and ends with local triage,
a content-minimized evidence bundle, and transport-ready Splunk and Microsoft
Sentinel records. It does not contact an LLM provider, visit links, open
attachments, or send the sample email anywhere.

## 1. Install the released package

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install lurescope
lurescope --help
```

On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1`.

## 2. Save a defanged training message

Use a synthetic message for this walkthrough. For a real report, export the
original message as RFC 5322 `.eml` from the mail client instead of copying only
the visible body.

```bash
mkdir -p reported-emails
cat > reported-emails/suspicious-invoice.eml <<'EMAIL'
From: Accounts Team <billing@example.invalid>
Reply-To: payment-desk@lookalike.invalid
To: analyst@example.invalid
Subject: Urgent invoice correction
Authentication-Results: mx.example.invalid; spf=fail; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Please process the corrected invoice immediately. Verify your account at
hxxps://example[.]invalid and keep this request confidential.
EMAIL
```

All domains and links above are non-routable or defanged.

## 3. Triage before opening links or attachments

```bash
lurescope triage reported-emails/suspicious-invoice.eml
```

Review the two evidence channels separately: the local fraud-content score and
the deterministic email context. Authentication headers are trustworthy only
when your receiving gateway supplied them. A low result is not proof of safety.

## 4. Create privacy-minimized case evidence

```bash
lurescope inbox reported-emails --out lurescope-cases
lurescope verify lurescope-cases/case-*.lureproof.json
```

The private `lurescope-cases` directory contains a random case ID, one LureProof,
a JSONL manifest, and a summary. It excludes source paths, subjects, bodies,
addresses, message IDs, URL values, and attachment names. Keep the terminal log
private because it is where the source filename and random case ID appear
together.

For authenticated issuer evidence, generate a protected P-256 key and rerun the
inbox command with `--signing-key`; follow the complete
[Inbox-to-LureProof guide](INBOX_TO_LUREPROOF.md#authenticate-the-evidence).

## 5. Produce SIEM-ready payloads without transmitting them

```bash
lurescope export lurescope-cases/manifest.jsonl \
  --format splunk-hec --out lurescope-cases/splunk-hec.jsonl
lurescope export lurescope-cases/manifest.jsonl \
  --format sentinel --out lurescope-cases/sentinel.json
```

These transforms are offline. Submit them only through your organization's
authenticated Splunk HEC or Azure Monitor ingestion client, with retries,
dead-letter handling, and retention controls appropriate for security events.

## Decision boundary

LureScope supports routing and investigation; it does not autonomously delete,
quarantine, or block email. Verify payment, credential, and identity requests
through a known-good channel and retain analyst review and an appeal path.
