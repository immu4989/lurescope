# Synthetic Shadow Inbox pilot pack

These messages exercise distinct offline review paths without using real people,
credentials, domains, accounts, or working links. All network-looking destinations
use the reserved `.invalid` top-level domain or the defanged `hxxps` scheme.

| File | Synthetic behavior |
|---|---|
| `01-qr-benefits.eml` | HTML image plus QR/scan language; no image decoding |
| `02-bec-bank-change.eml` | Executive impersonation and Reply-To mismatch |
| `03-archive-attachment.eml` | Defanged payment lure with an inert `.zip` attachment |
| `04-multilingual-alert.eml` | Spanish and Arabic account-verification language |
| `05-benign-agenda.eml` | Routine internal meeting note |
| `06-duplicate-bec.eml` | Exact duplicate of message 02 for deduplication checks |

From the repository root:

```bash
lurescope shadow run examples/shadow-pilot/eml \
  --out ./shadow-pilot --format eml
```

The run should discover six candidates and remove one duplicate. Scores and risk
tiers can change when the detector artifact or policy changes, so the pack does not
assert a fixed prediction. It validates ingestion, minimization, deterministic
context evidence, review labeling, reporting, and export mechanics—not real-world
accuracy. Do not use these messages as a substitute for a representative, legally
approved organizational evaluation set.
