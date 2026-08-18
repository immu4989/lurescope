# Synthetic Shadow Inbox pilot pack

These messages exercise distinct offline review paths without using real people,
credentials, domains, accounts, or working links. All network-looking destinations
use the reserved `.invalid` top-level domain or the defanged `hxxps` scheme.

## Verify the complete path in one command

From a source checkout:

```bash
uv run --frozen --extra dev python scripts/run_golden_pilot.py \
  --out ./golden-shadow-pilot
```

Expected terminal result:

```text
GOLDEN PILOT VERIFIED: PASS
receipt: golden-shadow-pilot/golden-pilot-receipt.json
boundary: synthetic workflow verification only; not deployment evidence
```

The command is deliberately synthetic-only. It does not accept a mailbox path. It:

1. verifies the exact filename set and SHA-256 digest of every reviewed fixture;
2. verifies the bundled detector artifact digest;
3. creates the Pilot Gate plan before running the mailbox export;
4. checks six candidates, one exact duplicate, and five processed cases;
5. applies ground truth fixed in source before model execution—four fraud, one benign;
6. requires every evidence, exact-confidence-bound, and workload check to pass;
7. validates the plan, gate, and Golden Pilot receipt against strict public schemas;
8. scans the private bundle for fixture paths, addresses, message IDs, subjects,
   body fragments, URL values, and attachment names that must not persist.

The output directory and every artifact use private permissions. The aggregate
receipt contains no case IDs or message content and binds the fixture set, detector,
plan, minimized manifest, label log, and gate by SHA-256. The bundle itself still
contains random case IDs and must be treated as private.

The command refuses to overwrite an output directory. It also fails before creating
one if a fixture or detector artifact changed without an explicit contract review.
It runs as a named required CI step in addition to adversarial tests for fixture
tampering, no-network operation, schema strictness, privacy, and no-overwrite behavior.

> The Golden Pilot demonstrates software wiring, not model quality. Its five unique
> examples are not representative, its acceptance limits are intentionally lenient,
> and its locally created plan is not externally registered. Never reuse these
> thresholds for a real pilot.

Inspect the aggregate receipt and human-readable gate:

```bash
jq . ./golden-shadow-pilot/golden-pilot-receipt.json
sed -n '1,220p' ./golden-shadow-pilot/pilot-gate.md
```

## Fixture contract

| File | Synthetic behavior |
|---|---|
| `01-qr-benefits.eml` | HTML image plus QR/scan language; no image decoding |
| `02-bec-bank-change.eml` | Executive impersonation and Reply-To mismatch |
| `03-archive-attachment.eml` | Defanged payment lure with an inert `.zip` attachment |
| `04-multilingual-alert.eml` | Spanish and Arabic account-verification language |
| `05-benign-agenda.eml` | Routine internal meeting note |
| `06-duplicate-bec.eml` | Exact duplicate of message 02 for deduplication checks |

## Run the pack manually

To practice the review workflow without the locked ground-truth runner:

```bash
lurescope shadow run examples/shadow-pilot/eml \
  --out ./shadow-pilot --format eml
```

The run should discover six candidates and remove one duplicate. Scores and risk
tiers can change when the detector artifact or policy changes. The generic pack does
not assert a fixed prediction; the separate Golden Pilot intentionally freezes its
reviewed detector, routing, and ground-truth contract so changes fail CI until they
are examined. Neither path establishes real-world accuracy. Do not use these messages
as a substitute for a representative, legally approved organizational evaluation set.
