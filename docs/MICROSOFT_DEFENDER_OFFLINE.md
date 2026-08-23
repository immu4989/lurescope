# Offline Microsoft Defender EmailEvents comparison

LureScope can compare its Shadow Inbox routing with Microsoft Defender for Office
365 signals without tenant API access and without copying tenant identifiers into
the comparison report. It joins an exported `EmailEvents` table to exported `.eml`
evidence in memory, replaces message identifiers with random Shadow Inbox case
IDs, and retains only four fixed native-attention signals.

This is an offline evaluation workflow. It does not connect to Microsoft 365,
change a message, rerun Defender, or claim that the exported sample represents
future traffic.

## 1. Pre-register the pilot

Create the Pilot Gate plan before exporting or scoring the cohort. Use sample
sizes and operating limits approved for your environment; the tiny values below
are only a workflow example.

```bash
lurescope shadow plan --out ./pilot-plan.json --plan-id defender-comparison \
  --min-processed 100 --min-fraud-labels 25 --min-benign-labels 75 \
  --max-uncertain-rate 0.02 --max-failure-rate 0.01 \
  --min-recall-lower 0.85 --max-fpr-upper 0.02 \
  --max-routed-rate 0.25 --max-routed-count 25
```

## 2. Export the bounded evidence

In Microsoft Defender, run a bounded Advanced Hunting query over `EmailEvents`:

```kusto
EmailEvents
| where Timestamp between (datetime(2026-08-01) .. datetime(2026-08-08))
| project Timestamp, NetworkMessageId, InternetMessageId,
          ThreatTypes, DeliveryAction, DeliveryLocation,
          LatestDeliveryAction, LatestDeliveryLocation, UserLevelAction
```

Microsoft documents the current
[`EmailEvents` columns](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table)
and the portal's
[query-result export workflow](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-query-results).
Guided mode currently exports CSV; advanced table view may export an Excel
workbook. If necessary, save only the result sheet as UTF-8 CSV through your
approved local process. Do not add columns merely for LureScope—the importer
ignores addresses and subjects even when present.

Export the same bounded messages as `.eml` through your organization's approved
evidence or eDiscovery process. LureScope can pair on standard `Message-ID` /
`InternetMessageId` or the Exchange
`X-MS-Exchange-Organization-Network-Message-Id` header. Messages without a match
remain visible as unmatched aggregate counts and are excluded from paired
performance denominators.

Keep both source exports in an access-controlled working directory. They contain
sensitive tenant evidence and are not shareable LureScope artifacts.

## 3. Import without a tenant connection

```bash
lurescope defender import ./EmailEvents.csv ./exported-eml \
  --recursive --threshold 0.5 --out ./defender-shadow-pilot
```

The command checks file, row, field, and message limits before materialization;
rejects symbolic links and ambiguous identifier matches; then runs the normal
private Shadow Inbox workflow. The output adds:

- `defender-import.json`: private byte bindings and aggregate match counts;
- `defender-cases.jsonl`: random case ID, processing/match state, and fixed
  native-attention signals only;
- `defender-report.json` and `.md`: aggregate paired comparison.

Identifiers are used only in memory. The persisted integration artifacts exclude
paths, subjects, sender/recipient addresses, Internet and Network message IDs,
tenant IDs, URLs, attachment names, and content. Tests scan every persisted file
for those values.

## 4. Adjudicate and compare

Use the ordinary fixed-vocabulary review command for every processed case:

```bash
lurescope shadow label ./defender-shadow-pilot case-0123456789abcdef fraud \
  --reason confirmed_external
```

Each label revision atomically refreshes the Shadow, Defender, and—when
registered—Pilot Gate reports. You can also rebuild explicitly:

```bash
lurescope defender report ./defender-shadow-pilot --confidence 0.95
lurescope shadow gate ./defender-shadow-pilot --plan ./pilot-plan.json
```

The paired report includes exact one-sided Clopper–Pearson recall lower bounds and
false-positive-rate upper bounds for both controls over exactly the same matched,
processed, fraud/benign-labeled messages. Uncertain, unlabeled, unmatched, and
failed cases do not enter those denominators.

## Native-attention decision rule

`defender_attention_v1` is true when any matched `EmailEvents` row has at least
one of:

- a non-empty `ThreatTypes` classification;
- `Blocked`, `Junked`, or `Replaced` delivery action;
- Junk, Quarantine, Failed, Dropped, or Deleted Items delivery location; or
- a fixed blocking/deleting/move-to-junk user action.

This is a transparent evaluation boundary, not a reconstruction of every
Microsoft Defender policy decision. Microsoft can change export values; verify
the current schema before each pilot and retain the source export under your
normal evidence controls.
