# LureEval operational evaluation receipts

LureEval turns one reviewed Shadow Inbox and its pre-registered Pilot Gate into a
portable, aggregate-only in-toto Statement. Organizations can compare or pool
field evidence without sharing email, identities, case IDs, paths, URLs, raw
message hashes, or per-message scores.

LureBench owns the protocol, strict schemas, verifier, and compatible-receipt
aggregator. LureScope is a producer. This split prevents the serving tool from
quietly weakening the evidence contract it emits.

## Create a receipt

First complete the [Pilot Gate workflow](PILOT_GATE.md). The bundle must contain
its registered `pilot-plan.json`; receipt creation refreshes the gate against the
current bound manifest and latest-label log before emitting anything.

```bash
lurescope lureeval create ./shadow-pilot \
  --sampling consecutive_sample \
  --minimum-slice-count 20 \
  --issuer "Example SOC" \
  --signing-key issuer.pem \
  --out site-a.lureeval.dsse.json
```

The receipt includes:

- exact detector artifact, threshold, and optional policy-byte bindings;
- commitments to the cohort manifest, latest labels, registered plan, and current
  Pilot Gate;
- confusion counts with recomputed recall/FPR/precision and exact one-sided
  bounds;
- routing workload and adversarial evasion/recovery counts;
- Pilot Gate verdict and failed-check IDs; and
- only slices meeting the declared minimum count.

If the registered plan names a decision-policy ID, `--policy policy.json` is
required and its ID must match. LureScope refuses to publish an unbound policy
claim. If the bundle came from `lurescope defender import`, the receipt declares
`microsoft_defender_export` as its source and binds the minimized import artifact;
it still reports the registered LureScope routing control.

## Verify authentication

```bash
lurescope lureeval verify site-a.lureeval.dsse.json \
  --public-key issuer.pub.pem --require-signature
```

The command performs LureBench's strict semantic validation, recomputes every
derived value, verifies canonical DSSE payload bytes, and authenticates an ECDSA
P-256 signature against the supplied trusted key. Key ownership must be
established out of band.

Unsigned statements remain useful for local reproducibility, but they do not
authenticate an issuer. The browser Evidence Explorer intentionally reports only
that a signature is present; it never calls it authenticated without a trusted
key.

## Pool compatible sites

Use LureBench to verify and aggregate multiple source receipts. Compatibility
requires the same protocol, sampling declaration, labeling protocol, confidence,
small-cell threshold, detector artifact, policy, threshold, and decision
boundary. Counts are pooled and metrics recomputed; percentages are never
averaged.

```bash
lurebench aggregate-receipts \
  --receipt site-a.lureeval.dsse.json \
  --receipt site-b.lureeval.dsse.json \
  --source-key "$PWD/site-a.lureeval.dsse.json=$PWD/site-a.pub.pem" \
  --source-key "$PWD/site-b.lureeval.dsse.json=$PWD/site-b.pub.pem" \
  --require-source-signatures \
  --signing-key consortium.pem \
  --issuer "Regional fraud-defense pilot" \
  --out pooled.lureeval.dsse.json
```

## Interpretation boundary

A receipt authenticates aggregate claims to a key and makes internal
inconsistency detectable. It does not prove that sampling was representative,
review was blinded, labels were correct, cohorts were independent, or future
traffic will match the evaluated population. Small-cell suppression is not
differential privacy. A receipt is not certification, compliance evidence by
itself, an authorization decision, or permission to enforce.
