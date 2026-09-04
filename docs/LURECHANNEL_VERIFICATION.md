# Independent LureChannel verification

LureScope independently reparses a LureChannel plan, observation run, and
producer evaluation without importing LureBench. It recomputes topology,
lifetimes, sensor-window coverage, positive delivery controls, unexpected
paths, unauthorized active flows, post-termination residue, every finding, and
the final three-state verdict. A test is rejected if its deadline is outside the
observation window or the applicable source/observer lifetime, or if a sighting
claims a channel its sensor does not cover.

## Create and check a private report

```bash
lurescope channel verify \
  conformance/lurechannel-v1/plan.json \
  conformance/lurechannel-v1/run.json \
  conformance/lurechannel-v1/evaluation.json \
  --verified-at 2026-09-05T00:09:00Z \
  --out channel-verification.json

lurescope channel check channel-verification.json
```

The report is created with mode `0600` and refuses overwrite. It embeds the
exact bytes of all three inputs in canonical standard base64, binds each with
SHA-256, and preserves the producer evaluation. `channel check` decodes and
hashes those bytes again, strictly reparses them, reruns the independent
evaluator, and requires exact report reproduction.

The public vector is a synthetic pass. A semantically valid producer `fail` or
`inconclusive` remains that state after independent verification; it is not
converted into a verifier error. Malformed contracts, source rebinding, changed
summaries, duplicate JSON keys, noncanonical base64, and embedded-byte tampering
fail closed with exit code 2.

## Operational boundary

The verifier accepts individual source files up to 8 MiB and a self-contained
report up to 32 MiB. Reports contain no raw canaries by contract but may reveal
internal run, tenant, channel, isolation-domain, and sensor identifiers. Keep
them private unless those identifiers have been reviewed for release.

Independent recomputation proves that the report follows the published bounded
semantics. It does not authenticate who supplied a sensor assertion, discover
unknown communication paths, prove logs complete, establish universal
noninterference or containment, inspect model reasoning, determine compliance,
certify safety, or authorize deployment.

See the [LureBench LureChannel contract](https://github.com/immu4989/lurebench/blob/main/docs/LURECHANNEL.md)
for the controlled-adapter procedure and research basis.
