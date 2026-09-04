# Independent LureBOM Twin verification

LureScope verifies a LureBOM evaluation from the original CycloneDX 1.7 and
SPDX 3.0.1 bytes. It imports no LureBench code and does not trust the producer's
normalized projection.

The verifier:

1. strictly parses the artifact plan, reviewed mapping manifest, producer
   evaluation, and both source BOMs with duplicate-key and non-finite-number
   rejection;
2. binds the primary BOM to the exact LureArtifact AI-BOM digest and binds the
   mirror to the manifest;
3. independently extracts every bounded component reference, class, one exact
   SHA-256, Package URL, and directed `dependsOn` edge;
4. rejects unknown edge references, duplicate identifiers/hashes/edges, self
   edges, unsupported versions, and unsafe or oversized inputs;
5. requires explicit mapping coverage rather than inferring identity from
   names or versions;
6. reproduces component, artifact-subject, and dependency findings and metrics;
7. requires the producer evaluation to match that independent recomputation
   byte-for-byte as canonical data; and
8. embeds both exact source documents in a private report so `check` can repeat
   the entire operation without the original files.

```bash
lurescope bom verify \
  artifact-plan.json \
  manifest.json \
  lurebom-evaluation.json \
  cyclonedx-1.7.json \
  spdx-3.0.1.json \
  --verified-at 2026-09-05T00:04:00Z \
  --out lurebom-verification.json

lurescope bom check lurebom-verification.json
```

The output is canonical JSON, mode `0600`, and never overwritten. It can contain
the complete private software and AI inventory from both BOMs; handle it as
sensitive supply-chain evidence.

## Semantic coverage and projection loss

The normative v1 common denominator is intentionally narrow:

- explicit source identifiers;
- component classes;
- one exact SHA-256 per component;
- Package URLs, including explicit absence; and
- directed `dependsOn` edges.

Every other encountered top-level or component field is recorded by path in
the source projection's `ignored_field_paths`. For example, a model card can
contain intended uses, datasets, metrics, and limitations, while SPDX AI
packages expose AI-specific properties. Those fields are preserved in the
embedded raw bytes but do not contribute to the parity verdict. The count is a
loss disclosure, not an error count.

This behavior follows the relevant source semantics in the
[CycloneDX 1.7 reference](https://cyclonedx.org/docs/1.7/json/),
[SPDX 3.0.1 AI profile](https://spdx.github.io/spdx-spec/v3.0.1/model/AI/AI/),
[SPDX Hash model](https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Classes/Hash/),
and [SPDX relationship vocabulary](https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Vocabularies/RelationshipType/).

## Failure model

Exit `0` means the producer result was independently reproduced and semantic
parity passed. Exit `1` means the producer result was authentic as data and was
reproduced, but it correctly reports cross-format drift. Exit `2` means the
evidence contract was invalid, stale, tampered, ambiguous, oversized, or could
not be reproduced.

The verifier intentionally permits a valid fail report. This distinction lets
CI and incident workflows preserve evidence of a real mismatch without
misclassifying it as parser corruption.

## Claims boundary

This is not full CycloneDX or SPDX schema validation and not a signature,
certificate, transparency-log, or issuer-authorization verifier. It does not
establish BOM completeness or truth, fetch external references, assess VEX,
scan vulnerabilities or licenses, compare rich AI/model-card semantics, or
open any listed artifact. A pass is not software safety, regulatory compliance,
procurement approval, certification, or deployment authorization.
