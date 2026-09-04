# LureAttest authenticated provenance verification

LureScope independently recompiles a LureAttest policy and then verifies the
actual provenance evidence offline. It imports no LureBench code.

For every planned attestation, the verifier:

1. requires the evidence directory to contain exactly the derived
   `<attestation-id>.dsse.json` files and refuses symlinks;
2. loads only the externally supplied ECDSA P-256 public keys and verifies that
   their SPKI DER fingerprints exactly equal the reviewed policy;
3. decodes one standard- or URL-safe-base64 DSSE payload and one signature;
4. verifies ECDSA P-256/SHA-256 over the DSSE pre-authentication encoding;
5. parses the same authenticated payload bytes as strict UTF-8 JSON;
6. checks the raw statement digest, in-toto Statement v1 type, SLSA Provenance
   v1 predicate type, and exactly one artifact subject digest;
7. binds the authenticated signer to the expected `builder.id` and checks the
   exact `buildType`;
8. requires exactly one `resolvedDependencies` match for the reviewed source
   URI and SHA-256; and
9. compares canonical `externalParameters` bytes with the preregistered
   commitment.

This implements the bounded fixed-key path in the
[SLSA v1.2 artifact-verification model](https://slsa.dev/spec/v1.2/verifying-artifacts)
and the [DSSE verification sequence](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md).
The unauthenticated DSSE `keyid` is treated only as a hint; the verifier always
tries the public key selected by reviewed policy.

## Run the verifier

```bash
lurescope attest verify \
  artifact-plan.json \
  trust-policy.json \
  attest-plan.json \
  ./provenance-envelopes \
  --public-key builder-a-public.pem \
  --public-key builder-b-public.pem \
  --verified-at 2026-09-04T16:02:00Z \
  --out lureattest-verification.json

lurescope attest check lureattest-verification.json
```

Repeat `--public-key` once for each distinct reviewed builder key. Missing and
extra keys both fail closed. The result embeds the exact envelopes and public
keys as bounded base64 plus their SHA-256 digests. This makes the private report
self-contained: `check` re-authenticates the signatures and re-evaluates every
semantic expectation without the original directory.

The report is canonical JSON, mode `0600`, and never overwritten because SLSA
provenance may disclose repository, workflow, dependency, or build details. The
golden vector is available at
[`conformance/lureattest-v1`](../conformance/lureattest-v1/).

## Prepare policy commitments

```bash
lurescope attest key-id builder-public.pem
lurescope attest commit-external-parameters external-parameters.json
```

The first command hashes DER SubjectPublicKeyInfo. The second strictly parses a
JSON object and hashes LureAttest's sorted, compact UTF-8 encoding with a final
newline. Duplicate keys and NaN/Infinity are rejected.

## Operational boundary

The public key must arrive through a separately trusted channel. A matching
fingerprint does not establish who controls the corresponding private key or
whether key issuance, storage, rotation, revocation, and destruction were
sound. The policy's SLSA Build levels are reviewer assertions; this verifier
does not certify a build platform.

This fixed-key profile is intentionally not Sigstore keyless verification.
According to the [Sigstore bundle format](https://docs.sigstore.dev/about/bundle/),
public verification can require Fulcio identity certificates, transparency-log
material, and signed timestamps. LureScope does not validate those materials,
certificate identities or lifetimes, Rekor inclusion promises/proofs, RFC 3161
timestamps, KMS state, or trust-root updates.

The verifier does not open or hash the subject artifact itself; it binds the
authenticated statement to the digest preregistered by LureArtifact. It also
does not parse AI-BOM documents, fetch source repositories, reproduce builds,
scan dependencies, or establish artifact safety, licensing, vulnerability
status, containment, compliance, or deployment authorization.
