# LureProof 0.1

LureProof is an experimental open evidence format for answering a practical
question: **what did this fraud control decide, and did that decision survive
basic adversarial manipulation?**

Unlike a screenshot or vendor report, the artifact is machine-readable and its
digest can be independently recomputed. Unlike a forwarded suspicious email, the
default profile contains no body, subject, addresses, URL values, attachment
names, message ID, or generated attack text.

```bash
lurescope proof suspicious.eml -o suspicious.lureproof.json
lurescope verify suspicious.lureproof.json
```

The API equivalents are `POST /proof/email` and `POST /proof/verify`. The schema
is in [`spec/lureproof.schema.json`](../spec/lureproof.schema.json).

## What the proof contains

- SHA-256 and byte length of the original RFC 5322 artifact;
- detector, threshold, threshold provenance, policy ID, score, and routing tier;
- context evidence **codes and counts**, without their identifying values;
- outcomes for homoglyph, leet, zero-width, and whitespace attacks;
- whether normalization recovered each evasion;
- implementation version, framework mappings, and explicit limitations;
- a digest over deterministic, sorted, compact UTF-8 JSON.

The proof does not contain the original or transformed message. This makes it
appropriate for tickets, inter-team handoffs, procurement evidence, aggregate
research, and cross-organization exercises where sharing live lure content or
personal data is undesirable.

## What verification means

`lurescope verify` proves that the payload still matches its embedded SHA-256
digest. It does **not** authenticate the issuer, prove when the test ran, establish
that the detector was configured honestly, or replace evidence custody controls.
A future signing profile can add issuer identity without weakening this clear
boundary.

The subject hash also has a privacy trade-off: two parties can determine that
they saw an identical artifact. Do not publish proofs when even that correlation
is unacceptable.

## Relationship to existing work

LureProof complements rather than replaces established formats:

| Existing work | What it represents | Gap LureProof addresses |
|---|---|---|
| IETF ARF (RFC 5965) | An email abuse feedback report, normally enclosing the original message or headers | Privacy-minimized detector and adversarial outcomes |
| STIX 2.1 / MISP | Threat objects, email observables, indicators, and forensic evidence | Reproducible control behavior at a named threshold |
| OCSF Email Activity | A normalized security event | Portable robustness evidence rather than an event record |
| NIST AI RMF | Risk-management and TEVV guidance | A concrete artifact teams can produce and compare |
| SBOM and generic attestations | Component inventory or generic claims | Fraud-control-specific assessment semantics |

Our documented landscape review found these adjacent systems, but no open format
combining minimized message identity, decision-policy provenance, and per-message
attack/defense outcomes. That is a bounded observation, not an unprovable claim
that nobody has ever built something similar.

## Intended public value

- **Individuals and small organizations:** obtain a shareable second-opinion
  artifact without uploading a mailbox to a third party.
- **Companies:** compare control versions, attach evidence to SOC cases, and test
  procurement claims on representative messages.
- **Critical infrastructure and government:** exchange minimized exercise results
  across organizational boundaries and retain repeatable TEVV evidence.
- **Researchers and vendors:** build compatible producers, validators, mappings,
  signatures, and aggregate scorecards around a vendor-neutral schema.

LureProof is experimental, not a NIST, MITRE, IETF, OASIS, or government-endorsed
standard. Framework mappings indicate relevance only; they do not claim
conformance or certification.
