# Email inspection verification on 10 October 2026

Unreleased changes based on `292ab032d2f35e236834e13825b9f01545752055` make incomplete
email inspection visible in triage, minimized proofs, and inbox routing. At
verification time, the changes were local and uncommitted; hosted services and
PyPI were unchanged.

## Behavior and limits

Unsupported inline bodies, undecodable text, malformed MIME, repeated singleton
headers, and subject-only assessments now carry review cues. A benign content
label does not suppress those cues. Unknown charsets are not guessed; text that
cannot be decoded is omitted from scoring. Valid UTF-8, ISO-8859-1, and Windows-1252
fixtures remain readable without a coverage warning.

When the selected plain body and extracted HTML body differ after whitespace
normalization, `html_body_differs` requires review without another model call.
This includes a benign plain alternative paired with different HTML text. It is
not an HTML rendering engine or proof of malicious intent. Ordinary encrypted,
signed, subject-only, and differently formatted mail may require more review.

Evidence codes travel through existing API and proof fields; proof schema version
and historical verification remain unchanged. Attachment payloads are still not
decoded or audited. A message lacking both subject and readable body fails rather
than receiving a decision. See [migration guidance](HARDENING_MIGRATION.md#email-scoring-coverage).

## Results

| Check | Result |
| --- | --- |
| Full Python suite on Python 3.12.13 | 1,040 passed, 16 warnings |
| Browser suite across five files | 97 passed |
| New inspection regression cases | 28 passed, including API, inbox, and proof checks |
| Ruff and Git whitespace checks | Passed |
| Content-bound browser script check | Passed |
| Producer contract verification | 26 pins matched |
| Producer-independent authority verification | 10 artifacts verified |
| Wheel source and asset comparison | 164 exact files matched |
| Source archive browser reproduction inputs | 18 exact files matched |
| Installed authority profiles | 10 of 10 passed |
| Installed model and proof path with model frameworks blocked | Passed |
| Installed browser scoring and assets | Passed |
| Installed opaque-body review cue and proof verification | Passed |

The new tests assert that malformed or omitted content is not silently classified
as fully inspected low-risk mail. They also check that persisted inbox artifacts
and proofs do not expose private fixture subjects, bodies, or paths. The suite
does not estimate real-world false-positive rates, inspect attachments, establish
mail-client equivalence, or certify operational readiness.

Warnings are the existing Starlette/httpx and joblib/NumPy compatibility warnings.
The local wheel is still named 0.11.0 for testing; it must not replace a published
release. No paid-provider calls, model downloads, pushes, or deployments were made.
