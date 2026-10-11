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

## MIME tree limits follow-up

Local changes based on `2cdb2c8` address a separately reproduced failure: a 36 KB
message with 1,200 nested embedded messages raised `RecursionError` despite
passing the 5 MiB byte check. Tree construction now rejects more than 256 nodes
or 32 levels, including the root and attachment descendants, before scoring or
proof creation. These fixed application limits do not bound all header/HTML
parsing work or replace process-level resource controls.

The follow-up suite passed **1,066 Python tests** (16 existing warnings) and
**97 browser tests**. Twenty-six new tests cover exact boundaries, three line
ending styles, mixed/digest/embedded messages, delivery-status blocks, attachment
nesting, allocation and header-read cutoffs, concurrent inputs, both API byte
representations, and CLI/inbox continuation without a partial decision or proof.
Ruff, whitespace checks, 26 producer pins, and 10 independent authority artifacts
also passed.

The rebuilt wheel matched 164 source/asset files; the source archive matched 18
browser inputs. Installed-wheel checks outside the checkout passed data-only
scoring, proof generation, and MIME-limit rejection with model frameworks blocked
on Python 3.12.13. A separate Python 3.13.15 smoke check passed normal parsing and
both MIME-limit rejections; it did not run proof generation because that separate
environment lacks Pydantic. The full local suite used Python 3.12.13, not the
entire CI version matrix. Follow-up changes remained local at verification time.

## Header parsing follow-up

Deeply nested comments in `From` and `Content-Type` headers reproduced a separate
`RecursionError` with inputs below 3 KB, even after MIME tree limits were enabled.
Python now checks raw field bytes, total header bytes, field count, and unquoted/
unescaped parenthesis nesting before structured interpretation. Browser preview
applies corresponding budgets to the headers it visits. Unsupported bare-CR
browser header framing is rejected rather than miscounted as one field.

The full suite passed **1,107 Python tests** with 16 existing warnings, and the
five browser test files passed **101 tests**. Forty-one new Python tests cover
exact boundaries, raw UTF-8 octet counting, folded fields, quoted/escaped literals,
attachment descendants, rejection before scoring/proof generation, private API
errors in both byte representations, concurrent per-input budgets, and inbox
continuation. One cross-language test checks acceptance on 26 synthetic fixtures.
Ruff, whitespace checks, and content-bound browser script verification passed.

The rebuilt wheel matched 164 exact source/asset files, and the source archive
matched 18 browser reproduction inputs. Installed checks outside the checkout
passed data-only scoring, proof creation, and MIME/header rejections on Python
3.12.13 with model-framework imports blocked. Python 3.13.15 also passed normal
email parsing and header-budget rejection with both packages explicitly installed
and site packages disabled. Installed browser checks passed normal scoring and
the new field-size, field-count, and nesting rejections. Producer contract pins
and independent authority verification remained valid.

The limits are conservative application policy, not email-format requirements or
a bound on every parsing operation. Legitimate long-header messages may require
controlled review. No attachment contents are scored, no original email is
rewritten to fit a budget, and no provider calls or deployment changes were made.
