# JSON resource admission verification

The source branch limits JSON structure before HTTP routing and independent
evidence decoding. These changes are unreleased. Temporary wheels retain version 0.11.0
for installed verification; no release has been published.

## Reproduction and behavior

A 750,001-byte synthetic JSON array containing 250,000 empty dictionaries was
accepted by the previous parser, with 18,807,694 peak traced allocation bytes.
The new HTTP budget rejects the same payload with 751,541 peak traced bytes.
These are local `tracemalloc` measurements of parsing only, not process RSS,
end-to-end request memory, or a latency guarantee.

Before implementation, 12 of 13 initial regression cases failed by entering a
forbidden decoder or downstream application. Only the Permit reader's existing
nesting guard passed. Boundary, Watch, and Witness readers now also reject
excessive nesting and nonfinite overflowing numeric literals.

HTTP JSON admits at most 100,000 nodes; independent Permit, Boundary, Watch,
and Witness evidence readers admit 1,000,000. Each container, object key, and
scalar value counts once. Both profiles allow 128 container levels and at most
4,096 characters per unquoted token. String punctuation and escaping do not
create nodes. Existing byte limits still apply; there is no process-wide memory
or concurrency bound. HTTP rejection remains a fixed 422 response with no input
content. High-complexity older artifacts may now fail; their bytes and identities
are never rewritten.

## Verification

- Full suite: 1,439 passed, 16 existing dependency warnings; 107 browser tests
  passed. Together with LureBench's 2,134 tests, 3,680 tests passed.
- All 65 new complexity cases pass, including exact budgets, escaped keys and strings,
  duplicate-key/syntax rejection, 400 seeded structures, pre-decode admission,
  all four independent evidence readers, absent/JSON/+json content types, and
  chunked exact-limit/over-limit HTTP input.
- A maximum 50,000-feature portable model still loads with a verified file pin.
- Ruff, static asset stamps, 26 producer contract pins, and 10 authority
  reference artifacts pass. Authority verification runs with LureBench imports
  forbidden, preserving the independent consumer boundary.
- Offline wheels and source distributions build. Archive checks match 167 exact
  authority-source files and 19 browser inputs. Installed model/proof, HTTP JSON,
  authentication, and browser smokes pass outside the checkout. Independent
  installed parser rejection and 10 authority artifacts also pass with producer
  imports forbidden.

The temporary build directory is `/private/tmp/lure-json-20261103.GKQhe1`.
Tests use synthetic local inputs; no provider calls, external credentials, or
external writes are involved.

## Research basis

[OWASP API4](https://api-security.owasp.org/editions/2023/en/0xa4-unrestricted-resource-consumption/)
recommends resource and input limits. [RFC 8259 section 9](https://www.rfc-editor.org/rfc/rfc8259.html#section-9)
permits parser limits, and the [ASGI HTTP contract](https://asgi.readthedocs.io/en/stable/specs/www.html)
defines request chunks. The node budgets are project choices; the controls do
not replace gateway limits or establish compliance.

## Companion runtime HTTP verification

After the LureBench runtime HTTP boundary changes, the paired LureScope full
suite again passes: 1,439 tests, with 16 dependency warnings. Browser tests pass
107/107. The combined total with LureBench's 2,177 tests is 3,723. Producer pins,
independent authority checks, static stamps, and Ruff also pass. Fresh paired
wheels in `/private/tmp/lure-runtime-http-20261103.JxVzp0` pass installed
model/proof, JSON/authentication, and browser smokes; 167 authority-source files
and 19 source-distribution browser inputs match their source bytes.

The HTTP implementation change lives in LureBench. LureScope's runtime guide
now distinguishes transport rejection from uncertain processing outcomes and
documents that receipt-chain verification cannot reconstruct a missing receipt.
No LureScope runtime receipt semantics or historical evidence IDs changed.

## Companion runtime audit failure verification

The producer now stops admitting valid decisions after a receipt-storage failure
or uncertain engine error and reports unavailable readiness. LureScope's guide
documents that this neither repairs missing receipts nor authorizes automatic
retry, rollback, or replay-state restoration.

Paired full suites pass: LureBench 2,208, LureScope 1,439, and browser 107
(3,754 total; 40 LureBench skips). Fresh paired wheels in
`/private/tmp/lure-audit-failure-20261103.xo4Y1E` pass installed core checks
on Python 3.12/3.13, model/proof, authentication/JSON, and browser smokes.
Ruff passes; archive checks match 167 authority-source files and 19 browser
source inputs. Receipt semantics and historical evidence identities are unchanged.
