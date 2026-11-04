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

## Dependency and interpreter baseline verification

The source minimum is Python 3.11+, matching the companion's reviewed dependency
baseline after Python 3.10 end-of-life. CI matrices, README, lint target, wheel
metadata, and the lock agree; CI installation rejects stale locks with `--locked`.
certifi is locked to 2026.10.23 with a >=2026.10.19 resolution floor. Builds
require setuptools >=84.1.0. The certificate/build floor tests initially failed
and now pass. Python-3.10-only resolution branches were removed without upgrading
unrelated remaining package versions.

A fresh locked Python 3.11.15 environment with released LureBench passes 1,382
tests and skips 60 tests requiring newer producer features. Pairing the local
producer passes all 1,442 tests with one dependency warning. The existing paired
Python 3.12 environment also passes 1,442 tests, with 16 dependency warnings.
Browser tests pass 107; together with 2,217 Bench tests, the distinct total is
3,766. Bench also passes its full suite on Python 3.11 and 3.13.

Builds, wheel Python metadata, 167 authority archive files, 19 browser source
inputs, 26 producer pins, 10 independent artifacts, static stamps, and Ruff pass.
Installed model/proof, authentication/JSON, and browser smokes pass outside the
checkout. Verification artifacts are in
`/private/tmp/lure-dependencies-20261103.25aZ2O`.

This does not claim that all 42 GitHub default-branch alerts are resolved: the
full alert lookup timed out in permission review twice. Existing environments,
containers, published packages, and the static Space have not been updated.
No remote writes or provider calls were made. See [deployment notes](../SECURITY.md#deployment-notes)
for migration and the distinction between uv constraints and pip dependencies.

## Companion runtime capacity — 4 November 2026

The paired producer now bounds worker admission across TCP/IPv6/Unix sockets and
waiting for the decision lock. Transport saturation is not an authorization
decision. Four consumer regressions reject busy/unavailable response objects
substituted for receipts and missing receipt evidence with a retained passing
verdict, including repaired trace/receipt hashes. Existing verification semantics
and historical evidence identities remain unchanged.

The full paired suite passes 1,446 tests (16 dependency warnings); browser
tests pass 107. LureBench passes 2,255 with 40 skips on both Python 3.11 and
3.13, giving 3,808 distinct passed tests across the projects and browser.
Producer tests include real loopback IPv4/IPv6 and private Unix saturation and
recovery, plus a stalled-write/health case and ambiguous thread-start failure.
Ruff, static stamps, 26 producer pins, 10 independent artifacts, 167 authority
archive files, 19 browser source inputs, and installed model/proof, auth/JSON,
and browser smokes pass. The core producer installed smoke passes Python
3.11/3.12/3.13 with optional imports forbidden.

Artifacts are under `/private/tmp/lure-capacity-20261103.uXAcey`; the run began
before local midnight. No provider calls, model downloads, commits, pushes,
releases, or deployments occurred. Admission is not storage cancellation,
guaranteed health availability, or a production-service claim; integration
limits are recorded in [runtime mediation evidence](RUNTIME_MEDIATION_EVIDENCE.md).

## Session exhaustion and pre-push verification — 4 November 2026

The companion producer now enforces its existing 512-receipt ceiling before
evaluation and exposes planned exhaustion separately from storage failure.
An additional consumer regression rejects `runtime_exhausted` JSON substituted
for authorization evidence even after hash repair. Integration documentation
explains the session budget, uncertain persistence/delivery, and operator-managed
recovery; consumer schemas and historical identities remain unchanged.

The final paired suite passes **1,447 tests**, with 16 dependency warnings;
browser tests pass **107**. LureBench passes **2,277 with 40 skips** on Python
3.11 and 3.13. Distinct combined passed count: **3,831**. Ruff, whitespace, static
stamps, 26 producer pins, and 10 independent authority artifacts pass. Offline
archives build; 167 authority source files and 19 browser source inputs match.
Installed model/proof, auth/JSON, and browser checks pass, as do the companion
core checks on Python 3.11/3.12/3.13 with optional imports forbidden.

Artifacts and logs: `/private/tmp/lure-push-20261104.BAkBgj`. This is verification
for the requested branch push, not a release, deployment, default-branch merge,
or assertion that all remote dependency alerts are resolved.
