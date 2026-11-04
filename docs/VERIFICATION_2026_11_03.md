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

## Bounded HTTP admission and upload lifetime — 4 November 2026

Three initial regressions exposed a seventeenth simultaneous request entering
the application with sixteen held routes, absent body-deadline configuration,
and duplicate content-type headers consuming an upload before rejection.
Inspection confirmed that the existing 8 MiB byte cap alone did not bound
simultaneously retained requests or waiting for an incomplete upload.

The middleware now admits 16 HTTP calls by default, with nonblocking saturation
rejection before reading an additional body or entering authentication/routing.
Slots remain held through the downstream ASGI response and release in `finally`.
Body collection has one 30-second deadline rather than an idle timeout reset
by chunks; cooperative cancellation and explicit elapsed checks handle stalled,
trickled, empty/immediate, and late-final events. Existing external cancellation
and upstream timeout exceptions are not mislabeled as local upload deadlines.
An observed disconnect produces no synthetic response, including a late one.

Configuration is snapshotted at application construction, validated, and bounded
to 1..256 admitted requests and a finite positive deadline of at most 300 seconds.
Fixed 503/408 responses do not represent model decisions. Input rejections close
HTTP/1.x connections without emitting the hop-by-hop header on HTTP/2/3 scopes.
AnyIO, already installed transitively, is now declared explicitly (`>=4,<5`);
the offline lock change only adds the direct requirement, not package upgrades.

The 54 new tests cover saturation, slot ownership through upload/route/response,
exception and cancellation cleanup, disconnects, rejected JSON/bytes/headers,
total deadlines, blocking final events, unchanged body replay, configuration,
and non-HTTP scope passthrough. Two actual Uvicorn/h11 loopback tests exercise
asyncio and uvloop: the occupied upload prevents a second request from routing,
both 503 and 408 close their HTTP/1.1 connections, and subsequent health succeeds.
No external host is contacted by those tests; explicit sandbox permission was
required for their ephemeral `127.0.0.1` listeners.

Full paired LureScope suites: **1,501 passed** on both Python 3.11 and 3.12
(1/16 dependency warnings respectively). Unchanged companion LureBench at
`5826995247e0bed7a16fe5650126e9f1e52eab49` passes **2,277 with 40 skips** on
Python 3.13; browser **107 passed**. Distinct combined total: **3,885 passed**.
Ruff, whitespace, offline lock consistency, 26 producer pins, 10 independent
authority artifacts, and static stamps pass. Offline builds and archive checks
pass (167 exact authority sources; 19 browser source inputs). Installed upload
capacity/deadline, JSON/authentication checks pass on Python 3.11 and 3.12;
installed model/proof and browser checks pass outside the checkout.

Verification logs and packages: `/private/tmp/lure-admission-20261104.4Law1C`.
The change does not cap transport connections/buffers, all ASGI tasks, total
process memory, or execution surviving cancellation. It cannot preempt a blocked
event loop and does not reserve health capacity or cancel inference/response
writing. Multiple middleware instances have independent limits. See [operational
boundaries and primary references](PUBLIC_DEPLOYMENT.md#http-admission-and-upload-deadline).
At completion of this milestone, the changes were local only: no commit, push,
release, or deployment had occurred.

## Companion request-head boundary — 4 November 2026

The paired LureBench decision service now collects the complete HTTP head under
a 16 KiB wire-byte bound and five-second total deadline before parsing/routing.
Five additional consumer cases reject head-timeout/overflow/incomplete/read-error
response objects substituted for authorization receipts, even after repairing
receipt and trace hashes. Integration notes distinguish failed transport
admission from a policy decision, and do not claim guaranteed error delivery.

Full paired suite: **1,506 passed** (16 dependency warnings); browser **107 passed**.
LureBench passes **2,317 with 40 skips** on Python 3.11 and 3.13. The distinct
combined total is **3,930 passed**. Producer checks include real IPv4/IPv6/Unix
slow-head expiry and worker recovery, exact body-prefix preservation, and
independent head/body deadlines. Ruff, whitespace, 26 producer pins, 10 independent
authority artifacts, static stamps, offline archives, 167 authority source files,
19 browser source inputs, and installed model/proof, authentication/upload, and
browser checks pass. Installed producer core checks pass Python 3.11/3.12/3.13
with optional imports forbidden.

Artifacts: `/private/tmp/lure-head-20261104.Dx6rnl`. At completion of this
verification, the preceding upload-admission milestone was included and
uncommitted. No push, release, or deployment had occurred; evidence schemas and
historical identities are unchanged.

### Requested branch-push verification

Before the subsequent user-requested push, the full suites were rerun:
paired LureScope Python 3.12 **1,506 passed**, LureBench Python 3.13
**2,317 passed, 40 skipped**, and browser **107 passed**. Existing dependency
warnings remain. Ruff, whitespace, 26 producer pins, 10 independent authority
artifacts, and static stamps pass. Both feature branches match their fetched
remote tips before committing. Logs: `/private/tmp/lure-push-verify-20261104.dN5UAF`.
This prepares branch publication, not a merge, package release, or deployment.

## Companion Unix-socket lifecycle — 4 November 2026

The source-branch producer now requires an owned mode-0700 parent and tracks a
bound socket's identity/metadata through a retained directory descriptor.
Lifecycle cleanup preserves observed replacements, covers startup failures and
interruption, and reports cleanup errors without treating them as successful
CLI shutdown. Integration and migration notes explain the new directory
requirement, same-UID/privileged-race limits, and operator inspection of leftovers.
No lifecycle failure becomes an authorization receipt or changed evidence format.
These controls require the paired source branch, not merely the released pin.

Final paired suite: **1,506 passed** (16 existing dependency warnings); browser:
**107 passed**. LureBench passes **2,371 with 40 skips** on both Python 3.11 and
3.13, including 54 new lifecycle tests. Distinct combined passed count: **3,984**.
Ruff, whitespace, 26 producer pins, 10 independent authority artifacts, static
stamps, offline archives, 167 exact wheel sources, 19 browser source inputs,
installed model/proof, authentication/upload, and browser checks pass. Installed
producer core checks pass on Python 3.11/3.12/3.13 with optional imports forbidden.

The initial parallel build/test attempt exposed pytest collecting the backend's
temporary source tree, causing import mismatches and an archive/bytecode race.
The generated tree was preserved outside the checkout; sequential full tests and
fresh offline packaging pass. This milestone does not fix that workflow collision.
Docker's daemon was unavailable; these results are local macOS evidence, with
Linux runtime verification pending. Artifacts: `/private/tmp/lure-unix-20261104.LuV629`.
This milestone remains local and uncommitted, with no push, release, deployment,
or changes to historical receipt identities.

## Complete source-test reproduction — 4 November 2026

The old source distribution failed collection because scorecard helper modules
were absent; inspection also found the omitted portable `conftest.py`, workflow
inputs and export/verification scripts. An intermediate corrected archive then
exposed four scorecard failures from the missing public sample JSONL and a broken
README link to the omitted blog post. The source inventory and manifest now
include these reviewed inputs plus linked public documentation/assets. The
scorecard JSONL also ships in the wheel; two initially failing wheel regressions
now enforce exact scorecard/pilot fixture bytes.

Default discovery is restricted to `tests/`, with explicit test selection still
supported. Documentation scans use first-party roots, including the blog, rather
than backend-generated source trees. A synthetic reproduction failed before the
change; the actual overlapping build/full-test run now passes. This does not make
arbitrary concurrent source edits or multiple builds in one checkout safe.

The new standard-library archive gate checks 506 exact consumer reproduction
inputs (553 producer inputs), package/version naming, regular canonical members,
duplicates, configured transient/credential filenames and resource budgets.
It does not extract or execute content and does not authenticate a publisher or
sandbox arbitrary untrusted compressed archives. CI runs this gate and the full
suite from the built source archive. The read-only release build verifies source
and wheel contents before upload without acquiring publishing authority.

Full checkout and extracted-source consumer suites both pass **1,548 tests**
(16 existing dependency warnings); browser **107 passed**. Producer checkout:
**2,411 passed, 40 skipped** on Python 3.11 and 3.13. Distinct checkout total:
**4,066 passed**. Producer archive: **2,405 passed, 46 skipped**; six extra skips
are tests for deliberately unbundled datasets. Imports were confirmed inside the
extracted producer and consumer roots. This milestone adds 82 tests across the
repositories, including 42 here; no failing source test was hidden or excluded.

Ruff, whitespace, unchanged offline locks, 26 producer pins, 10 independent
authority artifacts, static stamps, 174 exact consumer wheel inputs, 19 browser
archive inputs, installed model/proof, authentication/upload and browser checks
pass. Producer installed core checks pass Python 3.11/3.12/3.13 with optional
imports forbidden. The installed scorecard JSONL matches the source bytes.

Artifacts: `/private/tmp/lure-source-20261104.qo1H9R`. These are local macOS
results; remote CI has not run and Linux runtime verification remains pending.
All new changes remain local and uncommitted, including the preceding Unix
lifecycle integration notes. No push, merge, release or deployment occurred.
