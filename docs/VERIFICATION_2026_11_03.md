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

## Companion OCI execution identity — 4 November 2026

The paired source producer now launches its admitted full local image ID instead
of re-resolving a supplied tag. Real Docker regressions reproduced the prior
mismatch in both detector and boundary adapters, then passed after the fix,
including clean restart and deliberate new admission. The installed producer
wheel passes the same real-daemon checks outside the checkout. Podman's native
bare-hex inspection ID is normalized to the unchanged evidence format; actual
Podman execution remains unverified because it is not installed.

Consumer guidance now distinguishes image-reference labels, local runtime IDs,
and registry manifest/index digests. LureScope does not contact the runtime or
independently establish execution identity. Historical mutable-tag evidence with
an uncertain executed image must be re-evaluated, not rewritten. Two new
regressions confirm that a changed or omitted image artifact under the same
monitor name is rejected by an artifact-bound plan, preserving every existing
bundle byte and entry count. Existing schemas, pins and identities are unchanged.

Consumer checkout and extracted-source suites both pass **1,550 tests** with 16
existing dependency warnings; browser **107 passed**. Producer checkout passes
**2,502 with 42 skips** on Python 3.11 and 3.13; two of those skips are Docker
checks that pass separately. Combined distinct passed count is **4,161**.
Producer source archive: **2,496 passed, 48 skipped**, with six additional skips
for deliberately unbundled datasets. This milestone adds 95 cases across repos.

The now-running Docker Desktop also verifies **242 focused producer tests on
Linux**, including all 54 Unix-socket lifecycle tests, as an unprivileged user
with no network and read-only source/dependency mounts. This resolves the earlier
Unix-runtime gap but is not a full Linux-suite or Podman execution claim.

Offline locks/builds, 506 exact consumer source inputs, 174 wheel inputs, 19 browser
archive inputs, 26 producer pins, 10 independent authority artifacts, static
stamps, installed model/proof, authentication/upload and browser checks pass.
Installed producer core checks pass Python 3.11/3.12/3.13 with optional imports
forbidden. No dependency versions changed. Logs and retained synthetic Docker
fixtures are described at `/private/tmp/lure-oci-20261104.ySttcb`.
New changes remain local and uncommitted; no push, release, merge, or deployment
occurred. The added producer CI workflow has not run remotely yet.

## Companion OCI teardown verification — 4 November 2026

The paired producer's prior CLI-only cleanup failed four real-Docker regressions:
normal close and response timeout left a stopped synthetic workload behind in
each adapter. It now separates creation, ownership verification and attachment;
cleanup rechecks the exact container ID/image/name/label, force-removes that owned
ID and associated anonymous volumes, and confirms absence before publishing.
Uncertain creation or cleanup retains recovery diagnostics and blocks evaluation
reuse. It still attempts local CLI/pipe cleanup after daemon-control failure.

Consumer guidance treats these errors as failed execution, not abstention or an
assurance result. A missing report cannot be replaced by an older successful
report. LureScope does not independently attest the runtime's cleanup; schemas,
artifact-bound plans and existing evidence identities are unchanged. Runtime
connections must remain stable, and process/host failures need external
supervision. These are unreleased source changes, not changes to PyPI 0.11.0.

The consumer checkout and extracted-source suites both pass **1,550 tests** with
16 existing dependency warnings; browser **107 passed**. Producer checkout:
**2,584 passed, 46 skipped** on Python 3.11/3.13; extracted producer:
**2,578 passed, 52 skipped**, including six extra skips for unbundled datasets.
All six opt-in Docker tests pass separately from the checkout and installed wheel,
giving **4,247 distinct passes** across the paired checkout/browser/Docker checks.
The producer adds 82 deterministic lifecycle cases and four real-Docker cases;
its focused unprivileged, offline Linux suite passes **324 tests**. Actual Podman
execution remains unverified. A Docker fixture-inspection error preceded a
successful read-only inspection and rerun; the unexplained first error is logged.

Offline locks/builds, 506 exact consumer source inputs, 174 wheel inputs, 19 browser
archive inputs, 26 producer pins, 10 independent authority artifacts, static
stamps, installed model/proof, authentication/upload and browser checks pass.
Producer source/wheel gates verify 561/160 inputs and its installed core passes
Python 3.11/3.12/3.13 with optional imports blocked. No dependency versions changed
in this lifecycle milestone. Test-owned containers and temporary aliases were
absent after verification; retained fixture images and unrelated resources were
not removed. Logs and artifacts: `/private/tmp/lure-lifecycle-20261104.m2ySvP`.
All new changes remain local and uncommitted; no push, merge, release or deployment
occurred, and the modified producer CI workflow has not run remotely.

## Optional Pillow security floor and PNG compatibility — 4 November 2026

The approved read-only GitHub lookup succeeded: 42 default-branch alerts were
open, comprising 41 Pillow entries and one certifi entry. All Pillow entries
identified 13.0.0 as their first patched version. The optional `viz` graph
previously selected Pillow 12.3.0 through Matplotlib. The default API graph and
the existing API test environment did not include Pillow or Matplotlib; the
companion producer lock did not include Pillow either. These observations are
not an audit of arbitrary deployed environments or evidence of non-reachability.

The `viz` extra now directly requires `pillow>=13.0.0`; the lock selects 13.0.0
without changing any other package version. The built wheel's `Requires-Dist`
was checked to enforce that floor only when `extra == "viz"`, not for default or
dev installations. An offline, non-mutating resolver test rejects the built
`[viz]` wheel with `pillow<13` specifically because of the incompatible requirement.
The already-patched certifi lock remains unchanged. No alert was dismissed;
GitHub's default-branch counts and deployed/released packages are unchanged.

Two new baseline checks failed before the manifest/CI change. Three added
dependency/CI regressions verify the extra floor, lock metadata and versions,
default dependency graph including requested transitive extras, and required
Python-version matrix. Three explicitly enabled real rendering tests create and
decode synthetic PNGs, preserve aggregate data, close successful figures, and
verify that missing rates remain masked rather than becoming zero. Tests block
network connections and evaluation factories; no provider key or model run is
needed. A newly observed Matplotlib deprecation was removed using the supported
`with_extremes` equivalent, retaining the neutral-gray missing-value color.
Both generated charts were visually inspected; they are labelled synthetic,
not published benchmark measurements.

Fresh isolated locked dev/viz environments pass the full paired-source suite on
Python 3.11, 3.12 and 3.13: **1,556 tests each** (1/16/16 existing dependency
warnings). The nine-case dependency/rendering selection also passes against the
locked public producer without an adjacent-producer import override. The existing
default environment passes **1,553 tests, 3 intentional visualization skips**;
its installed packages were not changed. The producer full suite passes
**2,584 with 46 skips**, and browser tests **107**. Distinct Python/browser passes
are **4,247**, not multiplied by interpreter repeats. Six cases were added here.
The preceding milestone's real-Docker coverage is unchanged and was not rerun.

Validated extracted-source suites pass **1,556** consumer and **2,578/52** producer
passes/skips; six extra producer skips cover intentionally unbundled datasets.
Offline locks/builds, Ruff/whitespace, 561/508 exact source inputs, 160/174 wheel
inputs, 19 browser archive inputs, 26 producer pins, 10 independent authority
artifacts and static stamps pass. Installed consumer model/proof, authentication/
upload and browser checks pass; installed producer core passes with optional
imports forbidden. Source-only visualization helpers and tests are included in
the source archive; the wheel metadata floor is independently verified above.

Artifacts, isolated environments, resolver diagnostics and synthetic PNGs:
`/private/tmp/lure-pillow-20261104.TT0wcu`. Compatibility is established for these
locked environments, not all allowed future versions or upstream exploit fixes.
The new Linux CI matrix has not run remotely; these rendering runs were on macOS.
No published scorecard, provider cache, historical evidence, release, deployment,
or default API environment was changed. All work remains local and uncommitted.
See [dependency scope and upgrade instructions](DEPENDENCY_SECURITY.md).

## Scorecard missing-outcome accounting — 4 November 2026

Thirty-nine regression cases failed against the earlier scorecard code: character
aggregation converted abstentions into zero and no eligible catches into zero
evasion; cross-model aggregation hid missing outcomes in a scored-only denominator.
The shared, standard-library-only helper now preserves unknowns, validates finite
non-boolean probabilities and thresholds, reports exact counts/coverage and logical
completion bounds, and emits a nullable primary rate under `scorecard-outcomes-v2`.
Missing or extra detector/record/variant results are errors, not abstentions.
Invalid cached values and duplicate judge names fail before provider callbacks.
Cache identity/authenticity is not established by validating its score values.

Markdown and optional PNGs label unresolved/ineligible outcomes explicitly; gray
cells are not zero. Synthetic charts were rendered and visually checked, including
partial bounds and scored/eligible counts. Generated prose no longer invents
model superiority or universal normalization success. Published scorecard files
remain byte-for-byte unchanged, and earlier corrections remain in the generator.
All 16 evasion rates and both recalls on the fully scored ten-record bundled fraud
sample match the prior aggregation. This small reproduction check is not a new
headline benchmark or a paid provider experiment.

Sixty-four new outcome cases, two additional visualization cases, and one paired
producer regression were added. Both repositories enumerate all 121 small-cohort
outcome patterns and every binary completion to check exact bound endpoints.
These are logical missingness bounds, not confidence intervals or a novel estimator.
The focused consumer selection passes **77 tests** on Python 3.11 and 3.13.
The final default Python 3.12 suite passes **1,617 with 5 intentional viz skips**;
the final extracted-source dev/viz suite passes **1,622**, with 16 existing warnings.
Producer checkout passes **2,585/46**, extracted source **2,579/52** passes/skips;
six extra archive skips concern unbundled datasets. Browser tests pass **107**.
Distinct paired Python/browser passes total **4,314**, excluding repeated versions
and prior Docker checks, which were not rerun for this measurement-only change.

Offline locks/builds, Ruff/whitespace, 561/511 exact producer/consumer source inputs,
160/175 wheel inputs, 19 browser archive inputs, 26 producer pins, 10 independent
authority artifacts and static stamps pass. Installed model/proof, authentication/
upload and browser checks pass; installed producer core runs with optional imports
forbidden. The installed new measurement helper passes with site packages disabled
on Python 3.11/3.12/3.13. Source scripts are checked in extracted archives, not
misrepresented as installed wheel entry points. Final verification-document-only
archive changes and unchanged wheel member bytes are checked after rebuilding.

Artifacts: `/private/tmp/lure-scorecard-20261104.dEwJXf`.
See [measurement contract and limits](SCORECARD_MEASUREMENT.md). No historical
evidence, provider cache, schema, default API environment or dependency version
changed in this milestone. No provider call, push, merge, release, deployment or
remote CI run occurred; all new work remains local and uncommitted.

## Whole-file research cohort admission — 4 November 2026

The scorecard loaders admitted boolean/floating labels as binary integers, ignored
malformed excluded records, accepted duplicate/non-finite JSON, and allowed the
character sample limit to bypass trailing validation. All **62 baseline regression
cases failed** before this fix. A local standard-library helper now admits the
complete bounded regular-file input before selection, validates every record and
selection argument, and returns exact consumed-source and framed ordered-occurrence
commitments. Duplicate IDs/text remain separate observations, not collapsed keys.
This is a lightweight scorecard contract, not the full producer Lure schema.

Both CLIs now offer `--validate-corpus`: no keys, evaluation, cache access or output
file writes. New JSON/Markdown include `scorecard-cohort-v1`, counts and selection
parameters; hashes are not authentication, anonymization or label-quality evidence.
Tests independently construct digest framing, check source replacement after the
single admitted read, and verify fail-before-evaluation/output preservation. Local
filesystem and JSON helper limits remain explicit; this is not an atomic snapshot
or a hard process-memory/time bound. See [the input contract](SCORECARD_CORPUS.md).

The **107 new cases** pass. The full existing 3,489,681-byte core/test corpus admits
2,056 records (819 fraud, 1,237 benign). Both new loaders select exactly the same
records in the same order as the prior milestone at limits 0, 1 and 120; the
cross-model comparison uses phishing cap 50. Actual offline preflight commands
also pass for the bundled 16-record sample and the core/test 120-record selection.
These checks did not score the full corpus or refresh benchmark measurements.

Final checkout suites: consumer **1,724 passed, 5 intentional viz skips**, or
**1,729 passed** with visualization enabled; producer **2,585 passed, 46 skipped**;
browser **107 passed**. Distinct Python/browser passes total **4,421**. Focused
scorecard checks pass **184 each** on Python 3.11 and 3.13 against the locked public
producer. Extracted paired-source suites pass consumer **1,729** and producer
**2,579/52** passes/skips, with six extra unbundled-data skips. Explicit import-path
checks confirm the extracted source trees are used. Existing warnings remain.

Offline locks/builds, Ruff/whitespace, 561/514 exact source inputs, 160/176 wheel
inputs, 19 browser archive inputs, 26 producer pins, 10 independent authority
artifacts and static stamps pass. Installed consumer model/proof, authentication/
upload and browser checks pass; producer core passes with optional imports blocked.
The new installed corpus helper passes without site packages on Python 3.11/3.12/
3.13. Final rebuilt wheels retain the tested member bytes; final source changes
are limited to this verification documentation. No dependency changes, provider
calls, historical scorecard/cache rewrites, Docker reruns, pushes, releases or
remote CI runs occurred. All new work remains local and uncommitted.
Artifacts: `/private/tmp/lure-cohort-20261104.gTXhWV`; the baseline failure log is
`/private/tmp/lure-cohort-baseline-20261104.log`.

## Context-bound scorecard replay and push verification — 6 November 2026

The cross-model driver now uses the portable baseline instead of loading its JSON
as a legacy joblib artifact. Cache envelopes bind selected implementations, prompts,
requested models, generation configuration, endpoint, portable artifact and runtime
identity. Legacy or mismatched files fail before provider construction. Explicit
cache-only replay requires complete entries and uses no keys or model factories;
reports identify replay rather than presenting cached outcomes as new evidence.
Duplicate text work is shared while input positions remain separate observations.
Paraphrases and scores are validated, parallel admission is bounded, and failed
evaluations do not partially update the caller's cache mappings.

Eight initial regressions failed against the earlier implementation. The new
77-case cache suite covers identity, preflight, replay, deduplication, invalid
outputs, bounded dispatch, private atomic replacement and preservation on failure.
Each cache file is replaced separately: this is not a two-file transaction,
cross-process compare-and-swap, provider attestation or crash-durability guarantee.
Trusted parent directories and a single writer remain required; legacy caches
must be preserved separately. See [the cache contract](SCORECARD_CACHE.md).

Final paired checkout tests pass consumer **1,806** with visualization enabled,
producer **2,585 with 46 skips**, and browser **107**: **4,498 distinct passes**.
Extracted source suites pass consumer **1,806** and producer **2,579/52**
passes/skips; the six extra skips concern unbundled datasets. Focused scorecard
tests pass **261 each** on Python 3.11 and 3.13 against the locked public producer.
Existing dependency warnings remain. No provider calls or model downloads ran.

Offline locks/builds, Ruff/whitespace, 561/517 exact source inputs, 160/177 wheel
inputs, 19 browser archive inputs, 26 producer pins, 10 independent authority
artifacts and static stamps pass. Installed consumer model/proof, authentication/
upload and browser checks pass; producer core passes with optional imports blocked.
The installed cache helper passes roundtrip, private-mode and context-rejection
checks with site packages disabled on Python 3.11/3.12/3.13. Final rebuilt wheel
member bytes match the tested candidates; final source changes are limited to
verification documentation. Artifacts: `/private/tmp/lure-push-20261106.hj5OhJ`.

This records local pre-push verification of the accumulated feature-branch changes,
not a main-branch merge, release, deployment or remote CI result. Earlier milestone
notes describe their state at the time. Prior Docker checks were not rerun here
and are not added to these totals. Published scorecards and provider caches remain
unchanged; the continuous improvement goal remains paused.
