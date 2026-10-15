# Public deployment guardrails

LureScope remains local-first. Public mode adds a safe application boundary for
single-process deployments; it does not replace TLS termination, a distributed
rate limiter, an identity provider, or cloud billing controls.

### Source-branch scoring failure semantics

Unreleased serving changes reject detector abstentions, non-finite numbers,
booleans, strings, and out-of-range probabilities. `/score`, `/attack`,
`/triage/email`, and `/proof/email` return an error without a decision or proof;
missing evidence is never converted to a benign probability of zero. A failed
attacked/defended score cannot support an evasion or recovery claim. A valid
probability of exactly zero remains valid.

API failures use fixed messages or static capability guidance rather than raw
provider exceptions, which may contain credentials, prompts, or filesystem
paths. This covers these scoring routes, not arbitrary reverse-proxy logs or
third-party instrumentation. Do not turn API failures into benign classifications
in downstream integrations; retry or route to review under your own policy.

Binoculars is unavailable on the fraud-scoring, attack, triage, and proof routes.
Its provenance score answers a different question and must not be emitted as
`fraud_probability` or used to create fraud evidence. The service rejects it
before detector construction, even if the optional package is installed. The
capability catalog retains the name with this explicit limitation. Reviewed
offline provenance experiments belong in LureBench; the HTTP API provides no
opt-in for upstream remote-code loading.

When paired with the source-branch LureBench moderation adapter, incomplete or
invalid moderation category responses raise instead of falling back to a boolean
flag. `/score`, `/attack`, and `/triage/email` return a redacted `502`, without a
decision or evasion claim; proof creation already refuses provider-backed
moderation. This parser fix requires the companion adapter update, not merely a
LureScope upgrade with the older published LureBench dependency. Test and deploy
compatible builds together. A valid moderation maximum remains a content-safety
proxy, not calibrated fraud probability.

### Source-branch detector lifecycle

Llama Guard construction additionally requires the operator-controlled
`LURESCOPE_ALLOW_UNSAFE_LLAMA_GUARD=1` and `LURESCOPE_LLAMA_GUARD_REVISION` set to a
reviewed immutable lowercase 40-character Hub commit. Installing dependencies
does not opt in. Use this only in a separately isolated worker after artifact
and dependency review; it is not a checkpoint-safety certificate or an Accelerate
patch. The companion adapter must support explicit upstream loading. Request
engine/model fields cannot set either control or select another local model.

The guard is checked before cache lookup. Removing the opt-in blocks later
operations even with resident weights; changing the revision blocks reuse of
old cached weights until worker restart or the private cache-clear operation.
This does not cancel already-running operations or release their references.
Use a controlled worker rollout rather than racing environment mutations.
Binoculars remains unavailable on fraud routes regardless of this opt-in.

Only `tfidf-logreg`, `heuristic-v0`, and `llama-guard-3` are cached across service
operations. The cache holds at most one instance of each name per process.
Engine/model fields do not change these local detectors and no longer create
extra cache entries. They remain meaningful for `llm-judge` and semantic attack
generation. Per-name construction locks prevent duplicate successful cold loads;
loading optional Llama Guard weights does not hold the default detector's lock.
Failed constructors are not cached and a subsequent request can retry.

`llm-judge` and `openai-moderation` are request-scoped rather than cached globally.
Each service operation constructs a new detector using the configuration visible
at construction. Provider credentials and SDK clients are not retained in the
service cache. This removes cross-operation connection reuse and adds constructor
overhead. A single attack operation still shares its detector across clean,
attacked, and defended scoring, without additional constructor calls per score.

These limits bound retained detector instances, not model size, concurrent
inference, request duration, SDK cleanup, or total process memory. Waiting for a
local constructor has no application-level timeout; retain gateway deadlines
and worker limits. Cached local models are not automatically reloaded when model
files or environment variables change. Restart workers to deploy new weights or
configuration. Provider rotation affects later constructors, not already-running
operations; mutating process environment while requests run is not an atomic
policy/configuration update. Use a controlled worker rollout for such changes.
The private cache-clear hook waits for constructors and drops cache references;
it does not cancel active scoring or guarantee immediate GPU-memory reclamation.
There is no HTTP cache-management endpoint.

### Source-branch HTTP input boundary

All HTTP routes now enforce an **8 MiB total body-byte limit before routing and
JSON parsing**, in local and public mode. The middleware counts actual ASGI
body chunks; absent or understated `Content-Length` cannot bypass the limit.
Oversize requests return `413`. Malformed/duplicate length headers or a mismatch
with received bytes return `400`. Non-identity `Content-Encoding` returns `415`;
the application does not decompress request bodies. Request-validation errors
return a fixed `422` message rather than echoing submitted field values or email
content. This changes the diagnostic response shape from framework defaults.

Declared JSON (`application/json`, `application/*+json`, or the API's absent-header
default) is checked for duplicate keys, nonfinite numbers, overflowing literals,
and excessive nesting before framework decoding. Those failures return `422`.
Request models reject unknown fields and coercion of controls: thresholds must
be JSON numbers (not strings or booleans), and `require_signature` must be a JSON
boolean. This deliberately exposes misspelled options rather than ignoring them.

`/proof/verify` returns redacted diagnostics for invalid evidence. Local Python
and CLI verification retain field-level diagnostics. A successful HTTP response
is not proof validity: inspect `valid`, `schema_valid`, and `authenticated`.

The byte limit includes JSON syntax and escaping. Existing field-character and
decoded-email limits still apply; a heavily escaped email may exceed the HTTP
limit before reaching the decoded-email limit. Submit UTF-8 JSON without needless
ASCII escaping. No API body is streamed through to a route before the bound is
checked. This bounded buffering is intentional for the current non-streaming APIs.

The implementation follows the [ASGI HTTP receive-event contract](https://asgi.readthedocs.io/en/latest/specs/www.html#request-receive-event).
The server has already allocated incoming chunks and processed transfer framing
before middleware receives them. The application does not bound headers,
transport buffers, concurrent request counts, JSON object expansion, or slow-client
connection lifetime. Enforce those at the server/gateway. Authentication remains
a route dependency; the size bound applies before it, not an authentication-before-
upload guarantee. No request content is logged by this middleware.

## What public mode changes

Set `LURESCOPE_PUBLIC_MODE=true` to make LureScope fail closed unless at least one
salted API-key verifier is configured. Every content-bearing `POST` route then requires
`Authorization: Bearer <key>` or `X-API-Key: <key>`.

Public mode also:

- limits each credential to 60 requests per minute by default;
- allows only `tfidf-logreg` and `heuristic-v0` by default;
- blocks LLM attacks unless they are explicitly allowlisted;
- blocks arbitrary provider engines and models;
- sets the provider-call budget to zero until the operator opts in; and
- exposes the non-secret posture at `GET /security`.

`GET /health`, `/capabilities`, `/policy`, `/policy/readiness`, `/security`, the OpenAPI documentation,
and the static lab remain readable without a key.
`GET /health` returns `503` if public-mode security is misconfigured, preventing
a load balancer from routing traffic to an accidentally unprotected replica.

Authentication alone does not require validated model decisions. For that,
enable `LURESCOPE_POLICY_ENFORCEMENT=bound` or `risk_controlled_bound` with a
reviewed v3 policy and its approved SHA-256 pin. This rejects threshold/model
overrides and disables exploratory attacks and proof generation on that worker.
Use `/policy/readiness` or `lurescope policy --check-readiness` to check admission,
model binding, and security configuration without inference. See
[operator policy enforcement](BOUND_POLICY.md#require-reviewed-policy-decisions)
for setup, status codes, research-worker separation, and readiness limits.

## Create a client key

### Source-branch authentication work limits

The unreleased service rejects repeated `Authorization` or `X-API-Key` headers,
including identical duplicates, before key derivation. If both header types are
present, each must be valid and they must carry the same key. An empty or malformed
authorization header cannot fall back to another credential. Use the canonical
`Authorization: Bearer <key>` form with one separator space and no padding.

Keys must contain 32–512 visible ASCII characters, without spaces, controls, or
commas. Generated keys already satisfy this. The verifier-creation API enforces
the same contract, and unsupported custom keys must be rotated. Invalid syntax
returns the same fixed `401` response as a nonmatching key, without running scrypt.
This checks credential fields after the ASGI server has received them; it is not
a general header-size or pre-upload authentication limit.

At most two protected requests per process can perform scrypt verification at
once. Admission is nonblocking: saturation returns a fixed `503` response with
`Retry-After: 1`, without queuing another derivation. Slots are released after
success, mismatch, and exceptions. Supported scrypt work factors and memory
parameters are unchanged; every configured candidate is checked even after a
match. Known KDF resource failures also return a redacted retryable `503`.

Configure at most eight distinct verifier entries for key rotation. Each entry
is limited to 256 characters, with exactly a 16-byte salt and 32-byte digest;
the entire environment value is limited to 2,056 characters. Duplicate, empty,
oversized, or malformed entries fail deployment configuration closed. Generated
verifiers are compatible. Empty/unset configuration remains allowed only when
public mode is disabled. There is no positive authentication cache that could
keep a removed verifier usable on subsequent requests; in-flight checks still
use the settings snapshot they already obtained.

This ordering follows [OWASP's guidance on cheap checks before expensive validation](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html#software-design-concepts).
The two-slot guard is a concurrent KDF-work limit, not a request-rate, elapsed-time,
total process-memory, or CPU-utilization guarantee. Invalid but well-formed keys
can still consume available slots, and valid clients can receive `503` during
contention. Unauthenticated rate limits, fair admission, total connection limits,
and multi-replica protection belong at the gateway. Public health/static routes
do not need a key-check slot. The existing post-authentication per-key rate and
provider-call budgets remain separate controls.

Generate a high-entropy client key and a random-salted, memory-hard scrypt
verifier in a new mode-0600 file:

```bash
lurescope api-key --out api-key.json
```

Distribute `client_api_key` to the client through a secret manager. Give the
service only `lurescope_api_key_scrypt`; it never needs the plaintext client key.
Do not commit the JSON file or either value. For rotation, create another file,
configure both comma-separated verifiers, move clients to the new key, and then
remove the old verifier:

```bash
lurescope api-key --out rotated-api-key.json
```

For the commands below, set `API_KEY` from `client_api_key` and
`API_KEY_VERIFIER` from `lurescope_api_key_scrypt` using your shell or deployment
secret manager.

## Run the guarded container

```bash
docker build -t lurescope .
docker run --name lurescope-public --restart unless-stopped \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop ALL --security-opt no-new-privileges:true \
  -p 127.0.0.1:8000:8000 \
  -e LURESCOPE_PUBLIC_MODE=true \
  -e LURESCOPE_API_KEY_SCRYPT="$API_KEY_VERIFIER" \
  -e LURESCOPE_RATE_LIMIT_PER_MINUTE=30 \
  -e LURESCOPE_PROVIDER_DAILY_LIMIT=0 \
  lurescope
```

Keep the container bound to loopback and publish it through an HTTPS reverse
proxy or managed API gateway. Verify the posture before routing traffic:

```bash
curl --fail http://127.0.0.1:8000/health
curl --fail http://127.0.0.1:8000/security
curl --fail http://127.0.0.1:8000/score \
  -H "Authorization: Bearer $API_KEY" \
  -H 'content-type: application/json' \
  -d '{"text":"Verify your account at hxxps://example[.]invalid"}'
```

## Secure Docker Compose

The checked-in [`compose.yaml`](../compose.yaml) pins the public v0.10.0 image by
tag and digest and applies the same non-root, read-only, capability-dropped
boundary used by CI. It also enables authentication, a per-key rate limit,
local-only detectors and attacks, a zero provider-call budget, process and memory
limits, bounded logs, and a loopback-only port.

Generate one client key and export its verifier into the current shell. The
plaintext key is for the client; Compose receives only the salted scrypt
verifier:

```bash
python -m pip install lurescope
lurescope api-key --out api-key.json
export API_KEY="$(python -c 'import json; print(json.load(open("api-key.json"))["client_api_key"])')"
export LURESCOPE_API_KEY_SCRYPT="$(python -c 'import json; print(json.load(open("api-key.json"))["lurescope_api_key_scrypt"])')"

docker compose up --detach --wait
```

Do not commit `api-key.json`, paste the client key into `compose.yaml`, or pass it
to the service container. Verify the deployment with the client key:

```bash
curl --fail http://127.0.0.1:8000/security
curl --fail http://127.0.0.1:8000/score \
  -H "Authorization: Bearer $API_KEY" \
  -H 'content-type: application/json' \
  -d '{"text":"Verify your account at hxxps://example[.]invalid"}'
```

Stop it with `docker compose down`. Set `LURESCOPE_PORT` before `up` to select a
different loopback port. The file deliberately has no provider-key fields; add
provider operations only after applying the controls in the next section.

## Provider-backed operations

Provider spending is disabled by default. To enable it, specify every permitted
surface and a process-local daily call budget. For example:

```bash
LURESCOPE_ALLOWED_DETECTORS=tfidf-logreg,heuristic-v0,llm-judge
LURESCOPE_ALLOWED_ATTACKS=homoglyph,leet,zero-width,whitespace,llm-paraphrase
LURESCOPE_ALLOWED_ENGINES=openrouter
LURESCOPE_ALLOWED_MODELS=openai/gpt-4o-mini
LURESCOPE_LLM_ENGINE=openrouter
LURESCOPE_PROVIDER_DAILY_LIMIT=100
```

Pass the provider key through the deployment platform's secret manager. Never
put it in an image, compose file committed to Git, browser JavaScript, or client
request. A request is charged against the circuit breaker before attempting the
provider call; an LLM-backed detector used during an attack can reserve multiple
calls because clean, attacked, and defended text are scored separately.

The built-in budget resets at midnight UTC and is maintained in process memory.
Multiple workers or replicas each have their own counter, and a restart resets
it. Enforce the real monetary ceiling at the provider account and gateway too.

## Environment reference

| Variable | Local default | Public default | Purpose |
|---|---:|---:|---|
| `LURESCOPE_PUBLIC_MODE` | `false` | — | Enable fail-closed deployment behavior. |
| `LURESCOPE_API_KEY_SCRYPT` | empty | required | Up to eight distinct comma-separated random-salted scrypt verifiers. |
| `LURESCOPE_RATE_LIMIT_PER_MINUTE` | `0` | `60` | Per-key, process-local sliding-window limit. |
| `LURESCOPE_PROVIDER_DAILY_LIMIT` | unlimited | `0` | Process-local attempted-provider-call circuit breaker. |
| `LURESCOPE_ALLOWED_DETECTORS` | unrestricted | local defaults | Comma-separated detector allowlist. |
| `LURESCOPE_ALLOWED_ATTACKS` | unrestricted | local attacks only | If set, all requested attacks must appear in this list. |
| `LURESCOPE_ALLOWED_ENGINES` | unrestricted | empty | Engines permitted for public provider calls. |
| `LURESCOPE_ALLOWED_MODELS` | unrestricted | empty | Models permitted for public provider calls. |

## Production boundary

For an internet-facing service, the gateway should additionally enforce:

- TLS, real user or workload identity, and key rotation;
- transport/header/body limits in addition to the application's 8 MiB byte bound;
- distributed rate, concurrency, and monetary limits;
- timeouts and egress allowlists for provider endpoints;
- logs that exclude message bodies, authorization headers, and provider keys;
- retention and deletion rules appropriate for potentially sensitive email; and
- monitoring for `401`, `429`, `5xx`, latency, and provider-budget exhaustion.

The application never treats a model score as an autonomous consequential
decision. Keep analyst review and an appeal path in every real workflow.
