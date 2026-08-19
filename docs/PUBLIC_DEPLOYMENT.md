# Public deployment guardrails

LureScope remains local-first. Public mode adds a safe application boundary for
single-process deployments; it does not replace TLS termination, a distributed
rate limiter, an identity provider, or cloud billing controls.

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

`GET /health`, `/capabilities`, `/policy`, `/security`, the OpenAPI documentation,
and the static lab remain readable without a key.
`GET /health` returns `503` if public-mode security is misconfigured, preventing
a load balancer from routing traffic to an accidentally unprotected replica.

## Create a client key

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

The checked-in [`compose.yaml`](../compose.yaml) pins the public v0.8.0 image by
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
| `LURESCOPE_API_KEY_SCRYPT` | empty | required | Comma-separated random-salted scrypt client-key verifiers. |
| `LURESCOPE_RATE_LIMIT_PER_MINUTE` | `0` | `60` | Per-key, process-local sliding-window limit. |
| `LURESCOPE_PROVIDER_DAILY_LIMIT` | unlimited | `0` | Process-local attempted-provider-call circuit breaker. |
| `LURESCOPE_ALLOWED_DETECTORS` | unrestricted | local defaults | Comma-separated detector allowlist. |
| `LURESCOPE_ALLOWED_ATTACKS` | unrestricted | local attacks only | If set, all requested attacks must appear in this list. |
| `LURESCOPE_ALLOWED_ENGINES` | unrestricted | empty | Engines permitted for public provider calls. |
| `LURESCOPE_ALLOWED_MODELS` | unrestricted | empty | Models permitted for public provider calls. |

## Production boundary

For an internet-facing service, the gateway should additionally enforce:

- TLS, real user or workload identity, and key rotation;
- a total request-body byte limit before JSON parsing;
- distributed rate, concurrency, and monetary limits;
- timeouts and egress allowlists for provider endpoints;
- logs that exclude message bodies, authorization headers, and provider keys;
- retention and deletion rules appropriate for potentially sensitive email; and
- monitoring for `401`, `429`, `5xx`, latency, and provider-budget exhaustion.

The application never treats a model score as an autonomous consequential
decision. Keep analyst review and an appeal path in every real workflow.
