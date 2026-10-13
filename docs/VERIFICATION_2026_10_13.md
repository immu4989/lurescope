# Local verification 13 October 2026

Moderation provider failures must not create a fraud decision, an evasion claim,
or a proof. The companion source-branch LureBench adapter now validates a complete
numeric moderation result and raises on malformed evidence. LureScope's existing
runtime-error handling returns a redacted failure. These local changes are not
part of published PyPI 0.11.0 and remain uncommitted and unpushed.

## Moderation route verification

All **seven new route tests passed**. Three provider-runtime failure tests verify
fixed `502` responses on score, attack, and triage without provider diagnostics or
results. A fourth test confirms proof creation rejects moderation before model
construction. Three paired cases exercise the actual new LureBench parser with a
synthetic client, then confirm recovery after correcting the score to valid zero.
The paired cases explicitly skip with an older installed companion parser; that
skip is not evidence of the parsing fix being deployed.

The rebuilt local wheels were installed together in a fresh temporary directory.
An installed ASGI check independently exercised all four routes using the actual
new adapter: malformed scores produced three `502` responses, proof creation
stopped with `400` before another provider-client call, and valid-zero scoring
recovered successfully. No network or real provider credential was involved.

## Supporting verification and limitations

The full paired-source Scope suite passed **1,262 tests**, with 16 existing
warnings and no skips. The companion Bench suite passed **1,970 tests**, with
40 skips and 15 warnings using its documented temporary urllib3 overlay. Its
optional Pydantic moderation case passed separately in the Scope environment,
where all **69 moderation contract cases** passed.

The **107 browser tests**, **26 producer pins**, and **10 independent authority
artifacts** passed, as did Ruff, whitespace, and static asset URL checks. Scope's
wheel matched **164 exact files**, and its source archive retained **19 browser
inputs**. Installed model/proof, authentication, and browser checks passed under
Python **3.12.13**. Companion Bench installed checks passed under Python **3.12.13**
and **3.13.15** with optional SDK/model imports blocked.

This verifies malformed-result handling, not moderation accuracy or fraud
calibration. The actual OpenAI SDK was unavailable in the offline cache; the
checks used synthetic client responses, actual parser code, and Pydantic-shaped
category objects. A service-only upgrade with an older LureBench dependency does
not apply the parser fix. Review [deployment boundaries](PUBLIC_DEPLOYMENT.md)
and deploy compatible companion builds together. Local wheels remain test
artifacts; nothing was pushed, published, or deployed.
