# Security Policy

LureScope serves a fraud-detection model over HTTP and demonstrates evasion
against it. It is defensive research tooling, and it is also a web service, so
this policy covers both conventional vulnerabilities and the dual-use questions
specific to the project.

## Reporting a vulnerability

Use GitHub's [private vulnerability reporting form][report] whenever possible.
Reports submitted there are visible only to the reporter and repository
maintainers. If GitHub reporting is unavailable, email **immu4989@gmail.com**.
Please do not open a public issue for anything that could be exploited before a
fix ships.

[report]: https://github.com/immu4989/lurescope/security/advisories/new

Include what you have: affected version or commit, reproduction steps, and the
impact you see. A rough report sent promptly is more useful than a polished one
sent late.

Expect an acknowledgement within **5 working days** and an assessment within
**15 working days**. This is a single-maintainer research project, not a vendor
with an on-call rotation, so those are honest targets rather than an SLA. You
will get credit in the changelog for anything you report unless you ask
otherwise.

## What is in scope

- Anything reachable through the API: injection, path traversal, SSRF via the
  configurable provider engine, or code execution through request payloads.
- Denial of service that a single unauthenticated request can trigger, beyond the
  documented input size limit.
- Leakage of provider API keys through responses, logs, or error messages. The
  service accepts an `engine` and `model` per request and reads keys from the
  environment, so key handling is a real surface.
- Scored text reaching a network endpoint the operator did not configure.
- Anything in the browser demo that lets one visitor affect another, or that
  sends page content off the page. The Hugging Face Space is a static build and
  is meant to run entirely client-side.
- LureProof signature bypasses, DSSE type-confusion issues, acceptance of an
  internally contradictory statement, accidental inclusion of message content,
  private-key permission failures, or proof-verification denial of service.
- SCuBA bridge acceptance of a contradictory or unsupported report, cross-artifact
  rebinding, DSSE bypass, or leakage of tenant identity, raw provider settings,
  requirements, details, comments, or remediation annotations into minimized output.

## What is not a vulnerability

- **That the attacks work.** `homoglyph`, `leet`, `zero-width`, `whitespace`, and
  the LLM rewrites are supposed to evade detectors. `/attack` exists to measure
  that. A new evasion technique is a welcome *contribution*, not a report.
- **That the `normalize` defense does not stop everything.** It reverses
  typographic obfuscation and deliberately does not touch word-splitting or
  semantic paraphrase, because neither can be undone without corrupting
  legitimate text. This is documented behaviour.
- **That a detector scores badly**, or that a gated detector returns `400`
  without its key. Both are intended.

## Deployment notes

The service is local-first. `LURESCOPE_PUBLIC_MODE=true` adds fail-closed bearer
authentication, per-credential process-local rate limiting, detector/attack and
provider/model allowlists, and a provider-call circuit breaker. It refuses to
start protected requests without a salted, memory-hard API-key verifier and exposes its
non-secret posture at `GET /security`. See
[public deployment guardrails](docs/PUBLIC_DEPLOYMENT.md).

These controls do not replace an HTTPS gateway, a shared limiter for multiple
workers, an identity provider, a pre-parse request-byte limit, or provider-side
billing caps. Treat every scored message as sensitive: `/score` and `/attack`
echo the submitted text to the authenticated caller, and enabled LLM-backed
operations send it to the explicitly configured provider.

The container runs as a normal user and needs no privileged capabilities.

`POST /proof/email` deliberately creates unsigned statements only and never
loads or accepts a private key. Sign reviewed evidence offline or through your
access-controlled KMS/HSM workflow. `lurescope keygen` is a local development
helper, not a PKI: protect the private PEM, distribute the public key through a
trusted channel, and rotate it according to your organization's policy.

SCuBA-derived output excludes direct tenant identifiers and raw settings, but it
still reveals security posture and carries a source-report digest that can correlate
copies of the same report. The bridge therefore marks the bundle as not shareable by
default, creates private files, and should run only inside the system authorized to
hold the source report. A SHA-256-bound unsigned statement proves self-consistency,
not authorship; require a trusted DSSE signature when provenance must be authenticated.

## Acceptable use

This project is licensed under Apache-2.0, which does not restrict use. That is a
licensing fact, not an endorsement. The intended uses are scoring your own
messages, stress-testing your own detectors, and researching detection and
defense.

The service does not generate deliverable lures, personalize to real targets, or
embed working links or payment rails. Using it to build or refine fraud against
real people is outside the intent of the project and is a Code of Conduct
violation if it involves this community.

## Supported versions

The `main` branch is supported. Fixes ship in the next release rather than as
backports to older tags.
