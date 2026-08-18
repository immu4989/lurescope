"""LureScope CLI: serve, triage, and create verifiable resilience evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

MAX_BATCH_INPUT_BYTES = 64 * 1024 * 1024
MAX_BATCH_MESSAGES = 1_000


def _serve(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="lurescope", description="Run the LureScope API + lab.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reload", action="store_true", help="auto-reload on code changes (dev)")
    args = parser.parse_args(argv)

    import uvicorn

    uvicorn.run("lurescope.app:app", host=args.host, port=args.port, reload=args.reload)
    return 0


def _input_messages(
    inputs: Sequence[str],
    recursive: bool,
    *,
    max_messages: int = MAX_BATCH_MESSAGES,
    max_total_bytes: int = MAX_BATCH_INPUT_BYTES,
) -> List[Tuple[str, bytes]]:
    """Discover and bound a batch before reading any message into memory."""
    from .triage import MAX_EMAIL_BYTES

    if max_messages < 1 or max_messages > MAX_BATCH_MESSAGES:
        raise ValueError(f"max_messages must be between 1 and {MAX_BATCH_MESSAGES}")
    if max_total_bytes < 1 or max_total_bytes > MAX_BATCH_INPUT_BYTES:
        raise ValueError(
            f"max_total_bytes must be between 1 and {MAX_BATCH_INPUT_BYTES}"
        )

    sources: List[Tuple[str, Optional[Path]]] = []
    for value in inputs:
        if value == "-":
            if any(path is None for _, path in sources):
                raise ValueError("stdin may be specified only once")
            sources.append(("stdin", None))
        else:
            path = Path(value)
            if path.is_dir():
                pattern = "**/*.eml" if recursive else "*.eml"
                sources.extend(
                    (str(item), item)
                    for item in sorted(path.glob(pattern))
                    if item.is_file()
                )
            elif path.is_file():
                sources.append((str(path), path))
            else:
                raise FileNotFoundError(value)
        if len(sources) > max_messages:
            raise ValueError(
                f"inbox contains more than {max_messages} messages; no files were read"
            )
    if not sources:
        raise ValueError("no .eml messages found")

    # Oversized files are read only to MAX_EMAIL_BYTES + 1 so the parser can emit
    # a per-message EmailTooLarge result without allocating the complete file.
    bounded_sizes = [
        MAX_EMAIL_BYTES + 1
        if path is None
        else min(path.stat().st_size, MAX_EMAIL_BYTES + 1)
        for _, path in sources
    ]
    if sum(bounded_sizes) > max_total_bytes:
        raise ValueError(
            f"bounded inbox input exceeds the {max_total_bytes} byte batch limit; "
            "no files were read"
        )

    messages: List[Tuple[str, bytes]] = []
    for (source, path), bounded_size in zip(sources, bounded_sizes, strict=True):
        if path is None:
            raw = sys.stdin.buffer.read(MAX_EMAIL_BYTES + 1)
        else:
            with path.open("rb") as stream:
                raw = stream.read(bounded_size)
        messages.append((source, raw))
    return messages


def _human_result(source: str, result) -> str:
    lines = [
        f"[{result.risk_tier.upper()}] {source}",
        f"  subject: {result.subject or '(none)'}",
        f"  from: {result.from_address or '(unknown)'}",
        f"  content: {result.content_probability:.0%} ({result.content_label}; "
        f"threshold {result.threshold:.0%})",
    ]
    if result.evidence:
        lines.append("  evidence:")
        lines.extend(
            f"    - {item.severity.upper()}: {item.title} — {item.detail}"
            for item in result.evidence
        )
    else:
        lines.append("  evidence: no deterministic email-context flags")
    lines.append(f"  action: {result.recommended_action}")
    return "\n".join(lines)


def _triage(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lurescope triage",
        description="Triage .eml files locally; links and attachments are never opened.",
    )
    parser.add_argument("input", nargs="+", help=".eml file, directory, or - for stdin")
    parser.add_argument(
        "--recursive", "-r", action="store_true", help="scan directories recursively"
    )
    parser.add_argument("--json", action="store_true", help="emit one JSON object per input")
    parser.add_argument("--detector", default="tfidf-logreg")
    parser.add_argument("--threshold", type=float, default=None)
    args = parser.parse_args(argv)

    from .triage import triage_email

    try:
        messages = _input_messages(args.input, args.recursive)
    except (FileNotFoundError, OSError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2

    failures = 0
    for source, raw in messages:
        try:
            result = triage_email(
                raw, detector_name=args.detector, threshold=args.threshold
            )
            if args.json:
                payload = {"source": source, **result.as_dict()}
                print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
            else:
                if source != messages[0][0]:
                    print()
                print(_human_result(source, result))
        except Exception as exc:  # noqa: BLE001 - continue a batch after one malformed message
            failures += 1
            if args.json:
                print(json.dumps({"source": source, "error": f"{type(exc).__name__}: {exc}"}))
            else:
                print(f"[ERROR] {source}: {type(exc).__name__}: {exc}", file=sys.stderr)
    return 1 if failures else 0


def _inbox(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lurescope inbox",
        description=(
            "Turn .eml files into private per-case LureProofs and a privacy-minimized "
            "JSONL manifest. Links and attachments are never opened."
        ),
    )
    parser.add_argument("input", nargs="+", help=".eml file, directory, or - for stdin")
    parser.add_argument("--out", "-o", required=True, help="new private output directory")
    parser.add_argument(
        "--recursive", "-r", action="store_true", help="scan directories recursively"
    )
    parser.add_argument("--detector", default="tfidf-logreg")
    parser.add_argument("--threshold", type=float, default=None)
    parser.add_argument(
        "--privacy", choices=("salted-commitment", "correlatable"),
        default="salted-commitment",
        help="salted-commitment blocks direct hash matching; correlatable exposes raw SHA-256",
    )
    parser.add_argument("--nonce", help="verifier challenge shared by this batch")
    parser.add_argument(
        "--issuer", help="issuer label; authenticated only when proofs are signed"
    )
    parser.add_argument("--signing-key", help="unencrypted ECDSA P-256 private PEM key")
    parser.add_argument(
        "--max-messages", type=int, default=1000,
        help="fail before processing when the inbox exceeds this limit (maximum 1000)",
    )
    args = parser.parse_args(argv)

    try:
        messages = _input_messages(
            args.input,
            args.recursive,
            max_messages=args.max_messages,
        )
        from .inbox import process_inbox

        signing_key = Path(args.signing_key).read_bytes() if args.signing_key else None
        run = process_inbox(
            messages,
            Path(args.out),
            detector_name=args.detector,
            threshold=args.threshold,
            privacy_profile=args.privacy,
            nonce=args.nonce,
            issuer=args.issuer,
            signing_key_pem=signing_key,
            max_messages=args.max_messages,
        )
    except (FileExistsError, FileNotFoundError, OSError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2

    for item in run.items:
        if item.status == "processed":
            print(
                f"[{item.risk_tier.upper()}] {item.source} -> "
                f"{item.case_id} ({item.proof_file})"
            )
        else:
            print(
                f"[ERROR] {item.source} -> {item.case_id}: {item.error}",
                file=sys.stderr,
            )
    print(
        f"processed {run.summary['processed_count']}/{run.summary['input_count']}; "
        f"failed {run.failed_count}; wrote {run.output_dir}"
    )
    return 1 if run.failed_count else 0


def _proof(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lurescope proof", description="Create a privacy-minimized LureProof from one .eml."
    )
    parser.add_argument("input", help=".eml file or - for stdin")
    parser.add_argument("--out", "-o", required=True, help="output .lureproof.json path")
    parser.add_argument("--detector", default="tfidf-logreg")
    parser.add_argument("--threshold", type=float, default=None)
    parser.add_argument(
        "--privacy", choices=("salted-commitment", "correlatable"),
        default="salted-commitment",
        help="salted-commitment blocks direct hash matching; correlatable exposes raw SHA-256",
    )
    parser.add_argument("--nonce", help="verifier challenge (8-256 characters) for freshness")
    parser.add_argument(
        "--issuer", help="issuer label; authenticated only when the proof is signed"
    )
    parser.add_argument("--signing-key", help="unencrypted ECDSA P-256 private PEM key")
    args = parser.parse_args(argv)
    try:
        raw = sys.stdin.buffer.read() if args.input == "-" else Path(args.input).read_bytes()
        from .proof import create_email_proof, dumps_proof, verify_proof

        signing_key = Path(args.signing_key).read_bytes() if args.signing_key else None
        proof = create_email_proof(
            raw, args.detector, args.threshold, privacy_profile=args.privacy,
            nonce=args.nonce, issuer=args.issuer, signing_key_pem=signing_key,
        )
        Path(args.out).write_text(dumps_proof(proof), encoding="utf-8")
    except (OSError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2
    result = verify_proof(proof)
    kind = "signed DSSE" if result["artifact_type"] == "dsse" else "unsigned statement"
    print(f"created {args.out} ({kind}; sha256:{result['statement_sha256']})")
    return 0


def _export(argv: Sequence[str]) -> int:
    from .integrations import EXPORT_FORMATS

    parser = argparse.ArgumentParser(
        prog="lurescope export",
        description="Transform a minimized inbox manifest for a SIEM or generic webhook.",
    )
    parser.add_argument("manifest", help="inbox manifest.jsonl path")
    parser.add_argument("--format", required=True, choices=EXPORT_FORMATS)
    parser.add_argument("--out", "-o", required=True, help="new output file")
    parser.add_argument(
        "--labels",
        help="optional Shadow Inbox analyst-labels.jsonl for reviewed export state",
    )
    args = parser.parse_args(argv)
    try:
        from .integrations import export_inbox_manifest

        count = export_inbox_manifest(
            Path(args.manifest),
            Path(args.out),
            args.format,
            labels_path=Path(args.labels) if args.labels else None,
        )
    except (FileExistsError, FileNotFoundError, OSError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2
    print(f"exported {count} events as {args.format} to {args.out}")
    return 0


def _shadow(argv: Sequence[str]) -> int:
    from .shadow import ANALYST_LABELS, INPUT_FORMATS, LABEL_REASONS

    parser = argparse.ArgumentParser(
        prog="lurescope shadow",
        description=(
            "Run an offline, no-enforcement pilot over exported .eml, Maildir, or mbox data."
        ),
    )
    commands = parser.add_subparsers(dest="shadow_command", required=True)

    plan_parser = commands.add_parser(
        "plan", help="create a new pre-run statistical acceptance plan"
    )
    plan_parser.add_argument("--out", "-o", required=True, help="new private plan JSON path")
    plan_parser.add_argument("--plan-id", required=True, help="lowercase registration slug")
    plan_parser.add_argument("--min-processed", type=int, required=True)
    plan_parser.add_argument("--min-fraud-labels", type=int, required=True)
    plan_parser.add_argument("--min-benign-labels", type=int, required=True)
    plan_parser.add_argument("--max-uncertain-rate", type=float, required=True)
    plan_parser.add_argument("--max-failure-rate", type=float, required=True)
    plan_parser.add_argument("--min-recall-lower", type=float, required=True)
    plan_parser.add_argument("--max-fpr-upper", type=float, required=True)
    plan_parser.add_argument("--max-routed-rate", type=float, required=True)
    plan_parser.add_argument("--max-routed-count", type=int, required=True)
    plan_parser.add_argument("--confidence", type=float, default=0.95)
    plan_parser.add_argument("--detector", default="tfidf-logreg")
    plan_parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="exact threshold the subsequent shadow run must use (default: 0.5)",
    )
    plan_parser.add_argument(
        "--policy-id",
        help="expected validated policy ID; omit when using an explicit threshold",
    )
    plan_parser.add_argument(
        "--labeling-protocol",
        choices=("full_blinded_review", "full_review"),
        default="full_blinded_review",
    )

    run_parser = commands.add_parser(
        "run", help="create a new privacy-minimized Shadow Inbox pilot bundle"
    )
    run_parser.add_argument("input", nargs="+", help="exported mailbox file or directory")
    run_parser.add_argument("--out", "-o", required=True, help="new private output directory")
    run_parser.add_argument("--format", choices=INPUT_FORMATS, default="auto")
    run_parser.add_argument(
        "--recursive", "-r", action="store_true", help="scan .eml directories recursively"
    )
    run_parser.add_argument("--detector", default="tfidf-logreg")
    run_parser.add_argument("--threshold", type=float, default=None)
    run_parser.add_argument(
        "--privacy",
        choices=("salted-commitment", "correlatable"),
        default="salted-commitment",
        help="salted-commitment prevents direct raw-message hash matching",
    )
    run_parser.add_argument("--nonce", help="verifier challenge shared by this batch")
    run_parser.add_argument(
        "--issuer", help="issuer label; authenticated only when proofs are signed"
    )
    run_parser.add_argument("--signing-key", help="unencrypted ECDSA P-256 private PEM key")
    run_parser.add_argument(
        "--max-messages",
        type=int,
        default=MAX_BATCH_MESSAGES,
        help="fail before body reads above this limit (maximum 1000)",
    )

    label_parser = commands.add_parser(
        "label", help="append a fixed-vocabulary analyst decision and refresh reports"
    )
    label_parser.add_argument("bundle", help="Shadow Inbox bundle directory")
    label_parser.add_argument("case_id")
    label_parser.add_argument("label", choices=ANALYST_LABELS)
    label_parser.add_argument("--reason", required=True, choices=LABEL_REASONS)

    report_parser = commands.add_parser(
        "report", help="rebuild aggregate JSON and Markdown pilot reports"
    )
    report_parser.add_argument("bundle", help="Shadow Inbox bundle directory")

    gate_parser = commands.add_parser(
        "gate", help="evaluate a pre-registered plan and refresh decision artifacts"
    )
    gate_parser.add_argument("bundle", help="Shadow Inbox bundle directory")
    gate_parser.add_argument("--plan", required=True, help="pre-run Pilot Gate plan JSON")

    args = parser.parse_args(argv)
    try:
        if args.shadow_command == "plan":
            from .pilot import create_pilot_plan, pilot_plan_sha256

            target = Path(args.out)
            plan = create_pilot_plan(
                target,
                plan_id=args.plan_id,
                min_processed_count=args.min_processed,
                min_fraud_labels=args.min_fraud_labels,
                min_benign_labels=args.min_benign_labels,
                max_uncertain_rate=args.max_uncertain_rate,
                max_processing_failure_rate=args.max_failure_rate,
                min_routing_recall_lower_bound=args.min_recall_lower,
                max_routing_false_positive_rate_upper_bound=args.max_fpr_upper,
                max_routed_rate=args.max_routed_rate,
                max_routed_count=args.max_routed_count,
                confidence=args.confidence,
                labeling_protocol=args.labeling_protocol,
                detector=args.detector,
                threshold=args.threshold,
                policy_id=args.policy_id,
            )
            print(
                f"created {target} for {plan['plan_id']}; "
                f"sha256:{pilot_plan_sha256(target)}"
            )
            return 0
        if args.shadow_command == "run":
            from .shadow import run_shadow_inbox

            signing_key = Path(args.signing_key).read_bytes() if args.signing_key else None
            run = run_shadow_inbox(
                [Path(value) for value in args.input],
                Path(args.out),
                input_format=args.format,
                recursive=args.recursive,
                detector_name=args.detector,
                threshold=args.threshold,
                privacy_profile=args.privacy,
                nonce=args.nonce,
                issuer=args.issuer,
                signing_key_pem=signing_key,
                max_messages=args.max_messages,
            )
            print(
                f"processed {run.inbox.summary['processed_count']}/"
                f"{run.discovery.candidate_count} candidates; removed "
                f"{run.discovery.duplicate_count} duplicate(s); failed "
                f"{run.failed_count}; wrote {run.output_dir}"
            )
            return 1 if run.failed_count else 0
        if args.shadow_command == "label":
            from .shadow import append_analyst_label

            event = append_analyst_label(
                Path(args.bundle), args.case_id, args.label, args.reason
            )
            print(
                f"labeled {event['case_id']} as {event['label']} "
                f"({event['reason_code']}); refreshed aggregate reports"
                + (
                    " and Pilot Gate"
                    if (Path(args.bundle) / "pilot-plan.json").exists()
                    else ""
                )
            )
            return 0

        if args.shadow_command == "gate":
            from .pilot import write_pilot_gate

            gate = write_pilot_gate(Path(args.bundle), Path(args.plan))
            print(
                f"Pilot Gate: {gate['verdict']}; wrote pilot-gate.json and "
                f"pilot-gate.md in {args.bundle}"
            )
            return 0 if gate["verdict"] == "pass" else 1

        from .shadow import write_shadow_reports

        write_shadow_reports(Path(args.bundle), overwrite=True)
        print(f"refreshed aggregate reports in {args.bundle}")
        return 0
    except (FileExistsError, FileNotFoundError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _assurance(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lurescope assurance",
        description=(
            "Create and export a privacy-minimized Federal Email Assurance Profile."
        ),
    )
    commands = parser.add_subparsers(dest="assurance_command", required=True)

    init_parser = commands.add_parser(
        "init", help="pre-register Pilot Gate and OSCAL assessment plans"
    )
    init_parser.add_argument("--out", "-o", required=True, help="new private plan directory")
    init_parser.add_argument("--plan-id", required=True, help="lowercase registration slug")
    init_parser.add_argument(
        "--ssp-href",
        required=True,
        help="portable urn: or https: identifier for the operator-controlled OSCAL SSP",
    )
    init_parser.add_argument("--min-processed", type=int, required=True)
    init_parser.add_argument("--min-fraud-labels", type=int, required=True)
    init_parser.add_argument("--min-benign-labels", type=int, required=True)
    init_parser.add_argument("--max-uncertain-rate", type=float, required=True)
    init_parser.add_argument("--max-failure-rate", type=float, required=True)
    init_parser.add_argument("--min-recall-lower", type=float, required=True)
    init_parser.add_argument("--max-fpr-upper", type=float, required=True)
    init_parser.add_argument("--max-routed-rate", type=float, required=True)
    init_parser.add_argument("--max-routed-count", type=int, required=True)
    init_parser.add_argument("--confidence", type=float, default=0.95)
    init_parser.add_argument("--detector", default="tfidf-logreg")
    init_parser.add_argument("--threshold", type=float, default=0.5)
    init_parser.add_argument("--policy-id")
    init_parser.add_argument(
        "--labeling-protocol",
        choices=("full_blinded_review", "full_review"),
        default="full_blinded_review",
    )

    export_parser = commands.add_parser(
        "export", help="refresh Pilot Gate and write OSCAL Assessment Results"
    )
    export_parser.add_argument("bundle", help="reviewed Shadow Inbox bundle")
    export_parser.add_argument(
        "--plan", required=True, help="pre-registered assurance plan directory"
    )

    args = parser.parse_args(argv)
    try:
        if args.assurance_command == "init":
            from .assurance import create_assurance_plan

            profile = create_assurance_plan(
                Path(args.out),
                ssp_href=args.ssp_href,
                plan_id=args.plan_id,
                min_processed_count=args.min_processed,
                min_fraud_labels=args.min_fraud_labels,
                min_benign_labels=args.min_benign_labels,
                max_uncertain_rate=args.max_uncertain_rate,
                max_processing_failure_rate=args.max_failure_rate,
                min_routing_recall_lower_bound=args.min_recall_lower,
                max_routing_false_positive_rate_upper_bound=args.max_fpr_upper,
                max_routed_rate=args.max_routed_rate,
                max_routed_count=args.max_routed_count,
                confidence=args.confidence,
                labeling_protocol=args.labeling_protocol,
                detector=args.detector,
                threshold=args.threshold,
                policy_id=args.policy_id,
            )
            print(
                f"created {args.out} with {profile['profile_id']}; "
                f"OSCAL AP {profile['artifacts']['oscal_assessment_plan']['uuid']}"
            )
            profile_digest = hashlib.sha256(
                (Path(args.out) / "assurance-profile.json").read_bytes()
            ).hexdigest()
            print(f"register assurance-profile.json sha256:{profile_digest}")
            print(
                "register pilot-plan.json sha256:"
                f"{profile['artifacts']['pilot_plan']['sha256']}"
            )
            print(
                "register oscal-assessment-plan.json sha256:"
                f"{profile['artifacts']['oscal_assessment_plan']['sha256']}"
            )
            return 0

        from .assurance import export_assurance_results

        result = export_assurance_results(Path(args.bundle), Path(args.plan))
        verdict = result["gate"]["verdict"]
        print(
            f"Federal Email Assurance: {verdict}; wrote registered plan, Pilot Gate, "
            f"and oscal-assessment-results.json in {args.bundle}"
        )
        return 0 if verdict == "pass" else 1
    except (FileExistsError, FileNotFoundError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _verify(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lurescope verify", description="Validate LureProof and authenticate DSSE signatures."
    )
    parser.add_argument("proof", help=".lureproof.json path")
    parser.add_argument("--public-key", help="trusted ECDSA P-256 public PEM key")
    parser.add_argument(
        "--require-signature", action="store_true",
        help="fail unless a signature authenticates against --public-key",
    )
    args = parser.parse_args(argv)
    try:
        from .proof import verify_proof

        proof_path = Path(args.proof)
        if proof_path.stat().st_size > 2 * 1024 * 1024:
            raise ValueError("proof exceeds the 2 MB safety limit")
        proof = json.loads(proof_path.read_text(encoding="utf-8"))
        public_key = Path(args.public_key).read_bytes() if args.public_key else None
        result = verify_proof(proof, public_key, args.require_signature)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["valid"] else 1


def _keygen(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lurescope keygen", description="Generate a local ECDSA P-256 LureProof keypair."
    )
    parser.add_argument("--private-out", required=True, help="new private PEM path (mode 0600)")
    parser.add_argument("--public-out", required=True, help="new public PEM path")
    args = parser.parse_args(argv)
    try:
        from .proof import generate_keypair

        key_id = generate_keypair(Path(args.private_out), Path(args.public_out))
    except OSError as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2
    print(f"created P-256 keypair (keyid:{key_id})")
    return 0


def _api_key(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lurescope api-key",
        description="Generate a client API key and a salted scrypt verifier.",
    )
    parser.add_argument(
        "--out",
        required=True,
        help="new JSON path containing the client key and scrypt verifier (mode 0600)",
    )
    args = parser.parse_args(argv)
    try:
        from .security import create_api_key_material

        client_key, verifier = create_api_key_material()
        payload = {
            "client_api_key": client_key,
            "lurescope_api_key_scrypt": verifier,
        }
        target = Path(args.out)
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
    except (KeyError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2
    print(f"created {args.out} (mode 0600); distribute client_api_key separately")
    return 0


def _policy(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lurescope policy",
        description="Validate and inspect a LureBench decision policy without serving the API.",
    )
    parser.add_argument(
        "path", nargs="?",
        help="policy JSON path; omit to inspect LURESCOPE_POLICY_PATH",
    )
    args = parser.parse_args(argv)
    try:
        from .policy import configured_policy, load_policy, policy_status

        policy = load_policy(str(Path(args.path).resolve())) if args.path else configured_policy()
        status = policy_status(policy)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"! invalid policy: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(status, indent=2, sort_keys=True))
    return 0 if status["configured"] else 1


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "triage":
        return _triage(args[1:])
    if args and args[0] == "inbox":
        return _inbox(args[1:])
    if args and args[0] == "proof":
        return _proof(args[1:])
    if args and args[0] == "export":
        return _export(args[1:])
    if args and args[0] == "shadow":
        return _shadow(args[1:])
    if args and args[0] == "assurance":
        return _assurance(args[1:])
    if args and args[0] == "verify":
        return _verify(args[1:])
    if args and args[0] == "keygen":
        return _keygen(args[1:])
    if args and args[0] == "api-key":
        return _api_key(args[1:])
    if args and args[0] == "policy":
        return _policy(args[1:])
    return _serve(args)


if __name__ == "__main__":
    raise SystemExit(main())
