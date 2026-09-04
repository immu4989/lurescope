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
        raise ValueError(f"max_total_bytes must be between 1 and {MAX_BATCH_INPUT_BYTES}")

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
                    (str(item), item) for item in sorted(path.glob(pattern)) if item.is_file()
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
        MAX_EMAIL_BYTES + 1 if path is None else min(path.stat().st_size, MAX_EMAIL_BYTES + 1)
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
            result = triage_email(raw, detector_name=args.detector, threshold=args.threshold)
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
        "--privacy",
        choices=("salted-commitment", "correlatable"),
        default="salted-commitment",
        help="salted-commitment blocks direct hash matching; correlatable exposes raw SHA-256",
    )
    parser.add_argument("--nonce", help="verifier challenge shared by this batch")
    parser.add_argument("--issuer", help="issuer label; authenticated only when proofs are signed")
    parser.add_argument("--signing-key", help="unencrypted ECDSA P-256 private PEM key")
    parser.add_argument(
        "--max-messages",
        type=int,
        default=1000,
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
            print(f"[{item.risk_tier.upper()}] {item.source} -> {item.case_id} ({item.proof_file})")
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
        "--privacy",
        choices=("salted-commitment", "correlatable"),
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
            raw,
            args.detector,
            args.threshold,
            privacy_profile=args.privacy,
            nonce=args.nonce,
            issuer=args.issuer,
            signing_key_pem=signing_key,
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
            print(f"created {target} for {plan['plan_id']}; sha256:{pilot_plan_sha256(target)}")
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

            event = append_analyst_label(Path(args.bundle), args.case_id, args.label, args.reason)
            print(
                f"labeled {event['case_id']} as {event['label']} "
                f"({event['reason_code']}); refreshed aggregate reports"
                + (" and Pilot Gate" if (Path(args.bundle) / "pilot-plan.json").exists() else "")
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
        if (Path(args.bundle) / "defender-import.json").exists():
            from .defender import write_defender_report

            write_defender_report(Path(args.bundle), overwrite=True)
        print(f"refreshed aggregate reports in {args.bundle}")
        return 0
    except (FileExistsError, FileNotFoundError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _defender(argv: Sequence[str]) -> int:
    from .shadow import INPUT_FORMATS

    parser = argparse.ArgumentParser(
        prog="lurescope defender",
        description=(
            "Pair an offline Microsoft Defender EmailEvents CSV with exported .eml "
            "evidence; no tenant API or mailbox connection is used."
        ),
    )
    commands = parser.add_subparsers(dest="defender_command", required=True)
    import_parser = commands.add_parser(
        "import", help="create a minimized paired Shadow Inbox bundle"
    )
    import_parser.add_argument("csv", help="Defender portal EmailEvents CSV export")
    import_parser.add_argument("input", nargs="+", help="exported .eml file or directory")
    import_parser.add_argument("--out", "-o", required=True, help="new private output directory")
    import_parser.add_argument("--format", choices=INPUT_FORMATS, default="auto")
    import_parser.add_argument("--recursive", "-r", action="store_true")
    import_parser.add_argument("--detector", default="tfidf-logreg")
    import_parser.add_argument("--threshold", type=float, default=None)
    import_parser.add_argument(
        "--privacy",
        choices=("salted-commitment", "correlatable"),
        default="salted-commitment",
    )
    import_parser.add_argument("--nonce")
    import_parser.add_argument("--issuer")
    import_parser.add_argument("--signing-key")
    import_parser.add_argument("--max-messages", type=int, default=MAX_BATCH_MESSAGES)

    report_parser = commands.add_parser(
        "report", help="refresh the aggregate Defender-vs-LureScope paired report"
    )
    report_parser.add_argument("bundle", help="Defender Shadow Inbox bundle")
    report_parser.add_argument("--confidence", type=float, default=0.95)

    args = parser.parse_args(argv)
    try:
        if args.defender_command == "import":
            from .defender import import_defender_shadow

            signing_key = Path(args.signing_key).read_bytes() if args.signing_key else None
            result = import_defender_shadow(
                Path(args.csv),
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
            imported = result["import"]
            print(
                f"paired {imported['matched_message_count']}/{imported['message_count']} "
                f"messages to {imported['matched_source_row_count']}/"
                f"{imported['source_row_count']} EmailEvents rows; wrote {args.out}"
            )
            return 1 if result["run"].failed_count else 0

        from .defender import write_defender_report

        report = write_defender_report(
            Path(args.bundle), overwrite=True, confidence=args.confidence
        )
        print(
            f"refreshed paired report for "
            f"{report['cohort']['evaluated_matched_messages']} evaluated messages"
        )
        return 0
    except (
        FileExistsError,
        FileNotFoundError,
        OSError,
        RuntimeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _lureeval(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lurescope lureeval",
        description="Create or verify privacy-minimized operational evaluation receipts.",
    )
    commands = parser.add_subparsers(dest="lureeval_command", required=True)
    create_parser = commands.add_parser(
        "create", help="create a receipt from a reviewed, Pilot-Gated Shadow bundle"
    )
    create_parser.add_argument("bundle", help="reviewed Shadow Inbox bundle")
    create_parser.add_argument("--out", "-o", required=True, help="new receipt JSON path")
    create_parser.add_argument(
        "--sampling",
        choices=(
            "complete_population",
            "consecutive_sample",
            "random_sample",
            "operator_declared_other",
        ),
        default="consecutive_sample",
    )
    create_parser.add_argument("--minimum-slice-count", type=int, default=20)
    create_parser.add_argument("--issuer")
    create_parser.add_argument(
        "--policy", help="policy JSON required when the registered plan has a policy_id"
    )
    create_parser.add_argument("--signing-key", help="ECDSA P-256 private PEM")

    verify_parser = commands.add_parser(
        "verify", help="strictly verify a LureEval receipt or aggregate"
    )
    verify_parser.add_argument("artifact")
    verify_parser.add_argument("--public-key", help="trusted ECDSA P-256 public PEM")
    verify_parser.add_argument("--require-signature", action="store_true")

    args = parser.parse_args(argv)
    try:
        if args.lureeval_command == "create":
            from .lureeval import create_lureeval_receipt

            signing_key = Path(args.signing_key).read_bytes() if args.signing_key else None
            artifact = create_lureeval_receipt(
                Path(args.bundle),
                Path(args.out),
                sampling=args.sampling,
                minimum_slice_count=args.minimum_slice_count,
                issuer=args.issuer,
                policy_path=Path(args.policy) if args.policy else None,
                signing_key_pem=signing_key,
            )
            signed = set(artifact) == {"payloadType", "payload", "signatures"}
            print(f"created {args.out} ({'signed DSSE' if signed else 'unsigned statement'})")
            return 0

        from .lureeval import verify_lureeval_receipt

        public_key = Path(args.public_key).read_bytes() if args.public_key else None
        verification = verify_lureeval_receipt(
            Path(args.artifact),
            public_key_pem=public_key,
            require_signature=args.require_signature,
        )
        print(json.dumps(verification, sort_keys=True))
        return 0
    except (
        FileExistsError,
        FileNotFoundError,
        ImportError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _assurance(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lurescope assurance",
        description=("Create and export a privacy-minimized Federal Email Assurance Profile."),
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

    ingest_parser = commands.add_parser(
        "ingest-scuba",
        help="combine a CISA ScubaGear report with registered pilot evidence",
    )
    ingest_parser.add_argument("report", help="ScubaGear 1.8.x consolidated JSON report")
    ingest_parser.add_argument(
        "--bundle",
        "--pilot",
        dest="bundle",
        required=True,
        help="reviewed Shadow Inbox bundle",
    )
    ingest_parser.add_argument(
        "--plan", required=True, help="pre-registered assurance plan directory"
    )
    ingest_parser.add_argument(
        "--out", "-o", required=True, help="new private combined-evidence directory"
    )
    ingest_parser.add_argument(
        "--signing-key", help="optional unencrypted ECDSA P-256 private PEM key"
    )

    verify_scuba_parser = commands.add_parser(
        "verify-scuba",
        help="verify a combined SCuBA and Shadow Inbox assurance bundle",
    )
    verify_scuba_parser.add_argument("bundle", help="combined assurance directory")
    verify_scuba_parser.add_argument("--public-key", help="trusted ECDSA P-256 public PEM key")
    verify_scuba_parser.add_argument(
        "--require-signature",
        action="store_true",
        help="fail unless the DSSE signature authenticates against --public-key",
    )

    drift_parser = commands.add_parser(
        "drift",
        help="compare two compatible Combined Email Assurance bundles",
    )
    drift_parser.add_argument("before", help="earlier combined assurance directory")
    drift_parser.add_argument("after", help="later combined assurance directory")
    drift_parser.add_argument(
        "--out", "-o", required=True, help="new private drift-evidence directory"
    )
    drift_parser.add_argument(
        "--signing-key", help="optional unencrypted ECDSA P-256 private PEM key"
    )
    drift_parser.add_argument(
        "--source-public-key",
        help="trusted ECDSA P-256 key shared by both sources unless overridden",
    )
    drift_parser.add_argument(
        "--before-source-public-key",
        help="trusted key for the earlier source bundle; supports key rotation",
    )
    drift_parser.add_argument(
        "--after-source-public-key",
        help="trusted key for the later source bundle; supports key rotation",
    )
    drift_parser.add_argument(
        "--require-source-signatures",
        action="store_true",
        help="require both source bundles to authenticate against --source-public-key",
    )
    drift_parser.add_argument(
        "--previous-drift",
        help="verified predecessor drift directory used to extend the ledger chain",
    )

    verify_drift_parser = commands.add_parser(
        "verify-drift",
        help="verify a SCuBA Assurance Drift package and optional chain/source bindings",
    )
    verify_drift_parser.add_argument("drift", help="drift evidence directory")
    verify_drift_parser.add_argument(
        "--public-key", help="trusted ECDSA P-256 public PEM key for this drift entry"
    )
    verify_drift_parser.add_argument(
        "--require-signature",
        action="store_true",
        help="fail unless this drift entry authenticates against --public-key",
    )
    verify_drift_parser.add_argument(
        "--previous-drift", help="predecessor drift directory for chain verification"
    )
    verify_drift_parser.add_argument(
        "--previous-public-key", help="trusted ECDSA P-256 key for the predecessor"
    )
    verify_drift_parser.add_argument(
        "--require-chain",
        action="store_true",
        help="fail when a bound predecessor is not supplied and verified",
    )
    verify_drift_parser.add_argument(
        "--before", help="original earlier source bundle for semantic reverification"
    )
    verify_drift_parser.add_argument(
        "--after", help="original later source bundle for semantic reverification"
    )
    verify_drift_parser.add_argument(
        "--source-public-key", help="trusted key shared by both sources unless overridden"
    )
    verify_drift_parser.add_argument(
        "--before-source-public-key", help="trusted key for the earlier source bundle"
    )
    verify_drift_parser.add_argument(
        "--after-source-public-key", help="trusted key for the later source bundle"
    )
    verify_drift_parser.add_argument(
        "--require-source-signatures",
        action="store_true",
        help="require both supplied source bundles to authenticate",
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
            print(f"register pilot-plan.json sha256:{profile['artifacts']['pilot_plan']['sha256']}")
            print(
                "register oscal-assessment-plan.json sha256:"
                f"{profile['artifacts']['oscal_assessment_plan']['sha256']}"
            )
            return 0

        if args.assurance_command == "ingest-scuba":
            from .scuba import create_scuba_assurance_bundle

            result = create_scuba_assurance_bundle(
                Path(args.report),
                Path(args.bundle),
                Path(args.plan),
                Path(args.out),
                signing_key=Path(args.signing_key) if args.signing_key else None,
            )
            gate_verdict = result["gate"]["verdict"]
            evidence = result["evidence"]
            print(
                f"Combined Email Assurance: {gate_verdict}; imported "
                f"{evidence['integrity']['control_count']} minimized SCuBA controls and "
                f"wrote {evidence['integrity']['candidate_poam_count']} candidate POA&M "
                f"items in {args.out}"
            )
            print(f"source ScubaGear report sha256:{evidence['source']['report_sha256']}")
            return 0 if gate_verdict == "pass" else 1

        if args.assurance_command == "verify-scuba":
            from .scuba import verify_scuba_assurance_bundle

            verification = verify_scuba_assurance_bundle(
                Path(args.bundle),
                public_key=Path(args.public_key) if args.public_key else None,
                require_signature=args.require_signature,
            )
            print(json.dumps(verification, sort_keys=True))
            return 0

        if args.assurance_command == "drift":
            from .drift import create_scuba_drift_package

            result = create_scuba_drift_package(
                Path(args.before),
                Path(args.after),
                Path(args.out),
                signing_key=Path(args.signing_key) if args.signing_key else None,
                source_public_key=(
                    Path(args.source_public_key) if args.source_public_key else None
                ),
                before_source_public_key=(
                    Path(args.before_source_public_key) if args.before_source_public_key else None
                ),
                after_source_public_key=(
                    Path(args.after_source_public_key) if args.after_source_public_key else None
                ),
                require_source_signatures=args.require_source_signatures,
                previous_drift=(Path(args.previous_drift) if args.previous_drift else None),
            )
            drift = result["drift"]
            print(
                f"SCuBA Assurance Drift: {drift['summary']['changed_control_count']} of "
                f"{drift['summary']['total_control_count']} controls changed; "
                f"{drift['summary']['candidate_lifecycle']['new_candidate']} new and "
                f"{drift['summary']['candidate_lifecycle']['persistent_candidate']} "
                f"persistent candidate POA&M observations in {args.out}"
            )
            return 0

        if args.assurance_command == "verify-drift":
            from .drift import verify_scuba_drift_package

            verification = verify_scuba_drift_package(
                Path(args.drift),
                public_key=Path(args.public_key) if args.public_key else None,
                require_signature=args.require_signature,
                previous_drift=(Path(args.previous_drift) if args.previous_drift else None),
                previous_public_key=(
                    Path(args.previous_public_key) if args.previous_public_key else None
                ),
                require_chain=args.require_chain,
                before_bundle=Path(args.before) if args.before else None,
                after_bundle=Path(args.after) if args.after else None,
                source_public_key=(
                    Path(args.source_public_key) if args.source_public_key else None
                ),
                before_source_public_key=(
                    Path(args.before_source_public_key) if args.before_source_public_key else None
                ),
                after_source_public_key=(
                    Path(args.after_source_public_key) if args.after_source_public_key else None
                ),
                require_source_signatures=args.require_source_signatures,
            )
            print(json.dumps(verification, sort_keys=True))
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
        "--require-signature",
        action="store_true",
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
        "path",
        nargs="?",
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


def _operational_pilot(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lurescope pilot",
        description=("Create or reverify the offline synthetic operational evidence bundle."),
    )
    commands = parser.add_subparsers(dest="pilot_command", required=True)
    run_parser = commands.add_parser(
        "run", help="atomically create the reviewed one-command pilot bundle"
    )
    run_parser.add_argument("--out", "-o", required=True, help="new private output directory")
    run_parser.add_argument("--json", action="store_true", help="print the final receipt")
    verify_parser = commands.add_parser(
        "verify", help="reverify every binding without changing the bundle"
    )
    verify_parser.add_argument("bundle", help="existing operational pilot directory")
    verify_parser.add_argument("--json", action="store_true", help="print the receipt")
    args = parser.parse_args(argv)
    try:
        from .operational_pilot import run_operational_pilot, verify_operational_pilot

        if args.pilot_command == "run":
            target = Path(args.out)
            receipt = run_operational_pilot(target)
        else:
            target = Path(args.bundle)
            receipt = verify_operational_pilot(target)
        if args.json:
            print(json.dumps(receipt, indent=2, sort_keys=True))
        else:
            action = "CREATED" if args.pilot_command == "run" else "VERIFIED"
            print(f"OPERATIONAL PILOT {action}: PASS — {target}")
            print(
                "boundary: synthetic offline workflow proof; not deployment or compliance evidence"
            )
        return 0
    except (
        AssertionError,
        FileExistsError,
        FileNotFoundError,
        ImportError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        print(f"! operational pilot failed: {exc}", file=sys.stderr)
        return 2


def _monitor(argv: Sequence[str]) -> int:
    """Create, append, and independently verify LureWatch evidence."""

    parser = argparse.ArgumentParser(
        prog="lurescope monitor",
        description=(
            "Anytime-valid, aggregate-only post-deployment FPR/FNR monitoring. "
            "Repeated inspection at submitted batch boundaries does not inflate the "
            "declared false-alarm budget."
        ),
    )
    commands = parser.add_subparsers(dest="monitor_command", required=True)

    init_parser = commands.add_parser(
        "init", help="create an immutable monitor plan and empty checkpoint chain"
    )
    init_parser.add_argument("--out", "-o", required=True, help="new private bundle directory")
    init_parser.add_argument("--plan-id", help="portable plan identifier; generated if omitted")
    init_parser.add_argument("--policy", help="validated LureBench decision-policy JSON")
    init_parser.add_argument("--detector", help="detector identity; defaults from policy or tfidf")
    init_parser.add_argument(
        "--threshold", type=float, help="decision threshold; defaults from policy"
    )
    init_parser.add_argument(
        "--fpr-limit",
        type=float,
        help="overall false-positive-rate limit; defaults from risk-controlled policy or 0.01",
    )
    init_parser.add_argument("--fnr-limit", type=float, default=0.10)
    init_parser.add_argument("--family-alpha", type=float, default=0.05)
    init_parser.add_argument(
        "--sampling",
        choices=(
            "complete_population",
            "consecutive_sample",
            "random_sample",
            "operator_declared_other",
        ),
        default="random_sample",
    )
    init_parser.add_argument("--labeling-protocol", default="human-adjudication-v1")
    init_parser.add_argument(
        "--signer-public-key",
        help="external ECDSA P-256 trust key; requires signed checkpoints",
    )

    append_parser = commands.add_parser(
        "append", help="append one adjudicated aggregate confusion matrix"
    )
    append_parser.add_argument("bundle")
    append_parser.add_argument("--batch-id", required=True)
    append_parser.add_argument("--true-positive", type=int, required=True)
    append_parser.add_argument("--false-positive", type=int, required=True)
    append_parser.add_argument("--true-negative", type=int, required=True)
    append_parser.add_argument("--false-negative", type=int, required=True)
    append_parser.add_argument("--observed-at", help="ISO 8601 time represented by the batch")
    append_parser.add_argument(
        "--source-sha256",
        help="optional SHA-256 commitment to the private adjudication source",
    )
    append_parser.add_argument(
        "--signing-key", help="unencrypted P-256 private key required by signed plans"
    )
    append_parser.add_argument("--json", action="store_true")

    verify_parser = commands.add_parser(
        "verify", help="recompute every statistic, digest, chain link, and signature"
    )
    verify_parser.add_argument("bundle")
    verify_parser.add_argument("--public-key", help="external trusted P-256 public key")
    verify_parser.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    try:
        from .watch import (
            append_monitor_batch,
            confusion_counts,
            create_monitor_bundle,
            default_monitors,
            verify_monitor_bundle,
        )

        if args.monitor_command == "init":
            import uuid

            from .pilot import detector_artifact_sha256

            policy = None
            policy_digest = None
            if args.policy:
                from .policy import load_policy

                policy_path = Path(args.policy)
                policy_bytes = policy_path.read_bytes()
                if len(policy_bytes) > 2 * 1024 * 1024:
                    raise ValueError("decision policy exceeds the 2 MB safety limit")
                policy = load_policy(str(policy_path.resolve()))
                policy_digest = hashlib.sha256(policy_bytes).hexdigest()
            detector = args.detector or (policy.detector if policy else "tfidf-logreg")
            threshold = args.threshold
            if threshold is None:
                threshold = policy.threshold if policy else 0.5
            if policy and detector != policy.detector:
                raise ValueError("--detector conflicts with the bound decision policy")
            if policy and threshold != policy.threshold:
                raise ValueError("--threshold conflicts with the bound decision policy")
            fpr_limit = args.fpr_limit
            if fpr_limit is None:
                fpr_limit = policy.target_fpr if policy and policy.target_fpr else 0.01
            signer_public = (
                Path(args.signer_public_key).read_bytes() if args.signer_public_key else None
            )
            plan = create_monitor_bundle(
                Path(args.out),
                plan_id=args.plan_id or f"lurewatch-{uuid.uuid4()}",
                detector=detector,
                threshold=threshold,
                monitors=default_monitors(fpr_limit, args.fnr_limit),
                family_alpha=args.family_alpha,
                sampling=args.sampling,
                labeling_protocol=args.labeling_protocol,
                detector_artifact_sha256=detector_artifact_sha256(detector),
                policy_id=policy.policy_id if policy else None,
                policy_sha256=policy_digest,
                signer_public_key_pem=signer_public,
            )
            print(
                f"LUREWATCH PLAN CREATED: {plan['plan_id']} — {args.out}\n"
                f"monitors: FPR <= {fpr_limit:g}; FNR <= {args.fnr_limit:g}; "
                f"family alpha {args.family_alpha:g}\n"
                "boundary: aggregate adjudicated counts only; no alarm is not proof of safety"
            )
            return 0

        if args.monitor_command == "append":
            signing_key = Path(args.signing_key).read_bytes() if args.signing_key else None
            entry = append_monitor_batch(
                Path(args.bundle),
                batch_id=args.batch_id,
                counts=confusion_counts(
                    true_positive=args.true_positive,
                    false_positive=args.false_positive,
                    true_negative=args.true_negative,
                    false_negative=args.false_negative,
                ),
                observed_at=args.observed_at,
                source_commitment_sha256=args.source_sha256,
                signing_key_pem=signing_key,
            )
            if args.json:
                print(json.dumps(entry, indent=2, sort_keys=True))
            else:
                print(
                    f"LUREWATCH BATCH {entry['sequence']} APPENDED: "
                    f"{entry['family_status'].upper()} — {args.batch_id}"
                )
                for state in entry["states"]:
                    rate = (
                        "not measurable"
                        if state["empirical_rate"] is None
                        else f"{state['empirical_rate']:.2%}"
                    )
                    print(
                        f"  {state['monitor_id']}: {rate}; "
                        f"log(e)={state['log_e_value']:.3f}; {state['status']}"
                    )
                print("boundary: a breach is evidence under the plan assumptions, not causality")
            return 1 if entry["family_status"] == "breach" else 0

        public_key = Path(args.public_key).read_bytes() if args.public_key else None
        result = verify_monitor_bundle(Path(args.bundle), public_key_pem=public_key)
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            auth = "authenticated" if result["authenticated"] else "unsigned"
            print(
                f"LUREWATCH VERIFIED: {result['family_status'].upper()} — "
                f"{result['entry_count']} checkpoints ({auth})"
            )
            print(f"plan sha256:{result['plan_sha256']}")
            if result["latest_statement_sha256"]:
                print(f"latest checkpoint sha256:{result['latest_statement_sha256']}")
            print("boundary: integrity and statistical evidence are not compliance")
        return 0
    except (
        FileExistsError,
        FileNotFoundError,
        ImportError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        print(f"! LureWatch failed: {exc}", file=sys.stderr)
        return 2


def _boundary(argv: Sequence[str]) -> int:
    """Preregister, append, verify, and export LureBoundary evidence."""

    parser = argparse.ArgumentParser(
        prog="lurescope boundary",
        description=(
            "Tamper-evident assurance for safe synthetic autonomous-agent boundary "
            "evaluations. Records human response requirements; never executes enforcement."
        ),
    )
    commands = parser.add_subparsers(dest="boundary_command", required=True)

    init_parser = commands.add_parser(
        "init", help="bind a benchmark, monitor, system, and response authority before use"
    )
    init_parser.add_argument("--out", "-o", required=True, help="new private bundle directory")
    init_parser.add_argument("--plan-id", required=True)
    init_parser.add_argument(
        "--evaluation",
        required=True,
        help="reviewed LureBench boundary evaluation used to bind suite and thresholds",
    )
    init_parser.add_argument("--system-id", required=True)
    init_parser.add_argument(
        "--environment",
        choices=("development", "evaluation", "staging", "production"),
        default="evaluation",
    )
    init_parser.add_argument("--model-id", required=True)
    init_parser.add_argument("--model-sha256")
    init_parser.add_argument("--policy-id")
    init_parser.add_argument("--policy-sha256")
    init_parser.add_argument("--controller-id")
    init_parser.add_argument("--controller-sha256")
    init_parser.add_argument("--authority-id", default="human-security-authority")
    init_parser.add_argument(
        "--critical-action",
        choices=(
            "human_review_required",
            "pause_authority_notification",
            "evaluation_shutdown_review",
        ),
        default="human_review_required",
    )
    init_parser.add_argument("--review-sla-minutes", type=int, default=60)
    init_parser.add_argument("--signer-public-key", help="external ECDSA P-256 trust key")
    init_parser.add_argument(
        "--oscal-ap-href",
        help="operator-controlled https: or urn: OSCAL Assessment Plan reference",
    )

    append_parser = commands.add_parser(
        "append", help="append one validated LureBench boundary evaluation"
    )
    append_parser.add_argument("bundle")
    append_parser.add_argument("evaluation")
    append_parser.add_argument("--evaluation-id", required=True)
    append_parser.add_argument("--signing-key", help="P-256 key required by signed plans")
    append_parser.add_argument("--json", action="store_true")

    verify_parser = commands.add_parser(
        "verify", help="recompute every metric, digest, chain link, and signature"
    )
    verify_parser.add_argument("bundle")
    verify_parser.add_argument("--public-key", help="external trusted P-256 public key")
    verify_parser.add_argument("--json", action="store_true")

    export_parser = commands.add_parser(
        "export-oscal", help="export latest verified evidence as observation-only OSCAL AR"
    )
    export_parser.add_argument("bundle")
    export_parser.add_argument("--out", "-o", required=True, help="new private OSCAL JSON")
    export_parser.add_argument("--public-key", help="trusted key for a signed bundle")

    args = parser.parse_args(argv)
    try:
        from .boundary import (
            append_boundary_evaluation,
            create_boundary_bundle,
            export_boundary_oscal,
            load_boundary_evaluation,
            verify_boundary_bundle,
        )

        if args.boundary_command == "init":
            report, _ = load_boundary_evaluation(Path(args.evaluation))
            suite = report["suite"]
            monitor = report["monitor"]
            acceptance = report["acceptance"]
            signer_public = (
                Path(args.signer_public_key).read_bytes() if args.signer_public_key else None
            )
            plan = create_boundary_bundle(
                Path(args.out),
                plan_id=args.plan_id,
                system_id=args.system_id,
                environment=args.environment,
                model_id=args.model_id,
                model_sha256=args.model_sha256,
                suite_id=suite["suite_id"],
                suite_version=suite["suite_version"],
                suite_sha256=suite["suite_sha256"],
                monitor_id=monitor["monitor_id"],
                monitor_artifact_sha256=monitor["artifact_sha256"],
                minimum_trajectory_recall=acceptance["minimum_trajectory_recall"],
                maximum_benign_false_positive_rate=acceptance["maximum_benign_false_positive_rate"],
                maximum_detection_delay_events=acceptance["maximum_detection_delay_events"],
                minimum_category_accuracy=acceptance["minimum_category_accuracy"],
                policy_id=args.policy_id,
                policy_sha256=args.policy_sha256,
                controller_id=args.controller_id,
                controller_sha256=args.controller_sha256,
                authority_id=args.authority_id,
                critical_action=args.critical_action,
                review_sla_minutes=args.review_sla_minutes,
                signer_public_key_pem=signer_public,
                oscal_assessment_plan_href=args.oscal_ap_href,
            )
            print(
                f"LUREBOUNDARY PLAN CREATED: {plan['plan_id']} — {args.out}\n"
                f"suite sha256:{plan['benchmark']['suite_sha256']}\n"
                "boundary: synthetic evaluation evidence only; no enforcement is executed"
            )
            return 0

        if args.boundary_command == "append":
            signing_key = Path(args.signing_key).read_bytes() if args.signing_key else None
            entry = append_boundary_evaluation(
                Path(args.bundle),
                Path(args.evaluation),
                evaluation_id=args.evaluation_id,
                signing_key_pem=signing_key,
            )
            if args.json:
                print(json.dumps(entry, indent=2, sort_keys=True))
            else:
                print(
                    f"LUREBOUNDARY EVALUATION {entry['sequence']} APPENDED: "
                    f"{entry['decision']['boundary_status'].upper()} — {args.evaluation_id}"
                )
                print(f"required action: {entry['decision']['required_action']}")
                print("boundary: response is recorded for a human authority, never executed")
            return 1 if entry["decision"]["boundary_status"] == "breach" else 0

        public_key = Path(args.public_key).read_bytes() if args.public_key else None
        if args.boundary_command == "export-oscal":
            document = export_boundary_oscal(
                Path(args.bundle), Path(args.out), public_key_pem=public_key
            )
            status = document["assessment-results"]["results"][0]["props"][0]["value"]
            print(f"LUREBOUNDARY OSCAL EXPORTED: {status.upper()} — {args.out}")
            print("boundary: observations only; not a compliance or authorization decision")
            return 0

        result = verify_boundary_bundle(Path(args.bundle), public_key_pem=public_key)
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            authentication = "authenticated" if result["authenticated"] else "unsigned"
            print(
                f"LUREBOUNDARY VERIFIED: {result['boundary_status'].upper()} — "
                f"{result['entry_count']} checkpoints ({authentication})"
            )
            print(f"plan sha256:{result['plan_sha256']}")
            if result["latest_statement_sha256"]:
                print(f"latest checkpoint sha256:{result['latest_statement_sha256']}")
            print("boundary: integrity evidence is not proof of deployment containment")
        return 0
    except (
        FileExistsError,
        FileNotFoundError,
        ImportError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        print(f"! LureBoundary failed: {exc}", file=sys.stderr)
        return 2


def _boundary_watch(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lurescope boundary-watch",
        description="Anytime-valid monitoring for disjoint scheduled boundary canary batches.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    init_parser = commands.add_parser("init")
    init_parser.add_argument("--out", "-o", required=True)
    init_parser.add_argument("--plan-id", required=True)
    init_parser.add_argument("--monitor-id", required=True)
    init_parser.add_argument("--monitor-artifact-sha256")
    init_parser.add_argument("--coverage-manifest-id")
    init_parser.add_argument("--coverage-manifest-sha256")
    init_parser.add_argument("--probe-miss-limit", type=float, default=0.01)
    init_parser.add_argument("--benign-false-alarm-limit", type=float, default=0.01)
    init_parser.add_argument("--lineage-failure-limit", type=float, default=0.01)
    init_parser.add_argument("--duplicate-delivery-limit", type=float, default=0.01)
    init_parser.add_argument("--family-alpha", type=float, default=0.05)
    init_parser.add_argument("--signer-public-key")

    append_parser = commands.add_parser("append")
    append_parser.add_argument("bundle")
    append_parser.add_argument("--batch-id", required=True)
    append_parser.add_argument("--coverage-report", required=True)
    append_parser.add_argument("--boundary-evaluation", required=True)
    append_parser.add_argument("--observed-at")
    append_parser.add_argument("--signing-key")
    append_parser.add_argument("--json", action="store_true")

    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("bundle")
    verify_parser.add_argument("--public-key")
    verify_parser.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            from .boundary_watch import create_boundary_watch

            signer = Path(args.signer_public_key).read_bytes() if args.signer_public_key else None
            plan = create_boundary_watch(
                Path(args.out),
                plan_id=args.plan_id,
                monitor_id=args.monitor_id,
                monitor_artifact_sha256=args.monitor_artifact_sha256,
                coverage_manifest_id=args.coverage_manifest_id,
                coverage_manifest_sha256=args.coverage_manifest_sha256,
                maximum_probe_miss_rate=args.probe_miss_limit,
                maximum_benign_false_alarm_rate=args.benign_false_alarm_limit,
                maximum_lineage_failure_rate=args.lineage_failure_limit,
                maximum_duplicate_delivery_rate=args.duplicate_delivery_limit,
                family_alpha=args.family_alpha,
                signer_public_key_pem=signer,
            )
            print(
                f"BOUNDARYWATCH PLAN CREATED: {plan['plan_id']} — {args.out}\n"
                "boundary: only disjoint scheduled synthetic probe batches are eligible"
            )
            return 0
        if args.command == "append":
            from .boundary_watch import append_boundary_watch_batch

            key = Path(args.signing_key).read_bytes() if args.signing_key else None
            entry = append_boundary_watch_batch(
                Path(args.bundle),
                batch_id=args.batch_id,
                coverage_report=Path(args.coverage_report),
                boundary_evaluation=Path(args.boundary_evaluation),
                observed_at=args.observed_at,
                signing_key_pem=key,
            )
            if args.json:
                print(json.dumps(entry, indent=2, sort_keys=True))
            else:
                print(
                    f"BOUNDARYWATCH BATCH {entry['sequence']} APPENDED: "
                    f"{entry['family_status'].upper()} — {args.batch_id}"
                )
            return 1 if entry["family_status"] == "breach" else 0
        from .watch import verify_monitor_bundle

        key = Path(args.public_key).read_bytes() if args.public_key else None
        result = verify_monitor_bundle(Path(args.bundle), public_key_pem=key)
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(
                f"BOUNDARYWATCH VERIFIED: {result['family_status'].upper()} — "
                f"{result['entry_count']} checkpoints"
            )
        return 0
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! BoundaryWatch failed: {exc}", file=sys.stderr)
        return 2


def _agent_assurance(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lurescope agent-assurance",
        description="Create or verify a combined boundary, coverage, delegation, and IR portfolio.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    create_parser = commands.add_parser("create")
    create_parser.add_argument("--out", "-o", required=True)
    create_parser.add_argument("--portfolio-id", required=True)
    create_parser.add_argument("--system-id", required=True)
    create_parser.add_argument(
        "--environment",
        choices=("development", "evaluation", "staging", "production"),
        default="evaluation",
    )
    create_parser.add_argument("--boundary-bundle", required=True)
    create_parser.add_argument("--boundary-public-key")
    create_parser.add_argument("--coverage-report", required=True)
    create_parser.add_argument("--delegation-report", required=True)
    create_parser.add_argument("--incident-response-report", required=True)
    create_parser.add_argument("--signer-public-key")
    create_parser.add_argument("--signing-key")

    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("portfolio")
    verify_parser.add_argument("--boundary-bundle", required=True)
    verify_parser.add_argument("--boundary-public-key")
    verify_parser.add_argument("--portfolio-public-key")
    verify_parser.add_argument("--json", action="store_true")
    export_parser = commands.add_parser("export-oscal")
    export_parser.add_argument("portfolio")
    export_parser.add_argument("--boundary-bundle", required=True)
    export_parser.add_argument("--boundary-public-key")
    export_parser.add_argument("--portfolio-public-key")
    export_parser.add_argument("--assessment-plan-href", required=True)
    export_parser.add_argument("--out", "-o", required=True)
    args = parser.parse_args(argv)
    try:
        from .agent_assurance import (
            create_assurance_portfolio,
            export_assurance_oscal,
            verify_assurance_portfolio,
        )

        boundary_key = (
            Path(args.boundary_public_key).read_bytes() if args.boundary_public_key else None
        )
        if args.command == "create":
            signer_public = (
                Path(args.signer_public_key).read_bytes() if args.signer_public_key else None
            )
            signing_key = Path(args.signing_key).read_bytes() if args.signing_key else None
            portfolio = create_assurance_portfolio(
                Path(args.out),
                portfolio_id=args.portfolio_id,
                system_id=args.system_id,
                environment=args.environment,
                boundary_bundle=Path(args.boundary_bundle),
                boundary_public_key_pem=boundary_key,
                coverage_report=Path(args.coverage_report),
                delegation_report=Path(args.delegation_report),
                incident_response_report=Path(args.incident_response_report),
                signer_public_key_pem=signer_public,
                signing_key_pem=signing_key,
            )
            print(f"AGENT ASSURANCE PORTFOLIO: {portfolio['overall_status'].upper()} — {args.out}")
            print("boundary: combined evidence is not certification or authorization")
            return 0 if portfolio["overall_status"] == "pass" else 1
        portfolio_key = (
            Path(args.portfolio_public_key).read_bytes() if args.portfolio_public_key else None
        )
        if args.command == "export-oscal":
            document = export_assurance_oscal(
                Path(args.portfolio),
                Path(args.out),
                boundary_bundle=Path(args.boundary_bundle),
                assessment_plan_href=args.assessment_plan_href,
                boundary_public_key_pem=boundary_key,
                portfolio_public_key_pem=portfolio_key,
            )
            status = document["assessment-results"]["results"][0]["props"][0]["value"]
            print(f"AGENT ASSURANCE OSCAL EXPORTED: {status.upper()} — {args.out}")
            return 0
        result = verify_assurance_portfolio(
            Path(args.portfolio),
            boundary_bundle=Path(args.boundary_bundle),
            boundary_public_key_pem=boundary_key,
            portfolio_public_key_pem=portfolio_key,
        )
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(
                f"AGENT ASSURANCE VERIFIED: {result['overall_status'].upper()} — "
                f"sha256:{result['statement_sha256']}"
            )
        return 0
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! Agent assurance failed: {exc}", file=sys.stderr)
        return 2


def _witness(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lurescope witness",
        description="Create and verify offline independent checkpoint witness receipts.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    request_parser = commands.add_parser("request")
    request_parser.add_argument("bundle")
    request_parser.add_argument(
        "--kind", choices=("lureboundary", "lurewatch", "lurerevoke"), required=True
    )
    request_parser.add_argument("--public-key")
    request_parser.add_argument("--request-id")
    request_parser.add_argument("--nonce")
    request_parser.add_argument("--out", "-o", required=True)

    issue_parser = commands.add_parser("issue")
    issue_parser.add_argument("request")
    issue_parser.add_argument("--witness-id", required=True)
    issue_parser.add_argument("--signing-key", required=True)
    issue_parser.add_argument("--out", "-o", required=True)

    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("request")
    verify_parser.add_argument("receipt")
    verify_parser.add_argument("--public-key", required=True)
    verify_parser.add_argument("--bundle")
    verify_parser.add_argument("--bundle-public-key")
    verify_parser.add_argument("--json", action="store_true")

    quorum_parser = commands.add_parser("quorum")
    quorum_parser.add_argument("request")
    quorum_parser.add_argument("--receipt", action="append", required=True)
    quorum_parser.add_argument("--public-key", action="append", required=True)
    quorum_parser.add_argument("--minimum", type=int, required=True)
    quorum_parser.add_argument("--bundle")
    quorum_parser.add_argument("--bundle-public-key")
    quorum_parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        from .witness import (
            create_witness_request,
            issue_witness_receipt,
            verify_witness_quorum,
            verify_witness_receipt,
            verify_witness_request_binding,
        )

        if args.command in {"verify", "quorum"} and args.bundle_public_key and not args.bundle:
            raise ValueError("--bundle-public-key requires --bundle")

        if args.command == "request":
            key = Path(args.public_key).read_bytes() if args.public_key else None
            request = create_witness_request(
                Path(args.bundle),
                Path(args.out),
                bundle_kind=args.kind,
                public_key_pem=key,
                request_id=args.request_id,
                nonce=args.nonce,
            )
            print(
                f"WITNESS REQUEST CREATED: checkpoint "
                f"sha256:{request['checkpoint_statement_sha256']} — {args.out}"
            )
            return 0
        if args.command == "issue":
            receipt = issue_witness_receipt(
                Path(args.request),
                Path(args.out),
                witness_id=args.witness_id,
                signing_key_pem=Path(args.signing_key).read_bytes(),
            )
            print(f"WITNESS RECEIPT ISSUED: {receipt['witness']['witness_id']} — {args.out}")
            return 0
        if args.command == "verify":
            result = verify_witness_receipt(
                Path(args.request),
                Path(args.receipt),
                public_key_pem=Path(args.public_key).read_bytes(),
            )
        else:
            result = verify_witness_quorum(
                Path(args.request),
                [Path(path) for path in args.receipt],
                [Path(path).read_bytes() for path in args.public_key],
                minimum_witnesses=args.minimum,
            )
        if args.bundle:
            bundle_key = (
                Path(args.bundle_public_key).read_bytes() if args.bundle_public_key else None
            )
            verify_witness_request_binding(
                Path(args.request), Path(args.bundle), public_key_pem=bundle_key
            )
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"WITNESS VERIFIED: sha256:{result['checkpoint_statement_sha256']}")
        return 0
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! Witness workflow failed: {exc}", file=sys.stderr)
        return 2


def _invariant(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lurescope invariant",
        description=(
            "Preserve, authenticate, and compare independently recomputed "
            "LureInvariant graph and temporal evidence."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)

    create_parser = commands.add_parser(
        "create", help="create a new private invariant evidence bundle"
    )
    create_parser.add_argument("--plan", required=True)
    create_parser.add_argument("--observations", required=True)
    create_parser.add_argument("--evaluation", required=True)
    create_parser.add_argument("--bundle-id", required=True)
    create_parser.add_argument(
        "--environment",
        choices=("development", "evaluation", "staging", "production"),
        required=True,
    )
    create_parser.add_argument("--signer-public-key")
    create_parser.add_argument("--signing-key")
    create_parser.add_argument("--out", "-o", required=True)
    create_parser.add_argument("--json", action="store_true")

    verify_parser = commands.add_parser(
        "verify", help="verify a bundle and independently recompute every invariant"
    )
    verify_parser.add_argument("bundle")
    verify_parser.add_argument("--public-key")
    verify_parser.add_argument("--json", action="store_true")

    compare_parser = commands.add_parser(
        "compare", help="compare before/after bundles without allowing weaker checks"
    )
    compare_parser.add_argument("before")
    compare_parser.add_argument("after")
    compare_parser.add_argument("--comparison-id", required=True)
    compare_parser.add_argument("--before-public-key")
    compare_parser.add_argument("--after-public-key")
    compare_parser.add_argument("--out", "-o", required=True)
    compare_parser.add_argument("--json", action="store_true")

    comparison_parser = commands.add_parser(
        "verify-comparison", help="recompute a remediation comparison from both bundles"
    )
    comparison_parser.add_argument("comparison")
    comparison_parser.add_argument("before")
    comparison_parser.add_argument("after")
    comparison_parser.add_argument("--before-public-key")
    comparison_parser.add_argument("--after-public-key")
    comparison_parser.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)

    try:
        from .invariant import (
            compare_invariant_bundles,
            create_invariant_bundle,
            verify_invariant_bundle,
            verify_remediation_comparison,
        )

        before_key = (
            Path(args.before_public_key).read_bytes()
            if getattr(args, "before_public_key", None)
            else None
        )
        after_key = (
            Path(args.after_public_key).read_bytes()
            if getattr(args, "after_public_key", None)
            else None
        )
        if args.command == "create":
            public_key = (
                Path(args.signer_public_key).read_bytes() if args.signer_public_key else None
            )
            signing_key = Path(args.signing_key).read_bytes() if args.signing_key else None
            result = create_invariant_bundle(
                Path(args.out),
                bundle_id=args.bundle_id,
                environment=args.environment,
                plan=Path(args.plan),
                observations=Path(args.observations),
                evaluation=Path(args.evaluation),
                signer_public_key_pem=public_key,
                signing_key_pem=signing_key,
            )
            status = result["overall_status"]
            label = "INVARIANT BUNDLE CREATED"
            destination = args.out
        elif args.command == "verify":
            public_key = Path(args.public_key).read_bytes() if args.public_key else None
            verified = verify_invariant_bundle(Path(args.bundle), public_key_pem=public_key)
            result = {
                key: value for key, value in verified.items() if key not in {"plan", "evaluation"}
            }
            status = result["overall_status"]
            label = "INVARIANT BUNDLE VERIFIED"
            destination = args.bundle
        elif args.command == "compare":
            result = compare_invariant_bundles(
                Path(args.before),
                Path(args.after),
                Path(args.out),
                comparison_id=args.comparison_id,
                before_public_key_pem=before_key,
                after_public_key_pem=after_key,
            )
            status = result["summary"]["status"]
            label = "INVARIANT REMEDIATION COMPARED"
            destination = args.out
        else:
            result = verify_remediation_comparison(
                Path(args.comparison),
                Path(args.before),
                Path(args.after),
                before_public_key_pem=before_key,
                after_public_key_pem=after_key,
            )
            status = result["status"]
            label = "INVARIANT REMEDIATION VERIFIED"
            destination = args.comparison
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"{label}: {status.upper()} — {destination}")
        return 0 if status in {"pass", "effective"} else 1
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! Invariant evidence workflow failed: {exc}", file=sys.stderr)
        return 2


def _range_evidence(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lurescope range",
        description=(
            "Preserve, authenticate, and compare independently recomputed "
            "LurePermit/LureRange conformance evidence."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    create_parser = commands.add_parser(
        "create", help="create a private evidence bundle from a LureRange evaluation"
    )
    create_parser.add_argument("--evaluation", required=True)
    create_parser.add_argument("--bundle-id", required=True)
    create_parser.add_argument(
        "--environment",
        choices=("development", "evaluation", "staging", "production"),
        required=True,
    )
    create_parser.add_argument("--signer-public-key")
    create_parser.add_argument("--signing-key")
    create_parser.add_argument("--out", "-o", required=True)
    create_parser.add_argument("--json", action="store_true")

    verify_parser = commands.add_parser(
        "verify", help="verify a bundle and independently recompute suite semantics and metrics"
    )
    verify_parser.add_argument("bundle")
    verify_parser.add_argument("--public-key")
    verify_parser.add_argument("--json", action="store_true")

    compare_parser = commands.add_parser(
        "compare", help="compare before/after bundles under an identical conformance contract"
    )
    compare_parser.add_argument("before")
    compare_parser.add_argument("after")
    compare_parser.add_argument("--comparison-id", required=True)
    compare_parser.add_argument("--before-public-key")
    compare_parser.add_argument("--after-public-key")
    compare_parser.add_argument("--out", "-o", required=True)
    compare_parser.add_argument("--json", action="store_true")

    comparison_parser = commands.add_parser(
        "verify-comparison", help="recompute a comparison from both source bundles"
    )
    comparison_parser.add_argument("comparison")
    comparison_parser.add_argument("before")
    comparison_parser.add_argument("after")
    comparison_parser.add_argument("--before-public-key")
    comparison_parser.add_argument("--after-public-key")
    comparison_parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        from .permit import (
            compare_range_bundles,
            create_range_bundle,
            verify_range_bundle,
            verify_range_comparison,
        )

        before_key = (
            Path(args.before_public_key).read_bytes()
            if getattr(args, "before_public_key", None)
            else None
        )
        after_key = (
            Path(args.after_public_key).read_bytes()
            if getattr(args, "after_public_key", None)
            else None
        )
        if args.command == "create":
            public_key = (
                Path(args.signer_public_key).read_bytes() if args.signer_public_key else None
            )
            signing_key = Path(args.signing_key).read_bytes() if args.signing_key else None
            result = create_range_bundle(
                Path(args.out),
                bundle_id=args.bundle_id,
                environment=args.environment,
                evaluation=Path(args.evaluation),
                signer_public_key_pem=public_key,
                signing_key_pem=signing_key,
            )
            status = result["overall_status"]
            label = "LURERANGE BUNDLE CREATED"
            destination = args.out
        elif args.command == "verify":
            public_key = Path(args.public_key).read_bytes() if args.public_key else None
            verified = verify_range_bundle(Path(args.bundle), public_key_pem=public_key)
            result = {key: value for key, value in verified.items() if key != "report"}
            status = result["overall_status"]
            label = "LURERANGE BUNDLE VERIFIED"
            destination = args.bundle
        elif args.command == "compare":
            result = compare_range_bundles(
                Path(args.before),
                Path(args.after),
                Path(args.out),
                comparison_id=args.comparison_id,
                before_public_key_pem=before_key,
                after_public_key_pem=after_key,
            )
            status = result["summary"]["status"]
            label = "LURERANGE REMEDIATION COMPARED"
            destination = args.out
        else:
            result = verify_range_comparison(
                Path(args.comparison),
                Path(args.before),
                Path(args.after),
                before_public_key_pem=before_key,
                after_public_key_pem=after_key,
            )
            status = result["status"]
            label = "LURERANGE REMEDIATION VERIFIED"
            destination = args.comparison
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"{label}: {status.upper()} — {destination}")
            print("boundary: conformance evidence only; no runtime action or containment claim")
        return 0 if status in {"pass", "effective", "unchanged_pass"} else 1
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! LureRange evidence workflow failed: {exc}", file=sys.stderr)
        return 2


def _runtime_evidence(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lurescope runtime",
        description=(
            "Independently recompute, preserve, authenticate, compare, and export "
            "LurePermit runtime-mediation evidence."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    create_parser = commands.add_parser(
        "create", help="create a private bundle from a canonical runtime evaluation"
    )
    create_parser.add_argument("--evaluation", required=True)
    create_parser.add_argument("--bundle-id", required=True)
    create_parser.add_argument(
        "--environment",
        choices=("development", "evaluation", "staging", "production"),
        required=True,
    )
    create_parser.add_argument("--signer-public-key")
    create_parser.add_argument("--signing-key")
    create_parser.add_argument("--out", "-o", required=True)
    create_parser.add_argument("--json", action="store_true")

    verify_parser = commands.add_parser(
        "verify", help="verify a bundle and independently recompute all runtime metrics"
    )
    verify_parser.add_argument("bundle")
    verify_parser.add_argument("--public-key")
    verify_parser.add_argument("--json", action="store_true")

    compare_parser = commands.add_parser(
        "compare", help="compare before/after bundles under an unchanged runtime contract"
    )
    compare_parser.add_argument("before")
    compare_parser.add_argument("after")
    compare_parser.add_argument("--comparison-id", required=True)
    compare_parser.add_argument("--before-public-key")
    compare_parser.add_argument("--after-public-key")
    compare_parser.add_argument("--out", "-o", required=True)
    compare_parser.add_argument("--json", action="store_true")

    comparison_parser = commands.add_parser(
        "verify-comparison", help="recompute a comparison from both source bundles"
    )
    comparison_parser.add_argument("comparison")
    comparison_parser.add_argument("before")
    comparison_parser.add_argument("after")
    comparison_parser.add_argument("--before-public-key")
    comparison_parser.add_argument("--after-public-key")
    comparison_parser.add_argument("--json", action="store_true")

    oscal_parser = commands.add_parser(
        "export-oscal", help="export observation-only OSCAL 1.2.2 Assessment Results"
    )
    oscal_parser.add_argument("bundle")
    oscal_parser.add_argument("--assessment-plan-href", required=True)
    oscal_parser.add_argument("--public-key")
    oscal_parser.add_argument("--out", "-o", required=True)
    oscal_parser.add_argument("--json", action="store_true")

    sarif_parser = commands.add_parser(
        "export-sarif", help="export non-effective runtime outcomes as SARIF 2.1.0"
    )
    sarif_parser.add_argument("bundle")
    sarif_parser.add_argument("--public-key")
    sarif_parser.add_argument("--out", "-o", required=True)
    sarif_parser.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    try:
        from .runtime import (
            compare_runtime_bundles,
            create_runtime_bundle,
            export_runtime_oscal,
            export_runtime_sarif,
            verify_runtime_bundle,
            verify_runtime_comparison,
        )

        before_key = (
            Path(args.before_public_key).read_bytes()
            if getattr(args, "before_public_key", None)
            else None
        )
        after_key = (
            Path(args.after_public_key).read_bytes()
            if getattr(args, "after_public_key", None)
            else None
        )
        public_key = (
            Path(args.public_key).read_bytes() if getattr(args, "public_key", None) else None
        )
        if args.command == "create":
            signer_public = (
                Path(args.signer_public_key).read_bytes() if args.signer_public_key else None
            )
            signing_key = Path(args.signing_key).read_bytes() if args.signing_key else None
            result = create_runtime_bundle(
                Path(args.out),
                bundle_id=args.bundle_id,
                environment=args.environment,
                evaluation=Path(args.evaluation),
                signer_public_key_pem=signer_public,
                signing_key_pem=signing_key,
            )
            status = result["overall_status"]
            label, destination = "RUNTIME BUNDLE CREATED", args.out
        elif args.command == "verify":
            verified = verify_runtime_bundle(Path(args.bundle), public_key_pem=public_key)
            result = {key: value for key, value in verified.items() if key != "report"}
            status = result["overall_status"]
            label, destination = "RUNTIME BUNDLE VERIFIED", args.bundle
        elif args.command == "compare":
            result = compare_runtime_bundles(
                Path(args.before),
                Path(args.after),
                Path(args.out),
                comparison_id=args.comparison_id,
                before_public_key_pem=before_key,
                after_public_key_pem=after_key,
            )
            status = result["summary"]["status"]
            label, destination = "RUNTIME REMEDIATION COMPARED", args.out
        elif args.command == "verify-comparison":
            result = verify_runtime_comparison(
                Path(args.comparison),
                Path(args.before),
                Path(args.after),
                before_public_key_pem=before_key,
                after_public_key_pem=after_key,
            )
            status = result["status"]
            label, destination = "RUNTIME REMEDIATION VERIFIED", args.comparison
        elif args.command == "export-oscal":
            result = export_runtime_oscal(
                Path(args.bundle),
                Path(args.out),
                assessment_plan_href=args.assessment_plan_href,
                public_key_pem=public_key,
            )
            status = "written"
            label, destination = "RUNTIME OSCAL EXPORTED", args.out
        else:
            result = export_runtime_sarif(
                Path(args.bundle), Path(args.out), public_key_pem=public_key
            )
            status = "written"
            label, destination = "RUNTIME SARIF EXPORTED", args.out
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"{label}: {status.upper()} — {destination}")
            print(
                "boundary: evidence integrity only; no action execution, complete-observation, "
                "or compliance claim"
            )
        return 0 if status in {"pass", "effective", "unchanged_pass", "written"} else 1
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! Runtime evidence workflow failed: {exc}", file=sys.stderr)
        return 2


def _revocation_evidence(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lurescope revoke",
        description=(
            "Independently recompute, bind, sign, and export LureRevoke convergence evidence."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    create_parser = commands.add_parser("create", help="create a private evidence bundle")
    create_parser.add_argument("--evaluation", required=True)
    create_parser.add_argument("--bundle-id", required=True)
    create_parser.add_argument(
        "--environment",
        choices=("development", "evaluation", "staging", "production"),
        required=True,
    )
    create_parser.add_argument("--signer-public-key")
    create_parser.add_argument("--signing-key")
    create_parser.add_argument("--out", "-o", required=True)
    create_parser.add_argument("--json", action="store_true")

    verify_parser = commands.add_parser(
        "verify", help="verify exact bytes, independent metrics, and optional signature"
    )
    verify_parser.add_argument("bundle")
    verify_parser.add_argument("--public-key")
    verify_parser.add_argument("--json", action="store_true")

    topology_parser = commands.add_parser(
        "verify-topology", help="independently recompute a revocation/runtime scope audit"
    )
    topology_parser.add_argument("audit")
    topology_parser.add_argument("--json", action="store_true")

    otel_parser = commands.add_parser(
        "verify-otel", help="independently recompute a body-free OpenTelemetry projection"
    )
    otel_parser.add_argument("projection")
    otel_parser.add_argument("--json", action="store_true")

    gate_parser = commands.add_parser(
        "gate", help="bind topology, body-free telemetry, and signed convergence evidence"
    )
    gate_parser.add_argument("topology_audit")
    gate_parser.add_argument("otel_projection")
    gate_parser.add_argument("bundle")
    gate_parser.add_argument("--bundle-public-key", required=True)
    gate_parser.add_argument("--expected-bundle-key-id", required=True)
    gate_parser.add_argument("--maximum-allowed-convergence-ms", type=int, required=True)
    gate_parser.add_argument("--minimum-run-generated-at", required=True)
    gate_parser.add_argument("--expected-system-id", required=True)
    gate_parser.add_argument(
        "--expected-environment",
        choices=("development", "evaluation", "staging", "production"),
        required=True,
    )
    gate_parser.add_argument("--expected-receiver-name", required=True)
    gate_parser.add_argument("--expected-receiver-artifact-sha256", required=True)
    gate_parser.add_argument("--gate-id", required=True)
    gate_parser.add_argument("--created-at")
    gate_parser.add_argument("--out", "-o", required=True)
    gate_parser.add_argument("--json", action="store_true")

    verify_gate_parser = commands.add_parser(
        "verify-gate", help="recompute a deployment gate from all three exact sources"
    )
    verify_gate_parser.add_argument("gate")
    verify_gate_parser.add_argument("topology_audit")
    verify_gate_parser.add_argument("otel_projection")
    verify_gate_parser.add_argument("bundle")
    verify_gate_parser.add_argument("--bundle-public-key", required=True)
    verify_gate_parser.add_argument("--expected-bundle-key-id", required=True)
    verify_gate_parser.add_argument("--maximum-allowed-convergence-ms", type=int, required=True)
    verify_gate_parser.add_argument("--minimum-run-generated-at", required=True)
    verify_gate_parser.add_argument("--expected-system-id", required=True)
    verify_gate_parser.add_argument(
        "--expected-environment",
        choices=("development", "evaluation", "staging", "production"),
        required=True,
    )
    verify_gate_parser.add_argument("--expected-receiver-name", required=True)
    verify_gate_parser.add_argument("--expected-receiver-artifact-sha256", required=True)
    verify_gate_parser.add_argument("--json", action="store_true")

    compare_parser = commands.add_parser(
        "compare", help="compare before/after bundles under an identical revocation plan"
    )
    compare_parser.add_argument("before")
    compare_parser.add_argument("after")
    compare_parser.add_argument("--comparison-id", required=True)
    compare_parser.add_argument("--before-public-key")
    compare_parser.add_argument("--after-public-key")
    compare_parser.add_argument("--out", "-o", required=True)
    compare_parser.add_argument("--json", action="store_true")

    comparison_parser = commands.add_parser(
        "verify-comparison", help="recompute a comparison from both exact source bundles"
    )
    comparison_parser.add_argument("comparison")
    comparison_parser.add_argument("before")
    comparison_parser.add_argument("after")
    comparison_parser.add_argument("--before-public-key")
    comparison_parser.add_argument("--after-public-key")
    comparison_parser.add_argument("--json", action="store_true")

    registry_init = commands.add_parser(
        "registry-init", help="initialize a signed same-system revocation history"
    )
    registry_init.add_argument("--registry-id", required=True)
    registry_init.add_argument("--system-id", required=True)
    registry_init.add_argument(
        "--environment",
        choices=("development", "evaluation", "staging", "production"),
        required=True,
    )
    registry_init.add_argument("--receiver-name", required=True)
    registry_init.add_argument("--signer-public-key", required=True)
    registry_init.add_argument("--out", "-o", required=True)
    registry_init.add_argument("--json", action="store_true")

    registry_append = commands.add_parser(
        "registry-append", help="verify and append a signed LureRevoke bundle"
    )
    registry_append.add_argument("registry")
    registry_append.add_argument("bundle")
    registry_append.add_argument("--registry-public-key", required=True)
    registry_append.add_argument("--registry-signing-key", required=True)
    registry_append.add_argument("--bundle-public-key", required=True)
    registry_append.add_argument("--registered-at")
    registry_append.add_argument("--json", action="store_true")

    registry_verify = commands.add_parser(
        "registry-verify", help="recompute Merkle history and authenticate every tree head"
    )
    registry_verify.add_argument("registry")
    registry_verify.add_argument("--registry-public-key", required=True)
    registry_verify.add_argument("--trusted-head-statement")
    registry_verify.add_argument("--trusted-head-dsse")
    registry_verify.add_argument("--json", action="store_true")

    registry_prove = commands.add_parser(
        "registry-prove-inclusion",
        help="export one entry with a portable authenticated Merkle inclusion proof",
    )
    registry_prove.add_argument("registry")
    registry_prove.add_argument("--sequence", type=int, required=True)
    registry_prove.add_argument("--tree-size", type=int)
    registry_prove.add_argument("--registry-public-key", required=True)
    registry_prove.add_argument("--out", "-o", required=True)
    registry_prove.add_argument("--json", action="store_true")

    registry_verify_inclusion = commands.add_parser(
        "registry-verify-inclusion",
        help="verify a portable entry proof without receiving the full registry",
    )
    registry_verify_inclusion.add_argument("proof")
    registry_verify_inclusion.add_argument("--registry-public-key", required=True)
    registry_verify_inclusion.add_argument("--json", action="store_true")

    registry_consistency = commands.add_parser(
        "registry-prove-consistency",
        help="export an authenticated proof that a later tree extends an earlier tree",
    )
    registry_consistency.add_argument("registry")
    registry_consistency.add_argument("--first-tree-size", type=int, required=True)
    registry_consistency.add_argument("--second-tree-size", type=int)
    registry_consistency.add_argument("--registry-public-key", required=True)
    registry_consistency.add_argument("--out", "-o", required=True)
    registry_consistency.add_argument("--json", action="store_true")

    registry_verify_consistency = commands.add_parser(
        "registry-verify-consistency",
        help="verify two signed heads and their portable append-only proof",
    )
    registry_verify_consistency.add_argument("proof")
    registry_verify_consistency.add_argument("--registry-public-key", required=True)
    registry_verify_consistency.add_argument("--json", action="store_true")

    registry_compare_heads = commands.add_parser(
        "registry-compare-heads",
        help="authenticate two exchanged heads and detect same-size equivocation",
    )
    registry_compare_heads.add_argument("--registry-config", required=True)
    registry_compare_heads.add_argument("--first-statement", required=True)
    registry_compare_heads.add_argument("--first-dsse", required=True)
    registry_compare_heads.add_argument("--second-statement", required=True)
    registry_compare_heads.add_argument("--second-dsse", required=True)
    registry_compare_heads.add_argument("--registry-public-key", required=True)
    registry_compare_heads.add_argument("--out", "-o", required=True)
    registry_compare_heads.add_argument("--json", action="store_true")

    registry_verify_heads = commands.add_parser(
        "registry-verify-head-comparison",
        help="recompute a portable dual-head comparison and both signatures",
    )
    registry_verify_heads.add_argument("comparison")
    registry_verify_heads.add_argument("--registry-public-key", required=True)
    registry_verify_heads.add_argument("--json", action="store_true")

    oscal_parser = commands.add_parser(
        "export-oscal", help="export observation-only OSCAL 1.2.2 Assessment Results"
    )
    oscal_parser.add_argument("bundle")
    oscal_parser.add_argument("--assessment-plan-href", required=True)
    oscal_parser.add_argument("--public-key")
    oscal_parser.add_argument("--out", "-o", required=True)
    oscal_parser.add_argument("--json", action="store_true")

    sarif_parser = commands.add_parser(
        "export-sarif", help="export revocation failures as SARIF 2.1.0"
    )
    sarif_parser.add_argument("bundle")
    sarif_parser.add_argument("--public-key")
    sarif_parser.add_argument("--out", "-o", required=True)
    sarif_parser.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    try:
        from .revocation import (
            compare_revocation_bundles,
            create_revocation_bundle,
            export_revocation_oscal,
            export_revocation_sarif,
            verify_revocation_bundle,
            verify_revocation_comparison,
        )
        from .revocation_registry import (
            append_revocation_registry,
            compare_revocation_tree_heads,
            create_revocation_consistency_proof,
            create_revocation_inclusion_proof,
            create_revocation_registry,
            verify_revocation_consistency_proof,
            verify_revocation_head_comparison,
            verify_revocation_inclusion_proof,
            verify_revocation_registry,
        )
        from .revocation_topology import load_revocation_topology_audit

        public_key = (
            Path(args.public_key).read_bytes() if getattr(args, "public_key", None) else None
        )
        before_key = (
            Path(args.before_public_key).read_bytes()
            if getattr(args, "before_public_key", None)
            else None
        )
        after_key = (
            Path(args.after_public_key).read_bytes()
            if getattr(args, "after_public_key", None)
            else None
        )
        if args.command == "verify-topology":
            report = load_revocation_topology_audit(Path(args.audit))
            result = {
                "valid": True,
                "revocation_plan_sha256": report["inputs"]["revocation_plan_sha256"],
                "runtime_profile_sha256": report["inputs"]["runtime_profile_sha256"],
                "summary": report["summary"],
                "limitations": report["limitations"],
            }
            status = report["summary"]["verdict"]
            label, destination = "LUREREVOKE TOPOLOGY VERIFIED", args.audit
        elif args.command == "verify-otel":
            from .revocation_otel import load_otel_revocation_projection

            report = load_otel_revocation_projection(Path(args.projection))
            result = {
                "valid": True,
                "plan_sha256": report["inputs"]["revocation_plan_sha256"],
                "otel_log_export_sha256": report["inputs"]["otel_log_export_sha256"],
                "run_sha256": report["run_sha256"],
                "record_count": len(report["inputs"]["otel_log_export"]["records"]),
                "limitations": report["limitations"],
            }
            status = "verified"
            label, destination = "LUREREVOKE OTEL VERIFIED", args.projection
        elif args.command == "gate":
            from .revocation_gate import create_revocation_deployment_gate

            result = create_revocation_deployment_gate(
                Path(args.topology_audit),
                Path(args.otel_projection),
                Path(args.bundle),
                Path(args.out),
                gate_id=args.gate_id,
                bundle_public_key_pem=Path(args.bundle_public_key).read_bytes(),
                expected_bundle_key_id=args.expected_bundle_key_id,
                maximum_allowed_convergence_ms=args.maximum_allowed_convergence_ms,
                minimum_run_generated_at=args.minimum_run_generated_at,
                expected_system_id=args.expected_system_id,
                expected_environment=args.expected_environment,
                expected_receiver_name=args.expected_receiver_name,
                expected_receiver_artifact_sha256=args.expected_receiver_artifact_sha256,
                created_at=args.created_at,
            )
            status = result["overall_status"]
            label, destination = "LUREREVOKE DEPLOYMENT GATE CREATED", args.out
        elif args.command == "verify-gate":
            from .revocation_gate import verify_revocation_deployment_gate

            result = verify_revocation_deployment_gate(
                Path(args.gate),
                Path(args.topology_audit),
                Path(args.otel_projection),
                Path(args.bundle),
                bundle_public_key_pem=Path(args.bundle_public_key).read_bytes(),
                expected_bundle_key_id=args.expected_bundle_key_id,
                maximum_allowed_convergence_ms=args.maximum_allowed_convergence_ms,
                minimum_run_generated_at=args.minimum_run_generated_at,
                expected_system_id=args.expected_system_id,
                expected_environment=args.expected_environment,
                expected_receiver_name=args.expected_receiver_name,
                expected_receiver_artifact_sha256=args.expected_receiver_artifact_sha256,
            )
            status = result["overall_status"]
            label, destination = "LUREREVOKE DEPLOYMENT GATE VERIFIED", args.gate
        elif args.command == "create":
            signer_public = (
                Path(args.signer_public_key).read_bytes() if args.signer_public_key else None
            )
            signing_key = Path(args.signing_key).read_bytes() if args.signing_key else None
            result = create_revocation_bundle(
                Path(args.out),
                bundle_id=args.bundle_id,
                environment=args.environment,
                evaluation=Path(args.evaluation),
                signer_public_key_pem=signer_public,
                signing_key_pem=signing_key,
            )
            status = result["overall_status"]
            label, destination = "LUREREVOKE BUNDLE CREATED", args.out
        elif args.command == "verify":
            verified = verify_revocation_bundle(Path(args.bundle), public_key_pem=public_key)
            result = {key: value for key, value in verified.items() if key != "report"}
            status = result["overall_status"]
            label, destination = "LUREREVOKE BUNDLE VERIFIED", args.bundle
        elif args.command == "compare":
            result = compare_revocation_bundles(
                Path(args.before),
                Path(args.after),
                Path(args.out),
                comparison_id=args.comparison_id,
                before_public_key_pem=before_key,
                after_public_key_pem=after_key,
            )
            status = result["summary"]["status"]
            label, destination = "LUREREVOKE REMEDIATION COMPARED", args.out
        elif args.command == "verify-comparison":
            result = verify_revocation_comparison(
                Path(args.comparison),
                Path(args.before),
                Path(args.after),
                before_public_key_pem=before_key,
                after_public_key_pem=after_key,
            )
            status = result["status"]
            label, destination = "LUREREVOKE REMEDIATION VERIFIED", args.comparison
        elif args.command == "registry-init":
            result = create_revocation_registry(
                Path(args.out),
                registry_id=args.registry_id,
                system_id=args.system_id,
                environment=args.environment,
                receiver_name=args.receiver_name,
                signer_public_key_pem=Path(args.signer_public_key).read_bytes(),
            )
            status = "initialized"
            label, destination = "LUREREVOKE REGISTRY INITIALIZED", args.out
        elif args.command == "registry-append":
            result = append_revocation_registry(
                Path(args.registry),
                Path(args.bundle),
                registry_public_key_pem=Path(args.registry_public_key).read_bytes(),
                registry_signing_key_pem=Path(args.registry_signing_key).read_bytes(),
                bundle_public_key_pem=Path(args.bundle_public_key).read_bytes(),
                registered_at=args.registered_at,
            )
            status = "appended"
            label, destination = "LUREREVOKE REGISTRY APPENDED", args.registry
        elif args.command == "registry-verify":
            result = verify_revocation_registry(
                Path(args.registry),
                public_key_pem=Path(args.registry_public_key).read_bytes(),
                trusted_head_statement=(
                    Path(args.trusted_head_statement) if args.trusted_head_statement else None
                ),
                trusted_head_dsse=(
                    Path(args.trusted_head_dsse) if args.trusted_head_dsse else None
                ),
            )
            status = "verified"
            label, destination = "LUREREVOKE REGISTRY VERIFIED", args.registry
        elif args.command == "registry-prove-inclusion":
            result = create_revocation_inclusion_proof(
                Path(args.registry),
                Path(args.out),
                sequence=args.sequence,
                tree_size=args.tree_size,
                public_key_pem=Path(args.registry_public_key).read_bytes(),
            )
            status = "written"
            label, destination = "LUREREVOKE INCLUSION PROOF CREATED", args.out
        elif args.command == "registry-verify-inclusion":
            result = verify_revocation_inclusion_proof(
                Path(args.proof),
                public_key_pem=Path(args.registry_public_key).read_bytes(),
            )
            status = "verified"
            label, destination = "LUREREVOKE INCLUSION PROOF VERIFIED", args.proof
        elif args.command == "registry-prove-consistency":
            result = create_revocation_consistency_proof(
                Path(args.registry),
                Path(args.out),
                first_tree_size=args.first_tree_size,
                second_tree_size=args.second_tree_size,
                public_key_pem=Path(args.registry_public_key).read_bytes(),
            )
            status = "written"
            label, destination = "LUREREVOKE CONSISTENCY PROOF CREATED", args.out
        elif args.command == "registry-verify-consistency":
            result = verify_revocation_consistency_proof(
                Path(args.proof),
                public_key_pem=Path(args.registry_public_key).read_bytes(),
            )
            status = "verified"
            label, destination = "LUREREVOKE CONSISTENCY PROOF VERIFIED", args.proof
        elif args.command == "registry-compare-heads":
            result = compare_revocation_tree_heads(
                Path(args.registry_config),
                Path(args.first_statement),
                Path(args.first_dsse),
                Path(args.second_statement),
                Path(args.second_dsse),
                Path(args.out),
                public_key_pem=Path(args.registry_public_key).read_bytes(),
            )
            status = result["summary"]["status"]
            label, destination = "LUREREVOKE TREE HEADS COMPARED", args.out
        elif args.command == "registry-verify-head-comparison":
            result = verify_revocation_head_comparison(
                Path(args.comparison),
                public_key_pem=Path(args.registry_public_key).read_bytes(),
            )
            status = result["summary"]["status"]
            label, destination = "LUREREVOKE TREE HEAD COMPARISON VERIFIED", args.comparison
        elif args.command == "export-oscal":
            result = export_revocation_oscal(
                Path(args.bundle),
                Path(args.out),
                assessment_plan_href=args.assessment_plan_href,
                public_key_pem=public_key,
            )
            status = "written"
            label, destination = "LUREREVOKE OSCAL EXPORTED", args.out
        else:
            result = export_revocation_sarif(
                Path(args.bundle), Path(args.out), public_key_pem=public_key
            )
            status = "written"
            label, destination = "LUREREVOKE SARIF EXPORTED", args.out
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"{label}: {status.upper()} — {destination}")
            print(
                "boundary: evidence integrity only; no signal, receiver, clock, enforcement, "
                "or compliance authenticity claim"
            )
        return (
            0
            if status
            in {
                "pass",
                "effective",
                "unchanged_pass",
                "written",
                "initialized",
                "appended",
                "verified",
                "identical",
            }
            else 1
        )
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! LureRevoke evidence workflow failed: {exc}", file=sys.stderr)
        return 2


def _identity_evidence(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lurescope identity",
        description=(
            "Independently recompute, bind, sign, and export LureIdentity lifecycle evidence."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    create_parser = commands.add_parser("create", help="create a private evidence bundle")
    create_parser.add_argument("--evaluation", required=True)
    create_parser.add_argument("--bundle-id", required=True)
    create_parser.add_argument(
        "--environment",
        choices=("development", "evaluation", "staging", "production"),
        required=True,
    )
    create_parser.add_argument("--signer-public-key")
    create_parser.add_argument("--signing-key")
    create_parser.add_argument("--out", "-o", required=True)
    create_parser.add_argument("--json", action="store_true")

    verify_parser = commands.add_parser(
        "verify", help="verify exact bytes, graph closure, metrics, and optional signature"
    )
    verify_parser.add_argument("bundle")
    verify_parser.add_argument("--public-key")
    verify_parser.add_argument("--json", action="store_true")

    campaign_parser = commands.add_parser(
        "verify-campaign",
        help="independently derive a campaign plan and require exact byte-equivalent content",
    )
    campaign_parser.add_argument("campaign")
    campaign_parser.add_argument("plan")
    campaign_parser.add_argument("--verified-at")
    campaign_parser.add_argument("--out", "-o")
    campaign_parser.add_argument("--json", action="store_true")

    topology_parser = commands.add_parser(
        "verify-topology", help="independently recompute an identity/runtime scope audit"
    )
    topology_parser.add_argument("audit")
    topology_parser.add_argument("--json", action="store_true")

    otel_parser = commands.add_parser(
        "verify-otel", help="independently recompute a body-free OpenTelemetry projection"
    )
    otel_parser.add_argument("projection")
    otel_parser.add_argument("--json", action="store_true")

    gate_parser = commands.add_parser(
        "gate",
        help="bind identity/artifact compiler proofs, topology, telemetry, and signed evidence",
    )
    gate_parser.add_argument("campaign_verification")
    gate_parser.add_argument("artifact_verification")
    gate_parser.add_argument("topology_audit")
    gate_parser.add_argument("otel_projection")
    gate_parser.add_argument("bundle")
    gate_parser.add_argument("--bundle-public-key", required=True)
    gate_parser.add_argument("--expected-bundle-key-id", required=True)
    gate_parser.add_argument("--maximum-allowed-convergence-ms", type=int, required=True)
    gate_parser.add_argument("--minimum-run-generated-at", required=True)
    gate_parser.add_argument("--expected-system-id", required=True)
    gate_parser.add_argument(
        "--expected-environment",
        choices=("development", "evaluation", "staging", "production"),
        required=True,
    )
    gate_parser.add_argument("--expected-receiver-name", required=True)
    gate_parser.add_argument("--expected-receiver-artifact-sha256", required=True)
    gate_parser.add_argument("--gate-id", required=True)
    gate_parser.add_argument("--created-at")
    gate_parser.add_argument("--out", "-o", required=True)
    gate_parser.add_argument("--json", action="store_true")

    verify_gate_parser = commands.add_parser(
        "verify-gate", help="recompute a deployment gate from all five exact sources"
    )
    verify_gate_parser.add_argument("gate")
    verify_gate_parser.add_argument("campaign_verification")
    verify_gate_parser.add_argument("artifact_verification")
    verify_gate_parser.add_argument("topology_audit")
    verify_gate_parser.add_argument("otel_projection")
    verify_gate_parser.add_argument("bundle")
    verify_gate_parser.add_argument("--bundle-public-key", required=True)
    verify_gate_parser.add_argument("--expected-bundle-key-id", required=True)
    verify_gate_parser.add_argument("--maximum-allowed-convergence-ms", type=int, required=True)
    verify_gate_parser.add_argument("--minimum-run-generated-at", required=True)
    verify_gate_parser.add_argument("--expected-system-id", required=True)
    verify_gate_parser.add_argument(
        "--expected-environment",
        choices=("development", "evaluation", "staging", "production"),
        required=True,
    )
    verify_gate_parser.add_argument("--expected-receiver-name", required=True)
    verify_gate_parser.add_argument("--expected-receiver-artifact-sha256", required=True)
    verify_gate_parser.add_argument("--json", action="store_true")

    oscal_parser = commands.add_parser(
        "export-oscal", help="export observation-only OSCAL assessment results"
    )
    oscal_parser.add_argument("bundle")
    oscal_parser.add_argument("--assessment-plan-href", required=True)
    oscal_parser.add_argument("--public-key")
    oscal_parser.add_argument("--out", "-o", required=True)
    oscal_parser.add_argument("--json", action="store_true")

    sarif_parser = commands.add_parser(
        "export-sarif", help="export lifecycle closure failures as SARIF"
    )
    sarif_parser.add_argument("bundle")
    sarif_parser.add_argument("--public-key")
    sarif_parser.add_argument("--out", "-o", required=True)
    sarif_parser.add_argument("--json", action="store_true")

    args = parser.parse_args(list(argv))
    try:
        from .identity import (
            create_identity_bundle,
            export_identity_oscal,
            export_identity_sarif,
            verify_identity_bundle,
        )

        public_key = (
            Path(args.public_key).read_bytes() if getattr(args, "public_key", None) else None
        )
        if args.command == "verify-campaign":
            from .identity_campaign import create_identity_campaign_verification

            result = create_identity_campaign_verification(
                Path(args.campaign),
                Path(args.plan),
                Path(args.out) if args.out else None,
                verified_at=args.verified_at,
            )
            status = result["overall_status"]
            label = "LUREIDENTITY CAMPAIGN VERIFIED"
            destination = args.out or args.plan
        elif args.command == "verify-topology":
            from .identity_topology import load_identity_topology_audit

            report = load_identity_topology_audit(Path(args.audit))
            result = {
                "valid": True,
                "identity_plan_sha256": report["inputs"]["identity_plan_sha256"],
                "runtime_profile_sha256": report["inputs"]["runtime_profile_sha256"],
                "summary": report["summary"],
                "limitations": report["limitations"],
            }
            status = report["summary"]["verdict"]
            label, destination = "LUREIDENTITY TOPOLOGY VERIFIED", args.audit
        elif args.command == "verify-otel":
            from .identity_otel import load_identity_otel_projection

            report = load_identity_otel_projection(Path(args.projection))
            result = {
                "valid": True,
                "plan_sha256": report["inputs"]["identity_plan_sha256"],
                "otel_log_export_sha256": report["inputs"]["otel_log_export_sha256"],
                "run_sha256": report["run_sha256"],
                "record_count": len(report["inputs"]["otel_log_export"]["records"]),
                "limitations": report["limitations"],
            }
            status = "verified"
            label, destination = "LUREIDENTITY OTEL VERIFIED", args.projection
        elif args.command == "gate":
            from .identity_gate import create_identity_deployment_gate

            result = create_identity_deployment_gate(
                Path(args.campaign_verification),
                Path(args.artifact_verification),
                Path(args.topology_audit),
                Path(args.otel_projection),
                Path(args.bundle),
                Path(args.out),
                gate_id=args.gate_id,
                bundle_public_key_pem=Path(args.bundle_public_key).read_bytes(),
                expected_bundle_key_id=args.expected_bundle_key_id,
                maximum_allowed_convergence_ms=args.maximum_allowed_convergence_ms,
                minimum_run_generated_at=args.minimum_run_generated_at,
                expected_system_id=args.expected_system_id,
                expected_environment=args.expected_environment,
                expected_receiver_name=args.expected_receiver_name,
                expected_receiver_artifact_sha256=args.expected_receiver_artifact_sha256,
                created_at=args.created_at,
            )
            status = result["overall_status"]
            label, destination = "LUREIDENTITY DEPLOYMENT GATE CREATED", args.out
        elif args.command == "verify-gate":
            from .identity_gate import verify_identity_deployment_gate

            result = verify_identity_deployment_gate(
                Path(args.gate),
                Path(args.campaign_verification),
                Path(args.artifact_verification),
                Path(args.topology_audit),
                Path(args.otel_projection),
                Path(args.bundle),
                bundle_public_key_pem=Path(args.bundle_public_key).read_bytes(),
                expected_bundle_key_id=args.expected_bundle_key_id,
                maximum_allowed_convergence_ms=args.maximum_allowed_convergence_ms,
                minimum_run_generated_at=args.minimum_run_generated_at,
                expected_system_id=args.expected_system_id,
                expected_environment=args.expected_environment,
                expected_receiver_name=args.expected_receiver_name,
                expected_receiver_artifact_sha256=args.expected_receiver_artifact_sha256,
            )
            status = result["overall_status"]
            label, destination = "LUREIDENTITY DEPLOYMENT GATE VERIFIED", args.gate
        elif args.command == "create":
            signer_public = (
                Path(args.signer_public_key).read_bytes() if args.signer_public_key else None
            )
            signing_key = Path(args.signing_key).read_bytes() if args.signing_key else None
            result = create_identity_bundle(
                Path(args.out),
                bundle_id=args.bundle_id,
                environment=args.environment,
                evaluation=Path(args.evaluation),
                signer_public_key_pem=signer_public,
                signing_key_pem=signing_key,
            )
            status = result["overall_status"]
            label, destination = "LUREIDENTITY BUNDLE CREATED", args.out
        elif args.command == "verify":
            verified = verify_identity_bundle(Path(args.bundle), public_key_pem=public_key)
            result = {key: value for key, value in verified.items() if key != "report"}
            status = result["overall_status"]
            label, destination = "LUREIDENTITY BUNDLE VERIFIED", args.bundle
        elif args.command == "export-oscal":
            result = export_identity_oscal(
                Path(args.bundle),
                Path(args.out),
                assessment_plan_href=args.assessment_plan_href,
                public_key_pem=public_key,
            )
            status = "written"
            label, destination = "LUREIDENTITY OSCAL EXPORTED", args.out
        else:
            result = export_identity_sarif(
                Path(args.bundle), Path(args.out), public_key_pem=public_key
            )
            status = "written"
            label, destination = "LUREIDENTITY SARIF EXPORTED", args.out
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"{label}: {status.upper()} — {destination}")
            print(
                "boundary: evidence integrity only; no identity, directory, clock, mediation, "
                "enforcement, or compliance authenticity claim"
            )
        return 0 if status in {"pass", "verified", "written"} else 1
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! LureIdentity evidence workflow failed: {exc}", file=sys.stderr)
        return 2


def _artifact_evidence(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lurescope artifact",
        description=(
            "Independently recompile and verify workload-to-model, image, policy, "
            "AI-BOM, and SLSA provenance bindings without loading artifact bytes."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    verify_parser = commands.add_parser(
        "verify",
        help="rederive the identity/artifact plans and producer evaluation from exact sources",
    )
    verify_parser.add_argument("identity_campaign_verification")
    verify_parser.add_argument("artifact_campaign")
    verify_parser.add_argument("artifact_plan")
    verify_parser.add_argument("observation")
    verify_parser.add_argument("evaluation")
    verify_parser.add_argument("--verified-at")
    verify_parser.add_argument("--out", "-o", required=True)
    verify_parser.add_argument("--json", action="store_true")

    check_parser = commands.add_parser(
        "check", help="strictly parse and independently recompute a saved verification"
    )
    check_parser.add_argument("verification")
    check_parser.add_argument("--json", action="store_true")

    args = parser.parse_args(list(argv))
    try:
        if args.command == "verify":
            from .artifact import create_artifact_verification

            result = create_artifact_verification(
                Path(args.identity_campaign_verification),
                Path(args.artifact_campaign),
                Path(args.artifact_plan),
                Path(args.observation),
                Path(args.evaluation),
                Path(args.out),
                verified_at=args.verified_at,
            )
            destination = args.out
        else:
            from .artifact import load_artifact_verification

            result = load_artifact_verification(Path(args.verification))
            destination = args.verification
        status = result["overall_status"]
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            summary = result["summary"]
            print(
                f"LUREARTIFACT INDEPENDENT VERIFICATION: {status.upper()} — "
                f"workloads={summary['active_workload_count']} "
                f"deployments={summary['deployment_count']} "
                f"artifact-bindings={summary['artifact_binding_count']} "
                f"findings={summary['finding_count']} — {destination}"
            )
            print(
                "boundary: exact declared metadata recomputation only; no artifact loading, "
                "builder authentication, observation completeness, or safety claim"
            )
        return 0 if status == "pass" else 1
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! LureArtifact verification failed: {exc}", file=sys.stderr)
        return 2


def _recall_evidence(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lurescope recall",
        description=(
            "Independently rederive transitive AI-artifact blast radius, advisory delivery, "
            "quarantine, exact replacement recovery, and collateral controls."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    verify_parser = commands.add_parser(
        "verify",
        help="rederive the plan and producer evaluation from six exact source artifacts",
    )
    verify_parser.add_argument("artifact_plan")
    verify_parser.add_argument("lineage")
    verify_parser.add_argument("advisory")
    verify_parser.add_argument("plan")
    verify_parser.add_argument("run")
    verify_parser.add_argument("evaluation")
    verify_parser.add_argument("--verified-at")
    verify_parser.add_argument("--out", "-o", required=True)
    verify_parser.add_argument("--json", action="store_true")

    check_parser = commands.add_parser(
        "check", help="strictly parse and independently recompute a saved verification"
    )
    check_parser.add_argument("verification")
    check_parser.add_argument("--json", action="store_true")

    args = parser.parse_args(list(argv))
    try:
        if args.command == "verify":
            from .recall import create_recall_verification

            result = create_recall_verification(
                Path(args.artifact_plan),
                Path(args.lineage),
                Path(args.advisory),
                Path(args.plan),
                Path(args.run),
                Path(args.evaluation),
                Path(args.out),
                verified_at=args.verified_at,
            )
            destination = args.out
        else:
            from .recall import load_recall_verification

            result = load_recall_verification(Path(args.verification))
            destination = args.verification
        status = result["overall_status"]
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            summary = result["summary"]
            print(
                f"LURERECALL INDEPENDENT VERIFICATION: {status.upper()} — "
                f"affected-deployments={summary['affected_deployment_count']} "
                f"quarantine-recall={summary['quarantine_recall']:.3f} "
                f"recovery-recall={summary['recovery_recall']:.3f} "
                f"findings={summary['finding_count']} — {destination}"
            )
            print(
                "boundary: exact metadata recomputation only; no source-document or artifact "
                "loading, advisory authentication, containment, or recovery claim"
            )
        return 0 if status == "pass" else 1
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! LureRecall verification failed: {exc}", file=sys.stderr)
        return 2


def _attest_evidence(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lurescope attest",
        description=(
            "Authenticate exact DSSE payload bytes and verify bounded in-toto/SLSA "
            "subject, builder, build-type, source, and parameter expectations."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    verify_parser = commands.add_parser(
        "verify", help="independently recompile policy and authenticate all planned envelopes"
    )
    verify_parser.add_argument("artifact_plan")
    verify_parser.add_argument("trust_policy")
    verify_parser.add_argument("plan")
    verify_parser.add_argument("evidence_directory")
    verify_parser.add_argument(
        "--public-key",
        action="append",
        required=True,
        help="trusted ECDSA P-256 public PEM; repeat once per reviewed signer",
    )
    verify_parser.add_argument("--verified-at")
    verify_parser.add_argument("--out", "-o", required=True)
    verify_parser.add_argument("--json", action="store_true")

    check_parser = commands.add_parser(
        "check", help="re-authenticate every embedded envelope in a saved private report"
    )
    check_parser.add_argument("verification")
    check_parser.add_argument("--json", action="store_true")

    key_parser = commands.add_parser(
        "key-id", help="print the SHA-256 fingerprint used to pin a P-256 public key"
    )
    key_parser.add_argument("public_key")

    commit_parser = commands.add_parser(
        "commit-external-parameters",
        help="print the canonical SHA-256 commitment for a strict JSON object",
    )
    commit_parser.add_argument("json_object")

    args = parser.parse_args(list(argv))
    try:
        if args.command == "key-id":
            from .attest import public_key_sha256

            print(public_key_sha256(Path(args.public_key).read_bytes()))
            return 0
        if args.command == "commit-external-parameters":
            from .attest import external_parameters_sha256

            print(external_parameters_sha256(Path(args.json_object).read_bytes()))
            return 0
        if args.command == "verify":
            from .attest import create_attest_verification

            result = create_attest_verification(
                Path(args.artifact_plan),
                Path(args.trust_policy),
                Path(args.plan),
                Path(args.evidence_directory),
                [Path(item) for item in args.public_key],
                Path(args.out),
                verified_at=args.verified_at,
            )
            destination = args.out
        else:
            from .attest import load_attest_verification

            result = load_attest_verification(Path(args.verification))
            destination = args.verification
        summary = result["summary"]
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(
                f"LUREATTEST AUTHENTICATED VERIFICATION: PASS — "
                f"attestations={summary['authenticated_attestation_count']}/"
                f"{summary['attestation_count']} builders={len(result['public_keys'])} "
                f"policy-SLSA-level>={summary['minimum_policy_slsa_build_level']} — "
                f"{destination}"
            )
            print(
                "boundary: pinned-key ECDSA P-256 DSSE plus bounded SLSA expectations; "
                "not Sigstore transparency, builder certification, artifact safety, "
                "or authorization"
            )
        return 0
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! LureAttest verification failed: {exc}", file=sys.stderr)
        return 2


def _bom_evidence(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lurescope bom",
        description=(
            "Independently reparse exact CycloneDX 1.7 and SPDX 3.0.1 bytes, "
            "recompute their bounded semantic projection, and verify LureBOM parity."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    verify_parser = commands.add_parser(
        "verify", help="recompute a producer evaluation from the original source BOM bytes"
    )
    verify_parser.add_argument("artifact_plan")
    verify_parser.add_argument("manifest")
    verify_parser.add_argument("producer_evaluation")
    verify_parser.add_argument("cyclonedx")
    verify_parser.add_argument("spdx")
    verify_parser.add_argument("--verified-at")
    verify_parser.add_argument("--out", "-o", required=True)
    verify_parser.add_argument("--json", action="store_true")

    check_parser = commands.add_parser(
        "check", help="reparse the embedded source BOM bytes in a saved private report"
    )
    check_parser.add_argument("verification")
    check_parser.add_argument("--json", action="store_true")

    args = parser.parse_args(list(argv))
    try:
        if args.command == "verify":
            from .bom import create_bom_verification

            result = create_bom_verification(
                Path(args.artifact_plan),
                Path(args.manifest),
                Path(args.producer_evaluation),
                Path(args.cyclonedx),
                Path(args.spdx),
                Path(args.out),
                verified_at=args.verified_at,
            )
            destination = args.out
        else:
            from .bom import load_bom_verification

            result = load_bom_verification(Path(args.verification))
            destination = args.verification
        summary = result["summary"]
        if args.json:
            print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
        else:
            print(
                f"LUREBOM INDEPENDENT VERIFICATION: {summary['verdict'].upper()} — "
                f"components={summary['matched_component_count']}/{summary['component_count']} "
                f"dependencies={summary['matched_dependency_count']}/"
                f"{summary['dependency_count']} ignored-fields="
                f"{summary['ignored_field_count']} — {destination}"
            )
            print(
                "boundary: original BOM bytes reparsed for a declared common denominator; "
                "not full schema conformance, issuer authenticity, completeness, or safety"
            )
        return 0 if summary["verdict"] == "pass" else 1
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! LureBOM verification failed: {exc}", file=sys.stderr)
        return 2


def _channel_evidence(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lurescope channel",
        description=(
            "Independently re-evaluate metadata-only canary flows across declared "
            "agent-run isolation boundaries."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    verify_parser = commands.add_parser(
        "verify", help="recompute a producer evaluation from its exact plan and run"
    )
    verify_parser.add_argument("plan")
    verify_parser.add_argument("run")
    verify_parser.add_argument("producer_evaluation")
    verify_parser.add_argument("--verified-at")
    verify_parser.add_argument("--out", "-o", required=True)
    verify_parser.add_argument("--json", action="store_true")

    check_parser = commands.add_parser(
        "check", help="reparse and recompute a saved self-contained verification"
    )
    check_parser.add_argument("verification")
    check_parser.add_argument("--json", action="store_true")
    args = parser.parse_args(list(argv))
    try:
        if args.command == "verify":
            from .channel import create_channel_verification

            result = create_channel_verification(
                Path(args.plan),
                Path(args.run),
                Path(args.producer_evaluation),
                Path(args.out),
                verified_at=args.verified_at,
            )
            destination = args.out
        else:
            from .channel import load_channel_verification

            result = load_channel_verification(Path(args.verification))
            destination = args.verification
        summary = result["summary"]
        if args.json:
            print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
        else:
            print(
                f"LURECHANNEL INDEPENDENT VERIFICATION: {summary['verdict'].upper()} — "
                f"tests={summary['passed_test_count']}/{summary['test_count']} "
                f"inconclusive={summary['inconclusive_test_count']} "
                f"unauthorized={summary['unauthorized_flow_count']} "
                f"residual={summary['residual_flow_count']} — {destination}"
            )
            print(
                "boundary: exact source bytes and declared sensor windows only; "
                "not universal noninterference, containment, safety, or authorization"
            )
        return 0 if summary["verdict"] == "pass" else 1
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! LureChannel verification failed: {exc}", file=sys.stderr)
        return 2


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
    if args and args[0] == "defender":
        return _defender(args[1:])
    if args and args[0] == "lureeval":
        return _lureeval(args[1:])
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
    if args and args[0] == "pilot":
        return _operational_pilot(args[1:])
    if args and args[0] == "monitor":
        return _monitor(args[1:])
    if args and args[0] == "boundary":
        return _boundary(args[1:])
    if args and args[0] == "boundary-watch":
        return _boundary_watch(args[1:])
    if args and args[0] == "agent-assurance":
        return _agent_assurance(args[1:])
    if args and args[0] == "witness":
        return _witness(args[1:])
    if args and args[0] == "invariant":
        return _invariant(args[1:])
    if args and args[0] == "range":
        return _range_evidence(args[1:])
    if args and args[0] == "runtime":
        return _runtime_evidence(args[1:])
    if args and args[0] == "revoke":
        return _revocation_evidence(args[1:])
    if args and args[0] == "identity":
        return _identity_evidence(args[1:])
    if args and args[0] == "artifact":
        return _artifact_evidence(args[1:])
    if args and args[0] == "recall":
        return _recall_evidence(args[1:])
    if args and args[0] == "attest":
        return _attest_evidence(args[1:])
    if args and args[0] == "bom":
        return _bom_evidence(args[1:])
    if args and args[0] == "channel":
        return _channel_evidence(args[1:])
    return _serve(args)


if __name__ == "__main__":
    raise SystemExit(main())
