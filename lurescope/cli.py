"""LureScope CLI: serve, triage, and create verifiable resilience evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Sequence, Tuple


def _serve(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="lurescope", description="Run the LureScope API + lab.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reload", action="store_true", help="auto-reload on code changes (dev)")
    args = parser.parse_args(argv)

    import uvicorn

    uvicorn.run("lurescope.app:app", host=args.host, port=args.port, reload=args.reload)
    return 0


def _input_messages(inputs: Sequence[str], recursive: bool) -> List[Tuple[str, bytes]]:
    messages: List[Tuple[str, bytes]] = []
    for value in inputs:
        if value == "-":
            messages.append(("stdin", sys.stdin.buffer.read()))
            continue
        path = Path(value)
        if path.is_dir():
            pattern = "**/*.eml" if recursive else "*.eml"
            messages.extend((str(item), item.read_bytes()) for item in sorted(path.glob(pattern)))
        elif path.is_file():
            messages.append((str(path), path.read_bytes()))
        else:
            raise FileNotFoundError(value)
    if not messages:
        raise ValueError("no .eml messages found")
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


def _proof(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lurescope proof", description="Create a privacy-minimized LureProof from one .eml."
    )
    parser.add_argument("input", help=".eml file or - for stdin")
    parser.add_argument("--out", "-o", required=True, help="output .lureproof.json path")
    parser.add_argument("--detector", default="tfidf-logreg")
    parser.add_argument("--threshold", type=float, default=None)
    args = parser.parse_args(argv)
    try:
        raw = sys.stdin.buffer.read() if args.input == "-" else Path(args.input).read_bytes()
        from .proof import create_email_proof, dumps_proof

        proof = create_email_proof(raw, args.detector, args.threshold)
        Path(args.out).write_text(dumps_proof(proof), encoding="utf-8")
    except (OSError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2
    print(f"created {args.out} ({proof['integrity']['algorithm']}:{proof['integrity']['digest']})")
    return 0


def _verify(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lurescope verify", description="Verify a LureProof structure and digest."
    )
    parser.add_argument("proof", help=".lureproof.json path")
    args = parser.parse_args(argv)
    try:
        from .proof import verify_proof

        proof = json.loads(Path(args.proof).read_text(encoding="utf-8"))
        result = verify_proof(proof)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["valid"] else 1


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "triage":
        return _triage(args[1:])
    if args and args[0] == "proof":
        return _proof(args[1:])
    if args and args[0] == "verify":
        return _verify(args[1:])
    return _serve(args)


if __name__ == "__main__":
    raise SystemExit(main())
