"""LureScope CLI: serve, triage, and create verifiable resilience evidence."""

from __future__ import annotations

import argparse
import json
import os
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
        description="Generate a client API key and a server-side peppered verifier.",
    )
    parser.add_argument(
        "--out",
        required=True,
        help="new JSON path containing the client key and deployment values (mode 0600)",
    )
    parser.add_argument(
        "--pepper-file",
        help="existing JSON output whose pepper should be reused during key rotation",
    )
    args = parser.parse_args(argv)
    try:
        pepper = None
        if args.pepper_file:
            prior = json.loads(Path(args.pepper_file).read_text(encoding="utf-8"))
            pepper = bytes.fromhex(prior["lurescope_api_key_pepper"])

        from .security import create_api_key_material

        client_key, pepper_hex, verifier = create_api_key_material(pepper)
        payload = {
            "client_api_key": client_key,
            "lurescope_api_key_pepper": pepper_hex,
            "lurescope_api_key_hmac_sha256": verifier,
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
    if args and args[0] == "proof":
        return _proof(args[1:])
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
