"""Check data-only default scoring from a trusted local wheel, outside checkout.

Run in a fresh interpreter after installing the wheel with --no-deps --target.
No providers, downloads, model deserialization, or production traffic are used.
"""

from __future__ import annotations

import argparse
import importlib
import math
import os
import sys
import tempfile
from pathlib import Path


class ForbidModelFrameworks:
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in {"pickle", "joblib", "sklearn", "numpy", "torch"}:
            raise ImportError("executable model framework forbidden in portable serving check")
        return None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installed-root", type=Path, required=True)
    args = parser.parse_args(argv)
    root = args.installed_root.resolve(strict=True)
    checkout = Path(__file__).resolve().parents[1]
    if Path.cwd().resolve().is_relative_to(checkout):
        parser.error("run outside the source checkout")
    forbidden = {"lurescope", "joblib", "pickle", "sklearn", "numpy", "torch"}
    if any(name.split(".")[0] in forbidden for name in sys.modules):
        parser.error("use a fresh interpreter without model frameworks")
    if not (root / "lurescope/__init__.py").is_file():
        parser.error("installed LureScope initializer is missing")
    sys.path.insert(0, str(root))
    sys.meta_path.insert(0, ForbidModelFrameworks())
    service = importlib.import_module("lurescope.service")
    portable = importlib.import_module("lurescope.portable_tfidf")
    try:
        service.score("Synthetic input", detector_name="binoculars")
    except service.DetectorUnavailable:
        pass
    else:
        raise ValueError("installed fraud service accepted a provenance-only detector")
    detector = service._detector("tfidf-logreg")
    if not isinstance(detector, portable.PortableTfidfDetector):
        raise ValueError("default serving did not select the data-only model")
    for index in range(32):
        if service._detector("tfidf-logreg", f"unused-{index}", f"unused-{index}") is not detector:
            raise ValueError("ignored provider options multiplied installed local models")
    if len(service._LOCAL_DETECTORS) != 1:
        raise ValueError("installed detector cache retained unexpected entries")
    original_constructor = service.get_detector
    try:
        service.get_detector = lambda *args, **kwargs: object()
        for name in ("llm-judge", "openai-moderation"):
            first = service._detector(name, "synthetic")
            if service._detector(name, "synthetic") is first:
                raise ValueError("installed service retained a provider detector")
        for name in ("unknown", "llm-judge-provenance"):
            try:
                service._detector(name)
            except KeyError:
                pass
            else:
                raise ValueError("installed service constructed an unserved detector")
    finally:
        service.get_detector = original_constructor
    # Fixed historical-model anchor plus threshold and signal smoke checks.
    result = service.score("Please verify your bank account", threshold=.5)
    if (
        not math.isclose(result.fraud_probability, .8944714598915419, abs_tol=1e-12,
                         rel_tol=0.)
        or result.label != "fraud" or not result.signals
    ):
        raise ValueError("installed default scoring changed from its reviewed anchor")
    proof_module = importlib.import_module("lurescope.proof")
    statement = proof_module.create_email_proof(
        b"Subject: Team notes\n\nPlease review the project notes.",
        created_at="2026-10-02T00:00:00Z", subject_salt=bytes(range(32)),
    )
    if not proof_module.verify_proof(statement)["valid"]:
        raise ValueError("installed data-only proof failed verification")
    repeated = proof_module.create_email_proof(
        b"Subject: Notes\n\nLinks http://192.0.2.1/ and http://192.0.2.2/",
        created_at="2026-10-02T00:00:00Z", subject_salt=bytes(range(32)),
    )
    assessment = repeated["predicate"]["assessment"]
    if (not proof_module.verify_proof(repeated)["valid"]
            or assessment["evidence_codes"] != ["ip_literal_url"]
            or assessment["url_count"] != 2):
        raise ValueError("installed proof lost repeated findings or emitted duplicate categories")
    with tempfile.TemporaryDirectory(prefix="lurescope-proof-write-") as directory:
        output = Path(directory) / "proof.json"
        publication = proof_module.write_proof(output, repeated)
        before = output.read_bytes()
        if not publication["valid"] or proof_module.load_proof(output) != repeated:
            raise ValueError("installed proof publication changed the artifact")
        if os.name == "posix" and output.stat().st_mode & 0o077:
            raise ValueError("installed proof publication granted group/world access")
        try:
            proof_module.write_proof(output, statement)
        except FileExistsError:
            pass
        else:
            raise ValueError("installed proof publication replaced existing evidence")
        if output.read_bytes() != before or list(Path(directory).glob(".lureproof-*.tmp")):
            raise ValueError("installed proof publication changed evidence or leaked staging files")
    triage = importlib.import_module("lurescope.triage")
    nested = (b"Content-Type: message/rfc822\n\n" * 1200
              + b"Subject: Notes\n\nOrdinary notes")
    wide = (b"Content-Type: multipart/mixed; boundary=wide\n\n"
            + b"--wide\nContent-Type: text/plain\n\nNotes\n" * 256
            + b"--wide--\n")
    nested_header = (b"From: " + b"(" * 1200 + b"comment" + b")" * 1200
                     + b" <sender@example.test>\n\nNotes")
    oversized_header = b"X-Padding: " + b"x" * 16384 + b"\n\nNotes"
    for raw in (nested, wide, nested_header, oversized_header):
        try:
            proof_module.create_email_proof(raw)
        except triage.EmailTooComplex:
            pass
        else:
            raise ValueError("installed proof creation accepted over-complex email")
    for name, module in list(sys.modules.items()):
        if name == "lurescope" or name.startswith("lurescope."):
            location = getattr(module, "__file__", None)
            if location is None or not Path(location).resolve().is_relative_to(root):
                raise ValueError("LureScope import escaped the installed root")
    print("PASS installed data-only scoring, private proof publication, and MIME/header limits "
          "with model frameworks blocked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
