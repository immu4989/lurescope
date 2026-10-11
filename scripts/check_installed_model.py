"""Check data-only default scoring from a trusted local wheel, outside checkout.

Run in a fresh interpreter after installing the wheel with --no-deps --target.
No providers, downloads, model deserialization, or production traffic are used.
"""

from __future__ import annotations

import argparse
import importlib
import math
import sys
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
    detector = service._detector("tfidf-logreg")
    if not isinstance(detector, portable.PortableTfidfDetector):
        raise ValueError("default serving did not select the data-only model")
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
    print("PASS installed data-only scoring, email proof, and MIME/header limits "
          "with model frameworks blocked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
