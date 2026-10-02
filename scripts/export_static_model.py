#!/usr/bin/env python3
"""Export reviewed data-only weights for the packaged lab and static Space.

No pickle deserialization, model frameworks, training, or downloads. The browser
profile rounds IDF/coefficients to five decimals and the intercept to six; it is
not the full-precision Python serving artifact. Use --check in CI without writes.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import tempfile
from pathlib import Path

from lurescope.local_io import read_regular_file
from lurescope.portable_tfidf import PortableTfidfDetector
from lurescope.service import _DEFAULT_TFIDF_SHA256

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "lurescope/models/tfidf-logreg-fraud.json"
OUTPUTS = (ROOT / "space/model.json", ROOT / "lurescope/static/model.json")


def render(source: Path = SOURCE, expected_sha256: str = _DEFAULT_TFIDF_SHA256) -> bytes:
    detector = PortableTfidfDetector(source, expected_sha256=expected_sha256)
    model = {
        "intercept": round(detector._intercept, 6), "ngram_max": 2,
        "sublinear_tf": True, "norm": "l2",
        "vocab": {term: [round(idf, 5), round(coefficient, 5)]
                  for term, (_, idf, coefficient) in sorted(detector._features.items())},
    }
    return json.dumps(model, separators=(",", ":"), allow_nan=False).encode("utf-8")


def write_atomic(destination: Path, payload: bytes) -> None:
    if destination.is_symlink() or (
        destination.exists() and not stat.S_ISREG(destination.stat().st_mode)
    ):
        raise ValueError("browser model output must be a regular non-symlink path")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            # Bundled public weights must remain readable in non-root containers.
            if os.name == "posix":
                os.fchmod(stream.fileno(), 0o644)
        os.replace(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="verify both artifacts without changing them"
    )
    args = parser.parse_args(argv)
    payload = render()
    for destination in OUTPUTS:
        if args.check:
            actual = read_regular_file(destination, maximum=8 * 1024 * 1024, label="browser model")
            if actual != payload:
                raise ValueError("browser model does not match the pinned data-only source")
        else:
            write_atomic(destination, payload)
    action = "verified" if args.check else "wrote"
    print(f"{action} both browser models from pinned data-only weights")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
