"""Exercise authority verifiers with all LureBench imports actively forbidden.

Run in a fresh Python process. This checks the transitive runtime import
boundary; it is stronger than scanning the verifier's direct import statements.
"""

from __future__ import annotations

import argparse
import importlib.abc
import sys
from pathlib import Path


class ForbidProducerImports(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "lurebench" or fullname.startswith("lurebench."):
            raise ImportError(f"producer runtime import forbidden: {fullname}")
        return None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--conformance-root",
        type=Path,
        help="optional reference corpus; default resolves the installed package data",
    )
    args = parser.parse_args(argv)
    if any(name == "lurebench" or name.startswith("lurebench.") for name in sys.modules):
        parser.error("run this audit in a fresh interpreter before importing LureBench")
    guard = ForbidProducerImports()
    sys.meta_path.insert(0, guard)
    try:
        from lurescope.mandate_selftest import run_mandate_selftest

        result = run_mandate_selftest(args.conformance_root)
        if result["summary"]["status"] != "pass":
            failures = [item["profile"] for item in result["results"] if item["status"] != "pass"]
            parser.exit(1, f"reference verification failed: {', '.join(failures)}\n")
        if any(name == "lurebench" or name.startswith("lurebench.") for name in sys.modules):
            parser.exit(1, "producer code was imported during verification\n")
    finally:
        sys.meta_path.remove(guard)
    print(
        f"verified {result['summary']['total']} authority artifacts "
        "with LureBench imports forbidden"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
