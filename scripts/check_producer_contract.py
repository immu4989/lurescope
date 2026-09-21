"""Check copied artifacts against pinned producer bytes, optionally against Git.

Run from any directory. No network access, source imports, or file writes occur.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--producer-root", type=Path, help="optional LureBench Git checkout")
    args = parser.parse_args(argv)
    manifest = json.loads((ROOT / "tests/producer-contract.json").read_text())
    commit = manifest["commit"]
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        parser.error("producer commit must be a complete SHA-1 Git object ID")
    for relative, expected in manifest["files"].items():
        path = PurePosixPath(relative)
        if path.is_absolute() or ".." in path.parts:
            parser.error("manifest paths must be relative and remain inside the repository")
        payload = (ROOT / relative).read_bytes()
        if hashlib.sha256(payload).hexdigest() != expected:
            parser.exit(1, f"consumer differs from pin: {relative}\n")
        if args.producer_root is not None:
            result = subprocess.run(
                ["git", "-C", str(args.producer_root), "show", f"{commit}:{relative}"],
                capture_output=True,
                check=False,
                timeout=30,
            )
            if result.returncode or hashlib.sha256(result.stdout).hexdigest() != expected:
                parser.exit(1, f"producer commit differs from pin or is unavailable: {relative}\n")
    print(f"verified {len(manifest['files'])} producer artifact pins at {commit}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
