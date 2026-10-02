"""Verify browser reproduction inputs in a locally built source distribution.

Read archive members without extracting them. Compare exact bytes to this
checkout; this check is not publisher authentication.
"""

from __future__ import annotations

import argparse
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "scripts/export_static_model.py", "scripts/stamp_static_assets.py",
    "scripts/check_installed_model.py", "scripts/check_installed_browser.cjs",
    "scripts/check_browser_sdist.py", "space/model.json",
    "lurescope/models/tfidf-logreg-fraud.json", "lurescope/static/model.json",
    "lurescope/static/index.html", "lurescope/static/browser-engine.js",
    "lurescope/static/evidence-explorer.js", "lurescope/static/capacity-planner.js",
    "lurescope/static/capacity-ui.js", "tests/browser_engine.test.cjs",
    "tests/evidence_explorer.test.cjs", "tests/workbench_ui.test.cjs",
    "tests/capacity_planner.test.cjs", "tests/capacity_ui.test.cjs",
)


def verify(path: Path, root: Path = ROOT) -> None:
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        if len({member.name for member in members}) != len(members):
            raise ValueError("duplicate source archive members")
        prefixes = {member.name.split("/", 1)[0] for member in members}
        if len(prefixes) != 1:
            raise ValueError("source archive must have one top-level directory")
        prefix = prefixes.pop()
        for relative in REQUIRED:
            member = archive.getmember(f"{prefix}/{relative}")
            expected = (root / relative).read_bytes()
            if not member.isfile() or member.size != len(expected):
                raise ValueError(f"missing or invalid browser reproduction input: {relative}")
            with archive.extractfile(member) as stream:
                if stream.read(len(expected) + 1) != expected:
                    raise ValueError(f"stale browser reproduction input: {relative}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    args = parser.parse_args(argv)
    verify(args.archive)
    print(f"Verified {len(REQUIRED)} exact browser source-distribution inputs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
