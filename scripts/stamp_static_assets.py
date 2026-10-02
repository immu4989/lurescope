"""Bind workbench script URLs to exact local bytes for cache-safe deployment.

Run without --check after editing a script. No network, dependencies, or model
loading. URL hashes invalidate caches; they do not authenticate publishers.
"""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "lurescope/static"
SCRIPTS = ("browser-engine.js", "evidence-explorer.js", "capacity-planner.js", "capacity-ui.js")


def stamped_html(root: Path = ROOT) -> str:
    text = (root / "index.html").read_text(encoding="utf-8")
    for name in SCRIPTS:
        digest = hashlib.sha256((root / name).read_bytes()).hexdigest()
        pattern = rf'(<script src="static/{re.escape(name)})(?:\?sha256=[a-f0-9]{{64}})?(")'
        text, count = re.subn(pattern, rf'\g<1>?sha256={digest}\2', text)
        if count != 1:
            raise ValueError("each workbench script must appear exactly once")
    return text


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    updated = stamped_html(ROOT)
    target = ROOT / "index.html"
    if args.check:
        if target.read_text(encoding="utf-8") != updated:
            raise ValueError("stale script URLs: run python scripts/stamp_static_assets.py")
    else:
        target.write_text(updated, encoding="utf-8")
    action = "Verified content-bound" if args.check else "Stamped"
    print(f"{action} workbench script URLs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
