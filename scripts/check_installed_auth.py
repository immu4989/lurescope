"""Verify authentication from an installed wheel using synthetic local credentials.

Run outside the checkout in a fresh interpreter with the normal API dependencies.
No server, provider requests, credential files, or external accounts are used.
"""

from __future__ import annotations

import argparse
import os
import sys
from contextlib import ExitStack
from pathlib import Path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installed-root", type=Path, required=True)
    args = parser.parse_args(argv)
    root = args.installed_root.resolve(strict=True)
    checkout = Path(__file__).resolve().parents[1]
    if Path.cwd().resolve().is_relative_to(checkout) or root.is_relative_to(checkout):
        parser.error("use an installed wheel outside the source checkout")
    if any(name == "lurescope" or name.startswith("lurescope.") for name in sys.modules):
        parser.error("fresh interpreter required")
    sys.path.insert(0, str(root))
    from fastapi import HTTPException, Request, Response

    from lurescope import security

    variables = ("LURESCOPE_PUBLIC_MODE", "LURESCOPE_API_KEY_SCRYPT",
                 "LURESCOPE_RATE_LIMIT_PER_MINUTE", "LURESCOPE_PROVIDER_DAILY_LIMIT")
    saved = {name: os.environ.get(name) for name in variables}
    key = "synthetic-installed-authentication-key-" + "k" * 32
    encoded = security.create_api_key_verifier(key)

    def authorize(headers):
        return security.require_api_access(Request({"type": "http", "path": "/score",
                                                   "headers": headers}), Response())

    def rejected(headers, status):
        try:
            authorize(headers)
        except HTTPException as exc:
            if exc.status_code != status or key in str(exc.detail):
                raise ValueError("installed authentication returned unexpected diagnostics"
                                 ) from exc
        else:
            raise ValueError("installed authentication accepted a rejected request")

    try:
        os.environ.update(LURESCOPE_PUBLIC_MODE="true", LURESCOPE_API_KEY_SCRYPT=encoded,
                          LURESCOPE_RATE_LIMIT_PER_MINUTE="60", LURESCOPE_PROVIDER_DAILY_LIMIT="0")
        header = (b"authorization", f"Bearer {key}".encode())
        if authorize([header]) != security.ApiKeyVerifier.parse(encoded).digest.hex():
            raise ValueError("installed authentication changed key identity")
        rejected([header, header], 401)
        rejected([(b"x-api-key", b"k" * 513)], 401)
        with ExitStack() as stack:
            for _ in range(security.MAX_CONCURRENT_KEY_CHECKS):
                stack.enter_context(security._KEY_CHECK_SLOTS)
            rejected([header], 503)
        if not authorize([header]):
            raise ValueError("installed authentication did not recover released capacity")
        os.environ["LURESCOPE_API_KEY_SCRYPT"] = security.create_api_key_verifier("z" * 43)
        rejected([header], 401)
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    for name, module in list(sys.modules.items()):
        if name == "lurescope" or name.startswith("lurescope."):
            location = getattr(module, "__file__", None)
            if location is None or not Path(location).resolve().is_relative_to(root):
                raise ValueError("authentication imports escaped installed wheel")
    print("PASS installed key verification, ambiguous headers, admission limits, and rotation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
