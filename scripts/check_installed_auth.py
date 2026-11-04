"""Verify authentication from an installed wheel using synthetic local credentials.

Run outside the checkout in a fresh interpreter with the normal API dependencies.
No server, provider requests, credential files, or external accounts are used.
"""

from __future__ import annotations

import argparse
import asyncio
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
    from lurescope.http_boundary import MAX_REQUEST_JSON_NODES, RequestBodyLimit

    sent = []

    async def receive():
        return {"type": "http.request", "body": b'[' + b'0,' * MAX_REQUEST_JSON_NODES + b'0]'}

    async def send(message):
        sent.append(message)

    async def forbidden_app(*args):
        raise ValueError("installed HTTP boundary admitted excessive JSON nodes")

    asyncio.run(RequestBodyLimit(forbidden_app)({"type": "http", "headers": []}, receive, send))
    if sent[0]["status"] != 422:
        raise ValueError("installed HTTP boundary changed complexity rejection")

    async def check_admission():
        entered, release = asyncio.Event(), asyncio.Event()
        output = []

        async def body():
            return {'type': 'http.request', 'body': b'{}', 'more_body': False}

        async def held_app(scope, receive, send):
            if (await receive())['body'] != b'{}':
                raise ValueError('installed middleware changed request bytes')
            entered.set()
            await release.wait()

        async def collect(message):
            output.append(message)

        async def forbidden_receive():
            raise ValueError('installed saturated admission read another upload')

        scope = {'type': 'http', 'http_version': '1.1', 'headers': []}
        boundary = RequestBodyLimit(held_app, max_in_flight=1, body_timeout_seconds=1)
        first = asyncio.create_task(boundary(scope, body, collect))
        try:
            await asyncio.wait_for(entered.wait(), 2)
            await boundary(scope, forbidden_receive, collect)
            if output[0]['status'] != 503:
                raise ValueError('installed middleware lost concurrent admission bound')
        finally:
            release.set()
            await first
        output.clear()

        async def stalled_receive():
            await asyncio.Event().wait()

        deadline = RequestBodyLimit(forbidden_app, max_in_flight=1, body_timeout_seconds=.02)
        await asyncio.wait_for(deadline(scope, stalled_receive, collect), 2)
        if output[0]['status'] != 408 or not deadline._slots.acquire(blocking=False):
            raise ValueError('installed upload deadline failed to reject or release capacity')
        deadline._slots.release()

    asyncio.run(check_admission())

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
    print("PASS installed upload capacity/deadlines, JSON admission, key checks, and rotation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
