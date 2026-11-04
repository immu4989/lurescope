"""Bound HTTP input before routing and strictly validate declared JSON syntax.

These are application-layer bounds, not protection against transport buffering,
connection floods, oversized headers, or non-cooperative downstream code.
"""

from __future__ import annotations

import math
import os
import threading
from typing import Optional

import anyio
from anyio.lowlevel import checkpoint
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .permit import _strict

MAX_REQUEST_BODY_BYTES = 8 * 1024 * 1024
MAX_REQUEST_JSON_NODES = 100_000
MAX_IN_FLIGHT_REQUESTS = 16
REQUEST_BODY_TIMEOUT_SECONDS = 30.0


def _admission_limits(max_in_flight, body_timeout_seconds):
    if type(max_in_flight) is not int or not 1 <= max_in_flight <= 256:
        raise ValueError('max_in_flight must be an integer from 1 through 256')
    if (type(body_timeout_seconds) not in (int, float)
            or not 0 < body_timeout_seconds <= 300 or not math.isfinite(body_timeout_seconds)):
        raise ValueError('body_timeout_seconds must be finite, positive, and at most 300')
    return max_in_flight, float(body_timeout_seconds)


def configured_admission_limits() -> dict:
    """Read once at application construction, never from request input."""
    count = os.environ.get('LURESCOPE_HTTP_MAX_IN_FLIGHT', str(MAX_IN_FLIGHT_REQUESTS))
    duration = os.environ.get('LURESCOPE_HTTP_BODY_TIMEOUT_SECONDS',
                              str(REQUEST_BODY_TIMEOUT_SECONDS))
    try:
        if len(count) > 64 or len(duration) > 64:
            raise ValueError('oversized setting')
        limit, timeout = _admission_limits(int(count), float(duration))
    except (ValueError, OverflowError):
        raise ValueError('invalid HTTP admission configuration') from None
    return {'max_in_flight': limit, 'body_timeout_seconds': timeout}


class _BodyRejected(Exception):
    def __init__(self, status, detail):
        self.status = status
        self.detail = detail
        super().__init__(detail)


async def _reject(scope, receive, send, status, detail, *, retry=False):
    headers = {'Cache-Control': 'no-store'}
    if retry:
        headers['Retry-After'] = '1'
    # An incomplete HTTP/1.x upload is not a reusable connection. Do not emit
    # this hop-by-hop header on HTTP/2 or HTTP/3 streams.
    if scope.get('http_version') in {'1.0', '1.1'}:
        headers['Connection'] = 'close'
    await JSONResponse({'detail': detail}, status_code=status,
                       headers=headers)(scope, receive, send)


class RequestBodyLimit:
    """Count actual ASGI body bytes, including streams without Content-Length.

    The downstream application receives a bounded complete body only after all
    chunks have passed. No request-derived content is included in errors.
    """

    def __init__(self, app: ASGIApp, maximum: int = MAX_REQUEST_BODY_BYTES, *,
                 max_in_flight: int = MAX_IN_FLIGHT_REQUESTS,
                 body_timeout_seconds: float = REQUEST_BODY_TIMEOUT_SECONDS):
        if type(maximum) is not int or maximum <= 0:
            raise ValueError("request body limit must be a positive integer")
        self.app = app
        self.maximum = maximum
        limit, self.body_timeout_seconds = _admission_limits(max_in_flight, body_timeout_seconds)
        # Nonblocking, loop-independent admission. There is no task queue and
        # the slot covers upload, validation, routing, and the ASGI response.
        self._slots = threading.BoundedSemaphore(limit)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        if not self._slots.acquire(blocking=False):
            await _reject(scope, receive, send, 503, 'request admission is busy', retry=True)
            return
        try:
            await self._admitted(scope, receive, send)
        finally:
            self._slots.release()

    async def _read_body(self, receive: Receive, deadline: float) -> Optional[bytes]:
        body = bytearray()
        while True:
            # A receive callable can complete synchronously (including empty
            # chunks); explicitly yield so a stream cannot starve cancellation.
            await checkpoint()
            message = await receive()
            if message['type'] == 'http.disconnect':
                return None
            if anyio.current_time() >= deadline:
                raise _BodyRejected(408, 'request body deadline exceeded')
            chunk = message.get('body', b'')
            more = message.get('more_body', False)
            if (message['type'] != 'http.request' or not isinstance(chunk, bytes)
                    or type(more) is not bool):
                raise _BodyRejected(400, 'invalid request stream')
            if len(chunk) > self.maximum - len(body):
                raise _BodyRejected(413, 'request body exceeds the application byte limit')
            body.extend(chunk)
            if not more:
                return bytes(body)

    async def _admitted(self, scope: Scope, receive: Receive, send: Send) -> None:

        async def reject(status: int, detail: str) -> None:
            await _reject(scope, receive, send, status, detail)

        lengths = []
        content_types = []
        encodings = []
        for key, value in scope.get("headers", []):
            if key.lower() == b"content-type":
                content_types.append(value.split(b";", 1)[0].strip().lower())
            if key.lower() == b"content-encoding":
                encodings.append(value.strip().lower())
            if key.lower() == b"content-length":
                lengths.append(value.strip())
        if len(content_types) > 1 or len(encodings) > 1:
            await reject(400, 'ambiguous request content headers')
            return
        if encodings and encodings[0] != b'identity':
            await reject(415, 'encoded request bodies are not supported')
            return
        if len(lengths) > 1 or (lengths and (
            not lengths[0] or not lengths[0].isdigit() or len(lengths[0]) > 20
        )):
            await reject(400, "invalid request length")
            return
        declared = int(lengths[0]) if lengths else None
        if declared is not None and declared > self.maximum:
            await reject(413, "request body exceeds the application byte limit")
            return

        try:
            with anyio.fail_after(self.body_timeout_seconds) as budget:
                complete = await self._read_body(receive, budget.deadline)
        except TimeoutError:
            if not budget.cancelled_caught:
                raise  # A server error is not this middleware's elapsed deadline.
            await reject(408, 'request body deadline exceeded')
            return
        except _BodyRejected as exc:
            await reject(exc.status, exc.detail)
            return
        if complete is None:  # Client disconnected; do not enter a route or send a response.
            return
        if anyio.current_time() >= budget.deadline:
            await reject(408, 'request body deadline exceeded')
            return
        if declared is not None and declared != len(complete):
            await reject(400, "request length does not match received bytes")
            return

        # FastAPI treats an absent Content-Type as JSON for these model-backed
        # APIs. Reject duplicate keys/nonfinite constants before its permissive
        # decoder can discard that evidence. Avoid changing non-JSON protocols.
        is_json = (not content_types or content_types[0] == b"application/json"
                   or (content_types[0].startswith(b"application/")
                       and content_types[0].endswith(b"+json")))
        if complete and is_json:
            try:
                _strict(complete, "request", max_nodes=MAX_REQUEST_JSON_NODES)
            except ValueError:
                await reject(422, "request validation failed")
                return
        delivered = False

        async def bounded_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": complete, "more_body": False}
            return await receive()

        await self.app(scope, bounded_receive, send)
