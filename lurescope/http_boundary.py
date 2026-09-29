"""Bound HTTP input before routing and strictly validate declared JSON syntax.

This is an application-layer bound, not protection against transport buffering,
slow clients, many concurrent connections, or oversized headers at the gateway.
"""

from __future__ import annotations

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .permit import _strict

MAX_REQUEST_BODY_BYTES = 8 * 1024 * 1024


class RequestBodyLimit:
    """Count actual ASGI body bytes, including streams without Content-Length.

    The downstream application receives a bounded complete body only after all
    chunks have passed. No request-derived content is included in errors.
    """

    def __init__(self, app: ASGIApp, maximum: int = MAX_REQUEST_BODY_BYTES):
        if type(maximum) is not int or maximum <= 0:
            raise ValueError("request body limit must be a positive integer")
        self.app = app
        self.maximum = maximum

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def reject(status: int, detail: str) -> None:
            await JSONResponse({"detail": detail}, status_code=status)(scope, receive, send)

        lengths = []
        content_types = []
        for key, value in scope.get("headers", []):
            if key.lower() == b"content-type":
                content_types.append(value.split(b";", 1)[0].strip().lower())
            if key.lower() == b"content-encoding" and value.strip().lower() != b"identity":
                await reject(415, "encoded request bodies are not supported")
                return
            if key.lower() == b"content-length":
                lengths.append(value.strip())
        if len(lengths) > 1 or (lengths and (
            not lengths[0] or not lengths[0].isdigit() or len(lengths[0]) > 20
        )):
            await reject(400, "invalid request length")
            return
        declared = int(lengths[0]) if lengths else None
        if declared is not None and declared > self.maximum:
            await reject(413, "request body exceeds the application byte limit")
            return

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                await reject(400, "invalid request stream")
                return
            chunk = message.get("body", b"")
            if len(chunk) > self.maximum - len(body):
                await reject(413, "request body exceeds the application byte limit")
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break
        if declared is not None and declared != len(body):
            await reject(400, "request length does not match received bytes")
            return

        complete = bytes(body)
        del body
        # FastAPI treats an absent Content-Type as JSON for these model-backed
        # APIs. Reject duplicate keys/nonfinite constants before its permissive
        # decoder can discard that evidence. Avoid changing non-JSON protocols.
        if len(content_types) > 1:
            await reject(400, "ambiguous request content type")
            return
        is_json = (not content_types or content_types[0] == b"application/json"
                   or (content_types[0].startswith(b"application/")
                       and content_types[0].endswith(b"+json")))
        if complete and is_json:
            try:
                _strict(complete, "request")
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
