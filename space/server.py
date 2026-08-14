"""Serve the PyPI-packaged browser lab without accepting message content."""

from __future__ import annotations

import json
import os
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit

SITE = Path(__file__).with_name("site")


class StaticLabHandler(SimpleHTTPRequestHandler):
    """Static-only handler with an explicit privacy and browser-security boundary."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(SITE), **kwargs)

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Permissions-Policy",
            "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
        )
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'none'; connect-src 'self'; "
            "font-src 'self'; form-action 'none'; frame-ancestors 'self' "
            "https://huggingface.co https://*.huggingface.co; "
            "img-src 'self' data:; object-src 'none'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'",
        )
        super().end_headers()

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        parsed = urlsplit(self.path)
        if parsed.path == "/health":
            payload = json.dumps({"status": "ok", "mode": "static-browser-only"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if parsed.path in {"", "/"}:
            query = dict(parse_qsl(parsed.query, keep_blank_values=True))
            if query.get("standalone") != "1":
                query["standalone"] = "1"
                self.send_response(302)
                self.send_header("Location", f"/?{urlencode(query)}")
                self.end_headers()
                return
        super().do_GET()

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        self.send_response(405)
        self.send_header("Allow", "GET, HEAD")
        self.end_headers()

    def list_directory(self, path):
        self.send_error(404, "Directory listing disabled")
        return None


def main() -> None:
    port = int(os.environ.get("PORT", "7860"))
    if not 1 <= port <= 65535:
        raise ValueError("PORT must be between 1 and 65535")
    server = ThreadingHTTPServer(("0.0.0.0", port), StaticLabHandler)
    print(f"serving static LureScope lab on 0.0.0.0:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
