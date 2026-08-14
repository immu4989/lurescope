"""Verify the browser-only Space and its privacy boundary over HTTP."""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request


def _get(url: str):
    request = urllib.request.Request(url, headers={"User-Agent": "lurescope-space-check"})
    return urllib.request.urlopen(request, timeout=10)


def _post_json(url: str):
    request = urllib.request.Request(
        url,
        data=b'{"text":"must remain in the browser"}',
        headers={"Content-Type": "application/json", "User-Agent": "lurescope-space-check"},
        method="POST",
    )
    return urllib.request.urlopen(request, timeout=10)


def verify(base_url: str) -> None:
    base = base_url.rstrip("/")
    with _get(f"{base}/health") as response:
        health = json.load(response)
        if response.status != 200 or health != {"status": "ok", "mode": "static-browser-only"}:
            raise AssertionError("static Space health contract failed")

    with _get(f"{base}/") as response:
        html = response.read().decode("utf-8")
        if "standalone=1" not in response.url:
            raise AssertionError("root did not force the private browser engine")
        if "LureScope — Adversarial fraud detection lab" not in html:
            raise AssertionError("PyPI-packaged browser lab was not served")
        if "no-referrer" != response.headers.get("Referrer-Policy"):
            raise AssertionError("privacy headers are missing")
        if "object-src 'none'" not in response.headers.get("Content-Security-Policy", ""):
            raise AssertionError("content security policy is missing")
        if "camera=()" not in response.headers.get("Permissions-Policy", ""):
            raise AssertionError("browser permissions are not disabled")

    with _get(f"{base}/static/model.json") as response:
        model = json.load(response)
        if not isinstance(model.get("vocab"), dict) or len(model["vocab"]) < 1000:
            raise AssertionError("browser model is missing or unexpectedly small")

    try:
        _get(f"{base}/capabilities")
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
    else:
        raise AssertionError("Space unexpectedly exposes a backend capabilities route")

    try:
        _post_json(f"{base}/score")
    except urllib.error.HTTPError as exc:
        if exc.code != 405 or exc.headers.get("Allow") != "GET, HEAD":
            raise
    else:
        raise AssertionError("Space unexpectedly accepts message content")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    args = parser.parse_args()
    verify(args.base_url)


if __name__ == "__main__":
    main()
