"""Verify the hardened container without executing downloaded response data."""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple


def _request(
    base_url: str,
    path: str,
    *,
    method: str = "GET",
    payload: Optional[Dict[str, str]] = None,
    api_key: Optional[str] = None,
) -> Tuple[int, Dict[str, Any]]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"content-type": "application/json"} if data is not None else {}
    if api_key is not None:
        headers["authorization"] = f"Bearer {api_key}"
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}{path}", data=data, headers=headers, method=method
    )
    try:
        response = urllib.request.urlopen(request, timeout=5)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        body = json.loads(response.read().decode("utf-8"))
        return response.status, body


def verify(base_url: str, api_key: str) -> None:
    for _ in range(30):
        try:
            status, health = _request(base_url, "/health")
            if status == 200 and health.get("status") == "ok":
                break
        except (OSError, ValueError):
            pass
        time.sleep(1)
    else:
        raise RuntimeError("container did not become healthy within 30 seconds")

    status, _ = _request(
        base_url,
        "/score",
        method="POST",
        payload={"text": "Verify your account"},
    )
    if status != 401:
        raise AssertionError(f"unauthenticated score request returned {status}, expected 401")

    status, score = _request(
        base_url,
        "/score",
        method="POST",
        payload={"text": "Verify your account at hxxps://example[.]invalid"},
        api_key=api_key,
    )
    probability = score.get("fraud_probability")
    if status != 200 or not isinstance(probability, (int, float)) or not 0 <= probability <= 1:
        raise AssertionError("authenticated score response violated the API contract")

    status, security = _request(base_url, "/security")
    expected = (
        status == 200
        and security.get("mode") == "public"
        and security.get("authentication_required") is True
        and security.get("provider_daily_limit") == 0
    )
    if not expected:
        raise AssertionError("public security posture did not match the hardened CI profile")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--api-key", required=True)
    args = parser.parse_args()
    verify(args.base_url, args.api_key)


if __name__ == "__main__":
    main()
