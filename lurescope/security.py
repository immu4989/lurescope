"""Fail-closed API authentication, request policy, and process-local budgets.

The defaults preserve LureScope's local research workflow. Setting
``LURESCOPE_PUBLIC_MODE=true`` changes the posture: a server-peppered API-key
verifier becomes mandatory, per-credential rate limiting is enabled, and
provider-backed operations stay disabled until the operator explicitly allows
and budgets them.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Annotated, Deque, Dict, FrozenSet, Optional, Tuple

from fastapi import Depends, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_LOG = logging.getLogger("lurescope.security")
_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off", ""}
_DEFAULT_PUBLIC_DETECTORS = frozenset({"tfidf-logreg", "heuristic-v0"})
_PROVIDER_DETECTORS = frozenset({"llm-judge", "openai-moderation"})
_BEARER = HTTPBearer(
    auto_error=False,
    description="Client API key required by protected deployments.",
)


def _boolean(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    normalized = raw.strip().casefold()
    if normalized in _TRUE:
        return True
    if normalized in _FALSE:
        return False
    raise ValueError(f"{name} must be true or false")


def _integer(name: str, default: Optional[int]) -> Optional[int]:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value < 0:
        raise ValueError(f"{name} cannot be negative")
    return value


def _csv(name: str) -> FrozenSet[str]:
    return frozenset(item.strip() for item in os.environ.get(name, "").split(",") if item.strip())


def _key_verifiers(public_mode: bool) -> Tuple[bytes, Tuple[bytes, ...]]:
    pepper_hex = os.environ.get("LURESCOPE_API_KEY_PEPPER", "").strip()
    pepper = b""
    if pepper_hex:
        if len(pepper_hex) < 64 or len(pepper_hex) % 2:
            raise ValueError(
                "LURESCOPE_API_KEY_PEPPER must contain at least 64 hexadecimal characters"
            )
        try:
            pepper = bytes.fromhex(pepper_hex)
        except ValueError as exc:
            raise ValueError("LURESCOPE_API_KEY_PEPPER contains a non-hexadecimal value") from exc

    digests = []
    for value in _csv("LURESCOPE_API_KEY_HMAC_SHA256"):
        if len(value) != 64:
            raise ValueError(
                "LURESCOPE_API_KEY_HMAC_SHA256 entries must be 64 hexadecimal characters"
            )
        try:
            digests.append(bytes.fromhex(value))
        except ValueError as exc:
            raise ValueError(
                "LURESCOPE_API_KEY_HMAC_SHA256 contains a non-hexadecimal entry"
            ) from exc

    if digests and not pepper:
        raise ValueError(
            "LURESCOPE_API_KEY_HMAC_SHA256 requires LURESCOPE_API_KEY_PEPPER"
        )
    if pepper and not digests:
        raise ValueError(
            "LURESCOPE_API_KEY_PEPPER requires LURESCOPE_API_KEY_HMAC_SHA256"
        )
    if public_mode and not digests:
        raise ValueError(
            "LURESCOPE_PUBLIC_MODE requires LURESCOPE_API_KEY_HMAC_SHA256 and "
            "LURESCOPE_API_KEY_PEPPER"
        )

    return pepper, tuple(dict.fromkeys(digests))


def create_api_key_material(pepper: Optional[bytes] = None) -> Tuple[str, str, str]:
    """Generate a client key and its server-side peppered verifier."""
    server_pepper = secrets.token_bytes(32) if pepper is None else pepper
    if len(server_pepper) < 32:
        raise ValueError("API-key pepper must contain at least 32 bytes")
    client_key = secrets.token_urlsafe(32)
    verifier = hmac.digest(server_pepper, client_key.encode("utf-8"), hashlib.sha256)
    return client_key, server_pepper.hex(), verifier.hex()


@dataclass(frozen=True)
class SecuritySettings:
    public_mode: bool
    api_key_pepper: bytes
    api_key_verifiers: Tuple[bytes, ...]
    rate_limit_per_minute: int
    provider_daily_limit: Optional[int]
    allowed_detectors: FrozenSet[str]
    allowed_attacks: FrozenSet[str]
    allowed_engines: FrozenSet[str]
    allowed_models: FrozenSet[str]

    @property
    def authentication_required(self) -> bool:
        return self.public_mode or bool(self.api_key_verifiers)

    @classmethod
    def from_env(cls) -> "SecuritySettings":
        public_mode = _boolean("LURESCOPE_PUBLIC_MODE")
        pepper, verifiers = _key_verifiers(public_mode)

        rate = _integer("LURESCOPE_RATE_LIMIT_PER_MINUTE", 60 if public_mode else 0)
        assert rate is not None
        if public_mode and rate == 0:
            raise ValueError("public mode requires a positive LURESCOPE_RATE_LIMIT_PER_MINUTE")

        provider_limit = _integer(
            "LURESCOPE_PROVIDER_DAILY_LIMIT", 0 if public_mode else None
        )
        detectors = _csv("LURESCOPE_ALLOWED_DETECTORS")
        if public_mode and not detectors:
            detectors = _DEFAULT_PUBLIC_DETECTORS

        return cls(
            public_mode=public_mode,
            api_key_pepper=pepper,
            api_key_verifiers=verifiers,
            rate_limit_per_minute=rate,
            provider_daily_limit=provider_limit,
            allowed_detectors=detectors,
            allowed_attacks=_csv("LURESCOPE_ALLOWED_ATTACKS"),
            allowed_engines=_csv("LURESCOPE_ALLOWED_ENGINES"),
            allowed_models=_csv("LURESCOPE_ALLOWED_MODELS"),
        )


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    remaining: int
    retry_after: int


class SlidingWindowLimiter:
    """A bounded, per-credential sliding-window limiter for a single process."""

    def __init__(self) -> None:
        self._events: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, identity: str, limit: int, now: Optional[float] = None) -> RateDecision:
        if limit <= 0:
            return RateDecision(True, 0, 0)
        current = time.monotonic() if now is None else now
        cutoff = current - 60.0
        with self._lock:
            events = self._events[identity]
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= limit:
                retry_after = max(1, int(61 - (current - events[0])))
                return RateDecision(False, 0, retry_after)
            events.append(current)
            return RateDecision(True, limit - len(events), 0)

    def reset(self) -> None:
        with self._lock:
            self._events.clear()


class DailyBudget:
    """Process-local UTC-day counter; a circuit breaker, not a billing control."""

    def __init__(self) -> None:
        self._day = ""
        self._used = 0
        self._lock = threading.Lock()

    def consume(self, amount: int, limit: int) -> Tuple[bool, int, int]:
        now = datetime.now(timezone.utc)
        day = now.date().isoformat()
        with self._lock:
            if self._day != day:
                self._day = day
                self._used = 0
            if self._used + amount > limit:
                tomorrow = datetime.combine(
                    now.date() + timedelta(days=1), datetime.min.time(), tzinfo=timezone.utc
                )
                retry_after = max(1, int((tomorrow - now).total_seconds()))
                return False, max(0, limit - self._used), retry_after
            self._used += amount
            return True, limit - self._used, 0

    def reset(self) -> None:
        with self._lock:
            self._day = ""
            self._used = 0


_RATE_LIMITER = SlidingWindowLimiter()
_PROVIDER_BUDGET = DailyBudget()


def _settings_or_503() -> SecuritySettings:
    try:
        return SecuritySettings.from_env()
    except ValueError as exc:
        raise HTTPException(503, f"deployment security is misconfigured: {exc}") from exc


def _presented_key(request: Request) -> Optional[str]:
    authorization = request.headers.get("authorization", "")
    bearer: Optional[str] = None
    if authorization:
        scheme, separator, value = authorization.partition(" ")
        if separator and scheme.casefold() == "bearer" and value.strip():
            bearer = value.strip()
        else:
            return None
    header_key = request.headers.get("x-api-key")
    if bearer and header_key and bearer != header_key:
        return None
    return bearer or header_key


def _credential_identity(
    token: str,
    pepper: bytes,
    expected: Tuple[bytes, ...],
) -> Optional[str]:
    digest = hmac.digest(pepper, token.encode("utf-8"), hashlib.sha256)
    valid = False
    for candidate in expected:
        valid = secrets.compare_digest(digest, candidate) or valid
    return digest.hex() if valid else None


def require_api_access(
    request: Request,
    response: Response,
    _documented_bearer: Annotated[
        Optional[HTTPAuthorizationCredentials], Depends(_BEARER)
    ] = None,
) -> str:
    """FastAPI dependency protecting stateful, costly, or content-bearing routes."""
    settings = _settings_or_503()
    if not settings.authentication_required:
        return "local-unrestricted"

    token = _presented_key(request)
    identity = (
        _credential_identity(token, settings.api_key_pepper, settings.api_key_verifiers)
        if token
        else None
    )
    if identity is None:
        raise HTTPException(
            401,
            "a valid API key is required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    decision = _RATE_LIMITER.check(identity, settings.rate_limit_per_minute)
    if not decision.allowed:
        raise HTTPException(
            429,
            "API rate limit exceeded",
            headers={
                "Retry-After": str(decision.retry_after),
                "X-RateLimit-Limit": str(settings.rate_limit_per_minute),
                "X-RateLimit-Remaining": "0",
            },
        )
    response.headers["X-RateLimit-Limit"] = str(settings.rate_limit_per_minute)
    response.headers["X-RateLimit-Remaining"] = str(decision.remaining)
    _LOG.info("authorized request credential=%s path=%s", identity[:12], request.url.path)
    return identity


def _provider_call_cost(detector: str, attack: Optional[str], defense: str) -> int:
    calls = 0
    if attack and attack.startswith("llm-"):
        calls += 1
    if detector in _PROVIDER_DETECTORS:
        calls += 1 if attack is None else 2 + int(defense != "none")
    return calls


def enforce_request_policy(
    *,
    detector: str,
    attack: Optional[str] = None,
    defense: str = "none",
    engine: Optional[str] = None,
    model: Optional[str] = None,
) -> None:
    """Apply public-mode allowlists and reserve provider-call budget."""
    settings = _settings_or_503()
    if settings.allowed_detectors and detector not in settings.allowed_detectors:
        raise HTTPException(403, f"detector {detector!r} is not enabled for this deployment")
    if settings.allowed_attacks and attack and attack not in settings.allowed_attacks:
        raise HTTPException(403, f"attack {attack!r} is not enabled for this deployment")

    # In public mode, semantic attacks must be explicitly allowlisted even when
    # no general attack allowlist was configured.
    if settings.public_mode and attack and attack.startswith("llm-"):
        if attack not in settings.allowed_attacks:
            raise HTTPException(403, f"attack {attack!r} requires an explicit public allowlist")

    cost = _provider_call_cost(detector, attack, defense)
    if cost == 0:
        return

    uses_llm = detector == "llm-judge" or bool(attack and attack.startswith("llm-"))
    if settings.public_mode and uses_llm:
        effective_engine = engine or os.environ.get("LURESCOPE_LLM_ENGINE")
        if not effective_engine or effective_engine not in settings.allowed_engines:
            raise HTTPException(
                403,
                "provider-backed LLM operations require an allowlisted engine",
            )
        effective_model = model
        if effective_model is None:
            from lurebench.generate import PROVIDERS

            effective_model = PROVIDERS.get(effective_engine, {}).get("default_model")
        if not effective_model or effective_model not in settings.allowed_models:
            raise HTTPException(
                403,
                "provider-backed LLM operations require an allowlisted model",
            )

    limit = settings.provider_daily_limit
    if limit is None:
        return
    if limit == 0:
        raise HTTPException(403, "provider-backed operations are disabled for this deployment")
    allowed, remaining, retry_after = _PROVIDER_BUDGET.consume(cost, limit)
    if not allowed:
        raise HTTPException(
            429,
            "provider daily request budget exhausted",
            headers={
                "Retry-After": str(retry_after),
                "X-Provider-Budget-Limit": str(limit),
                "X-Provider-Budget-Remaining": str(remaining),
            },
        )


def security_status() -> dict:
    """Return non-secret deployment posture for operator and uptime checks."""
    try:
        settings = SecuritySettings.from_env()
    except ValueError as exc:
        return {
            "mode": "misconfigured",
            "authentication_required": True,
            "rate_limit_per_minute": None,
            "provider_daily_limit": None,
            "allowed_detectors": [],
            "provider_overrides_restricted": True,
            "limitations": [str(exc)],
        }
    limitations = [
        "Rate and provider budgets are process-local; use a shared gateway for multiple replicas.",
        "The provider budget counts attempted calls and is not a monetary billing guarantee.",
        "Terminate TLS and enforce total request-body limits at the deployment gateway.",
    ]
    if not settings.public_mode:
        limitations.insert(0, "Local mode does not require authentication unless API keys are set.")
    return {
        "mode": "public" if settings.public_mode else "local",
        "authentication_required": settings.authentication_required,
        "rate_limit_per_minute": settings.rate_limit_per_minute,
        "provider_daily_limit": settings.provider_daily_limit,
        "allowed_detectors": sorted(settings.allowed_detectors),
        "provider_overrides_restricted": settings.public_mode,
        "limitations": limitations,
    }


def _reset_for_tests() -> None:
    _RATE_LIMITER.reset()
    _PROVIDER_BUDGET.reset()
