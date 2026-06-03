"""
webdash/security.py — bearer-token auth for the dashboard API.

Token lives in the OS keychain via SecretStore (key WEBDASH_TOKEN), with env
fallback. Minted at launch and printed to the operator console; the frontend
receives it via the launch URL fragment. All /api routes depend on
`require_token`. Control routes additionally apply the guards in webdash.guards.

The keychain record is JSON ``{"token": ..., "issued": <epoch>}``. A token older
than ``WEBDASH_TOKEN_TTL`` seconds (default 8h; ``0`` disables expiry) is rejected,
and `get_or_create_token` mints a fresh one on the next launch (rotation). Tokens
minted before TTL existed are bare strings with no issue time and never expire.
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
import time

from fastapi import Header, HTTPException, status

from secret_store import SecretStore

_TOKEN_KEY = "WEBDASH_TOKEN"  # nosec B105 — keychain entry name, not a secret value
_TTL_DEFAULT_SECONDS = 8 * 3600


def _now() -> float:
    """Wall clock, isolated so tests can pin it."""
    return time.time()


def _ttl() -> int:
    """Token lifetime in seconds from WEBDASH_TOKEN_TTL; <=0 disables expiry."""
    try:
        return int(os.getenv("WEBDASH_TOKEN_TTL", str(_TTL_DEFAULT_SECONDS)))
    except ValueError:
        return _TTL_DEFAULT_SECONDS


def _read_record() -> dict | None:
    """Parse the keychain entry into {'token', 'issued'}.

    New entries are JSON. A legacy bare-string token (minted before TTL existed)
    is returned with ``issued=None`` so it is treated as non-expiring.
    """
    raw = SecretStore.get_secret(_TOKEN_KEY)
    if not raw:
        return None
    try:
        rec = json.loads(raw)
    except (ValueError, TypeError):
        # Not JSON -> legacy bare-string token (minted before TTL). Never expires.
        return {"token": raw, "issued": None}
    # Parsed as JSON: accept only a well-formed record. A JSON value of any other
    # shape (dict without "token", list, number) is a corrupt/tampered entry and
    # is refused rather than coerced into a token (fail-closed).
    if isinstance(rec, dict) and "token" in rec:
        return {"token": rec["token"], "issued": rec.get("issued")}
    return None


def current_token() -> str | None:
    """Active dashboard token value (keychain, then env fallback). None if unset."""
    rec = _read_record()
    return rec["token"] if rec else None


def _token_issued() -> float | None:
    """Epoch the active token was minted, or None for a legacy/absent token."""
    rec = _read_record()
    return rec["issued"] if rec else None


def is_expired() -> bool:
    """True iff the active token has an issue time older than the TTL."""
    issued = _token_issued()
    if issued is None:  # legacy/unknown -> cannot prove expiry
        return False
    ttl = _ttl()
    if ttl <= 0:  # expiry disabled
        return False
    return (_now() - issued) > ttl


def generate_token() -> str:
    """Create + persist a fresh token (stamped with the current time), returning it."""
    token = secrets.token_urlsafe(32)
    SecretStore.set_secret(_TOKEN_KEY, json.dumps({"token": token, "issued": _now()}))
    return token


# Explicit alias for callers that want to force a new token regardless of state.
rotate_token = generate_token


def get_or_create_token() -> str:
    """Return the active token, or mint a fresh one if missing OR expired.

    Called at server launch, so an expired token is rotated on the next start.
    """
    if current_token() is None or is_expired():
        return generate_token()
    return current_token()  # type: ignore[return-value]  # not None per guard above


def _token_from_header(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return authorization.split(" ", 1)[1].strip()


def verify(token: str) -> bool:
    """Constant-time compare against the active token; False if expired."""
    expected = current_token()
    if not expected or not token or is_expired():
        return False
    return hmac.compare_digest(token, expected)


async def require_token(authorization: str | None = Header(default=None)) -> None:
    """FastAPI dependency: 401 unless a valid, unexpired bearer token is presented."""
    expected = current_token()
    if not expected:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="dashboard token not configured",
        )
    provided = _token_from_header(authorization)
    if is_expired():
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="token expired — relaunch the dashboard for a fresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not hmac.compare_digest(provided, expected):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
