"""
webdash/security.py — bearer-token auth for the dashboard API.

Token lives in the OS keychain via SecretStore (key WEBDASH_TOKEN), with env
fallback. Generated once on launch and printed to the operator console; the
frontend receives it via the launch URL fragment. All /api routes depend on
`require_token`. Control routes additionally apply the guards in webdash.guards.
"""

from __future__ import annotations

import hmac
import secrets

from fastapi import Header, HTTPException, status

from secret_store import SecretStore

_TOKEN_KEY = "WEBDASH_TOKEN"  # nosec B105 — keychain entry name, not a secret value


def current_token() -> str | None:
    """Active dashboard token (keychain, then env fallback). None if unset."""
    return SecretStore.get_secret(_TOKEN_KEY)


def generate_token() -> str:
    """Create + persist a fresh token, returning it."""
    token = secrets.token_urlsafe(32)
    SecretStore.set_secret(_TOKEN_KEY, token)
    return token


def get_or_create_token() -> str:
    """Return the existing token or mint one. Called at server launch."""
    return current_token() or generate_token()


def _token_from_header(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return authorization.split(" ", 1)[1].strip()


def verify(token: str) -> bool:
    """Constant-time compare against the active token."""
    expected = current_token()
    if not expected or not token:
        return False
    return hmac.compare_digest(token, expected)


async def require_token(authorization: str | None = Header(default=None)) -> None:
    """FastAPI dependency: 401 unless a valid bearer token is presented."""
    expected = current_token()
    if not expected:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="dashboard token not configured",
        )
    provided = _token_from_header(authorization)
    if not hmac.compare_digest(provided, expected):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
