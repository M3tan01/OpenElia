"""Unit tests for core.webhook.auth_headers — outbound callback auth header."""
from __future__ import annotations

import core.webhook
from core.webhook import WEBHOOK_AUTH_HEADER, auth_headers


def test_auth_headers_returns_header_when_secret_set(monkeypatch):
    monkeypatch.setattr(core.webhook.SecretStore, "get_secret", lambda key: "tok-123")
    assert auth_headers("N8N_WEBHOOK_TOKEN") == {WEBHOOK_AUTH_HEADER: "tok-123"}


def test_auth_headers_empty_when_secret_unset(monkeypatch):
    monkeypatch.setattr(core.webhook.SecretStore, "get_secret", lambda key: None)
    assert auth_headers("N8N_WEBHOOK_TOKEN") == {}


def test_auth_headers_strips_whitespace(monkeypatch):
    monkeypatch.setattr(core.webhook.SecretStore, "get_secret", lambda key: "  tok  ")
    assert auth_headers("N8N_WEBHOOK_TOKEN") == {WEBHOOK_AUTH_HEADER: "tok"}
