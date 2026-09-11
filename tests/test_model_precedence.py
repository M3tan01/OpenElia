"""
Precedence rules for ModelManager.get_client_config (expensive/cloud tier).

Regression guard for the footgun where a stale, provider-agnostic
EXPENSIVE_BRAIN_* secret silently overrode an explicitly-configured named
provider — routing e.g. a Google key to the Anthropic endpoint (401).

Rule under test:
  - When cloud_provider is a KNOWN named provider AND its own key is set,
    that provider's endpoint + key win outright. Generic EXPENSIVE_BRAIN_*
    slots are ignored.
  - The generic slots only apply as an escape hatch when the named
    provider's key is absent (or the provider is unknown).
"""
import pytest

import secret_store
from model_manager import ModelManager


def _patch(monkeypatch, config: dict, secrets: dict) -> None:
    """Stub the two I/O seams: persisted config + keychain reads."""
    monkeypatch.setattr(ModelManager, "_load", classmethod(lambda cls: dict(config)))
    monkeypatch.setattr(
        secret_store.SecretStore, "get_secret",
        staticmethod(lambda key_name: secrets.get(key_name)),
    )


def test_named_provider_beats_stale_generic_url(monkeypatch):
    # Arrange: google is configured with its key, but stale EXPENSIVE_BRAIN_*
    # slots from a previous Anthropic setup are still in the keychain.
    _patch(
        monkeypatch,
        config={
            "mode": "local",
            "cloud_provider": "google",
            "cloud_model": "gemini-3.6-flash",
            "agent_overrides": {},
        },
        secrets={
            "GOOGLE_API_KEY": "goog-key",
            "EXPENSIVE_BRAIN_URL": "https://api.anthropic.com",   # stale
            "EXPENSIVE_BRAIN_KEY": "anthropic-stale-key",         # stale
        },
    )

    # Act: brain_tier="expensive" routes to the cloud path even in mode=local.
    cfg = ModelManager.get_client_config(brain_tier="expensive")

    # Assert: Google endpoint + Google key, stale generic slots ignored.
    assert "generativelanguage.googleapis.com" in cfg["base_url"]
    assert "anthropic.com" not in cfg["base_url"]
    assert cfg["api_key"] == "goog-key"
    assert cfg["model"] == "gemini-3.6-flash"
    assert cfg["is_local"] is False


def test_generic_slots_used_when_named_key_absent(monkeypatch):
    # Arrange: provider is google but NO GOOGLE_API_KEY — the operator relies
    # on the provider-agnostic escape hatch (custom endpoint + key).
    _patch(
        monkeypatch,
        config={
            "mode": "cloud",
            "cloud_provider": "google",
            "cloud_model": "some-model",
            "agent_overrides": {},
        },
        secrets={
            "EXPENSIVE_BRAIN_URL": "https://proxy.internal/v1",
            "EXPENSIVE_BRAIN_KEY": "proxy-key",
        },
    )

    cfg = ModelManager.get_client_config(brain_tier="expensive")

    # Escape hatch still works: generic URL + key are honored.
    assert "proxy.internal" in cfg["base_url"]
    assert cfg["api_key"] == "proxy-key"


def test_named_provider_openai_default_endpoint(monkeypatch):
    # Sanity: named provider with its key, no generic slots at all.
    _patch(
        monkeypatch,
        config={
            "mode": "cloud",
            "cloud_provider": "openai",
            "cloud_model": "gpt-4o",
            "agent_overrides": {},
        },
        secrets={"OPENAI_API_KEY": "oai-key"},
    )

    cfg = ModelManager.get_client_config(brain_tier="expensive")

    assert "api.openai.com" in cfg["base_url"]
    assert cfg["api_key"] == "oai-key"
    assert cfg["model"] == "gpt-4o"
