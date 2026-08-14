"""
tests/test_keystore_bootstrap.py — Regression tests for SecretStore.bootstrap()
under non-interactive (non-tty) stdin.

Pins the a327e17 behavior: bootstrap() must NOT call getpass (and therefore must NOT
raise EOFError) when stdin is not a tty, while still migrating .env keys to the cache.
"""
import json
from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def clear_cache():
    """Reset the in-process cache and disable Fernet so tests don't hit the keyring."""
    import secret_store
    from secret_store import SecretStore
    SecretStore._cache = None
    secret_store._fernet_key_cache = b""  # passthrough — no keyring hit for the Fernet key
    yield
    SecretStore._cache = None
    secret_store._fernet_key_cache = None


def _make_keyring(initial: dict | None = None):
    """Return (get_password, set_password) mocks backed by a shared dict."""
    store: dict = {}
    if initial:
        store["OpenElia:secrets"] = json.dumps(initial)

    def _get(service, key):
        return store.get(f"{service}:{key}")

    def _set(service, key, value):
        store[f"{service}:{key}"] = value

    return _get, _set, store


def test_bootstrap_non_tty_does_not_call_getpass_or_raise(monkeypatch):
    """Non-interactive stdin must skip the prompt loop — no getpass, no EOFError."""
    from secret_store import SecretStore
    get_pw, set_pw, _ = _make_keyring()
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)

    with patch("keyring.get_password", side_effect=get_pw), \
         patch("keyring.set_password", side_effect=set_pw), \
         patch("getpass.getpass", side_effect=AssertionError("getpass must not be called on non-tty stdin")):
        # Must not raise (regression: pre-a327e17 this raised EOFError via getpass).
        SecretStore.bootstrap()


def test_bootstrap_non_tty_still_migrates_env_keys(monkeypatch):
    """The .env -> keychain migration must run even when prompts are skipped."""
    from secret_store import SecretStore
    get_pw, set_pw, _ = _make_keyring()
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    # A required key present only in the environment must be migrated into the cache.
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://localhost:11434")

    with patch("keyring.get_password", side_effect=get_pw), \
         patch("keyring.set_password", side_effect=set_pw), \
         patch("getpass.getpass", side_effect=AssertionError("getpass must not be called on non-tty stdin")):
        SecretStore.bootstrap()

    assert SecretStore._cache.get("OLLAMA_BASE_URL") == "http://localhost:11434"
