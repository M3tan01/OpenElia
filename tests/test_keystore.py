"""
tests/test_secret_store.py — Unit tests for SecretStore.

Uses monkeypatching so no real OS Keychain is touched.
"""
import json
import pytest
from unittest.mock import patch, call


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clear_cache():
    """Reset the in-process cache and Fernet key cache before every test."""
    import secret_store
    from secret_store import SecretStore
    SecretStore._cache = None
    secret_store._fernet_key_cache = b""  # Disable Fernet so tests don't hit keyring for the key
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


# ---------------------------------------------------------------------------
# Basic get / set / delete
# ---------------------------------------------------------------------------

class TestBasicOperations:
    def test_get_returns_none_when_empty(self):
        from secret_store import SecretStore
        get_pw, set_pw, _ = _make_keyring()
        with patch("keyring.get_password", side_effect=get_pw), \
             patch("keyring.set_password", side_effect=set_pw):
            assert SecretStore.get_secret("MISSING_KEY") is None

    def test_set_and_get_roundtrip(self):
        from secret_store import SecretStore
        get_pw, set_pw, _ = _make_keyring()
        with patch("keyring.get_password", side_effect=get_pw), \
             patch("keyring.set_password", side_effect=set_pw):
            SecretStore.set_secret("MY_KEY", "my-value")
            assert SecretStore.get_secret("MY_KEY") == "my-value"

    def test_set_overwrites_existing(self):
        from secret_store import SecretStore
        get_pw, set_pw, _ = _make_keyring({"MY_KEY": "old"})
        with patch("keyring.get_password", side_effect=get_pw), \
             patch("keyring.set_password", side_effect=set_pw):
            SecretStore.set_secret("MY_KEY", "new")
            assert SecretStore.get_secret("MY_KEY") == "new"

    def test_delete_removes_key(self):
        from secret_store import SecretStore
        get_pw, set_pw, _ = _make_keyring({"MY_KEY": "value"})
        with patch("keyring.get_password", side_effect=get_pw), \
             patch("keyring.set_password", side_effect=set_pw):
            SecretStore.delete_secret("MY_KEY")
            assert SecretStore.get_secret("MY_KEY") is None

    def test_delete_nonexistent_is_noop(self):
        from secret_store import SecretStore
        get_pw, set_pw, _ = _make_keyring()
        with patch("keyring.get_password", side_effect=get_pw), \
             patch("keyring.set_password", side_effect=set_pw):
            SecretStore.delete_secret("DOES_NOT_EXIST")   # must not raise


# ---------------------------------------------------------------------------
# In-process cache behaviour
# ---------------------------------------------------------------------------

class TestCache:
    def test_cache_is_populated_on_first_get(self):
        from secret_store import SecretStore
        get_pw, set_pw, _ = _make_keyring({"CACHED": "yes"})
        with patch("keyring.get_password", side_effect=get_pw) as mock_get, \
             patch("keyring.set_password", side_effect=set_pw):
            SecretStore.get_secret("CACHED")
            SecretStore.get_secret("CACHED")
            # keyring.get_password called once only (first load), not twice
            assert mock_get.call_count == 1

    def test_cache_is_cleared_between_tests(self):
        from secret_store import SecretStore
        assert SecretStore._cache is None


# ---------------------------------------------------------------------------
# Env-var fallback
# ---------------------------------------------------------------------------

class TestEnvFallback:
    def test_falls_back_to_env_when_keyring_empty(self, monkeypatch):
        from secret_store import SecretStore
        monkeypatch.setenv("MY_ENV_KEY", "env-value")
        get_pw, set_pw, _ = _make_keyring()
        with patch("keyring.get_password", side_effect=get_pw), \
             patch("keyring.set_password", side_effect=set_pw):
            assert SecretStore.get_secret("MY_ENV_KEY") == "env-value"

    def test_keyring_takes_priority_over_env(self, monkeypatch):
        from secret_store import SecretStore
        monkeypatch.setenv("MY_KEY", "env-value")
        get_pw, set_pw, _ = _make_keyring({"MY_KEY": "keychain-value"})
        with patch("keyring.get_password", side_effect=get_pw), \
             patch("keyring.set_password", side_effect=set_pw):
            assert SecretStore.get_secret("MY_KEY") == "keychain-value"


# ---------------------------------------------------------------------------
# Keyring failure resilience
# ---------------------------------------------------------------------------

class TestKeyringFailure:
    def test_read_failure_returns_none(self):
        from secret_store import SecretStore
        with patch("keyring.get_password", side_effect=Exception("keyring unavailable")):
            result = SecretStore.get_secret("ANY_KEY")
        assert result is None

    def test_write_failure_does_not_raise(self):
        from secret_store import SecretStore
        get_pw, _, _ = _make_keyring()
        with patch("keyring.get_password", side_effect=get_pw), \
             patch("keyring.set_password", side_effect=Exception("write failed")):
            SecretStore.set_secret("KEY", "value")   # must not raise

    def test_cache_survives_keyring_write_failure(self):
        from secret_store import SecretStore
        get_pw, _, _ = _make_keyring()
        with patch("keyring.get_password", side_effect=get_pw), \
             patch("keyring.set_password", side_effect=Exception("write failed")):
            SecretStore.set_secret("KEY", "value")
            # Cache should still hold the value even if flush failed
            assert SecretStore._cache.get("KEY") == "value"


# ---------------------------------------------------------------------------
# Single-blob integrity
# ---------------------------------------------------------------------------

class TestBlobIntegrity:
    def test_multiple_keys_in_single_blob(self):
        from secret_store import SecretStore
        get_pw, set_pw, store = _make_keyring()
        with patch("keyring.get_password", side_effect=get_pw), \
             patch("keyring.set_password", side_effect=set_pw):
            SecretStore.set_secret("K1", "v1")
            SecretStore.set_secret("K2", "v2")
            # Reset cache to force a re-read from the "keychain"
            SecretStore._cache = None
            assert SecretStore.get_secret("K1") == "v1"
            assert SecretStore.get_secret("K2") == "v2"

    def test_blob_is_valid_json(self):
        from secret_store import SecretStore
        get_pw, set_pw, store = _make_keyring()
        with patch("keyring.get_password", side_effect=get_pw), \
             patch("keyring.set_password", side_effect=set_pw):
            SecretStore.set_secret("K", "v")
        raw = store.get("OpenElia:secrets")
        assert raw is not None
        parsed = json.loads(raw)
        assert parsed["K"] == "v"
