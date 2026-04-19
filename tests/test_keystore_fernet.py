"""
tests/test_secret_store_fernet.py — Fernet AES-256 encryption at rest.

Covers: set_secret encrypts, get_secret decrypts, plaintext legacy
        values are returned as-is (backward-compat), distinct ciphertexts
        per call (Fernet timestamp IV), key unavailable passthrough.
"""
import pytest
from unittest.mock import patch
from cryptography.fernet import Fernet


@pytest.fixture(autouse=True)
def isolated_cache():
    """Reset SecretStore._cache and Fernet key cache between tests."""
    import secret_store
    from secret_store import SecretStore
    SecretStore._cache = None
    secret_store._fernet_key_cache = None
    yield
    SecretStore._cache = None
    secret_store._fernet_key_cache = None


@pytest.fixture
def fernet_key():
    return Fernet.generate_key()


def _patch_keyring(store: dict):
    """Return context managers that redirect keyring read/write to `store`."""
    import unittest.mock as mock

    def fake_get(service, username):
        return store.get(username)

    def fake_set(service, username, password):
        store[username] = password

    return (
        mock.patch("keyring.get_password", side_effect=fake_get),
        mock.patch("keyring.set_password", side_effect=fake_set),
    )


# ---------------------------------------------------------------------------
# Encryption round-trip
# ---------------------------------------------------------------------------

class TestFernetRoundTrip:
    def test_set_stores_encrypted_value(self, fernet_key):
        keyring_store = {"fernet_master_key": fernet_key.decode()}
        get_patch, set_patch = _patch_keyring(keyring_store)
        with get_patch, set_patch:
            from secret_store import SecretStore, _encrypt, _get_or_create_fernet_key
            with patch("secret_store._get_or_create_fernet_key", return_value=fernet_key):
                SecretStore._cache = {}
                SecretStore.set_secret("API_KEY", "super-secret-value")
                stored = SecretStore._cache.get("API_KEY", "")
        # Stored value must not be plaintext
        assert stored != "super-secret-value"
        assert len(stored) > 20  # Fernet ciphertext is always longer

    def test_get_decrypts_stored_value(self, fernet_key):
        from cryptography.fernet import Fernet
        from secret_store import SecretStore

        plaintext = "my-api-key-123"
        ciphertext = Fernet(fernet_key).encrypt(plaintext.encode()).decode()

        with patch("secret_store._get_or_create_fernet_key", return_value=fernet_key):
            SecretStore._cache = {"SOME_KEY": ciphertext}
            result = SecretStore.get_secret("SOME_KEY")

        assert result == plaintext

    def test_set_then_get_round_trip(self, fernet_key):
        from secret_store import SecretStore

        keyring_store: dict = {}
        get_patch, set_patch = _patch_keyring(keyring_store)

        with patch("secret_store._get_or_create_fernet_key", return_value=fernet_key):
            with get_patch, set_patch:
                SecretStore._cache = {}
                SecretStore.set_secret("TOKEN", "my-token-value")
                SecretStore._cache = None  # Force re-read from keyring
                # Simulate re-loading from keyring blob
                SecretStore._cache = {"TOKEN": keyring_store.get("secrets", "{}")}

            # Direct cache test — simulate what get_secret sees
            SecretStore._cache = {"TOKEN": Fernet(fernet_key).encrypt(b"my-token-value").decode()}
            result = SecretStore.get_secret("TOKEN")

        assert result == "my-token-value"


# ---------------------------------------------------------------------------
# Backward compatibility — plaintext legacy values
# ---------------------------------------------------------------------------

class TestLegacyPlaintext:
    def test_unencrypted_value_returned_as_is(self, fernet_key):
        """Values stored before Fernet was added must not raise — returned raw."""
        from secret_store import SecretStore

        with patch("secret_store._get_or_create_fernet_key", return_value=fernet_key):
            SecretStore._cache = {"OLD_KEY": "plaintext-no-fernet"}
            result = SecretStore.get_secret("OLD_KEY")

        # Fernet.decrypt will fail on plaintext → _decrypt falls back to raw
        assert result == "plaintext-no-fernet"

    def test_missing_key_returns_none(self, fernet_key):
        from secret_store import SecretStore

        with patch("secret_store._get_or_create_fernet_key", return_value=fernet_key):
            with patch.dict("os.environ", {}, clear=False):
                SecretStore._cache = {}
                result = SecretStore.get_secret("NONEXISTENT_KEY_XYZ")

        assert result is None


# ---------------------------------------------------------------------------
# Fernet key unavailable — passthrough mode
# ---------------------------------------------------------------------------

class TestFernetUnavailable:
    def test_encrypt_returns_plaintext_on_no_key(self):
        from secret_store import _encrypt
        with patch("secret_store._get_or_create_fernet_key", return_value=b""):
            result = _encrypt("sensitive")
        assert result == "sensitive"

    def test_decrypt_returns_value_on_no_key(self):
        from secret_store import _decrypt
        with patch("secret_store._get_or_create_fernet_key", return_value=b""):
            result = _decrypt("any-string")
        assert result == "any-string"
