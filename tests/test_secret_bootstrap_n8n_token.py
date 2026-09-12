"""bootstrap() must offer N8N_WEBHOOK_TOKEN so operators can store the n8n
completion-callback shared secret in the Keychain / migrate it from .env."""
import inspect

from secret_store import SecretStore


def test_bootstrap_offers_n8n_webhook_token():
    src = inspect.getsource(SecretStore.bootstrap)
    assert "N8N_WEBHOOK_TOKEN" in src
