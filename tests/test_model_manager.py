"""
tests/test_model_manager.py — Unit tests for ModelManager and LLMClient.
"""
import json
import pathlib
import pytest
from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    """Redirect config I/O to a temp directory for every test."""
    import model_manager as mm
    monkeypatch.setattr(mm, "_CONFIG_DIR",  tmp_path / "openelia")
    monkeypatch.setattr(mm, "_CONFIG_FILE", tmp_path / "openelia" / "config.json")
    # Also patch the module-level names the class methods resolve at call time
    monkeypatch.setattr("model_manager._CONFIG_DIR",  tmp_path / "openelia")
    monkeypatch.setattr("model_manager._CONFIG_FILE", tmp_path / "openelia" / "config.json")
    yield tmp_path


# ---------------------------------------------------------------------------
# ModelManager — config I/O
# ---------------------------------------------------------------------------

class TestModelManagerDefaults:
    def test_get_config_returns_defaults_when_no_file(self):
        from model_manager import ModelManager, _DEFAULTS
        cfg = ModelManager.get_config()
        assert cfg["mode"]           == _DEFAULTS["mode"]
        assert cfg["local_model"]    == _DEFAULTS["local_model"]
        assert cfg["cloud_provider"] == _DEFAULTS["cloud_provider"]
        assert cfg["cloud_model"]    == _DEFAULTS["cloud_model"]
        assert cfg["agent_overrides"] == {}

    def test_set_local_model(self):
        from model_manager import ModelManager
        ModelManager.set_local_model("mistral:7b")
        cfg = ModelManager.get_config()
        assert cfg["local_model"] == "mistral:7b"
        assert cfg["mode"]        == "local"

    def test_set_cloud_model(self):
        from model_manager import ModelManager
        ModelManager.set_cloud_model("anthropic", "claude-opus-4-6")
        cfg = ModelManager.get_config()
        assert cfg["cloud_provider"] == "anthropic"
        assert cfg["cloud_model"]    == "claude-opus-4-6"
        assert cfg["mode"]           == "cloud"

    def test_set_cloud_model_normalises_provider(self):
        from model_manager import ModelManager
        ModelManager.set_cloud_model("OPENAI", "gpt-4o")
        assert ModelManager.get_config()["cloud_provider"] == "openai"

    def test_set_agent_override_enables_hybrid(self):
        from model_manager import ModelManager
        ModelManager.set_agent_override("Reporter", "anthropic", "claude-sonnet-4-6")
        cfg = ModelManager.get_config()
        assert cfg["mode"] == "hybrid"
        assert cfg["agent_overrides"]["Reporter"] == "anthropic:claude-sonnet-4-6"

    def test_multiple_overrides_preserved(self):
        from model_manager import ModelManager
        ModelManager.set_agent_override("Pentester", "local", "llama3.1:8b")
        ModelManager.set_agent_override("Reporter",  "openai", "gpt-4o")
        cfg = ModelManager.get_config()
        assert cfg["agent_overrides"]["Pentester"] == "local:llama3.1:8b"
        assert cfg["agent_overrides"]["Reporter"]  == "openai:gpt-4o"

    def test_set_local_preserves_hybrid_mode(self):
        """Changing local model should not downgrade hybrid → local."""
        from model_manager import ModelManager
        ModelManager.set_agent_override("Defender", "openai", "gpt-4o")
        ModelManager.set_local_model("llama3.2:latest")
        assert ModelManager.get_config()["mode"] == "hybrid"

    def test_config_persists_across_instances(self, tmp_path):
        from model_manager import ModelManager
        ModelManager.set_local_model("deepseek-r1:14b")
        cfg = ModelManager.get_config()
        assert cfg["local_model"] == "deepseek-r1:14b"

    def test_corrupt_config_falls_back_to_defaults(self, tmp_path):
        import model_manager as mm
        config_file = tmp_path / "openelia" / "config.json"
        config_file.parent.mkdir(parents=True, exist_ok=True)
        config_file.write_text("{ invalid json }")
        from model_manager import ModelManager
        cfg = ModelManager.get_config()
        assert cfg["mode"] == "local"


# ---------------------------------------------------------------------------
# ModelManager — store_provider_key
# ---------------------------------------------------------------------------

class TestStoreProviderKey:
    def test_valid_provider(self):
        from model_manager import ModelManager
        with patch("secret_store.SecretStore.set_secret") as mock_set:
            ModelManager.store_provider_key("openai", "sk-test")
            mock_set.assert_called_once_with("OPENAI_API_KEY", "sk-test")

    def test_anthropic_key_name(self):
        from model_manager import ModelManager
        with patch("secret_store.SecretStore.set_secret") as mock_set:
            ModelManager.store_provider_key("anthropic", "sk-ant-test")
            mock_set.assert_called_once_with("ANTHROPIC_API_KEY", "sk-ant-test")

    def test_google_key_name(self):
        from model_manager import ModelManager
        with patch("secret_store.SecretStore.set_secret") as mock_set:
            ModelManager.store_provider_key("google", "AIza-test")
            mock_set.assert_called_once_with("GOOGLE_API_KEY", "AIza-test")

    def test_unknown_provider_raises(self):
        from model_manager import ModelManager
        with pytest.raises(ValueError, match="Unknown provider"):
            ModelManager.store_provider_key("perplexity", "some-key")


# ---------------------------------------------------------------------------
# ModelManager — get_client_config
# ---------------------------------------------------------------------------

class TestGetClientConfig:
    def _mock_secret(self, key_map: dict):
        """Return a side_effect fn that looks up keys in key_map."""
        def _get(key):
            return key_map.get(key)
        return _get

    def test_local_config_default(self):
        from model_manager import ModelManager
        with patch("secret_store.SecretStore.get_secret", side_effect=self._mock_secret({})):
            cfg = ModelManager.get_client_config(brain_tier="local")
        assert cfg["api_key"] == "ollama"
        assert cfg["model"]   == "llama3.1:8b"
        assert "11434" in cfg["base_url"]

    def test_local_config_uses_ollama_url_from_keychain(self):
        from model_manager import ModelManager
        secrets = {"OLLAMA_BASE_URL": "http://gpu-server:11434/v1"}
        with patch("secret_store.SecretStore.get_secret", side_effect=self._mock_secret(secrets)):
            cfg = ModelManager.get_client_config(brain_tier="local")
        assert cfg["base_url"] == "http://gpu-server:11434/v1"

    def test_expensive_uses_cloud_config(self):
        from model_manager import ModelManager
        ModelManager.set_cloud_model("openai", "gpt-4o")
        secrets = {"OPENAI_API_KEY": "sk-real"}
        with patch("secret_store.SecretStore.get_secret", side_effect=self._mock_secret(secrets)):
            cfg = ModelManager.get_client_config(brain_tier="expensive")
        assert cfg["api_key"] == "sk-real"
        assert cfg["model"]   == "gpt-4o"

    def test_expensive_falls_back_to_expensive_brain_key(self):
        from model_manager import ModelManager
        ModelManager.set_cloud_model("openai", "gpt-4o")
        secrets = {"EXPENSIVE_BRAIN_KEY": "sk-fallback"}
        with patch("secret_store.SecretStore.get_secret", side_effect=self._mock_secret(secrets)):
            cfg = ModelManager.get_client_config(brain_tier="expensive")
        assert cfg["api_key"] == "sk-fallback"

    def test_hybrid_override_wins(self):
        from model_manager import ModelManager
        ModelManager.set_agent_override("Reporter", "openai", "gpt-4o")
        secrets = {"OPENAI_API_KEY": "sk-openai"}
        with patch("secret_store.SecretStore.get_secret", side_effect=self._mock_secret(secrets)):
            cfg = ModelManager.get_client_config(brain_tier="local", agent_name="Reporter")
        assert cfg["model"]   == "gpt-4o"
        assert cfg["api_key"] == "sk-openai"

    def test_hybrid_falls_back_to_local_when_no_override(self):
        from model_manager import ModelManager
        ModelManager.set_agent_override("Reporter", "openai", "gpt-4o")
        with patch("secret_store.SecretStore.get_secret", return_value=None):
            # Pentester has no override — should get local config
            cfg = ModelManager.get_client_config(brain_tier="local", agent_name="Pentester")
        assert cfg["api_key"] == "ollama"

    def test_global_cloud_mode_without_brain_tier(self):
        from model_manager import ModelManager
        ModelManager.set_cloud_model("anthropic", "claude-sonnet-4-6")
        secrets = {"ANTHROPIC_API_KEY": "sk-ant-real"}
        with patch("secret_store.SecretStore.get_secret", side_effect=self._mock_secret(secrets)):
            cfg = ModelManager.get_client_config(brain_tier="local")  # mode wins
        assert cfg["model"]   == "claude-sonnet-4-6"
        assert cfg["api_key"] == "sk-ant-real"

    def test_expensive_brain_url_overrides_provider_default(self):
        from model_manager import ModelManager
        ModelManager.set_cloud_model("openai", "gpt-4o")
        secrets = {
            "OPENAI_API_KEY":     "sk-real",
            "EXPENSIVE_BRAIN_URL": "https://custom.proxy.com/v1",
        }
        with patch("secret_store.SecretStore.get_secret", side_effect=self._mock_secret(secrets)):
            cfg = ModelManager.get_client_config(brain_tier="expensive")
        assert cfg["base_url"] == "https://custom.proxy.com/v1"


# ---------------------------------------------------------------------------
# LLMClient
# ---------------------------------------------------------------------------

class TestLLMClient:
    def test_create_returns_client_and_model(self):
        from llm_client import LLMClient
        with patch("secret_store.SecretStore.get_secret", return_value=None):
            client, model = LLMClient.create(brain_tier="local")
        assert model == "llama3.1:8b"
        assert hasattr(client, "chat")

    def test_create_expensive_returns_cloud_model(self, isolated_config):
        from llm_client import LLMClient
        from model_manager import ModelManager
        ModelManager.set_cloud_model("openai", "gpt-4o")
        secrets = {"OPENAI_API_KEY": "sk-test"}
        with patch("secret_store.SecretStore.get_secret", side_effect=lambda k: secrets.get(k)):
            client, model = LLMClient.create(brain_tier="expensive")
        assert model == "gpt-4o"

    def test_create_hybrid_respects_agent_name(self, isolated_config):
        from llm_client import LLMClient
        from model_manager import ModelManager
        ModelManager.set_agent_override("Reporter", "openai", "gpt-4o-mini")
        secrets = {"OPENAI_API_KEY": "sk-test"}
        with patch("secret_store.SecretStore.get_secret", side_effect=lambda k: secrets.get(k)):
            _, model = LLMClient.create(brain_tier="local", agent_name="Reporter")
        assert model == "gpt-4o-mini"
