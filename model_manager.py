#!/usr/bin/env python3
"""
model_manager.py — Dynamic Model Configuration Manager for OpenElia.

Config is persisted to ~/.config/openelia/config.json.
Only mode/model names are stored here — API keys stay exclusively in the
OS keychain via SecretStore.

Supported sub-commands (invoked through main.py):
  model status                                  — show active configuration
  model set local <model_name>                  — set Ollama model
  model set cloud <provider> <model_name>       — set cloud provider + model
  model auth <provider> <api_key>               — store API key in keychain
  model hybrid --agent <name> --provider <p> --model <m>  — per-agent override
"""

import json
import os
import pathlib

_CONFIG_DIR  = pathlib.Path.home() / ".config" / "openelia"
_CONFIG_FILE = _CONFIG_DIR / "config.json"

_DEFAULTS: dict = {
    "mode":            "local",    # "local" | "cloud" | "hybrid"
    "local_model":     "llama3.1:8b",
    "cloud_provider":  "openai",   # "openai" | "anthropic" | "google"
    "cloud_model":     "gpt-4o",
    "agent_overrides": {},          # {"Pentester": "local:llama3.1:8b", ...}
    "loop_detection": {             # tool-loop guardrail thresholds (core/loop_guard.py)
        "enabled":                True,
        "max_total_turns":        25,
        "max_same_call":          3,
        "max_idempotent_repeats": 2,
    },
}

# OpenAI-compatible base URLs for each provider
PROVIDER_BASE_URLS: dict[str, str] = {
    "openai":    "https://api.openai.com/v1/",
    "anthropic": "https://api.anthropic.com/v1/",
    "google":    "https://generativelanguage.googleapis.com/v1beta/openai/",
    "ollama":    "http://localhost:11434/v1/",
    "local":     "http://localhost:11434/v1/",
}

# SecretStore key names for each provider
PROVIDER_KEY_NAMES: dict[str, str] = {
    "openai":    "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "google":    "GOOGLE_API_KEY",
}

SUPPORTED_PROVIDERS = list(PROVIDER_KEY_NAMES.keys())


class ModelManager:
    """Read/write model configuration. API keys never leave the OS keychain."""

    # ------------------------------------------------------------------ #
    # Config I/O                                                           #
    # ------------------------------------------------------------------ #

    @classmethod
    def _load(cls) -> dict:
        _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        if _CONFIG_FILE.exists():
            try:
                with _CONFIG_FILE.open() as fh:
                    data = json.load(fh)
                merged = {**_DEFAULTS, **data}
                merged.setdefault("agent_overrides", {})
                return merged
            except Exception:
                pass
        return dict(_DEFAULTS)

    @classmethod
    def _save(cls, config: dict) -> None:
        _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with _CONFIG_FILE.open("w") as fh:
            json.dump(config, fh, indent=2)

    # ------------------------------------------------------------------ #
    # Mutators                                                             #
    # ------------------------------------------------------------------ #

    @classmethod
    def get_config(cls) -> dict:
        return cls._load()

    @classmethod
    def get_loop_config(cls):
        """
        Return a LoopGuardConfig for the agent tool-loop guardrail.

        Sourced from the persisted ``loop_detection`` block, with an env override:
        ``OPENELIA_LOOP_DETECTION_ENABLED=0`` (or false/no/off) force-disables it.
        """
        from core.loop_guard import LoopGuardConfig

        cfg = cls._load().get("loop_detection") or {}
        env = os.environ.get("OPENELIA_LOOP_DETECTION_ENABLED")
        if env is not None:
            cfg = {**cfg, "enabled": env.strip().lower() not in ("0", "false", "no", "off")}
        return LoopGuardConfig.from_mapping(cfg)

    @classmethod
    def set_local_model(cls, model_name: str) -> None:
        cfg = cls._load()
        cfg["local_model"] = model_name
        if cfg["mode"] != "hybrid":
            cfg["mode"] = "local"
        cls._save(cfg)

    @classmethod
    def list_local_models(cls) -> list[str]:
        """Names of models installed in the local Ollama daemon.

        Hits the Ollama ``/api/tags`` endpoint (derived from OLLAMA_BASE_URL,
        default localhost:11434). Returns a sorted, de-duped list of model
        names. Never raises — Ollama down / unreachable / bad payload → [].
        """
        import json
        import urllib.error
        import urllib.request

        from secret_store import SecretStore

        base = SecretStore.get_secret("OLLAMA_BASE_URL") or "http://localhost:11434/v1/"
        # tags live at the daemon root, not under the OpenAI-compat /v1 path
        root = base.split("/v1", 1)[0].rstrip("/")
        if not root.startswith(("http://", "https://")):
            return []  # refuse non-HTTP schemes (file://, etc.)
        url = f"{root}/api/tags"
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:  # nosec B310 - scheme guarded above; local Ollama
                payload = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError):
            return []
        models = payload.get("models", []) if isinstance(payload, dict) else []
        names = [m.get("name") for m in models if isinstance(m, dict) and m.get("name")]
        return sorted(set(names))

    @classmethod
    def set_cloud_model(cls, provider: str, model_name: str) -> None:
        provider = provider.lower()
        cfg = cls._load()
        cfg["cloud_provider"] = provider
        cfg["cloud_model"] = model_name
        if cfg["mode"] != "hybrid":
            cfg["mode"] = "cloud"
        cls._save(cfg)

    @classmethod
    def set_agent_override(cls, agent: str, provider: str, model_name: str) -> None:
        """Pin a specific agent to a provider:model pair and enable hybrid mode."""
        cfg = cls._load()
        cfg["mode"] = "hybrid"
        cfg["agent_overrides"][agent] = f"{provider.lower()}:{model_name}"
        cls._save(cfg)

    @classmethod
    def store_provider_key(cls, provider: str, api_key: str) -> None:
        """Persist a provider API key to the OS keychain via SecretStore."""
        from secret_store import SecretStore
        provider = provider.lower()
        key_name = PROVIDER_KEY_NAMES.get(provider)
        if not key_name:
            raise ValueError(
                f"Unknown provider '{provider}'. Supported: {SUPPORTED_PROVIDERS}"
            )
        SecretStore.set_secret(key_name, api_key)

    # ------------------------------------------------------------------ #
    # Client resolution                                                    #
    # ------------------------------------------------------------------ #

    @classmethod
    def _sanitize_url(cls, url: str) -> str:
        """AUTONOMIC RESILIENCE: Ensure URL has /v1; do not force a trailing slash.

        The OpenAI-compatible client accepts base URLs with or without a
        trailing slash, and forcing one risks a double slash when callers
        join paths (f"{url}/models"). We normalize the /v1 suffix only and
        return the URL otherwise untouched (sans trailing slash).
        """
        if not url: return ""
        u = url.strip().rstrip("/")

        # If it's a standard provider but missing /v1, add it
        if "api.openai.com" in u and "/v1" not in u:
            u = u + "/v1"
        if "api.anthropic.com" in u and "/v1" not in u:
            u = u + "/v1"

        # Generic check for Ollama / local proxies
        if u.endswith(":11434"):
            u = u + "/v1"

        return u

    @classmethod
    def get_client_config(
        cls,
        brain_tier: str = "local",
        agent_name: str | None = None,
    ) -> dict:
        """
        Return {"base_url": ..., "api_key": ..., "model": ..., "is_local": ...} for the
        given brain_tier / agent_name combination.

        Resolution order:
          1. Per-agent hybrid override (if mode == "hybrid" and agent_name set)
          2. Explicit brain_tier == "expensive"  → cloud config
          3. Global mode == "cloud"              → cloud config
          4. Default                             → local Ollama config
        """
        from secret_store import SecretStore
        cfg = cls._load()

        # 1. Per-agent override takes precedence in hybrid mode
        if agent_name and cfg["mode"] == "hybrid":
            override = cfg["agent_overrides"].get(agent_name)
            if override and ":" in override:
                prov, mdl = override.split(":", 1)
                res = cls._resolve(prov, mdl)
                res["is_local"] = (prov in ("local", "ollama"))
                return res

        # 2 & 3. Expensive tier or global cloud mode
        if brain_tier == "expensive" or cfg["mode"] == "cloud":
            provider  = cfg.get("cloud_provider", "openai")
            model     = cfg.get("cloud_model", "gpt-4o")
            key_name  = PROVIDER_KEY_NAMES.get(provider, "EXPENSIVE_BRAIN_KEY")
            api_key   = (
                SecretStore.get_secret(key_name)
                or SecretStore.get_secret("EXPENSIVE_BRAIN_KEY")
                or "ollama"
            )
            base_url  = (
                SecretStore.get_secret("EXPENSIVE_BRAIN_URL")
                or PROVIDER_BASE_URLS.get(provider, "https://api.openai.com/v1/")
            )
            return {
                "base_url": cls._sanitize_url(base_url),
                "api_key": api_key,
                "model": model,
                "is_local": False
            }

        # 4. Local / Ollama
        res = cls._resolve("local", cfg.get("local_model", "llama3.1:8b"))
        res["is_local"] = True
        return res

    @classmethod
    def _resolve(cls, provider: str, model: str) -> dict:
        from secret_store import SecretStore
        if provider in ("local", "ollama"):
            base_url = (
                SecretStore.get_secret("OLLAMA_BASE_URL")
                or "http://localhost:11434/v1/"
            )
            return {
                "base_url": cls._sanitize_url(base_url),
                "api_key": "ollama",
                "model": model
            }
        key_name = PROVIDER_KEY_NAMES.get(provider, "EXPENSIVE_BRAIN_KEY")
        api_key  = (
            SecretStore.get_secret(key_name)
            or SecretStore.get_secret("EXPENSIVE_BRAIN_KEY")
            or "ollama"
        )
        base_url = PROVIDER_BASE_URLS.get(provider, "https://api.openai.com/v1/")
        return {
            "base_url": cls._sanitize_url(base_url),
            "api_key": api_key,
            "model": model
        }
