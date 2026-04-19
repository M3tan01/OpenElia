#!/usr/bin/env python3
"""
secret_store.py — OS keyring integration for OpenElia.

All secrets are stored as a single JSON blob under one Keychain entry
("OpenElia" / "secrets"). This means macOS prompts exactly once per
process — one dialog for the read on startup, one for the write when
something changes — regardless of how many individual keys exist.

An in-memory cache means subsequent get_secret() calls within the same
process never touch the Keychain at all.
"""
import base64
import json
import keyring
import logging
import os
import sys
import getpass
from rich.console import Console

_audit_logger = logging.getLogger("OpenElia.SecretStore")

console = Console()

SERVICE_NAME = "OpenElia"
_BLOB_KEY    = "secrets"        # Single Keychain entry that holds everything
_FERNET_KEY_ENTRY = "fernet_master_key"  # Keychain entry for the Fernet key

# ---------------------------------------------------------------------------
# Fernet encryption helpers — AES-128-CBC + HMAC-SHA256 (cryptography package)
# ---------------------------------------------------------------------------

_fernet_key_cache: bytes | None = None  # Process-level cache — one keyring hit per process


def _get_or_create_fernet_key() -> bytes:
    """
    Load the Fernet key from the Keychain, generating one on first run.
    Cached in-process so subsequent calls never touch the Keychain.
    The key itself lives unencrypted in the OS Keychain, which is the
    trust boundary. Values in the secrets blob are encrypted with it.
    """
    global _fernet_key_cache
    if _fernet_key_cache is not None:
        return _fernet_key_cache
    try:
        raw = keyring.get_password(SERVICE_NAME, _FERNET_KEY_ENTRY)
        if raw:
            _fernet_key_cache = raw.encode()
            return _fernet_key_cache
        # First run — generate and persist
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()          # URL-safe base64, 32 random bytes
        keyring.set_password(SERVICE_NAME, _FERNET_KEY_ENTRY, key.decode())
        _fernet_key_cache = key
        return _fernet_key_cache
    except Exception as exc:
        _audit_logger.warning("Fernet key unavailable (%s) — using passthrough mode", exc)
        _fernet_key_cache = b""
        return b""


def _encrypt(value: str) -> str:
    """Return Fernet-encrypted, base64-encoded ciphertext, or plain value on error."""
    key = _get_or_create_fernet_key()
    if not key:
        return value
    try:
        from cryptography.fernet import Fernet
        return Fernet(key).encrypt(value.encode()).decode()
    except Exception as exc:
        _audit_logger.warning("Fernet encrypt failed (%s) — storing plaintext", exc)
        return value


def _decrypt(value: str) -> str:
    """Return decrypted plaintext, or the original value if it was never encrypted."""
    key = _get_or_create_fernet_key()
    if not key:
        return value
    try:
        from cryptography.fernet import Fernet
        return Fernet(key).decrypt(value.encode()).decode()
    except Exception:
        # Not encrypted (legacy plaintext entry) — return as-is
        return value


class SecretStore:
    # In-process cache — populated on first access, avoids repeated Keychain dialogs
    _cache: dict | None = None

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    @classmethod
    def _load(cls) -> dict:
        """Read the blob from Keychain once and warm the cache."""
        if cls._cache is None:
            try:
                raw = keyring.get_password(SERVICE_NAME, _BLOB_KEY)
                cls._cache = json.loads(raw) if raw else {}
            except Exception as e:
                _audit_logger.warning("Keyring read failed: %s", e)
                cls._cache = {}
        return cls._cache

    @classmethod
    def _flush(cls):
        """Write the current cache back to the single Keychain entry."""
        try:
            keyring.set_password(SERVICE_NAME, _BLOB_KEY, json.dumps(cls._cache))
        except Exception as e:
            _audit_logger.warning("Keyring write failed: %s", e)

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    @classmethod
    def set_secret(cls, key_name: str, value: str):
        """Encrypt and store a secret. Triggers at most one Keychain write dialog."""
        cls._load()
        cls._cache[key_name] = _encrypt(value)
        cls._flush()

    @classmethod
    def get_secret(cls, key_name: str) -> str | None:
        """Retrieve and decrypt a secret from cache/Keychain, then fall back to env."""
        secrets = cls._load()
        raw = secrets.get(key_name)
        source = "keyring" if raw else "missing"

        if raw:
            secret = _decrypt(raw)
        else:
            secret = os.getenv(key_name)
            if secret:
                source = "env"
            else:
                secret = None

        _audit_logger.info("secret_access key=%s source=%s found=%s",
                           key_name, source, secret is not None)
        return secret

    @classmethod
    def delete_secret(cls, key_name: str):
        """Remove a single key from the blob."""
        cls._load()
        if key_name in cls._cache:
            del cls._cache[key_name]
            cls._flush()

    # ------------------------------------------------------------------ #
    # Bootstrap                                                            #
    # ------------------------------------------------------------------ #

    @classmethod
    def bootstrap(cls):
        """
        Interactively prompt for missing secrets and store them in the
        OS Keychain. Secrets are stored as a single JSON blob so macOS
        shows only ONE Keychain dialog for the entire session.
        """
        if sys.platform == "darwin":
            console.print(
                "\n[bold yellow]macOS Keychain:[/bold yellow] You will see one dialog "
                "when OpenElia first reads/writes the Keychain.\n"
                "  → Click [bold]'Always Allow'[/bold] so it does not ask again.\n"
            )

        # Health check: one write + read verifies the Keychain is usable.
        # This also warms the cache so the loop below never triggers a dialog.
        try:
            keyring.set_password(SERVICE_NAME, _BLOB_KEY,
                                 keyring.get_password(SERVICE_NAME, _BLOB_KEY) or "{}")
            raw = keyring.get_password(SERVICE_NAME, _BLOB_KEY)
            cls._cache = json.loads(raw) if raw else {}
        except Exception as e:
            console.print(f"[yellow]⚠️  Keyring unavailable: {e}[/yellow]")
            console.print("[yellow]Add your keys to .env instead.[/yellow]")
            return

        console.print("\n[bold cyan]🔐 OpenElia Secret Setup[/bold cyan]")

        required_keys = [
            "OLLAMA_BASE_URL",
            "GEMINI_API_KEY",
            "SHODAN_API_KEY",
            "VT_API_KEY",
            "GRAYNOISE_API_KEY",
        ]

        optional_keys = [
            # Expensive brain — skip if using local Ollama only
            ("EXPENSIVE_BRAIN_URL", "Expensive brain base URL (e.g. https://api.openai.com/v1 or https://api.anthropic.com)"),
            ("EXPENSIVE_BRAIN_KEY", "Expensive brain API key (OpenAI / Anthropic / Gemini)"),
            ("EXPENSIVE_MODEL",     "Model name (e.g. gpt-4o, claude-opus-4-6, gemini-1.5-pro) [default: gpt-4o]"),
            # Operational constraints
            ("MAX_TOKEN_BUDGET",    "Max spend per session in USD [default: 5.00]"),
            ("CYBER_RISK_INSTRUCTION", "Custom risk instruction injected into every agent prompt"),
            # SIEM webhook forwarding
            ("SIEM_WEBHOOK_ALLOWLIST", "Comma-separated approved SIEM hostnames (e.g. splunk.corp.com,siem.internal)"),
            # Blue team live remediation
            ("BLUE_REMEDIATE_RBAC_TOKEN", "RBAC token for live iptables/kill execution (any strong random string)"),
            # TheHive — skip if not using case management
            ("THEHIVE_URL",         "TheHive instance URL (e.g. https://thehive.corp.com)"),
            ("THEHIVE_API_KEY",     "TheHive API key"),
        ]

        def _prompt(key: str, label: str, required: bool = True):
            existing = cls.get_secret(key)
            if existing:
                console.print(f"  [dim]✓ {key} already set.[/dim]")
                return
            value = getpass.getpass(f"  {label}: ").strip()
            if value:
                # Write directly into cache; single _flush() at the end
                cls._cache[key] = value
                console.print(f"  [green]✓ {key} noted.[/green]")
            else:
                if required:
                    console.print(f"  [yellow]↩ {key} skipped — add to .env if needed.[/yellow]")
                else:
                    console.print(f"  [dim]↩ {key} skipped.[/dim]")

        console.print("\n[bold]Required integrations:[/bold]")
        for key in required_keys:
            _prompt(key, f"Enter your {key}", required=True)

        console.print("\n[bold]Optional integrations[/bold] [dim](press Enter to skip):[/dim]")
        for key, label in optional_keys:
            _prompt(key, label, required=False)

        # Single write for everything entered above
        cls._flush()

        # Migrate any remaining .env keys into the blob
        migrated = []
        for key in [*required_keys, *[k for k, _ in optional_keys]]:
            if not cls._cache.get(key) and os.getenv(key):
                cls._cache[key] = os.getenv(key)
                migrated.append(key)
        if migrated:
            cls._flush()
            for key in migrated:
                console.print(f"[green]✓ Migrated {key} from .env to keychain.[/green]")

        if os.path.exists(".env"):
            console.print("\n[bold red]⚠️  SECURITY WARNING:[/bold red]")
            console.print("Secrets are now stored in the OS Keychain.")
            console.print("Delete the plaintext [bold].env[/bold] file: [bold]rm .env[/bold]\n")
