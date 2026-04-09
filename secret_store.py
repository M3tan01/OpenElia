#!/usr/bin/env python3
import keyring
import logging
import os
import getpass
from rich.console import Console

_audit_logger = logging.getLogger("OpenElia.SecretStore")

console = Console()

SERVICE_NAME = "OpenElia"

class SecretStore:
    @staticmethod
    def set_secret(key_name: str, value: str):
        """Store a secret in the OS keyring."""
        keyring.set_password(SERVICE_NAME, key_name, value)

    @staticmethod
    def get_secret(key_name: str) -> str:
        """Retrieve a secret from the OS keyring."""
        secret = keyring.get_password(SERVICE_NAME, key_name)
        source = "keyring"

        if not secret:
            secret = os.getenv(key_name)
            source = "env" if secret else "missing"

        # Audit: log key name and source only — never the value
        _audit_logger.info("secret_access key=%s source=%s found=%s", key_name, source, secret is not None)

        return secret

    @staticmethod
    def delete_secret(key_name: str):
        """Delete a secret from the OS keyring."""
        try:
            keyring.delete_password(SERVICE_NAME, key_name)
        except keyring.errors.PasswordDeleteError:
            pass

    @classmethod
    def bootstrap(cls):
        """
        Interactively migrate keys from .env to keyring and prompt for missing ones.
        """
        console.print("\n[bold cyan]🔐 OpenElia Tier 1 Secret Migration[/bold cyan]")
        
        required_keys = [
            "GEMINI_API_KEY", 
            "OLLAMA_BASE_URL", 
            "SHODAN_API_KEY", 
            "VT_API_KEY", 
            "GRAYNOISE_API_KEY", 
            "THEHIVE_API_KEY"
        ]
        
        for key in required_keys:
            existing = cls.get_secret(key)
            
            if not existing:
                console.print(f"[yellow]Missing {key}.[/yellow]")
                value = getpass.getpass(f"Enter your {key}: ").strip()
                if value:
                    cls.set_secret(key, value)
                    console.print(f"[green]✓ {key} stored in hardware-backed keychain.[/green]")
            else:
                # Key exists in keyring or env
                # If it's only in env, move it to keyring
                if not keyring.get_password(SERVICE_NAME, key) and os.getenv(key):
                    cls.set_secret(key, os.getenv(key))
                    console.print(f"[green]✓ Migrated {key} from .env to hardware-backed keychain.[/green]")

        # Check if .env still exists and contains secrets
        if os.path.exists(".env"):
            console.print("\n[bold red]⚠️ SECURITY WARNING:[/bold red]")
            console.print("Your secrets are now stored securely in your OS Keychain.")
            console.print("The plaintext [bold].env[/bold] file is no longer needed and represents a security risk.")
            console.print("[bold green]Recommendation: Delete the .env file now.[/bold green]\n")
