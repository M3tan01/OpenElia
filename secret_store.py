#!/usr/bin/env python3
import keyring
import logging
import os
import sys
import getpass
from rich.console import Console

_audit_logger = logging.getLogger("OpenElia.SecretStore")

console = Console()

SERVICE_NAME = "OpenElia"

class SecretStore:
    @staticmethod
    def set_secret(key_name: str, value: str):
        """Store a secret in the OS keyring."""
        try:
            keyring.set_password(SERVICE_NAME, key_name, value)
        except Exception as e:
            _audit_logger.warning("Failed to store secret in keyring: %s", str(e))

    @staticmethod
    def get_secret(key_name: str) -> str:
        """Retrieve a secret from the OS keyring."""
        secret = None
        source = "missing"
        try:
            secret = keyring.get_password(SERVICE_NAME, key_name)
            source = "keyring" if secret else "missing"
        except Exception as e:
            _audit_logger.warning("Keyring access failed for %s: %s", key_name, str(e))
            source = "keyring_error"

        if not secret:
            secret = os.getenv(key_name)
            if secret:
                source = "env"

        # Audit: log key name and source only — never the value
        _audit_logger.info("secret_access key=%s source=%s found=%s", key_name, source, secret is not None)

        return secret

    @staticmethod
    def delete_secret(key_name: str):
        """Delete a secret from the OS keyring."""
        try:
            keyring.delete_password(SERVICE_NAME, key_name)
        except (keyring.errors.PasswordDeleteError, Exception):
            pass

    @classmethod
    def bootstrap(cls):
        """
        Interactively migrate keys from .env to keyring and prompt for missing ones.
        """
        # On macOS the Keychain distinguishes read vs write access. We do a
        # write+read+delete here so macOS prompts ONCE before the key loop.
        # The user should click "Always Allow" — not just "Allow" — to avoid
        # a separate dialog for every key.
        if sys.platform == "darwin":
            console.print(
                "\n[bold yellow]macOS Keychain:[/bold yellow] A dialog will ask for permission.\n"
                "  → Click [bold]'Always Allow'[/bold] (not just 'Allow') to grant access for all keys at once.\n"
            )

        try:
            keyring.set_password(SERVICE_NAME, "_health_check", "ok")
            result = keyring.get_password(SERVICE_NAME, "_health_check")
            if result != "ok":
                raise RuntimeError("Keyring write-read verification failed")
            keyring.delete_password(SERVICE_NAME, "_health_check")
        except Exception as e:
            console.print(f"[yellow]⚠️ Keyring access is limited or unavailable: {str(e)}[/yellow]")
            console.print("[yellow]Falling back to environment variables. Add your keys to .env instead.[/yellow]")
            return

        console.print("\n[bold cyan]🔐 OpenElia Tier 1 Secret Migration[/bold cyan]")
        
        required_keys = [
            "GEMINI_API_KEY",
            "OLLAMA_BASE_URL",
            "SHODAN_API_KEY",
            "VT_API_KEY",
            "GRAYNOISE_API_KEY",
            "THEHIVE_API_KEY",
        ]
        
        for key in required_keys:
            existing = cls.get_secret(key)
            
            if not existing:
                console.print(f"[yellow]Missing {key}.[/yellow]")
                value = getpass.getpass(f"Enter your {key}: ").strip()
                if value:
                    cls.set_secret(key, value)
                    # Verify the write actually persisted
                    if keyring.get_password(SERVICE_NAME, key):
                        console.print(f"[green]✓ {key} stored in hardware-backed keychain.[/green]")
                    else:
                        console.print(f"[red]✗ {key} could not be saved to keychain.[/red]")
                        console.print(f"[yellow]  Add it to your .env file: {key}=<value>[/yellow]")
            else:
                # Key exists in keyring or env
                # If it's only in env, move it to keyring
                # Use a safe check for keyring presence
                try:
                    is_in_keyring = keyring.get_password(SERVICE_NAME, key) is not None
                except Exception:
                    is_in_keyring = False

                if not is_in_keyring and os.getenv(key):
                    try:
                        cls.set_secret(key, os.getenv(key))
                        console.print(f"[green]✓ Migrated {key} from .env to hardware-backed keychain.[/green]")
                    except Exception:
                        pass

        # Check if .env still exists and contains secrets
        if os.path.exists(".env"):
            console.print("\n[bold red]⚠️ SECURITY WARNING:[/bold red]")
            console.print("Your secrets are now stored securely in your OS Keychain.")
            console.print("The plaintext [bold].env[/bold] file is no longer needed and represents a security risk.")
            console.print("[bold green]Recommendation: Delete the .env file now.[/bold green]\n")
