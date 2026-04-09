#!/usr/bin/env python3
import hashlib
import hmac
import os
import platform
import ctypes
import json
import sys
from rich.console import Console

console = Console()

_IDP_HMAC_KEY_NAME = "IDP_HMAC_KEY"


def _get_hmac_key() -> bytes:
    """Return the HMAC signing key, auto-generating and persisting one if absent."""
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__))))
    from secret_store import SecretStore
    key = SecretStore.get_secret(_IDP_HMAC_KEY_NAME)
    if not key:
        import secrets as _sec
        key = _sec.token_hex(32)
        SecretStore.set_secret(_IDP_HMAC_KEY_NAME, key)
    return key.encode() if isinstance(key, str) else key


def sign_idp_session(claims: dict) -> dict:
    """Return a copy of claims with an HMAC-SHA256 signature appended."""
    payload = json.dumps({k: v for k, v in claims.items() if k != "_sig"}, sort_keys=True).encode()
    sig = hmac.new(_get_hmac_key(), payload, hashlib.sha256).hexdigest()
    return {**claims, "_sig": sig}


def verify_idp_session(session: dict) -> bool:
    """Return True if the session's HMAC signature is valid."""
    sig = session.get("_sig")
    if not sig:
        return False
    payload = json.dumps({k: v for k, v in session.items() if k != "_sig"}, sort_keys=True).encode()
    expected = hmac.new(_get_hmac_key(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected)


class RBACManager:
    @staticmethod
    def is_os_admin() -> bool:
        """Check for OS-level administrative/root privileges."""
        try:
            if platform.system() == "Windows":
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.getuid() == 0
        except AttributeError:
            return False

    @staticmethod
    def verify_idp_claims(required_roles: list) -> bool:
        """
        Verify the authenticated user's OAuth claims.
        In this prototype, we look for an 'idp_session.json' which simulates 
        a verified token from an IdP (e.g., GitHub, Okta).
        """
        idp_path = "state/idp_session.json"
        
        if not os.path.exists(idp_path):
            console.print("[yellow]Warning: No IdP session found. Access restricted.[/yellow]")
            return False
            
        try:
            with open(idp_path, "r") as f:
                claims = json.load(f)

            if not verify_idp_session(claims):
                console.print("[red]✗ IdP Session integrity check failed: signature invalid or tampered.[/red]")
                return False

            user_roles = claims.get("roles", [])
            has_role = any(role in user_roles for role in required_roles)

            if has_role:
                console.print(f"[green]✓ IdP Claims Verified: User '{claims.get('user')}' has {user_roles}.[/green]")
                return True
            else:
                console.print(f"[red]✗ IdP Auth Error: User lacks required roles {required_roles}.[/red]")
                return False
        except Exception as e:
            console.print(f"[red]Error parsing IdP session: {e}[/red]")
            return False

    @classmethod
    def enforce_red_team_auth(cls):
        """Tier 1: Enforce high-level authentication for offensive ops."""
        console.print("\n[bold magenta]🛡️ OpenElia RBAC Authorization[/bold magenta]")
        
        # 1. Check OS Privileges
        if not cls.is_os_admin():
            console.print("[red]✗ Access Denied: OS Administrative privileges required for offensive modules.[/red]")
            console.print("[dim]Hint: Run with 'sudo' or as Administrator.[/dim]")
            return False
            
        # 2. Check IdP Claims
        if not cls.verify_idp_claims(["admin", "security_lead", "red_team_lead"]):
            console.print("[red]✗ Access Denied: Verified Security Lead claim required.[/red]")
            return False
            
        console.print("[bold green]✅ Authorization Granted: Unlocking Offensive Modules.[/bold green]\n")
        return True
