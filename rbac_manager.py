#!/usr/bin/env python3
import hashlib
import hmac
import os
import platform
import ctypes
import json
import sys
import time
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
        # Resolve the state dir at call time so `grant` (which mints the session)
        # and this verifier agree on one path, and both honor an OPENELIA_STATE_DIR
        # override — matching AuditLogger / webdash/guards / mcp siem.
        idp_path = os.path.join(os.getenv("OPENELIA_STATE_DIR", "state"), "idp_session.json")

        if not os.path.exists(idp_path):
            console.print("[yellow]Warning: No IdP session found. Access restricted.[/yellow]")
            return False
            
        try:
            with open(idp_path, "r") as f:
                claims = json.load(f)

            if not verify_idp_session(claims):
                console.print("[red]✗ IdP Session integrity check failed: signature invalid or tampered.[/red]")
                return False

            # Fail-closed expiry: `exp` is inside the signed payload, so it cannot be
            # extended without invalidating the signature. A session with no exp, or a
            # past/malformed exp, is rejected — a leaked file must not be a permanent
            # credential.
            exp = claims.get("exp")
            if exp is None:
                console.print("[red]✗ IdP Session missing expiry — rejecting (fail-closed).[/red]")
                return False
            try:
                if float(exp) < time.time():
                    console.print("[red]✗ IdP Session expired — mint a fresh one with 'openelia grant'.[/red]")
                    return False
            except (TypeError, ValueError):
                console.print("[red]✗ IdP Session has a malformed expiry — rejecting.[/red]")
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
        
        # 1. Check OS Privileges.
        # The host-root gate exists so a stray offensive module can't fire from an
        # unprivileged shell. It is deliberately bypassable in a rootless lab via
        # OPENELIA_ALLOW_UNPRIV_RED=1: the documented architecture runs offensive
        # tooling inside rootless, ephemeral Docker containers, so the *host* process
        # never needs to be root — and running the dashboard/API as root would be
        # worse posture than skipping this check. The IdP role gate below remains the
        # real authorization control in both modes; it is never bypassed.
        allow_unpriv = os.getenv("OPENELIA_ALLOW_UNPRIV_RED") == "1"
        if not cls.is_os_admin() and not allow_unpriv:
            console.print("[red]✗ Access Denied: OS Administrative privileges required for offensive modules.[/red]")
            console.print("[dim]Hint: run with 'sudo'/as Administrator, or set OPENELIA_ALLOW_UNPRIV_RED=1 for a rootless lab.[/dim]")
            return False
        if allow_unpriv and not cls.is_os_admin():
            console.print("[dim]OS-root gate bypassed via OPENELIA_ALLOW_UNPRIV_RED=1 (rootless lab mode).[/dim]")
            
        # 2. Check IdP Claims
        if not cls.verify_idp_claims(["admin", "security_lead", "red_team_lead"]):
            console.print("[red]✗ Access Denied: Verified Security Lead claim required.[/red]")
            return False
            
        console.print("[bold green]✅ Authorization Granted: Unlocking Offensive Modules.[/bold green]\n")
        return True
