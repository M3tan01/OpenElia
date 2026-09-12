"""
core/webhook.py — shared SSRF-guard for outbound webhook URLs.

Any code posting to an operator-supplied URL (SIEM sync, n8n completion
callback, ...) must validate it against a hostname allowlist stored in
SecretStore first. Unknown hostnames are denied by default.
"""
from __future__ import annotations

from urllib.parse import urlparse

from secret_store import SecretStore


def load_webhook_allowlist(allowlist_secret_key: str) -> list[str]:
    """Load approved hostnames for `allowlist_secret_key` from SecretStore.

    The secret value is a comma-separated list of hostnames, e.g.
    "splunk.corp.com,siem.internal". Returns an empty list if unset, which
    causes all URLs to be rejected.
    """
    raw = (SecretStore.get_secret(allowlist_secret_key) or "").strip()
    if not raw:
        return []
    return [h.strip().lower() for h in raw.split(",") if h.strip()]


def _parse_allowlist_entry(entry: str) -> tuple[str, int | None]:
    """Split an allowlist entry into (host, port).

    ``"host"``      -> ``(host, None)`` — matches any port (backward compatible).
    ``"host:port"`` -> ``(host, port)`` — restricts to that exact port.
    A non-integer port -> ``("", None)`` — unmatchable (no real hostname equals
    ""), so a malformed entry fails closed rather than allowing all ports.
    IPv6 bracketed literals are not supported (project uses DNS hostnames).
    """
    if ":" not in entry:
        return entry, None
    host, _, port_str = entry.rpartition(":")
    try:
        return host, int(port_str)
    except ValueError:
        return "", None


def validate_webhook_url(url: str, allowlist_secret_key: str) -> str:
    """Validate `url` against the hostname allowlist stored under
    `allowlist_secret_key`. Raises ValueError if not explicitly approved.
    """
    allowlist = load_webhook_allowlist(allowlist_secret_key)
    if not allowlist:
        raise ValueError(
            f"Webhook allowlist is empty. Set {allowlist_secret_key} to approved hostnames."
        )

    try:
        parsed = urlparse(url)
    except Exception:
        raise ValueError("Malformed webhook URL.")

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Webhook URL must use http or https.")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise ValueError("Webhook URL missing hostname.")

    if hostname not in allowlist:
        raise ValueError(
            f"Webhook hostname '{hostname}' is not in the approved {allowlist_secret_key} allowlist."
        )
    return url


# Header the emitter sends and the n8n Webhook node's Header Auth credential
# checks. This name and the n8n credential's "name" field are one contract —
# changing it here means rotating the credential to match.
WEBHOOK_AUTH_HEADER = "X-OpenElia-Token"


def auth_headers(secret_key: str) -> dict[str, str]:
    """Return the outbound auth header for a completion callback, sourced from
    SecretStore (env fallback). Empty dict when the secret is unset — the POST
    then goes out unauthenticated and a receiver enforcing Header Auth rejects
    it with 403 (logged, never fatal). The token is never logged.
    """
    token = (SecretStore.get_secret(secret_key) or "").strip()
    if not token:
        return {}
    return {WEBHOOK_AUTH_HEADER: token}
