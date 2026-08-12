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
