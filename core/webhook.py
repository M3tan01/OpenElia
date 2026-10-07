"""
core/webhook.py — shared SSRF-guard for outbound webhook URLs.

Any code posting to an operator-supplied URL (SIEM sync, n8n completion
callback, ...) must validate it first. A target is accepted when it is in
RFC1918 private space (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) OR matches an
explicit host[:port] allowlist stored in SecretStore. Everything else — public
IPs, loopback, and link-local (incl. the 169.254.169.254 cloud-metadata
endpoint) — is denied by default.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from secret_store import SecretStore

# RFC1918 private IPv4 ranges. Internal callback targets (an n8n instance on the
# operator's own network) live here and are always in-scope, independent of the
# explicit allowlist. Kept deliberately narrow: loopback (127.0.0.0/8) and
# link-local (169.254.0.0/16, which contains cloud-metadata 169.254.169.254) are
# NOT RFC1918 and are NOT auto-accepted — that is why we do not use
# ipaddress.is_private, which would also cover those.
_RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def _ip_is_rfc1918(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True only for an IPv4 address inside one of the three RFC1918 ranges."""
    return isinstance(ip, ipaddress.IPv4Address) and any(ip in net for net in _RFC1918_NETWORKS)


def _is_rfc1918_host(hostname: str) -> bool:
    """True if `hostname` is (or resolves entirely to) RFC1918 private IPv4 space.

    Literal IPs are checked directly. A hostname is resolved via getaddrinfo and
    accepted only when it resolves to at least one address and EVERY resolved
    address is RFC1918 — fail-closed: any public/IPv6/other address, or a
    resolution failure, returns False so the target then falls through to the
    explicit allowlist. NOTE: resolve-then-connect leaves a DNS-rebinding gap
    (the later POST re-resolves); acceptable here for a lab-internal callback
    guard, but do not treat this as a hardened public-facing SSRF control.
    """
    try:
        return _ip_is_rfc1918(ipaddress.ip_address(hostname))
    except ValueError:
        pass  # not a literal IP — resolve it

    try:
        infos = socket.getaddrinfo(hostname, None)
    except OSError:
        return False

    resolved: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for _family, _type, _proto, _canon, sockaddr in infos:
        try:
            resolved.append(ipaddress.ip_address(sockaddr[0]))
        except ValueError:
            return False
    return bool(resolved) and all(_ip_is_rfc1918(ip) for ip in resolved)


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
    """Validate `url` as an outbound webhook target.

    Accepted if the host is RFC1918 private space (any port) OR matches an entry
    in the allowlist under `allowlist_secret_key`. Allowlist entries are either
    ``host`` (matches any port) or ``host:port`` (restricts to that exact port).
    Raises ValueError if neither condition holds.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        raise ValueError("Malformed webhook URL.")

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Webhook URL must use http or https.")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise ValueError("Webhook URL missing hostname.")

    try:
        port = parsed.port  # None when absent; raises ValueError on a bad port
    except ValueError:
        raise ValueError("Webhook URL has an invalid port.")
    effective_port = port if port is not None else (443 if parsed.scheme == "https" else 80)

    # RFC1918 private ranges are always in-scope (internal callback targets) and
    # port-independent — checked before the allowlist so an unset allowlist does
    # not reject a legitimate internal target.
    if _is_rfc1918_host(hostname):
        return url

    allowlist = load_webhook_allowlist(allowlist_secret_key)
    if not allowlist:
        raise ValueError(
            f"Webhook target '{hostname}:{effective_port}' is not RFC1918 private "
            f"space and the {allowlist_secret_key} allowlist is empty."
        )

    for entry in allowlist:
        allowed_host, allowed_port = _parse_allowlist_entry(entry)
        if allowed_host != hostname:
            continue
        if allowed_port is None or allowed_port == effective_port:
            return url

    raise ValueError(
        f"Webhook target '{hostname}:{effective_port}' is not RFC1918 private space "
        f"and is not in the approved {allowlist_secret_key} allowlist."
    )


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
