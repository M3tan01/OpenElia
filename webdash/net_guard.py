"""
webdash/net_guard.py — client-IP allowlist for the LAN-exposed dashboard.

The dashboard binds all interfaces (0.0.0.0) so private-network operators can
reach it, but the network boundary is still enforced in software: every
request's peer IP must be RFC1918 private space (10/8, 172.16/12, 192.168/16)
or loopback (127/8, ::1). A public/routable client is refused with 403 before
the request reaches auth or any handler.

Fail-closed: a request with no resolvable client IP is denied. The peer IP is
the real TCP socket source (request.client.host) — X-Forwarded-For and other
client-supplied headers are deliberately NOT consulted, so the check cannot be
spoofed by a header. This is the network gate *underneath* the bearer token,
which remains the primary auth boundary (see webdash/security.py).
"""
from __future__ import annotations

import ipaddress
from typing import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from core.webhook import _ip_is_rfc1918

# Loopback stays allowed so a local operator (127.0.0.1 / ::1) keeps working
# after the bind moves off loopback to 0.0.0.0.
_LOOPBACK_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)


def _ip_is_loopback(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(ip in net for net in _LOOPBACK_NETWORKS)


def client_is_allowed(host: str | None) -> bool:
    """True iff `host` is a literal RFC1918-private or loopback IP.

    Fail-closed on everything else: a missing host, a non-literal string, a
    public/routable address, or an IPv6 global-unicast address all return
    False. RFC1918 reuses core.webhook's helper so the private-range definition
    stays in one place.
    """
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return _ip_is_loopback(ip) or _ip_is_rfc1918(ip)


class PrivateClientMiddleware(BaseHTTPMiddleware):
    """Reject any request whose peer IP is not RFC1918 private or loopback.

    Applied to the whole app (static SPA, /healthz, and every /api route) so
    the network boundary is enforced ahead of token auth and independent of it.
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        client = request.client
        host = client.host if client else None
        if not client_is_allowed(host):
            return JSONResponse(
                {"detail": "forbidden: dashboard is reachable from private networks only"},
                status_code=403,
            )
        return await call_next(request)
