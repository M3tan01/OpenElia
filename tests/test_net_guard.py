"""
Unit + integration tests for webdash.net_guard — the RFC1918/loopback client-IP
allowlist that gates the LAN-exposed dashboard ahead of bearer-token auth.

client_is_allowed() is the security decision (fail-closed on anything that is
not a literal private/loopback IP); PrivateClientMiddleware wires it into the
request path so a public/routable peer gets 403 before any route or auth runs.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from webdash.net_guard import PrivateClientMiddleware, client_is_allowed


# --- client_is_allowed (the decision) ---------------------------------------- #

@pytest.mark.parametrize(
    "host",
    [
        "10.0.0.5",         # 10/8
        "10.255.255.255",
        "172.16.0.1",       # 172.16/12 low edge
        "172.31.255.254",   # 172.16/12 high edge
        "192.168.1.10",     # 192.168/16
        "127.0.0.1",        # IPv4 loopback
        "127.5.6.7",        # 127/8 is all loopback
        "::1",              # IPv6 loopback
    ],
)
def test_allows_private_and_loopback(host):
    assert client_is_allowed(host) is True


@pytest.mark.parametrize(
    "host",
    [
        "8.8.8.8",               # public
        "1.1.1.1",               # public
        "172.15.255.255",        # just below 172.16/12
        "172.32.0.0",            # just above 172.16/12
        "169.254.1.1",           # link-local — deliberately NOT allowed
        "2001:4860:4860::8888",  # public IPv6
        "fe80::1",               # IPv6 link-local
        "not-an-ip",             # garbage string
        "testclient",            # TestClient's default non-IP peer
        "",                      # empty
        None,                    # missing client
    ],
)
def test_denies_public_linklocal_and_garbage(host):
    assert client_is_allowed(host) is False


# --- PrivateClientMiddleware (the wiring) ------------------------------------ #

def _app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(PrivateClientMiddleware)

    @app.get("/probe")
    def probe() -> dict:
        return {"ok": True}

    return app


def test_middleware_allows_loopback_peer():
    with TestClient(_app(), client=("127.0.0.1", 40000)) as c:
        r = c.get("/probe")
    assert r.status_code == 200
    assert r.json() == {"ok": True}


def test_middleware_allows_rfc1918_peer():
    with TestClient(_app(), client=("192.168.1.50", 40000)) as c:
        r = c.get("/probe")
    assert r.status_code == 200


def test_middleware_denies_public_peer():
    with TestClient(_app(), client=("203.0.113.7", 40000)) as c:
        r = c.get("/probe")
    assert r.status_code == 403
    assert "private networks only" in r.json()["detail"]


def test_middleware_denies_non_ip_peer():
    # Default TestClient peer is "testclient" — a non-IP → fail-closed 403.
    with TestClient(_app()) as c:
        r = c.get("/probe")
    assert r.status_code == 403


def test_middleware_does_not_trust_x_forwarded_for():
    # A public peer spoofing a private XFF header must still be rejected: the
    # guard reads the real TCP peer, not client-supplied headers.
    with TestClient(_app(), client=("8.8.8.8", 40000)) as c:
        r = c.get("/probe", headers={"X-Forwarded-For": "10.0.0.5"})
    assert r.status_code == 403
