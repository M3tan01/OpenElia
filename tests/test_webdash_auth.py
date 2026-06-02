"""
Auth tests for the webdash API: every /api route is bearer-token gated;
/healthz is open; the WebSocket rejects a bad token.
"""
from __future__ import annotations

import pytest
from starlette.websockets import WebSocketDisconnect

from tests.conftest_webdash import TEST_TOKEN, auth, client, state_dir, token  # noqa: F401

API_ROUTES = ["/api/state", "/api/audit", "/api/tasks", "/api/graph", "/api/cost", "/api/models"]


@pytest.mark.parametrize("route", API_ROUTES)
def test_route_requires_token(client, state_dir, token, route):
    # Arrange / Act — no Authorization header
    resp = client.get(route)
    # Assert
    assert resp.status_code == 401


@pytest.mark.parametrize("route", API_ROUTES)
def test_route_rejects_bad_token(client, state_dir, token, route):
    resp = client.get(route, headers={"Authorization": "Bearer wrong-token"})
    assert resp.status_code == 401


@pytest.mark.parametrize("route", API_ROUTES)
def test_route_accepts_valid_token(client, state_dir, auth, route):
    resp = client.get(route, headers=auth)
    assert resp.status_code == 200


def test_healthz_is_open(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


def test_missing_bearer_prefix_is_401(client, state_dir, token):
    resp = client.get("/api/state", headers={"Authorization": TEST_TOKEN})  # no "Bearer "
    assert resp.status_code == 401


def test_websocket_rejects_bad_token(client, state_dir, token):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/api/stream?token=bad") as ws:
            ws.receive_json()
