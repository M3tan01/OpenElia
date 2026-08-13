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


# --- token TTL / rotation -------------------------------------------------

import json as _json


def test_verify_rejects_expired_token(monkeypatch):
    from webdash import security
    monkeypatch.setenv("WEBDASH_TOKEN_TTL", "3600")
    monkeypatch.setattr(security, "current_token", lambda: "tok")
    monkeypatch.setattr(security, "_token_issued", lambda: 1000.0)
    monkeypatch.setattr(security, "_now", lambda: 1000.0 + 7200)  # 2h > 1h ttl
    assert security.verify("tok") is False


def test_verify_accepts_token_within_ttl(monkeypatch):
    from webdash import security
    monkeypatch.setenv("WEBDASH_TOKEN_TTL", "3600")
    monkeypatch.setattr(security, "current_token", lambda: "tok")
    monkeypatch.setattr(security, "_token_issued", lambda: 1000.0)
    monkeypatch.setattr(security, "_now", lambda: 1000.0 + 60)
    assert security.verify("tok") is True


def test_ttl_zero_disables_expiry(monkeypatch):
    from webdash import security
    monkeypatch.setenv("WEBDASH_TOKEN_TTL", "0")
    monkeypatch.setattr(security, "current_token", lambda: "tok")
    monkeypatch.setattr(security, "_token_issued", lambda: 1.0)
    monkeypatch.setattr(security, "_now", lambda: 1.0 + 10_000_000)
    assert security.verify("tok") is True


def test_legacy_bare_token_never_expires(monkeypatch):
    # A token minted before TTL existed has no issued time -> must not expire.
    from webdash import security
    monkeypatch.setenv("WEBDASH_TOKEN_TTL", "3600")
    monkeypatch.setattr(security, "current_token", lambda: "tok")
    monkeypatch.setattr(security, "_token_issued", lambda: None)
    monkeypatch.setattr(security, "_now", lambda: 9_999_999.0)
    assert security.verify("tok") is True


def test_get_or_create_rotates_expired_token(monkeypatch):
    from webdash import security
    box = {"v": _json.dumps({"token": "old", "issued": 1.0})}
    monkeypatch.setattr("secret_store.SecretStore.get_secret", lambda k: box["v"])
    monkeypatch.setattr("secret_store.SecretStore.set_secret",
                        lambda k, val: box.__setitem__("v", val))
    monkeypatch.setenv("WEBDASH_TOKEN_TTL", "3600")
    monkeypatch.setattr(security, "_now", lambda: 1.0 + 7200)
    new = security.get_or_create_token()
    assert new != "old"
    assert _json.loads(box["v"])["token"] == new


def test_get_or_create_keeps_fresh_token(monkeypatch):
    from webdash import security
    box = {"v": _json.dumps({"token": "fresh", "issued": 5000.0})}
    monkeypatch.setattr("secret_store.SecretStore.get_secret", lambda k: box["v"])
    monkeypatch.setattr("secret_store.SecretStore.set_secret",
                        lambda k, val: box.__setitem__("v", val))
    monkeypatch.setenv("WEBDASH_TOKEN_TTL", "3600")
    monkeypatch.setattr(security, "_now", lambda: 5000.0 + 60)
    assert security.get_or_create_token() == "fresh"


def test_current_token_parses_legacy_bare_string(monkeypatch):
    from webdash import security
    monkeypatch.setattr("secret_store.SecretStore.get_secret", lambda k: "barevalue")
    assert security.current_token() == "barevalue"
    assert security._token_issued() is None


def test_corrupt_json_record_is_refused(monkeypatch):
    # A tampered keychain entry that parses as JSON but isn't our record shape
    # must yield no token (fail-closed), not be coerced into a usable token.
    from webdash import security
    for blob in ('{"foo": "bar"}', "[1, 2, 3]", "1234"):
        monkeypatch.setattr("secret_store.SecretStore.get_secret", lambda k, b=blob: b)
        assert security.current_token() is None
        assert security.verify(blob) is False


def test_generate_token_records_issue_time(monkeypatch):
    from webdash import security
    box = {}
    monkeypatch.setattr("secret_store.SecretStore.set_secret",
                        lambda k, val: box.__setitem__(k, val))
    monkeypatch.setattr(security, "_now", lambda: 4242.0)
    tok = security.generate_token()
    rec = _json.loads(box["WEBDASH_TOKEN"])
    assert rec["token"] == tok and rec["issued"] == 4242.0
