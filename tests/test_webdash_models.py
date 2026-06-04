"""
Model-config endpoint tests. ModelManager is mocked so no real ~/.config or
keychain writes happen. /models/auth must never echo the API key.
"""
from __future__ import annotations

import pytest

from tests.conftest_webdash import auth, client, state_dir, token  # noqa: F401


@pytest.fixture
def mock_mm(monkeypatch):
    from model_manager import ModelManager

    calls: dict = {}
    monkeypatch.setattr(ModelManager, "set_local_model", classmethod(lambda cls, m: calls.__setitem__("local", m)))
    monkeypatch.setattr(ModelManager, "set_cloud_model", classmethod(lambda cls, p, m: calls.__setitem__("cloud", (p, m))))
    monkeypatch.setattr(ModelManager, "set_agent_override", classmethod(lambda cls, a, p, m: calls.__setitem__("hybrid", (a, p, m))))
    monkeypatch.setattr(ModelManager, "store_provider_key", classmethod(lambda cls, p, k: calls.__setitem__("auth", (p, k))))
    monkeypatch.setattr(ModelManager, "get_config", classmethod(lambda cls: {"mode": "local", "local_model": "llama3.1:8b", "agent_overrides": {}}))
    return calls


def test_set_local_requires_confirm(client, auth, mock_mm):
    assert client.post("/api/models/local", headers=auth, json={"model": "llama3.1:8b"}).status_code == 400
    assert "local" not in mock_mm


def test_set_local_ok(client, auth, mock_mm):
    resp = client.post("/api/models/local", headers=auth, json={"model": "qwen2.5:14b", "confirm": True})
    assert resp.status_code == 200
    assert mock_mm["local"] == "qwen2.5:14b"


def test_local_available_lists_detected_models(client, auth, monkeypatch):
    from model_manager import ModelManager

    monkeypatch.setattr(
        ModelManager, "list_local_models", classmethod(lambda cls: ["llama3.1:8b", "qwen2.5:14b"])
    )
    resp = client.get("/api/models/local/available", headers=auth)
    assert resp.status_code == 200
    assert resp.json() == {"models": ["llama3.1:8b", "qwen2.5:14b"]}


def test_local_available_empty_when_ollama_down(client, auth, monkeypatch):
    from model_manager import ModelManager

    monkeypatch.setattr(ModelManager, "list_local_models", classmethod(lambda cls: []))
    resp = client.get("/api/models/local/available", headers=auth)
    assert resp.status_code == 200
    assert resp.json() == {"models": []}


def test_local_available_requires_token(client):
    assert client.get("/api/models/local/available").status_code == 401


def test_set_cloud_bad_provider(client, auth, mock_mm):
    resp = client.post("/api/models/cloud", headers=auth, json={"provider": "bogus", "model": "x", "confirm": True})
    assert resp.status_code == 400
    assert "cloud" not in mock_mm


def test_set_cloud_ok(client, auth, mock_mm):
    resp = client.post("/api/models/cloud", headers=auth, json={"provider": "openai", "model": "gpt-4o", "confirm": True})
    assert resp.status_code == 200
    assert mock_mm["cloud"] == ("openai", "gpt-4o")


def test_set_hybrid_bad_agent(client, auth, mock_mm):
    resp = client.post(
        "/api/models/hybrid", headers=auth,
        json={"agent": "not_an_agent", "provider": "openai", "model": "gpt-4o", "confirm": True},
    )
    assert resp.status_code == 400


def test_set_hybrid_ok(client, auth, mock_mm):
    resp = client.post(
        "/api/models/hybrid", headers=auth,
        json={"agent": "pentester_recon", "provider": "openai", "model": "gpt-4o", "confirm": True},
    )
    assert resp.status_code == 200
    assert mock_mm["hybrid"] == ("pentester_recon", "openai", "gpt-4o")


def test_auth_stores_key_without_echoing_it(client, auth, mock_mm):
    fake_key = "totally-fake-value-123456"  # dummy; not a real-looking credential
    resp = client.post(
        "/api/models/auth", headers=auth,
        json={"provider": "openai", "api_key": fake_key, "confirm": True},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"stored": True, "provider": "openai"}
    assert fake_key not in str(body)           # never echoed
    assert mock_mm["auth"] == ("openai", fake_key)  # but was stored


def test_auth_requires_confirm(client, auth, mock_mm):
    resp = client.post("/api/models/auth", headers=auth, json={"provider": "openai", "api_key": "x"})
    assert resp.status_code == 400
    assert "auth" not in mock_mm


def test_hybrid_bad_provider(client, auth, mock_mm):
    resp = client.post(
        "/api/models/hybrid", headers=auth,
        json={"agent": "pentester_recon", "provider": "bogus", "model": "x", "confirm": True},
    )
    assert resp.status_code == 400
    assert "hybrid" not in mock_mm


def test_auth_bad_provider(client, auth, mock_mm):
    resp = client.post(
        "/api/models/auth", headers=auth,
        json={"provider": "bogus", "api_key": "x", "confirm": True},
    )
    assert resp.status_code == 400
    assert "auth" not in mock_mm
