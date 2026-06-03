import json

from tests.conftest_webdash import *  # noqa: F401,F403


def test_actors_requires_token(client):
    assert client.get("/api/actors").status_code == 401


def test_actors_lists_names(tmp_path, monkeypatch, client, auth):
    m = {"APT29": {"aliases": ["Cozy Bear"], "techniques": []},
         "FIN7": {"aliases": [], "techniques": []}}
    p = tmp_path / "actor_ttps.json"
    p.write_text(json.dumps(m))
    monkeypatch.setenv("OPENELIA_ACTOR_MAP", str(p))
    r = client.get("/api/actors", headers=auth)
    assert r.status_code == 200
    assert sorted(r.json()) == ["APT29", "FIN7"]


def test_actors_missing_map_returns_empty(tmp_path, monkeypatch, client, auth):
    monkeypatch.setenv("OPENELIA_ACTOR_MAP", str(tmp_path / "nope.json"))
    r = client.get("/api/actors", headers=auth)
    assert r.status_code == 200
    assert r.json() == []


def test_forge_requires_token(client):
    assert client.post("/api/forge", json={"actor": "APT29"}).status_code == 401


def test_forge_requires_confirm(client, auth):
    r = client.post("/api/forge", json={"actor": "APT29", "confirm": False}, headers=auth)
    assert r.status_code == 400


def test_forge_returns_profile_and_omitted(monkeypatch, client, auth):
    fake = {
        "profile": {"name": "APT29", "alias": "APT29", "description": "d",
                    "preferred_ttps": ["T1059.001"], "tools": [],
                    "stealth_required": False, "rationale": "r"},
        "omitted": [{"t_code": "T1110", "reason": "RoE blacklist"}],
        "metadata": {"actor": "APT29", "tier": "local", "kept": 1, "dropped": 1},
    }

    async def fake_forge(self, actor_name, brain_tier="local"):
        return fake

    monkeypatch.setattr("adversary_forge.AdversaryForge.forge", fake_forge)
    r = client.post("/api/forge",
                    json={"actor": "APT29", "brain_tier": "local",
                          "auto_commit": False, "confirm": True},
                    headers=auth)
    assert r.status_code == 200
    body = r.json()
    assert body["profile"]["name"] == "APT29"
    assert body["omitted"][0]["t_code"] == "T1110"
    assert body["saved_path"] is None  # auto_commit False -> not written
