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
