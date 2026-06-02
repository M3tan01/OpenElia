import asyncio
import json
from types import SimpleNamespace

import pytest


def test_cmd_forge_dry_run_does_not_write(tmp_path, monkeypatch, capsys):
    import main
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
    monkeypatch.setattr("main._require_api_key", lambda tier="local": None)
    args = SimpleNamespace(actor="APT29", brain_tier="local", auto_commit=False,
                           adversaries_dir=str(tmp_path))
    asyncio.run(main.cmd_forge(args))
    out = capsys.readouterr().out
    assert "1" in out  # kept count surfaced
    assert not list(tmp_path.glob("*.json"))  # dry run wrote nothing


def test_cmd_forge_auto_commit_writes(tmp_path, monkeypatch):
    import main
    fake = {
        "profile": {"name": "APT29", "alias": "APT29", "description": "d",
                    "preferred_ttps": ["T1059.001"], "tools": [],
                    "stealth_required": False, "rationale": "r"},
        "omitted": [], "metadata": {"actor": "APT29", "tier": "local", "kept": 1, "dropped": 0},
    }

    async def fake_forge(self, actor_name, brain_tier="local"):
        return fake

    monkeypatch.setattr("adversary_forge.AdversaryForge.forge", fake_forge)
    monkeypatch.setattr("main._require_api_key", lambda tier="local": None)
    args = SimpleNamespace(actor="APT29", brain_tier="local", auto_commit=True,
                           adversaries_dir=str(tmp_path))
    asyncio.run(main.cmd_forge(args))
    written = json.loads((tmp_path / "tailored_apt29.json").read_text())
    assert written["name"] == "APT29"
