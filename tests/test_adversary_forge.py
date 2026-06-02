from graph_manager import GraphManager


def test_detected_os_collects_lowercased_host_os(tmp_path):
    gm = GraphManager(db_path=str(tmp_path / "g.json"))
    gm.add_host("10.0.0.5", os="Windows")
    gm.add_host("10.0.0.6", os="linux")
    gm.add_host("10.0.0.7")  # os is None -> skipped
    assert gm.detected_os() == {"windows", "linux"}


def test_detected_os_empty_when_no_os_known(tmp_path):
    gm = GraphManager(db_path=str(tmp_path / "g.json"))
    gm.add_host("10.0.0.5")
    assert gm.detected_os() == set()


import json
import pytest
from adversary_schema import AdversaryProfile, save_profile


def test_profile_requires_core_fields():
    with pytest.raises(Exception):
        AdversaryProfile(name="x")  # missing required fields


def test_profile_roundtrips_existing_schema():
    p = AdversaryProfile(
        name="APT29", alias="Cozy Bear", description="d",
        preferred_ttps=["T1059.001"], tools=["powershell"],
        stealth_required=True, rationale="r",
    )
    d = p.model_dump()
    assert set(d) == {"name", "alias", "description", "preferred_ttps",
                      "tools", "stealth_required", "rationale"}


def test_save_profile_writes_into_adversaries_dir(tmp_path):
    p = AdversaryProfile(
        name="TEST", alias="t", description="d",
        preferred_ttps=["T1059"], tools=["nmap"],
        stealth_required=False, rationale="r",
    )
    path = save_profile(p, "tailored_test", adversaries_dir=str(tmp_path))
    on_disk = json.loads((tmp_path / "tailored_test.json").read_text())
    assert on_disk["name"] == "TEST"
    assert path.endswith("tailored_test.json")


def test_save_profile_blocks_path_traversal(tmp_path):
    p = AdversaryProfile(
        name="TEST", alias="t", description="d",
        preferred_ttps=[], tools=[], stealth_required=False, rationale="r",
    )
    with pytest.raises(ValueError):
        save_profile(p, "../evil", adversaries_dir=str(tmp_path))


from adversary_forge import AdversaryForge


def _write_map(tmp_path):
    m = {
        "APT29": {"aliases": ["Cozy Bear"], "techniques": [
            {"t_code": "T1059.001", "name": "PowerShell", "platforms": ["windows"]},
            {"t_code": "T1110", "name": "Brute Force", "platforms": ["windows", "linux"]},
        ]},
    }
    p = tmp_path / "actor_ttps.json"
    p.write_text(json.dumps(m))
    return str(p)


def test_load_actor_by_name(tmp_path):
    f = AdversaryForge(actor_map_path=_write_map(tmp_path))
    rec = f.load_actor("APT29")
    assert rec["name"] == "APT29"
    assert len(rec["techniques"]) == 2


def test_load_actor_by_alias_case_insensitive(tmp_path):
    f = AdversaryForge(actor_map_path=_write_map(tmp_path))
    rec = f.load_actor("cozy bear")
    assert rec["name"] == "APT29"


def test_load_actor_unknown_raises(tmp_path):
    f = AdversaryForge(actor_map_path=_write_map(tmp_path))
    with pytest.raises(ValueError):
        f.load_actor("NoSuchActor")


TECHS = [
    {"t_code": "T1059.001", "name": "PowerShell", "platforms": ["windows"]},
    {"t_code": "T1110", "name": "Brute Force", "platforms": ["windows", "linux"]},
    {"t_code": "T1059.004", "name": "Unix Shell", "platforms": ["linux", "macos"]},
]


def test_filter_drops_roe_blacklisted():
    f = AdversaryForge()
    kept, dropped = f.filter_techniques(TECHS, detected_os=set(), blacklisted=["T1110"])
    assert "T1110" not in {t["t_code"] for t in kept}
    assert any(d["t_code"] == "T1110" and "RoE" in d["reason"] for d in dropped)


def test_filter_drops_platform_mismatch():
    f = AdversaryForge()
    kept, dropped = f.filter_techniques(TECHS, detected_os={"windows"}, blacklisted=[])
    codes = {t["t_code"] for t in kept}
    assert "T1059.001" in codes and "T1110" in codes  # windows-capable kept
    assert "T1059.004" not in codes                    # linux/macos only -> dropped
    assert any(d["t_code"] == "T1059.004" and "platform" in d["reason"].lower()
               for d in dropped)


def test_filter_keeps_all_when_os_unknown():
    f = AdversaryForge()
    kept, _ = f.filter_techniques(TECHS, detected_os=set(), blacklisted=[])
    assert len(kept) == 3  # empty topology cannot prove mismatch -> keep


def test_filter_keeps_platformless_technique():
    f = AdversaryForge()
    techs = [{"t_code": "T1583", "name": "Acquire Infra", "platforms": []}]
    kept, _ = f.filter_techniques(techs, detected_os={"windows"}, blacklisted=[])
    assert len(kept) == 1  # no platform metadata -> cannot prove mismatch


import asyncio
from types import SimpleNamespace


class _FakeMsg:
    def __init__(self, content): self.message = SimpleNamespace(content=content)


class _FakeCompletions:
    def __init__(self, content): self._c = content
    async def create(self, **kwargs):
        return SimpleNamespace(choices=[_FakeMsg(self._c)])


class _FakeClient:
    def __init__(self, content):
        self.chat = SimpleNamespace(completions=_FakeCompletions(content))


def _patch_llm(monkeypatch, content):
    from adversary_forge import LLMClient  # re-exported for patching
    monkeypatch.setattr(
        LLMClient, "create",
        staticmethod(lambda **kw: (_FakeClient(content), "fake-model", True)),
    )


def test_sequence_orders_and_guards_hallucinations(tmp_path, monkeypatch):
    # LLM returns a real code, a reordered one, and an invented one.
    _patch_llm(monkeypatch, '["T1110", "T1059.001", "T9999"]')
    f = AdversaryForge()
    kept = [
        {"t_code": "T1059.001", "name": "PowerShell", "platforms": ["windows"]},
        {"t_code": "T1110", "name": "Brute Force", "platforms": ["windows"]},
    ]
    ordered = asyncio.run(f.sequence(kept, brain_tier="local", topology={}))
    assert ordered == ["T1110", "T1059.001"]  # invented T9999 dropped


def test_sequence_falls_back_on_bad_json(tmp_path, monkeypatch):
    _patch_llm(monkeypatch, "not json at all")
    f = AdversaryForge()
    kept = [{"t_code": "T1059.001", "name": "PowerShell", "platforms": ["windows"]}]
    ordered = asyncio.run(f.sequence(kept, brain_tier="local", topology={}))
    assert ordered == ["T1059.001"]  # fall back to filtered order


def test_forge_end_to_end(tmp_path, monkeypatch):
    _patch_llm(monkeypatch, '["T1059.001", "T1110"]')
    actor_map = tmp_path / "actor_ttps.json"
    actor_map.write_text(json.dumps({"APT29": {"aliases": [], "techniques": [
        {"t_code": "T1059.001", "name": "PowerShell", "platforms": ["windows"]},
        {"t_code": "T1110", "name": "Brute Force", "platforms": ["windows"]},
        {"t_code": "T1059.004", "name": "Unix Shell", "platforms": ["linux"]},
    ]}}))
    roe = tmp_path / "roe.json"
    roe.write_text(json.dumps({"blacklisted_techniques": ["T1110"]}))
    graph = tmp_path / "g.json"
    gm = GraphManager(db_path=str(graph)); gm.add_host("10.0.0.5", os="Windows")
    f = AdversaryForge(actor_map_path=str(actor_map), graph_path=str(graph), roe_path=str(roe))
    result = asyncio.run(f.forge("APT29", brain_tier="local"))
    prof = result["profile"]
    assert prof["name"] == "APT29"
    assert prof["preferred_ttps"] == ["T1059.001"]  # T1110 RoE-dropped, T1059.004 platform-dropped
    reasons = {d["t_code"]: d["reason"] for d in result["omitted"]}
    assert "RoE" in reasons["T1110"]
    assert "platform" in reasons["T1059.004"].lower()
    assert result["metadata"]["actor"] == "APT29"
    assert result["metadata"]["tier"] == "local"
