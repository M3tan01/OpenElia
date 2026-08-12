# Adversary Forge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an "Adversary Forge" that turns a MITRE threat-actor name into an environment-constrained, RoE-compliant `adversaries/*.json` profile the existing orchestrator can run.

**Architecture:** A→B hybrid. A one-time **offline** extract parses the MITRE STIX bundle (`state/enterprise-attack.json`) into a slim, committed `actor_ttps.json` (actor → techniques with platforms). The **runtime** `AdversaryForge` reads only the slim map (no `stix2` in the hot path): load actor → deterministic filter (RoE technique blocklist + topology-OS mismatch) → brain-tier LLM **sequences** the survivors → hallucination guard drops invented T-codes → map to the existing adversary schema. A single Pydantic `AdversaryProfile` gate validates the output before any file is written, on both the CLI and the webdash paths. Forge only reads and generates — it never launches ops; running a forged profile still goes through the existing gated `/run` path.

**Tech Stack:** Python 3.14 (stdlib + `stix2` for extract only), `pydantic` v2, FastAPI (webdash), `LLMClient`/`ModelManager` (Ollama local / cloud expensive), React + TS (Vite) frontend, pytest.

---

## File Structure

| File | Responsibility |
|---|---|
| `scripts/extract_actor_ttps.py` | CREATE — offline: STIX bundle → slim `actor_ttps.json`. Only file importing `stix2`. |
| `actor_ttps.json` | CREATE (generated, committed) — slim actor→techniques map shipped for offline runtime. |
| `graph_manager.py` | MODIFY — add `detected_os()`. |
| `adversary_schema.py` | CREATE — Pydantic `AdversaryProfile` gate + `save_profile()`. |
| `adversary_forge.py` | CREATE — `AdversaryForge`: load_actor, filter, sequence, forge. |
| `roe.example.json` | MODIFY — add `blacklisted_techniques: []`. |
| `webdash/data.py` | MODIFY — RoE whitelist gains `blacklisted_techniques`; add `actors()`. |
| `main.py` | MODIFY — `cmd_forge` + `forge` subparser. |
| `src/src/cli.ts` | MODIFY — `forge` passthrough subcommand. |
| `webdash/api/monitor.py` | MODIFY — `GET /api/actors`. |
| `webdash/api/control.py` | MODIFY — `POST /api/forge` (token + confirm). |
| `webdash/frontend/src/api.ts` | MODIFY — `ForgeResp`, `ActorResp` types. |
| `webdash/frontend/src/components/AdversaryForgeView.tsx` | CREATE — forge UI. |
| `webdash/frontend/src/components/Sidebar.tsx` | MODIFY — add "Adversary Forge" nav. |
| `webdash/frontend/src/App.tsx` | MODIFY — route `forge` view. |
| `requirements.txt` | MODIFY — add `stix2` (extract-only, commented). |
| `tests/test_adversary_forge.py` | CREATE — forge core + schema tests. |
| `tests/test_webdash_forge.py` | CREATE — `/api/actors`, `/api/forge` tests. |
| `tests/conftest_webdash.py` | MODIFY — seed `actor_ttps.json` + host OS in fixture. |

---

## Task 1: `GraphManager.detected_os()`

**Files:**
- Modify: `graph_manager.py` (after `query_by_type`, ~line 66)
- Test: `tests/test_adversary_forge.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_adversary_forge.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `venv/bin/pytest tests/test_adversary_forge.py -k detected_os -v`
Expected: FAIL — `AttributeError: 'GraphManager' object has no attribute 'detected_os'`

- [ ] **Step 3: Implement `detected_os`**

```python
# graph_manager.py — add method to GraphManager
    def detected_os(self) -> set:
        """Lowercased OS strings across host nodes. Hosts with no os are skipped.

        Empty set means "OS unknown" — callers MUST treat that as
        'cannot prove a platform mismatch' (fail-open on the OS rule only).
        """
        result = set()
        for _, attrs in self.graph.nodes(data=True):
            if attrs.get("type") == "host":
                os_val = attrs.get("os")
                if os_val:
                    result.add(str(os_val).lower())
        return result
```

- [ ] **Step 4: Run test to verify it passes**

Run: `venv/bin/pytest tests/test_adversary_forge.py -k detected_os -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add graph_manager.py tests/test_adversary_forge.py
git commit -m "feat(forge): add GraphManager.detected_os topology OS reader"
```

---

## Task 2: Offline extract script → `actor_ttps.json`

**Files:**
- Create: `scripts/extract_actor_ttps.py`
- Create (generated, committed): `actor_ttps.json`
- Modify: `requirements.txt`

- [ ] **Step 1: Write the extract script**

```python
# scripts/extract_actor_ttps.py
"""Offline extract: MITRE STIX bundle -> slim actor_ttps.json.

Run ONCE by a maintainer who has the 51MB bundle at state/enterprise-attack.json
(gitignored). Output actor_ttps.json is committed so fresh clones work offline
with no stix2 dependency in the runtime path. This is the ONLY module importing
stix2.

Usage: venv/bin/python scripts/extract_actor_ttps.py
"""
from __future__ import annotations

import json
import os
import sys

STIX_PATH = os.path.join("state", "enterprise-attack.json")
OUT_PATH = "actor_ttps.json"


def build() -> dict:
    from stix2 import Filter, MemoryStore

    if not os.path.exists(STIX_PATH):
        sys.exit(f"STIX bundle missing at {STIX_PATH} — download it first.")

    store = MemoryStore()
    store.load_from_file(STIX_PATH)

    actors = store.query([Filter("type", "=", "intrusion-set")])
    out: dict = {}
    for actor in actors:
        rels = store.query([
            Filter("type", "=", "relationship"),
            Filter("relationship_type", "=", "uses"),
            Filter("source_ref", "=", actor.id),
        ])
        techniques = []
        for rel in rels:
            target = store.get(rel.target_ref)
            if not target or target.type != "attack-pattern":
                continue
            if getattr(target, "x_mitre_deprecated", False) or getattr(target, "revoked", False):
                continue
            t_code = next(
                (e.external_id for e in target.external_references
                 if e.source_name == "mitre-attack"),
                None,
            )
            if not t_code:
                continue
            techniques.append({
                "t_code": t_code,
                "name": target.name,
                "platforms": [p.lower() for p in getattr(target, "x_mitre_platforms", [])],
            })
        if techniques:
            out[actor.name] = {
                "aliases": list(getattr(actor, "aliases", [])),
                "techniques": techniques,
            }
    return out


if __name__ == "__main__":
    data = build()
    with open(OUT_PATH, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    print(f"[+] Wrote {OUT_PATH}: {len(data)} actors")
```

- [ ] **Step 2: Run the extract to generate the committed map**

Run: `venv/bin/python scripts/extract_actor_ttps.py`
Expected: `[+] Wrote actor_ttps.json: 18x actors` (≈189). Verify shape:
Run: `venv/bin/python -c "import json;d=json.load(open('actor_ttps.json'));a=d['APT29'];print(len(d),'actors; APT29 techniques:',len(a['techniques']),'; sample:',a['techniques'][0])"`
Expected: `189 actors; APT29 techniques: 66 ; sample: {'t_code': ..., 'name': ..., 'platforms': [...]}`

- [ ] **Step 3: Add stix2 to requirements (extract-only)**

```text
# requirements.txt — append
stix2  # extract-only: scripts/extract_actor_ttps.py; NOT imported at runtime
```

- [ ] **Step 4: Commit**

```bash
git add scripts/extract_actor_ttps.py actor_ttps.json requirements.txt
git commit -m "feat(forge): offline STIX->actor_ttps.json extract + committed slim map"
```

---

## Task 3: `AdversaryProfile` schema gate

**Files:**
- Create: `adversary_schema.py`
- Test: `tests/test_adversary_forge.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_adversary_forge.py — append
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `venv/bin/pytest tests/test_adversary_forge.py -k profile -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'adversary_schema'`

- [ ] **Step 3: Implement the schema gate**

```python
# adversary_schema.py
"""Unified validation gate for forged adversary profiles.

Every forged profile — whether produced by the CLI or the webdash endpoint —
is validated through AdversaryProfile before it is written, and saved only via
save_profile(), which reuses AdversaryManager's realpath/regex guards.
"""
from __future__ import annotations

import json
import os

from pydantic import BaseModel, Field

from adversary_manager import AdversaryManager


class AdversaryProfile(BaseModel):
    """Mirrors the adversaries/*.json schema the orchestrator already consumes."""
    name: str = Field(min_length=1)
    alias: str
    description: str
    preferred_ttps: list[str]
    tools: list[str]
    stealth_required: bool
    rationale: str


def save_profile(profile: AdversaryProfile, file_stem: str,
                 adversaries_dir: str = "adversaries") -> str:
    """Validate the file_stem with AdversaryManager guards, then write the JSON.

    Returns the absolute path written. Raises ValueError on a bad/traversing stem.
    """
    mgr = AdversaryManager(adversaries_dir=adversaries_dir)
    safe = file_stem.lower()
    if not mgr._APT_NAME_RE.fullmatch(safe):
        raise ValueError(f"Invalid profile file name: '{file_stem}'")
    path = os.path.realpath(os.path.join(mgr.adversaries_dir, f"{safe}.json"))
    if not path.startswith(mgr.adversaries_dir + os.sep):
        raise ValueError("Path traversal detected in profile file name.")
    os.makedirs(mgr.adversaries_dir, exist_ok=True)
    with open(path, "w") as f:
        json.dump(profile.model_dump(), f, indent=2)
    return path
```

- [ ] **Step 4: Run test to verify it passes**

Run: `venv/bin/pytest tests/test_adversary_forge.py -k profile -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add adversary_schema.py tests/test_adversary_forge.py
git commit -m "feat(forge): AdversaryProfile pydantic gate + guarded save_profile"
```

---

## Task 4: `AdversaryForge.load_actor` (slim map + alias resolution)

**Files:**
- Create: `adversary_forge.py`
- Test: `tests/test_adversary_forge.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_adversary_forge.py — append
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `venv/bin/pytest tests/test_adversary_forge.py -k load_actor -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'adversary_forge'`

- [ ] **Step 3: Implement module skeleton + `load_actor`**

```python
# adversary_forge.py
"""AdversaryForge — turn a MITRE actor name into an RoE/topology-constrained
adversary profile. Runtime path imports NO stix2 (reads the slim actor_ttps.json
produced offline by scripts/extract_actor_ttps.py).
"""
from __future__ import annotations

import json
import os

from graph_manager import GraphManager


class AdversaryForge:
    def __init__(
        self,
        actor_map_path: str = "actor_ttps.json",
        graph_path: str = "state/attack_surface.json",
        roe_path: str = "roe.json",
    ) -> None:
        self.actor_map_path = actor_map_path
        self.graph_path = graph_path
        self.roe_path = roe_path

    def load_actor(self, actor_name: str) -> dict:
        """Return {'name', 'techniques'} for actor_name (matched by name or alias).

        Raises ValueError if the map is missing or the actor is not found.
        """
        if not os.path.exists(self.actor_map_path):
            raise ValueError(f"actor map missing at {self.actor_map_path}")
        with open(self.actor_map_path) as f:
            actor_map = json.load(f)

        needle = actor_name.strip().lower()
        for name, rec in actor_map.items():
            names = {name.lower()} | {a.lower() for a in rec.get("aliases", [])}
            if needle in names:
                return {"name": name, "techniques": rec.get("techniques", [])}
        raise ValueError(f"Actor '{actor_name}' not found in {self.actor_map_path}")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `venv/bin/pytest tests/test_adversary_forge.py -k load_actor -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add adversary_forge.py tests/test_adversary_forge.py
git commit -m "feat(forge): AdversaryForge.load_actor with alias resolution"
```

---

## Task 5: Deterministic filter (RoE blocklist + OS mismatch)

**Files:**
- Modify: `adversary_forge.py`
- Test: `tests/test_adversary_forge.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_adversary_forge.py — append
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `venv/bin/pytest tests/test_adversary_forge.py -k filter -v`
Expected: FAIL — `AttributeError: 'AdversaryForge' object has no attribute 'filter_techniques'`

- [ ] **Step 3: Implement `filter_techniques`**

```python
# adversary_forge.py — add method to AdversaryForge
    def filter_techniques(
        self, techniques: list[dict], detected_os: set, blacklisted: list[str]
    ) -> tuple[list[dict], list[dict]]:
        """Deterministic pre-curation. Returns (kept, dropped).

        Rule 1 (RoE, fail-closed): drop any T-code in the RoE blacklist.
        Rule 2 (platform): drop only when topology OS is KNOWN and the
        technique's platforms are KNOWN and the two sets do not intersect.
        Unknown OS or platform-less technique -> kept (cannot prove a mismatch).
        """
        blocked = set(blacklisted)
        kept: list[dict] = []
        dropped: list[dict] = []
        for tech in techniques:
            code = tech["t_code"]
            if code in blocked:
                dropped.append({"t_code": code, "reason": "RoE blacklist"})
                continue
            platforms = {p.lower() for p in tech.get("platforms", [])}
            if detected_os and platforms and not (platforms & detected_os):
                dropped.append({
                    "t_code": code,
                    "reason": f"platform mismatch: {sorted(platforms)} not in "
                              f"topology {sorted(detected_os)}",
                })
                continue
            kept.append(tech)
        return kept, dropped
```

- [ ] **Step 4: Run test to verify it passes**

Run: `venv/bin/pytest tests/test_adversary_forge.py -k filter -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add adversary_forge.py tests/test_adversary_forge.py
git commit -m "feat(forge): deterministic RoE + platform filter (fail-closed RoE)"
```

---

## Task 6: Brain-sequence + hallucination guard + `forge()`

**Files:**
- Modify: `adversary_forge.py`
- Test: `tests/test_adversary_forge.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_adversary_forge.py — append
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `venv/bin/pytest tests/test_adversary_forge.py -k "sequence or forge_end" -v`
Expected: FAIL — `AttributeError: ... 'sequence'` / `'forge'`

- [ ] **Step 3: Implement `sequence`, `forge`, and re-export `LLMClient`**

```python
# adversary_forge.py — add near the top imports
import json as _json

from llm_client import LLMClient  # re-exported so tests can monkeypatch it
```

```python
# adversary_forge.py — add methods to AdversaryForge
    async def sequence(self, kept: list[dict], brain_tier: str, topology: dict) -> list[str]:
        """Ask the brain to ORDER the kept T-codes. Guard against hallucination:
        only codes already in `kept` survive; bad output falls back to filter order.
        """
        kept_codes = [t["t_code"] for t in kept]
        if not kept_codes:
            return []
        allowed = set(kept_codes)
        prompt = (
            "Order these validated MITRE T-codes into a realistic attack sequence "
            "for the given topology. Return ONLY a JSON array of T-code strings, "
            "no prose.\n"
            f"T-codes: {_json.dumps(kept)}\n"
            f"Topology: {_json.dumps(topology)}"
        )
        try:
            client, model, _ = LLMClient.create(brain_tier=brain_tier, agent_name="Forge")
            resp = await client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0,
            )
            raw = resp.choices[0].message.content or ""
            start, end = raw.find("["), raw.rfind("]")
            parsed = _json.loads(raw[start:end + 1]) if start != -1 and end != -1 else []
            ordered = [c for c in parsed if isinstance(c, str) and c in allowed]
            # append any kept code the model omitted, preserving filter order
            ordered += [c for c in kept_codes if c not in ordered]
            return ordered if ordered else kept_codes
        except Exception:
            return kept_codes  # never let brain failure break the deterministic core

    def _read_blacklist(self) -> list[str]:
        try:
            with open(self.roe_path) as f:
                return list(_json.load(f).get("blacklisted_techniques", []))
        except (OSError, ValueError):
            return []

    async def forge(self, actor_name: str, brain_tier: str = "local") -> dict:
        """Full pipeline -> {profile (adversary schema), omitted, metadata}.

        Does NOT write a file. The caller validates via AdversaryProfile and
        decides whether to persist (auto_commit).
        """
        actor = self.load_actor(actor_name)
        detected = GraphManager(db_path=self.graph_path).detected_os()
        kept, dropped = self.filter_techniques(
            actor["techniques"], detected_os=detected, blacklisted=self._read_blacklist()
        )
        topology = {"detected_os": sorted(detected)}
        ordered = await self.sequence(kept, brain_tier=brain_tier, topology=topology)
        stealth = any(c.startswith(("T1070", "T1027", "T1562", "T1564")) for c in ordered)
        profile = {
            "name": actor["name"],
            "alias": actor["name"],
            "description": f"Topology- and RoE-constrained emulation of {actor['name']}.",
            "preferred_ttps": ordered,
            "tools": [],
            "stealth_required": stealth,
            "rationale": (
                f"Forged from {len(actor['techniques'])} actor techniques: "
                f"{len(ordered)} applicable, {len(dropped)} filtered."
            ),
        }
        return {
            "profile": profile,
            "omitted": dropped,
            "metadata": {
                "actor": actor["name"],
                "tier": brain_tier,
                "detected_os": sorted(detected),
                "kept": len(ordered),
                "dropped": len(dropped),
            },
        }
```

- [ ] **Step 4: Run full forge test module**

Run: `venv/bin/pytest tests/test_adversary_forge.py -v`
Expected: PASS (all)

- [ ] **Step 5: Commit**

```bash
git add adversary_forge.py tests/test_adversary_forge.py
git commit -m "feat(forge): brain-tier sequencing with hallucination guard + forge() pipeline"
```

---

## Task 7: RoE `blacklisted_techniques` field

**Files:**
- Modify: `roe.example.json`
- Modify: `webdash/data.py` (`_ROE_WHITELIST`, `_ROE_SENTINEL`)
- Test: `tests/test_webdash_monitor.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_webdash_monitor.py — append (uses existing token/client/monkeypatch fixtures)
def test_roe_exposes_blacklisted_techniques(tmp_path, monkeypatch, client, auth):
    import json
    roe = tmp_path / "roe.json"
    roe.write_text(json.dumps({"blacklisted_techniques": ["T1110"], "secret": "x"}))
    monkeypatch.setenv("OPENELIA_ROE_PATH", str(roe))
    r = client.get("/api/roe", headers=auth)
    assert r.status_code == 200
    body = r.json()
    assert body["blacklisted_techniques"] == ["T1110"]
    assert "secret" not in body  # whitelist still drops unknown keys


def test_roe_backfills_blacklisted_techniques_when_absent(tmp_path, monkeypatch, client, auth):
    import json
    roe = tmp_path / "roe.json"
    roe.write_text(json.dumps({"authorized_subnets": ["10.0.0.0/24"]}))
    monkeypatch.setenv("OPENELIA_ROE_PATH", str(roe))
    r = client.get("/api/roe", headers=auth)
    assert r.json()["blacklisted_techniques"] == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `venv/bin/pytest tests/test_webdash_monitor.py -k blacklisted -v`
Expected: FAIL — `KeyError: 'blacklisted_techniques'`

- [ ] **Step 3: Add the field**

```python
# webdash/data.py — _ROE_WHITELIST
_ROE_WHITELIST: frozenset[str] = frozenset(
    {"authorized_subnets", "blacklisted_ips", "prohibited_tools",
     "quiet_hours", "blacklisted_techniques"}
)

# webdash/data.py — _ROE_SENTINEL
_ROE_SENTINEL: dict = {
    "authorized_subnets": [],
    "blacklisted_ips": [],
    "prohibited_tools": [],
    "quiet_hours": None,
    "blacklisted_techniques": [],
}
```

```json
// roe.example.json — add key (after "prohibited_tools")
  "blacklisted_techniques": ["T1485", "T1486"],
```

- [ ] **Step 4: Run test to verify it passes**

Run: `venv/bin/pytest tests/test_webdash_monitor.py -k blacklisted -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add roe.example.json webdash/data.py tests/test_webdash_monitor.py
git commit -m "feat(forge): RoE blacklisted_techniques field (whitelist + sentinel + example)"
```

---

## Task 8: CLI `forge` subcommand

**Files:**
- Modify: `main.py` (`cmd_forge` near other cmd_*; subparser near `purple_p`; func binding)
- Test: `tests/test_cli_forge.py` (create)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cli_forge.py
import asyncio
import json
from types import SimpleNamespace

import pytest


def test_cmd_forge_dry_run_does_not_write(tmp_path, monkeypatch, capsys):
    import main
    # stub AdversaryForge.forge to a known result
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
    args = SimpleNamespace(actor="APT29", brain_tier="local", auto_commit=True,
                           adversaries_dir=str(tmp_path))
    asyncio.run(main.cmd_forge(args))
    written = json.loads((tmp_path / "tailored_apt29.json").read_text())
    assert written["name"] == "APT29"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `venv/bin/pytest tests/test_cli_forge.py -v`
Expected: FAIL — `AttributeError: module 'main' has no attribute 'cmd_forge'`

- [ ] **Step 3: Implement `cmd_forge` + subparser + binding**

```python
# main.py — add cmd_forge (place near cmd_purple)
async def cmd_forge(args) -> None:
    """Forge a topology/RoE-constrained adversary profile from a MITRE actor."""
    from adversary_forge import AdversaryForge
    from adversary_schema import AdversaryProfile, save_profile

    _require_api_key(args.brain_tier)
    forge = AdversaryForge()
    print(f"[*] Forging adversary profile for {args.actor} (tier={args.brain_tier})...")
    result = await forge.forge(args.actor, brain_tier=args.brain_tier)
    profile = AdversaryProfile(**result["profile"])  # unified schema gate
    meta = result["metadata"]
    print(f"[+] Techniques applicable: {meta['kept']} | filtered: {meta['dropped']}")
    for d in result["omitted"]:
        print(f"    - dropped {d['t_code']}: {d['reason']}")
    if getattr(args, "auto_commit", False):
        adir = getattr(args, "adversaries_dir", "adversaries")
        path = save_profile(profile, f"tailored_{args.actor.lower()}", adversaries_dir=adir)
        print(f"[+] Saved to {path}")
    else:
        print("[i] Dry run (use --auto-commit to write). Profile preview:")
        print(profile.model_dump_json(indent=2))
```

```python
# main.py — add subparser (place near purple_p block)
    forge_p = sub.add_parser("forge", parents=[common],
                             help="Forge an RoE/topology-constrained adversary profile")
    forge_p.add_argument("--actor", required=True, help="MITRE threat-actor name or alias")
    forge_p.add_argument("--scope", help="Network block (informational; run uses RoE)")
    forge_p.add_argument("--auto-commit", action="store_true",
                         help="Write the profile to adversaries/ (default: dry run)")
```

Then ensure dispatch binds `forge` -> `cmd_forge`. Inspect how `main()` maps commands to handlers (e.g. a `COMMANDS = {...}` dict or `if args.command == ...`). Run:
`grep -n "cmd_purple\|args.command ==\|COMMANDS\|globals()\[" main.py`
Add the `forge` mapping in the same style the other commands use.

- [ ] **Step 4: Run tests to verify they pass**

Run: `venv/bin/pytest tests/test_cli_forge.py -v`
Expected: PASS (2 passed)
Run: `venv/bin/python main.py forge --help`
Expected: forge usage shown, exit 0.

- [ ] **Step 5: Commit**

```bash
git add main.py tests/test_cli_forge.py
git commit -m "feat(forge): CLI 'forge' subcommand (dry-run default, --auto-commit)"
```

---

## Task 9: `cli.ts` forge passthrough

**Files:**
- Modify: `src/src/cli.ts` (add `forge` command in the commander block; extend `CLIOptions`)

- [ ] **Step 1: Add the option fields + command**

Add to `CLIOptions`:
```typescript
  autoCommit?: boolean;
```

Add a commander command mirroring the existing python-spawn pattern (find an existing `.command(...)` that calls `this.runPython(...)` / spawns `main.py` and copy its shape):
```typescript
    this.program
      .command('forge')
      .description('Forge an RoE/topology-constrained adversary profile from a MITRE actor')
      .requiredOption('-a, --actor <name>', 'MITRE threat-actor name or alias')
      .option('-t, --brain-tier <tier>', 'local | expensive', 'local')
      .option('--auto-commit', 'Write the profile to adversaries/', false)
      .action((opts: { actor: string; brainTier: string; autoCommit: boolean }) => {
        const pyArgs = ['forge', '--actor', opts.actor, '--brain-tier', opts.brainTier];
        if (opts.autoCommit) pyArgs.push('--auto-commit');
        this.spawnPython(pyArgs);  // use whatever the existing spawn helper is named
      });
```

> NOTE for implementer: confirm the real spawn-helper name (e.g. `runPython`, `spawnPython`, `execPython`) by reading how `red`/`purple` commands invoke python in this file, and use that exact method. Do not invent a method.

- [ ] **Step 2: Typecheck / build**

Run: `cd src && npm run build`
Expected: build succeeds, no TS errors.

- [ ] **Step 3: Commit**

```bash
git add src/src/cli.ts
git commit -m "feat(forge): cli.ts forge passthrough to python main.py"
```

---

## Task 10: webdash `GET /api/actors`

**Files:**
- Modify: `webdash/data.py` (add `actors()`)
- Modify: `webdash/api/monitor.py` (add route)
- Test: `tests/test_webdash_forge.py` (create)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_webdash_forge.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `venv/bin/pytest tests/test_webdash_forge.py -k actors -v`
Expected: FAIL — 404 (route missing).

- [ ] **Step 3: Implement `actors()` + route**

```python
# webdash/data.py — add method to DashboardData
    def actors(self) -> list[str]:
        """Sorted actor names from the slim actor map (OPENELIA_ACTOR_MAP env,
        default 'actor_ttps.json'). Missing/unreadable -> []."""
        path = Path(os.getenv("OPENELIA_ACTOR_MAP", "actor_ttps.json"))
        try:
            return sorted(json.loads(path.read_text()).keys())
        except (OSError, json.JSONDecodeError, AttributeError):
            return []
```

```python
# webdash/api/monitor.py — add route
@router.get("/actors")
def get_actors(data: DashboardData = Depends(get_data)) -> list[str]:
    return data.actors()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `venv/bin/pytest tests/test_webdash_forge.py -k actors -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add webdash/data.py webdash/api/monitor.py tests/test_webdash_forge.py
git commit -m "feat(forge): GET /api/actors lists available adversary names"
```

---

## Task 11: webdash `POST /api/forge`

**Files:**
- Modify: `webdash/api/control.py` (`ForgeRun` model + route)
- Modify: `webdash/frontend/src/api.ts` (`ForgeResp`, `ActorResp`)
- Test: `tests/test_webdash_forge.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_webdash_forge.py — append
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `venv/bin/pytest tests/test_webdash_forge.py -k "forge_" -v`
Expected: FAIL — 404 (route missing).

- [ ] **Step 3: Implement `ForgeRun` + route**

```python
# webdash/api/control.py — add model (near other *Run models)
class ForgeRun(BaseModel):
    actor: str
    brain_tier: str = "local"
    auto_commit: bool = False
    confirm: bool = False
```

```python
# webdash/api/control.py — add route (near other @router.post)
@router.post("/forge")
async def run_forge(req: ForgeRun, data: DashboardData = Depends(get_data)) -> dict:
    # Forge only reads + generates a profile; it does NOT launch ops, so it needs
    # token + confirm but not scope_gate. Running the forged profile later still
    # goes through the gated /run/* endpoints.
    require_confirm(req.confirm)
    from adversary_forge import AdversaryForge
    from adversary_schema import AdversaryProfile, save_profile

    result = await AdversaryForge().forge(req.actor, brain_tier=req.brain_tier)
    profile = AdversaryProfile(**result["profile"])  # unified schema gate
    saved_path = None
    if req.auto_commit:
        saved_path = save_profile(profile, f"tailored_{req.actor.lower()}")
    return {
        "profile": profile.model_dump(),
        "omitted": result["omitted"],
        "metadata": result["metadata"],
        "saved_path": saved_path,
    }
```

```typescript
// webdash/frontend/src/api.ts — append types
export type ActorResp = string;
export type ForgeResp = {
  profile: AdversaryResp;
  omitted: { t_code: string; reason: string }[];
  metadata: { actor: string; tier: string; detected_os?: string[]; kept: number; dropped: number };
  saved_path: string | null;
};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `venv/bin/pytest tests/test_webdash_forge.py -v`
Expected: PASS (all)
Run: `cd src/.. && venv/bin/pytest tests/test_webdash_monitor.py -q` (regression)
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add webdash/api/control.py webdash/frontend/src/api.ts tests/test_webdash_forge.py
git commit -m "feat(forge): POST /api/forge (token+confirm, schema-gated) + api.ts types"
```

---

## Task 12: React `AdversaryForgeView` + sidebar + route

**Files:**
- Create: `webdash/frontend/src/components/AdversaryForgeView.tsx`
- Modify: `webdash/frontend/src/components/Sidebar.tsx` (Operations group)
- Modify: `webdash/frontend/src/App.tsx` (switch case)

- [ ] **Step 1: Implement the view**

```tsx
// webdash/frontend/src/components/AdversaryForgeView.tsx
import { useEffect, useState } from "react";
import { apiGet, apiPost, ActorResp, ForgeResp } from "../api";
import { Badge, Panel } from "./Panel";

type Tier = "local" | "expensive";

export function AdversaryForgeView() {
  const [actors, setActors] = useState<ActorResp[] | null>(null);
  const [actor, setActor] = useState("");
  const [tier, setTier] = useState<Tier>("local");
  const [autoCommit, setAutoCommit] = useState(false);
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<ForgeResp | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    apiGet<ActorResp[]>("/api/actors")
      .then((a) => { setActors(a); if (a.length) setActor(a[0]); })
      .catch((e: unknown) => setErr(e instanceof Error ? e.message : String(e)));
  }, []);

  async function forge() {
    if (!actor || pending) return;
    setPending(true); setErr(null); setResult(null);
    try {
      const r = await apiPost<ForgeResp>("/api/forge", {
        actor, brain_tier: tier, auto_commit: autoCommit, confirm: true,
      });
      setResult(r);
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally { setPending(false); }
  }

  return (
    <Panel title="Adversary Forge" className="h-full">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 h-full">
        {/* left: config workspace */}
        <div className="space-y-3">
          <div className="font-display text-[10px] uppercase tracking-[0.2em] text-amber/70">
            Configuration
          </div>
          <select
            value={actor}
            onChange={(e) => setActor(e.target.value)}
            className="w-full bg-void border border-line px-2 py-1 text-xs font-mono text-slate-200 focus:border-amber focus:outline-none"
          >
            {(actors ?? []).map((a) => <option key={a} value={a}>{a}</option>)}
          </select>
          <div className="flex gap-2">
            {(["local", "expensive"] as Tier[]).map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => setTier(t)}
                className={`font-display uppercase tracking-widest text-xs px-3 py-1 border ${
                  tier === t ? "border-amber text-amber glow" : "border-line text-dim"
                }`}
              >
                {t}
              </button>
            ))}
          </div>
          <label className="flex items-center gap-2 text-xs font-mono text-dim">
            <input type="checkbox" checked={autoCommit}
                   onChange={(e) => setAutoCommit(e.target.checked)} />
            auto-commit to adversaries/
          </label>
          {err && <Badge ok={false}>{err}</Badge>}
        </div>

        {/* right: verification pipeline stream */}
        <div className="border border-line bg-surface/50 p-3 overflow-auto scroll-thin">
          <div className="font-display text-[10px] uppercase tracking-[0.2em] text-amber/70 mb-2">
            Pipeline
          </div>
          {!result && <div className="text-dim text-xs italic">no run yet</div>}
          {result && (
            <div className="space-y-1">
              {result.profile.preferred_ttps.map((t) => (
                <div key={t} className="font-mono text-xs px-2 py-0.5 border-l-2 border-phos text-phos">
                  ✓ {t}
                </div>
              ))}
              {result.omitted.map((d) => (
                <div key={d.t_code}
                     className="font-mono text-[11px] px-2 py-0.5 border-l-2 border-amber/40 text-dim line-through opacity-60">
                  ✗ {d.t_code} — {d.reason}
                </div>
              ))}
              {result.saved_path && (
                <div className="mt-2 text-[11px] font-mono text-phos">saved: {result.saved_path}</div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* footer security anchor */}
      <div className="mt-3 border-t border-line pt-2 flex items-center justify-between">
        <span className="text-[11px] font-mono text-dim">
          Forge generates a profile only — running it still requires the gated /run path.
        </span>
        <button
          type="button"
          onClick={forge}
          disabled={!actor || pending}
          className="font-display uppercase tracking-widest bg-amber/15 border border-amber text-amber glow text-xs px-4 py-1 disabled:opacity-40 hover:bg-amber/25"
        >
          {pending ? "···" : "▶ Forge Profile"}
        </button>
      </div>
    </Panel>
  );
}
```

- [ ] **Step 2: Wire sidebar + route**

```tsx
// Sidebar.tsx — add to the "Operations" group views array (after apt)
      { id: "forge", label: "Adversary Forge" },
```

```tsx
// App.tsx — add import + switch case
import { AdversaryForgeView } from "./components/AdversaryForgeView";
// inside switch(activeView):
      case "forge": return <Solo><AdversaryForgeView /></Solo>;
```

- [ ] **Step 3: Build the frontend**

Run: `cd webdash/frontend && npm run build`
Expected: build succeeds, no TS errors.

- [ ] **Step 4: Commit**

```bash
git add webdash/frontend/src/components/AdversaryForgeView.tsx \
        webdash/frontend/src/components/Sidebar.tsx \
        webdash/frontend/src/App.tsx
git commit -m "feat(forge): AdversaryForgeView UI + sidebar nav + App route"
```

---

## Final Verification (after all tasks)

- [ ] `venv/bin/pytest tests/test_adversary_forge.py tests/test_cli_forge.py tests/test_webdash_forge.py tests/test_webdash_monitor.py -v` → all pass
- [ ] `cd webdash/frontend && npm run build` → clean
- [ ] `cd src && npm run build` → clean
- [ ] `venv/bin/python main.py forge --actor APT29 --brain-tier local` → prints kept/dropped, dry-run preview, writes nothing
- [ ] `scripts/secret-scan.sh --staged` clean before each commit
- [ ] No `stix2` import anywhere outside `scripts/extract_actor_ttps.py`:
      `grep -rn "import stix2\|from stix2" --include=*.py . | grep -v venv | grep -v scripts/extract_actor_ttps.py` → empty

## Security Invariants (must hold at the end)

- Forge reads + generates only; never calls `route()`/launches. Running a forged profile goes through the existing gated `/run/*` (confirm + unlocked + scope_gate).
- Every persisted profile passes the `AdversaryProfile` gate (CLI + webdash).
- LLM cannot introduce T-codes outside the deterministically-filtered set (hallucination guard).
- RoE rule fails closed; OS rule fails open only when OS/platform unknown (documented).
- `save_profile` reuses `AdversaryManager` realpath + regex guards (no path traversal).
- `/api/forge` is token + confirm gated; `/api/actors` is token gated.
- The 51 MB STIX bundle stays gitignored; only the slim `actor_ttps.json` is committed.
