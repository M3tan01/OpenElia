"""AdversaryForge — turn a MITRE actor name into an RoE/topology-constrained
adversary profile. Runtime path imports NO stix2 (reads the slim actor_ttps.json
produced offline by scripts/extract_actor_ttps.py).
"""
from __future__ import annotations

import json
import json as _json
import os

from graph_manager import GraphManager
from llm_client import LLMClient  # re-exported so tests can monkeypatch it


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
