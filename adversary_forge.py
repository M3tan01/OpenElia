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
