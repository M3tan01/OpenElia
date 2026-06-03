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
        software: set[str] = set()
        for rel in rels:
            target = store.get(rel.target_ref)
            if not target:
                continue
            if getattr(target, "x_mitre_deprecated", False) or getattr(target, "revoked", False):
                continue
            # actor 'uses' a tool/malware -> emulation tool inventory
            if target.type in ("tool", "malware"):
                software.add(target.name)
                continue
            if target.type != "attack-pattern":
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
                "software": sorted(software),
                "techniques": techniques,
            }
    return out


if __name__ == "__main__":
    data = build()
    with open(OUT_PATH, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    print(f"[+] Wrote {OUT_PATH}: {len(data)} actors")
