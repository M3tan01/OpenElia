"""Unified validation gate for forged adversary profiles.

Every forged profile — whether produced by the CLI or the webdash endpoint —
is validated through AdversaryProfile before it is written, and saved only via
save_profile(), which reuses AdversaryManager's realpath/regex guards.
"""
from __future__ import annotations

import json
import os
import re

from pydantic import BaseModel, Field

from adversary_manager import AdversaryManager


def make_stem(actor: str) -> str:
    """Build a safe adversaries/ file stem from an actor name.

    Slugifies spaces/punctuation to '_' and bounds length so the result always
    satisfies AdversaryManager._APT_NAME_RE. Many MITRE actor names contain
    spaces (e.g. "Aquatic Panda") and would otherwise fail save_profile's strict
    guard after the profile was already forged.
    """
    slug = re.sub(r"[^a-z0-9_-]+", "_", actor.lower()).strip("_")
    stem = f"tailored_{slug}"[:32].rstrip("_")
    return stem or "tailored_profile"


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
