"""
jit_loader.py — Dynamic Just-In-Time skill loader for OpenElia.

Implements Auto-Discovery:
1. Scans the 'skills/' directory for SKILL.md files.
2. Automatically maps skills to agents by checking for agent-specific subfolders 
   or naming conventions (zero-code extension).
"""

import os
import re
from pathlib import Path
from typing import Dict, List


_SKILLS_PATH = os.getenv("SKILLS_PATH", "./skills")

# Section header to extract from each SKILL.md.
_SECTION_PATTERN = re.compile(
    r"^## Agent Skill Definition\s*\n(.*?)(?=\n## |\Z)",
    re.MULTILINE | re.DOTALL,
)


class JITLoader:
    def __init__(self, skills_path: str = _SKILLS_PATH):
        self.skills_path = Path(skills_path)
        self.dynamic_skill_map: Dict[str, List[str]] = self._auto_discover_skills()

    def _auto_discover_skills(self) -> Dict[str, List[str]]:
        """
        Scans the filesystem to build the skill map dynamically.
        Logic:
        - If a skill folder 'X' exists in 'skills/'
        - And 'agents/red/X.py' or 'agents/blue/X.py' exists
        - We map skill 'X' to agent 'X'.
        - General skills (no matching agent name) are mapped by checking 
          an optional 'MANIFEST.json' in the skill folder or by naming prefix.
        """
        mapping = {}
        
        if not self.skills_path.exists():
            return {}

        # 1. Get all available skills
        available_skills = [d.name for d in self.skills_path.iterdir() if d.is_dir() and (d / "SKILL.md").exists()]

        # 2. Get all available agents (red and blue)
        agents_dir = Path("agents")
        agent_names = []
        if agents_dir.exists():
            for team in ["red", "blue"]:
                team_dir = agents_dir / team
                if team_dir.exists():
                    agent_names += [f.stem for f in team_dir.glob("*.py") if f.name != "__init__.py"]

        # 3. Dynamic Mapping
        for agent in agent_names:
            mapping[agent] = []
            
            # Match by direct name (e.g. skill 'pentester_recon' -> agent 'pentester_recon')
            if agent in available_skills:
                mapping[agent].append(agent)
            
            # Match by prefix (e.g. skill 'recon-nmap' -> agent 'pentester_recon')
            prefix = agent.split("_")[-1] # 'recon', 'vuln', 'ana', etc.
            for skill in available_skills:
                if skill.startswith(prefix) or f"-{prefix}" in skill:
                    if skill not in mapping[agent]:
                        mapping[agent].append(skill)
                        
            # Custom logic: if it's a 'common' skill, give it to everyone
            for skill in available_skills:
                if "common" in skill or "base" in skill:
                    mapping[agent].append(skill)

        return mapping

    def load_for_agent(self, agent_name: str) -> str:
        """
        Return a compact skill block for injection into a system prompt.
        """
        skill_names = self.dynamic_skill_map.get(agent_name, [])
        if not skill_names:
            return ""

        blocks: list[str] = []
        for skill_name in skill_names:
            content = self._load_skill(skill_name)
            if content:
                extracted = self._extract_skill_definition(content, skill_name)
                if extracted:
                    blocks.append(extracted)

        if not blocks:
            return ""

        header = "## Loaded Skills (Auto-Discovered JIT)\n\n"
        return header + "\n\n---\n\n".join(blocks)

    def _load_skill(self, skill_name: str) -> str:
        skill_file = self.skills_path / skill_name / "SKILL.md"
        if not skill_file.exists():
            return ""
        return skill_file.read_text(encoding="utf-8")

    def _extract_skill_definition(self, content: str, skill_name: str) -> str:
        match = _SECTION_PATTERN.search(content)
        if match:
            body = match.group(1).strip()
            return f"### {skill_name}\n\n{body}"

        # Fallback: first 60 lines
        lines = content.splitlines()
        start = 0
        if lines and lines[0].strip() == "---":
            for i, line in enumerate(lines[1:], 1):
                if line.strip() == "---":
                    start = i + 1
                    break
        excerpt = "\n".join(lines[start : start + 60]).strip()
        if excerpt:
            return f"### {skill_name} (excerpt)\n\n{excerpt}"
        return ""
