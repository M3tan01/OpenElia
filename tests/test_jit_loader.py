"""
tests/test_jit_loader.py — JITLoader auto-discovery and skill injection.

Covers: empty skills dir, direct-name mapping, common-skill broadcast,
        SKILL.md section extraction, fallback excerpt, load_for_agent,
        load_semantic_skills alias, get_skills_for_agent.
"""
import pytest
from pathlib import Path
from jit_loader import JITLoader


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_skill(skills_root: Path, skill_name: str, section_content: str = "", full_content: str = ""):
    """Create a skills/<name>/SKILL.md with optional section or full content."""
    skill_dir = skills_root / skill_name
    skill_dir.mkdir(parents=True, exist_ok=True)
    if full_content:
        (skill_dir / "SKILL.md").write_text(full_content)
    else:
        content = f"# {skill_name}\n\n## Agent Skill Definition\n\n{section_content}\n"
        (skill_dir / "SKILL.md").write_text(content)


def _make_agent(agents_root: Path, team: str, agent_name: str):
    team_dir = agents_root / team
    team_dir.mkdir(parents=True, exist_ok=True)
    (team_dir / f"{agent_name}.py").write_text("")


# ---------------------------------------------------------------------------
# Auto-discovery
# ---------------------------------------------------------------------------

class TestAutoDiscovery:
    def test_empty_skills_dir_returns_empty_map(self, tmp_path, monkeypatch):
        # Redirect _PROJECT_ROOT so no real agents/ are discovered
        monkeypatch.setattr("jit_loader._PROJECT_ROOT", tmp_path)
        (tmp_path / "skills").mkdir()
        loader = JITLoader(skills_path=str(tmp_path / "skills"))
        assert loader.dynamic_skill_map == {}

    def test_nonexistent_skills_dir_returns_empty_map(self, tmp_path, monkeypatch):
        monkeypatch.setattr("jit_loader._PROJECT_ROOT", tmp_path)
        loader = JITLoader(skills_path=str(tmp_path / "no_such_dir"))
        assert loader.dynamic_skill_map == {}

    def test_direct_name_mapping(self, tmp_path, monkeypatch):
        skills = tmp_path / "skills"
        agents = tmp_path / "agents"
        _make_skill(skills, "pentester_recon", "Do recon.")
        _make_agent(agents, "red", "pentester_recon")
        monkeypatch.setattr("jit_loader._PROJECT_ROOT", tmp_path)
        loader = JITLoader(skills_path=str(skills))
        assert "pentester_recon" in loader.get_skills_for_agent("pentester_recon")

    def test_common_skill_mapped_to_all_agents(self, tmp_path, monkeypatch):
        skills = tmp_path / "skills"
        agents = tmp_path / "agents"
        _make_skill(skills, "common_opsec", "OPSEC checklist.")
        _make_agent(agents, "red", "pentester_recon")
        _make_agent(agents, "blue", "defender_mon")
        monkeypatch.setattr("jit_loader._PROJECT_ROOT", tmp_path)
        loader = JITLoader(skills_path=str(skills))
        assert "common_opsec" in loader.get_skills_for_agent("pentester_recon")
        assert "common_opsec" in loader.get_skills_for_agent("defender_mon")

    def test_unknown_agent_returns_empty_list(self, tmp_path):
        loader = JITLoader(skills_path=str(tmp_path / "skills"))
        assert loader.get_skills_for_agent("nonexistent_agent") == []


# ---------------------------------------------------------------------------
# Skill extraction
# ---------------------------------------------------------------------------

class TestSkillExtraction:
    def test_extracts_agent_skill_definition_section(self, tmp_path, monkeypatch):
        skills = tmp_path / "skills"
        agents = tmp_path / "agents"
        _make_skill(skills, "pentester_recon", "Run nmap. Enumerate services.")
        _make_agent(agents, "red", "pentester_recon")
        monkeypatch.setattr("jit_loader._PROJECT_ROOT", tmp_path)
        loader = JITLoader(skills_path=str(skills))
        result = loader.load_for_agent("pentester_recon")
        assert "Run nmap" in result
        assert "pentester_recon" in result

    def test_fallback_excerpt_when_no_section(self, tmp_path, monkeypatch):
        skills = tmp_path / "skills"
        agents = tmp_path / "agents"
        # No "## Agent Skill Definition" section
        _make_skill(skills, "pentester_recon", full_content="# Recon\nLine one.\nLine two.\n")
        _make_agent(agents, "red", "pentester_recon")
        monkeypatch.setattr("jit_loader._PROJECT_ROOT", tmp_path)
        loader = JITLoader(skills_path=str(skills))
        result = loader.load_for_agent("pentester_recon")
        assert "Line one" in result or "excerpt" in result

    def test_missing_skill_file_returns_empty(self, tmp_path, monkeypatch):
        skills = tmp_path / "skills"
        agents = tmp_path / "agents"
        # Agent exists but no matching skill directory
        _make_agent(agents, "red", "pentester_ex")
        monkeypatch.setattr("jit_loader._PROJECT_ROOT", tmp_path)
        loader = JITLoader(skills_path=str(skills))
        result = loader.load_for_agent("pentester_ex")
        assert result == ""

    def test_load_for_agent_returns_header(self, tmp_path, monkeypatch):
        skills = tmp_path / "skills"
        agents = tmp_path / "agents"
        _make_skill(skills, "defender_mon", "Watch logs.")
        _make_agent(agents, "blue", "defender_mon")
        monkeypatch.setattr("jit_loader._PROJECT_ROOT", tmp_path)
        loader = JITLoader(skills_path=str(skills))
        result = loader.load_for_agent("defender_mon")
        assert "Loaded Skills" in result


# ---------------------------------------------------------------------------
# load_semantic_skills alias
# ---------------------------------------------------------------------------

class TestLoadSemanticSkills:
    def test_alias_returns_same_as_load_for_agent(self, tmp_path, monkeypatch):
        skills = tmp_path / "skills"
        agents = tmp_path / "agents"
        _make_skill(skills, "defender_res", "Remediate.")
        _make_agent(agents, "blue", "defender_res")
        monkeypatch.setattr("jit_loader._PROJECT_ROOT", tmp_path)
        loader = JITLoader(skills_path=str(skills))
        assert loader.load_semantic_skills("defender_res") == loader.load_for_agent("defender_res")

    def test_alias_accepts_task_context_without_error(self, tmp_path):
        loader = JITLoader(skills_path=str(tmp_path / "skills"))
        # Must not raise even with non-empty task_context
        result = loader.load_semantic_skills("no_agent", task_context="hunt for persistence")
        assert result == ""
