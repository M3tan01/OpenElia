"""
tests/test_playbook.py — Tests for core/playbook.py (TDD, written first).

All tests use tmp_path for YAML fixtures — no real files on disk.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
from pydantic import ValidationError

from core.playbook import Playbook, PlaybookPhase, PlaybookVariable


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_yaml(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "playbook.yaml"
    p.write_text(textwrap.dedent(content))
    return p


# ---------------------------------------------------------------------------
# PlaybookVariable
# ---------------------------------------------------------------------------

class TestPlaybookVariable:
    def test_defaults(self):
        v = PlaybookVariable()
        assert v.required is False
        assert v.description == ""

    def test_custom_values(self):
        v = PlaybookVariable(required=True, description="Root domain")
        assert v.required is True
        assert v.description == "Root domain"


# ---------------------------------------------------------------------------
# PlaybookPhase
# ---------------------------------------------------------------------------

class TestPlaybookPhase:
    def test_defaults(self):
        phase = PlaybookPhase(name="recon")
        assert phase.name == "recon"
        assert phase.tools == []
        assert phase.post_analysis is None

    def test_with_tools_and_post_analysis(self):
        phase = PlaybookPhase(
            name="scan",
            tools=["nmap", "gobuster"],
            post_analysis="Catalogue services",
        )
        assert phase.tools == ["nmap", "gobuster"]
        assert phase.post_analysis == "Catalogue services"


# ---------------------------------------------------------------------------
# Playbook model validation
# ---------------------------------------------------------------------------

class TestPlaybookValidation:
    def _minimal_phases(self):
        return [{"name": "recon"}]

    def test_valid_domain_red(self):
        p = Playbook(name="x", phases=[PlaybookPhase(name="recon")], domain="red")
        assert p.domain == "red"

    def test_valid_domain_blue(self):
        p = Playbook(name="x", phases=[PlaybookPhase(name="recon")], domain="blue")
        assert p.domain == "blue"

    def test_valid_domain_purple(self):
        p = Playbook(name="x", phases=[PlaybookPhase(name="recon")], domain="purple")
        assert p.domain == "purple"

    def test_invalid_domain_raises(self):
        with pytest.raises((ValueError, ValidationError)):
            Playbook(name="x", phases=[PlaybookPhase(name="recon")], domain="yellow")

    def test_empty_phases_raises(self):
        with pytest.raises((ValueError, ValidationError)):
            Playbook(name="x", phases=[])

    def test_defaults(self):
        p = Playbook(name="x", phases=[PlaybookPhase(name="recon")])
        assert p.description == ""
        assert p.domain == "red"
        assert p.passive is False
        assert p.stealth is False
        assert p.brain_tier == "local"
        assert p.apt_profile is None
        assert p.variables == {}


# ---------------------------------------------------------------------------
# Playbook.load
# ---------------------------------------------------------------------------

class TestPlaybookLoad:
    def test_load_valid_yaml(self, tmp_path):
        yaml_content = """
            name: web-owasp
            description: "OWASP Top 10 web app assessment"
            domain: red
            passive: false
            stealth: false
            brain_tier: local
            apt_profile: null
            variables:
              target:
                required: true
                description: "Root domain or IP/CIDR"
            phases:
              - name: recon
                tools: [nmap, gobuster]
                post_analysis: "Catalogue services and tech stack"
              - name: exploit
                tools: [sqlmap]
                post_analysis: "Document vulnerabilities found"
        """
        p_file = _write_yaml(tmp_path, yaml_content)
        pb = Playbook.load(str(p_file))

        assert pb.name == "web-owasp"
        assert pb.description == "OWASP Top 10 web app assessment"
        assert pb.domain == "red"
        assert pb.passive is False
        assert pb.stealth is False
        assert pb.brain_tier == "local"
        assert pb.apt_profile is None

    def test_load_phases_parsed(self, tmp_path):
        yaml_content = """
            name: test
            phases:
              - name: recon
                tools: [nmap, gobuster]
                post_analysis: "Catalogue services"
              - name: exploit
        """
        p_file = _write_yaml(tmp_path, yaml_content)
        pb = Playbook.load(str(p_file))

        assert len(pb.phases) == 2
        assert pb.phases[0].name == "recon"
        assert pb.phases[0].tools == ["nmap", "gobuster"]
        assert pb.phases[0].post_analysis == "Catalogue services"
        assert pb.phases[1].name == "exploit"
        assert pb.phases[1].tools == []
        assert pb.phases[1].post_analysis is None

    def test_load_variables_parsed(self, tmp_path):
        yaml_content = """
            name: test
            variables:
              target:
                required: true
                description: "Target host"
            phases:
              - name: recon
        """
        p_file = _write_yaml(tmp_path, yaml_content)
        pb = Playbook.load(str(p_file))

        assert "target" in pb.variables
        assert pb.variables["target"].required is True
        assert pb.variables["target"].description == "Target host"

    def test_load_path_object(self, tmp_path):
        yaml_content = """
            name: test
            phases:
              - name: recon
        """
        p_file = _write_yaml(tmp_path, yaml_content)
        # Pass Path object, not str
        pb = Playbook.load(p_file)
        assert pb.name == "test"

    def test_load_nonexistent_path_raises_file_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            Playbook.load(str(tmp_path / "does_not_exist.yaml"))

    def test_load_invalid_domain_raises_validation_error(self, tmp_path):
        yaml_content = """
            name: bad
            domain: orange
            phases:
              - name: recon
        """
        p_file = _write_yaml(tmp_path, yaml_content)
        with pytest.raises((ValueError, ValidationError)):
            Playbook.load(str(p_file))

    def test_load_empty_phases_raises_validation_error(self, tmp_path):
        yaml_content = """
            name: bad
            phases: []
        """
        p_file = _write_yaml(tmp_path, yaml_content)
        with pytest.raises((ValueError, ValidationError)):
            Playbook.load(str(p_file))


# ---------------------------------------------------------------------------
# Playbook.resolve_variables
# ---------------------------------------------------------------------------

class TestResolveVariables:
    def _make_playbook(self, variables: dict) -> Playbook:
        return Playbook(
            name="test",
            phases=[PlaybookPhase(name="recon")],
            variables=variables,
        )

    def test_all_required_provided_returns_values(self):
        pb = self._make_playbook({
            "target": PlaybookVariable(required=True, description="Target"),
            "port": PlaybookVariable(required=True, description="Port"),
        })
        result = pb.resolve_variables({"target": "10.0.0.1", "port": "80"})
        assert result == {"target": "10.0.0.1", "port": "80"}

    def test_missing_required_raises_with_name(self):
        pb = self._make_playbook({
            "target": PlaybookVariable(required=True, description="Target"),
            "port": PlaybookVariable(required=True, description="Port"),
        })
        with pytest.raises(ValueError) as exc_info:
            pb.resolve_variables({"target": "10.0.0.1"})
        assert "port" in str(exc_info.value)

    def test_missing_multiple_required_lists_all(self):
        pb = self._make_playbook({
            "target": PlaybookVariable(required=True),
            "port": PlaybookVariable(required=True),
            "proto": PlaybookVariable(required=True),
        })
        with pytest.raises(ValueError) as exc_info:
            pb.resolve_variables({})
        err = str(exc_info.value)
        assert "target" in err
        assert "port" in err
        assert "proto" in err

    def test_optional_var_not_provided_does_not_raise(self):
        pb = self._make_playbook({
            "target": PlaybookVariable(required=True),
            "port": PlaybookVariable(required=False),
        })
        # Should not raise — port is optional
        result = pb.resolve_variables({"target": "10.0.0.1"})
        assert result["target"] == "10.0.0.1"

    def test_no_variables_no_raise(self):
        pb = self._make_playbook({})
        result = pb.resolve_variables({})
        assert result == {}

    def test_does_not_mutate_input(self):
        pb = self._make_playbook({
            "target": PlaybookVariable(required=True),
        })
        provided = {"target": "10.0.0.1"}
        original = dict(provided)
        pb.resolve_variables(provided)
        assert provided == original


# ---------------------------------------------------------------------------
# Playbook.compose_task
# ---------------------------------------------------------------------------

class TestComposeTask:
    def _make_playbook(self, **kwargs) -> Playbook:
        defaults = dict(
            name="web-owasp",
            description="OWASP Top 10 web app assessment",
            phases=[
                PlaybookPhase(
                    name="recon",
                    tools=["nmap", "gobuster"],
                    post_analysis="Catalogue services and tech stack",
                ),
                PlaybookPhase(name="exploit", tools=["sqlmap"]),
            ],
        )
        defaults.update(kwargs)
        return Playbook(**defaults)

    def test_description_in_output(self):
        pb = self._make_playbook()
        result = pb.compose_task({})
        assert "OWASP Top 10 web app assessment" in result

    def test_phase_names_in_output(self):
        pb = self._make_playbook()
        result = pb.compose_task({})
        assert "recon" in result
        assert "exploit" in result

    def test_tool_names_in_output(self):
        pb = self._make_playbook()
        result = pb.compose_task({})
        assert "nmap" in result
        assert "gobuster" in result
        assert "sqlmap" in result

    def test_post_analysis_in_output(self):
        pb = self._make_playbook()
        result = pb.compose_task({})
        assert "Catalogue services and tech stack" in result

    def test_phases_in_declared_order(self):
        pb = self._make_playbook()
        result = pb.compose_task({})
        recon_pos = result.index("recon")
        exploit_pos = result.index("exploit")
        assert recon_pos < exploit_pos

    def test_variable_substitution(self):
        pb = Playbook(
            name="test",
            description="Assessment of {target}",
            phases=[
                PlaybookPhase(
                    name="recon",
                    post_analysis="Scan {target} for open ports",
                )
            ],
        )
        result = pb.compose_task({"target": "192.168.1.1"})
        assert "192.168.1.1" in result
        assert "{target}" not in result

    def test_unknown_placeholder_does_not_crash(self):
        """If a placeholder has no matching value, compose_task must not raise."""
        pb = Playbook(
            name="test",
            description="Assessment of {unknown_var}",
            phases=[PlaybookPhase(name="recon")],
        )
        # Must not raise; behaviour is documented as: leave unknown placeholder intact
        result = pb.compose_task({})
        assert isinstance(result, str)

    def test_extra_values_do_not_crash(self):
        """Extra keys in values dict that don't appear as placeholders are fine."""
        pb = Playbook(
            name="test",
            description="Simple assessment",
            phases=[PlaybookPhase(name="recon")],
        )
        result = pb.compose_task({"target": "10.0.0.1", "extra": "unused"})
        assert isinstance(result, str)

    def test_phase_with_no_tools_or_post_analysis(self):
        pb = Playbook(
            name="test",
            description="Minimal",
            phases=[PlaybookPhase(name="recon")],
        )
        result = pb.compose_task({})
        assert "recon" in result
        assert isinstance(result, str)
