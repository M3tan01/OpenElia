"""
core/playbook.py — Declarative engagement playbook model + loader.

A Playbook is a YAML-described engagement template. The orchestrator is a
message broker only (it does not consume a per-phase tool list), so a
playbook's phases/tools are ADVISORY: compose_task() folds them into the
single task string the orchestrator already accepts, so the agents see the
intended flow. This module is pure data + composition — it imports no
orchestrator/agent code and runs no engagement.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, field_validator

_ALLOWED_DOMAINS = {"red", "blue", "purple"}


class PlaybookVariable(BaseModel):
    """A declared input variable for a playbook (e.g. target)."""
    required: bool = False
    description: str = ""


class PlaybookPhase(BaseModel):
    """One advisory phase: a name, optional tool hints, optional directive."""
    name: str
    tools: list[str] = []
    post_analysis: str | None = None


class Playbook(BaseModel):
    """A declarative engagement template loaded from YAML."""
    name: str
    description: str = ""
    domain: str = "red"
    passive: bool = False
    stealth: bool = False
    brain_tier: str = "local"
    apt_profile: str | None = None
    variables: dict[str, PlaybookVariable] = {}
    phases: list[PlaybookPhase]

    @field_validator("domain")
    @classmethod
    def _validate_domain(cls, v: str) -> str:
        if v not in _ALLOWED_DOMAINS:
            raise ValueError(
                f"domain must be one of {sorted(_ALLOWED_DOMAINS)}, got {v!r}"
            )
        return v

    @field_validator("phases")
    @classmethod
    def _validate_phases_nonempty(cls, v: list[PlaybookPhase]) -> list[PlaybookPhase]:
        if not v:
            raise ValueError("playbook must declare at least one phase")
        return v

    # ------------------------------------------------------------------ load

    @classmethod
    def load(cls, path: str | Path) -> "Playbook":
        """Load and validate a playbook from a YAML file.

        Raises FileNotFoundError if the path is missing and pydantic
        ValidationError on malformed data.
        """
        import yaml

        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Playbook not found: {p}")
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        return cls(**data)

    # -------------------------------------------------------------- variables

    def resolve_variables(self, provided: dict[str, str]) -> dict[str, str]:
        """Return a copy of provided values after asserting all required
        variables are present. Raises ValueError naming every missing one.
        Does not mutate the input.
        """
        missing = [
            name
            for name, spec in self.variables.items()
            if spec.required and name not in provided
        ]
        if missing:
            raise ValueError(
                f"missing required playbook variable(s): {', '.join(sorted(missing))}"
            )
        return dict(provided)

    # ------------------------------------------------------------- composition

    @staticmethod
    def _safe_substitute(text: str, values: dict[str, str]) -> str:
        """Replace only {key} placeholders for keys present in values.

        Unknown placeholders are left intact (documented behaviour); literal
        braces that aren't a known key are untouched. Avoids str.format's
        KeyError/ValueError on stray braces.
        """
        for key, value in values.items():
            text = text.replace("{" + key + "}", str(value))
        return text

    def compose_task(self, values: dict[str, str]) -> str:
        """Build the single advisory task string the orchestrator receives.

        Includes the description and, in declared order, each phase's name,
        tool hints, and post_analysis directive. {var} placeholders in the
        description/post_analysis are substituted from values.
        """
        lines: list[str] = []
        if self.description:
            lines.append(self._safe_substitute(self.description, values))
        lines.append("")
        lines.append("Intended engagement flow (advisory):")
        for i, phase in enumerate(self.phases, start=1):
            header = f"{i}. {phase.name}"
            if phase.tools:
                header += f" — tools: {', '.join(phase.tools)}"
            lines.append(header)
            if phase.post_analysis:
                directive = self._safe_substitute(phase.post_analysis, values)
                lines.append(f"   {directive}")
        return "\n".join(lines)
