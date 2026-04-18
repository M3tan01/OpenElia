"""
core/schemas.py — Strict Pydantic v2 contracts for all inter-agent communication.

Every task placed into the AsyncWorkerPool MUST be wrapped in an AgentTask.
Every agent MUST return an AgentResult. No raw dicts cross agent boundaries.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AgentTier(str, Enum):
    """Execution tier. Orderable via < / > for pipeline sequencing."""
    RECON = "recon"         # Data gathering (nmap, OSINT, log pull)
    ANALYSIS = "analysis"   # Reasoning over gathered data
    EXECUTION = "execution" # Active action (exploit, patch, report emit)

    _order = ["recon", "analysis", "execution"]

    def __lt__(self, other: "AgentTier") -> bool:  # type: ignore[override]
        return self._order.value.index(self.value) < self._order.value.index(other.value)

    def __le__(self, other: "AgentTier") -> bool:  # type: ignore[override]
        return self == other or self < other


class Domain(str, Enum):
    RED = "red"
    BLUE = "blue"
    REPORTER = "reporter"
    PURPLE = "purple"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AgentTask(BaseModel):
    """Immutable task descriptor passed between Orchestrator → WorkerPool → Agent."""
    task_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    domain: Domain
    tier: AgentTier
    agent_name: str
    payload: dict[str, Any]
    brain_tier: str = "local"
    stealth: bool = False
    proxy_port: int | None = None
    apt_profile: str | None = None
    created_at: str = Field(default_factory=_now_iso)
    retry_count: int = 0

    model_config = {"frozen": True}   # Tasks are immutable — retries create new instances


class AgentResult(BaseModel):
    """Structured output from a completed or failed agent run."""
    task_id: str
    agent_name: str
    status: str          # "success" | "error" | "skipped"
    output: dict[str, Any]
    completed_at: str = Field(default_factory=_now_iso)
    tokens_used: int = 0
    error_detail: str | None = None


class RoutingDecision(BaseModel):
    """Output of the Orchestrator's classifier — the routing manifest."""
    domain: Domain
    confidence: float
    reason: str
    tasks: list[AgentTask] = []


class ErrorPayload(BaseModel):
    """Structured error record written to state/audit.log by error_hook."""
    task_id: str
    agent_name: str
    error: str
    retry_count: int
    will_retry: bool
