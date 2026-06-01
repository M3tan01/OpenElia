"""
core/loop_guard.py — Per-run tool-loop guardrail for OpenElia agents.

Closes a gap in ``BaseAgent._run_tool_loop`` (a ``while True`` loop whose only
ceiling is the reflective-retry counter, which increments on *error* results
only). A loop of *successful* identical tool calls — e.g. ``read_state`` →
``read_state`` → … — is otherwise unbounded.

Design (ported from NousResearch/hermes-agent ``tool_guardrails.py``):
  - Side-effect free: the guard tracks per-run observations and returns a
    decision. The caller decides whether a decision becomes a warning (steer the
    model) or an enforced halt (break the loop). The guard never touches external
    state, logs, or I/O.
  - One ``LoopGuard`` instance per ``_run_tool_loop`` call; discarded after.

Three failure modes detected:
  1. Absolute turn ceiling      — total observed tool calls exceeds a hard cap.
  2. Repeated identical call     — same (tool, args) seen N times consecutively.
  3. Idempotent-result spinning  — an idempotent tool returns the same result
                                    N times consecutively.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Literal

# Read-only / idempotent tools: calling them repeatedly with the same args is
# expected to return the same result, so a repeating result is a strong loop
# signal. Conservative seed — extend via LoopGuardConfig, not by editing here.
DEFAULT_IDEMPOTENT_TOOLS: frozenset[str] = frozenset(
    {
        "read_state",
        "record_service",
        "query_threat_intel",
        "search_memory",
        "web_search",
    }
)

Action = Literal["ok", "warn", "block"]


@dataclass(frozen=True)
class LoopGuardConfig:
    """Immutable guardrail thresholds. Built from ModelManager config."""

    enabled: bool = True
    max_total_turns: int = 25
    max_same_call: int = 3
    max_idempotent_repeats: int = 2
    idempotent_tools: frozenset[str] = DEFAULT_IDEMPOTENT_TOOLS

    @classmethod
    def from_mapping(cls, data: dict[str, Any] | None) -> "LoopGuardConfig":
        """Build from a config dict, falling back to defaults for missing keys."""
        data = data or {}
        tools = data.get("idempotent_tools")
        return cls(
            enabled=bool(data.get("enabled", True)),
            max_total_turns=int(data.get("max_total_turns", 25)),
            max_same_call=int(data.get("max_same_call", 3)),
            max_idempotent_repeats=int(data.get("max_idempotent_repeats", 2)),
            idempotent_tools=(
                frozenset(tools) if tools is not None else DEFAULT_IDEMPOTENT_TOOLS
            ),
        )


@dataclass(frozen=True)
class LoopDecision:
    """Result of a single observation. ``action`` is the caller's cue."""

    action: Action
    rationale: str

    @property
    def is_block(self) -> bool:
        return self.action == "block"

    @property
    def is_warn(self) -> bool:
        return self.action == "warn"


_OK = LoopDecision("ok", "")


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _args_key(tool_name: str, args: dict[str, Any]) -> str:
    """Stable identity for a (tool, args) pair. Non-serializable args degrade to str."""
    canonical = json.dumps(args, sort_keys=True, default=str)
    return f"{tool_name}::{_hash(canonical)}"


@dataclass
class LoopGuard:
    """
    Stateful per-run controller. Internal counters are the guard's own state
    only — ``observe`` never mutates its arguments or any external object.
    """

    cfg: LoopGuardConfig = field(default_factory=LoopGuardConfig)
    _turns: int = 0
    _last_call_key: str | None = None
    _same_call_count: int = 0
    # tool_name -> (last_result_hash, consecutive_count)
    _idem_state: dict[str, tuple[str, int]] = field(default_factory=dict)

    def observe(self, tool_name: str, args: dict[str, Any], result: str) -> LoopDecision:
        """Record one executed tool call and return a loop decision."""
        if not self.cfg.enabled:
            return _OK

        self._turns += 1

        # 1. Absolute turn ceiling — hard cap regardless of call shape.
        if self._turns > self.cfg.max_total_turns:
            return LoopDecision(
                "block",
                f"tool-loop turn ceiling exceeded "
                f"({self._turns} > {self.cfg.max_total_turns})",
            )

        # 2. Repeated identical (tool, args) call.
        call_key = _args_key(tool_name, args)
        if call_key == self._last_call_key:
            self._same_call_count += 1
        else:
            self._last_call_key = call_key
            self._same_call_count = 1

        same_decision = self._evaluate_same_call(tool_name)
        if same_decision is not None:
            return same_decision

        # 3. Idempotent-result spinning.
        idem_decision = self._evaluate_idempotent(tool_name, result)
        if idem_decision is not None:
            return idem_decision

        return _OK

    def _evaluate_same_call(self, tool_name: str) -> LoopDecision | None:
        threshold = self.cfg.max_same_call
        if self._same_call_count >= threshold:
            return LoopDecision(
                "block",
                f"identical call to '{tool_name}' repeated "
                f"{self._same_call_count} times (limit {threshold})",
            )
        # Warn one step before blocking, but never on the first occurrence.
        if self._same_call_count >= 2 and self._same_call_count == threshold - 1:
            return LoopDecision(
                "warn",
                f"identical call to '{tool_name}' repeating "
                f"({self._same_call_count}/{threshold}) — change approach",
            )
        return None

    def _evaluate_idempotent(self, tool_name: str, result: str) -> LoopDecision | None:
        if tool_name not in self.cfg.idempotent_tools:
            return None

        result_hash = _hash(result)
        last_hash, count = self._idem_state.get(tool_name, (None, 0))
        count = count + 1 if result_hash == last_hash else 1
        self._idem_state[tool_name] = (result_hash, count)

        threshold = self.cfg.max_idempotent_repeats
        if count >= threshold:
            return LoopDecision(
                "block",
                f"idempotent tool '{tool_name}' returned identical result "
                f"{count} times (limit {threshold})",
            )
        return None
