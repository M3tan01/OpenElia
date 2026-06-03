"""
core/prioritizer.py — pheromone-style task priority for the tier worker pool.

OpenElia already computes a per-action risk signal (success probability + detection
risk) in risk_calculator.RiskCalculator, but the scheduler ignored it and ran tasks
FIFO. This turns that signal into a priority score so the worker pool pursues
high-success / low-detection work first, with a recency *decay* (pheromone half-life)
so stale work sinks.

The score is used to set AgentTask.priority at enqueue time. Decay is computed from
the task's age (created_at → now); at enqueue age≈0 so decay≈1, but the term is
correct and becomes meaningful when tasks are re-scored or sit queued — and it keeps
the function honest as the stepping-stone toward fuller stigmergic scheduling.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

# Lower detection risk → higher weight (we prefer quieter actions, esp. under stealth).
_DETECTION_WEIGHT = {"low": 1.0, "medium": 0.7, "high": 0.4}

_DEFAULT_HALF_LIFE_S = 1800.0  # 30 min; override via OPENELIA_PRIORITY_HALFLIFE_S


def _half_life_s() -> float:
    try:
        v = float(os.getenv("OPENELIA_PRIORITY_HALFLIFE_S", _DEFAULT_HALF_LIFE_S))
        return v if v > 0 else _DEFAULT_HALF_LIFE_S
    except (TypeError, ValueError):
        return _DEFAULT_HALF_LIFE_S


def _parse_iso(ts: str) -> datetime:
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def decay_factor(created_at: str | None, now: datetime | None = None,
                 half_life_s: float | None = None) -> float:
    """Pheromone decay in (0, 1]: 0.5 ** (age / half_life). age clamped ≥ 0.

    created_at None (or unparseable) → 1.0 (no decay) rather than crashing."""
    if not created_at:
        return 1.0
    now = now or datetime.now(timezone.utc)
    hl = half_life_s if (half_life_s and half_life_s > 0) else _half_life_s()
    try:
        age = (now - _parse_iso(created_at)).total_seconds()
    except (ValueError, TypeError):
        return 1.0
    age = max(0.0, age)
    return 0.5 ** (age / hl)


def score(
    success_probability: int,
    detection_risk: str,
    created_at: str | None = None,
    now: datetime | None = None,
    graph_signal: float = 0.0,
    half_life_s: float | None = None,
) -> float:
    """Priority for a task. Higher = scheduled sooner within its tier.

    success_probability: 0–100 (from RiskCalculator). detection_risk: low/medium/high.
    graph_signal: optional additive boost in [0, 1] from attack-graph context (Task D).
    """
    base = max(0, min(100, success_probability)) / 100.0
    weight = _DETECTION_WEIGHT.get((detection_risk or "medium").lower(), 0.7)
    decay = decay_factor(created_at, now=now, half_life_s=half_life_s)
    return base * weight * decay + max(0.0, graph_signal)
