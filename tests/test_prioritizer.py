"""Tests for core.prioritizer — risk → priority score with pheromone decay."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from core import prioritizer


def test_score_monotonic_in_success_probability():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    lo = prioritizer.score(40, "medium", now=now)
    hi = prioritizer.score(90, "medium", now=now)
    assert hi > lo


def test_lower_detection_scores_higher():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    quiet = prioritizer.score(80, "low", now=now)
    loud = prioritizer.score(80, "high", now=now)
    assert quiet > loud


def test_decay_lowers_older_tasks():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    fresh_at = now.isoformat()
    old_at = (now - timedelta(hours=2)).isoformat()
    fresh = prioritizer.score(80, "medium", created_at=fresh_at, now=now, half_life_s=1800)
    old = prioritizer.score(80, "medium", created_at=old_at, now=now, half_life_s=1800)
    assert old < fresh


def test_decay_factor_half_life():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    one_hl_ago = (now - timedelta(seconds=1800)).isoformat()
    f = prioritizer.decay_factor(one_hl_ago, now=now, half_life_s=1800)
    assert abs(f - 0.5) < 1e-9  # exactly one half-life → 0.5


def test_no_created_at_means_no_decay():
    assert prioritizer.decay_factor(None) == 1.0
    # score without created_at uses decay 1.0
    assert prioritizer.score(100, "low", created_at=None) == 1.0  # 1.0*1.0*1.0


def test_unparseable_timestamp_does_not_crash():
    assert prioritizer.decay_factor("not-a-date") == 1.0


def test_graph_signal_boost_is_additive():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    base = prioritizer.score(50, "medium", now=now)
    boosted = prioritizer.score(50, "medium", now=now, graph_signal=0.3)
    assert abs((boosted - base) - 0.3) < 1e-9


def test_success_probability_clamped():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    # out-of-range inputs must not blow past the [0,1] base band
    assert prioritizer.score(150, "low", now=now) <= 1.0 + 1e-9
    assert prioritizer.score(-20, "low", now=now) >= 0.0
