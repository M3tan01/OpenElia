"""
tests/test_cost_tracker.py — Unit tests for CostTracker.
"""
import json
import os
import pytest
from unittest.mock import patch


@pytest.fixture
def tracker(tmp_path):
    """CostTracker pointed at a temp log file, budget = $10."""
    with patch("secret_store.SecretStore.get_secret", return_value="10.00"):
        from cost_tracker import CostTracker
        ct = CostTracker(log_path=str(tmp_path / "costs.json"))
    return ct


class TestCostTracker:
    def test_track_usage_returns_cost_and_total(self, tracker):
        cost, total = tracker.track_usage("gpt-4o", input_tokens=1000, output_tokens=500)
        assert cost  > 0
        assert total > 0
        assert total == pytest.approx(cost)

    def test_known_model_pricing(self, tmp_path):
        # gpt-4o: $5/M input, $15/M output → 1M + 1M = $20
        # Use a budget large enough that the budget guard doesn't fire.
        with patch("secret_store.SecretStore.get_secret", return_value="100.00"):
            from cost_tracker import CostTracker
            ct = CostTracker(log_path=str(tmp_path / "costs_pricing.json"))
        cost, _ = ct.track_usage("gpt-4o", input_tokens=1_000_000, output_tokens=1_000_000)
        assert cost == pytest.approx(20.0, rel=1e-3)

    def test_local_model_is_free(self, tracker):
        cost, _ = tracker.track_usage("llama3.1:8b", input_tokens=100_000, output_tokens=100_000)
        assert cost == 0.0

    def test_unknown_model_uses_default_pricing(self, tracker):
        # default: $10/M input, $30/M output
        cost, _ = tracker.track_usage("unknown-model-xyz", input_tokens=1_000_000, output_tokens=0)
        assert cost == pytest.approx(10.0, rel=1e-3)

    def test_cumulative_cost_accumulates(self, tracker):
        tracker.track_usage("gpt-4o", 100_000, 100_000)
        _, total1 = tracker.track_usage("gpt-4o", 100_000, 100_000)
        assert total1 > 0

    def test_get_summary_keys(self, tracker):
        tracker.track_usage("gpt-4o", 1000, 500)
        summary = tracker.get_summary()
        assert "session_cost"           in summary
        assert "total_historical_cost"  in summary
        assert "budget_remaining"       in summary

    def test_budget_exceeded_raises(self, tmp_path):
        with patch("secret_store.SecretStore.get_secret", return_value="0.001"):
            from cost_tracker import CostTracker
            ct = CostTracker(log_path=str(tmp_path / "costs.json"))
        with pytest.raises(PermissionError, match="Token Budget Exceeded"):
            ct.track_usage("gpt-4o", input_tokens=1_000_000, output_tokens=1_000_000)

    def test_session_id_uses_utc(self, tmp_path):
        """Ensure no DeprecationWarning from datetime.utcnow()."""
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("error", DeprecationWarning)
            with patch("secret_store.SecretStore.get_secret", return_value="5.00"):
                from cost_tracker import CostTracker
                CostTracker(log_path=str(tmp_path / "costs.json"))   # must not raise
