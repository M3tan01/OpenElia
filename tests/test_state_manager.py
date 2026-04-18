"""
tests/test_state_manager.py — Unit tests for StateManager.

Covers: engagement lifecycle, phase validation, add_response_action return value,
get_escalated_analysis_count, and the PHASE_ORDER whitelist guard.
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from state_manager import StateManager, PHASE_ORDER


@pytest.fixture
def sm(tmp_path):
    """StateManager backed by a temporary SQLite file, with one active engagement."""
    db = str(tmp_path / "test_engagement.db")
    manager = StateManager(db_path=db)
    manager.initialize_engagement("10.0.0.1", "test scope")
    return manager


# ---------------------------------------------------------------------------
# Engagement creation
# ---------------------------------------------------------------------------

class TestEngagementLifecycle:
    def test_initialize_engagement_returns_dict(self, tmp_path):
        db = str(tmp_path / "e.db")
        manager = StateManager(db_path=db)
        result = manager.initialize_engagement("10.0.0.1", "test scope")
        assert isinstance(result, dict)

    def test_active_engagement_set_after_init(self, tmp_path):
        db = str(tmp_path / "e2.db")
        manager = StateManager(db_path=db)
        manager.initialize_engagement("10.0.0.2", "scope")
        assert manager.active_engagement_id is not None
        assert manager.active_engagement_id.startswith("ENG-")

    def test_read_returns_engagement(self, sm):
        state = sm.read()
        assert isinstance(state, dict)
        assert "target" in state or "current_phase" in state

    def test_is_locked_default_false(self, sm):
        assert sm.is_locked() is False

    def test_lock_unlock(self, sm):
        sm.set_locked(True)
        assert sm.is_locked() is True
        sm.set_locked(False)
        assert sm.is_locked() is False


# ---------------------------------------------------------------------------
# Phase validation (C7)
# ---------------------------------------------------------------------------

class TestPhaseValidation:
    def test_phase_order_constant(self):
        assert PHASE_ORDER == ["recon", "vuln", "exploit", "lateral", "exfil"]

    def test_write_agent_result_valid_phase(self, sm):
        sm.write_agent_result("recon", "nmap_output", {"hosts": ["10.0.0.5"]})
        data = sm.get_phase_data("recon")
        assert data.get("nmap_output") == {"hosts": ["10.0.0.5"]}

    def test_write_agent_result_invalid_phase_raises(self, sm):
        with pytest.raises(ValueError, match="Invalid phase"):
            sm.write_agent_result("pwned", "output", "data")

    @pytest.mark.parametrize("phase", PHASE_ORDER)
    def test_write_agent_result_all_valid_phases(self, tmp_path, phase):
        db = str(tmp_path / f"e_{phase}.db")
        manager = StateManager(db_path=db)
        manager.initialize_engagement("10.0.0.9", "scope")
        manager.write_agent_result(phase, "test_key", "test_value")
        assert manager.get_phase_data(phase).get("test_key") == "test_value"


# ---------------------------------------------------------------------------
# add_response_action returns row ID (C7)
# ---------------------------------------------------------------------------

class TestAddResponseAction:
    def test_returns_dict_with_id(self, sm):
        result = sm.add_response_action({
            "action_type": "block_ip",
            "target": "1.2.3.4",
            "command": "iptables -I INPUT -s 1.2.3.4 -j DROP",
            "rationale": "Malicious scanner",
            "requires_approval": False,
        })
        assert isinstance(result, dict)
        assert "id" in result
        assert isinstance(result["id"], int)
        assert result["id"] >= 1

    def test_sequential_ids_increment(self, sm):
        r1 = sm.add_response_action({"action_type": "block_ip", "target": "1.1.1.1",
                                      "command": "cmd1", "rationale": "r1"})
        r2 = sm.add_response_action({"action_type": "block_ip", "target": "2.2.2.2",
                                      "command": "cmd2", "rationale": "r2"})
        assert r2["id"] > r1["id"]


# ---------------------------------------------------------------------------
# get_escalated_analysis_count (H4 gate)
# ---------------------------------------------------------------------------

class TestEscalatedAnalysisCount:
    def test_zero_when_no_analyses(self, sm):
        assert sm.get_escalated_analysis_count() == 0

    def test_counts_escalated_only(self, sm):
        sm.add_blue_analysis({"verdict": "TP", "severity": "HIGH",
                               "reasoning": "bad", "escalate": True})
        sm.add_blue_analysis({"verdict": "FP", "severity": "LOW",
                               "reasoning": "benign", "escalate": False})
        assert sm.get_escalated_analysis_count() == 1

    def test_counts_multiple_escalated(self, sm):
        for i in range(3):
            sm.add_blue_analysis({"verdict": "TP", "severity": "CRITICAL",
                                   "reasoning": f"threat {i}", "escalate": True})
        assert sm.get_escalated_analysis_count() == 3
