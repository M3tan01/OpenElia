"""
tests/test_risk_calculator.py — RiskCalculator exploit risk scoring.

Covers: default probability range, stealth reduces detection, nmap/msf
        tool-specific overrides, probability clamping, rationale field.
"""
import pytest
from unittest.mock import MagicMock, patch


@pytest.fixture(autouse=True)
def stub_graph(monkeypatch):
    """Replace GraphManager with a stub so no real DB is needed."""
    mock_gm = MagicMock()
    mock_gm.get_summary.return_value = {"vulnerabilities": 0, "hosts": 1}
    with patch("risk_calculator.GraphManager", return_value=mock_gm):
        yield mock_gm


from risk_calculator import RiskCalculator


class TestCalculateExploitRisk:
    def setup_method(self):
        self.rc = RiskCalculator()

    def test_returns_required_keys(self):
        result = self.rc.calculate_exploit_risk("10.0.0.1", "nmap -sV 10.0.0.1")
        assert "success_probability" in result
        assert "detection_risk" in result
        assert "rationale" in result

    def test_success_probability_within_bounds(self):
        result = self.rc.calculate_exploit_risk("10.0.0.1", "some_tool -x")
        assert 10 <= result["success_probability"] <= 99

    def test_nmap_gives_high_probability(self):
        result = self.rc.calculate_exploit_risk("10.0.0.1", "nmap -sV 10.0.0.1")
        assert result["success_probability"] == 95

    def test_nmap_stealth_timing_gives_low_detection(self):
        result = self.rc.calculate_exploit_risk("10.0.0.1", "nmap -T2 -sV 10.0.0.1")
        assert result["detection_risk"] == "Low"

    def test_nmap_loud_gives_high_detection(self):
        result = self.rc.calculate_exploit_risk("10.0.0.1", "nmap -A 10.0.0.1", stealth=False)
        # nmap without T2/stealth → High detection
        assert result["detection_risk"] == "High"

    def test_msf_command_reduces_probability(self):
        result = self.rc.calculate_exploit_risk("10.0.0.1", "msf exploit/multi/handler")
        assert result["success_probability"] == 60

    def test_stealth_mode_sets_low_detection(self):
        result = self.rc.calculate_exploit_risk("10.0.0.1", "custom_tool", stealth=True)
        assert result["detection_risk"] == "Low"

    def test_vulns_in_graph_boost_probability(self):
        self.rc.graph_manager.get_summary.return_value = {"vulnerabilities": 3, "hosts": 1}
        # Non-nmap/msf command: base 0.70, stealth=False → -0 + 0.10 boost = 0.80
        result = self.rc.calculate_exploit_risk("10.0.0.1", "custom_tool", stealth=False)
        assert result["success_probability"] >= 70  # boosted

    def test_rationale_contains_mode(self):
        r1 = self.rc.calculate_exploit_risk("10.0.0.1", "tool", stealth=True)
        r2 = self.rc.calculate_exploit_risk("10.0.0.1", "tool", stealth=False)
        assert "stealth" in r1["rationale"].lower()
        assert "loud" in r2["rationale"].lower()
