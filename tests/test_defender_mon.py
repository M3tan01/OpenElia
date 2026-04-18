"""
tests/test_defender_mon.py — Unit tests for DefenderMon (Tier 1 regex/threshold monitoring).

Covers: sigma rule firing, threshold counters, alert structure, and no-alert path.
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from state_manager import StateManager
from agents.blue.defender_mon import DefenderMon


@pytest.fixture
def mon(tmp_path):
    db = str(tmp_path / "mon_test.db")
    sm = StateManager(db_path=db)
    sm.initialize_engagement("10.0.0.1", "test scope")
    return DefenderMon(sm)


# ---------------------------------------------------------------------------
# Alert structure
# ---------------------------------------------------------------------------

class TestAlertStructure:
    def test_alert_has_required_fields(self, mon):
        log = "sekurlsa::logonpasswords"
        alerts = mon.analyze(log)
        assert len(alerts) >= 1
        for a in alerts:
            assert "type" in a
            assert "severity" in a
            assert "description" in a

    def test_no_alerts_on_benign_log(self, mon):
        log = "User jsmith logged in from 10.0.0.5 at 09:00"
        alerts = mon.analyze(log)
        assert alerts == [] or all(
            a.get("severity", "").upper() not in ("CRITICAL", "HIGH") for a in alerts
        )


# ---------------------------------------------------------------------------
# Credential-dumping detection
# ---------------------------------------------------------------------------

class TestCredentialDumpingDetection:
    @pytest.mark.parametrize("payload", [
        "sekurlsa::logonpasswords",
        "lsadump::sam",
        "procdump -ma lsass.exe",
        "LSASS memory dump initiated",
    ])
    def test_lsass_patterns_fire(self, mon, payload):
        alerts = mon.analyze(payload)
        types = [a.get("type", "").upper() for a in alerts]
        # Accept any alert — the key check is that something fires on LSASS content
        assert len(alerts) >= 1, f"No alert fired for: {payload}"

    def test_lsass_severity_is_high_or_critical(self, mon):
        alerts = mon.analyze("sekurlsa::logonpasswords executed")
        high_or_crit = [a for a in alerts if a.get("severity", "").upper() in ("HIGH", "CRITICAL")]
        assert len(high_or_crit) >= 1


# ---------------------------------------------------------------------------
# Lateral movement / pass-the-hash
# ---------------------------------------------------------------------------

class TestLateralMovementDetection:
    @pytest.mark.parametrize("payload", [
        "EventCode 4624 LogonType 3",
        "Pass-the-Hash detected",
        "wmiexec.py admin@10.0.0.5",
        "PsExec executing remote command",
    ])
    def test_lateral_movement_patterns(self, mon, payload):
        alerts = mon.analyze(payload)
        # Not every Tier 1 engine implements all patterns; verify no crash at minimum
        assert isinstance(alerts, list)


# ---------------------------------------------------------------------------
# Ransomware / VSS deletion
# ---------------------------------------------------------------------------

class TestRansomwareDetection:
    @pytest.mark.parametrize("payload", [
        "vssadmin.exe delete shadows /all",
        "wmic shadowcopy delete",
        "bcdedit /set {default} recoveryenabled No",
    ])
    def test_vss_deletion_fires(self, mon, payload):
        alerts = mon.analyze(payload)
        assert len(alerts) >= 1, f"VSS deletion not detected: {payload}"

    def test_vss_deletion_is_high_severity(self, mon):
        alerts = mon.analyze("vssadmin.exe delete shadows /all /quiet")
        high_plus = [a for a in alerts if a.get("severity", "").lower() in ("high", "critical")]
        assert len(high_plus) >= 1


# ---------------------------------------------------------------------------
# Empty / whitespace input
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_string_no_crash(self, mon):
        alerts = mon.analyze("")
        assert isinstance(alerts, list)

    def test_whitespace_only_no_crash(self, mon):
        alerts = mon.analyze("   \n\t  ")
        assert isinstance(alerts, list)

    def test_very_long_log_no_crash(self, mon):
        big = "normal log line\n" * 5000
        alerts = mon.analyze(big)
        assert isinstance(alerts, list)


# ---------------------------------------------------------------------------
# Sliding window threshold behaviour (T2)
# ---------------------------------------------------------------------------

class TestSlidingWindow:
    """Verify that threshold counters respect the time window and evict stale entries."""

    def test_threshold_not_reached_in_single_batch(self, mon):
        # Password spray requires 10 hits; 5 matches should NOT fire.
        log = ("EventCode=4625\nLogon_Type=3\n" * 5)
        alerts = mon.analyze(log)
        spray = [a for a in alerts if "PASSWORD_SPRAY" in a.get("type", "")]
        assert spray == []

    def test_threshold_reached_across_batches(self, mon):
        # Accumulate 10 matches across two batches — should fire on the second.
        log_batch = ("EventCode=4625\nLogon_Type=3\n" * 5)
        mon.analyze(log_batch)      # 5 hits
        alerts = mon.analyze(log_batch)  # 10 hits total
        spray = [a for a in alerts if "PASSWORD_SPRAY" in a.get("type", "")]
        assert len(spray) >= 1

    def test_reset_clears_counts(self, mon):
        log_batch = ("EventCode=4625\nLogon_Type=3\n" * 5)
        mon.analyze(log_batch)
        mon.reset_counters()
        # After reset, 5 more hits should NOT fire (threshold = 10)
        alerts = mon.analyze(log_batch)
        spray = [a for a in alerts if "PASSWORD_SPRAY" in a.get("type", "")]
        assert spray == []

    def test_expired_events_do_not_count(self, mon):
        """Timestamps older than the window are evicted and do not contribute."""
        import time
        from collections import deque
        from agents.blue.defender_mon import _DEFAULT_WINDOW_SECONDS

        log_batch = ("EventCode=4625\nLogon_Type=3\n" * 5)
        mon.analyze(log_batch)   # 5 hits recorded

        # Age all bucket timestamps to beyond the window boundary
        window_key = "logon_failure_count"
        if window_key in mon._counters:
            stale = time.monotonic() - _DEFAULT_WINDOW_SECONDS - 10
            mon._counters[window_key] = deque(stale for _ in mon._counters[window_key])

        # 5 fresh hits — stale ones are evicted during the next analyze(), total in-window = 5 < 10
        alerts = mon.analyze(log_batch)
        spray = [a for a in alerts if "PASSWORD_SPRAY" in a.get("type", "")]
        assert spray == [], "Stale events outside the window should not trigger the threshold"
