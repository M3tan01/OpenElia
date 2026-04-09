#!/usr/bin/env python3
"""
agents/blue/defender_mon.py — Tier 1 monitoring agent.

NO LLM — pure Python regex/threshold pattern matching.
Zero API calls. Fast, cheap, runs continuously.
Only emits high-confidence alerts to avoid LLM invocation noise.
"""

import re
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from state_manager import StateManager


# --------------------------------------------------------------------------- #
# Sigma-style rules as Python dicts
# Threshold: minimum matches before an alert fires
# --------------------------------------------------------------------------- #

SIGMA_RULES: dict[str, dict] = {
    "T1110.003_PASSWORD_SPRAY": {
        "description": "Password spray — many failed logons across different accounts",
        "patterns": [r"EventCode=4625", r"Logon_Type=3"],
        "threshold": 10,
        "window_key": "logon_failure_count",
        "severity": "high",
        "mitre": "T1110.003",
    },
    "T1490_VSS_DELETION": {
        "description": "Volume shadow copy deletion — ransomware precursor",
        "patterns": [r"vssadmin.*delete|wmic.*shadowcopy.*delete|bcdedit.*recoveryenabled.*no"],
        "threshold": 1,
        "severity": "high",
        "mitre": "T1490",
    },
    "T1071_C2_BEACON": {
        "description": "C2 beaconing — high RITA beacon score",
        "patterns": [r"beacon_score.*0\.[89]\d*|beacon_score.*1\.0"],
        "threshold": 1,
        "severity": "high",
        "mitre": "T1071.001",
    },
    "T1059_OFFICE_SHELL": {
        "description": "Office application spawning a shell process",
        "patterns": [
            r"ParentImage.*(WINWORD|EXCEL|OUTLOOK|POWERPNT)\.EXE",
            r"NewProcessName.*(cmd\.exe|powershell\.exe|wscript\.exe|mshta\.exe|certutil\.exe)",
        ],
        "threshold": 1,
        "severity": "high",
        "mitre": "T1059.001",
    },
    "T1003_LSASS_ACCESS": {
        "description": "LSASS memory access — credential dumping attempt",
        "patterns": [r"TargetImage.*lsass\.exe", r"EventCode=10"],
        "threshold": 1,
        "severity": "high",
        "mitre": "T1003.001",
    },
    "T1547_REGISTRY_RUN": {
        "description": "Registry Run key modification — persistence",
        "patterns": [
            r"TargetObject.*\\CurrentVersion\\Run",
            r"EventCode=13",
        ],
        "threshold": 1,
        "severity": "medium",
        "mitre": "T1547.001",
    },
    "T1021_LATERAL_RDP": {
        "description": "Unusual RDP logon — potential lateral movement",
        "patterns": [r"EventCode=4624", r"Logon_Type=10"],
        "threshold": 3,
        "window_key": "rdp_logon_count",
        "severity": "medium",
        "mitre": "T1021.001",
    },
    "T1566_PHISHING_CLICK": {
        "description": "User clicked link in email — potential phishing",
        "patterns": [r"OUTLOOK\.EXE.*http", r"EventCode=4688.*OUTLOOK"],
        "threshold": 1,
        "severity": "medium",
        "mitre": "T1566.002",
    },
}


class DefenderMon:
    """
    Tier 1 monitoring agent — no LLM, no API calls.

    Analyzes log text with regex and threshold counting.
    Returns a list of high-confidence alerts for Tier 2 escalation.
    """

    def __init__(self, state_manager: StateManager):
        self.state = state_manager
        self._counters: dict[str, int] = {}

    def analyze(self, log_text: str) -> list[dict]:
        """
        Analyze a block of log text against all SIGMA_RULES.

        Returns a list of alert dicts for rules that fire.
        Only returns alerts — no output for clean log batches.
        """
        alerts: list[dict] = []

        for rule_name, rule in SIGMA_RULES.items():
            if self._rule_matches(rule, log_text):
                alert = {
                    "type": rule_name,
                    "description": rule["description"],
                    "severity": rule["severity"],
                    "mitre": rule["mitre"],
                    "source": "defender_mon",
                    "matched_log_excerpt": self._excerpt(log_text, rule["patterns"]),
                }
                alerts.append(alert)

                # Write alert to state for Tier 2 pickup
                self.state.add_blue_alert(
                    alert_type=rule_name,
                    description=rule["description"],
                    severity=rule["severity"],
                    source="defender_mon",
                )

        return alerts

    def _rule_matches(self, rule: dict, log_text: str) -> bool:
        """All patterns in a rule must match (AND logic), then threshold is checked."""
        patterns = rule["patterns"]
        threshold = rule.get("threshold", 1)

        # Check all patterns match (case-insensitive)
        for pattern in patterns:
            if not re.search(pattern, log_text, re.IGNORECASE | re.DOTALL):
                return False

        # Threshold > 1: count occurrences of the first (primary) pattern
        if threshold > 1:
            window_key = rule.get("window_key", f"_count_{patterns[0][:20]}")
            count = len(re.findall(patterns[0], log_text, re.IGNORECASE))
            self._counters[window_key] = self._counters.get(window_key, 0) + count
            return self._counters[window_key] >= threshold

        return True

    def _excerpt(self, log_text: str, patterns: list[str], max_chars: int = 300) -> str:
        """Return the first matching line for context in the alert."""
        for pattern in patterns:
            match = re.search(pattern, log_text, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 50)
                end = min(len(log_text), match.end() + 100)
                return log_text[start:end][:max_chars]
        return log_text[:max_chars]

    def reset_counters(self) -> None:
        """Reset threshold counters — call at the start of each analysis window."""
        self._counters.clear()

    def get_unescalated_high_alerts(self) -> list[dict]:
        """Return high-severity alerts not yet escalated to Tier 2."""
        state = self.state.read()
        return [
            a for a in state.get("blue_alerts", [])
            if a.get("severity") == "high" and not a.get("escalated", False)
        ]
