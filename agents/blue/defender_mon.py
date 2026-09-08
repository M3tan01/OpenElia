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
import time
from collections import deque
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from state_manager import StateManager

# Default sliding window duration in seconds (1 hour).
# Override per rule by adding "window_seconds" to the rule dict.
_DEFAULT_WINDOW_SECONDS = 3600


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
        "description": "LSASS memory access — credential dumping attempt (Sysmon EventCode 10)",
        "patterns": [r"TargetImage.*lsass\.exe", r"EventCode=10"],
        "threshold": 1,
        "severity": "high",
        "mitre": "T1003.001",
    },
    "T1003_MIMIKATZ_CMD": {
        "description": "Mimikatz credential-dumping command detected in logs",
        "patterns": [
            r"sekurlsa::|lsadump::|kerberos::|dpapi::|"
            r"procdump.*lsass|lsass.*dump|LSASS.*dump|dump.*lsass",
        ],
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

    def __init__(self, state_manager: StateManager, brain_tier: str = "local", tier=None):
        self.state = state_manager
        # DefenderMon is a NON-LLM agent — brain_tier/tier are accepted only so it
        # conforms to the uniform agent interface the Orchestrator's _run_agent
        # dispatch uses (construct with brain_tier=, then await .run()). They are
        # intentionally unused by the regex/threshold logic.
        self.brain_tier = brain_tier
        self.tier = tier
        # Each key maps to a deque of float timestamps (epoch seconds).
        # Only timestamps within the rule's window are counted toward the threshold.
        self._counters: dict[str, deque] = {}

    async def run(self, task: str) -> list[dict]:
        """Uniform entry point for the Orchestrator dispatch path.

        DefenderMon does no LLM work — this simply runs the synchronous regex/
        threshold analysis over the supplied text and returns any alerts that
        fired (also persisted to state via analyze()).
        """
        text = task or ""
        alerts = self.analyze(text)
        # Honest signal: a standalone blue run from the dashboard is handed the
        # task *description*, not logs. DefenderMon only detects on log tokens, so
        # with none present the empty result is correct — not a failure. Say so,
        # rather than silently returning [] and looking broken.
        if not alerts and not self._has_log_tokens(text):
            print(
                "[defender_mon] 0 alerts — no log telemetry to analyze. This agent "
                "scans log text (EventCodes, process/beacon/LSASS data); the task "
                "description alone contains none. Supply real log input (Sysmon/EVTX, "
                "Zeek/RITA, EDR telemetry) for the detectors to fire. NOTE: a purple "
                "engagement does NOT change this — the orchestrator hands blue agents "
                "the task string, not red's output, so blue still sees no logs."
            )
        return alerts

    # Compact anchor tokens drawn from SIGMA_RULES — enough to tell "this is log
    # data" from "this is a task sentence" without duplicating every pattern.
    _LOG_TOKEN_RE = re.compile(
        r"EventCode=|Logon_Type=|beacon_score|lsass|vssadmin|ParentImage|"
        r"NewProcessName|TargetObject|TargetImage|sekurlsa::|lsadump::",
        re.IGNORECASE,
    )

    def _has_log_tokens(self, text: str) -> bool:
        """True if the text contains anything the SIGMA rules could match on."""
        return bool(self._LOG_TOKEN_RE.search(text))

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
                    mitre_ttp=rule["mitre"],
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

        # Threshold > 1: count occurrences within the sliding time window
        if threshold > 1:
            window_key = rule.get("window_key", f"_count_{patterns[0][:20]}")
            window_secs = rule.get("window_seconds", _DEFAULT_WINDOW_SECONDS)
            now = time.monotonic()
            cutoff = now - window_secs

            if window_key not in self._counters:
                self._counters[window_key] = deque()

            bucket = self._counters[window_key]

            # Add one timestamp per match of the primary pattern in this log batch
            match_count = len(re.findall(patterns[0], log_text, re.IGNORECASE))
            for _ in range(match_count):
                bucket.append(now)

            # Evict timestamps older than the window
            while bucket and bucket[0] < cutoff:
                bucket.popleft()

            return len(bucket) >= threshold

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
        """Clear all sliding-window buckets (e.g. at engagement start)."""
        self._counters.clear()

    def get_unescalated_high_alerts(self) -> list[dict]:
        """Return high-severity alerts not yet escalated to Tier 2."""
        state = self.state.read()
        return [
            a for a in state.get("blue_alerts", [])
            if a.get("severity") == "high" and not a.get("escalated", False)
        ]
