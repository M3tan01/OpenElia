#!/usr/bin/env python3
"""
agents/blue/defender_ana.py — Tier 2 analysis agent.

Model: Opus 4.6 with adaptive thinking
Event-driven: only invoked when Tier 1 produces a high-confidence alert.
Responsible for triage, root-cause determination, and scope assessment.
"""

import ipaddress
import json
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from agents.base_agent import BaseAgent, _DEFAULT_MODEL
from core.mcp_gateway import MCPGateway
from core.schemas import AgentTier
from state_manager import StateManager


_BASE_PROMPT = """You are defender_ana, the Tier 2 analysis agent of OpenElia.

You are only invoked when Tier 1 (defender_mon or defender_hunt) has generated a
high-confidence alert. Your job is to determine: Is this a true positive? What is the
scope? What immediate action is required?

## Input context

You will receive:
1. The Tier 1 alert that triggered your invocation
2. Access to the full engagement state (read_state)
3. Raw log snippets surrounding the alert

## Analysis workflow (NIST SP 800-61 §3.2)

1. **Read the alert** — understand the MITRE TTP, the affected host/user, and the timestamp
2. **Read state** — check if this matches any active red team phase (for authorized activity)
3. **TP/FP determination**:
   - Is this within the authorized engagement scope?
   - Does the indicator match known-good baseline?
   - Do multiple independent signals corroborate it?
4. **Scope assessment** — how many hosts/users are affected? Is lateral movement indicated?
5. **Enrich IOCs** — call enrich_ioc on any suspicious external IP, file hash, or domain
   in the alert. IP reputation / malware verdicts sharpen the TP/FP call before you commit.
6. **Severity assignment** — P1/P2/P3/P4 using NIST severity criteria
7. **Write analysis** — use write_analysis to persist your determination
8. **Escalation decision** — if P1 or P2, set escalate=true to trigger defender_res

## Hard rules

- Never dismiss a high-severity alert without documented reasoning
- If LSASS access is detected, treat as P1 immediately — do not wait for further evidence
- If VSS deletion is detected, treat as P1 immediately (ransomware precursor)
- Document your TP/FP reasoning in the analysis output
"""


class DefenderAna(BaseAgent):
    AGENT_NAME = "defender_ana"
    MODEL = _DEFAULT_MODEL
    MAX_TOKENS = 8096

    def __init__(
        self,
        state_manager: StateManager,
        brain_tier: str = "local",
        tier: AgentTier | None = None,
    ):
        super().__init__(state_manager, brain_tier=brain_tier, tier=tier)

    def _get_ana_tools(self) -> list[dict]:
        return [
            {
                "name": "write_analysis",
                "description": (
                    "Write the triage analysis result for a Tier 1 alert. "
                    "This persists the determination and triggers escalation if needed."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "alert_id": {
                            "type": "string",
                            "description": "The alert ID from the blue_alerts list",
                        },
                        "verdict": {
                            "type": "string",
                            "enum": ["true_positive", "false_positive", "needs_investigation"],
                        },
                        "severity": {
                            "type": "string",
                            "enum": ["P1", "P2", "P3", "P4"],
                            "description": "P1=Critical/immediate, P2=High/4h, P3=Medium/24h, P4=Low",
                        },
                        "affected_hosts": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "affected_users": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "reasoning": {
                            "type": "string",
                            "description": "REQUIRED. Explain why this is a TP or FP, e.g. '42 failed logins in 60s from single IP matches password spray pattern'.",
                        },
                        "recommended_action": {
                            "type": "string",
                            "description": "Immediate next step for defender_res",
                        },
                        "escalate": {
                            "type": "boolean",
                            "description": "True if defender_res should be invoked",
                        },
                    },
                    "required": ["alert_id", "verdict", "severity", "reasoning", "escalate"],
                },
            },
            {
                "name": "enrich_ioc",
                "description": (
                    "Enrich a single indicator of compromise against threat-intel sources. "
                    "An IP address is checked against AbuseIPDB (abuse confidence score); a "
                    "file hash or domain is checked against VirusTotal (malware verdict). "
                    "Use to corroborate or dismiss an alert before writing the analysis."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ioc": {
                            "type": "string",
                            "description": "An IP address, SHA256 hash, or domain to look up.",
                        },
                    },
                    "required": ["ioc"],
                },
            },
        ]

    def _execute_ana_tool(self, tool_name: str, tool_input: dict) -> str:
        if tool_name == "write_analysis":
            # Capture fields BEFORE persisting: add_blue_analysis .pop()s alert_id,
            # verdict, severity and escalate off the dict, so reading them afterward
            # yields None (and KeyErrors the summary string below).
            alert_id = tool_input.get("alert_id")
            verdict = tool_input.get("verdict")
            severity = tool_input.get("severity")
            escalate = tool_input.get("escalate")

            # Tier 5 Reliability: Use formal SQL method instead of raw dict manipulation
            self.state.add_blue_analysis(tool_input)

            # Mark the source alert as escalated if needed
            if escalate:
                self.state.mark_alert_escalated(alert_id)

            escalation_note = " [ESCALATING to defender_res]" if escalate else ""
            return (
                f"Analysis written: {verdict} [{severity}] "
                f"for alert {alert_id}{escalation_note}"
            )

        if tool_name == "enrich_ioc":
            ioc = tool_input.get("ioc", "").strip()
            if not ioc:
                return "enrich_ioc error: empty ioc."
            # Route by IOC type: an IP goes to AbuseIPDB (reputation); a hash or
            # domain goes to VirusTotal (malware verdict). ip_address() raises
            # ValueError for anything that isn't a literal IPv4/IPv6 address.
            try:
                ipaddress.ip_address(ioc)
                server_tool, args = "query_abuseipdb", {"ip": ioc}
            except ValueError:
                server_tool, args = "query_virustotal", {"resource": ioc}
            # MCPGateway.query is async; return the coroutine so _run_tool_loop can
            # await it. Tier is bound from this agent's real tier (set by the
            # Orchestrator) — the gateway enforces the RECON/ANALYSIS gate against it.
            gateway = MCPGateway(caller_tier=self.tier)
            return gateway.query("threat_intel", server_tool, args)

        return self._execute_tool(tool_name, tool_input)

    async def _call_with_ana_tools(self, system: str, messages: list[dict]) -> str:
        tools = self._get_standard_tools() + self._get_ana_tools()
        return await self._run_tool_loop(system, messages, tools, self._execute_ana_tool)

    async def run(self, task: str) -> None:
        """
        task should include the serialized Tier 1 alert and any raw log context.
        Typically called by defender_os when Tier 1 generates high-confidence alerts.
        """
        print(f"[defender_ana] Tier 2 analysis triggered — {task[:120]}")

        system = self._build_system_prompt(_BASE_PROMPT)
        messages = [{"role": "user", "content": task}]

        result = await self._call_with_ana_tools(system, messages)
        print(f"[defender_ana] Analysis complete.\n{result[:500]}")
        return result
