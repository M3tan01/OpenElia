#!/usr/bin/env python3
"""
agents/blue/defender_res.py — Tier 2 response agent.

Model: Opus 4.6 with adaptive thinking
Event-driven: only invoked when defender_ana sets escalate=true
Responsible for containment actions, TheHive case creation, and IOC sharing.
"""

import json
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from agents.base_agent import BaseAgent, _DEFAULT_MODEL
from state_manager import StateManager


_BASE_PROMPT = """You are defender_res, the Tier 2 response agent of OpenElia.

You are only invoked after defender_ana has confirmed a true positive and set escalate=true.
Your job is to execute the appropriate containment and response actions per NIST SP 800-61 §3.3.

## Input context

You will receive:
1. The triage analysis from defender_ana (verdict, severity, affected hosts/users)
2. The original Tier 1 alert
3. Access to the full engagement state (read_state)

## Response workflow

1. **Read the analysis** — understand severity, affected scope, recommended action
2. **Select response playbook** based on alert type:
   - T1110.003 (Password Spray) → block source IP, force MFA, alert SOC
   - T1490 (VSS Deletion) → ISOLATE IMMEDIATELY, invoke PLAYBOOK-RANSOMWARE
   - T1071 (C2 Beacon) → soft isolate, memory acquisition, invoke PLAYBOOK-C2
   - T1059 (Office Shell) → isolate endpoint, invoke PLAYBOOK-PHISH
   - T1003 (LSASS) → isolate, rotate all credentials on host, invoke PLAYBOOK-MALWARE
3. **Document response actions** via write_response_action
4. **Create TheHive case** outline via write_thehive_case
5. **Mark incident resolved or escalated** based on scope

## Hard rules

- For P1: containment BEFORE investigation — do not delay isolation to gather more evidence
- For VSS deletion: ISOLATION IS MANDATORY — do not attempt live analysis first
- For LSASS access: rotate ALL credentials on the host, not just the victim's
- Every response action must be documented — audit trail is mandatory
- Do NOT share TLP:RED indicators externally (insider threat cases)
"""


class DefenderRes(BaseAgent):
    AGENT_NAME = "defender_res"
    MODEL = _DEFAULT_MODEL
    MAX_TOKENS = 8096

    def __init__(self, state_manager: StateManager, brain_tier: str = "local"):
        super().__init__(state_manager, brain_tier=brain_tier)

    def _get_res_tools(self) -> list[dict]:
        return [
            {
                "name": "write_response_action",
                "description": "Document a containment or response action taken.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "action_type": {
                            "type": "string",
                            "enum": [
                                "isolate_host",
                                "disable_account",
                                "block_ip",
                                "revoke_sessions",
                                "rotate_credentials",
                                "purge_email",
                                "block_domain",
                                "memory_acquisition",
                                "evidence_collection",
                                "escalate_to_manager",
                                "other",
                            ],
                        },
                        "target": {
                            "type": "string",
                            "description": "Host, account, IP, or domain this action targets",
                        },
                        "command": {
                            "type": "string",
                            "description": "REQUIRED. Exact command or procedure, e.g. 'iptables -I INPUT -s 10.0.0.77 -j DROP' or 'Disable-ADAccount -Identity jsmith'.",
                        },
                        "rationale": {"type": "string"},
                        "requires_approval": {
                            "type": "boolean",
                            "description": "True if this action needs IR Manager sign-off first",
                        },
                    },
                    "required": ["action_type", "target", "command", "rationale"],
                },
            },
            {
                "name": "write_thehive_case",
                "description": "Generate a TheHive case outline for this incident.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "severity": {"type": "string", "enum": ["P1", "P2", "P3", "P4"]},
                        "tlp": {"type": "string", "enum": ["WHITE", "GREEN", "AMBER", "RED"]},
                        "tags": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "description": {"type": "string"},
                        "observables": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "type": {"type": "string"},
                                    "value": {"type": "string"},
                                    "ioc": {"type": "boolean"},
                                },
                                "required": ["type", "value"],
                            },
                        },
                        "tasks": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                    },
                    "required": ["title", "severity", "tlp", "description"],
                },
            },
        ]

    def _execute_res_tool(self, tool_name: str, tool_input: dict) -> str:
        if tool_name == "write_response_action":
            # Tier 5 Reliability: Use formal SQL method
            self.state.add_response_action(tool_input)
            approval = " [REQUIRES APPROVAL]" if tool_input.get("requires_approval") else ""
            return f"Response action logged: {tool_input['action_type']} on {tool_input['target']}{approval}"

        if tool_name == "write_thehive_case":
            # Tier 5 Reliability: Use formal SQL method
            self.state.set_thehive_case(tool_input)
            return f"TheHive case drafted: {tool_input['title']} [{tool_input['severity']}] TLP:{tool_input['tlp']}"

        return self._execute_tool(tool_name, tool_input)

    async def _call_with_res_tools(self, system: str, messages: list[dict]) -> str:
        tools = self._get_standard_tools() + self._get_res_tools()
        return await self._run_tool_loop(system, messages, tools, self._execute_res_tool)

    async def run(self, task: str) -> None:
        """
        task should include the defender_ana analysis output and original alert context.
        """
        print(f"[defender_res] Response triggered — {task[:120]}")

        system = self._build_system_prompt(_BASE_PROMPT)
        messages = [{"role": "user", "content": task}]

        result = await self._call_with_res_tools(system, messages)
        print(f"[defender_res] Response actions complete.\n{result[:500]}")
        return result
