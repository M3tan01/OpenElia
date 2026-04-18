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
import hashlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from agents.base_agent import BaseAgent, _DEFAULT_MODEL
from state_manager import StateManager
from secret_store import SecretStore


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

    # Commands the executor is permitted to run. Any DB-stored command that does
    # not start with one of these prefixes is rejected — this closes the vector
    # where a compromised DB row could execute arbitrary OS commands.
    _ALLOWED_CMD_PREFIXES = (
        "iptables ",           # Linux firewall
        "ip6tables ",          # Linux IPv6 firewall
        "kill ",               # Unix/Linux/macOS process signal
        "killall ",            # Unix/Linux/macOS process termination by name
        "taskkill ",           # Windows process termination
        "Disable-ADAccount ",  # Windows PowerShell AD
        "Set-ADAccountPassword ",             # Windows PowerShell AD
        "Revoke-AzureADUserAllRefreshToken ", # Windows PowerShell Azure AD
        "net user ",           # Windows user management
        "usermod ",            # Linux user management
    )

    async def execute_remediation(self, action_id: int):
        """Execute a previously logged remediation action after explicit operator approval."""
        with self.state._get_conn() as conn:
            cursor = conn.execute(
                "SELECT action_type, target, command FROM response_actions WHERE id = ?",
                (action_id,),
            )
            row = cursor.fetchone()
            if not row:
                return "Error: Action ID not found."

            action_type, target, command = row

            # Security gate: only allow known-safe command prefixes (prevents
            # arbitrary execution if a DB row is tampered with).
            stripped = command.lstrip()
            if not any(stripped.startswith(p) for p in self._ALLOWED_CMD_PREFIXES):
                print(f"[defender_res] BLOCKED: command '{stripped[:60]}' is not in the remediation allowlist.")
                return (
                    f"EXECUTION BLOCKED: Command does not match a permitted prefix. "
                    f"Allowed prefixes: {', '.join(self._ALLOWED_CMD_PREFIXES)}"
                )

            print(f"[defender_res] Executing approved remediation: {action_type} on {target}")

            import subprocess
            import shlex
            try:
                cmd_list = shlex.split(stripped)
                result = subprocess.run(cmd_list, capture_output=True, text=True, timeout=30)  # nosec: B603
                status = "SUCCESS" if result.returncode == 0 else "FAILED"
                output = (result.stdout + result.stderr)[:500]
                conn.execute(
                    "UPDATE response_actions SET status = ?, output = ? WHERE id = ?",
                    (status, output, action_id),
                )
                return f"Remediation {status}: {output[:200]}"
            except Exception as e:
                return f"Remediation execution error: {e}"

    async def _execute_res_tool(self, tool_name: str, tool_input: dict) -> str:
        if tool_name == "write_response_action":
            res = self.state.add_response_action(tool_input)
            action_id = res.get("id")

            if tool_input.get("requires_approval"):
                return (
                    f"Response action logged (ID={action_id}). "
                    f"Awaiting IR Manager approval before execution."
                )
            # All remediation commands require explicit human approval — never auto-execute.
            return (
                f"Response action logged (ID={action_id}). "
                f"Command: `{tool_input.get('command', '')}` — "
                f"Execute via: python main.py execute-remediation --action-id {action_id}"
            )

        if tool_name == "write_thehive_case":
            self.state.set_thehive_case(tool_input)
            dispatch_result = await self.dispatch_thehive_case(tool_input)
            return f"TheHive case saved: {tool_input['title']} — {dispatch_result}"

        return self._execute_tool(tool_name, tool_input)

    async def _call_with_res_tools(self, system: str, messages: list[dict]) -> str:
        tools = self._get_standard_tools() + self._get_res_tools()
        return await self._run_tool_loop(system, messages, tools, self._execute_res_tool)

    async def dispatch_thehive_case(self, case_data: dict) -> str:
        """Push a case directly to TheHive REST API."""
        hive_url = SecretStore.get_secret("THEHIVE_URL")
        api_key = SecretStore.get_secret("THEHIVE_API_KEY")
        if not hive_url or not api_key:
            print(f"[defender_res] TheHive dispatch skipped — THEHIVE_URL or THEHIVE_API_KEY not configured. Case saved to local SQLite only.")
            return "Case saved to local SQLite only. Set THEHIVE_URL and THEHIVE_API_KEY in the vault to enable live dispatch."

        print(f"[defender_res] Dispatching TheHive case (local only until live API is wired): {case_data['title']}")
        # Wire real httpx POST here when TheHive endpoint is available:
        # import httpx
        # async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
        #     response = await client.post(
        #         f"{hive_url}/api/v1/case",
        #         json=case_data,
        #         headers={"Authorization": f"Bearer {api_key}"},
        #     )
        #     response.raise_for_status()
        #     return f"TheHive case created: {response.json().get('_id', 'unknown')}"
        case_hash = hashlib.sha256(case_data['title'].encode()).hexdigest()[:8]
        return f"TheHive case saved locally (ID: TH-{case_hash}). Live dispatch pending API wiring."
