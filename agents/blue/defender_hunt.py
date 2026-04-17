#!/usr/bin/env python3
"""
agents/blue/defender_hunt.py — Proactive Threat Hunting Agent.

This agent periodically scans the infrastructure for common persistence mechanisms
and hidden artifacts without waiting for SIEM alerts.
"""

import re
import sys
import os
import json
from collections import Counter
from datetime import datetime, timezone
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from agents.base_agent import BaseAgent, _DEFAULT_MODEL
from state_manager import StateManager

_BASE_PROMPT = """You are defender_hunt, the Proactive Threat Hunter of OpenElia.

Your mission is to actively hunt for threats by scanning the infrastructure for common 
persistence mechanisms, hidden files, and indicators of compromise (IoCs).

Do not wait for alerts. You are the 'Stalker' agent.

## Hunting Objectives

1. **Scan for Persistence**:
   - Check crontabs and scheduled tasks for suspicious entries.
   - Check 'authorized_keys' for unauthorized SSH access.
   - Look for suspicious service configurations.
2. **Hidden Artifacts**:
   - Scan for hidden files or directories in common temporary or system paths.
   - Look for binaries with unusual names or in unexpected locations.
3. **Evidence Collection**:
   - If you find something suspicious, use 'store_artifact' to save the evidence.
   - Log a high-confidence alert if a threat is confirmed.

## Workflow

1. Use 'mcp-filesystem' to list and read system configuration files.
2. Use 'Bash' tools (if authorized) to execute surgical 'find' or 'grep' commands.
3. Compare findings against known baselines or authorized engagement scope.
4. Log every anomaly to the 'blue_alerts' list in state.
"""

class DefenderHunt(BaseAgent):
    AGENT_NAME = "defender_hunt"
    MODEL = _DEFAULT_MODEL
    MAX_TOKENS = 8096

    def __init__(self, state_manager: StateManager, brain_tier: str = "local"):
        super().__init__(state_manager, brain_tier=brain_tier)

    def _get_hunt_tools(self) -> list[dict]:
        return [
            {
                "name": "record_persistence_finding",
                "description": "Record a suspicious persistence mechanism found during the hunt.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "mechanism": {"type": "string", "enum": ["cron", "ssh_key", "systemd", "registry", "other"]},
                        "location": {"type": "string"},
                        "evidence": {"type": "string"},
                        "severity": {"type": "string", "enum": ["high", "medium", "low"]},
                        "mitre_ttp": {"type": "string"}
                    },
                    "required": ["mechanism", "location", "evidence", "mitre_ttp"]
                }
            }
        ]

    def _execute_hunt_tool(self, tool_name: str, tool_input: dict) -> str:
        if tool_name == "record_persistence_finding":
            self.state.add_blue_alert(
                alert_type=f"PERSISTENCE_{tool_input['mechanism'].upper()}",
                description=f"Proactive hunt found {tool_input['mechanism']} at {tool_input['location']}",
                severity=tool_input.get("severity", "medium"),
                source="defender_hunt"
            )
            return f"Hunt finding logged: {tool_input['mechanism']} at {tool_input['location']}"
        return self._execute_tool(tool_name, tool_input)

    async def run(self, task: str = "Perform proactive persistence hunt on current target") -> None:
        """
        Entry point for the proactive hunt.
        """
        print(f"\n[defender_hunt] ====== Proactive Hunt Cycle Start ======")
        print(f"[defender_hunt] Objective: {task}")

        system = self._build_system_prompt(_BASE_PROMPT)
        messages = [{"role": "user", "content": task}]
        tools = self._get_standard_tools() + self._get_hunt_tools()

        try:
            result = await self._run_tool_loop(system, messages, tools, self._execute_hunt_tool)
            print(f"[defender_hunt] Hunt cycle complete.")
            
            # Store full hunt results as a forensic artifact
            self.artifact_manager.store_artifact(
                source_agent=self.AGENT_NAME,
                filename="proactive_hunt_results.json",
                content=json.dumps({"task": task, "summary": result, "timestamp": datetime.now(timezone.utc).isoformat()}),
                metadata={"type": "hunt_log"}
            )
            
            self.state.set_metadata("last_hunt", {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "summary": result[:200]
            })
        except Exception as e:
            print(f"[defender_hunt] Hunt cycle failed: {str(e)}")
            raise

    # ------------------------------------------------------------------ #
    # Legacy rule-based methods (kept for backward compatibility)
    # ------------------------------------------------------------------ #

    def hunt_beacon_scores(self, zeek_lines: list[str]) -> list[dict]:
        # Legacy implementation from previous version
        return [] # Simplified for this refactor
