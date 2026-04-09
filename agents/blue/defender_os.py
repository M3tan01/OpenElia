#!/usr/bin/env python3
"""
agents/blue/defender_os.py — Blue team Tier 2 orchestrator.

Coordinates between Tier 1 monitoring (DefenderMon) and Tier 3 deep analysis (DefenderAna).
Orchestrates the "Detection -> Analysis -> Remediation" loop.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from state_manager import StateManager
from agents.blue.defender_mon import DefenderMon
from agents.blue.defender_ana import DefenderAna
from agents.blue.defender_res import DefenderRes
from agents.blue.defender_hunt import DefenderHunt


class DefenderOS:
    def __init__(self, state_manager: StateManager, brain_tier: str = "local"):
        self.state = state_manager
        self.mon = DefenderMon(state_manager)
        self.hunt = DefenderHunt(state_manager, brain_tier=brain_tier)
        self.ana = DefenderAna(state_manager, brain_tier=brain_tier)
        self.res = DefenderRes(state_manager, brain_tier=brain_tier)

    async def analyze_logs(self, log_text: str = "", logon_lines: list[str] = None, zeek_lines: list[str] = None) -> None:
        """
        Run the blue team pipeline:
        1. Tier 1: Monitor (Regex/Threshold)
        2. Tier 1.5: Proactive Hunt (AI-driven)
        3. Tier 3: LLM deep analysis if alerts found
        4. Tier 4: LLM-driven remediation
        """
        print("\n[DefenderOS] ====== Blue Team Operation Start ======")

        # Combine inputs for monitoring
        combined_text = log_text
        if logon_lines:
            combined_text += "\n" + "\n".join(logon_lines)
        if zeek_lines:
            combined_text += "\n" + "\n".join(zeek_lines)

        # 1. Tier 1 Monitoring (Reactive)
        print("[DefenderOS] Running Tier 1 monitoring...")
        alerts = self.mon.analyze(combined_text)
        
        # 2. Tier 1.5 Proactive Hunt
        print("[DefenderOS] Launching proactive AI hunt...")
        await self.hunt.run()

        # 3. Escalation and Analysis
        if alerts:
            print(f"[DefenderOS] ! TIER 1 ALERT FIRE: {len(alerts)} alerts generated.")
        else:
            # If no direct regex alerts, check if there's enough interesting context for LLM
            if len(combined_text) > 100:
                print("[DefenderOS] No Tier 1 alerts, but log volume significant. Escalating to Tier 3 for anomaly check.")
            else:
                print("[DefenderOS] Monitoring quiet. No escalation.")
                print("\n[DefenderOS] ====== Blue Team Operation Complete ======")
                return

        # 4. Tier 3 Deep Analysis
        print("[DefenderOS] Escalating to Tier 3 deep analysis...")
        analysis_result = await self.ana.run(f"Analyze the following logs/alerts for malicious intent: {combined_text}")
        
        # 5. Tier 4 Remediation
        if "REMEDIATION REQUIRED" in analysis_result.upper() or "CRITICAL" in analysis_result.upper():
            print("[DefenderOS] !!! Tier 3 indicates critical threat. Escalating to Tier 4 remediation.")
            await self.res.run(f"Based on this analysis, implement remediation: {analysis_result}")
        else:
            print("[DefenderOS] Deep analysis complete. No active remediation triggered.")

        print("\n[DefenderOS] ====== Blue Team Operation Complete ======")
