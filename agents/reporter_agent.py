#!/usr/bin/env python3
"""
agents/reporter_agent.py — Executive Reporting Agent.

Mandate:
- Generate executive summaries and tactical MITRE heatmaps.
- Include a professional Forensic Chain of Custody log.
- Generate TLP:RED and TLP:WHITE versions of the report.
"""

import os
import json
import hashlib
from datetime import datetime, timezone
from agents.base_agent import BaseAgent, _DEFAULT_MODEL
from state_manager import StateManager
from artifact_manager import ArtifactManager
from graph_manager import GraphManager

_REPORT_PROMPT = """You are the OpenElia Reporter Agent.
Your mission is to synthesize the results of a security engagement into a high-signal report.

## Reporting Mandates

1. **Executive Summary**: High-level overview of the engagement status, critical findings, and business risk.
2. **Tactical MITRE Analysis**: Map findings to ATT&CK tactics and techniques.
3. **Forensic Integrity**: Provide a clear, immutable chain of custody for all evidence.
4. **Remediation Roadmap**: Prioritized list of actions for the defense team.

## Input Context
You will receive JSON data containing findings, alerts, and the forensic timeline.
"""

class ReporterAgent(BaseAgent):
    AGENT_NAME = "reporter"
    MODEL = _DEFAULT_MODEL

    def __init__(self, state_manager: StateManager, brain_tier: str = "local"):
        super().__init__(state_manager, brain_tier=brain_tier)
        self.artifact_manager = ArtifactManager()
        self.graph_manager = GraphManager()

    async def run(self, task: str = "Generate full engagement report") -> str:
        print(f"[{self.AGENT_NAME}] Generating strategic report...")
        
        # 1. Gather all state data
        state = self.state.read()
        findings = state.get("findings", [])
        alerts = state.get("blue_alerts", [])
        coc = self.artifact_manager.get_chain_of_custody()
        heatmap = self.graph_manager.get_mitre_heatmap(findings)
        
        # 2. Build the context for the LLM
        context = {
            "engagement": state.get("engagement", {}),
            "findings_count": len(findings),
            "findings": findings[:20], # Sample for summary
            "blue_alerts": alerts[:20],
            "mitre_coverage": heatmap,
            "forensic_timeline_count": len(coc)
        }

        system = self._build_system_prompt(_REPORT_PROMPT)
        messages = [
            {"role": "user", "content": f"Context: {json.dumps(context)}\n\nTask: {task}"}
        ]

        try:
            report_content = await self._call_with_tools(system, messages, self._get_standard_tools())
            
            # 3. Append Chain of Custody (Immutable Section)
            report_content += "\n\n## 🛡️ Forensic Chain of Custody (Verified Timeline)\n"
            report_content += "| Timestamp | Agent | Filename | SHA-256 | Status |\n"
            report_content += "| :--- | :--- | :--- | :--- | :--- |\n"
            for entry in coc:
                report_content += f"| {entry['timestamp']} | {entry['source_agent']} | {entry['filename']} | `{entry['sha256'][:16]}...` | {entry['status']} |\n"
            
            # 4. Save the report as an artifact
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            report_filename = f"Final_Report_{ts}.md"
            self.artifact_manager.store_artifact(
                source_agent=self.AGENT_NAME,
                filename=report_filename,
                content=report_content,
                metadata={"type": "report", "tlp": "RED"}
            )
            
            # --- ARCHITECTURAL UPGRADE: Strategic GRC Export ---
            # Export the raw MITRE heatmap data as JSON for external platform ingestion
            heatmap_filename = f"MITRE_Heatmap_{ts}.json"
            self.artifact_manager.store_artifact(
                source_agent=self.AGENT_NAME,
                filename=heatmap_filename,
                content=json.dumps(heatmap, indent=2),
                metadata={"type": "strategic_export", "format": "json"}
            )
            
            print(f"[{self.AGENT_NAME}] Report generated: {report_filename}")
            print(f"[{self.AGENT_NAME}] Strategic MITRE Export generated: {heatmap_filename}")
            return report_content

        except Exception as e:
            print(f"[{self.AGENT_NAME}] Reporting FAILED: {str(e)}")
            raise
