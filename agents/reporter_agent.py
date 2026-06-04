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

_BRIEF_PROMPT = """You are the OpenElia Reporter Agent generating a concise executive brief.
Produce a SHORT Markdown document with exactly four sections:

1. **Summary** — One paragraph covering engagement scope, total findings, and overall risk posture.
2. **Top Risks** — Bullet list of the highest-severity findings ordered by CVSS score (descending). Include title, severity, and CVSS where available.
3. **ATT&CK Coverage Highlights** — Two to five bullet points naming the ATT&CK tactics/techniques with the most activity or highest gap risk.
4. **Recommended Actions** — Numbered prioritized remediation steps (most urgent first).

Keep the entire brief under 400 words. Output Markdown only — no preamble, no chain-of-custody block.
"""

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

    async def brief(self, findings: list[dict] | None = None) -> str:
        """Concise exec brief over the given findings (or current engagement findings
        if None): top risks, ATT&CK coverage, recommended actions. Returns Markdown.
        Does NOT save an artifact (unlike run())."""
        if findings is None:
            findings = self.state.read().get("findings", [])

        if not findings:
            return "_No findings to summarize._"

        heatmap = self.graph_manager.get_mitre_heatmap(findings)
        context = {
            "findings_count": len(findings),
            "findings": findings[:30],
            "mitre_coverage": heatmap,
        }

        system = self._build_system_prompt(_BRIEF_PROMPT)
        messages = [
            {"role": "user", "content": f"Findings context: {json.dumps(context)}"}
        ]
        md = await self._call_with_tools(system, messages, [])
        return md

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
