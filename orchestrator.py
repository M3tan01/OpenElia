#!/usr/bin/env python3
"""
orchestrator.py — Stateless message broker for OpenElia.

Supports Parallel Swarming:
Can launch multiple agents simultaneously across a subnet.
"""

import json
import os
import asyncio
from openai import AsyncOpenAI
from state_manager import StateManager
from artifact_manager import ArtifactManager
from secret_store import SecretStore
from cost_tracker import CostTracker
from rbac_manager import RBACManager
from risk_calculator import RiskCalculator

_OLLAMA_BASE_URL = SecretStore.get_secret("OLLAMA_BASE_URL") or "http://localhost:11434/v1"
_ORCHESTRATOR_MODEL = SecretStore.get_secret("OLLAMA_MODEL") or "llama3.1:8b"

_CLASSIFY_SYSTEM = """You are a cybersecurity operations classifier.

Given a task description and engagement context, output ONLY a JSON object with:
{
  "domain": "red" | "blue" | "status" | "purple" | "unknown",
  "confidence": 0.0-1.0,
  "reason": "one sentence"
}

domain definitions:
- "red"    = penetration testing, exploitation, recon, lateral movement, exfil simulation
- "blue"   = threat detection, log analysis, incident response, alert triage, hunting
- "status" = show current state, findings summary, phase status, report generation
- "purple" = collaborative attack/defend simulation, autonomous purple team loop
- "unknown" = cannot classify

Output ONLY the JSON. No preamble, no explanation."""


class Orchestrator:
    def __init__(self, state_manager: StateManager):
        self.state = state_manager
        self.artifact_manager = ArtifactManager()
        self.cost_tracker = CostTracker()
        self.risk_calculator = RiskCalculator()
        self.client = AsyncOpenAI(
            base_url=_OLLAMA_BASE_URL,
            api_key="ollama",
        )

    async def route(self, task: str, targets: list[str] = None, stealth: bool = False, proxy_port: int | None = None, brain_tier: str = "local", apt_profile: str = None) -> dict:
        """
        Classify the task domain and delegate to the appropriate OS.
        Supports swarming across multiple targets in parallel.
        """
        routing = await self._classify(task, str(targets))
        proxy_info = f" [PROXY:{proxy_port}]" if proxy_port else ""
        tier_info = f" [TIER:{brain_tier}]"
        apt_info = f" [APT:{apt_profile}]" if apt_profile else ""
        
        target_list = targets or ["unknown"]
        
        print(
            f"[Orchestrator] Domain: {routing['domain']} "
            f"(confidence={routing['confidence']:.2f}) — {routing['reason']} "
            f"{'[STEALTH]' if stealth else ''}{proxy_info}{tier_info}{apt_info}"
        )
        print(f"[Orchestrator] Swarm Targets: {', '.join(target_list)}")

        if routing["domain"] not in ("red", "blue", "status", "purple"):
            print(f"[Orchestrator] Unknown domain — task not routed.")
            return routing

        await self._delegate(routing, task, target_list, stealth, proxy_port, brain_tier, apt_profile)
        return routing

    async def _classify(self, task: str, context: str) -> dict:
        """Single local Ollama call to classify the task domain. Returns routing dict."""
        user_content = f"Task: {task}"
        if context:
            user_content += f"\n\nContext: {context}"

        response = await self.client.chat.completions.create(
            model=_ORCHESTRATOR_MODEL,
            messages=[
                {"role": "system", "content": _CLASSIFY_SYSTEM},
                {"role": "user", "content": user_content},
            ],
            max_tokens=256,
        )

        if response.usage:
            self.cost_tracker.track_usage(
                model=_ORCHESTRATOR_MODEL,
                input_tokens=response.usage.prompt_tokens,
                output_tokens=response.usage.completion_tokens
            )

        text = (response.choices[0].message.content or "").strip()

        # Strip markdown code fences if present
        if text.startswith("```"):
            lines = text.splitlines()
            text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

        try:
            result = json.loads(text)
            result.setdefault("confidence", 0.5)
            result.setdefault("reason", "")
            return result
        except json.JSONDecodeError:
            return {"domain": "unknown", "confidence": 0.0, "reason": f"Parse error: {text[:100]}"}

    async def _delegate(self, routing: dict, task: str, targets: list[str], stealth: bool = False, proxy_port: int | None = None, brain_tier: str = "local", apt_profile: str = None) -> None:
        """Instantiate the appropriate OS and run the task for all targets in parallel."""
        domain = routing["domain"]

        if domain in ("red", "purple"):
            # Tier 1 Security: RBAC Enforcement
            if not RBACManager.enforce_red_team_auth():
                print(f"[Orchestrator] Access Denied for {domain} operation.")
                return

        if domain == "red":
            from agents.red.pentester_os import PentesterOS
            # Parallel Swarm with Concurrency Limits
            sem = asyncio.Semaphore(10)
            
            async def run_with_sem(target_ip):
                async with sem:
                    # Tier 2: Risk Assessment per target
                    risk = self.risk_calculator.calculate_exploit_risk(target_ip, task, stealth)
                    print(f"[Orchestrator] ⚖️ Risk Analysis ({target_ip}): Success {risk['success_probability']}% | Detection {risk['detection_risk']}")
                    red_os = PentesterOS(self.state, brain_tier=brain_tier)
                    await red_os.run(f"Target: {target_ip}. {task}", stealth=stealth, proxy_port=proxy_port, apt_profile=apt_profile)

            parallel_tasks = [run_with_sem(target) for target in targets]
            if parallel_tasks:
                await asyncio.gather(*parallel_tasks)

        elif domain == "blue":
            from agents.blue.defender_os import DefenderOS
            blue_os = DefenderOS(self.state, brain_tier=brain_tier)
            await blue_os.analyze_logs(log_text=task)

        elif domain == "status":
            self._print_status()

        elif domain == "purple":
            await self.run_purple_loop(task, targets, stealth, proxy_port, brain_tier, iterations=2, apt_profile=apt_profile)

    async def run_purple_loop(self, task: str, targets: list[str], stealth: bool = False, proxy_port: int | None = None, brain_tier: str = "local", iterations: int = 2, apt_profile: str = None) -> None:
        """
        Execute an Iterative Purple Team cycle (Continuous Chaos) with parallel swarming.
        """
        print("\n" + "="*60)
        print(f"🟣 PURPLE TEAM SWARM STARTING ({len(targets)} targets)")
        print("="*60)

        from agents.red.pentester_os import PentesterOS
        from agents.blue.defender_os import DefenderOS

        sem = asyncio.Semaphore(10)

        for i in range(iterations):
            print(f"\n[Purple] --- ITERATION {i+1} START ---")
            
            # 1. Red Team Swarm Phase
            print(f"\n[Purple] PHASE 1: Offensive Swarm Execution ({len(targets)} agents)")
            
            async def run_with_sem(target_ip):
                async with sem:
                    red_os = PentesterOS(self.state, brain_tier=brain_tier)
                    await red_os.run(f"Target: {target_ip}. {task}", stealth=stealth, proxy_port=proxy_port, apt_profile=apt_profile)

            red_tasks = [run_with_sem(target) for target in targets]
            if red_tasks:
                await asyncio.gather(*red_tasks)

            # 2. Blue Team Phase (Detection & Remediation)
            blue_os = DefenderOS(self.state, brain_tier=brain_tier)
            print("\n[Purple] PHASE 2: Defensive Response & Remediation (Blue Team)")
            await blue_os.analyze_logs(log_text=f"Purple Swarm Iteration {i+1} Analysis for {len(targets)} targets")

            # 3. War Room Update
            self._print_status()

        print("\n" + "="*60)
        print("🟣 PURPLE TEAM SWARM COMPLETE")
        print("="*60)

    def _print_status(self) -> None:
        state = self.state.read()
        if not state:
            print("[Orchestrator] No active engagement.")
            return

        engagement = state.get("engagement", {})
        print(f"\n{'='*60}")
        print(f"WAR ROOM DASHBOARD - Engagement: {engagement.get('id', 'UNKNOWN')}")
        print(f"Target:     {engagement.get('target', 'UNKNOWN')}")
        print(f"Scope:      {engagement.get('scope', 'UNKNOWN')}")
        print(f"Started:    {engagement.get('started', 'UNKNOWN')}")
        print("="*60)

        print("\n-- Red Team Phases --")
        for phase in ["recon", "vuln", "exploit", "lateral", "exfil"]:
            status = state.get(phase, {}).get("status", "unknown")
            icon = {"complete": "✓", "failed": "✗", "dormant": "—",
                    "pending": "○", "running": "▶"}.get(status, "?")
            print(f"  {icon} {phase:<10} {status}")

        findings = state.get("findings", [])
        print(f"\n-- Findings ({len(findings)}) --")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = sum(1 for f in findings if f.get("severity") == sev)
            if count:
                print(f"  {sev.upper():<10} {count}")

        alerts = state.get("blue_alerts", [])
        analyses = state.get("blue_analyses", [])
        print(f"\n-- Blue Team --")
        print(f"  Alerts:   {len(alerts)}")
        print(f"  Analyses: {len(analyses)}")
        
        costs = self.cost_tracker.get_summary()
        print(f"\n-- Budget Awareness --")
        print(f"  Session Cost:  ${costs['session_cost']:.4f}")
        print(f"  Total History: ${costs['total_historical_cost']:.4f}")
        print(f"  Remaining:     ${costs['budget_remaining']:.2f}")
        
        artifacts = self.artifact_manager.list_artifacts()
        if artifacts:
            print(f"\n-- Evidence Bag (Artifacts: {len(artifacts)}) --")
            for art in artifacts[:5]: # Show first 5
                print(f"  📦 {art}")
            if len(artifacts) > 5:
                print(f"  ... and {len(artifacts)-5} more.")

        print(f"\n{'='*60}\n")
