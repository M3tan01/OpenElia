#!/usr/bin/env python3
"""
orchestrator.py — Stateless message broker for OpenElia.

Supports Parallel Swarming:
Enqueues typed AgentTask objects into an AsyncWorkerPool; agents are lazily
imported and dispatched per-tier, not instantiated directly in route().
"""

import json
import traceback
from state_manager import StateManager
from artifact_manager import ArtifactManager
from cost_tracker import CostTracker
from rbac_manager import RBACManager
from risk_calculator import RiskCalculator
from llm_client import LLMClient
from core.schemas import AgentTask, AgentResult, AgentTier, Domain
from core.worker_pool import AsyncWorkerPool, MAX_RETRIES

_CLASSIFY_SYSTEM = """You are a cybersecurity operations classifier.

Given a task description and engagement context, output ONLY a JSON object with:
{
  "domain": "red" | "blue" | "status" | "purple" | "unknown",
  "confidence": 0.0-1.0,
  "reason": "one sentence"
}

domain definitions:
- "red"      = penetration testing, exploitation, recon, lateral movement, exfil simulation
- "blue"     = threat detection, log analysis, incident response, alert triage, hunting
- "reporter" = generate report, executive summary, MITRE heatmap, findings summary, chain of custody
- "purple"   = collaborative attack/defend simulation, autonomous purple team loop
- "unknown"  = cannot classify

Output ONLY the JSON. No preamble, no explanation."""


class Orchestrator:
    # ---------------------------------------------------------------------------
    # Agent registry — (tier, agent_name) pairs consumed by _enqueue
    # ---------------------------------------------------------------------------
    _RED_AGENTS: list[tuple[AgentTier, str]] = [
        (AgentTier.RECON,     "pentester_recon"),
        (AgentTier.ANALYSIS,  "pentester_vuln"),
        (AgentTier.EXECUTION, "pentester_exploit"),
        (AgentTier.EXECUTION, "pentester_lat"),
        (AgentTier.EXECUTION, "pentester_ex"),
    ]
    _BLUE_AGENTS: list[tuple[AgentTier, str]] = [
        (AgentTier.RECON,     "defender_mon"),
        (AgentTier.ANALYSIS,  "defender_ana"),
        (AgentTier.ANALYSIS,  "defender_hunt"),
        (AgentTier.EXECUTION, "defender_res"),
    ]

    def __init__(self, state_manager: StateManager):
        self.state = state_manager
        self.artifact_manager = ArtifactManager()
        self.cost_tracker = CostTracker()
        self.risk_calculator = RiskCalculator()
        # Always use the local model for cheap task classification
        self.client, self._orchestrator_model = LLMClient.create(brain_tier="local")
        self._pool: AsyncWorkerPool | None = None  # Created fresh per route() call

    # ---------------------------------------------------------------------------
    # Public entry point
    # ---------------------------------------------------------------------------

    async def route(
        self,
        task: str,
        targets: list[str] = None,
        stealth: bool = False,
        proxy_port: int | None = None,
        brain_tier: str = "local",
        apt_profile: str = None,
        force_domain: str | None = None,
    ) -> dict:
        """
        Classify the task domain, then dispatch via AsyncWorkerPool.
        A fresh pool is created per route() call (pools are single-use).

        Args:
            force_domain: When set, skip the LLM classifier and use this domain
                          directly. Used by the purple team feedback loop to drive
                          alternating red/blue/reporter phases without paying
                          classification cost on every iteration.
        """
        target_list = targets or ["unknown"]
        proxy_info = f" [PROXY:{proxy_port}]" if proxy_port else ""
        tier_info = f" [TIER:{brain_tier}]"
        apt_info = f" [APT:{apt_profile}]" if apt_profile else ""

        if force_domain:
            routing = {"domain": force_domain, "confidence": 1.0, "reason": "forced by caller"}
        else:
            routing = await self._classify(task, str(targets))

        domain = routing["domain"]

        print(
            f"[Orchestrator] Domain: {domain} "
            f"(confidence={routing['confidence']:.2f}) — {routing['reason']} "
            f"{'[STEALTH]' if stealth else ''}{proxy_info}{tier_info}{apt_info}"
        )
        print(f"[Orchestrator] Swarm Targets: {', '.join(target_list)}")

        if domain not in ("red", "blue", "reporter", "purple"):
            print(f"[Orchestrator] Unknown domain — task not routed.")
            return routing

        # RBAC enforcement for offensive domains
        if domain in ("red", "purple"):
            if not RBACManager.enforce_red_team_auth():
                print(f"[Orchestrator] Access Denied for {domain} operation.")
                return routing

        # Fresh pool per route() invocation
        self._pool = AsyncWorkerPool(workers_per_tier=3)

        await self._enqueue(
            domain=domain,
            task=task,
            targets=target_list,
            stealth=stealth,
            proxy_port=proxy_port,
            brain_tier=brain_tier,
            apt_profile=apt_profile,
        )

        results = await self._pool.run_until_complete(self._dispatch_task)
        self._print_summary(results)
        return routing

    # ---------------------------------------------------------------------------
    # Enqueue — builds AgentTask objects and submits them to the pool
    # ---------------------------------------------------------------------------

    async def _enqueue(
        self,
        domain: str,
        task: str,
        targets: list[str],
        stealth: bool = False,
        proxy_port: int | None = None,
        brain_tier: str = "local",
        apt_profile: str = None,
    ) -> None:
        """Build AgentTask objects and submit them to the pool."""

        if domain in ("red", "purple"):
            for target in targets:
                risk = self.risk_calculator.calculate_exploit_risk(target, task, stealth)
                print(
                    f"[Orchestrator] Risk Analysis ({target}): "
                    f"Success {risk['success_probability']}% | "
                    f"Detection {risk['detection_risk']}"
                )
                for tier, agent_name in self._RED_AGENTS:
                    agent_task = AgentTask(
                        domain=Domain.RED,
                        tier=tier,
                        agent_name=agent_name,
                        payload={"target": target, "task": task},
                        brain_tier=brain_tier,
                        stealth=stealth,
                        proxy_port=proxy_port,
                        apt_profile=apt_profile,
                    )
                    await self._pool.submit(agent_task)

        if domain in ("blue", "purple"):
            for tier, agent_name in self._BLUE_AGENTS:
                agent_task = AgentTask(
                    domain=Domain.BLUE,
                    tier=tier,
                    agent_name=agent_name,
                    payload={"task": task, "target": targets[0] if targets else "unknown"},
                    brain_tier=brain_tier,
                    stealth=stealth,
                    proxy_port=proxy_port,
                    apt_profile=apt_profile,
                )
                await self._pool.submit(agent_task)

        if domain == "reporter":
            agent_task = AgentTask(
                domain=Domain.REPORTER,
                tier=AgentTier.EXECUTION,
                agent_name="reporter_agent",
                payload={"task": task},
                brain_tier=brain_tier,
                stealth=stealth,
                proxy_port=proxy_port,
                apt_profile=apt_profile,
            )
            await self._pool.submit(agent_task)

    # ---------------------------------------------------------------------------
    # Pool handler — hooks + _run_agent dispatch
    # ---------------------------------------------------------------------------

    async def _dispatch_task(self, task: AgentTask) -> AgentResult:
        from core.hooks import pre_run_hook, post_run_hook, error_hook

        context = pre_run_hook(task)
        try:
            output = await self._run_agent(task)
            result = AgentResult(
                task_id=task.task_id,
                agent_name=task.agent_name,
                status="success",
                output=output,
            )
            post_run_hook(task, result, context)
            return result
        except Exception as exc:
            error_hook(task, exc, task.retry_count, MAX_RETRIES)
            result = AgentResult(
                task_id=task.task_id,
                agent_name=task.agent_name,
                status="error",
                output={},
                error_detail=f"{exc}\n{traceback.format_exc()}",
            )
            post_run_hook(task, result, context)
            return result

    # ---------------------------------------------------------------------------
    # Inner dispatch — lazy import by agent_name
    # ---------------------------------------------------------------------------

    async def _run_agent(self, task: AgentTask) -> dict:
        name = task.agent_name
        target = task.payload.get("target", "unknown")
        raw_task = task.payload.get("task", "")

        if name == "pentester_recon":
            from agents.red.pentester_recon import PentesterRecon
            agent = PentesterRecon(self.state, brain_tier=task.brain_tier)
            result = await agent.run(f"Target: {target}. {raw_task}")
            return {"output": result}

        if name == "pentester_vuln":
            from agents.red.pentester_vuln import PentesterVuln
            agent = PentesterVuln(self.state, brain_tier=task.brain_tier)
            result = await agent.run(f"Target: {target}. {raw_task}")
            return {"output": result}

        if name == "pentester_exploit":
            from agents.red.pentester_exploit import PentesterExploit
            agent = PentesterExploit(self.state, brain_tier=task.brain_tier)
            result = await agent.run(
                f"Target: {target}. {raw_task}",
                stealth=task.stealth,
                proxy_port=task.proxy_port,
                apt_profile=task.apt_profile,
            )
            return {"output": result}

        if name == "defender_mon":
            from agents.blue.defender_mon import DefenderMon
            agent = DefenderMon(self.state, brain_tier=task.brain_tier)
            result = await agent.run(raw_task)
            return {"output": result}

        if name == "defender_ana":
            from agents.blue.defender_ana import DefenderAna
            agent = DefenderAna(self.state, brain_tier=task.brain_tier)
            result = await agent.run(raw_task)
            return {"output": result}

        if name == "defender_res":
            from agents.blue.defender_res import DefenderRes
            agent = DefenderRes(self.state, brain_tier=task.brain_tier)
            result = await agent.run(raw_task)
            return {"output": result}

        if name == "pentester_lat":
            from agents.red.pentester_lat import PentesterLat
            agent = PentesterLat(self.state, brain_tier=task.brain_tier)
            result = await agent.run(
                f"Target: {target}. {raw_task}",
                stealth=task.stealth,
                proxy_port=task.proxy_port,
                apt_profile=task.apt_profile,
            )
            return {"output": result}

        if name == "pentester_ex":
            from agents.red.pentester_ex import PentesterEx
            agent = PentesterEx(self.state, brain_tier=task.brain_tier)
            result = await agent.run(
                f"Target: {target}. {raw_task}",
                stealth=task.stealth,
                proxy_port=task.proxy_port,
                apt_profile=task.apt_profile,
            )
            return {"output": result}

        if name == "defender_hunt":
            from agents.blue.defender_hunt import DefenderHunt
            agent = DefenderHunt(self.state, brain_tier=task.brain_tier)
            result = await agent.run(raw_task)
            return {"output": result}

        if name == "reporter_agent":
            from agents.reporter_agent import ReporterAgent
            agent = ReporterAgent(self.state, brain_tier=task.brain_tier)
            result = await agent.run(raw_task)
            return {"output": result}

        raise ValueError(f"Unknown agent: {name}")

    # ---------------------------------------------------------------------------
    # Classifier — unchanged from original
    # ---------------------------------------------------------------------------

    async def _classify(self, task: str, context: str) -> dict:
        """Single local Ollama call to classify the task domain. Returns routing dict."""
        user_content = f"Task: {task}"
        if context:
            user_content += f"\n\nContext: {context}"

        response = await self.client.chat.completions.create(
            model=self._orchestrator_model,
            messages=[
                {"role": "system", "content": _CLASSIFY_SYSTEM},
                {"role": "user", "content": user_content},
            ],
            max_tokens=256,
        )

        if response.usage:
            self.cost_tracker.track_usage(
                model=self._orchestrator_model,
                input_tokens=response.usage.prompt_tokens,
                output_tokens=response.usage.completion_tokens,
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

    # ---------------------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------------------

    def _print_summary(self, results: list[AgentResult]) -> None:
        """Brief completion summary after pool drains."""
        success = sum(1 for r in results if r.status == "success")
        errors = sum(1 for r in results if r.status == "error")
        print(f"[Orchestrator] Pool complete — {success} succeeded, {errors} failed ({len(results)} total)")

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
            for art in artifacts[:5]:
                print(f"  {art}")
            if len(artifacts) > 5:
                print(f"  ... and {len(artifacts)-5} more.")

        print(f"\n{'='*60}\n")
