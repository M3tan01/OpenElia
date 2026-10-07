"""
webdash/runner.py — background runner for Orchestrator.route().

route() launches real agents (LLM + tools) and is long-running, so control
endpoints start it as a tracked asyncio task and return a run_id immediately;
clients poll /api/run/{id}/status. Single active run at a time (the engine is
single-engagement). `_invoke` is isolated so tests can mock it.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class RunManager:
    def __init__(self) -> None:
        self._runs: dict[str, dict[str, Any]] = {}
        self._active: str | None = None
        self._tasks: set = set()

    def get(self, run_id: str) -> dict | None:
        return self._runs.get(run_id)

    def active(self) -> str | None:
        if self._active and self._runs.get(self._active, {}).get("status") == "running":
            return self._active
        return None

    async def start(
        self,
        *,
        domain: str,
        task: str,
        targets: list[str],
        stealth: bool = False,
        proxy_port: int | None = None,
        brain_tier: str = "local",
        apt_profile: str | None = None,
        state_dir: str = "state",
        agent: str | None = None,
        callback_url: str | None = None,
        campaign_id: str | None = None,
        tool: str | None = None,
        nmap_args: str | None = None,
        msf_args: str | None = None,
        action_id: int | None = None,
    ) -> str:
        if self.active():
            raise RuntimeError("a run is already active")

        run_id = uuid.uuid4().hex[:12]
        self._runs[run_id] = {
            "run_id": run_id,
            "domain": domain,
            "task": task,
            "targets": targets,
            "status": "running",
            "started": _now(),
            "finished": None,
            "result": None,
            "error": None,
            "callback_url": callback_url,
            "state_dir": state_dir,
            "campaign_id": campaign_id,
            "tool": tool,
        }
        self._active = run_id
        t = asyncio.create_task(
            self._execute(
                run_id=run_id, domain=domain, task=task, targets=targets,
                stealth=stealth, proxy_port=proxy_port, brain_tier=brain_tier,
                apt_profile=apt_profile, agent=agent, state_dir=state_dir,
                campaign_id=campaign_id, tool=tool, nmap_args=nmap_args, msf_args=msf_args,
                action_id=action_id,
            )
        )
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)
        return run_id

    async def _execute(self, run_id, domain, task, targets, stealth, proxy_port, brain_tier, apt_profile, state_dir, agent=None, campaign_id=None, tool=None, nmap_args=None, msf_args=None, action_id=None):
        rec = self._runs[run_id]
        try:
            rec["result"] = await self._invoke(
                domain=domain, task=task, targets=targets, stealth=stealth,
                proxy_port=proxy_port, brain_tier=brain_tier, apt_profile=apt_profile,
                agent=agent, state_dir=state_dir, campaign_id=campaign_id,
                tool=tool, nmap_args=nmap_args, msf_args=msf_args, action_id=action_id,
            )
            rec["status"] = "done"
            # Trend snapshot: unconditional completion point for purple runs.
            # NOT in _notify (that is callback_url-gated) — a webhookless purple
            # run must still snapshot. No-op if the engagement has no campaign_id.
            if domain == "purple":
                try:
                    from state_manager import StateManager

                    sm = StateManager(db_path=str(Path(state_dir) / "engagement.db"))
                    sm.record_coverage_snapshot()
                except Exception as exc:  # best-effort — never flip a done run to error
                    print(f"trend snapshot failed: {type(exc).__name__}: {exc}")
        except (Exception, SystemExit) as exc:  # capture errors + kill-switch SystemExit; let CancelledError propagate
            rec["status"] = "error"
            rec["error"] = str(exc) or exc.__class__.__name__
        finally:
            rec["finished"] = _now()
            if rec["status"] == "running":  # task cancelled (CancelledError propagated past except)
                rec["status"] = "cancelled"
            if self._active == run_id:
                self._active = None
            if rec.get("callback_url"):
                nt = asyncio.create_task(self._notify(rec))
                self._tasks.add(nt)
                nt.add_done_callback(self._tasks.discard)

    async def _notify(self, rec: dict[str, Any]) -> None:
        """Fire-and-forget completion POST to an n8n callback URL. Failures are
        logged, not raised — a broken webhook must never affect run status."""
        import httpx

        from core.webhook import auth_headers, validate_webhook_url
        from security_manager import PrivacyGuard

        url = rec["callback_url"]
        try:
            validate_webhook_url(url, "N8N_WEBHOOK_ALLOWLIST")
        except ValueError as exc:
            print(f"n8n callback SSRF guard rejected {url}: {exc}")
            return

        payload = PrivacyGuard.redact({
            "run_id": rec["run_id"],
            "domain": rec["domain"],
            "task": rec["task"],
            "targets": rec["targets"],
            "status": rec["status"],
            "result": rec["result"],
            "error": rec["error"],
            "finished": rec["finished"],
        })

        # Purple runs carry detection-coverage telemetry so n8n can gate/alert on it.
        # Added AFTER redact() intentionally: only base TTP ids (non-PII) and a
        # number go out here — never finding titles/descriptions. Keep it that way,
        # or move any free-text field back through PrivacyGuard.redact first.
        if rec.get("domain") == "purple" and rec.get("state_dir"):
            try:
                from state_manager import StateManager

                sm = StateManager(db_path=str(Path(rec["state_dir"]) / "engagement.db"))
                sm.read()
                cov = sm.get_coverage(sm.active_engagement_id)
                payload["coverage_pct"] = cov["coverage_pct"]
                payload["caught_ttps"] = [c["ttp"] for c in cov["caught"]]
                payload["missed_ttps"] = [m["ttp"] for m in cov["missed"]]
            except Exception as exc:  # best-effort enrichment — never block the POST
                print(f"n8n coverage enrichment failed: {type(exc).__name__}: {exc}")

        headers = auth_headers("N8N_WEBHOOK_TOKEN")
        if not headers:
            print("n8n callback: N8N_WEBHOOK_TOKEN unset — POST will be unauthenticated")
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(url, json=payload, headers=headers, timeout=10)
                response.raise_for_status()
        except Exception as exc:
            print(f"n8n callback POST to {url} failed: {type(exc).__name__}: {exc}")

    async def _invoke(self, domain, task, targets, stealth, proxy_port, brain_tier, apt_profile, state_dir, agent=None, campaign_id=None, tool=None, nmap_args=None, msf_args=None, action_id=None) -> dict:
        """Actual engine call. Isolated for mocking in tests."""
        from state_manager import StateManager

        sm = StateManager(db_path=str(Path(state_dir) / "engagement.db"))
        # remediation acts on an EXISTING engagement's response_actions by id; it
        # must never fabricate an engagement from its sentinel target. Other tools
        # legitimately bootstrap one from a real target/IP.
        if not sm.read() and tool != "remediation":
            sm.initialize_engagement(targets[0] if targets else "unknown", "web dashboard engagement",
                                     campaign_id=campaign_id)

        # Tier 4 tool runs bypass the generic Orchestrator route and invoke the
        # specific agent entrypoint. nmap: PentesterRecon.run_nmap does a sterile
        # scan then an agent loop to record structured results (CLI-parity). The
        # target/args were already validated at the HTTP boundary (core.nmap).
        if tool == "nmap":
            from agents.red.pentester_recon import PentesterRecon

            recon = PentesterRecon(sm, brain_tier=brain_tier)
            # non_interactive=True: HITL already enforced at the HTTP boundary
            # (confirm + scope_gate + unlock). The terminal Confirm.ask would
            # block the uvicorn event loop — the HTTP caller never sees it.
            await recon.run_nmap(targets[0], nmap_args=nmap_args or "-sV", non_interactive=True)
            return {"tool": "nmap", "target": targets[0], "nmap_args": nmap_args or "-sV"}

        # msf: PentesterOS runs the sterile msfconsole command (no agent loop,
        # CLI-parity). Command is built + validated by core.msf; the target/args
        # were already validated at the HTTP boundary before launch.
        if tool == "msf":
            from agents.red.pentester_os import PentesterOS

            from core.msf import build_msf_command

            built = build_msf_command(targets[0], msf_args, stealth)
            pos = PentesterOS(sm)
            # non_interactive=True: see nmap branch — HITL enforced at the HTTP
            # boundary; the blocking Confirm.ask must not run on the event loop.
            output = await pos.run_sterile_command(built["command"], targets[0], proxy_port=proxy_port, non_interactive=True)
            return {"tool": "msf", "target": targets[0], "msf_args": built["msf_extra"], "output": output}

        # remediation: DefenderRes executes a previously approved, allowlisted
        # response action by its DB row id (blue op, no target). action_id was
        # validated at the HTTP boundary (core.remediation); the command
        # allowlist in execute_remediation still gates the actual subprocess.
        if tool == "remediation":
            from agents.blue.defender_res import DefenderRes

            res = DefenderRes(sm, brain_tier=brain_tier)
            output = await res.execute_remediation(action_id)
            return {"tool": "remediation", "action_id": action_id, "output": output}

        from orchestrator import Orchestrator

        orch = Orchestrator(sm)
        return await orch.route(
            task,
            targets=targets,
            stealth=stealth,
            proxy_port=proxy_port,
            brain_tier=brain_tier,
            apt_profile=apt_profile,
            force_domain=domain,
            force_agent=agent,
        )


_manager = RunManager()


def get_run_manager() -> RunManager:
    return _manager
