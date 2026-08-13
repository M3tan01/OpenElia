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
        }
        self._active = run_id
        t = asyncio.create_task(
            self._execute(
                run_id=run_id, domain=domain, task=task, targets=targets,
                stealth=stealth, proxy_port=proxy_port, brain_tier=brain_tier,
                apt_profile=apt_profile, agent=agent, state_dir=state_dir,
            )
        )
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)
        return run_id

    async def _execute(self, run_id, domain, task, targets, stealth, proxy_port, brain_tier, apt_profile, state_dir, agent=None):
        rec = self._runs[run_id]
        try:
            rec["result"] = await self._invoke(
                domain=domain, task=task, targets=targets, stealth=stealth,
                proxy_port=proxy_port, brain_tier=brain_tier, apt_profile=apt_profile,
                agent=agent, state_dir=state_dir,
            )
            rec["status"] = "done"
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

        from core.webhook import validate_webhook_url
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

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(url, json=payload, timeout=10)
                response.raise_for_status()
        except Exception as exc:
            print(f"n8n callback POST to {url} failed: {type(exc).__name__}: {exc}")

    async def _invoke(self, domain, task, targets, stealth, proxy_port, brain_tier, apt_profile, state_dir, agent=None) -> dict:
        """Actual engine call. Isolated for mocking in tests."""
        from orchestrator import Orchestrator
        from state_manager import StateManager

        sm = StateManager(db_path=str(Path(state_dir) / "engagement.db"))
        if not sm.read():
            sm.initialize_engagement(targets[0] if targets else "unknown", "web dashboard engagement")
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
