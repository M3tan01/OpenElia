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
        }
        self._active = run_id
        t = asyncio.create_task(
            self._execute(run_id, domain, task, targets, stealth, proxy_port, brain_tier, apt_profile, state_dir)
        )
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)
        return run_id

    async def _execute(self, run_id, domain, task, targets, stealth, proxy_port, brain_tier, apt_profile, state_dir):
        rec = self._runs[run_id]
        try:
            rec["result"] = await self._invoke(
                domain, task, targets, stealth, proxy_port, brain_tier, apt_profile, state_dir
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

    async def _invoke(self, domain, task, targets, stealth, proxy_port, brain_tier, apt_profile, state_dir) -> dict:
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
        )


_manager = RunManager()


def get_run_manager() -> RunManager:
    return _manager
