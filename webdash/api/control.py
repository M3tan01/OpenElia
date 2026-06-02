"""
webdash/api/control.py — state-changing control endpoints (token + confirm gated).

Red/purple additionally pass the RoE scope gate and the kill-switch check before
Orchestrator.route() is launched as a background run.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from webdash.data import DashboardData, get_data
from webdash.guards import require_confirm, require_unlocked, scope_gate
from webdash.runner import RunManager, get_run_manager
from webdash.security import require_token

router = APIRouter(prefix="/api", dependencies=[Depends(require_token)])


class RedRun(BaseModel):
    target: str
    task: str = "Full assessment"
    stealth: bool = False
    brain_tier: Literal["local", "expensive"] = "local"
    proxy_port: int | None = None
    apt_profile: str | None = None
    confirm: bool = False


class BlueRun(BaseModel):
    task: str
    target: str | None = None
    brain_tier: Literal["local", "expensive"] = "local"
    apt_profile: str | None = None
    confirm: bool = False


class PurpleRun(BaseModel):
    target: str
    task: str = "Purple-team simulation"
    stealth: bool = False
    brain_tier: Literal["local", "expensive"] = "local"
    proxy_port: int | None = None
    apt_profile: str | None = None
    confirm: bool = False


class Confirm(BaseModel):
    confirm: bool = False


async def _launch(rm: RunManager, **kwargs) -> dict:
    try:
        run_id = await rm.start(**kwargs)
    except RuntimeError as exc:  # an active run already exists
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc))
    return {"run_id": run_id, "status": "started"}


@router.post("/run/red")
async def run_red(req: RedRun, data: DashboardData = Depends(get_data), rm: RunManager = Depends(get_run_manager)):
    require_confirm(req.confirm)
    require_unlocked(str(data.db_path))
    scope_gate(req.target, req.task)
    return await _launch(
        rm, domain="red", task=req.task, targets=[req.target], stealth=req.stealth,
        proxy_port=req.proxy_port, brain_tier=req.brain_tier, apt_profile=req.apt_profile, state_dir=str(data.dir),
    )


@router.post("/run/blue")
async def run_blue(req: BlueRun, data: DashboardData = Depends(get_data), rm: RunManager = Depends(get_run_manager)):
    require_confirm(req.confirm)
    require_unlocked(str(data.db_path))  # defensive ops still respect the kill-switch
    return await _launch(
        rm, domain="blue", task=req.task, targets=[req.target or "unknown"],
        brain_tier=req.brain_tier, apt_profile=req.apt_profile, state_dir=str(data.dir),
    )


@router.post("/run/purple")
async def run_purple(req: PurpleRun, data: DashboardData = Depends(get_data), rm: RunManager = Depends(get_run_manager)):
    require_confirm(req.confirm)
    require_unlocked(str(data.db_path))
    scope_gate(req.target, req.task)
    return await _launch(
        rm, domain="purple", task=req.task, targets=[req.target], stealth=req.stealth,
        proxy_port=req.proxy_port, brain_tier=req.brain_tier, apt_profile=req.apt_profile, state_dir=str(data.dir),
    )


@router.get("/run/{run_id}/status")
def run_status(run_id: str, rm: RunManager = Depends(get_run_manager)) -> dict:
    rec = rm.get(run_id)
    if not rec:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="unknown run id")
    return rec


@router.post("/lock")
def lock(req: Confirm, data: DashboardData = Depends(get_data)) -> dict:
    require_confirm(req.confirm)
    from security_manager import AuditLogger
    from state_manager import StateManager

    StateManager(db_path=str(data.db_path)).set_locked(True)
    AuditLogger(log_path=str(data.audit_log)).log_event(
        "webdash", "SYSTEM", "", "LOCKED", "kill-switch engaged via dashboard"
    )
    return {"locked": True}


@router.post("/unlock")
def unlock(req: Confirm, data: DashboardData = Depends(get_data)) -> dict:
    require_confirm(req.confirm)
    from security_manager import AuditLogger
    from state_manager import StateManager

    StateManager(db_path=str(data.db_path)).set_locked(False)
    AuditLogger(log_path=str(data.audit_log)).log_event(
        "webdash", "SYSTEM", "", "UNLOCKED", "kill-switch released via dashboard"
    )
    return {"locked": False}
