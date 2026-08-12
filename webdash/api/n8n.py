"""
webdash/api/n8n.py — inbound trigger endpoint for n8n (or any external
orchestrator) to start a red/blue/purple engagement over HTTP.

Mirrors /run/red|blue|purple's guard order in control.py exactly (token +
confirm + kill-switch + agent validation + RoE scope gate), then optionally
registers a callback_url that RunManager posts the completion result to
(see webdash/runner.py's _notify).
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from core.webhook import validate_webhook_url
from webdash.api.control import _launch, _validate_agent
from webdash.data import DashboardData, get_data
from webdash.guards import require_confirm, require_unlocked, scope_gate
from webdash.runner import RunManager, get_run_manager
from webdash.security import require_token

router = APIRouter(prefix="/api/n8n", dependencies=[Depends(require_token)])


class N8nTrigger(BaseModel):
    domain: Literal["red", "blue", "purple"]
    target: str
    task: str = "Full assessment"
    stealth: bool = False
    brain_tier: Literal["local", "expensive"] = "local"
    apt_profile: str | None = None
    agent: str | None = None
    callback_url: str | None = None
    confirm: bool = False


@router.post("/trigger")
async def trigger(
    req: N8nTrigger,
    data: DashboardData = Depends(get_data),
    rm: RunManager = Depends(get_run_manager),
):
    require_confirm(req.confirm)
    require_unlocked(str(data.db_path))
    _validate_agent(req.domain, req.agent)
    if req.domain != "blue":
        scope_gate(req.target, req.task)
    if req.callback_url:
        try:
            validate_webhook_url(req.callback_url, "N8N_WEBHOOK_ALLOWLIST")
        except ValueError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return await _launch(
        rm, domain=req.domain, task=req.task, targets=[req.target],
        stealth=req.stealth, brain_tier=req.brain_tier, apt_profile=req.apt_profile,
        state_dir=str(data.dir), agent=req.agent, callback_url=req.callback_url,
    )
