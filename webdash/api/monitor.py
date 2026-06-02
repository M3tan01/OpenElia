"""
webdash/api/monitor.py — read-only monitoring endpoints (all token-gated).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from webdash.data import (
    DashboardData,
    get_data,
    roe as _roe_data,
    engagements as _engagements_data,
    adversaries as _adversaries_data,
    system as _system_data,
)
from webdash.security import require_token

router = APIRouter(prefix="/api", dependencies=[Depends(require_token)])


@router.get("/state")
def get_state(data: DashboardData = Depends(get_data)) -> dict:
    """Current engagement snapshot (engagement, phases, findings, blue alerts, pivots)."""
    return data.state()


@router.get("/audit")
def get_audit(
    limit: int = Query(200, ge=1, le=2000),
    data: DashboardData = Depends(get_data),
) -> dict:
    """Recent audit events + HMAC chain-integrity status."""
    return data.audit(limit)


@router.get("/tasks")
def get_tasks(
    limit: int = Query(200, ge=1, le=2000),
    data: DashboardData = Depends(get_data),
) -> list[dict]:
    """Recent agent task results."""
    return data.tasks(limit)


@router.get("/graph")
def get_graph(data: DashboardData = Depends(get_data)) -> dict:
    """Attack-surface graph (nodes/links) + summary counts."""
    return data.graph()


@router.get("/heatmap")
def get_heatmap(data: DashboardData = Depends(get_data)) -> dict:
    """MITRE ATT&CK tactic coverage from current findings."""
    return data.heatmap()


@router.get("/cost")
def get_cost(data: DashboardData = Depends(get_data)) -> dict:
    """Cost summary + per-session series."""
    return data.cost()


@router.get("/chain/verify")
def verify_chain(data: DashboardData = Depends(get_data)) -> dict:
    """Audit-log tamper-evidence check."""
    result = data.audit(limit=1)
    return {
        "chain_ok": result["chain_ok"],
        "chain_status": result["chain_status"],
        "chain_msg": result["chain_msg"],
    }


@router.get("/roe")
def get_roe() -> dict:
    """Read-only RoE scope config (field-whitelisted; never leaks secrets)."""
    return _roe_data()


@router.get("/engagements")
def get_engagements() -> list[dict]:
    """All engagements (id, target, started, current_phase, is_active, is_locked). Read-only."""
    return _engagements_data()


@router.get("/adversaries")
def get_adversaries() -> list[dict]:
    """All APT profiles (field-whitelisted). Read-only."""
    return _adversaries_data()


@router.get("/system")
def get_system() -> dict:
    """Lightweight system status: gateway health + active engagement count. Read-only."""
    return _system_data()
