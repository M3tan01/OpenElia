"""
webdash/api/monitor.py — read-only monitoring endpoints (all token-gated).
"""

from __future__ import annotations

import os

from fastapi import APIRouter, Depends, Query

from webdash.data import DashboardData, get_data, roe as _roe_data
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
def get_engagements(data: DashboardData = Depends(get_data)) -> list[dict]:
    """All engagements (id, target, started, current_phase, is_active, is_locked). Read-only."""
    return data.engagements()


@router.get("/adversaries")
def get_adversaries(data: DashboardData = Depends(get_data)) -> list[dict]:
    """All APT profiles (field-whitelisted). Read-only."""
    return data.adversaries()


@router.get("/actors")
def get_actors(data: DashboardData = Depends(get_data)) -> list[str]:
    return data.actors()


@router.get("/system")
def get_system(data: DashboardData = Depends(get_data)) -> dict:
    """Lightweight system status: gateway health + active engagement count. Read-only."""
    return data.system()


@router.get("/cleanup")
def get_cleanup(data: DashboardData = Depends(get_data)) -> list[dict]:
    """Pending rollback/undo actions for the active engagement (read-only)."""
    from state_manager import StateManager

    sm = StateManager(db_path=str(data.db_path))
    sm.read()
    eid = sm.active_engagement_id
    if not eid:
        return []
    return sm.cleanup_registry.pending(eid)


@router.get("/scope/check")
def scope_check(target: str = Query(..., min_length=1)) -> dict:
    """Dry-run a target against the RoE scope gate. Read-only — never launches."""
    from security_manager import ScopeValidator

    sv = ScopeValidator(roe_path=os.getenv("OPENELIA_ROE_PATH", "roe.json"))
    in_quiet, qmsg = sv.is_within_quiet_hours()
    return {
        "target": target,
        "allowed": bool(sv.is_allowed(target)),
        "quiet_hours_active": bool(in_quiet),
        "quiet_msg": qmsg if in_quiet else "",
    }


@router.get("/playbooks")
def get_playbooks() -> list[dict]:
    """Available declarative engagement playbooks (read-only)."""
    from pathlib import Path

    from core.playbook import Playbook

    out: list[dict] = []
    pdir = Path("playbooks")
    if not pdir.is_dir():
        return out
    for f in sorted(pdir.glob("*.yaml")):
        try:
            pb = Playbook.load(f)
        except Exception:  # nosec B112 — a malformed playbook is skipped, not fatal to the read-only listing
            continue
        out.append({
            "name": pb.name,
            "description": pb.description,
            "domain": pb.domain,
            "passive": pb.passive,
            "stealth": pb.stealth,
            "phases": [
                {"name": ph.name, "tools": ph.tools, "post_analysis": ph.post_analysis}
                for ph in pb.phases
            ],
            "variables": {
                k: {"required": v.required, "description": v.description}
                for k, v in pb.variables.items()
            },
        })
    return out
