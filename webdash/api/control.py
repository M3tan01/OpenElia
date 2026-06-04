"""
webdash/api/control.py — state-changing control endpoints (token + confirm gated).

Red/purple additionally pass the RoE scope gate and the kill-switch check before
Orchestrator.route() is launched as a background run.
"""

from __future__ import annotations

import os
import re
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


class ForgeRun(BaseModel):
    actor: str
    brain_tier: str = "local"
    auto_commit: bool = False
    confirm: bool = False


class PlaybookRun(BaseModel):
    name: str
    target: str | None = None
    variables: dict[str, str] = {}
    stealth: bool = False
    brain_tier: Literal["local", "expensive"] = "local"
    confirm: bool = False


class PlaybookVarReq(BaseModel):
    required: bool = False
    description: str = ""


class PlaybookPhaseReq(BaseModel):
    name: str
    tools: list[str] = []
    post_analysis: str | None = None


class PlaybookCreate(BaseModel):
    name: str
    description: str = ""
    domain: Literal["red", "blue", "purple"] = "red"
    passive: bool = False
    stealth: bool = False
    brain_tier: Literal["local", "expensive"] = "local"
    apt_profile: str | None = None
    variables: dict[str, PlaybookVarReq] = {}
    phases: list[PlaybookPhaseReq]
    overwrite: bool = False
    confirm: bool = False


class StixParse(BaseModel):
    content: str


_STIX_MAX_BYTES = 8_000_000  # 8 MB cap on uploaded STIX content


@router.post("/stix/parse")
def stix_parse(req: StixParse) -> dict:
    """Parse an uploaded STIX bundle into a hunt brief. Read-only — extracts
    IOCs/TTPs/actors and a composed hunt task for operator review. Does NOT run
    anything (the operator launches the hunt via /run/blue after preview)."""
    if len(req.content.encode("utf-8", "ignore")) > _STIX_MAX_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            detail="STIX file too large (8 MB cap)")

    from core.stix_ingest import compose_hunt_task, parse_stix

    try:
        brief = parse_stix(req.content)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc))
    brief["hunt_task"] = compose_hunt_task(brief)
    return brief


class IocListParse(BaseModel):
    content: str


@router.post("/ioc/parse")
def ioc_parse(req: IocListParse) -> dict:
    """Parse a plain IOC list into a hunt brief. Read-only — extracts IOCs and
    composes a hunt task for operator review. No TTPs/actors/malware extraction
    (a plain list carries none). Does NOT launch anything."""
    if len(req.content.encode("utf-8", "ignore")) > _STIX_MAX_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            detail="IOC list too large (8 MB cap)")

    from core.stix_ingest import compose_hunt_task, parse_ioc_list

    try:
        brief = parse_ioc_list(req.content)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc))
    brief["hunt_task"] = compose_hunt_task(brief)
    return brief


class Confirm(BaseModel):
    confirm: bool = False


_PLAYBOOK_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


@router.post("/playbooks")
def create_playbook(req: PlaybookCreate) -> dict:
    """Author a new playbook from the dashboard. Token + confirm gated; the name
    is sanitized and the content is validated through the Playbook model before
    anything is written under playbooks/."""
    require_confirm(req.confirm)
    if not _PLAYBOOK_NAME_RE.match(req.name):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="name must be lowercase alphanumeric with _ or - (no path separators)",
        )

    from pathlib import Path

    import yaml

    from core.playbook import Playbook

    # Validate by constructing the model (enforces domain + non-empty phases).
    try:
        pb = Playbook(
            name=req.name,
            description=req.description,
            domain=req.domain,
            passive=req.passive,
            stealth=req.stealth,
            brain_tier=req.brain_tier,
            apt_profile=req.apt_profile,
            variables={k: {"required": v.required, "description": v.description}
                       for k, v in req.variables.items()},
            phases=[{"name": p.name, "tools": p.tools, "post_analysis": p.post_analysis}
                    for p in req.phases],
        )
    except Exception as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"invalid playbook: {exc}")

    pdir = Path("playbooks")
    pdir.mkdir(exist_ok=True)
    dest = (pdir / f"{req.name}.yaml").resolve()
    # Defense-in-depth: the resolved path must stay inside playbooks/.
    if pdir.resolve() not in dest.parents:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="invalid playbook path")
    if dest.exists() and not req.overwrite:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"playbook '{req.name}' already exists (set overwrite to replace)",
        )

    dest.write_text(yaml.safe_dump(pb.model_dump(), sort_keys=False))
    return {"name": req.name, "saved": f"playbooks/{req.name}.yaml"}


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


@router.post("/forge")
async def run_forge(req: ForgeRun, data: DashboardData = Depends(get_data)) -> dict:
    # Forge only reads + generates a profile; it does NOT launch ops, so it needs
    # token + confirm but not scope_gate. Running the forged profile later still
    # goes through the gated /run/* endpoints.
    require_confirm(req.confirm)
    from adversary_forge import AdversaryForge
    from adversary_schema import AdversaryProfile, make_stem, save_profile

    result = await AdversaryForge().forge(req.actor, brain_tier=req.brain_tier)
    profile = AdversaryProfile(**result["profile"])  # unified schema gate
    saved_path = None
    if req.auto_commit:
        try:
            saved_path = save_profile(profile, make_stem(req.actor))
        except ValueError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return {
        "profile": profile.model_dump(),
        "omitted": result["omitted"],
        "metadata": result["metadata"],
        "saved_path": saved_path,
    }


@router.post("/run/playbook")
async def run_playbook(req: PlaybookRun, data: DashboardData = Depends(get_data), rm: RunManager = Depends(get_run_manager)):
    require_confirm(req.confirm)
    require_unlocked(str(data.db_path))

    from pathlib import Path

    from core.playbook import Playbook

    pb_path = Path("playbooks") / f"{req.name}.yaml"
    try:
        pb = Playbook.load(pb_path)
    except FileNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"playbook '{req.name}' not found")

    values = dict(req.variables)
    if req.target:
        values["target"] = req.target
    try:
        values = pb.resolve_variables(values)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc))

    task = pb.compose_task(values)
    target = values.get("target", "unknown")
    # Offensive playbooks pass the RoE scope gate before launch.
    if pb.domain in ("red", "purple"):
        scope_gate(target, task)
    return await _launch(
        rm, domain=pb.domain, task=task, targets=[target],
        stealth=req.stealth or pb.stealth, brain_tier=req.brain_tier,
        apt_profile=pb.apt_profile, state_dir=str(data.dir),
    )


class AdversaryCreate(BaseModel):
    name: str
    alias: str = ""
    description: str = ""
    preferred_ttps: list[str] = []
    tools: list[str] = []
    stealth_required: bool = False
    rationale: str = ""
    overwrite: bool = False
    confirm: bool = False


@router.post("/adversaries")
def create_adversary(req: AdversaryCreate) -> dict:
    """Author a custom adversary profile from the dashboard. Token + confirm gated;
    validated via AdversaryProfile and written through save_profile's traversal
    guards. No-overwrite by default."""
    require_confirm(req.confirm)
    if not req.name.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="name is required")

    from pathlib import Path

    from adversary_schema import AdversaryProfile, make_stem, save_profile

    try:
        profile = AdversaryProfile(
            name=req.name,
            alias=req.alias,
            description=req.description,
            preferred_ttps=req.preferred_ttps,
            tools=req.tools,
            stealth_required=req.stealth_required,
            rationale=req.rationale,
        )
    except Exception as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"invalid adversary: {exc}")

    adv_dir = os.getenv("OPENELIA_ADVERSARIES_DIR", "adversaries")
    stem = make_stem(req.name)
    if (Path(adv_dir) / f"{stem}.json").exists() and not req.overwrite:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"adversary '{stem}' already exists (set overwrite to replace)",
        )
    try:
        save_profile(profile, stem, adversaries_dir=adv_dir)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return {"name": profile.name, "stem": stem, "saved": f"{adv_dir}/{stem}.json"}


class AdversaryDelete(BaseModel):
    stem: str
    confirm: bool = False


@router.post("/adversaries/delete")
def delete_adversary(req: AdversaryDelete) -> dict:
    """Delete a custom/forged adversary profile by file stem. Token + confirm
    gated; the stem is validated and realpath-checked to stay inside the
    adversaries dir (no traversal)."""
    require_confirm(req.confirm)

    from adversary_manager import AdversaryManager

    adv_dir = os.getenv("OPENELIA_ADVERSARIES_DIR", "adversaries")
    mgr = AdversaryManager(adversaries_dir=adv_dir)
    safe = req.stem.lower()
    if not mgr._APT_NAME_RE.fullmatch(safe):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="invalid profile name")
    path = os.path.realpath(os.path.join(mgr.adversaries_dir, f"{safe}.json"))
    if not path.startswith(mgr.adversaries_dir + os.sep):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="path traversal detected")
    if not os.path.exists(path):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"profile '{safe}' not found")
    os.remove(path)
    return {"deleted": safe}


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

    sm = StateManager(db_path=str(data.db_path))
    sm.read()
    sm.set_locked(True)
    AuditLogger(log_path=str(data.audit_log)).log_event(
        "webdash", "SYSTEM", "", "LOCKED", "kill-switch engaged via dashboard"
    )

    # Fire registered rollback actions (LIFO, firewall-gated). Cleanup must never
    # mask the kill-switch itself, so any error is swallowed into the summary.
    cleanup = {"executed": 0, "refused": 0, "failed": 0, "pending": 0}
    try:
        if sm.active_engagement_id:
            for s in sm.cleanup_registry.run_all(sm.active_engagement_id):
                if s["status"] in cleanup:
                    cleanup[s["status"]] += 1
    except Exception:  # nosec B110 — cleanup failure must not block the lock
        pass
    return {"locked": True, "cleanup": cleanup}


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
