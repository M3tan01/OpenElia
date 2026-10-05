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

from webdash.data import AGENT_REGISTRY, DashboardData, get_data
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
    agent: str | None = None
    confirm: bool = False


class BlueRun(BaseModel):
    task: str
    target: str | None = None
    brain_tier: Literal["local", "expensive"] = "local"
    apt_profile: str | None = None
    agent: str | None = None
    confirm: bool = False


class PurpleRun(BaseModel):
    target: str
    task: str = "Purple-team simulation"
    stealth: bool = False
    brain_tier: Literal["local", "expensive"] = "local"
    proxy_port: int | None = None
    apt_profile: str | None = None
    agent: str | None = None
    campaign_id: str | None = None
    confirm: bool = False


def _validate_agent(domain: str, agent: str | None) -> None:
    """Raise HTTP 400 if agent is set but does not belong to domain.

    purple accepts agents from both red and blue sets.
    """
    if agent is None:
        return
    if domain == "red":
        allowed = set(AGENT_REGISTRY["red"])
    elif domain == "blue":
        allowed = set(AGENT_REGISTRY["blue"])
    else:  # purple
        allowed = set(AGENT_REGISTRY["red"]) | set(AGENT_REGISTRY["blue"])
    if agent not in allowed:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail=f"unknown agent '{agent}' for domain '{domain}'",
        )


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
    _validate_agent("red", req.agent)
    scope_gate(req.target, req.task)
    return await _launch(
        rm, domain="red", task=req.task, targets=[req.target], stealth=req.stealth,
        proxy_port=req.proxy_port, brain_tier=req.brain_tier, apt_profile=req.apt_profile,
        state_dir=str(data.dir), agent=req.agent,
    )


@router.post("/run/blue")
async def run_blue(req: BlueRun, data: DashboardData = Depends(get_data), rm: RunManager = Depends(get_run_manager)):
    require_confirm(req.confirm)
    require_unlocked(str(data.db_path))  # defensive ops still respect the kill-switch
    _validate_agent("blue", req.agent)
    return await _launch(
        rm, domain="blue", task=req.task, targets=[req.target or "unknown"],
        brain_tier=req.brain_tier, apt_profile=req.apt_profile, state_dir=str(data.dir),
        agent=req.agent,
    )


@router.post("/run/purple")
async def run_purple(req: PurpleRun, data: DashboardData = Depends(get_data), rm: RunManager = Depends(get_run_manager)):
    require_confirm(req.confirm)
    require_unlocked(str(data.db_path))
    _validate_agent("purple", req.agent)
    scope_gate(req.target, req.task)
    return await _launch(
        rm, domain="purple", task=req.task, targets=[req.target], stealth=req.stealth,
        proxy_port=req.proxy_port, brain_tier=req.brain_tier, apt_profile=req.apt_profile,
        state_dir=str(data.dir), agent=req.agent, campaign_id=req.campaign_id,
    )


class NmapRun(BaseModel):
    target: str
    args: str = "-sV"
    stealth: bool = False
    brain_tier: str = "local"
    proxy_port: int | None = None
    confirm: bool = False


@router.post("/nmap")
async def run_nmap(req: NmapRun, data: DashboardData = Depends(get_data), rm: RunManager = Depends(get_run_manager)):
    """Tier 4 dangerous op — launch a sterile nmap scan as a tracked background run.

    Guards mirror /run/red because nmap traverses the agent tool loop + kill-switch:
    require_token (router) + require_confirm (400) + require_unlocked (423) +
    scope_gate (403, target must be in RoE scope). Target + args are validated at
    the boundary via core.nmap.validate_nmap_request (400) BEFORE the run launches,
    so a malformed or injection-laden command line never reaches the sterile executor.
    """
    require_confirm(req.confirm)
    require_unlocked(str(data.db_path))
    from core.nmap import validate_nmap_request

    try:
        validate_nmap_request(req.target, req.args)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc))
    scope_gate(req.target, f"nmap {req.args}")
    return await _launch(
        rm, domain="red", task=f"nmap scan {req.target}", targets=[req.target],
        stealth=req.stealth, proxy_port=req.proxy_port, brain_tier=req.brain_tier,
        state_dir=str(data.dir), tool="nmap", nmap_args=req.args,
    )


class MsfRun(BaseModel):
    target: str
    args: str | None = None
    stealth: bool = False
    brain_tier: str = "local"
    proxy_port: int | None = None
    confirm: bool = False


@router.post("/msf")
async def run_msf(req: MsfRun, data: DashboardData = Depends(get_data), rm: RunManager = Depends(get_run_manager)):
    """Tier 4 dangerous op — launch a sterile Metasploit run as a tracked background run.

    Guards mirror /run/red and /api/nmap: require_token (router) + require_confirm
    (400) + require_unlocked (423) + scope_gate (403, target must be in RoE scope).
    core.msf.build_msf_command validates the target + builds the quoted command at
    the boundary (400) BEFORE launch, so a malformed target or an injection-laden
    args string never reaches the sterile executor.
    """
    require_confirm(req.confirm)
    require_unlocked(str(data.db_path))
    from core.msf import build_msf_command

    try:
        build_msf_command(req.target, req.args, req.stealth)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc))
    scope_gate(req.target, f"msf {req.args or 'show options'}")
    return await _launch(
        rm, domain="red", task=f"msf run {req.target}", targets=[req.target],
        stealth=req.stealth, proxy_port=req.proxy_port, brain_tier=req.brain_tier,
        state_dir=str(data.dir), tool="msf", msf_args=req.args,
    )


class RemediationRun(BaseModel):
    action_id: int
    brain_tier: str = "local"
    confirm: bool = False


@router.post("/execute-remediation")
async def run_execute_remediation(req: RemediationRun, data: DashboardData = Depends(get_data), rm: RunManager = Depends(get_run_manager)):
    """Tier 4 dangerous op — execute a previously approved response action by DB id.

    Blue op: it runs an allowlisted remediation command, not an offensive action
    against a target, so the guard stack is require_token (router) + require_confirm
    (400) + require_unlocked (423, defensive ops still respect the kill-switch) with
    NO scope_gate (there is no target to range against RoE). action_id is validated
    at the boundary via core.remediation.validate_action_id (400) BEFORE launch; the
    command allowlist in DefenderRes.execute_remediation still gates the subprocess.
    """
    require_confirm(req.confirm)
    require_unlocked(str(data.db_path))
    from core.remediation import validate_action_id

    try:
        action_id = validate_action_id(req.action_id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return await _launch(
        rm, domain="blue", task=f"execute remediation action {action_id}",
        targets=["remediation"], brain_tier=req.brain_tier,
        state_dir=str(data.dir), tool="remediation", action_id=action_id,
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


class ReportBrief(BaseModel):
    brain_tier: Literal["local", "expensive"] = "local"
    confirm: bool = False


@router.post("/report/brief")
async def report_brief(req: ReportBrief, data: DashboardData = Depends(get_data)) -> dict:
    """Generate a concise LLM executive brief over current engagement findings.
    Token + confirm gated. Read-only generation — no artifact saved."""
    require_confirm(req.confirm)
    # The brief routes through the agent tool loop, which calls _check_kill_switch
    # (raises SystemExit — a BaseException that would NOT convert to a clean HTTP
    # response). Reject up front with a clean 423 when the engine is locked.
    require_unlocked(str(data.db_path))
    from state_manager import StateManager
    from agents.reporter_agent import ReporterAgent

    sm = StateManager(db_path=str(data.db_path))
    state = sm.read()
    findings = state.get("findings", []) if state else []
    md = await ReporterAgent(sm, brain_tier=req.brain_tier).brief(findings)
    return {"markdown": md}


class ReportFull(BaseModel):
    brain_tier: Literal["local", "expensive"] = "local"
    confirm: bool = False


@router.post("/report/full")
async def report_full(req: ReportFull, data: DashboardData = Depends(get_data)) -> dict:
    """Generate the full engagement report (executive summary, MITRE heatmap,
    forensic chain of custody) over current state. Token + confirm gated. Unlike
    the brief, run() persists two artifacts (report .md + heatmap .json) as a
    side effect — matching the CLI `report` command."""
    require_confirm(req.confirm)
    # run() drives the agent tool loop, which calls _check_kill_switch (raises
    # SystemExit — a BaseException that would NOT convert to a clean HTTP
    # response). Reject up front with a clean 423 when the engine is locked.
    require_unlocked(str(data.db_path))
    from state_manager import StateManager
    from agents.reporter_agent import ReporterAgent

    sm = StateManager(db_path=str(data.db_path))
    if not sm.read():
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="no active engagement — run a red or blue engagement first",
        )
    md = await ReporterAgent(sm, brain_tier=req.brain_tier).run(
        "Generate full engagement report with MITRE heatmap and forensic chain of custody."
    )
    return {"markdown": md}


class ArchiveReq(BaseModel):
    brain_tier: Literal["local", "expensive"] = "local"
    confirm: bool = False


@router.post("/archive")
async def archive(req: ArchiveReq, data: DashboardData = Depends(get_data)) -> dict:
    """Package the engagement (state DB, audit log, SBOM, recovered artifacts) into
    a forensic zip and return {engagement_id, archive_path, sha256}. Token + confirm
    gated. Like report/full, run() drives the agent tool loop (kill-switch raises
    SystemExit, a BaseException that would NOT convert to a clean HTTP response), so
    reject up front with 423 when locked. Mirrors the CLI `archive` command; the zip
    is written under the API's configured state dir (data.dir), not a hardcoded path."""
    require_confirm(req.confirm)
    require_unlocked(str(data.db_path))
    from state_manager import StateManager
    from agents.reporter_agent import ReporterAgent
    from core.archive import build_case_archive

    sm = StateManager(db_path=str(data.db_path))
    state = sm.read()
    if not state:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="no active engagement — run a red or blue engagement first",
        )
    summary = await ReporterAgent(sm, brain_tier=req.brain_tier).run(
        "Generate the final executive case summary for the engagement archive."
    )
    return build_case_archive(state, state_dir=str(data.dir), summary=summary)


class ModelSet(BaseModel):
    tier: Literal["local", "cloud"]
    model: str
    provider: str | None = None
    confirm: bool = False


@router.post("/model/set")
def model_set(req: ModelSet) -> dict:
    """Switch the active brain model. Config-file mutation only — no target and
    no agent tool loop, so token + confirm are the only guards (no kill-switch
    or RoE scope path applies). Mirrors the CLI `model set` command; returns the
    resulting config. Provider is validated against SUPPORTED_PROVIDERS here so
    the network surface never trusts an arbitrary provider string."""
    require_confirm(req.confirm)
    from model_manager import ModelManager, SUPPORTED_PROVIDERS

    if req.tier == "local":
        ModelManager.set_local_model(req.model)
    else:  # cloud
        if not req.provider:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail="provider is required for tier=cloud",
            )
        provider = req.provider.lower()
        if provider not in SUPPORTED_PROVIDERS:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail=f"unknown provider '{req.provider}'; supported: {SUPPORTED_PROVIDERS}",
            )
        ModelManager.set_cloud_model(provider, req.model)
    return {"config": ModelManager.get_config()}


class GrantReq(BaseModel):
    user: str = "operator"
    # role is signed into a bearer credential, so constrain it at the boundary —
    # see core/grant.py's credential-injection note. Literal → 422 on anything else.
    role: Literal["admin", "security_lead", "red_team_lead"] = "red_team_lead"
    ttl_hours: float = 12.0
    revoke: bool = False
    confirm: bool = False


@router.post("/grant")
def grant_session(req: GrantReq, data: DashboardData = Depends(get_data)) -> dict:
    """Mint (or revoke) the signed IdP session authorizing red/purple ops.

    CREDENTIAL-INJECTION RESIDUAL RISK: this MINTS an offensive-authorization
    bearer credential — the most sensitive Tier 3 surface. It is NOT bound to a
    host/user, so any holder of the webdash bearer token who clears this gate can
    self-grant red/purple authority (privilege bootstrap). Guards: router-level
    require_token (401) + require_confirm (400); `role` is constrained by the
    GrantReq Literal and re-checked in core/grant.py. No agent tool loop → no
    require_unlocked; no target → no scope_gate (grant is what *creates* the scope
    authority scope_gate later checks). The OS-root gate still applies at red/purple
    *execution*, not here. See core/grant.py for the full threat note."""
    require_confirm(req.confirm)
    from core.grant import mint_grant_session, revoke_grant_session

    if req.revoke:
        return revoke_grant_session(state_dir=str(data.dir))
    return mint_grant_session(
        req.user, req.role, req.ttl_hours, state_dir=str(data.dir)
    )


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


@router.post("/engagements/{engagement_id}/terminate")
def terminate_engagement(
    engagement_id: str, req: Confirm, data: DashboardData = Depends(get_data)
) -> dict:
    """Gracefully end an engagement: fire its rollback queue (LIFO, firewall-gated),
    mark it inactive, stop open phases, and audit the action. Does NOT delete data.
    Confirm-gated (HITL). 404 if the engagement id is unknown."""
    require_confirm(req.confirm)
    from security_manager import AuditLogger
    from state_manager import StateManager

    if engagement_id not in {e["id"] for e in data.engagements()}:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="unknown engagement id")

    sm = StateManager(db_path=str(data.db_path))
    sm.read()

    # Roll back registered offensive actions for THIS engagement before ending it.
    # Mirrors the kill-switch contract but scoped to one session. Cleanup failure
    # must never block the terminate itself.
    cleanup = {"executed": 0, "refused": 0, "failed": 0, "pending": 0}
    try:
        for s in sm.cleanup_registry.run_all(engagement_id):
            if s["status"] in cleanup:
                cleanup[s["status"]] += 1
    except Exception:  # nosec B110 — cleanup failure must not block terminate
        pass

    sm.end_engagement(engagement_id)
    AuditLogger(log_path=str(data.audit_log)).log_event(
        "webdash", "SYSTEM", engagement_id, "TERMINATED",
        "engagement ended via dashboard",
    )
    return {"terminated": True, "engagement_id": engagement_id, "cleanup": cleanup}
