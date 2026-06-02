"""
webdash/guards.py — control-action guards (shared by control + models routers).

Layers applied to every state-changing endpoint (composed inline per route):
  1. require_token (router dependency) — bearer auth.
  2. require_confirm — explicit confirm:true in the body (HITL).
  3. scope_gate — ScopeValidator (RoE): target in authorized scope, not blacklisted,
     not quiet hours. Audited either way (red/purple only).
  4. require_unlocked — refuse while the kill-switch is engaged.
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import HTTPException, status


def roe_path() -> str:
    return os.getenv("OPENELIA_ROE_PATH", "roe.json")


def _audit_path() -> str:
    return str(Path(os.getenv("OPENELIA_STATE_DIR", "state")) / "audit.log")


def require_confirm(confirm: bool) -> None:
    """HITL gate — control actions must be explicitly confirmed."""
    if not confirm:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="confirm=true is required for control actions",
        )


def scope_gate(target: str, task: str) -> None:
    """Enforce RoE for a targeted (red/purple) action. Raises 403 on violation."""
    from security_manager import AuditLogger, ScopeValidator

    validator = ScopeValidator(roe_path=roe_path())
    audit = AuditLogger(log_path=_audit_path())

    if target and not validator.is_allowed(target):
        audit.log_event("webdash", target, task, "DENIED", "Out of RoE scope")
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=f"target {target} not in authorized scope")

    is_quiet, msg = validator.is_within_quiet_hours()
    if is_quiet:
        audit.log_event("webdash", target or "-", task, "DENIED", "Quiet hours")
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=f"RoE quiet hours active: {msg}")

    audit.log_event("webdash", target or "-", task, "AUTHORIZED", "Web control authorized")


def require_unlocked(db_path: str) -> None:
    """Refuse control if the engagement kill-switch is engaged. Raises 423."""
    from state_manager import StateManager

    if StateManager(db_path=db_path).is_locked():
        raise HTTPException(status.HTTP_423_LOCKED, detail="engine is locked (kill-switch active)")
