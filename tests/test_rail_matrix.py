"""
tests/test_rail_matrix.py — enforcement-rail matrix for the two security rails.

OpenElia enforces security across TWO rails that are easy to drift apart:

  * Engine rail  — security_manager.enforce_security_gate(source, target, payload)
                   Order: (1) scope → (2) quiet-hours → (3) prohibited-tool →
                   (4) semantic-firewall → audit AUTHORIZED.
  * Webdash rail — webdash.guards (require_confirm → scope_gate → require_unlocked)
                   composed per state-changing route.

This module asserts, table-driven:
  1. each rail rejects the condition it owns, with the right reason,
  2. rail ORDER (fail-closed composition): when a request violates several rails
     the EARLIEST one wins, so nothing leaks past the first failed check,
  3. every block is audited with the payload PII-redacted,
  4. the webdash kill-switch guard (require_unlocked) refuses when locked,
  5. a DESIGN INVARIANT (finding #6, reviewed): the engine rail does NOT consult
     the kill-switch — by design. The kill-switch is enforced at the agent layer
     (BaseAgent._check_kill_switch, before every tool + reasoning turn) and the
     webdash rail (require_unlocked). The shared gate stays exempt so cleanup
     rollback (which runs WHILE locked) can pass through it without deadlocking.

Runs under conftest's autouse bypass (OPENELIA_ALLOW_UNSIGNED_ROE=1), so the RoE
fixtures here are plain/unsigned; strict RoE signing is covered by
test_roe_signing.py. AUDIT_HMAC_KEY and OPENELIA_STATE_DIR are also supplied by
conftest, so the HMAC audit chain writes into a per-test tmp sandbox.
"""
import datetime as _dt
import json
import os
from pathlib import Path

import pytest

import security_manager
from security_manager import ScopeValidator, enforce_security_gate


# --------------------------------------------------------------------------- #
# Fixtures / helpers
# --------------------------------------------------------------------------- #

def _roe_body(**overrides):
    body = {
        "authorized_subnets": ["10.0.0.0/24"],
        "blacklisted_ips": [],
        "prohibited_tools": [],
        "quiet_hours": {"enabled": False},
    }
    body.update(overrides)
    return body


@pytest.fixture
def roe(tmp_path, monkeypatch):
    """Write a roe.json and point the engine gate (via env) at it."""
    def _write(doc):
        p = tmp_path / "roe.json"
        p.write_text(json.dumps(doc))
        monkeypatch.setenv("OPENELIA_ROE_PATH", str(p))
        ScopeValidator._resolution_cache.clear()
        return str(p)

    yield _write
    ScopeValidator._resolution_cache.clear()


@pytest.fixture
def frozen_noon(monkeypatch):
    """Freeze security_manager's clock to noon so quiet-hours windows are
    deterministic regardless of when the suite runs."""
    class _FrozenDT:
        @staticmethod
        def now(tz=None):
            return _dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=tz)

        @staticmethod
        def strptime(value, fmt):
            return _dt.datetime.strptime(value, fmt)

    monkeypatch.setattr(security_manager, "datetime", _FrozenDT)


def _audit_records():
    p = Path(os.getenv("OPENELIA_STATE_DIR", "state")) / "audit.log"
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text().splitlines() if line.strip()]


# --------------------------------------------------------------------------- #
# 1. Each engine rail blocks its own condition (table-driven)
# --------------------------------------------------------------------------- #

class TestEngineRailBlocks:
    def test_in_scope_safe_request_authorized(self, roe):
        roe(_roe_body())
        assert enforce_security_gate("nmap", "10.0.0.5", "nmap -sV 10.0.0.5") is True
        rec = _audit_records()[-1]
        assert rec["status"] == "AUTHORIZED"
        assert rec["reason"] == "Passed security checks"

    def test_rail1_out_of_scope_target_blocked(self, roe):
        roe(_roe_body())
        with pytest.raises(PermissionError, match="Mathematical Boundary Breach"):
            enforce_security_gate("nmap", "8.8.8.8", "nmap -sV 8.8.8.8")
        assert _audit_records()[-1]["reason"] == "Mathematical Boundary Breach"

    def test_rail2_quiet_hours_blocked(self, roe, frozen_noon):
        roe(_roe_body(quiet_hours={
            "enabled": True, "start": "00:00", "end": "23:59",
            "message": "maintenance window",
        }))
        with pytest.raises(PermissionError, match="Rules of Engagement Breach"):
            enforce_security_gate("nmap", "10.0.0.5", "nmap -sV 10.0.0.5")
        assert _audit_records()[-1]["reason"] == "Quiet Hours Breach"

    def test_rail3_prohibited_tool_blocked(self, roe):
        roe(_roe_body(prohibited_tools=["msf"]))
        with pytest.raises(PermissionError, match="prohibited by policy"):
            enforce_security_gate("msf", "10.0.0.5", "exploit/multi/handler")
        assert _audit_records()[-1]["reason"] == "Prohibited Tool Usage"

    def test_rail4_destructive_payload_blocked(self, roe):
        roe(_roe_body())
        with pytest.raises(PermissionError, match="Semantic Firewall Breach"):
            enforce_security_gate("shell", "10.0.0.5", "rm -rf /")
        assert _audit_records()[-1]["reason"] == "Destructive Payload Detected"


# --------------------------------------------------------------------------- #
# 2. Rail ORDER — the earliest violated rail wins (fail-closed composition)
# --------------------------------------------------------------------------- #

class TestEngineRailOrder:
    def test_scope_beats_firewall(self, roe):
        """Out-of-scope AND destructive → rejected at scope (rail 1), not firewall."""
        roe(_roe_body())
        with pytest.raises(PermissionError, match="Mathematical Boundary Breach"):
            enforce_security_gate("shell", "8.8.8.8", "rm -rf /")
        assert _audit_records()[-1]["reason"] == "Mathematical Boundary Breach"

    def test_quiet_hours_beats_prohibited_tool(self, roe, frozen_noon):
        """Quiet-hours AND prohibited tool → rejected at quiet-hours (rail 2)."""
        roe(_roe_body(
            prohibited_tools=["msf"],
            quiet_hours={"enabled": True, "start": "00:00", "end": "23:59", "message": "q"},
        ))
        with pytest.raises(PermissionError, match="Rules of Engagement Breach"):
            enforce_security_gate("msf", "10.0.0.5", "exploit/multi/handler")
        assert _audit_records()[-1]["reason"] == "Quiet Hours Breach"

    def test_prohibited_tool_beats_firewall(self, roe):
        """Prohibited tool AND destructive payload → rejected at tool (rail 3)."""
        roe(_roe_body(prohibited_tools=["shell"]))
        with pytest.raises(PermissionError, match="prohibited by policy"):
            enforce_security_gate("shell", "10.0.0.5", "rm -rf /")
        assert _audit_records()[-1]["reason"] == "Prohibited Tool Usage"


# --------------------------------------------------------------------------- #
# 3. Blocks are audited with PII redaction
# --------------------------------------------------------------------------- #

class TestAuditRedaction:
    def test_blocked_payload_is_redacted(self, roe):
        roe(_roe_body())
        pii = "exfil to admin@corp.com from 8.8.8.8"
        with pytest.raises(PermissionError):
            enforce_security_gate("nmap", "8.8.8.8", pii)
        rec = _audit_records()[-1]
        assert rec["status"] == "BLOCKED"
        assert "admin@corp.com" not in rec["payload"]
        assert "[REDACTED_EMAIL]" in rec["payload"]


# --------------------------------------------------------------------------- #
# 4. Webdash rail — kill-switch guard (require_unlocked)
# --------------------------------------------------------------------------- #

class TestWebdashKillSwitch:
    def test_require_unlocked_blocks_when_locked(self, tmp_path, monkeypatch):
        from fastapi import HTTPException
        import state_manager
        from webdash import guards

        monkeypatch.setattr(state_manager.StateManager, "is_locked",
                            lambda self, eid=None: True)
        with pytest.raises(HTTPException) as ei:
            guards.require_unlocked(str(tmp_path / "e.db"))
        assert ei.value.status_code == 423

    def test_require_unlocked_allows_when_unlocked(self, tmp_path, monkeypatch):
        import state_manager
        from webdash import guards

        monkeypatch.setattr(state_manager.StateManager, "is_locked",
                            lambda self, eid=None: False)
        # No raise → returns None.
        assert guards.require_unlocked(str(tmp_path / "e.db")) is None

    def test_webdash_scope_gate_audits_denied_with_redaction(self, roe, tmp_path, monkeypatch):
        from fastapi import HTTPException
        from webdash import guards

        p = roe(_roe_body())
        monkeypatch.setenv("OPENELIA_ROE_PATH", p)
        with pytest.raises(HTTPException) as ei:
            guards.scope_gate("8.8.8.8", "recon on admin@corp.com")
        assert ei.value.status_code == 403
        rec = _audit_records()[-1]
        assert rec["status"] == "DENIED"
        assert "admin@corp.com" not in rec["payload"]


# --------------------------------------------------------------------------- #
# 5. DOCUMENTED GAP — finding #6: engine rail does NOT consult the kill-switch
# --------------------------------------------------------------------------- #

class TestKillSwitchInvariant:
    def test_engine_gate_does_not_consult_kill_switch(self):
        """CHANGE-DETECTOR pinning finding #6 (reviewed — this is BY DESIGN).

        enforce_security_gate deliberately takes no engagement/db handle and
        never checks is_locked. The kill-switch is enforced elsewhere:
          * agent layer  — BaseAgent._check_kill_switch(), called before every
            tool execution (_execute_tool) and every reasoning turn; satisfies
            CLAUDE.md's "check is_locked before every tool execution".
          * webdash rail — require_unlocked() (see TestWebdashKillSwitch).

        The shared gate stays exempt on purpose: cleanup_registry.run_all() fires
        rollback undos WHILE the engagement is locked, and each undo passes
        through this gate. If the gate consulted is_locked, the kill-switch could
        never run its own cleanup — a deadlock.

        This test pins that invariant. If someone wires is_locked into the shared
        gate, this fails — reconsider the cleanup-rollback deadlock before
        updating it.
        """
        import inspect

        sig = inspect.signature(enforce_security_gate)
        assert "db_path" not in sig.parameters
        assert "engagement_id" not in sig.parameters
        assert "is_locked" not in inspect.getsource(enforce_security_gate)
