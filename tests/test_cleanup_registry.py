"""
tests/test_cleanup_registry.py — Unit tests for CleanupRegistry.

Tests:
- register → run_all executes callables in LIFO order
- undo whose enforce_security_gate raises is marked 'refused', callable NOT invoked
- pending() after crash (new registry on same db) lists rows; run_all leaves them pending
- cmd_lock path triggers run_all
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.cleanup_registry import CleanupRegistry


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def registry(tmp_path):
    """CleanupRegistry backed by a temp SQLite file."""
    db = str(tmp_path / "test_engagement.db")
    return CleanupRegistry(db_path=db)


@pytest.fixture
def populated_registry(registry):
    """Registry with an engagement and two registered actions."""
    eid = "ENG-TEST-001"
    call_log: list[str] = []

    def undo_first():
        call_log.append("first")

    def undo_second():
        call_log.append("second")

    id1 = registry.register(
        engagement_id=eid,
        description="First action",
        undo_command="iptables -D INPUT -s 10.0.0.1 -j DROP",
        target="10.0.0.1",
        source="defender_res",
        undo=undo_first,
    )
    id2 = registry.register(
        engagement_id=eid,
        description="Second action",
        undo_command="iptables -D INPUT -s 10.0.0.2 -j DROP",
        target="10.0.0.2",
        source="defender_res",
        undo=undo_second,
    )
    return registry, eid, id1, id2, call_log


# ---------------------------------------------------------------------------
# 1. Registration basics
# ---------------------------------------------------------------------------

class TestRegister:
    def test_register_returns_id_string(self, registry):
        action_id = registry.register(
            engagement_id="ENG-001",
            description="block host",
            undo_command="iptables -D INPUT -s 10.0.0.1 -j DROP",
            target="10.0.0.1",
            source="defender_res",
        )
        assert isinstance(action_id, str)
        assert action_id.startswith("CLN-")

    def test_register_persists_to_db(self, registry):
        eid = "ENG-002"
        registry.register(
            engagement_id=eid,
            description="test",
            undo_command="kill -9 1234",
            target="localhost",
            source="test",
        )
        rows = registry.pending(eid)
        assert len(rows) == 1
        assert rows[0]["status"] == "pending"
        assert rows[0]["description"] == "test"

    def test_register_stores_callable_in_memory(self, registry):
        called = []
        action_id = registry.register(
            engagement_id="ENG-003",
            description="test",
            undo_command="kill -9 5678",
            target="localhost",
            source="test",
            undo=lambda: called.append(True),
        )
        assert action_id in registry._callables

    def test_register_no_callable_is_fine(self, registry):
        """Registration without a callable is valid — crash-recovery scenario."""
        action_id = registry.register(
            engagement_id="ENG-004",
            description="test",
            undo_command="kill -9 9999",
            target="localhost",
            source="test",
            undo=None,
        )
        assert action_id.startswith("CLN-")


# ---------------------------------------------------------------------------
# 2. LIFO execution order
# ---------------------------------------------------------------------------

class TestRunAllLifo:
    def test_run_all_executes_in_lifo_order(self, tmp_path, monkeypatch):
        """Second-registered action must be undone before the first (LIFO).

        The security gate is mocked to pass so this test isolates ORDERING from
        roe.json policy (tool-allowlist / quiet-hours), which is time-dependent."""
        import core.cleanup_registry as cr
        monkeypatch.setattr(cr, "enforce_security_gate", lambda s, t, p: None)
        db = str(tmp_path / "lifo.db")
        reg = CleanupRegistry(db_path=db)
        eid = "ENG-LIFO"

        call_log: list[str] = []

        id1 = reg.register(
            engagement_id=eid,
            description="First",
            undo_command="iptables -D INPUT -s 10.0.0.1 -j DROP",
            target="10.0.0.1",
            source="test",
            undo=lambda: call_log.append("first"),
        )
        id2 = reg.register(
            engagement_id=eid,
            description="Second",
            undo_command="iptables -D INPUT -s 10.0.0.2 -j DROP",
            target="10.0.0.2",
            source="test",
            undo=lambda: call_log.append("second"),
        )

        results = reg.run_all(eid)

        # Both should be executed
        assert len(results) == 2
        executed = [r for r in results if r["status"] == "executed"]
        assert len(executed) == 2

        # LIFO: second registered → first executed
        assert call_log == ["second", "first"]

    def test_run_all_marks_rows_executed(self, populated_registry, monkeypatch):
        import core.cleanup_registry as cr
        monkeypatch.setattr(cr, "enforce_security_gate", lambda s, t, p: None)
        reg, eid, id1, id2, call_log = populated_registry
        results = reg.run_all(eid)
        statuses = {r["id"]: r["status"] for r in results}
        assert statuses[id1] == "executed"
        assert statuses[id2] == "executed"

    def test_run_all_returns_summary_dicts(self, populated_registry):
        reg, eid, id1, id2, call_log = populated_registry
        results = reg.run_all(eid)
        for r in results:
            assert "id" in r
            assert "status" in r

    def test_run_all_idempotent_no_double_execute(self, populated_registry):
        """After run_all, rows are 'executed'; second call should process 0 rows."""
        reg, eid, id1, id2, call_log = populated_registry
        reg.run_all(eid)
        call_log.clear()
        results = reg.run_all(eid)
        assert results == []
        assert call_log == []


# ---------------------------------------------------------------------------
# 3. Security gate: refused when gate raises
# ---------------------------------------------------------------------------

class TestSecurityGateRefusal:
    def test_destructive_undo_command_is_refused(self, tmp_path):
        """An undo_command containing a destructive pattern should be refused."""
        db = str(tmp_path / "refused.db")
        reg = CleanupRegistry(db_path=db)
        eid = "ENG-REFUSE"

        called = []
        # 'rm -rf /' is in DESTRUCTIVE_PATTERNS → gate raises PermissionError
        action_id = reg.register(
            engagement_id=eid,
            description="dangerous wipe",
            undo_command="rm -rf /",
            target="",           # empty target bypasses scope check; firewall check fires
            source="test",
            undo=lambda: called.append(True),
        )

        results = reg.run_all(eid)
        assert len(results) == 1
        assert results[0]["status"] == "refused"
        assert called == []  # callable was NOT invoked

    def test_out_of_scope_target_is_refused(self, tmp_path):
        """A target outside the RoE scope (roe.json not present → fail-closed) is refused."""
        db = str(tmp_path / "scope_refused.db")
        reg = CleanupRegistry(db_path=db)
        eid = "ENG-SCOPE"

        called = []
        action_id = reg.register(
            engagement_id=eid,
            description="out of scope undo",
            undo_command="iptables -D INPUT -s 8.8.8.8 -j DROP",
            target="8.8.8.8",   # no roe.json present → ScopeValidator fails closed
            source="test",
            undo=lambda: called.append(True),
        )

        results = reg.run_all(eid)
        assert len(results) == 1
        assert results[0]["status"] == "refused"
        assert called == []

    def test_refused_action_not_in_pending(self, tmp_path):
        """After refusal, row status is 'refused', not 'pending'."""
        db = str(tmp_path / "refused2.db")
        reg = CleanupRegistry(db_path=db)
        eid = "ENG-REFUSE2"

        reg.register(
            engagement_id=eid,
            description="wipe",
            undo_command="rm -rf /",
            target="",
            source="test",
        )
        reg.run_all(eid)
        rows = reg.pending(eid)
        assert rows == []


# ---------------------------------------------------------------------------
# 4. Crash-recovery: no callable → stays pending, never auto-executes
# ---------------------------------------------------------------------------

class TestCrashRecovery:
    def test_new_registry_sees_pending_rows(self, tmp_path):
        """After 'crash' (new registry instance, callables lost), pending() shows rows."""
        db = str(tmp_path / "crash.db")
        eid = "ENG-CRASH"

        # Register with a callable
        reg1 = CleanupRegistry(db_path=db)
        reg1.register(
            engagement_id=eid,
            description="registered before crash",
            undo_command="iptables -D INPUT -s 10.0.0.1 -j DROP",
            target="10.0.0.1",
            source="test",
            undo=lambda: None,
        )

        # Simulate crash: new instance, in-memory callables gone
        reg2 = CleanupRegistry(db_path=db)
        rows = reg2.pending(eid)
        assert len(rows) == 1
        assert rows[0]["status"] == "pending"

    def test_run_all_after_crash_leaves_rows_pending(self, tmp_path):
        """run_all with no in-memory callable must NOT execute and must leave row pending."""
        db = str(tmp_path / "crash2.db")
        eid = "ENG-CRASH2"

        reg1 = CleanupRegistry(db_path=db)
        action_id = reg1.register(
            engagement_id=eid,
            description="was registered",
            undo_command="iptables -D INPUT -s 10.0.0.1 -j DROP",
            target="10.0.0.1",
            source="test",
            undo=lambda: None,
        )

        # New registry instance — callable map is empty
        reg2 = CleanupRegistry(db_path=db)
        # The gate would pass (if roe allows), but there is no callable → must stay pending
        # We monkeypatch the gate to succeed so isolation is on "no callable → pending" only
        import unittest.mock as mock
        with mock.patch(
            "core.cleanup_registry.enforce_security_gate",
            return_value=True,
        ):
            results = reg2.run_all(eid)

        # The action should surface as "needs manual recovery" (pending in results)
        pending_results = [r for r in results if r["status"] == "pending"]
        assert len(pending_results) == 1

        # DB row must still be pending — never auto-executed
        rows = reg2.pending(eid)
        assert len(rows) == 1
        assert rows[0]["status"] == "pending"

    def test_persisted_undo_command_never_shelled(self, tmp_path):
        """Verify the string in undo_command is never passed to subprocess/eval."""
        db = str(tmp_path / "noshell.db")
        eid = "ENG-NOSHELL"

        reg1 = CleanupRegistry(db_path=db)
        reg1.register(
            engagement_id=eid,
            description="arbitrary command",
            undo_command="echo pwned > /tmp/owned.txt",
            target="",
            source="test",
            undo=lambda: None,
        )

        reg2 = CleanupRegistry(db_path=db)
        import unittest.mock as mock
        with mock.patch(
            "core.cleanup_registry.enforce_security_gate",
            return_value=True,
        ):
            reg2.run_all(eid)

        # File must NOT have been created — command was never shelled
        assert not os.path.exists("/tmp/owned.txt")


# ---------------------------------------------------------------------------
# 5. cmd_lock integration
# ---------------------------------------------------------------------------

class TestCmdLockIntegration:
    def test_cmd_lock_triggers_run_all(self, tmp_path, monkeypatch):
        """`python main.py lock` must fire the engagement's registered undos.

        cmd_lock does `from state_manager import StateManager; StateManager()`, so we
        patch state_manager.StateManager to hand back a pre-seeded instance whose
        cached cleanup_registry already holds a live undo callable. The security gate
        is mocked to pass; the undo must fire on lock."""
        import argparse
        import asyncio
        import core.cleanup_registry as cr
        import main as main_module
        import security_manager
        import state_manager as sm_mod

        db = str(tmp_path / "lock_test.db")
        state = sm_mod.StateManager(db_path=db)
        state.initialize_engagement("10.0.0.1", "test scope")
        eid = state.active_engagement_id

        fired: list[str] = []
        state.cleanup_registry.register(
            engagement_id=eid,
            description="revert block on lock",
            undo_command="iptables -D INPUT -s 10.0.0.1 -j DROP",
            target="10.0.0.1",
            source="test",
            undo=lambda: fired.append("undone"),
        )

        monkeypatch.setattr(cr, "enforce_security_gate", lambda s, t, p: None)
        monkeypatch.setattr(sm_mod, "StateManager", lambda *a, **k: state)
        monkeypatch.setattr(security_manager.AuditLogger, "log_event",
                            lambda *a, **k: None)

        asyncio.run(main_module.cmd_lock(argparse.Namespace()))

        # Lock fired the registered undo (same cached registry → callable present).
        assert fired == ["undone"]
        assert state.is_locked() is True

    def test_cleanup_registry_property_on_state_manager(self, tmp_path):
        """StateManager.cleanup_registry returns a CleanupRegistry instance."""
        from state_manager import StateManager
        from core.cleanup_registry import CleanupRegistry

        db = str(tmp_path / "prop_test.db")
        sm = StateManager(db_path=db)
        reg = sm.cleanup_registry
        assert isinstance(reg, CleanupRegistry)

    def test_cleanup_registry_property_uses_same_db(self, tmp_path):
        """StateManager.cleanup_registry uses the same db_path as the state manager."""
        from state_manager import StateManager
        from core.cleanup_registry import CleanupRegistry

        db = str(tmp_path / "samepath.db")
        sm = StateManager(db_path=db)
        reg = sm.cleanup_registry
        assert str(reg.db_path) == str(sm.db_path)
