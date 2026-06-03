"""
tests/test_state_manager.py — Unit tests for StateManager.

Covers: engagement lifecycle, phase validation, add_response_action return value,
get_escalated_analysis_count, and the PHASE_ORDER whitelist guard.
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from state_manager import StateManager, PHASE_ORDER


@pytest.fixture
def sm(tmp_path):
    """StateManager backed by a temporary SQLite file, with one active engagement."""
    db = str(tmp_path / "test_engagement.db")
    manager = StateManager(db_path=db)
    manager.initialize_engagement("10.0.0.1", "test scope")
    return manager


# ---------------------------------------------------------------------------
# Engagement creation
# ---------------------------------------------------------------------------

class TestEngagementLifecycle:
    def test_initialize_engagement_returns_dict(self, tmp_path):
        db = str(tmp_path / "e.db")
        manager = StateManager(db_path=db)
        result = manager.initialize_engagement("10.0.0.1", "test scope")
        assert isinstance(result, dict)

    def test_active_engagement_set_after_init(self, tmp_path):
        db = str(tmp_path / "e2.db")
        manager = StateManager(db_path=db)
        manager.initialize_engagement("10.0.0.2", "scope")
        assert manager.active_engagement_id is not None
        assert manager.active_engagement_id.startswith("ENG-")

    def test_read_returns_engagement(self, sm):
        state = sm.read()
        assert isinstance(state, dict)
        assert "target" in state or "current_phase" in state

    def test_is_locked_default_false(self, sm):
        assert sm.is_locked() is False

    def test_lock_unlock(self, sm):
        sm.set_locked(True)
        assert sm.is_locked() is True
        sm.set_locked(False)
        assert sm.is_locked() is False


# ---------------------------------------------------------------------------
# Phase validation (C7)
# ---------------------------------------------------------------------------

class TestPhaseValidation:
    def test_phase_order_constant(self):
        assert PHASE_ORDER == ["recon", "vuln", "exploit", "lateral", "exfil"]

    def test_write_agent_result_valid_phase(self, sm):
        sm.write_agent_result("recon", "nmap_output", {"hosts": ["10.0.0.5"]})
        data = sm.get_phase_data("recon")
        assert data.get("nmap_output") == {"hosts": ["10.0.0.5"]}

    def test_write_agent_result_invalid_phase_raises(self, sm):
        with pytest.raises(ValueError, match="Invalid phase"):
            sm.write_agent_result("pwned", "output", "data")

    @pytest.mark.parametrize("phase", PHASE_ORDER)
    def test_write_agent_result_all_valid_phases(self, tmp_path, phase):
        db = str(tmp_path / f"e_{phase}.db")
        manager = StateManager(db_path=db)
        manager.initialize_engagement("10.0.0.9", "scope")
        manager.write_agent_result(phase, "test_key", "test_value")
        assert manager.get_phase_data(phase).get("test_key") == "test_value"


# ---------------------------------------------------------------------------
# add_response_action returns row ID (C7)
# ---------------------------------------------------------------------------

class TestAddResponseAction:
    def test_returns_dict_with_id(self, sm):
        result = sm.add_response_action({
            "action_type": "block_ip",
            "target": "1.2.3.4",
            "command": "iptables -I INPUT -s 1.2.3.4 -j DROP",
            "rationale": "Malicious scanner",
            "requires_approval": False,
        })
        assert isinstance(result, dict)
        assert "id" in result
        assert isinstance(result["id"], int)
        assert result["id"] >= 1

    def test_sequential_ids_increment(self, sm):
        r1 = sm.add_response_action({"action_type": "block_ip", "target": "1.1.1.1",
                                      "command": "cmd1", "rationale": "r1"})
        r2 = sm.add_response_action({"action_type": "block_ip", "target": "2.2.2.2",
                                      "command": "cmd2", "rationale": "r2"})
        assert r2["id"] > r1["id"]


# ---------------------------------------------------------------------------
# get_escalated_analysis_count (H4 gate)
# ---------------------------------------------------------------------------

class TestEscalatedAnalysisCount:
    def test_zero_when_no_analyses(self, sm):
        assert sm.get_escalated_analysis_count() == 0

    def test_counts_escalated_only(self, sm):
        sm.add_blue_analysis({"verdict": "TP", "severity": "HIGH",
                               "reasoning": "bad", "escalate": True})
        sm.add_blue_analysis({"verdict": "FP", "severity": "LOW",
                               "reasoning": "benign", "escalate": False})
        assert sm.get_escalated_analysis_count() == 1

    def test_counts_multiple_escalated(self, sm):
        for i in range(3):
            sm.add_blue_analysis({"verdict": "TP", "severity": "CRITICAL",
                                   "reasoning": f"threat {i}", "escalate": True})
        assert sm.get_escalated_analysis_count() == 3


# ---------------------------------------------------------------------------
# CVSS score + vector in findings (Task A)
# ---------------------------------------------------------------------------

class TestCVSSInFindings:
    def test_add_finding_with_cvss_round_trips(self, sm):
        """CVSS score and vector are stored and retrievable."""
        sm.add_finding(
            severity="critical",
            title="RCE via deserialization",
            description="Unsafe object deserialization allows RCE.",
            evidence="PoC payload executed /tmp/pwn",
            mitre_ttp="T1059",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )
        with sm._get_conn() as conn:
            row = conn.execute(
                "SELECT cvss_score, cvss_vector FROM findings WHERE title = ?",
                ("RCE via deserialization",),
            ).fetchone()
        assert row is not None
        assert row["cvss_score"] == 9.8
        assert row["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def test_add_finding_without_cvss_stores_null(self, sm):
        """Back-compat: omitting cvss args stores NULL, no crash."""
        sm.add_finding(
            severity="low",
            title="Missing header",
            description="X-Frame-Options absent.",
            evidence="curl output",
            mitre_ttp="T1190",
        )
        with sm._get_conn() as conn:
            row = conn.execute(
                "SELECT cvss_score, cvss_vector FROM findings WHERE title = ?",
                ("Missing header",),
            ).fetchone()
        assert row is not None
        assert row["cvss_score"] is None
        assert row["cvss_vector"] is None

    def test_migration_adds_columns_to_legacy_db(self, tmp_path):
        """Guarded ALTER migration adds cvss columns to a legacy DB that
        lacks them, and leaves existing rows intact."""
        db_path = str(tmp_path / "legacy.db")

        # --- Build a legacy DB without the cvss columns ---
        import sqlite3 as _sqlite3
        conn = _sqlite3.connect(db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS engagement (
                id TEXT PRIMARY KEY,
                target TEXT,
                scope TEXT,
                started TEXT,
                authorized INTEGER,
                current_phase TEXT,
                is_active INTEGER DEFAULT 1,
                is_locked INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                engagement_id TEXT,
                severity TEXT,
                title TEXT,
                description TEXT,
                evidence TEXT,
                mitre_ttp TEXT,
                timestamp TEXT,
                FOREIGN KEY(engagement_id) REFERENCES engagement(id) ON DELETE CASCADE
            );
        """)
        # Insert a legacy row (no cvss columns)
        conn.execute(
            "INSERT INTO engagement (id, target, scope, started, authorized, current_phase)"
            " VALUES ('ENG-LEGACY', '10.0.0.1', 'test', '2024-01-01', 1, 'recon')"
        )
        conn.execute(
            "INSERT INTO findings (id, engagement_id, severity, title, description, evidence, mitre_ttp, timestamp)"
            " VALUES ('FIND-OLD', 'ENG-LEGACY', 'high', 'Old Finding', 'desc', 'ev', 'T1000', '2024-01-01')"
        )
        conn.commit()
        conn.close()

        # --- Run StateManager (triggers _init_db + migration) ---
        manager = StateManager(db_path=db_path)

        # Columns must now exist
        with manager._get_conn() as c:
            cols = {r[1] for r in c.execute("PRAGMA table_info(findings)").fetchall()}
        assert "cvss_score" in cols
        assert "cvss_vector" in cols

        # Pre-existing row is intact and new columns are NULL
        with manager._get_conn() as c:
            row = c.execute(
                "SELECT * FROM findings WHERE id = 'FIND-OLD'"
            ).fetchone()
        assert row is not None
        assert row["severity"] == "high"
        assert row["cvss_score"] is None
        assert row["cvss_vector"] is None

    def test_migration_idempotent_on_fresh_db(self, tmp_path):
        """Running StateManager twice on the same DB does not error
        (columns already present, guarded ALTER is a no-op)."""
        db_path = str(tmp_path / "fresh.db")
        m1 = StateManager(db_path=db_path)
        m1.initialize_engagement("10.0.0.5", "scope")
        # Second instantiation re-runs _init_db; must not raise
        m2 = StateManager(db_path=db_path)
        with m2._get_conn() as conn:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(findings)").fetchall()}
        assert "cvss_score" in cols
        assert "cvss_vector" in cols
