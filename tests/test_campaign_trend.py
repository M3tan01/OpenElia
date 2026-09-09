import sqlite3
from datetime import datetime, timezone

import pytest
from state_manager import StateManager


def _cols(db_path, table):
    con = sqlite3.connect(db_path)
    try:
        return {r[1] for r in con.execute(f"PRAGMA table_info({table})").fetchall()}
    finally:
        con.close()


def test_migration_adds_campaign_id_and_coverage_history(tmp_path):
    db = str(tmp_path / "engagement.db")
    StateManager(db_path=db)  # first construct runs migrations

    assert "campaign_id" in _cols(db, "engagement")

    covhist = _cols(db, "coverage_history")
    assert covhist == {
        "id", "campaign_id", "engagement_id", "ttp", "rung",
        "time_to_detect_s", "coverage_pct", "ts",
    }


def test_migration_is_idempotent_across_two_managers(tmp_path):
    db = str(tmp_path / "engagement.db")
    StateManager(db_path=db)
    # A second fresh manager on the same DB must not raise (race-safe migration).
    StateManager(db_path=db)
    assert "campaign_id" in _cols(db, "engagement")


def test_coverage_history_has_no_title_column(tmp_path):
    db = str(tmp_path / "engagement.db")
    StateManager(db_path=db)
    assert "title" not in _cols(db, "coverage_history")  # PII boundary


def test_initialize_engagement_persists_campaign_id(tmp_path):
    sm = StateManager(db_path=str(tmp_path / "engagement.db"))
    eng = sm.initialize_engagement("10.0.0.1", "authorized", campaign_id="Q3-uplift")
    with sm._get_conn() as conn:
        row = conn.execute(
            "SELECT campaign_id FROM engagement WHERE id = ?", (eng["engagement"]["id"],)
        ).fetchone()
    assert row["campaign_id"] == "Q3-uplift"


def test_initialize_engagement_defaults_campaign_id_null(tmp_path):
    sm = StateManager(db_path=str(tmp_path / "engagement.db"))
    eng = sm.initialize_engagement("10.0.0.1", "authorized")
    with sm._get_conn() as conn:
        row = conn.execute(
            "SELECT campaign_id FROM engagement WHERE id = ?", (eng["engagement"]["id"],)
        ).fetchone()
    assert row["campaign_id"] is None


def _seed_cycle(sm, eid, *, finding_ttp, alert_ttp=None):
    """Insert a finding (executed TTP) and optionally a matching blue alert."""
    now = datetime.now(timezone.utc).isoformat()
    with sm._get_conn() as conn:
        conn.execute(
            "INSERT INTO findings (engagement_id, title, severity, mitre_ttp, timestamp) "
            "VALUES (?, ?, ?, ?, ?)",
            (eid, "SECRET-TITLE-DO-NOT-LEAK", "high", finding_ttp, now),
        )
        if alert_ttp:
            conn.execute(
                "INSERT INTO blue_alerts (engagement_id, type, mitre_ttp, escalated, timestamp) "
                "VALUES (?, ?, ?, ?, ?)",
                (eid, "ids", alert_ttp, 0, now),
            )
        conn.commit()
    sm.set_metadata("blue_run_status", "complete", eid)


def test_snapshot_writes_one_row_per_scorecard_entry(tmp_path):
    sm = StateManager(db_path=str(tmp_path / "engagement.db"))
    eng = sm.initialize_engagement("10.0.0.1", "auth", campaign_id="C1")
    eid = eng["engagement"]["id"]
    _seed_cycle(sm, eid, finding_ttp="T1003", alert_ttp="T1003")
    _seed_cycle(sm, eid, finding_ttp="T1046")  # missed

    n = sm.record_coverage_snapshot(eid)

    cov = sm.get_coverage(eid)
    assert n == len(cov["scorecard"]) == 2
    with sm._get_conn() as conn:
        rows = conn.execute(
            "SELECT ttp, rung, coverage_pct, ts FROM coverage_history WHERE campaign_id='C1'"
        ).fetchall()
    assert len(rows) == 2
    assert len({r["ts"] for r in rows}) == 1            # one shared ts
    assert {r["coverage_pct"] for r in rows} == {cov["coverage_pct"]}  # headline captured


def test_snapshot_noop_when_campaign_null(tmp_path):
    sm = StateManager(db_path=str(tmp_path / "engagement.db"))
    eng = sm.initialize_engagement("10.0.0.1", "auth")  # no campaign
    eid = eng["engagement"]["id"]
    _seed_cycle(sm, eid, finding_ttp="T1003", alert_ttp="T1003")
    assert sm.record_coverage_snapshot(eid) == 0
    with sm._get_conn() as conn:
        assert conn.execute("SELECT COUNT(*) c FROM coverage_history").fetchone()["c"] == 0


def test_snapshot_never_writes_finding_title(tmp_path):
    sm = StateManager(db_path=str(tmp_path / "engagement.db"))
    eng = sm.initialize_engagement("10.0.0.1", "auth", campaign_id="C1")
    eid = eng["engagement"]["id"]
    _seed_cycle(sm, eid, finding_ttp="T1003", alert_ttp="T1003")
    sm.record_coverage_snapshot(eid)
    with sm._get_conn() as conn:
        blob = str(conn.execute("SELECT * FROM coverage_history").fetchall())
    assert "SECRET-TITLE-DO-NOT-LEAK" not in blob  # PII boundary


def test_trend_groups_by_ts_orders_ascending(tmp_path):
    """Verify that get_campaign_trend groups rows by ts, orders oldest first,
    and reads coverage_pct from the stored snapshot (not recomputed)."""
    import time

    RUNGS = ("PREVENTED", "ALERTED", "DETECTED", "LOGGED", "MISSED", "PENDING")

    sm = StateManager(db_path=str(tmp_path / "engagement.db"))
    eng = sm.initialize_engagement("10.0.0.1", "auth", campaign_id="C1")
    eid = eng["engagement"]["id"]

    # Seed two cycles with different TTPs
    _seed_cycle(sm, eid, finding_ttp="T1003", alert_ttp="T1003")
    _seed_cycle(sm, eid, finding_ttp="T1046")

    # Record first snapshot
    sm.record_coverage_snapshot(eid)
    time.sleep(0.001)  # guarantee distinct microsecond ts

    # Record second snapshot
    sm.record_coverage_snapshot(eid)

    # Read the trend
    trend = sm.get_campaign_trend("C1")

    # Assertions per brief
    assert len(trend) == 2, "Expected two snapshots, not merged"
    assert trend[0]["ts"] < trend[1]["ts"], "Expected ascending ts order"

    snap = trend[-1]
    assert snap["coverage_pct"] == sm.get_coverage(eid)["coverage_pct"], \
        "coverage_pct must be read back, not recomputed"
    assert set(snap["rung_counts"]) == set(RUNGS), "Must have all rung names"
    assert sum(snap["rung_counts"].values()) == len(snap["ttps"]) == 2, \
        "Expected 2 TTP entries and rung_counts sum matches"


def test_trend_unknown_campaign_returns_empty(tmp_path):
    """Verify that unknown/absent campaign_id returns []."""
    sm = StateManager(db_path=str(tmp_path / "engagement.db"))
    assert sm.get_campaign_trend("nope") == []


def test_cmd_purple_snapshots_per_iteration(tmp_path):
    """A campaign-tagged engagement snapshots once per completed purple cycle."""
    import time

    sm = StateManager(db_path=str(tmp_path / "engagement.db"))
    eng = sm.initialize_engagement("10.0.0.1", "auth", campaign_id="C1")
    eid = eng["engagement"]["id"]
    _seed_cycle(sm, eid, finding_ttp="T1003", alert_ttp="T1003")

    # Two iterations → two snapshots (distinct ts).
    sm.record_coverage_snapshot(eid)
    time.sleep(0.001)
    sm.record_coverage_snapshot(eid)
    assert len(sm.get_campaign_trend("C1")) == 2
