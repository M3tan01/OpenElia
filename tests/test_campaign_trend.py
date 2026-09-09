import sqlite3
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
