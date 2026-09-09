# Continuous Purple Teaming — Scheduling + Trend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist one PII-free coverage snapshot per completed purple cycle, keyed by a stable `campaign_id`, and expose the per-campaign trend over time via API + dashboard — scheduling delegated to external n8n/cron, no new daemon.

**Architecture:** Add a nullable `campaign_id` to `engagement` (threaded once at engagement creation). A single writer, `StateManager.record_coverage_snapshot`, reads that id off the engagement, runs the existing `get_coverage`, and INSERTs one `coverage_history` row per scorecard TTP — every row sharing one microsecond-precision `ts` and the authoritative `coverage_pct` scalar (captured from `get_coverage`, never recomputed). `get_campaign_trend` groups those rows by `ts` into a time series. A read-only monitor endpoint and a `CampaignTrendView.tsx` surface it. The snapshot fires at the two sites that already read purple coverage (CLI loop + dashboard run completion), not in the orchestrator.

**Tech Stack:** Python 3.11+, SQLite (WAL, per-request `StateManager`), FastAPI (monitor router), React + TypeScript (Vite), pytest + pytest-asyncio.

**Spec:** `docs/superpowers/specs/2026-09-08-continuous-pt-scheduling-trend-design.md`

## Global Constraints

- **PII boundary.** `coverage_history` stores only `{campaign_id, engagement_id, ttp, rung, time_to_detect_s, coverage_pct, ts}` — all structured, non-free-text. It has **no `title` column**. No finding/scorecard title (free-text, may contain PII) may ever be written to or flow out of this table.
- **`coverage_pct` is captured, never recomputed.** The live headline (`state_manager.py:649`) is `round(100.0 * len(caught) / (len(caught)+len(missed)), 1)` from the caught/missed **alert-presence** partition — NOT a function of the scorecard rungs. Store `get_coverage(eid)["coverage_pct"]` verbatim; on read, read it back. Do NOT derive a percentage from rungs anywhere. `get_coverage` is left unchanged (no `_coverage_pct` helper extraction).
- **Migration safety.** New column + new table use the existing idempotent pattern (`state_manager.py:188-228`): `PRAGMA table_info` guard + `ALTER TABLE` / `CREATE TABLE IF NOT EXISTS` wrapped in `try/except sqlite3.OperationalError`; `conn.commit()` after the block. Survives per-request `StateManager` races.
- **Single source of truth.** `campaign_id` lives on the `engagement` row only. `record_coverage_snapshot` reads it back off the engagement — callers never pass it in, so it cannot drift between a run and its snapshots.
- **Campaign-scoped only.** `campaign_id IS NULL` → writer is a no-op returning 0 (ad-hoc/legacy runs stay out of history). Only completed **purple** cycles snapshot; red-only / blue-only runs do not.
- **`ts` microsecond precision.** Write `datetime.now(timezone.utc).isoformat()` so back-to-back CLI loop cycles never collide onto one `ts` (which would merge two cycles).
- **Python conventions.** Type-annotate all new signatures. Lazy-import heavy modules inside functions. `pytest` async tests use `@pytest.mark.asyncio`.
- **No new dependency** for the chart if avoidable — confirm `victory-vendor`/`recharts` presence at build before importing; fall back to an inline SVG/table if absent.

---

### Task 1: Schema migration — `campaign_id` column + `coverage_history` table

**Files:**
- Modify: `state_manager.py:228` (append a new migration block after the `response_actions` block, before the block's closing)
- Test: `tests/test_campaign_trend.py` (new file)

**Interfaces:**
- Consumes: existing `_init_db` / connection setup and the migration pattern at `state_manager.py:188-228`.
- Produces: `engagement.campaign_id` (TEXT, nullable) and table `coverage_history(id, campaign_id, engagement_id, ttp, rung, time_to_detect_s, coverage_pct, ts)` + index `idx_covhist_campaign(campaign_id, ts)`. Later tasks rely on these column names exactly.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_campaign_trend.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_campaign_trend.py -v`
Expected: FAIL — `coverage_history` table does not exist / `campaign_id` not in engagement cols.

- [ ] **Step 3: Write minimal implementation**

Append after the `response_actions` migration block (`state_manager.py:228`, after its `conn.commit()`), inside the same `with self._get_conn() as conn:` scope:

```python
            # Idempotent migration: add campaign_id to engagement if absent
            # (series key for continuous purple teaming; nullable → legacy rows
            # excluded from trend). Same race-safe pattern as above.
            existing_eng_cols = {
                row[1]
                for row in conn.execute("PRAGMA table_info(engagement)").fetchall()
            }
            if "campaign_id" not in existing_eng_cols:
                try:
                    conn.execute("ALTER TABLE engagement ADD COLUMN campaign_id TEXT")
                except sqlite3.OperationalError:
                    pass  # column added by a concurrent initializer — fine
            conn.commit()

            # coverage_history: one row per TTP per completed purple cycle.
            # No `title` column by construction (PII boundary — see spec §3).
            # coverage_pct is the authoritative headline captured at write time,
            # repeated on every row of a snapshot; never recomputed on read.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS coverage_history (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id   TEXT NOT NULL,
                    engagement_id TEXT NOT NULL,
                    ttp           TEXT NOT NULL,
                    rung          TEXT NOT NULL,
                    time_to_detect_s INTEGER,
                    coverage_pct  REAL NOT NULL,
                    ts            TEXT NOT NULL
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_covhist_campaign "
                "ON coverage_history(campaign_id, ts)"
            )
            conn.commit()
```

Confirm `import sqlite3` is already present at module top (it is — used by existing migration blocks). No new import needed.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_campaign_trend.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add state_manager.py tests/test_campaign_trend.py
git commit -m "feat(state): add campaign_id column + coverage_history table"
```

---

### Task 2: Thread `campaign_id` into `initialize_engagement`

**Files:**
- Modify: `state_manager.py:369-384` (`initialize_engagement`)
- Test: `tests/test_campaign_trend.py`

**Interfaces:**
- Consumes: `engagement.campaign_id` column (Task 1).
- Produces: `initialize_engagement(self, target: str, scope: str, campaign_id: str | None = None) -> dict` — persists `campaign_id` to the new column. Existing 2-arg callers keep working (defaults to `None`). Tasks 5 & 6 pass this param.

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_campaign_trend.py
def test_initialize_engagement_persists_campaign_id(tmp_path):
    sm = StateManager(db_path=str(tmp_path / "engagement.db"))
    eng = sm.initialize_engagement("10.0.0.1", "authorized", campaign_id="Q3-uplift")
    with sm._get_conn() as conn:
        row = conn.execute(
            "SELECT campaign_id FROM engagement WHERE id = ?", (eng["id"],)
        ).fetchone()
    assert row["campaign_id"] == "Q3-uplift"


def test_initialize_engagement_defaults_campaign_id_null(tmp_path):
    sm = StateManager(db_path=str(tmp_path / "engagement.db"))
    eng = sm.initialize_engagement("10.0.0.1", "authorized")
    with sm._get_conn() as conn:
        row = conn.execute(
            "SELECT campaign_id FROM engagement WHERE id = ?", (eng["id"],)
        ).fetchone()
    assert row["campaign_id"] is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_campaign_trend.py::test_initialize_engagement_persists_campaign_id -v`
Expected: FAIL — `initialize_engagement()` got an unexpected keyword argument `campaign_id`.

- [ ] **Step 3: Write minimal implementation**

Replace `state_manager.py:369-376`:

```python
    def initialize_engagement(self, target: str, scope: str,
                              campaign_id: str | None = None) -> dict:
        eid = f"ENG-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        with self._get_conn() as conn:
            conn.execute("UPDATE engagement SET is_active = 0")
            conn.execute("""
                INSERT INTO engagement (id, target, scope, started, authorized, current_phase, is_active, is_locked, campaign_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (eid, target, scope, datetime.now(timezone.utc).isoformat(), 1, "recon", 1, 0, campaign_id))
```

(The `for p in PHASE_ORDER:` loop and everything after it are unchanged.)

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_campaign_trend.py -v`
Expected: PASS (all).

- [ ] **Step 5: Commit**

```bash
git add state_manager.py tests/test_campaign_trend.py
git commit -m "feat(state): thread campaign_id through initialize_engagement"
```

---

### Task 3: `record_coverage_snapshot` writer

**Files:**
- Modify: `state_manager.py` (add method near `get_coverage`, after `:717`)
- Test: `tests/test_campaign_trend.py`

**Interfaces:**
- Consumes: `get_coverage(eid) -> dict` with keys `coverage_pct`, `scorecard` (list of `{"ttp","title","rung","time_to_detect_s"}`); `engagement.campaign_id`; `self.active_engagement_id`.
- Produces: `record_coverage_snapshot(self, engagement_id: str | None = None) -> int` — returns rows written. Writes 0 when the engagement's `campaign_id IS NULL`. Tasks 5 & 6 call it.

**Design note (binding):** the writer copies `cov["coverage_pct"]` onto every row — it does NOT recompute a percent from rungs. It writes only `ttp`/`rung`/`time_to_detect_s` from each scorecard entry (never `title`).

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_campaign_trend.py — helpers seed a purple cycle directly.
from datetime import datetime, timezone


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
    eid = eng["id"]
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
    _seed_cycle(sm, eng["id"], finding_ttp="T1003", alert_ttp="T1003")
    assert sm.record_coverage_snapshot(eng["id"]) == 0
    with sm._get_conn() as conn:
        assert conn.execute("SELECT COUNT(*) c FROM coverage_history").fetchone()["c"] == 0


def test_snapshot_never_writes_finding_title(tmp_path):
    sm = StateManager(db_path=str(tmp_path / "engagement.db"))
    eng = sm.initialize_engagement("10.0.0.1", "auth", campaign_id="C1")
    _seed_cycle(sm, eng["id"], finding_ttp="T1003", alert_ttp="T1003")
    sm.record_coverage_snapshot(eng["id"])
    with sm._get_conn() as conn:
        blob = str(conn.execute("SELECT * FROM coverage_history").fetchall())
    assert "SECRET-TITLE-DO-NOT-LEAK" not in blob  # PII boundary
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_campaign_trend.py::test_snapshot_writes_one_row_per_scorecard_entry -v`
Expected: FAIL — `StateManager` has no attribute `record_coverage_snapshot`.

- [ ] **Step 3: Write minimal implementation**

Add after `get_coverage` (`state_manager.py:717`):

```python
    def record_coverage_snapshot(self, engagement_id: str | None = None) -> int:
        """Persist one coverage snapshot for the engagement's campaign.

        Reads campaign_id off the engagement row (single source of truth). If
        NULL, no-op → returns 0 (ad-hoc/legacy runs stay out of history). Else
        runs get_coverage(eid) and INSERTs one coverage_history row per scorecard
        entry, all sharing one UTC ts and the snapshot's authoritative
        coverage_pct scalar (captured, never recomputed). Returns rows written.
        """
        eid = engagement_id or self.active_engagement_id
        if not eid:
            return 0
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT campaign_id FROM engagement WHERE id = ?", (eid,)
            ).fetchone()
        campaign_id = row["campaign_id"] if row else None
        if not campaign_id:
            return 0  # campaign-scoped only

        cov = self.get_coverage(eid)
        coverage_pct = cov["coverage_pct"]
        ts = datetime.now(timezone.utc).isoformat()  # microsecond precision → no collision
        scorecard = cov["scorecard"]
        with self._get_conn() as conn:
            conn.executemany(
                "INSERT INTO coverage_history "
                "(campaign_id, engagement_id, ttp, rung, time_to_detect_s, coverage_pct, ts) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (campaign_id, eid, e["ttp"], e["rung"], e["time_to_detect_s"], coverage_pct, ts)
                    for e in scorecard
                ],
            )
            conn.commit()
        return len(scorecard)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_campaign_trend.py -v`
Expected: PASS (all).

- [ ] **Step 5: Commit**

```bash
git add state_manager.py tests/test_campaign_trend.py
git commit -m "feat(state): add record_coverage_snapshot writer"
```

---

### Task 4: `get_campaign_trend` reader

**Files:**
- Modify: `state_manager.py` (add method after `record_coverage_snapshot`)
- Test: `tests/test_campaign_trend.py`

**Interfaces:**
- Consumes: `coverage_history` rows (Task 1), written by `record_coverage_snapshot` (Task 3).
- Produces: `get_campaign_trend(self, campaign_id: str) -> list[dict]`, oldest first, each snapshot `{"ts": str, "coverage_pct": float, "rung_counts": {RUNG: int, ...}, "ttps": [{"ttp": str, "rung": str, "time_to_detect_s": int|None}, ...]}`. Task 8 (data.py/endpoint) consumes this shape.

**Design note (binding):** `coverage_pct` is READ BACK from the stored scalar (any row of the `ts` group), never recomputed. `rung_counts` is tallied from the group's rows.

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_campaign_trend.py
import time

RUNGS = ("PREVENTED", "ALERTED", "DETECTED", "LOGGED", "MISSED", "PENDING")


def test_trend_groups_by_ts_orders_ascending(tmp_path):
    sm = StateManager(db_path=str(tmp_path / "engagement.db"))
    eng = sm.initialize_engagement("10.0.0.1", "auth", campaign_id="C1")
    eid = eng["id"]
    _seed_cycle(sm, eid, finding_ttp="T1003", alert_ttp="T1003")
    _seed_cycle(sm, eid, finding_ttp="T1046")

    sm.record_coverage_snapshot(eid)   # cycle 1
    time.sleep(0.001)                  # guarantee distinct microsecond ts
    sm.record_coverage_snapshot(eid)   # cycle 2

    trend = sm.get_campaign_trend("C1")
    assert len(trend) == 2                                   # two snapshots, not merged
    assert trend[0]["ts"] < trend[1]["ts"]                   # ascending
    snap = trend[-1]
    assert snap["coverage_pct"] == sm.get_coverage(eid)["coverage_pct"]  # read-back == live headline
    assert set(snap["rung_counts"]) == set(RUNGS)
    assert sum(snap["rung_counts"].values()) == len(snap["ttps"]) == 2


def test_trend_unknown_campaign_returns_empty(tmp_path):
    sm = StateManager(db_path=str(tmp_path / "engagement.db"))
    assert sm.get_campaign_trend("nope") == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_campaign_trend.py::test_trend_groups_by_ts_orders_ascending -v`
Expected: FAIL — `StateManager` has no attribute `get_campaign_trend`.

- [ ] **Step 3: Write minimal implementation**

Add after `record_coverage_snapshot`:

```python
    def get_campaign_trend(self, campaign_id: str) -> list[dict]:
        """Return per-snapshot coverage trend for a campaign, oldest first.

        Rows grouped by ts. coverage_pct is read back from the stored scalar
        (never recomputed); rung_counts and ttps are tallied on read. See spec §6.
        """
        rung_names = ("PREVENTED", "ALERTED", "DETECTED", "LOGGED", "MISSED", "PENDING")
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT ttp, rung, time_to_detect_s, coverage_pct, ts "
                "FROM coverage_history WHERE campaign_id = ? ORDER BY ts ASC, id ASC",
                (campaign_id,),
            ).fetchall()

        snapshots: dict[str, dict] = {}
        for r in rows:
            snap = snapshots.get(r["ts"])
            if snap is None:
                snap = {
                    "ts": r["ts"],
                    "coverage_pct": r["coverage_pct"],          # read back, not recomputed
                    "rung_counts": {name: 0 for name in rung_names},
                    "ttps": [],
                }
                snapshots[r["ts"]] = snap
            snap["rung_counts"][r["rung"]] = snap["rung_counts"].get(r["rung"], 0) + 1
            snap["ttps"].append(
                {"ttp": r["ttp"], "rung": r["rung"], "time_to_detect_s": r["time_to_detect_s"]}
            )
        return list(snapshots.values())  # dict preserves insertion (ts-ascending) order
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_campaign_trend.py -v`
Expected: PASS (all).

- [ ] **Step 5: Commit**

```bash
git add state_manager.py tests/test_campaign_trend.py
git commit -m "feat(state): add get_campaign_trend reader"
```

---

### Task 5: CLI — `--campaign-id` + `cmd_purple` threading + snapshot

**Files:**
- Modify: `main.py:1055` (`purple` subparser, after `--iterations`), `main.py:511` (engagement init), `main.py:586-591` (per-iteration coverage read → insert snapshot after `:591`)
- Test: `tests/test_campaign_trend.py`

**Interfaces:**
- Consumes: `initialize_engagement(..., campaign_id=...)` (Task 2), `record_coverage_snapshot(eid)` (Task 3).
- Produces: `purple --campaign-id X` opts the run into a campaign and snapshots once per loop iteration.

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_campaign_trend.py — assert the wiring: snapshot per iteration.
def test_cmd_purple_snapshots_per_iteration(tmp_path, monkeypatch):
    """A campaign-tagged engagement snapshots once per completed purple cycle."""
    sm = StateManager(db_path=str(tmp_path / "engagement.db"))
    eng = sm.initialize_engagement("10.0.0.1", "auth", campaign_id="C1")
    eid = eng["id"]
    _seed_cycle(sm, eid, finding_ttp="T1003", alert_ttp="T1003")

    # Two iterations → two snapshots (distinct ts).
    import time
    sm.record_coverage_snapshot(eid)
    time.sleep(0.001)
    sm.record_coverage_snapshot(eid)
    assert len(sm.get_campaign_trend("C1")) == 2
```

*(This locks the writer contract cmd_purple depends on. The argparse/loop wiring below is verified by the manual smoke run in Step 4b.)*

- [ ] **Step 2: Run test to verify it fails / passes**

Run: `pytest tests/test_campaign_trend.py::test_cmd_purple_snapshots_per_iteration -v`
Expected: PASS (exercises Task 3/4 code — this is the regression guard the CLI relies on).

- [ ] **Step 3: Wire the CLI**

Add to the `purple` subparser (`main.py:1055`, after `--iterations`):

```python
    purple_p.add_argument("--campaign-id", dest="campaign_id",
                          help="Stable campaign label; opts this run's engagement into trend history")
```

Thread into engagement init — replace `main.py:511`:

```python
            state.initialize_engagement(target, args.scope or "Authorized purple team engagement",
                                        campaign_id=getattr(args, "campaign_id", None))
```

Add the snapshot after the per-iteration coverage read. Insert immediately after `main.py:591` (`prev_covered = covered_now`):

```python
        # Persist one trend snapshot per completed cycle (no-op if no --campaign-id).
        state.record_coverage_snapshot(state.active_engagement_id)
```

- [ ] **Step 4: Verify — targeted test then manual smoke**

Run: `pytest tests/test_campaign_trend.py -v` → PASS.

4b. Manual smoke (verifies argparse + threading; no network/LLM needed for the parse check):

Run: `python main.py purple --help`
Expected: `--campaign-id` appears in the help output.

- [ ] **Step 5: Commit**

```bash
git add main.py tests/test_campaign_trend.py
git commit -m "feat(cli): add --campaign-id and per-cycle trend snapshot to purple loop"
```

---

### Task 6: Dashboard runner — thread `campaign_id` + snapshot on purple completion

**Files:**
- Modify: `webdash/runner.py:37-50` (`start` signature), `:69-74` (`_execute` dispatch), `:80` (`_execute` signature), `:82-101` (snapshot after done), `:153-160` (`_invoke` signature + `initialize_engagement` call)
- Test: `tests/test_runner_trend.py` (new file) or extend an existing runner test

**Interfaces:**
- Consumes: `initialize_engagement(..., campaign_id=...)` (Task 2), `record_coverage_snapshot()` (Task 3).
- Produces: `RunManager.start(..., campaign_id: str | None = None)`; a purple run with a campaign snapshots exactly once on successful completion (the **unconditional** `_execute` completion point, not the `callback_url`-gated `_notify`).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_runner_trend.py
import pytest
from webdash.runner import RunManager


@pytest.mark.asyncio
async def test_purple_run_snapshots_on_completion(tmp_path, monkeypatch):
    state_dir = tmp_path
    captured = {}

    async def fake_invoke(self, **kw):
        # Simulate the engine: create a campaign-tagged engagement + a caught TTP.
        from state_manager import StateManager
        from datetime import datetime, timezone
        sm = StateManager(db_path=str(state_dir / "engagement.db"))
        eng = sm.initialize_engagement("10.0.0.1", "web", campaign_id=kw.get("campaign_id"))
        now = datetime.now(timezone.utc).isoformat()
        with sm._get_conn() as conn:
            conn.execute("INSERT INTO findings (engagement_id, title, severity, mitre_ttp, timestamp) "
                         "VALUES (?,?,?,?,?)", (eng["id"], "t", "high", "T1003", now))
            conn.execute("INSERT INTO blue_alerts (engagement_id, type, mitre_ttp, escalated, timestamp) "
                         "VALUES (?,?,?,?,?)", (eng["id"], "ids", "T1003", 0, now))
            conn.commit()
        sm.set_metadata("blue_run_status", "complete", eng["id"])
        captured["eid"] = eng["id"]
        return {"ok": True}

    monkeypatch.setattr(RunManager, "_invoke", fake_invoke)

    rm = RunManager()
    run_id = await rm.start(domain="purple", task="t", targets=["10.0.0.1"],
                            state_dir=str(state_dir), campaign_id="C1")
    # Wait for the background task to finish.
    import asyncio
    for _ in range(200):
        if rm._runs[run_id]["status"] in ("done", "error", "cancelled"):
            break
        await asyncio.sleep(0.01)

    from state_manager import StateManager
    sm = StateManager(db_path=str(state_dir / "engagement.db"))
    trend = sm.get_campaign_trend("C1")
    assert len(trend) == 1
    assert trend[0]["coverage_pct"] == 100.0


@pytest.mark.asyncio
async def test_non_purple_run_does_not_snapshot(tmp_path, monkeypatch):
    async def fake_invoke(self, **kw):
        from state_manager import StateManager
        sm = StateManager(db_path=str(tmp_path / "engagement.db"))
        sm.initialize_engagement("10.0.0.1", "web", campaign_id=kw.get("campaign_id"))
        return {"ok": True}
    monkeypatch.setattr(RunManager, "_invoke", fake_invoke)

    rm = RunManager()
    run_id = await rm.start(domain="red", task="t", targets=["10.0.0.1"],
                            state_dir=str(tmp_path), campaign_id="C1")
    import asyncio
    for _ in range(200):
        if rm._runs[run_id]["status"] in ("done", "error", "cancelled"):
            break
        await asyncio.sleep(0.01)

    from state_manager import StateManager
    sm = StateManager(db_path=str(tmp_path / "engagement.db"))
    assert sm.get_campaign_trend("C1") == []  # red-only never snapshots
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_runner_trend.py -v`
Expected: FAIL — `start()` got an unexpected keyword argument `campaign_id`.

- [ ] **Step 3: Write minimal implementation**

Add `campaign_id` to `start` (`webdash/runner.py:49`, after `callback_url`):

```python
        callback_url: str | None = None,
        campaign_id: str | None = None,
    ) -> str:
```

Store it on the run record (`:65-66`, alongside `state_dir`):

```python
            "state_dir": state_dir,
            "campaign_id": campaign_id,
```

Pass it into `_execute` (`:70-74`):

```python
            self._execute(
                run_id=run_id, domain=domain, task=task, targets=targets,
                stealth=stealth, proxy_port=proxy_port, brain_tier=brain_tier,
                apt_profile=apt_profile, agent=agent, state_dir=state_dir,
                campaign_id=campaign_id,
            )
```

Update `_execute` signature (`:80`) and add the snapshot right after `rec["status"] = "done"` (`:88`):

```python
    async def _execute(self, run_id, domain, task, targets, stealth, proxy_port, brain_tier, apt_profile, state_dir, agent=None, campaign_id=None):
        rec = self._runs[run_id]
        try:
            rec["result"] = await self._invoke(
                domain=domain, task=task, targets=targets, stealth=stealth,
                proxy_port=proxy_port, brain_tier=brain_tier, apt_profile=apt_profile,
                agent=agent, state_dir=state_dir, campaign_id=campaign_id,
            )
            rec["status"] = "done"
            # Trend snapshot: unconditional completion point for purple runs.
            # NOT in _notify (that is callback_url-gated) — a webhookless purple
            # run must still snapshot. No-op if the engagement has no campaign_id.
            if domain == "purple":
                try:
                    from state_manager import StateManager
                    # active_engagement_id resolves at construct
                    # (StateManager.__init__ → _get_last_active_id), so no read()
                    # is needed. No-arg → the writer resolves the active engagement
                    # itself and no-ops when it has no campaign_id.
                    sm = StateManager(db_path=str(Path(state_dir) / "engagement.db"))
                    sm.record_coverage_snapshot()
                except Exception as exc:  # best-effort — never flip a done run to error
                    print(f"trend snapshot failed: {type(exc).__name__}: {exc}")
```

Update `_invoke` signature (`:153`) and pass `campaign_id` to `initialize_engagement` (`:158-160`):

```python
    async def _invoke(self, domain, task, targets, stealth, proxy_port, brain_tier, apt_profile, state_dir, agent=None, campaign_id=None) -> dict:
        """Actual engine call. Isolated for mocking in tests."""
        from orchestrator import Orchestrator
        from state_manager import StateManager

        sm = StateManager(db_path=str(Path(state_dir) / "engagement.db"))
        if not sm.read():
            sm.initialize_engagement(targets[0] if targets else "unknown", "web dashboard engagement",
                                     campaign_id=campaign_id)
```

Confirm `from pathlib import Path` is already imported at the top of `webdash/runner.py` (it is — used at `:137,158`).

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_runner_trend.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add webdash/runner.py tests/test_runner_trend.py
git commit -m "feat(webdash): thread campaign_id + snapshot purple runs on completion"
```

---

### Task 7: API — `PurpleRun.campaign_id` + `/run/purple` pass-through

**Files:**
- Modify: `webdash/api/control.py:45-53` (`PurpleRun`), `:258-268` (`run_purple` → `_launch` call)
- Test: `tests/test_control_campaign.py` (new) or extend existing control tests

**Interfaces:**
- Consumes: `RunManager.start(..., campaign_id=...)` (Task 6) via `_launch(rm, **kwargs)` (`control.py:225`, which forwards `**kwargs` to `rm.start`).
- Produces: `POST /run/purple` accepts optional `"campaign_id"` and forwards it.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_control_campaign.py
from webdash.api.control import PurpleRun


def test_purplerun_accepts_campaign_id():
    r = PurpleRun(target="10.0.0.1", campaign_id="C1", confirm=True)
    assert r.campaign_id == "C1"


def test_purplerun_campaign_id_defaults_none():
    r = PurpleRun(target="10.0.0.1", confirm=True)
    assert r.campaign_id is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_control_campaign.py -v`
Expected: FAIL — `PurpleRun` has no field `campaign_id`.

- [ ] **Step 3: Write minimal implementation**

Add to `PurpleRun` (`control.py:52`, before `confirm`):

```python
    agent: str | None = None
    campaign_id: str | None = None
    confirm: bool = False
```

Forward it in `run_purple` (`control.py:264-268`):

```python
    return await _launch(
        rm, domain="purple", task=req.task, targets=[req.target], stealth=req.stealth,
        proxy_port=req.proxy_port, brain_tier=req.brain_tier, apt_profile=req.apt_profile,
        state_dir=str(data.dir), agent=req.agent, campaign_id=req.campaign_id,
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_control_campaign.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add webdash/api/control.py tests/test_control_campaign.py
git commit -m "feat(api): accept campaign_id on /run/purple"
```

---

### Task 8: Monitor endpoint — `GET /api/campaign/{campaign_id}/trend`

**Files:**
- Modify: `webdash/data.py` (add `campaign_trend` method near `coverage()`, `:181-186`), `webdash/api/monitor.py` (add route after `/coverage`, `:56`)
- Test: `tests/test_campaign_endpoint.py` (new)

**Interfaces:**
- Consumes: `StateManager.get_campaign_trend(campaign_id)` (Task 4).
- Produces: `GET /api/campaign/{campaign_id}/trend` → `{"campaign_id": str, "snapshots": [<snapshot>, ...]}`; empty `snapshots` for unknown campaign (not 404). Task 9 consumes this shape.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_campaign_endpoint.py
from webdash.data import DashboardData


def test_campaign_trend_data_method(tmp_path):
    from state_manager import StateManager
    from datetime import datetime, timezone
    sm = StateManager(db_path=str(tmp_path / "engagement.db"))
    eng = sm.initialize_engagement("10.0.0.1", "auth", campaign_id="C1")
    now = datetime.now(timezone.utc).isoformat()
    with sm._get_conn() as conn:
        conn.execute("INSERT INTO findings (engagement_id, title, severity, mitre_ttp, timestamp) "
                     "VALUES (?,?,?,?,?)", (eng["id"], "t", "high", "T1003", now))
        conn.execute("INSERT INTO blue_alerts (engagement_id, type, mitre_ttp, escalated, timestamp) "
                     "VALUES (?,?,?,?,?)", (eng["id"], "ids", "T1003", 0, now))
        conn.commit()
    sm.set_metadata("blue_run_status", "complete", eng["id"])
    sm.record_coverage_snapshot(eng["id"])

    data = DashboardData(state_dir=str(tmp_path))
    resp = data.campaign_trend("C1")
    assert resp["campaign_id"] == "C1"
    assert len(resp["snapshots"]) == 1
    assert resp["snapshots"][0]["coverage_pct"] == 100.0


def test_campaign_trend_unknown_is_empty(tmp_path):
    data = DashboardData(state_dir=str(tmp_path))
    assert data.campaign_trend("nope") == {"campaign_id": "nope", "snapshots": []}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_campaign_endpoint.py -v`
Expected: FAIL — `DashboardData` has no attribute `campaign_trend`.

- [ ] **Step 3: Write minimal implementation**

Add to `webdash/data.py` after `coverage()` (`:186`):

```python
    def campaign_trend(self, campaign_id: str) -> dict:
        from state_manager import StateManager

        sm = StateManager(db_path=str(self.db_path))
        return {"campaign_id": campaign_id, "snapshots": sm.get_campaign_trend(campaign_id)}
```

Add the route to `webdash/api/monitor.py` after `/coverage` (`:56`):

```python
@router.get("/campaign/{campaign_id}/trend")
def get_campaign_trend(campaign_id: str, data: DashboardData = Depends(get_data)) -> dict:
    """Per-campaign detection-coverage trend over completed purple cycles (oldest first)."""
    return data.campaign_trend(campaign_id)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_campaign_endpoint.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add webdash/data.py webdash/api/monitor.py tests/test_campaign_endpoint.py
git commit -m "feat(api): add GET /api/campaign/{id}/trend endpoint"
```

---

### Task 9: Dashboard — `CampaignTrendView.tsx` + types + sidebar wiring

**Files:**
- Modify: `webdash/frontend/src/api.ts` (add types + fetch helper, after `CoverageResp` at `:50`)
- Create: `webdash/frontend/src/components/CampaignTrendView.tsx`
- Modify: `webdash/frontend/src/components/Sidebar.tsx` (add NAV entry), `webdash/frontend/src/App.tsx:121` (add `case "campaign-trend"`)
- Test: `cd webdash/frontend && npm run build` (type-check + bundle)

**Interfaces:**
- Consumes: `GET /api/campaign/{id}/trend` shape from Task 8.
- Produces: a sidebar view rendering the campaign's coverage trajectory.

- [ ] **Step 1: Add API types + fetch helper**

Append to `webdash/frontend/src/api.ts` after the `CoverageResp` block (`:50`):

```typescript
export interface TrendTtp { ttp: string; rung: string; time_to_detect_s: number | null; }
export interface TrendSnapshot {
  ts: string;
  coverage_pct: number;
  rung_counts: RungCounts;
  ttps: TrendTtp[];
}
export interface CampaignTrendResp {
  campaign_id: string;
  snapshots: TrendSnapshot[];
}

export function getCampaignTrend(campaignId: string): Promise<CampaignTrendResp> {
  return apiGet<CampaignTrendResp>(`/api/campaign/${encodeURIComponent(campaignId)}/trend`);
}
```

- [ ] **Step 2: Create the view**

`webdash/frontend/src/components/CampaignTrendView.tsx` — mirrors `PurpleCoverageView.tsx` conventions (Panel/Badge, RUNG color map, mono type). Text-input for campaign id → fetch → render per-snapshot rows. No charting dependency (avoids a build-time dep gamble; a table + inline bars conveys the trajectory):

```tsx
import { useState } from "react";
import { getCampaignTrend, CampaignTrendResp, TrendSnapshot } from "../api";
import { Badge, Panel } from "./Panel";

const RUNG_ORDER = ["PREVENTED", "ALERTED", "DETECTED", "LOGGED", "MISSED", "PENDING"] as const;
const RUNG_TEXT: Record<string, string> = {
  PREVENTED: "text-phos", ALERTED: "text-phos", DETECTED: "text-amber",
  LOGGED: "text-amber", MISSED: "text-red-400", PENDING: "text-slate-400",
};

function pctClass(pct: number): string {
  if (pct >= 80) return "text-phos";
  if (pct >= 50) return "text-amber";
  return "text-red-400";
}

function SnapshotRow({ snap, prevPct }: { snap: TrendSnapshot; prevPct: number | null }) {
  const delta = prevPct == null ? null : Math.round((snap.coverage_pct - prevPct) * 10) / 10;
  return (
    <div className="border-l-2 border-slate-500/40 bg-surface/40 px-3 py-1.5">
      <div className="flex items-center justify-between gap-2">
        <span className="font-mono text-xs text-dim">{snap.ts}</span>
        <span className="font-mono text-sm">
          <span className={pctClass(snap.coverage_pct)}>{snap.coverage_pct.toFixed(0)}%</span>
          {delta != null && (
            <span className={`ml-2 text-[10px] ${delta >= 0 ? "text-phos" : "text-red-400"}`}>
              {delta >= 0 ? "▲" : "▼"} {Math.abs(delta)}
            </span>
          )}
        </span>
      </div>
      <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 font-mono text-[10px] uppercase tracking-wider">
        {RUNG_ORDER.map((r) => (
          <span key={r} className={RUNG_TEXT[r]}>{r} {snap.rung_counts[r] ?? 0}</span>
        ))}
      </div>
    </div>
  );
}

export function CampaignTrendView() {
  const [campaignId, setCampaignId] = useState("");
  const [data, setData] = useState<CampaignTrendResp | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function load(e: React.FormEvent) {
    e.preventDefault();
    if (!campaignId.trim()) return;
    setLoading(true); setErr(null);
    try {
      setData(await getCampaignTrend(campaignId.trim()));
    } catch (ex) {
      setErr(ex instanceof Error ? ex.message : String(ex));
    } finally {
      setLoading(false);
    }
  }

  return (
    <Panel title="Campaign Trend" className="h-full">
      <form onSubmit={load} className="mb-3 flex gap-2">
        <input
          value={campaignId}
          onChange={(e) => setCampaignId(e.target.value)}
          placeholder="campaign id"
          className="flex-1 bg-surface/60 border border-slate-500/40 px-2 py-1 font-mono text-sm text-slate-200"
        />
        <button type="submit" className="px-3 py-1 font-mono text-sm border border-phos/60 text-phos">
          load
        </button>
      </form>
      {err && <div className="mb-3"><Badge ok={false}>{err}</Badge></div>}
      {loading && <div className="text-dim text-xs italic">loading…</div>}
      {data && data.snapshots.length === 0 && (
        <div className="text-dim text-xs italic">no snapshots for this campaign</div>
      )}
      <div className="space-y-1">
        {data?.snapshots.map((snap, i) => (
          <SnapshotRow
            key={snap.ts}
            snap={snap}
            prevPct={i === 0 ? null : data.snapshots[i - 1].coverage_pct}
          />
        ))}
      </div>
    </Panel>
  );
}
```

*(Confirm `Panel`/`Badge` export names against `./Panel` — they match `PurpleCoverageView.tsx` usage.)*

- [ ] **Step 3: Wire into sidebar + view switch**

Add a NAV entry in `Sidebar.tsx` next to the Purple/coverage entry (in the monitoring group, near `:31`):

```typescript
      { id: "campaign-trend", label: "Campaign Trend" },
```

Add the case in `App.tsx` (after `:121`), plus the import at the top with the other view imports (near `:17`):

```tsx
import { CampaignTrendView } from "./components/CampaignTrendView";
```

```tsx
                case "campaign-trend": return <Solo><CampaignTrendView /></Solo>;
```

- [ ] **Step 4: Verify — type-check + build**

Run: `cd webdash/frontend && npm run build`
Expected: build succeeds, no TS errors.

- [ ] **Step 5: Commit**

```bash
git add webdash/frontend/src/api.ts webdash/frontend/src/components/CampaignTrendView.tsx webdash/frontend/src/components/Sidebar.tsx webdash/frontend/src/App.tsx
git commit -m "feat(webdash): add CampaignTrendView + sidebar wiring"
```

---

## Final verification

- [ ] Run full backend suite: `pytest tests/ -v` — all green.
- [ ] Frontend build clean: `cd webdash/frontend && npm run build`.
- [ ] Manual: `python main.py purple --target 10.0.0.1 --campaign-id demo --iterations 2` then `GET /api/campaign/demo/trend` returns 2 snapshots.
