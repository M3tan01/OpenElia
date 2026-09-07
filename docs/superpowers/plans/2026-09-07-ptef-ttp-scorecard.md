# PTEF Per-TTP Detection Scorecard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace OpenElia's crude `alerts/findings` purple-team ratio with a SCYTHE PTEF-style per-TTP detection scorecard (a 6-rung maturity ladder + time-to-detect), surfaced in the purple-loop console, the reporter, and the web dashboard.

**Architecture:** Add one nullable `mitre_ttp` column to `response_actions` (idempotent migration, matching the existing `blue_alerts.mitre_ttp` migration). Extend `StateManager.get_coverage()` **additively** — the legacy tri-state keys (`coverage_pct`/`caught`/`missed`/`pending`) keep their exact current logic and values; a separate pass adds `scorecard` (per executed TTP: highest-maturity rung + time-to-detect) and `rung_counts`. Consumers (purple loop, reporter, webdash) read the new keys; the n8n egress path is deliberately untouched.

**Tech Stack:** Python 3.11+, sqlite3 (stdlib), pytest; FastAPI + React/TypeScript (webdash). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-07-ptef-ttp-scorecard-design.md`

## Global Constraints

- Python 3.11+. Activate venv before running anything: `source venv/bin/activate` (fall back to `python3` if `python` is absent).
- **Back-compat is a hard requirement.** `get_coverage()` keys `coverage_pct`, `caught`, `missed`, `pending` MUST keep their current values and logic — the live n8n contract (`webdash/runner.py:140`) and 6 existing tests in `tests/test_state_coverage.py` depend on them. The scorecard is a *separate additive pass*, never derived from or feeding back into the tri-state.
- **TTP base-normalization** everywhere via the existing module helper `state_manager._base_ttp` (`T1003.001` → `T1003`).
- **Escalation-signal invariant:** the rung ladder reads `blue_alerts.escalated` (set by `mark_alert_escalated`), **never** `blue_analyses.escalate`. See spec Detection Ladder note.
- **PII boundary:** `scorecard` entries carry `title` (free-text finding title). It flows only through the localhost `data.py` API to the browser. It MUST NOT be added to the `webdash/runner.py` n8n `payload`. Leave `runner.py` exactly as-is.
- Rung precedence (highest wins): `PREVENTED`(5) > `ALERTED`(4) > `DETECTED`(3) > `LOGGED`(2) > `MISSED`(1) > `PENDING`(0).
- TDD: write the failing test first, watch it fail, implement minimally, watch it pass, commit. Commit messages use conventional-commit prefixes (`feat:`/`test:`/`refactor:`).

---

## File Structure

- `state_manager.py` — **modify.** Add `_ttd_seconds()` module helper; add the `response_actions.mitre_ttp` migration; persist `mitre_ttp` in `add_response_action`; extend `get_coverage` with the additive scorecard pass. This is the core; everything else consumes it.
- `agents/blue/defender_res.py` — **modify.** Add `mitre_ttp` to the `write_response_action` tool JSON schema so the model emits it (`add_response_action` already reads it after Task 1).
- `main.py` (`cmd_purple`) — **modify.** Replace the crude per-iteration ratio print with a `rung_counts` line + newly-covered-TTP delta. Keep the `coverage_pct` early-convergence check.
- `agents/reporter_agent.py` — **modify.** Inject `scorecard` into the report `context` dict.
- `webdash/frontend/src/api.ts` — **modify.** Extend `CoverageResp`; add `ScorecardEntry` + `RungCounts` types.
- `webdash/frontend/src/components/PurpleCoverageView.tsx` — **modify.** Render the scorecard matrix (rung-colored rows + time-to-detect) below the existing tri-state sections.
- `tests/test_state_coverage.py` — **modify.** Add rung/precedence/normalization/time-to-detect/migration tests. Existing 6 assertions stay byte-for-byte.

---

## Task 1: Schema migration + `add_response_action` persists `mitre_ttp`

**Files:**
- Modify: `state_manager.py` (migration block after `:205`; `add_response_action` at `:528-539`)
- Test: `tests/test_state_coverage.py`

**Interfaces:**
- Consumes: existing `StateManager(db_path=...)`, `initialize_engagement`, `add_response_action(action_data: dict)`, `read(engagement_id)`.
- Produces: `response_actions.mitre_ttp` column (nullable TEXT); `add_response_action` now persists `action_data.get("mitre_ttp")`. Read back via `read(eid)["response_actions"][i]["mitre_ttp"]`.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_state_coverage.py`:

```python
def test_add_response_action_persists_mitre_ttp():
    st = _fresh_state()
    st.initialize_engagement(target="t", scope="u")
    eid = st.active_engagement_id
    st.add_response_action(
        {"action_type": "block_ip", "target": "10.0.0.5", "command": "iptables -I INPUT -s 10.0.0.5 -j DROP",
         "rationale": "C2", "mitre_ttp": "T1071.001"},
        engagement_id=eid,
    )
    ras = st.read(eid)["response_actions"]
    assert ras[0]["mitre_ttp"] == "T1071.001"


def test_add_response_action_without_mitre_ttp_defaults_null():
    st = _fresh_state()
    st.initialize_engagement(target="t", scope="u")
    eid = st.active_engagement_id
    st.add_response_action(
        {"action_type": "other", "target": "host", "command": "noop", "rationale": "r"},
        engagement_id=eid,
    )
    assert st.read(eid)["response_actions"][0]["mitre_ttp"] is None


def test_legacy_db_gains_response_actions_mitre_ttp_column():
    import sqlite3 as _sq, os as _os, tempfile as _tf
    fd, path = _tf.mkstemp(suffix=".db")
    _os.close(fd)
    # Simulate a pre-migration DB: response_actions without mitre_ttp.
    conn = _sq.connect(path)
    conn.execute(
        "CREATE TABLE response_actions (id INTEGER PRIMARY KEY AUTOINCREMENT, engagement_id TEXT, "
        "action_type TEXT, target TEXT, command TEXT, rationale TEXT, requires_approval INTEGER, logged_at TEXT)"
    )
    conn.commit()
    conn.close()
    # Opening via StateManager must run the idempotent migration without error.
    st = StateManager(db_path=path)
    cols = {row[1] for row in _sq.connect(path).execute("PRAGMA table_info(response_actions)").fetchall()}
    assert "mitre_ttp" in cols
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `source venv/bin/activate 2>/dev/null; python3 -m pytest tests/test_state_coverage.py -k "response_action or legacy_db" -v`
Expected: FAIL — `mitre_ttp` not persisted / column missing.

- [ ] **Step 3: Add the migration**

In `state_manager.py`, immediately after the `blue_alerts` `mitre_ttp` migration block (ends at `:205` with its `conn.commit()`), add:

```python
            # Idempotent migration: add mitre_ttp to response_actions if absent
            # (PTEF scorecard PREVENTED rung matches a response to a finding's TTP).
            existing_ra_cols = {
                row[1]
                for row in conn.execute("PRAGMA table_info(response_actions)").fetchall()
            }
            if "mitre_ttp" not in existing_ra_cols:
                try:
                    conn.execute("ALTER TABLE response_actions ADD COLUMN mitre_ttp TEXT")
                except sqlite3.OperationalError:
                    pass  # column added by a concurrent initializer — fine
            conn.commit()
```

- [ ] **Step 4: Persist the column in `add_response_action`**

Replace the INSERT in `add_response_action` (`:532-537`) with one that includes `mitre_ttp`:

```python
            cursor = conn.execute("""
                INSERT INTO response_actions (engagement_id, action_type, target, command, rationale, requires_approval, mitre_ttp, logged_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (eid, action_data.get("action_type"), action_data.get("target"),
                  action_data.get("command"), action_data.get("rationale"),
                  1 if action_data.get("requires_approval") else 0,
                  action_data.get("mitre_ttp"), ts))
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `source venv/bin/activate 2>/dev/null; python3 -m pytest tests/test_state_coverage.py -k "response_action or legacy_db" -v`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
git add state_manager.py tests/test_state_coverage.py
git commit -m "feat(state): add response_actions.mitre_ttp column for PTEF PREVENTED rung"
```

---

## Task 2: `get_coverage` scorecard + `rung_counts` + time-to-detect

**Files:**
- Modify: `state_manager.py` (module helper near `_base_ttp` at `:35`; `get_coverage` at `:567-611`)
- Test: `tests/test_state_coverage.py`

**Interfaces:**
- Consumes: `_base_ttp`, `response_actions.mitre_ttp` (Task 1), `blue_alerts.{escalated,timestamp,mitre_ttp}`, `blue_analyses.{alert_id,escalate}`, `findings.{mitre_ttp,timestamp}`, `mark_alert_escalated(alert_id)`, `add_blue_analysis(dict)`.
- Produces: `get_coverage()` return dict gains two keys:
  - `scorecard: list[dict]` — each `{"ttp": str, "title": str, "rung": str, "time_to_detect_s": int | None}`, sorted by rung precedence desc then `ttp` asc.
  - `rung_counts: dict[str, int]` — count per rung name; all six keys always present.
  - Legacy keys unchanged.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_state_coverage.py`. Helper to fetch an alert id and attach a dismissing analysis:

```python
def _first_alert_id(st, eid):
    return st.read(eid)["blue_alerts"][0]["id"]


def _rung_of(cov, ttp):
    return next(e["rung"] for e in cov["scorecard"] if e["ttp"] == ttp)


def test_rung_prevented_when_response_matches():
    st = _fresh_state()
    st.initialize_engagement(target="t", scope="u")
    eid = st.active_engagement_id
    _seed(st, eid, findings=[("T1071.001", "C2")], alerts=["T1071"], blue_status="complete")
    st.add_response_action(
        {"action_type": "block_ip", "target": "1.1.1.1", "command": "iptables -I INPUT -s 1.1.1.1 -j DROP",
         "rationale": "r", "mitre_ttp": "T1071"},
        engagement_id=eid,
    )
    cov = st.get_coverage(eid)
    assert _rung_of(cov, "T1071") == "PREVENTED"


def test_rung_alerted_when_alert_escalated():
    st = _fresh_state()
    st.initialize_engagement(target="t", scope="u")
    eid = st.active_engagement_id
    _seed(st, eid, findings=[("T1003", "LSASS")], alerts=["T1003"], blue_status="complete")
    st.mark_alert_escalated(_first_alert_id(st, eid), eid)
    cov = st.get_coverage(eid)
    assert _rung_of(cov, "T1003") == "ALERTED"


def test_rung_detected_when_alert_unescalated_no_analysis():
    st = _fresh_state()
    st.initialize_engagement(target="t", scope="u")
    eid = st.active_engagement_id
    _seed(st, eid, findings=[("T1003", "LSASS")], alerts=["T1003"], blue_status="complete")
    cov = st.get_coverage(eid)
    assert _rung_of(cov, "T1003") == "DETECTED"


def test_rung_logged_when_dismissing_analysis_present():
    st = _fresh_state()
    st.initialize_engagement(target="t", scope="u")
    eid = st.active_engagement_id
    _seed(st, eid, findings=[("T1003", "LSASS")], alerts=["T1003"], blue_status="complete")
    aid = _first_alert_id(st, eid)
    st.add_blue_analysis({"alert_id": aid, "verdict": "fp", "escalate": False}, engagement_id=eid)
    cov = st.get_coverage(eid)
    assert _rung_of(cov, "T1003") == "LOGGED"


def test_rung_missed_when_blue_complete_no_signal():
    st = _fresh_state()
    st.initialize_engagement(target="t", scope="u")
    eid = st.active_engagement_id
    _seed(st, eid, findings=[("T1490", "VSS")], alerts=[], blue_status="complete")
    cov = st.get_coverage(eid)
    assert _rung_of(cov, "T1490") == "MISSED"


def test_rung_pending_when_blue_running_no_signal():
    st = _fresh_state()
    st.initialize_engagement(target="t", scope="u")
    eid = st.active_engagement_id
    _seed(st, eid, findings=[("T1490", "VSS")], alerts=[], blue_status="running")
    cov = st.get_coverage(eid)
    assert _rung_of(cov, "T1490") == "PENDING"


def test_rung_counts_and_sort_order():
    st = _fresh_state()
    st.initialize_engagement(target="t", scope="u")
    eid = st.active_engagement_id
    _seed(st, eid, findings=[("T1003", "a"), ("T1490", "b")], alerts=["T1003"], blue_status="complete")
    cov = st.get_coverage(eid)
    assert cov["rung_counts"]["DETECTED"] == 1
    assert cov["rung_counts"]["MISSED"] == 1
    # sorted by precedence desc: DETECTED(3) before MISSED(1)
    assert [e["ttp"] for e in cov["scorecard"]] == ["T1003", "T1490"]


def test_time_to_detect_none_when_no_alert():
    st = _fresh_state()
    st.initialize_engagement(target="t", scope="u")
    eid = st.active_engagement_id
    _seed(st, eid, findings=[("T1490", "b")], alerts=[], blue_status="complete")
    cov = st.get_coverage(eid)
    assert next(e for e in cov["scorecard"] if e["ttp"] == "T1490")["time_to_detect_s"] is None


def test_time_to_detect_clamps_and_computes():
    from state_manager import _ttd_seconds
    assert _ttd_seconds("2026-09-07T10:00:00+00:00", "2026-09-07T10:00:30+00:00") == 30
    assert _ttd_seconds("2026-09-07T10:00:30+00:00", "2026-09-07T10:00:00+00:00") == 0  # clock-skew clamp
    assert _ttd_seconds("garbage", "2026-09-07T10:00:00+00:00") is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `source venv/bin/activate 2>/dev/null; python3 -m pytest tests/test_state_coverage.py -k "rung or time_to_detect" -v`
Expected: FAIL — `scorecard`/`rung_counts` keys and `_ttd_seconds` don't exist.

- [ ] **Step 3: Add the `_ttd_seconds` module helper**

In `state_manager.py`, directly below `_base_ttp` (`:35`) add:

```python
def _ttd_seconds(finding_ts: str | None, alert_ts: str | None) -> int | None:
    """Seconds from earliest finding to earliest detecting alert for a TTP.
    Returns None on missing/malformed timestamps; clamps negatives (clock skew) to 0."""
    try:
        delta = (datetime.fromisoformat(alert_ts) - datetime.fromisoformat(finding_ts)).total_seconds()
    except (TypeError, ValueError):
        return None
    return max(0, int(delta))
```

(`datetime` is already imported at `state_manager.py:15`.)

- [ ] **Step 4: Extend `get_coverage` with the additive scorecard pass**

In `get_coverage`, inside the existing `with self._get_conn() as conn:` block, **after** the `alert_rows` query (`:582`), add the extra reads:

```python
            alert_detail_rows = conn.execute(
                "SELECT id, mitre_ttp, escalated, timestamp FROM blue_alerts "
                "WHERE engagement_id = ? AND mitre_ttp IS NOT NULL AND mitre_ttp != ''",
                (engagement_id,),
            ).fetchall()
            finding_ts_rows = conn.execute(
                "SELECT mitre_ttp, timestamp FROM findings "
                "WHERE engagement_id = ? AND mitre_ttp IS NOT NULL AND mitre_ttp != ''",
                (engagement_id,),
            ).fetchall()
            response_rows = conn.execute(
                "SELECT mitre_ttp FROM response_actions "
                "WHERE engagement_id = ? AND mitre_ttp IS NOT NULL AND mitre_ttp != ''",
                (engagement_id,),
            ).fetchall()
            dismiss_rows = conn.execute(
                "SELECT ba.mitre_ttp AS ttp FROM blue_analyses an "
                "JOIN blue_alerts ba ON an.alert_id = ba.id "
                "WHERE an.engagement_id = ? AND an.escalate = 0 "
                "AND ba.mitre_ttp IS NOT NULL AND ba.mitre_ttp != ''",
                (engagement_id,),
            ).fetchall()
```

Then **replace the `return {...}`** at the end of `get_coverage` (`:606-611`) with the scorecard computation followed by the extended return:

```python
        # ── PTEF scorecard: highest-maturity rung per executed (finding) base TTP ──
        # ISO-8601 UTC strings compare lexicographically == chronologically, so min()
        # over strings is safe for "earliest".
        finding_first_ts: dict[str, str] = {}
        for row in finding_ts_rows:
            base = _base_ttp(row["mitre_ttp"])
            if base and row["timestamp"] and (base not in finding_first_ts or row["timestamp"] < finding_first_ts[base]):
                finding_first_ts[base] = row["timestamp"]

        alert_by_base: dict[str, dict] = {}
        for row in alert_detail_rows:
            base = _base_ttp(row["mitre_ttp"])
            if not base:
                continue
            slot = alert_by_base.setdefault(base, {"escalated": False, "first_ts": None})
            if row["escalated"]:
                slot["escalated"] = True
            ts = row["timestamp"]
            if ts and (slot["first_ts"] is None or ts < slot["first_ts"]):
                slot["first_ts"] = ts

        prevented_bases = {_base_ttp(r["mitre_ttp"]) for r in response_rows}
        prevented_bases.discard("")
        dismissed_bases = {_base_ttp(r["ttp"]) for r in dismiss_rows}
        dismissed_bases.discard("")

        rung_precedence = {"PREVENTED": 5, "ALERTED": 4, "DETECTED": 3, "LOGGED": 2, "MISSED": 1, "PENDING": 0}
        scorecard = []
        for base, title in reps.items():
            if base in prevented_bases:
                rung = "PREVENTED"
            elif base in alert_by_base and alert_by_base[base]["escalated"]:
                rung = "ALERTED"
            elif base in alert_by_base and base in dismissed_bases:
                rung = "LOGGED"
            elif base in alert_by_base:
                rung = "DETECTED"
            elif blue_done:
                rung = "MISSED"
            else:
                rung = "PENDING"

            ttd = None
            if base in alert_by_base:
                ttd = _ttd_seconds(finding_first_ts.get(base), alert_by_base[base]["first_ts"])

            scorecard.append({"ttp": base, "title": title, "rung": rung, "time_to_detect_s": ttd})

        scorecard.sort(key=lambda e: (-rung_precedence[e["rung"]], e["ttp"]))
        rung_counts = {name: 0 for name in rung_precedence}
        for e in scorecard:
            rung_counts[e["rung"]] += 1

        return {
            "coverage_pct": coverage_pct,
            "caught": caught,
            "missed": missed,
            "pending": pending,
            "scorecard": scorecard,
            "rung_counts": rung_counts,
        }
```

Note: `blue_done` and `reps` already exist in `get_coverage` above the return; the legacy `caught/missed/pending/coverage_pct` block is unchanged.

- [ ] **Step 5: Run the full coverage suite (new + legacy back-compat)**

Run: `source venv/bin/activate 2>/dev/null; python3 -m pytest tests/test_state_coverage.py -v`
Expected: PASS — all new rung/ttd tests AND the 6 pre-existing tests (back-compat proof).

- [ ] **Step 6: Commit**

```bash
git add state_manager.py tests/test_state_coverage.py
git commit -m "feat(state): add PTEF per-TTP scorecard + rung_counts + time-to-detect to get_coverage"
```

---

## Task 3: `defender_res` emits `mitre_ttp` on `write_response_action`

**Files:**
- Modify: `agents/blue/defender_res.py` (`_get_res_tools`, `write_response_action` schema at `:75-108`)
- Test: `tests/test_defender_res.py`

**Interfaces:**
- Consumes: `add_response_action` from Task 1 (already persists `action_data.get("mitre_ttp")`).
- Produces: the `write_response_action` tool schema advertises an optional `mitre_ttp` string property, so the model supplies it and it reaches `add_response_action` via the existing `tool_input` passthrough at `defender_res.py:253`.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_defender_res.py`:

```python
def test_write_response_action_schema_advertises_mitre_ttp():
    from agents.blue.defender_res import DefenderRes
    from state_manager import StateManager
    import tempfile, os
    fd, path = tempfile.mkstemp(suffix=".db"); os.close(fd)
    agent = DefenderRes(StateManager(db_path=path))
    tools = agent._get_res_tools()
    schema = next(t for t in tools if t["name"] == "write_response_action")["input_schema"]
    assert "mitre_ttp" in schema["properties"]
    assert schema["properties"]["mitre_ttp"]["type"] == "string"
    # optional — must NOT be in required
    assert "mitre_ttp" not in schema["required"]
```

(If `DefenderRes.__init__` needs a `brain_tier` or other kwarg, mirror the construction already used elsewhere in `tests/test_defender_res.py`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `source venv/bin/activate 2>/dev/null; python3 -m pytest tests/test_defender_res.py::test_write_response_action_schema_advertises_mitre_ttp -v`
Expected: FAIL — `mitre_ttp` not in properties.

- [ ] **Step 3: Add the property to the schema**

In `agents/blue/defender_res.py`, in the `write_response_action` tool's `properties` (after the `rationale` property, before `requires_approval`), add:

```python
                        "mitre_ttp": {
                            "type": "string",
                            "description": "MITRE ATT&CK technique this response counters, e.g. 'T1071.001'. Used for PTEF PREVENTED-rung scoring — set it whenever the technique is known.",
                        },
```

Leave `required` unchanged (`mitre_ttp` stays optional).

- [ ] **Step 4: Run test to verify it passes**

Run: `source venv/bin/activate 2>/dev/null; python3 -m pytest tests/test_defender_res.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add agents/blue/defender_res.py tests/test_defender_res.py
git commit -m "feat(defender_res): advertise mitre_ttp on write_response_action for PTEF scoring"
```

---

## Task 4: `cmd_purple` renders `rung_counts` + newly-covered delta per iteration

**Files:**
- Modify: `main.py` (`cmd_purple` coverage-delta block at `:577-591`)

**Interfaces:**
- Consumes: `StateManager.get_coverage(engagement_id)` (Task 2) → `rung_counts`, `scorecard`, `coverage_pct`.
- Produces: console output only. Early-convergence still keyed on `coverage_pct`.

- [ ] **Step 1: Establish the state handle**

`cmd_purple` already holds a `state` object (used for `state.read()` at `:570`). Confirm the active engagement id is reachable as `state.active_engagement_id`. If a local `eid`/engagement id variable already exists in `cmd_purple`, reuse it instead.

- [ ] **Step 2: Replace the crude ratio block**

Replace the coverage-delta block (`main.py:577-591`, from the `# ── Coverage Delta ──` comment through the early-convergence `break`) with:

```python
        # ── Coverage Delta (PTEF per-TTP scorecard) ────────────────────────────
        cov = state.get_coverage(state.active_engagement_id)
        rc = cov["rung_counts"]
        coverage_pct = cov["coverage_pct"]
        rung_line = " · ".join(f"{name} {rc[name]}" for name in
                               ("PREVENTED", "ALERTED", "DETECTED", "LOGGED", "MISSED", "PENDING"))
        print(f"[Purple Loop] Detection ladder: {rung_line}")

        covered_now = {e["ttp"] for e in cov["scorecard"] if e["rung"] not in ("MISSED", "PENDING")}
        newly_covered = covered_now - prev_covered
        if newly_covered:
            print(f"[Purple Loop] Newly covered this iteration: {', '.join(sorted(newly_covered))}")
        print(f"[Purple Loop] Coverage: {coverage_pct}% ({len(covered_now)}/{len(cov['scorecard'])} TTPs)")
        prev_covered = covered_now

        prev_findings = current_findings
        prev_blue_alerts = current_alerts

        if coverage_pct >= 100 and current_findings:
            print(f"[Purple Loop] Full detection coverage achieved at iteration {i} — converging early.")
            break
```

- [ ] **Step 3: Initialize `prev_covered` before the loop**

Find where the loop's other `prev_*` accumulators are initialized (e.g. `prev_blue_alerts = []` before the `for i in ...` purple loop) and add alongside them:

```python
    prev_covered: set[str] = set()
```

- [ ] **Step 4: Smoke-check import/parse**

Run: `source venv/bin/activate 2>/dev/null; python3 -c "import ast; ast.parse(open('main.py').read()); print('parse OK')"`
Expected: `parse OK`. (No unit test — `cmd_purple` is an async CLI orchestration path; behavior is covered by the `get_coverage` tests it calls.)

- [ ] **Step 5: Commit**

```bash
git add main.py
git commit -m "feat(purple): render PTEF detection ladder + newly-covered delta per iteration"
```

---

## Task 5: Reporter injects `scorecard` into report context

**Files:**
- Modify: `agents/reporter_agent.py` (`run()` context dict at `:88-95`)
- Test: `tests/test_reporter_agent.py` (create if absent)

**Interfaces:**
- Consumes: `self.state.get_coverage(self.state.active_engagement_id)` (Task 2).
- Produces: the LLM `context` dict in `run()` gains a `ptef_scorecard` key (the `scorecard` list) and a `rung_counts` key, alongside the existing `mitre_coverage` heatmap.

- [ ] **Step 1: Write the failing test**

Create/append `tests/test_reporter_agent.py`. Verify the context builder includes the scorecard. Since `run()` calls the LLM, extract the context assembly by asserting on `get_coverage` wiring through a lightweight check:

```python
def test_reporter_run_context_includes_ptef_scorecard(monkeypatch):
    import asyncio, json
    from agents.reporter_agent import ReporterAgent
    from state_manager import StateManager
    import tempfile, os
    fd, path = tempfile.mkstemp(suffix=".db"); os.close(fd)
    st = StateManager(db_path=path)
    st.initialize_engagement(target="t", scope="u")
    eid = st.active_engagement_id
    st.add_finding(severity="high", title="LSASS", description="d", evidence="e",
                   mitre_ttp="T1003", source_agent="pentester_ex", engagement_id=eid)
    st.add_blue_alert(alert_type="A", description="d", severity="high",
                      source="defender_mon", engagement_id=eid, mitre_ttp="T1003")
    st.set_metadata("blue_run_status", "complete", eid)

    agent = ReporterAgent(st)
    captured = {}

    async def fake_call(system, messages, tools):
        captured["messages"] = messages
        return "REPORT"

    monkeypatch.setattr(agent, "_call_with_tools", fake_call)
    asyncio.run(agent.run("test"))
    payload = captured["messages"][0]["content"]
    assert "ptef_scorecard" in payload
    assert "T1003" in payload
```

(Match the real class name — the file may export `ReporterAgent` or `Reporter`. Match the real LLM entry method — it may be `_call_with_tools`; adjust the `monkeypatch.setattr` target to whatever `run()` actually awaits.)

- [ ] **Step 2: Run test to verify it fails**

Run: `source venv/bin/activate 2>/dev/null; python3 -m pytest tests/test_reporter_agent.py -v`
Expected: FAIL — `ptef_scorecard` not in payload.

- [ ] **Step 3: Inject the scorecard into `run()`'s context**

In `agents/reporter_agent.py`, in `run()` where `context` is built (`:88-95`), after the `mitre_coverage` entry add the coverage read and two keys:

```python
        coverage = self.state.get_coverage(self.state.active_engagement_id)
```

and inside the `context = {...}` dict add:

```python
            "ptef_scorecard": coverage["scorecard"],
            "rung_counts": coverage["rung_counts"],
```

- [ ] **Step 4: Run test to verify it passes**

Run: `source venv/bin/activate 2>/dev/null; python3 -m pytest tests/test_reporter_agent.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add agents/reporter_agent.py tests/test_reporter_agent.py
git commit -m "feat(reporter): inject PTEF scorecard + rung counts into report context"
```

---

## Task 6: webdash renders the scorecard matrix

**Files:**
- Modify: `webdash/frontend/src/api.ts` (`:41-42`)
- Modify: `webdash/frontend/src/components/PurpleCoverageView.tsx`

**Interfaces:**
- Consumes: `/api/coverage` response — now carries `scorecard` + `rung_counts` (Task 2, already flows through `webdash/data.py:186` unchanged).
- Produces: extended `CoverageResp` type; a scorecard matrix rendered in `PurpleCoverageView`.

- [ ] **Step 1: Extend the API types**

In `webdash/frontend/src/api.ts`, replace lines `41-42`:

```typescript
export interface CoverageTtp { ttp: string; title: string; }
export interface ScorecardEntry { ttp: string; title: string; rung: string; time_to_detect_s: number | null; }
export type RungCounts = Record<string, number>;
export interface CoverageResp {
  coverage_pct: number;
  caught: CoverageTtp[];
  missed: CoverageTtp[];
  pending: CoverageTtp[];
  scorecard: ScorecardEntry[];
  rung_counts: RungCounts;
}
```

- [ ] **Step 2: Render the scorecard matrix**

In `webdash/frontend/src/components/PurpleCoverageView.tsx`:

Update the import on line 1:

```typescript
import { apiGet, CoverageResp, CoverageTtp, ScorecardEntry } from "../api";
```

Add a rung → color map and a matrix row component above `export function PurpleCoverageView()`:

```typescript
const RUNG_CLASS: Record<string, string> = {
  PREVENTED: "border-phos/60 text-phos",
  ALERTED:   "border-phos/60 text-phos",
  DETECTED:  "border-amber/60 text-amber",
  LOGGED:    "border-amber/60 text-amber",
  MISSED:    "border-red-400/60 text-red-400",
  PENDING:   "border-slate-500/60 text-slate-400",
};

function ScorecardRow({ e }: { e: ScorecardEntry }) {
  const cls = RUNG_CLASS[e.rung] ?? "border-slate-500/60 text-slate-400";
  const ttd = e.time_to_detect_s == null ? "—" : `${e.time_to_detect_s}s`;
  return (
    <div className={`flex items-center justify-between gap-2 border-l-2 ${cls} bg-surface/40 px-3 py-1.5`}>
      <span className="font-mono text-sm">
        <span className="text-amber/80">{e.ttp}</span>
        <span className="text-slate-200 ml-2">{e.title}</span>
      </span>
      <span className="font-mono text-[10px] uppercase tracking-wider shrink-0">
        {e.rung} · {ttd}
      </span>
    </div>
  );
}
```

Inside the `<Panel>`, after the existing tri-state `<div className="space-y-3">…</div>` block (closes at line 66), add a scorecard section:

```typescript
      {data && data.scorecard.length > 0 && (
        <div className="mt-4 space-y-1">
          <div className="font-display uppercase tracking-wider text-dim text-[11px]">
            🎯 detection ladder · {data.scorecard.length}
          </div>
          {data.scorecard.map((e, i) => (
            <ScorecardRow key={`${e.ttp}-${i}`} e={e} />
          ))}
        </div>
      )}
```

- [ ] **Step 3: Build the frontend to verify it compiles**

Run: `cd webdash/frontend && npm run build`
Expected: build succeeds, no TypeScript errors. (If `npm` deps are not installed in this environment, confirm with the user before running `npm install` — it is a >1MB install.)

- [ ] **Step 4: Commit**

```bash
git add webdash/frontend/src/api.ts webdash/frontend/src/components/PurpleCoverageView.tsx
git commit -m "feat(webdash): render PTEF detection-ladder scorecard in Purple Coverage view"
```

---

## Final Verification

- [ ] **Full backend suite green:**

Run: `source venv/bin/activate 2>/dev/null; python3 -m pytest tests/ -v`
Expected: all pass, including the 6 original `test_state_coverage.py` assertions (back-compat) and every new rung/ttd/migration/schema/reporter test.

- [ ] **n8n PII guard intact:** confirm `git diff main -- webdash/runner.py` is empty — the n8n egress path must be untouched (scorecard titles never leave localhost).

---

## Self-Review Notes (author)

- **Spec coverage:** §1 migration + add_response_action → Task 1. §"Detection Ladder" + Time-to-Detect + get_coverage extension → Task 2. §2 defender_res → Task 3. §3 cmd_purple → Task 4. §4 reporter → Task 5. §5 webdash (data.py needs no change; type + PurpleCoverageView) → Task 6. §"Testing" rungs/precedence/normalization/ttd/migration → Tasks 1–2 tests. All spec sections mapped.
- **Spec §5 filepath correction:** spec originally named `AgentsView.tsx`; the live coverage component is `PurpleCoverageView.tsx` (spec and this plan both corrected).
- **Type consistency:** scorecard entry shape `{ttp, title, rung, time_to_detect_s}` is identical in Task 2 (Python dict), Task 5 (passed through), and Task 6 (`ScorecardEntry` TS interface). `rung_counts` keys are the six precedence names in Task 2, iterated in the same order in Task 4's console line.
- **Escalation invariant honored:** Task 2 reads `blue_alerts.escalated` for ALERTED/DETECTED/LOGGED discrimination, never `blue_analyses.escalate`.
