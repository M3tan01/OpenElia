# Purple Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Score, display, and emit per-engagement purple-team coverage — which red-team MITRE TTPs the blue team actually caught — with a tri-state (caught/pending/missed) that never false-reports a miss mid-run.

**Architecture:** Correlation is a MITRE-TTP join, not a threaded id. Red findings already carry `mitre_ttp`; blue detectors already compute the technique but discard it — this plan persists it on `blue_alerts` and joins the two sides in pure SQL (`StateManager.get_coverage`). A `metadata` key (`blue_run_status`) written by the orchestrator around the blue batch gates the missed/pending distinction so a UI polling mid-run sees `pending`, not false misses. A new `GET /api/coverage` route feeds a dedicated React panel, and completed purple runs emit coverage to the operator's n8n webhook over the existing SSRF-guarded `_notify` path.

**Tech Stack:** Python 3.11 (stdlib `sqlite3`, `pytest`/`pytest-asyncio`), FastAPI (webdash), React + TypeScript (Vite, `usePoll` hook, Tailwind), n8n (external, via webhook).

## Global Constraints

- Python 3.11+; tests are `pytest` + `pytest-asyncio`, files `tests/test_<module>.py`. Run with `venv/bin/pytest` or `python3 -m pytest` — `python` is not on PATH.
- No `AgentTask` schema change, no `findings`-schema change, no opaque correlation id, no new engine tier, no worker-pool change, no telemetry tagging, no red-agent change.
- Exactly one new DB column: `blue_alerts.mitre_ttp TEXT` (nullable). Race gate reuses the existing `metadata` key/value store (`set_metadata`/`get_metadata`), NOT the `phases` table.
- `add_blue_alert` gains an **optional** `mitre_ttp: str | None = None` param — default keeps every existing caller and test valid.
- TTPs normalized to base technique (`T1003.001` → `T1003`) on BOTH sides before comparison.
- `coverage_pct = caught / (caught + missed)`; pending is EXCLUDED from the denominator. Zero-resolved → `coverage_pct = 0`.
- Localhost-only project; every webdash route stays token-gated (`Depends(require_token)` via the shared router). n8n emit is best-effort: failure logged, never blocks the run.
- Frequent commits — one per task. Never blanket `git add`; use explicit pathspecs. A pre-commit secret scan runs; keep secrets out of diffs.

---

## Task 1: `add_blue_alert` mitre_ttp param + `blue_alerts` column + migration guard

**Files:**
- Modify: `state_manager.py` (`blue_alerts` `CREATE TABLE` def; new idempotent `ALTER TABLE` guard; `add_blue_alert` signature + INSERT)
- Test: `tests/test_state_coverage.py` (new file)

**Interfaces:**
- Consumes: existing `StateManager(db_path)` constructor and its schema-init path.
- Produces: `StateManager.add_blue_alert(self, alert_type: str, description: str, severity: str, source: str, engagement_id: str | None = None, mitre_ttp: str | None = None) -> None` — persists `mitre_ttp` into the new `blue_alerts.mitre_ttp` column (NULL when omitted).

- [ ] **Step 1: Write the failing test**

Add to a new file `tests/test_state_coverage.py`:

```python
import os
import tempfile

from state_manager import StateManager


def _fresh_state() -> StateManager:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return StateManager(db_path=path)


def test_add_blue_alert_persists_mitre_ttp():
    st = _fresh_state()
    eid = st.create_engagement(target="10.0.0.1", task="unit")
    st.add_blue_alert(
        alert_type="LSASS_ACCESS",
        description="handle to lsass",
        severity="high",
        source="defender_mon",
        engagement_id=eid,
        mitre_ttp="T1003.001",
    )
    alerts = st.get_blue_alerts(eid)
    assert alerts[0]["mitre_ttp"] == "T1003.001"


def test_add_blue_alert_without_mitre_ttp_defaults_null():
    st = _fresh_state()
    eid = st.create_engagement(target="10.0.0.1", task="unit")
    st.add_blue_alert(
        alert_type="GENERIC",
        description="no technique",
        severity="low",
        source="defender_hunt",
        engagement_id=eid,
    )
    alerts = st.get_blue_alerts(eid)
    assert alerts[0]["mitre_ttp"] is None
```

Before writing, confirm the real helper names with `grep -n "def create_engagement\|def get_blue_alerts\|def add_blue_alert" state_manager.py`. If `get_blue_alerts` has a different name (e.g. `list_blue_alerts`), use the real one; if none returns rows as dicts, query the column directly via `st.conn.execute("SELECT mitre_ttp FROM blue_alerts").fetchone()`.

- [ ] **Step 2: Run test to verify it fails**

Run: `venv/bin/pytest tests/test_state_coverage.py -v`
Expected: FAIL — `add_blue_alert() got an unexpected keyword argument 'mitre_ttp'` (or `no such column: mitre_ttp`).

- [ ] **Step 3: Write minimal implementation**

In `state_manager.py`:

1. Add the column to the `blue_alerts` `CREATE TABLE IF NOT EXISTS` definition. Append `mitre_ttp TEXT` as the last column (after `escalated_at`):

```python
# inside the blue_alerts CREATE TABLE IF NOT EXISTS (...) string, last column:
                mitre_ttp TEXT
```

2. Add an idempotent migration guard where the other schema-init/ALTERs run (search `PRAGMA table_info` or the schema-init method). Pattern:

```python
cols = {row[1] for row in self.conn.execute("PRAGMA table_info(blue_alerts)")}
if "mitre_ttp" not in cols:
    self.conn.execute("ALTER TABLE blue_alerts ADD COLUMN mitre_ttp TEXT")
```

3. Update `add_blue_alert` — add the param and the INSERT column/value:

```python
def add_blue_alert(
    self,
    alert_type: str,
    description: str,
    severity: str,
    source: str,
    engagement_id: str | None = None,
    mitre_ttp: str | None = None,
) -> None:
    eid = engagement_id or self.active_engagement_id
    self.conn.execute(
        "INSERT INTO blue_alerts "
        "(engagement_id, type, description, severity, source, mitre_ttp) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (eid, alert_type, description, severity, source, mitre_ttp),
    )
    self.conn.commit()
```

Match the exact existing INSERT column list and the exact `engagement_id` resolution the current method uses — read the current body first and add only `mitre_ttp` to the column tuple and values tuple. Do not change the other columns.

- [ ] **Step 4: Run test to verify it passes**

Run: `venv/bin/pytest tests/test_state_coverage.py -v`
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git add state_manager.py tests/test_state_coverage.py
git commit -m "feat(state): persist mitre_ttp on blue_alerts + migration guard"
```

---

## Task 2: `get_coverage` tri-state SQL with base-normalization + blue_run_status gate

**Files:**
- Modify: `state_manager.py` (new `get_coverage` method; a small base-normalize helper)
- Test: `tests/test_state_coverage.py`

**Interfaces:**
- Consumes: `add_blue_alert(..., mitre_ttp=...)` from Task 1; existing `add_finding(..., mitre_ttp=...)`, `set_metadata(key, value, engagement_id)`, `get_metadata(key, engagement_id)`.
- Produces: `StateManager.get_coverage(self, engagement_id: str) -> dict` returning
  `{"coverage_pct": float, "caught": [{"ttp": str, "title": str}], "missed": [...], "pending": [...]}`.
  Also `_base_ttp(ttp: str) -> str` (module-level or static): `"T1003.001" -> "T1003"`, `None`/empty → `""`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_state_coverage.py`:

```python
def _seed(st, eid, *, findings, alerts, blue_status):
    for ttp, title in findings:
        st.add_finding(
            severity="high", title=title, description="d", evidence="e",
            mitre_ttp=ttp, source_agent="pentester_ex", engagement_id=eid,
        )
    for ttp in alerts:
        st.add_blue_alert(
            alert_type="A", description="d", severity="high",
            source="defender_mon", engagement_id=eid, mitre_ttp=ttp,
        )
    if blue_status is not None:
        st.set_metadata("blue_run_status", blue_status, eid)


def test_caught_when_alert_matches_and_blue_complete():
    st = _fresh_state()
    eid = st.create_engagement(target="t", task="u")
    _seed(st, eid, findings=[("T1003", "LSASS")], alerts=["T1003"], blue_status="complete")
    cov = st.get_coverage(eid)
    assert [c["ttp"] for c in cov["caught"]] == ["T1003"]
    assert cov["missed"] == [] and cov["pending"] == []


def test_missed_when_no_alert_and_blue_complete():
    st = _fresh_state()
    eid = st.create_engagement(target="t", task="u")
    _seed(st, eid, findings=[("T1490", "VSS delete")], alerts=[], blue_status="complete")
    cov = st.get_coverage(eid)
    assert [m["ttp"] for m in cov["missed"]] == ["T1490"]
    assert cov["caught"] == [] and cov["pending"] == []


def test_pending_when_no_alert_and_blue_running():
    st = _fresh_state()
    eid = st.create_engagement(target="t", task="u")
    _seed(st, eid, findings=[("T1071.001", "C2 beacon")], alerts=[], blue_status="running")
    cov = st.get_coverage(eid)
    assert [p["ttp"] for p in cov["pending"]] == ["T1071.001"]
    assert cov["missed"] == []


def test_base_technique_normalization_matches_subtechnique():
    st = _fresh_state()
    eid = st.create_engagement(target="t", task="u")
    _seed(st, eid, findings=[("T1003.001", "LSASS")], alerts=["T1003"], blue_status="complete")
    cov = st.get_coverage(eid)
    assert len(cov["caught"]) == 1 and cov["missed"] == []


def test_coverage_pct_excludes_pending_and_zero_resolved():
    st = _fresh_state()
    eid = st.create_engagement(target="t", task="u")
    _seed(
        st, eid,
        findings=[("T1003", "a"), ("T1490", "b"), ("T1071.001", "c")],
        alerts=["T1003"], blue_status="running",
    )
    # blue still running: T1003 caught, others pending, none missed → 1/(1+0)=100
    cov = st.get_coverage(eid)
    assert cov["coverage_pct"] == 100.0

    eid2 = st.create_engagement(target="t", task="u")
    _seed(st, eid2, findings=[], alerts=[], blue_status=None)
    assert st.get_coverage(eid2)["coverage_pct"] == 0
```

Confirm `add_finding`'s real signature first: `grep -n "def add_finding" state_manager.py`. If it takes no `engagement_id` kwarg (writes to active engagement), drop that kwarg from `_seed` and rely on `create_engagement` setting the active id.

- [ ] **Step 2: Run test to verify it fails**

Run: `venv/bin/pytest tests/test_state_coverage.py -v`
Expected: FAIL — `AttributeError: 'StateManager' object has no attribute 'get_coverage'`.

- [ ] **Step 3: Write minimal implementation**

Add to `state_manager.py`:

```python
def _base_ttp(ttp: str | None) -> str:
    """T1003.001 -> T1003; None/empty -> ''."""
    if not ttp:
        return ""
    return ttp.split(".", 1)[0].strip().upper()
```

```python
def get_coverage(self, engagement_id: str) -> dict:
    blue_done = self.get_metadata("blue_run_status", engagement_id) == "complete"

    # Representative finding per base-normalized TTP (first row wins for title).
    finding_rows = self.conn.execute(
        "SELECT mitre_ttp, title FROM findings "
        "WHERE engagement_id = ? AND mitre_ttp IS NOT NULL AND mitre_ttp != '' "
        "ORDER BY id ASC",
        (engagement_id,),
    ).fetchall()
    reps: dict[str, str] = {}
    for row in finding_rows:
        base = _base_ttp(row["mitre_ttp"])
        if base and base not in reps:
            reps[base] = row["title"]

    alert_rows = self.conn.execute(
        "SELECT mitre_ttp FROM blue_alerts "
        "WHERE engagement_id = ? AND mitre_ttp IS NOT NULL AND mitre_ttp != ''",
        (engagement_id,),
    ).fetchall()
    caught_bases = {_base_ttp(r["mitre_ttp"]) for r in alert_rows}
    caught_bases.discard("")

    caught, missed, pending = [], [], []
    for base, title in reps.items():
        entry = {"ttp": base, "title": title}
        if base in caught_bases:
            caught.append(entry)
        elif blue_done:
            missed.append(entry)
        else:
            pending.append(entry)

    resolved = len(caught) + len(missed)
    coverage_pct = round(100.0 * len(caught) / resolved, 1) if resolved else 0
    return {
        "coverage_pct": coverage_pct,
        "caught": caught,
        "missed": missed,
        "pending": pending,
    }
```

If `self.conn` rows are not dict-like (`sqlite3.Row`), confirm via `grep -n "row_factory" state_manager.py`. If rows are plain tuples, index positionally (`row[0]`, `row[1]`) instead of by key, matching the file's existing query style.

- [ ] **Step 4: Run test to verify it passes**

Run: `venv/bin/pytest tests/test_state_coverage.py -v`
Expected: PASS (all coverage tests).

- [ ] **Step 5: Commit**

```bash
git add state_manager.py tests/test_state_coverage.py
git commit -m "feat(state): get_coverage tri-state TTP scoring with blue_run_status gate"
```

---

## Task 3: Blue detectors pass `mitre_ttp` (defender_mon, defender_hunt)

**Files:**
- Modify: `agents/blue/defender_mon.py` (the `add_blue_alert(...)` call — pass `mitre_ttp=rule["mitre"]`)
- Modify: `agents/blue/defender_hunt.py` (the `add_blue_alert(...)` call — pass `mitre_ttp=tool_input["mitre_ttp"]`)
- Test: `tests/test_state_coverage.py` (a focused unit test per detector call-site is heavy to wire; instead assert the call passes the kwarg via a light stub — see Step 1)

**Interfaces:**
- Consumes: `add_blue_alert(..., mitre_ttp=...)` from Task 1.
- Produces: no new symbols — both detectors now persist the technique they already compute.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_state_coverage.py`. Use a stub StateManager that records the kwarg, driving the detectors' alert-writing helper directly rather than a full LLM run:

```python
class _RecordingState:
    def __init__(self):
        self.calls = []

    def add_blue_alert(self, **kwargs):
        self.calls.append(kwargs)


def test_defender_mon_passes_rule_mitre_to_alert():
    from agents.blue import defender_mon

    st = _RecordingState()
    rule = {"description": "lsass", "severity": "high", "mitre": "T1003.001"}
    # Drive the same code path the detector uses to persist an alert.
    defender_mon._persist_alert(st, "LSASS_ACCESS", rule)  # see Step 3 for shape

    assert st.calls[0]["mitre_ttp"] == "T1003.001"


def test_defender_hunt_passes_tool_mitre_to_alert():
    from agents.blue import defender_hunt

    st = _RecordingState()
    tool_input = {
        "alert_type": "PERSISTENCE_RUN_KEY",
        "description": "run key",
        "severity": "high",
        "mitre_ttp": "T1547.001",
    }
    defender_hunt._persist_alert(st, tool_input)  # see Step 3 for shape

    assert st.calls[0]["mitre_ttp"] == "T1547.001"
```

**First read both detectors** (`agents/blue/defender_mon.py` around the `add_blue_alert` call, `agents/blue/defender_hunt.py:83`). If there is no natural seam to call in isolation, do NOT invent `_persist_alert`. Instead, replace this test with a direct assertion at the existing call site by monkeypatching `state.add_blue_alert` and invoking the smallest existing method that reaches it, OR delete this test and rely on the change being covered end-to-end by Task 2's data-level tests plus a manual `grep` verification. Prefer the smallest change that proves the kwarg is passed; do not refactor the detectors to create a seam.

- [ ] **Step 2: Run test to verify it fails**

Run: `venv/bin/pytest tests/test_state_coverage.py -k defender -v`
Expected: FAIL — `mitre_ttp` missing from recorded call (or `AttributeError` if you kept the stub-seam approach and the seam doesn't exist yet — in which case switch to the monkeypatch approach noted above).

- [ ] **Step 3: Write minimal implementation**

The minimal, non-refactoring change is to add one kwarg at each existing call site.

In `agents/blue/defender_mon.py` — the current call is:

```python
self.state.add_blue_alert(
    alert_type=rule_name,
    description=rule["description"],
    severity=rule["severity"],
    source="defender_mon",
)
```

Change to add `mitre_ttp=rule.get("mitre")` (use `.get` so a rule without a `mitre` key still fires the alert as NULL rather than KeyError):

```python
self.state.add_blue_alert(
    alert_type=rule_name,
    description=rule["description"],
    severity=rule["severity"],
    source="defender_mon",
    mitre_ttp=rule.get("mitre"),
)
```

In `agents/blue/defender_hunt.py:83` — the current call is:

```python
add_blue_alert(
    alert_type=f"PERSISTENCE_{...}",
    description=...,
    severity=...,
    source="defender_hunt",
)
```

Add `mitre_ttp=tool_input["mitre_ttp"]` (required tool input — safe to index; keep whatever the exact existing args are):

```python
    ...
    source="defender_hunt",
    mitre_ttp=tool_input["mitre_ttp"],
)
```

If you kept the `_persist_alert` seam test from Step 1, you must actually introduce that tiny helper in each detector and route the existing call through it — but that is a refactor. Preferred: drop the seam test, keep the two call-site edits above, and prove them with `grep -n "mitre_ttp" agents/blue/defender_mon.py agents/blue/defender_hunt.py`.

- [ ] **Step 4: Run test to verify it passes**

Run: `venv/bin/pytest tests/test_state_coverage.py -k defender -v` (if you kept seam tests)
Or, if you dropped them: `grep -n "mitre_ttp" agents/blue/defender_mon.py agents/blue/defender_hunt.py` shows the kwarg at both call sites, and `venv/bin/pytest tests/ -k defender -v` (existing detector tests) stays green.

- [ ] **Step 5: Commit**

```bash
git add agents/blue/defender_mon.py agents/blue/defender_hunt.py tests/test_state_coverage.py
git commit -m "feat(blue): persist detected mitre_ttp on blue alerts"
```

---

## Task 4: Orchestrator `blue_run_status` markers around the blue batch

**Files:**
- Modify: `orchestrator.py` (purple branch of `route()` — set `running` before dispatching the blue batch, `complete` after blue AgentResults return)
- Test: `tests/test_orchestrator_pool.py` (or the existing orchestrator purple test file — confirm name)

**Interfaces:**
- Consumes: `set_metadata("blue_run_status", value, engagement_id)` from `StateManager`.
- Produces: after a purple `route()` completes, `get_metadata("blue_run_status", eid) == "complete"`; while the blue batch is in flight it is `"running"`.

- [ ] **Step 1: Write the failing test**

Confirm the real orchestrator entrypoint and how a purple run is driven in existing tests: `grep -n "def route\|purple\|_enqueue\|blue_run_status" orchestrator.py tests/test_orchestrator_pool.py tests/test_orchestrator_llm.py`.

Add a test (adapt to the existing async orchestrator test harness — mirror an existing purple test's setup):

```python
import pytest


@pytest.mark.asyncio
async def test_purple_run_marks_blue_run_status_complete(purple_orchestrator, state):
    # purple_orchestrator / state: reuse whatever fixtures existing orchestrator
    # tests use; if none, construct Orchestrator with a temp StateManager as those
    # tests do.
    eid = state.create_engagement(target="10.0.0.5", task="purple")
    await purple_orchestrator.route(command="purple", target="10.0.0.5", task="purple")
    assert state.get_metadata("blue_run_status", eid) == "complete"
```

If existing orchestrator tests stub the worker pool so agents don't really run, assert instead that `set_metadata` was called with `("blue_run_status", "running", ...)` then `("blue_run_status", "complete", ...)` in order (spy on `state.set_metadata`). Match the existing tests' mocking style rather than standing up real agents.

- [ ] **Step 2: Run test to verify it fails**

Run: `venv/bin/pytest tests/test_orchestrator_pool.py -k blue_run_status -v`
Expected: FAIL — status never set (`None`), or the spy records no `blue_run_status` calls.

- [ ] **Step 3: Write minimal implementation**

In `orchestrator.py`, in the purple branch of `route()` (the block that dispatches the blue batch after/alongside the red batch — around the `_BLUE_AGENTS` enqueue / the `await self._pool.run_until_complete(...)` for blue). Wrap the blue dispatch:

```python
# purple branch, before dispatching the blue batch:
self.state.set_metadata("blue_run_status", "running", engagement_id)

# ... existing blue-batch enqueue + await run_until_complete ...

# after the blue AgentResults have returned:
self.state.set_metadata("blue_run_status", "complete", engagement_id)
```

Use the exact `engagement_id` variable the purple branch already has in scope (read the branch first — it may be `eid`, `self.state.active_engagement_id`, or a local). If red and blue are dispatched as one combined `run_until_complete`, set `running` immediately before that call and `complete` immediately after it — the gate only needs to flip to `complete` once blue results exist. Do not add a new tier, queue, or await; only the two `set_metadata` lines.

- [ ] **Step 4: Run test to verify it passes**

Run: `venv/bin/pytest tests/test_orchestrator_pool.py -k blue_run_status -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator.py tests/test_orchestrator_pool.py
git commit -m "feat(orchestrator): mark blue_run_status running/complete around blue batch"
```

---

## Task 5: `/api/coverage` route + `DashboardData.coverage()`

**Files:**
- Modify: `webdash/data.py` (new `coverage()` method mirroring `heatmap()` at `webdash/data.py:174-178`)
- Modify: `webdash/api/monitor.py` (new `@router.get("/coverage")`)
- Test: `tests/test_webdash_control.py` (or the existing webdash API test file — confirm which asserts token-gating on `/api/heatmap`)

**Interfaces:**
- Consumes: `StateManager.get_coverage(engagement_id)` from Task 2; the existing `DashboardData` → `StateManager` access used by `heatmap()`.
- Produces: `GET /api/coverage` → JSON `{coverage_pct, caught, missed, pending}` for the active engagement; token-gated. `DashboardData.coverage() -> dict`.

- [ ] **Step 1: Write the failing test**

Confirm the existing webdash test pattern for `/api/heatmap`: `grep -rn "heatmap\|require_token\|X-Token\|/api/" tests/test_webdash_control.py`. Mirror it:

```python
def test_coverage_requires_token(client):
    resp = client.get("/api/coverage")
    assert resp.status_code == 401  # or 403 — match what /api/heatmap returns


def test_coverage_returns_buckets(client, auth_headers, seeded_engagement):
    resp = client.get("/api/coverage", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == {"coverage_pct", "caught", "missed", "pending"}
```

Reuse the exact fixtures (`client`, `auth_headers`, whatever seeds an engagement) that the existing `/api/heatmap` test uses. If there is no `seeded_engagement` fixture, assert only the key set and 200 with an empty active engagement (get_coverage returns the four keys with empty lists and `coverage_pct == 0`).

- [ ] **Step 2: Run test to verify it fails**

Run: `venv/bin/pytest tests/test_webdash_control.py -k coverage -v`
Expected: FAIL — 404 (route not registered).

- [ ] **Step 3: Write minimal implementation**

In `webdash/data.py`, mirror `heatmap()` (lines 174-178):

```python
def coverage(self) -> dict:
    return self.state.get_coverage(self.state.active_engagement_id)
```

Match `heatmap()`'s exact attribute access — if it reads the engagement id differently (e.g. `self._active_eid()` or a property), use the same accessor.

In `webdash/api/monitor.py`, mirror the `/api/heatmap` route:

```python
@router.get("/coverage")
def get_coverage(data: DashboardData = Depends(get_data)) -> dict:
    return data.coverage()
```

The `router` already carries `dependencies=[Depends(require_token)]`, so the route is token-gated automatically. Name the function to avoid colliding with any existing `get_coverage` in that module.

- [ ] **Step 4: Run test to verify it passes**

Run: `venv/bin/pytest tests/test_webdash_control.py -k coverage -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add webdash/data.py webdash/api/monitor.py tests/test_webdash_control.py
git commit -m "feat(webdash): GET /api/coverage endpoint + DashboardData.coverage()"
```

---

## Task 6: `PurpleCoverageView.tsx` panel + `PANEL_CATALOG` registration

**Files:**
- Create: `webdash/frontend/src/components/PurpleCoverageView.tsx`
- Modify: `webdash/frontend/src/api.ts` (add `CoverageResp` interface)
- Modify: `webdash/frontend/src/dashboardPanels.tsx` (import + one `PANEL_CATALOG` entry)

**Interfaces:**
- Consumes: `apiGet<T>(path)` and `usePoll<T>(fetcher, intervalMs, deps?)` (returns `{data, error, loading, refresh}`); `Panel` (`{title, right?, children, className?}`) and `Badge` (`{ok, children}`) from `./Panel`; `GET /api/coverage` from Task 5.
- Produces: `PurpleCoverageView` React component; `PANEL_CATALOG` entry `{ id: "coverage", label: "Purple Coverage", span: "wide", render: () => <PurpleCoverageView /> }`.

- [ ] **Step 1: Add the API type**

In `webdash/frontend/src/api.ts`, next to the other response interfaces:

```ts
export interface CoverageTTP {
  ttp: string;
  title: string;
}

export interface CoverageResp {
  coverage_pct: number;
  caught: CoverageTTP[];
  missed: CoverageTTP[];
  pending: CoverageTTP[];
}
```

- [ ] **Step 2: Write the component**

Create `webdash/frontend/src/components/PurpleCoverageView.tsx`, mirroring `CostMitre.tsx`'s `usePoll` + `Panel` + palette usage:

```tsx
import { apiGet, type CoverageResp, type CoverageTTP } from "../api";
import { usePoll } from "../usePoll";
import { Panel } from "./Panel";

function pctColor(pct: number): string {
  if (pct >= 66) return "text-emerald-400";
  if (pct >= 33) return "text-amber-400";
  return "text-red-400";
}

function Section({ icon, label, rows }: { icon: string; label: string; rows: CoverageTTP[] }) {
  if (rows.length === 0) return null;
  return (
    <div className="mb-3">
      <div className="text-xs uppercase tracking-wide text-slate-400 mb-1">
        {icon} {label} ({rows.length})
      </div>
      <ul className="space-y-0.5">
        {rows.map((r) => (
          <li key={r.ttp} className="flex gap-2 text-sm">
            <span className="font-mono text-slate-300 w-24 shrink-0">{r.ttp}</span>
            <span className="text-slate-400 truncate">{r.title}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function PurpleCoverageView() {
  const { data, error } = usePoll<CoverageResp>(() => apiGet<CoverageResp>("/api/coverage"), 5000);

  const right = data ? (
    <span className={`text-lg font-bold ${pctColor(data.coverage_pct)}`}>{data.coverage_pct}%</span>
  ) : null;

  const empty =
    data && data.caught.length === 0 && data.missed.length === 0 && data.pending.length === 0;

  return (
    <Panel title="Purple Coverage" right={right}>
      {error && <div className="text-red-400 text-sm">coverage unavailable</div>}
      {empty && <div className="text-slate-500 text-sm">awaiting detections…</div>}
      {data && (
        <>
          <Section icon="✅" label="caught" rows={data.caught} />
          <Section icon="⏳" label="pending" rows={data.pending} />
          <Section icon="❌" label="missed" rows={data.missed} />
        </>
      )}
    </Panel>
  );
}
```

Before finalizing, open `CostMitre.tsx` and match its exact import paths and the `usePoll` call arity (2 args here — no deps). If `usePoll` lives at a different path than `../usePoll`, use the one `CostMitre.tsx` imports.

- [ ] **Step 3: Register the panel**

In `webdash/frontend/src/dashboardPanels.tsx`, add the import next to the other component imports:

```tsx
import { PurpleCoverageView } from "./components/PurpleCoverageView";
```

Add one entry to `PANEL_CATALOG` (after the `cost` entry, mirroring its shape):

```tsx
  { id: "coverage", label: "Purple Coverage", span: "wide", render: () => <PurpleCoverageView /> },
```

Do NOT add it to `DEFAULT_LAYOUT` — leave it opt-in via the panel customizer, keeping it separate from `CostMitre`.

- [ ] **Step 4: Build to verify it compiles**

Run: `cd webdash/frontend && npm run build`
Expected: build succeeds, no TS errors. (Confirm `npm` is available first; if the user must run it, hand off per the `!`-prefix convention.)

- [ ] **Step 5: Commit**

```bash
git add webdash/frontend/src/components/PurpleCoverageView.tsx webdash/frontend/src/api.ts webdash/frontend/src/dashboardPanels.tsx
git commit -m "feat(webdash): Purple Coverage panel"
```

---

## Task 7: n8n emit on purple-run completion via `_notify`

**Files:**
- Modify: `webdash/runner.py` (`_notify(rec)` — enrich the payload with a coverage block when `rec["domain"] == "purple"`)
- Test: `tests/test_webdash_control.py` (or the runner's existing test file — confirm which tests `_notify`)

**Interfaces:**
- Consumes: `StateManager.get_coverage(engagement_id)` from Task 2; the existing `_notify(rec)` payload/POST path (already `PrivacyGuard.redact`-ed, SSRF-guarded via `core/webhook.py`, best-effort).
- Produces: purple-run `_notify` payloads gain `coverage_pct`, `caught_ttps`, `missed_ttps`; non-purple payloads unchanged.

- [ ] **Step 1: Write the failing test**

Confirm how `_notify` is currently tested and what `rec` contains: `grep -rn "_notify\|coverage\|domain" webdash/runner.py tests/test_webdash_control.py`. Mirror the existing `_notify` test; assert the coverage keys are present only for purple:

```python
def test_notify_purple_includes_coverage(monkeypatch, runner, state):
    eid = state.create_engagement(target="t", task="purple")
    state.add_finding(
        severity="high", title="LSASS", description="d", evidence="e",
        mitre_ttp="T1003", source_agent="pentester_ex", engagement_id=eid,
    )
    state.add_blue_alert(
        alert_type="A", description="d", severity="high",
        source="defender_mon", engagement_id=eid, mitre_ttp="T1003",
    )
    state.set_metadata("blue_run_status", "complete", eid)

    sent = {}
    monkeypatch.setattr(runner, "_post_webhook", lambda payload: sent.update(payload))  # match real POST helper name

    runner._notify({"domain": "purple", "engagement_id": eid, "status": "done",
                     "task": "purple", "targets": ["t"], "result": "", "error": None,
                     "finished": True})

    assert sent["coverage_pct"] == 100.0
    assert sent["caught_ttps"] == ["T1003"]


def test_notify_non_purple_has_no_coverage(monkeypatch, runner):
    sent = {}
    monkeypatch.setattr(runner, "_post_webhook", lambda payload: sent.update(payload))
    runner._notify({"domain": "red", "engagement_id": "x", "status": "done",
                    "task": "red", "targets": ["t"], "result": "", "error": None,
                    "finished": True})
    assert "coverage_pct" not in sent
```

Match the real `rec` shape and the real POST-helper name from `webdash/runner.py`. If `_notify` builds `payload` then calls a named send function, monkeypatch that function; if it POSTs inline via `requests`/`httpx`, monkeypatch the HTTP client the module uses. Reuse existing runner-test fixtures for `runner`/`state`.

- [ ] **Step 2: Run test to verify it fails**

Run: `venv/bin/pytest tests/test_webdash_control.py -k notify -v`
Expected: FAIL — `KeyError: 'coverage_pct'` in the purple test.

- [ ] **Step 3: Write minimal implementation**

In `webdash/runner.py`, in `_notify`, after the existing `payload = PrivacyGuard.redact({...})` block and before the POST, enrich for purple:

```python
if rec.get("domain") == "purple" and rec.get("engagement_id"):
    cov = self.state.get_coverage(rec["engagement_id"])
    payload["coverage_pct"] = cov["coverage_pct"]
    payload["caught_ttps"] = [c["ttp"] for c in cov["caught"]]
    payload["missed_ttps"] = [m["ttp"] for m in cov["missed"]]
```

Use the runner's real handle to the StateManager (`self.state`, `self._state`, or via `DashboardData` — read the top of `_notify`/the class `__init__` first). Keep it inside the existing best-effort try/except so a coverage failure never blocks the notify (if `_notify` isn't already wrapped, wrap only the new lines in `try/except Exception: pass` matching the file's error-logging style). Do not add a second POST — reuse the one already there.

- [ ] **Step 4: Run test to verify it passes**

Run: `venv/bin/pytest tests/test_webdash_control.py -k notify -v`
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git add webdash/runner.py tests/test_webdash_control.py
git commit -m "feat(webdash): emit purple coverage to n8n on run completion"
```

---

## Final verification

- [ ] Full suite green: `venv/bin/pytest tests/ -v` (baseline 752 tests + new coverage tests; nothing regressed).
- [ ] Frontend builds: `cd webdash/frontend && npm run build`.
- [ ] Manual smoke (optional): `python3 main.py dashboard --web`, open the `#token=…` URL, add the "Purple Coverage" panel via the customizer, run a purple engagement, confirm buckets populate and the headline % updates.

## Self-review notes (author checklist — done)

- **Spec coverage:** correlation key (Tasks 1–3), race gate (Task 4 + Task 2 blue_done), coverage compute (Task 2), API (Task 5), UI panel (Task 6), n8n emit (Task 7), migration guard (Task 1). All spec sections mapped.
- **Placeholder scan:** no TBD/TODO; every code step carries real code. The two "read the real signature first" notes are grounding guards, not placeholders — the exact edit is shown in each case.
- **Type consistency:** `mitre_ttp: str | None` param name identical across state, detectors, tests; `get_coverage` return shape `{coverage_pct, caught, missed, pending}` identical across Task 2 producer, Task 5 API, Task 6 `CoverageResp`, Task 7 emit; base-normalization (`_base_ttp`) applied on both finding and alert sides in the same method.
