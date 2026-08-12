# Purple Coverage — Design Spec

**Date:** 2026-08-12
**Branch:** `feat/red-offensive-capabilities`
**Status:** Approved (tri-state race fix incorporated)

## Goal

Answer, per engagement: **which red-team TTPs did the blue team actually catch?**
Score it, show it on the dashboard, and emit it to an n8n workflow on completion.

This is the first slice of the "complete purple teaming" vision (auto correlation +
coverage scoring). Connector breadth and Reporter-agent integration are out of scope for
this spec.

## Constraints (vision pillars)

- **Simple code** — minimal touch count, no new engine tier, no new worker-pool state.
- **Good UX** — a dedicated, composable dashboard panel; unconfused with attack coverage.
- **Easy connectors** — external reporting/Slack/ticketing is an n8n workflow, not code,
  via the already-seeded `webdash/api/n8n.py` + `core/webhook.py` (SSRF-guarded).

## Non-goals

- No change to `AgentTask` schema (`payload: dict[str, Any]` already carries the id).
- No new engine tier, no worker-pool changes, no per-agent id-minting logic.
- Non-purple (independent red or blue) runs are **not** scored — their `correlation_id`
  is null and they are excluded from coverage.

---

## The race condition this design must avoid

A naive `LEFT JOIN findings → blue_alerts ON correlation_id` reports a TTP as **MISSED**
the instant the red action writes its finding — because the blue alert has not been
written yet (SIEM ingest latency, blue-agent polling/analysis time). A UI polling
`/api/coverage` mid-run would show false misses.

**Fix:** differentiate a definitive **missed** from a still-in-flight **pending** by
gating on the blue task's execution status for that `correlation_id`.

There is no existing per-correlation-id task-status store (`AgentResult.status` is
terminal-only; worker-pool status is transient; `task_results.jsonl` is
engagement-agnostic; the phases table is not keyed by correlation id). So the status is
anchored on the finding row itself.

---

## Data model

Two nullable columns on existing tables (one finding = one red action-step = one cid, so
status lives on the finding, not a new table):

| Table         | Column                | Values                                         |
|---------------|-----------------------|------------------------------------------------|
| `findings`    | `correlation_id TEXT` | uuid4 (purple runs) / NULL (independent runs)   |
| `findings`    | `blue_status TEXT`    | NULL (blue not yet dispatched) / `running` / `completed` / `failed` |
| `blue_alerts` | `correlation_id TEXT` | uuid4 matching a finding / NULL                 |

Migration: add columns to the `CREATE TABLE IF NOT EXISTS` definitions **and** run an
idempotent `ALTER TABLE ... ADD COLUMN` guard for the existing (gitignored) local
`state/engagement.db`. Guard = check `PRAGMA table_info` before altering, or catch the
"duplicate column" `OperationalError`.

---

## Correlation flow (orchestrator-minted, centralized)

```
purple loop, per red action-step:
  cid = uuid4()
  red_task.payload["correlation_id"]  = cid      # AgentTask.payload — no schema change
  blue_task.payload["correlation_id"] = cid

red agent (runs first):
  state.add_finding(..., correlation_id=cid)      # finding row now exists; blue_status = NULL

orchestrator, when it dispatches the blue task for cid:
  state.set_blue_status(cid, "running")           # updates the finding by correlation_id

blue agent (on detection):
  state.add_blue_alert(..., correlation_id=cid)

orchestrator, after awaiting the blue AgentResult:
  state.set_blue_status(cid, "completed" if result.status == "success" else "failed")
```

Lifecycle of `blue_status` on the finding row: **NULL** (finding written, blue not yet
dispatched — treated as pending) → **running** (blue dispatched) → **completed / failed**
(blue returned). `set_blue_status` is only ever called after the red finding exists, so
it always has a row to update. Agents read `task.payload.get("correlation_id")`; they do
not mint or manage ids. Independent runs pass no `correlation_id` → null → excluded from
scoring.

## Coverage compute (pure SQL in StateManager, no engine change)

`StateManager.get_coverage(engagement_id) -> dict`:

For each finding with `correlation_id IS NOT NULL` in the engagement:

- **caught**  — `correlation_id` appears in `blue_alerts` (same engagement).
- **pending** — not caught AND `blue_status` IS NULL or `running` (blue in flight).
- **missed**  — not caught AND `blue_status` IN (`completed`,`failed`).

Returns:
```json
{
  "coverage_pct": 72.0,                       // caught / (caught + missed); pending excluded
  "caught":  [{"ttp": "T1003",    "title": "LSASS access"}],
  "missed":  [{"ttp": "T1490",    "title": "VSS deletion"}],
  "pending": [{"ttp": "T1071.001","title": "C2 beacon"}]
}
```

`coverage_pct` excludes pending from the denominator so the percentage does not thrash as
detections land. When `caught + missed == 0`, return `coverage_pct = 0` (or `null`) and
let the UI show "awaiting detections".

## API

`GET /api/coverage` — mirror the existing `/api/heatmap` route registration; returns
`get_coverage(active_engagement_id)`. Token-gated like every other webdash route.

## UI (new composable panel)

- `webdash/frontend/src/components/PurpleCoverageView.tsx` — `usePoll` +
  `Panel`, coverage-% headline, three sections: ✅ caught / ⏳ pending / ❌ missed, each a
  `ttp — title` row. Reuse `heatColor`-style palette from `CostMitre`.
- Register in `PANEL_CATALOG` (`dashboardPanels.tsx`) as `{ id: "coverage", label:
  "Purple Coverage", span: "wide", render: () => <PurpleCoverageView /> }` → available in
  the panel customizer. Kept **separate** from `CostMitre` (attack coverage) to avoid
  conflating "red hit this TTP" with "blue caught it".

```
PURPLE COVERAGE            72%
✅ T1059.001 PowerShell    caught
✅ T1003     LSASS         caught
⏳ T1071.001 C2 beacon     pending
❌ T1490     VSS delete    MISSED
```

## n8n emit (reuse seeded connector)

On purple-run completion, POST `{engagement_id, coverage_pct, missed_ttps, caught_ttps}`
to the operator's n8n webhook via `webdash/api/n8n.py`, URL validated by
`core/webhook.py`'s SSRF guard. External Slack / TheHive / report generation is then an
n8n workflow (built with the n8n MCP), not application code. Emit is best-effort:
failure is logged, never blocks the run.

## Testing

- `tests/test_state_coverage.py`:
  - correlated finding + matching alert → **caught**.
  - finding, `blue_status=completed`, no alert → **missed**.
  - finding, `blue_status=running`, no alert → **pending** (race guard).
  - finding, `correlation_id` NULL → excluded from all three.
  - `coverage_pct` math: pending excluded from denominator; zero-resolved → 0/null.
- `/api/coverage` endpoint test (token-gated, returns the three buckets).
- Existing 752 tests stay green.

## Touch count

`state_manager.py` (2 columns + migration guard + `set_blue_status` + `correlation_id`
params on `add_finding`/`add_blue_alert` + `get_coverage`), `orchestrator.py` (purple-loop
mint + blue-status update + n8n emit), 3–4 agent read-lines, 1 API route, 1 React panel +
1 catalog line. No `AgentTask` schema change, no new engine tier, no worker-pool change.
