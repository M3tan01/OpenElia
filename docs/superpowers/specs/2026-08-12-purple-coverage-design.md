# Purple Coverage — Design Spec

**Date:** 2026-08-12
**Branch:** `feat/red-offensive-capabilities`
**Status:** Approved (tri-state race fix + MITRE-TTP correlation incorporated)

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

- No `AgentTask` schema change; no `findings`-schema change; no opaque correlation id.
  Correlation is a **MITRE-TTP join**, not a threaded id (see "Correlation key").
- No new engine tier, no worker-pool changes, no telemetry tagging, no red-agent change.
- Independent runs are not falsely scored: with no blue batch, the `"blue"` phase never
  reaches `complete`, so red TTPs stay **pending** (never false-missed), and the n8n emit
  fires only on purple-run completion.

---

## The race condition this design must avoid

Treating "red finding with no matching blue alert = MISSED" reports a TTP as **missed**
the instant the red action writes its finding — while the blue batch is still ingesting
telemetry and running its detectors (SIEM latency, blue-agent analysis time). A UI polling
`/api/coverage` mid-run would show false misses.

**Fix:** gate the missed/pending distinction on whether the engagement's **blue batch has
finished**. While blue is still running (or has not run), an unmatched red TTP is
**pending**, not missed. The engine already has a per-engagement key/value store
(`set_metadata(key, value, engagement_id)` / `get_metadata(key, engagement_id)`, backed by
the `metadata` table, INSERT-OR-REPLACE), so the gate needs no new store. (The `phases`
table is unsuitable: `update_phase_status` is UPDATE-only and phases are seeded from a
fixed `PHASE_ORDER` that has no `"blue"` row, so the marker would silently no-op.)

---

## Correlation key

Correlate on **MITRE TTP** — the join key the engine already carries. `findings` store
`mitre_ttp` (`add_finding`), and blue detectors already compute the technique
(`defender_mon` from `rule["mitre"]`, `defender_hunt` from its required `mitre_ttp` tool
input) and currently **discard** it. Persisting it makes the red↔blue join a plain SQL
comparison — no opaque id to thread through the telemetry-mediated blue path, which has no
per-finding blue dispatch to thread an id into, and no orchestrator-visible per-TTP
granularity to mint one at.

TTPs are normalized to their base technique (`T1003.001` → `T1003`) on both sides before
comparison, so a sub-technique-specific red finding still matches a base-technique blue
detection instead of registering a false miss.

## Data model

One nullable column on one existing table:

| Table         | Column           | Values / purpose                                              |
|---------------|------------------|--------------------------------------------------------------|
| `blue_alerts` | `mitre_ttp TEXT` | technique the detector fired on (NULL when a detector supplies none) |

No new `findings` columns. The blue-batch race gate reuses the existing `metadata`
key/value store: the orchestrator writes `blue_run_status` — `running` when it dispatches
the blue batch, `complete` when the blue results return.

Migration: add `mitre_ttp` to the `blue_alerts` `CREATE TABLE IF NOT EXISTS` definition
**and** run an idempotent `ALTER TABLE blue_alerts ADD COLUMN mitre_ttp TEXT` guard for the
existing (gitignored) local `state/engagement.db`. Guard = check
`PRAGMA table_info(blue_alerts)` before altering, or catch the "duplicate column"
`OperationalError`.

---

## Correlation flow

```
red agents (per purple run):
  state.add_finding(..., mitre_ttp="T1003")            # already happens today — unchanged

orchestrator, purple branch of route():
  before dispatching the blue batch:   set_metadata("blue_run_status", "running",  eid)
  after the blue AgentResults return:  set_metadata("blue_run_status", "complete", eid)

blue detectors (on detection):
  defender_mon:  add_blue_alert(..., mitre_ttp=rule["mitre"])
  defender_hunt: add_blue_alert(..., mitre_ttp=tool_input["mitre_ttp"])
```

`add_blue_alert` gains an optional `mitre_ttp: str | None = None` parameter — the default
keeps every existing caller and test valid. Red agents are untouched; they already log
`mitre_ttp`. The orchestrator only writes two `blue_run_status` markers around the blue
batch it already dispatches.

## Coverage compute (pure SQL in StateManager, no engine change)

`StateManager.get_coverage(engagement_id) -> dict`:

Let `blue_done = (get_metadata("blue_run_status", eid) == "complete")`. For each distinct
base-normalized `mitre_ttp` among the engagement's findings:

- **caught**  — that base TTP appears (base-normalized) in `blue_alerts` for the engagement.
- **pending** — not caught AND `blue_done` is false (blue in flight or never ran).
- **missed**  — not caught AND `blue_done` is true.

Each bucket entry's `ttp`/`title` come from a representative finding for that TTP (the
first/most-severe). Returns:
```json
{
  "coverage_pct": 72.0,                       // caught / (caught + missed); pending excluded
  "caught":  [{"ttp": "T1003",    "title": "LSASS access"}],
  "missed":  [{"ttp": "T1490",    "title": "VSS deletion"}],
  "pending": [{"ttp": "T1071.001","title": "C2 beacon"}]
}
```

`coverage_pct` excludes pending from the denominator so the percentage does not thrash as
detections land. When `caught + missed == 0`, return `coverage_pct = 0` and let the UI
show "awaiting detections".

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
  - finding `T1003` + `blue_alert` `T1003`, `blue_run_status=complete` → **caught**.
  - finding `T1490`, no alert, `blue_run_status=complete` → **missed**.
  - finding `T1071.001`, no alert, `blue_run_status=running` → **pending** (race guard).
  - finding `T1003.001` + `blue_alert` `T1003` → **caught** (base-technique normalization).
  - `coverage_pct` math: pending excluded from denominator; zero-resolved → 0.
  - `add_blue_alert` called without `mitre_ttp` still inserts (default None) — existing
    callers/tests unaffected.
- `/api/coverage` endpoint test (token-gated, returns the three buckets).
- Existing 752 tests stay green.

## Touch count

`state_manager.py` (1 `blue_alerts` column + migration guard + optional `mitre_ttp` param on
`add_blue_alert` + `get_coverage`), `orchestrator.py` (two `blue_run_status` metadata
markers around the blue batch + n8n emit), 2 blue-detector call-sites (`defender_mon`,
`defender_hunt` pass `mitre_ttp`), 1 API route, 1 React panel + 1 catalog line. No
`AgentTask` change, no `findings`-schema change, no red-agent change, no telemetry tagging,
no new engine tier, no worker-pool change.
