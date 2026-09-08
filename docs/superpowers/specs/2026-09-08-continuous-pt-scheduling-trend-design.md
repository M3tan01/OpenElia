# Continuous Purple Teaming — Scheduling + Trend Design

**Date:** 2026-09-08
**Status:** Design (pre-implementation)
**Author:** OpenElia
**Depends on:** `docs/superpowers/specs/2026-09-07-ptef-ttp-scorecard-design.md` (PTEF per-TTP detection scorecard)

## 1. Purpose

The PTEF per-TTP scorecard (prior spec) grades a *single* purple cycle: each
base-normalized MITRE TTP lands on one detection rung
(PREVENTED > ALERTED > DETECTED > LOGGED > MISSED > PENDING). SCYTHE PTEF calls
for purple teaming to be **continuous, repeatable, and measurable over time** —
not a one-shot grade.

This design adds the "over time" axis:

- **Scheduling** — let an external scheduler (n8n / cron) re-run a purple cycle
  on a cadence, tagged with a stable **campaign** identity, so successive cycles
  form a comparable series. No new in-process daemon.
- **Trend** — persist one coverage snapshot per cycle keyed by campaign, and
  expose the history so an operator can see detection posture improve (or
  regress) rung-by-rung across cycles.

**Framework alignment:** SCYTHE PTEF (continuous/measurable/repeatable) +
MITRE ATT&CK (the TTP taxonomy the rungs hang off). Not a SANS artifact.

## 2. Scope

**In scope**
- `campaign_id` as the series key: nullable column on `engagement`, threaded
  once at engagement creation.
- One snapshot per completed purple cycle → new `coverage_history` table,
  per-TTP granularity (one row per TTP per cycle).
- A single snapshot writer, `StateManager.record_coverage_snapshot`.
- A read/aggregate method, `StateManager.get_campaign_trend`.
- Read-only API: `GET /api/campaign/{campaign_id}/trend`.
- Dashboard trend view.

**Out of scope (YAGNI)**
- No new scheduler daemon — scheduling is delegated to external n8n/cron hitting
  the existing `/run/purple` API and the CLI `purple` command.
- No `campaign` table, no campaign CRUD, no campaign lifecycle state. A campaign
  is just a string label shared across engagements.
- Red-only / blue-only runs are not snapshotted (only completed purple cycles).
- Ad-hoc purple runs with no `campaign_id` are not persisted to history.

## 3. Non-negotiable constraints

- **PII boundary.** `coverage_history` stores only `{campaign_id, ttp, rung,
  time_to_detect_s, ts}`. It **never** stores the finding/scorecard `title`
  (free-text, may contain PII). This is structural: the table has no `title`
  column, so the PTEF §5 n8n-egress PII concern cannot arise from this table.
- **No secrets in code.** Nothing here reads or writes credentials.
- **Migration safety.** New column + new table use the existing idempotent
  migration pattern (`state_manager.py:188-228`): `PRAGMA table_info` guard +
  `ALTER TABLE` / `CREATE TABLE IF NOT EXISTS` wrapped in a
  `try/except sqlite3.OperationalError`, to survive the per-request
  `StateManager` instantiation races.
- **Single source of truth.** `campaign_id` lives on the engagement row only.
  The snapshot writer reads it back off the engagement — callers never pass it
  in, so it cannot drift between the run and its snapshots.

## 4. Data model + campaign threading

### 4.1 `engagement.campaign_id` (nullable)

`engagement` CREATE TABLE is at `state_manager.py:74` and has no `campaign_id`.
Add via idempotent migration alongside the existing ones:

```sql
ALTER TABLE engagement ADD COLUMN campaign_id TEXT
```

Nullable, no default → legacy rows read `NULL` and are excluded from trend.

### 4.2 `coverage_history` table (new)

```sql
CREATE TABLE IF NOT EXISTS coverage_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id   TEXT NOT NULL,
    engagement_id TEXT NOT NULL,
    ttp           TEXT NOT NULL,
    rung          TEXT NOT NULL,
    time_to_detect_s INTEGER,
    ts            TEXT NOT NULL          -- UTC ISO-8601 microsecond precision, one value per snapshot
)
```

```sql
CREATE INDEX IF NOT EXISTS idx_covhist_campaign ON coverage_history(campaign_id, ts)
```

- No `title` column — PII-free by construction (see §3).
- `ts` is identical for every row written in one snapshot call → groups a cycle.
  Written at **microsecond precision** (`datetime.now(timezone.utc).isoformat()`)
  so back-to-back cycles in the CLI `cmd_purple` loop never collide onto one
  `ts` (which would merge two cycles' rungs into one snapshot in §6).
- `time_to_detect_s` nullable (unresolved / not-yet-detected TTPs).

### 4.3 Threading `campaign_id` at creation

`StateManager.initialize_engagement` (`state_manager.py:369`) signature grows an
optional param and persists it to the new column:

```python
def initialize_engagement(self, target: str, scope: str,
                          campaign_id: str | None = None) -> dict:
    ...
    # INSERT now includes campaign_id (NULL when not supplied)
```

Existing callers (`main.py:229,411,511,736`; `webdash/runner.py:160`) keep
working unchanged — the param defaults to `None`.

**Entry paths that opt a run into a campaign:**

- **API.** `PurpleRun` (`webdash/api/control.py:45`) gains
  `campaign_id: str | None = None`. `/run/purple` (`:258`) passes it to
  `RunManager.start`, which threads it through `_execute` → `_invoke`
  (`webdash/runner.py:153-160`) into `initialize_engagement`. Purple-only for
  now (RedRun/BlueRun unchanged — YAGNI).
- **CLI.** `purple` subparser (`main.py:1048`) gains `--campaign-id`;
  `cmd_purple` (`main.py:511`) passes `args.campaign_id` to
  `initialize_engagement`.

## 5. Snapshot write path

### 5.1 Single writer

```python
def record_coverage_snapshot(self, engagement_id: str | None = None) -> int:
    """Persist one coverage snapshot for the engagement's campaign.

    Reads campaign_id off the engagement row. If NULL, no-op → returns 0
    (ad-hoc/legacy runs stay out of history; trend is campaign-scoped).
    Otherwise runs get_coverage(eid) and INSERTs one coverage_history row
    per scorecard entry, all sharing a single UTC ts. Returns rows written.
    """
```

- Campaign membership is read back off the engagement, not passed in → no drift.
- Reuses the existing `get_coverage` scorecard (rungs + `time_to_detect_s`) as
  the single classification authority. This design adds **no** new rung logic.
- Writes nothing when `campaign_id IS NULL`.

### 5.2 Call sites

The snapshot fires at the two places that already compute purple coverage — one
extra line each — **not** inside the orchestrator:

- **CLI purple loop.** `cmd_purple` (`main.py:579`), after
  `cov = state.get_coverage(...)`, per loop iteration → one snapshot per cycle.
- **Dashboard purple run.** `webdash/runner.py:139`, after
  `cov = sm.get_coverage(...)`.

**Why not the orchestrator cycle-completion point** (`orchestrator.py:156-157`,
`if blue_batch: set_metadata("blue_run_status", "complete")`): that point also
fires for blue-only batches and is toggled back to "running" by later red-only
runs. Snapshotting at the two coverage-read sites guarantees a snapshot maps to
exactly one completed purple cycle, never a half-cycle.

## 6. Read + aggregate path

### 6.1 Shared coverage-percent helper (DRY)

The percent formula currently lives inline in `get_coverage`. Extract it to a
pure module-level helper so the live scorecard and the trend recompute cannot
drift:

```python
def _coverage_pct(rung_counts: dict[str, int]) -> float:
    """Percentage of resolved TTPs the blue team caught.

    Denominator excludes PENDING (not yet resolved). Numerator counts rungs at
    or above the 'caught' threshold. Single source of truth — get_coverage and
    get_campaign_trend both call this; neither reimplements the arithmetic.
    """
```

`get_coverage` is refactored to call `_coverage_pct` (behavior-preserving — the
existing scorecard tests still pass). `get_campaign_trend` calls the same helper
on each snapshot's tallied `rung_counts`, guaranteeing a campaign's newest
snapshot equals its current `/api/coverage` headline.

### 6.2 Trend read

```python
def get_campaign_trend(self, campaign_id: str) -> list[dict]:
    """Return per-snapshot trend for a campaign, oldest first.

    Rows grouped by ts. Each snapshot dict:
      {
        "ts": str,
        "coverage_pct": float,          # recomputed from this ts's rungs
        "rung_counts": {RUNG: int, ...},# tallied from this ts's rows
        "ttps": [{"ttp": str, "rung": str, "time_to_detect_s": int|None}, ...]
      }
    """
```

- Aggregates are computed **on read** from the per-TTP rows — nothing aggregate
  is stored. `coverage_pct` comes from the shared `_coverage_pct` helper (§6.1),
  so a campaign's newest snapshot equals its current `/api/coverage` headline.
- Ordering by `ts` ascending gives a time series ready to plot.

## 7. API

`GET /api/campaign/{campaign_id}/trend` on the **monitor** router (read-only,
token-gated, localhost-only — same posture as `/api/coverage`).

Response:

```json
{
  "campaign_id": "Q3-detection-uplift",
  "snapshots": [
    {
      "ts": "2026-09-08T14:03:11Z",
      "coverage_pct": 62.5,
      "rung_counts": {"PREVENTED":1,"ALERTED":2,"DETECTED":2,"LOGGED":1,"MISSED":2,"PENDING":0},
      "ttps": [{"ttp":"T1003","rung":"DETECTED","time_to_detect_s":41}, ...]
    }
  ]
}
```

Empty `snapshots` for an unknown / never-snapshotted campaign (not a 404 — an
empty series is a valid answer).

## 8. Dashboard

New `CampaignTrendView.tsx`:

- Line chart: `coverage_pct` over `ts` (headline trajectory).
- Stacked area / bars: per-rung counts over `ts` (rung migration MISSED→DETECTED
  over cycles).
- `api.ts` gains `TrendSnapshot` and `CampaignTrendResp` types, and a fetch
  helper on `/api/campaign/{id}/trend`.
- Wired into the sidebar next to Purple Coverage. Chart lib: victory-vendor
  (already present under `webdash/frontend/node_modules`; confirm at build).

## 9. Testing

- **Migration idempotency** — an existing DB (pre-`campaign_id`) opens, migrates,
  and re-opening a second `StateManager` does not raise.
- **Threading** — `initialize_engagement(campaign_id="X")` persists `X`; default
  call persists `NULL`.
- **Writer writes N rows** — `record_coverage_snapshot` writes exactly
  `len(scorecard)` rows, all sharing one `ts`.
- **No-op path** — engagement with `campaign_id IS NULL` → writer returns 0,
  writes nothing.
- **Read-back off engagement** — writer uses the engagement's campaign, not any
  passed value.
- **Shared helper** — `_coverage_pct` returns the same value the pre-refactor
  `get_coverage` returned (regression: existing scorecard-pct assertions pass);
  `get_coverage` and `get_campaign_trend` on identical rungs agree.
- **ts collision** — two `record_coverage_snapshot` calls back-to-back in a loop
  produce distinct `ts` values → `get_campaign_trend` returns two snapshots, not
  one merged.
- **Trend aggregation** — `get_campaign_trend` groups by `ts`, orders ascending,
  recomputes `coverage_pct` and `rung_counts` per snapshot.
- **Endpoint** — `/api/campaign/{id}/trend` returns the series shape; unknown
  campaign returns empty `snapshots`.
- **PII guard** — assert `coverage_history` has no `title` column, and that no
  finding/scorecard title value ever appears in any `coverage_history` row.

## 10. File map

- `state_manager.py` — migrations (`:188-228` block), `initialize_engagement`
  (`:369`), extract `_coverage_pct` helper + refactor `get_coverage` to call it,
  new `record_coverage_snapshot`, new `get_campaign_trend`.
- `main.py` — `--campaign-id` on `purple` subparser (`:1048`); `cmd_purple`
  threads it (`:511`) and calls snapshot writer per iteration (`:579`).
- `webdash/api/control.py` — `PurpleRun.campaign_id` (`:45`), `/run/purple`
  (`:258`).
- `webdash/runner.py` — thread `campaign_id` through `start`/`_execute`/`_invoke`
  (`:37,80,153-160`); call snapshot writer (`:139`).
- `webdash/api/monitor.py` — new `/api/campaign/{id}/trend` route.
- `webdash/frontend/src/api.ts` — `TrendSnapshot`, `CampaignTrendResp`.
- `webdash/frontend/src/components/CampaignTrendView.tsx` — new view.
- `tests/test_state_coverage.py` (or new `tests/test_campaign_trend.py`) —
  §9 tests.
