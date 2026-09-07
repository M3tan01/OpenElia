# PTEF Per-TTP Scorecard — Design

**Date:** 2026-09-07
**Status:** Approved — user reviewed 2026-09-07; hardened (escalation-signal invariant + n8n PII boundary). Ready for implementation plan.
**Scope:** Architectural — touches state layer, blue response agent, purple loop, reporter, webdash, tests.

## Goal

Replace OpenElia's crude purple-team coverage metric (`alerts / findings` ratio at
`main.py:584`) with a SCYTHE PTEF-style **per-TTP detection scorecard**: for each
MITRE technique the red team executed, record the highest-maturity defensive outcome
achieved (a detection ladder), plus time-to-detect. Surface it in the purple-loop
console, the final report, and the web dashboard.

This adopts the core PTEF artifact — the TTP tracking matrix with per-technique
detected/prevented/logged outcomes — which OpenElia currently lacks. It builds on
existing state (`findings.mitre_ttp`, `blue_alerts.mitre_ttp` + `escalated`,
`blue_analyses.alert_id`, `response_actions`) and the existing tri-state
`StateManager.get_coverage()`.

## Non-Goals (YAGNI)

- No CTI-driven TTP selection / emulation-plan authoring (separate future spec).
- No PTEF planning-phase or roles workflow.
- No Purple Team Maturity Model scoring.
- No rename/removal of the existing `get_coverage` tri-state keys.

## Detection Ladder

Per base-normalized MITRE TTP (`T1003.001` → `T1003`, via existing
`state_manager._base_ttp`). **Highest rung wins** for a TTP:

| Rung | Precedence | Signal |
|---|---|---|
| `PREVENTED` | 5 (highest) | `response_actions` row whose `mitre_ttp` base-matches the finding's |
| `ALERTED`   | 4 | `blue_alerts` row for TTP base, `escalated = 1` (the `blue_alerts.escalated` column — **not** `blue_analyses.escalate`) |
| `DETECTED`  | 3 | `blue_alerts` row for TTP base, `escalated = 0`, no dismissing analysis |
| `LOGGED`    | 2 | `blue_alerts` row for TTP base, `escalated = 0`, **and** a `blue_analyses` row (joined `alert_id → alert`) with `escalate = 0` — i.e. triaged and dismissed |
| `MISSED`    | 1 | finding TTP, blue run complete, no blue signal at all |
| `PENDING`   | 0 | finding TTP, blue run not yet complete |

`blue_run_status == "complete"` (existing metadata) discriminates `MISSED` vs `PENDING`,
exactly as the current `get_coverage` does.

**Escalation-signal invariant.** Two escalation states exist in the schema:
`blue_alerts.escalated` (set by `state_manager.mark_alert_escalated`, called from
`defender_ana.py:156`) and `blue_analyses.escalate` (counted by
`get_escalated_analysis_count`). They agree only because `defender_ana` propagates one to
the other. The `ALERTED` rung and the `escalated = 0` discriminator on `DETECTED`/`LOGGED`
**must read `blue_alerts.escalated`** — the join key is the alert row, so keying off
`blue_analyses.escalate` instead would desync the rung the moment a second escalation path
is added. Implementer: read `blue_alerts.escalated`, never `blue_analyses.escalate`.

### Deviation from strict PTEF

Strict PTEF defines `LOGGED` as "activity produced telemetry but no alert." OpenElia has
**no alert-less telemetry channel** — every `blue_analyses` row rides an existing
`blue_alerts` row via `alert_id`, and monitor/hunt rules fire an alert whenever they match.
So a true "logged, not alerted" state cannot occur. `LOGGED` is therefore remapped to the
closest real, reachable signal: **an alert the analyst triaged and dismissed** (not
escalated, no response). This ranks below `DETECTED` (a live, un-dismissed alert) because a
dismissed alert yielded no defensive action. All six rungs are reachable under this mapping.

Every TTP in the scorecard originates from a **finding** (red executed it). Blue signals
with no corresponding finding TTP are ignored for scorecard purposes (they cannot be
"coverage" of an un-executed technique).

## Time-to-Detect

Per TTP, when a blue detection exists (rung ≥ DETECTED):

```
time_to_detect_s = min(blue_alerts.timestamp for TTP) − min(findings.timestamp for TTP)
```

ISO-8601 timestamps already stored on both tables. `None` when no alert exists
(PENDING/MISSED/LOGGED-only). Negative/zero clamped to `0` (clock skew guard).

## Components & Changes

### 1. `state_manager.py`

**Migration** — extend the existing idempotent migration block (`:172-205` pattern):
```
ALTER TABLE response_actions ADD COLUMN mitre_ttp TEXT
```
Guarded by `PRAGMA table_info` + `try/except sqlite3.OperationalError` (concurrent-init
race safe, matching current style). Nullable; legacy rows stay NULL.

**`add_response_action`** — accept optional `mitre_ttp` from `action_data`, persist to the
new column.

**`get_coverage(engagement_id)`** — extended, **not** renamed:
- Keep current keys `coverage_pct`, `caught`, `missed`, `pending` computed by the
  **existing logic, unchanged** (alert-presence join). No behavior change on these keys —
  this is what preserves the n8n contract and the 6 existing tests.
- Add `scorecard`: `list[dict]` — `{ttp, title, rung, time_to_detect_s}`, one per executed
  TTP base, sorted by precedence desc then TTP asc. Computed in a **separate additive pass**
  (extra queries against `blue_alerts.escalated`, `blue_analyses`, `response_actions`); the
  scorecard is NOT derived from `caught`/`missed`/`pending` and does not feed back into them.
- Add `rung_counts`: `dict[str, int]` — count per rung.

Note: a LOGGED-rung TTP still has an alert, so it remains a member of the legacy `caught`
set. The rung ladder and the legacy tri-state are independent views over the same rows —
intentional redundancy for back-compat (see the Decision-1 rationale).

### 2. `agents/blue/defender_res.py`

- Add `mitre_ttp` (string, optional) to the response-action tool input schema.
- Thread it into the `add_response_action(tool_input)` call at `:253`. The agent's system
  prompt is already TTP-keyed (`:38-42`), so the model has the TTP in hand.

### 3. `main.py` — `cmd_purple`

Replace the crude ratio print at `:578-585` with a per-iteration render of `rung_counts`
(e.g. `PREVENTED 2 · ALERTED 3 · DETECTED 1 · LOGGED 0 · MISSED 4 · PENDING 0`) plus the
delta of newly-covered TTPs vs previous iteration. Early-convergence check keeps working
off `coverage_pct` (unchanged).

### 4. `agents/reporter_agent.py`

Inject the `scorecard` into the final report context: a per-TTP table (TTP, title, rung,
time-to-detect) beside the existing MITRE heatmap. Reporter reads it from
`get_coverage()`.

### 5. webdash

- `webdash/data.py:coverage()` already returns `get_coverage()` — `scorecard` +
  `rung_counts` flow to the localhost API with no change.
- **PII boundary — do NOT extend the n8n payload.** `webdash/runner.py:129-131` guards that
  only base-TTP ids and numbers leave to n8n, never finding titles/descriptions. `scorecard`
  entries carry `title` (a finding title — free text, possible PII). The scorecard flows
  **only** through the localhost `data.py` API to `AgentsView`; it must **never** be added to
  the `runner.py` n8n `payload` (e.g. `payload["scorecard"] = cov["scorecard"]`) without first
  routing `title` through `PrivacyGuard.redact`. Leave `runner.py` reading only
  `coverage_pct` / `caught_ttps` / `missed_ttps` as it does today.
- `webdash/frontend/src/components/PurpleCoverageView.tsx` — the existing coverage
  component (polls `/api/coverage`, renders caught/pending/missed). Extend it with the
  scorecard matrix (rung-colored rows, time-to-detect column). `api.ts` `CoverageResp`
  type extended for the new fields.

## Data Flow

```
red agents ──▶ findings(mitre_ttp, ts)
blue mon/hunt ─▶ blue_alerts(mitre_ttp, escalated, ts)
blue ana ─────▶ blue_analyses(alert_id ─join─▶ alert.mitre_ttp)
blue res ─────▶ response_actions(mitre_ttp)          ← new column
                          │
                          ▼
        StateManager.get_coverage() → {coverage_pct, caught, missed,
                                        pending, scorecard, rung_counts}
                          │
          ┌───────────────┼──────────────────┐
          ▼               ▼                   ▼
   cmd_purple console  reporter_agent   webdash data.py → API → PurpleCoverageView
```

## Error Handling

- Missing/empty `mitre_ttp` on any row → excluded from that signal set (existing
  `get_coverage` already filters `NULL`/`''`).
- No findings → `scorecard = []`, `coverage_pct = 0` (existing behavior).
- Malformed timestamp → `time_to_detect_s = None`, rung still computed.
- New column read on legacy DB pre-migration → migration runs in `_init_db` before any
  read path, so column always present.

## Testing (`tests/test_state_coverage.py`, extended)

Existing 6 assertions untouched (back-compat proof). Add:
- One case per rung: PREVENTED, ALERTED, DETECTED, LOGGED (alert + dismissing
  `escalate=0` analysis), MISSED, PENDING.
- Precedence: a TTP with both an alert and a response resolves to PREVENTED; a TTP with a
  live alert and a dismissing analysis resolves to DETECTED over LOGGED only when the alert
  is un-dismissed (verify DETECTED vs LOGGED discrimination hinges on the analysis row).
- Base-normalization: `T1003.001` finding + `T1003` alert → matched.
- Time-to-detect: known finding/alert timestamps → expected seconds; clock-skew clamp → 0.
- `add_response_action` persists and round-trips `mitre_ttp`.
- Legacy-DB migration: pre-migration DB gains the column without error.

Target: cover every rung branch + the migration. `pytest tests/test_state_coverage.py -v`.

## Rollout / Risk

- Additive schema change, idempotent, precedented — low risk.
- `get_coverage` back-compat preserves the live n8n `coverage_pct` contract
  (`webdash/runner.py:140`).
- Forward-looking only: response rows written before this change stay NULL and never show
  PREVENTED retroactively (acceptable — no historical PT exercise depends on it).
- PII: `scorecard.title` is free text. It stays inside the localhost API/UI; the n8n egress
  path (`runner.py`) is unchanged and must remain title-free (see §5 PII boundary).
