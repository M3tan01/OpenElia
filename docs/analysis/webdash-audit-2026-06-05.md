# OpenElia Web Dashboard — Audit

**Date:** 2026-06-05
**Scope:** `webdash/` (FastAPI backend + React/TS frontend, ~3,300 LOC frontend)
**Method:** Read all 24 components + `api.ts`, `App.tsx`, backend routes (`control.py`, `monitor.py`, `models.py`), `data.py`, engagement lifecycle in `state_manager.py`.

Severity: **CRITICAL** (data loss / security) · **HIGH** (broken/missing core function) · **MEDIUM** (correctness / UX / efficiency) · **LOW** (polish).

---

## CRITICAL

None. Security posture is solid: every state-changing route is `require_token` + `require_confirm`; red/purple add `scope_gate` + `require_unlocked`; kill-switch fires `CleanupRegistry.run_all` (LIFO, firewall-gated); audit chain is HMAC-verified and surfaced in the UI.

---

## HIGH

### H1 — No graceful session termination *(being fixed)*
`state_manager` exposes only `initialize_engagement` (flips all others `is_active=0`) and `clear` (hard delete). There is **no `end_engagement`**. Consequence: a finished engagement shows **ACTIVE forever** until a *new* one starts. The only "stop" is the global kill-switch, which halts everything and isn't session-scoped. → **Building: `end_engagement()` + `POST /api/engagements/{id}/terminate` + Terminate button (graceful end + rollback).**

### H2 — Sessions / Agents / Agent-roster views never refresh
`EngagementsView`, `AgentsView`, and `AgentActivity` fetch **once** in `useEffect` with no polling. `EngagementsView` (Sessions) won't reflect a terminate or a new run without a full page reload. `AgentActivity`'s initial table is frozen unless the WebSocket stream delivers a `task` event — if the stream is down, it stays at first load. → Fix alongside terminate (poll `/api/engagements`, and give `AgentActivity` a fallback poll).

---

## MEDIUM

### M1 — Silent error swallowing on every polling panel
8 components use `.catch(() => {})` (AttackGraph, CostMitre, ModelSelector, AgentActivity, AuditTimeline, Sidebar). On backend error/auth expiry the panel just blanks or shows stale data with **no per-panel offline signal**. The header has one global telemetry dot, but a single failing endpoint is invisible. → Add a lightweight per-panel error/stale badge, or at minimum log.

### M2 — Polling storm / duplicate fetches
Independent timers: `App` `/api/state` @4s, `FindingsView` `/api/state` @5s (**duplicate endpoint**), `AttackGraph` @5s, `CostMitre` 2 calls @5s, `CleanupView` @5s, `Sidebar` @10s. That's ~7 concurrent intervals with no shared cache. The **customizable dashboard will multiply this** (same panel can mount on C2 console *and* as a Solo view). → Introduce a shared poll/dedup layer (small SWR-style hook) or a single state poller passed via context. At minimum, dedupe the two `/api/state` pollers.

### M3 — Polling never pauses on hidden tab
No `visibilitychange` handling. Every interval keeps hitting the API (and the `expensive` brain-tier cost surface) when the tab is backgrounded. → Pause intervals when `document.hidden`.

### M4 — `system.gateway` is hardcoded
`data.system()` returns `{"gateway": "running"}` unconditionally. The Sidebar renders **"GATEWAY: RUNNING"** as if it were a health check — it is always green, even if the gateway is wedged. → Either compute a real signal or relabel as static.

---

## LOW

- **L1 — Index keys on dynamic lists.** `FindingsView:291` and `AuditTimeline:69` use `key={i}`. Findings re-fetch every 5s; if the list reorders, React mis-reconciles row state. Prefer a stable key (e.g. `${ttp}:${title}`).
- **L2 — `any` escapes.** `AttackGraph` (`n: any`) and `ControlBar` (`e: any` in catch). Tighten to `unknown` + narrow, or the force-graph node type.
- **L3 — No error boundary.** A render throw in any one panel blanks the entire app. Add a React error boundary around the view switch (more important once panels are user-composed).
- **L4 — `window.confirm` for HITL.** ControlBar uses native `confirm()` for run/lock. Functional, but inconsistent with the in-app HUD aesthetic and not stylable. Low priority.
- **L5 — Stale registries are easy to drift.** `AgentActivity.TIERS` had already drifted (missing `pentester_persist`, fixed this session). The frontend re-encodes tier/agent membership that the backend already owns (`AGENT_REGISTRY`, orchestrator tier lists). Consider serving tier membership from `/api/agents` to kill the duplication.

---

## What's already good (keep)
- Token via URL fragment → memory; WebSocket token via subprotocol (out of logs). Strong.
- Findings export (JSON/CSV/MD/print) builds the print document via `createElement`/`appendChild` (no raw HTML injection) — XSS-safe.
- CSV/MD escaping is correct (quote-doubling, pipe-escaping).
- Sidebar nav groups already collapsible with proper `aria-expanded`/`aria-controls`.
- Read-only badges on Sessions/RoE make the safety boundary explicit.

---

## Recommended fix order
1. **H1 terminate** (requested) — + H2 refresh for Sessions.
2. **Customizable dashboard** (requested) — panel catalog; bundle M2/M3 shared-poll + pause-on-hidden since composition makes them bite harder.
3. M1 per-panel error badges, M4 gateway label, L3 error boundary.
4. L1/L2/L5 cleanups.

---

## Resolution status (updated 2026-06-05)

Fixed in commits `04d9d72` (terminate + customizable dashboard) and the
`usePoll` series (`4652c5c`, `0743e46`, `afc5a69`, `d37ca34`):

| Item | Status | Where |
|---|---|---|
| H1 graceful terminate | ✅ fixed | `end_engagement()` + `POST /api/engagements/{id}/terminate` + Sessions Terminate button |
| H2 Sessions/Agents never refresh | ✅ fixed | EngagementsView/AgentActivity/AgentsView now poll via `usePoll` (5s/8s/30s) |
| M1 silent error swallowing | ✅ fixed | per-panel error badges across the 8 migrated panels; `.catch(()=>{})` removed |
| M2 polling storm / dup fetches | ◑ partial | centralized via `usePoll`; App + FindingsView still both hit `/api/state` (no shared cache layer — deferred) |
| M3 no pause on hidden tab | ✅ fixed | `usePoll` pauses on `document.hidden`, refetches on resume |
| M4 hardcoded GATEWAY:RUNNING | ✅ fixed | Sidebar now shows reachability-based `API: ONLINE/OFFLINE` (backend `gateway` field left vestigial) |
| L3 no error boundary | ✅ fixed | `ErrorBoundary` wraps the App view switch (`resetKey={activeView}`) |
| L1 index keys | ▢ open | FindingsView / AuditTimeline still `key={i}` |
| L2 `any` escapes | ▢ open | AttackGraph node, ControlBar catch |
| L5 stale registry duplication | ▢ open | frontend still re-encodes tier/agent membership |

Customizable dashboard (panel catalog, localStorage layout) shipped in `04d9d72`.
