# n8n Integration Dashboard Panel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an "n8n Integration" view to the OpenElia dashboard hamburger sidebar that shows n8n callback configuration status and lets the operator trigger a red/blue/purple engagement through the existing `POST /api/n8n/trigger` endpoint.

**Architecture:** One new read-only backend endpoint (`GET /api/n8n/status`) reports whether the outbound-callback allowlist is configured (boolean + count only, never the hostnames). One new self-contained React view (`N8nView.tsx`) fetches that status on mount and renders a trigger form that POSTs to the existing `/api/n8n/trigger` route, surfacing the returned `run_id`/`status` or the server's error `detail`. The view is wired into the app through the established 3-touchpoint pattern: a `Sidebar` NAV entry, an `App.tsx` switch case, and an `App.tsx` import.

**Tech Stack:** Backend — Python 3.11, FastAPI, Pydantic v2, pytest + FastAPI `TestClient`. Frontend — React 18 + TypeScript + Vite + Tailwind. Existing helpers: `apiGet`/`apiPost` (`webdash/frontend/src/api.ts`), `Panel`/`Badge` (`webdash/frontend/src/components/Panel.tsx`).

**Spec:** This plan is self-specifying — brainstorming was skipped at the user's direction, so the requirements below (and the Global Constraints) are the spec. There is no separate `docs/superpowers/specs/` design doc.

## Global Constraints

- Bind surface is 127.0.0.1 only; every request already carries `Authorization: Bearer ${TOKEN}` via the existing `apiGet`/`apiPost` helpers — do not add a second auth mechanism.
- Never return secret-store values to the browser. `N8N_WEBHOOK_ALLOWLIST` hostnames are secrets: the status endpoint reports `allowlist_configured: bool` and `allowlist_count: int` only — never the hostname strings.
- Never put a token, password, or callback secret in any response model or any React text field. The callback URL is an operator-typed plain URL, not a secret.
- The new status endpoint is READ-ONLY: it must never launch a run, mutate state, or call `_launch`. It lives with the other read endpoints' style but stays in `webdash/api/n8n.py`.
- Do NOT change the existing `POST /api/n8n/trigger` handler, its `N8nTrigger` model, or its guard order (`require_confirm` → `require_unlocked` → `_validate_agent` → `scope_gate` for non-blue → `validate_webhook_url`).
- Follow the existing view component style (`AdversaryForgeView.tsx`): `font-display`, `uppercase tracking-*`, `amber`/`dim`/`phos`/`redteam` color tokens, `Panel` wrapper with `title`/`right`/`className`.
- Frontend build command is `cd webdash/frontend && npm run build`. Backend tests run with `venv/bin/pytest tests/ -v` (the bare `python` binary is not on PATH).
- The trigger form must send `confirm: true` explicitly (the endpoint calls `require_confirm(req.confirm)` and rejects a missing/false confirm), and it is the operator's explicit HITL action — gate it behind a distinct "Confirm & Trigger" button state, not an incidental click.

---

### Task 1: Backend `GET /api/n8n/status` read-only endpoint

**Files:**
- Modify: `webdash/api/n8n.py` (add a `GET /status` route + a `N8nStatus` response model; keep the existing `POST /trigger` untouched)
- Test: `tests/test_n8n_status.py` (create)

**Interfaces:**
- Consumes: `load_webhook_allowlist(allowlist_secret_key: str) -> list[str]` from `core.webhook` (already imported-alongside `validate_webhook_url` in this module's package).
- Produces: `GET /api/n8n/status` returning JSON matching `N8nStatus`:
  ```python
  class N8nStatus(BaseModel):
      allowlist_configured: bool   # True when N8N_WEBHOOK_ALLOWLIST has >=1 hostname
      allowlist_count: int         # number of approved hostnames (NOT the hostnames)
      trigger_path: str            # "/api/n8n/trigger" — the inbound route to POST to
      domains: list[str]           # ["red", "blue", "purple"]
  ```

- [ ] **Step 1: Write the failing test**

Create `tests/test_n8n_status.py`. This mirrors how the other webdash endpoint tests build a `TestClient` and pass the bearer token; if a shared fixture/helper already exists in `tests/` for an authorized webdash client, use it instead of the inline app build shown here (check `tests/` for an existing `conftest.py` client fixture first and prefer it).

```python
import os
from unittest.mock import patch

from fastapi.testclient import TestClient

from webdash.app import create_app  # if the factory lives elsewhere, import it from there
from webdash.security import require_token


def _client():
    app = create_app()
    # Bypass the bearer dependency for the test just like the other endpoint tests do.
    app.dependency_overrides[require_token] = lambda: None
    return TestClient(app)


def test_status_reports_configured_when_allowlist_set():
    client = _client()
    with patch("webdash.api.n8n.load_webhook_allowlist", return_value=["n8n.corp.local", "hooks.corp.local"]):
        r = client.get("/api/n8n/status")
    assert r.status_code == 200
    body = r.json()
    assert body["allowlist_configured"] is True
    assert body["allowlist_count"] == 2
    assert body["trigger_path"] == "/api/n8n/trigger"
    assert body["domains"] == ["red", "blue", "purple"]
    # HARD CONSTRAINT: hostnames must never be echoed back to the browser.
    assert "n8n.corp.local" not in r.text
    assert "hooks.corp.local" not in r.text


def test_status_reports_unconfigured_when_allowlist_empty():
    client = _client()
    with patch("webdash.api.n8n.load_webhook_allowlist", return_value=[]):
        r = client.get("/api/n8n/status")
    assert r.status_code == 200
    body = r.json()
    assert body["allowlist_configured"] is False
    assert body["allowlist_count"] == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `venv/bin/pytest tests/test_n8n_status.py -v`
Expected: FAIL — `GET /api/n8n/status` returns 404 (route not defined) / `load_webhook_allowlist` not importable from `webdash.api.n8n`.

- [ ] **Step 3: Write the minimal implementation**

In `webdash/api/n8n.py`, extend the existing `core.webhook` import and add the model + route. Do not touch the existing `N8nTrigger` model or `trigger` handler.

Change the existing import line:
```python
from core.webhook import validate_webhook_url
```
to:
```python
from core.webhook import load_webhook_allowlist, validate_webhook_url
```

Add near the `N8nTrigger` model:
```python
class N8nStatus(BaseModel):
    allowlist_configured: bool
    allowlist_count: int
    trigger_path: str
    domains: list[str]
```

Add the route (place it above or below `trigger`; both live under the same `router` with the token dependency already applied at the router level):
```python
@router.get("/status", response_model=N8nStatus)
def status_endpoint() -> N8nStatus:
    """Read-only n8n integration status. Reports whether the outbound-callback
    allowlist is configured (count only — never the hostnames, which are secret)
    and the inbound trigger path/domains an external orchestrator can POST to.
    Never launches a run."""
    hosts = load_webhook_allowlist("N8N_WEBHOOK_ALLOWLIST")
    return N8nStatus(
        allowlist_configured=bool(hosts),
        allowlist_count=len(hosts),
        trigger_path="/api/n8n/trigger",
        domains=["red", "blue", "purple"],
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `venv/bin/pytest tests/test_n8n_status.py -v`
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git add webdash/api/n8n.py tests/test_n8n_status.py
git commit -m "feat(n8n): add read-only GET /api/n8n/status endpoint"
```

---

### Task 2: `N8nView.tsx` React view

**Files:**
- Create: `webdash/frontend/src/components/N8nView.tsx`
- Modify: `webdash/frontend/src/api.ts` (add `N8nStatus` type + a `triggerN8n` request shape; reuse existing `RunResp`)

**Interfaces:**
- Consumes: `apiGet<T>`, `apiPost<T>`, `RunResp` from `../api`; `Panel`, `Badge` from `./Panel`.
- Produces: exported React component `N8nView` (default-free named export `export function N8nView()`), consumed by Task 3's `App.tsx` switch case.
- Produces (in `api.ts`): 
  ```ts
  export type N8nStatus = {
    allowlist_configured: boolean;
    allowlist_count: number;
    trigger_path: string;
    domains: string[];
  };
  ```

- [ ] **Step 1: Add the `N8nStatus` type to `api.ts`**

In `webdash/frontend/src/api.ts`, add near the other response types (e.g. after `SystemResp`):
```ts
export type N8nStatus = {
  allowlist_configured: boolean;
  allowlist_count: number;
  trigger_path: string;
  domains: string[];
};
```

- [ ] **Step 2: Create the component**

Create `webdash/frontend/src/components/N8nView.tsx`. Structure and styling mirror `AdversaryForgeView.tsx` (a `Panel` per section, `apiGet` on mount, `apiPost` on submit, `Badge` for errors, pending state on the submit button).

```tsx
import { useEffect, useState } from "react";
import { apiGet, apiPost, type N8nStatus, type RunResp } from "../api";
import { Badge, Panel } from "./Panel";

type Domain = "red" | "blue" | "purple";

export function N8nView() {
  const [status, setStatus] = useState<N8nStatus | null>(null);
  const [statusErr, setStatusErr] = useState("");

  const [domain, setDomain] = useState<Domain>("purple");
  const [target, setTarget] = useState("");
  const [task, setTask] = useState("Full assessment");
  const [callbackUrl, setCallbackUrl] = useState("");
  const [brainTier, setBrainTier] = useState<"local" | "expensive">("local");
  const [stealth, setStealth] = useState(false);

  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<RunResp | null>(null);
  const [runErr, setRunErr] = useState("");

  useEffect(() => {
    apiGet<N8nStatus>("/api/n8n/status")
      .then(setStatus)
      .catch((e) => setStatusErr(e.message));
  }, []);

  async function submit() {
    setPending(true);
    setRunErr("");
    setResult(null);
    try {
      const body = {
        domain,
        target: target.trim(),
        task: task.trim() || "Full assessment",
        stealth,
        brain_tier: brainTier,
        callback_url: callbackUrl.trim() || null,
        confirm: true, // explicit HITL: operator pressed Confirm & Trigger
      };
      const r = await apiPost<RunResp>("/api/n8n/trigger", body);
      setResult(r);
    } catch (e) {
      setRunErr(e instanceof Error ? e.message : String(e));
    } finally {
      setPending(false);
    }
  }

  const canSubmit = target.trim().length > 0 && !pending;

  return (
    <div className="h-full overflow-auto flex flex-col gap-3">
      <Panel
        title="n8n integration"
        right={
          status ? (
            <Badge tone={status.allowlist_configured ? "phos" : "amber"}>
              {status.allowlist_configured
                ? `callback allowlist: ${status.allowlist_count} host(s)`
                : "callback allowlist: not configured"}
            </Badge>
          ) : (
            <Badge tone="dim">loading…</Badge>
          )
        }
      >
        {statusErr ? (
          <Badge tone="redteam">{statusErr}</Badge>
        ) : (
          <p className="text-dim text-xs leading-relaxed">
            External orchestrators POST to{" "}
            <code className="text-amber">{status?.trigger_path ?? "/api/n8n/trigger"}</code>{" "}
            to launch an engagement. A callback URL is optional; when set it must be an
            approved host in the <code className="text-amber">N8N_WEBHOOK_ALLOWLIST</code>{" "}
            or the trigger is rejected.
          </p>
        )}
      </Panel>

      <Panel title="trigger engagement">
        <div className="flex flex-col gap-3">
          <div className="flex gap-2">
            {(["red", "blue", "purple"] as Domain[]).map((d) => (
              <button
                key={d}
                onClick={() => setDomain(d)}
                className={`px-3 py-1 font-display uppercase tracking-widest text-[11px] border ${
                  domain === d
                    ? "border-amber text-amber"
                    : "border-line text-dim hover:text-amber"
                }`}
              >
                {d}
              </button>
            ))}
          </div>

          <label className="flex flex-col gap-1 text-[11px] uppercase tracking-widest text-dim">
            target
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="10.0.0.0/24 or host"
              className="bg-surface border border-line px-2 py-1 text-amber font-mono text-xs"
            />
          </label>

          <label className="flex flex-col gap-1 text-[11px] uppercase tracking-widest text-dim">
            task
            <input
              value={task}
              onChange={(e) => setTask(e.target.value)}
              className="bg-surface border border-line px-2 py-1 text-amber font-mono text-xs"
            />
          </label>

          <label className="flex flex-col gap-1 text-[11px] uppercase tracking-widest text-dim">
            callback url (optional)
            <input
              value={callbackUrl}
              onChange={(e) => setCallbackUrl(e.target.value)}
              placeholder="https://n8n.corp.local/webhook/…"
              className="bg-surface border border-line px-2 py-1 text-amber font-mono text-xs"
            />
          </label>

          <div className="flex items-center gap-4 text-[11px] uppercase tracking-widest text-dim">
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={stealth}
                onChange={(e) => setStealth(e.target.checked)}
              />
              stealth
            </label>
            <label className="flex items-center gap-2">
              brain
              <select
                value={brainTier}
                onChange={(e) => setBrainTier(e.target.value as "local" | "expensive")}
                className="bg-surface border border-line px-2 py-1 text-amber font-mono text-xs"
              >
                <option value="local">local</option>
                <option value="expensive">expensive</option>
              </select>
            </label>
          </div>

          <button
            onClick={submit}
            disabled={!canSubmit}
            className="self-start px-4 py-1.5 font-display uppercase tracking-widest text-[11px] border border-redteam text-redteam hover:bg-redteam/10 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {pending ? "triggering…" : "confirm & trigger"}
          </button>

          {runErr && <Badge tone="redteam">{runErr}</Badge>}
          {result && (
            <Badge tone="phos">
              run {result.run_id} — {result.status}
            </Badge>
          )}
        </div>
      </Panel>
    </div>
  );
}
```

- [ ] **Step 3: Verify `Panel`/`Badge` prop shapes match**

Run: `sed -n '1,60p' webdash/frontend/src/components/Panel.tsx`
Expected: confirm `Panel` accepts `title`, `right`, `children` and `Badge` accepts a `tone` prop with the token names used above (`phos`, `amber`, `dim`, `redteam`). If the real `Badge` API differs (e.g. no `tone`, or different token names), adjust the JSX in Step 2 to match the actual component before building — match the codebase, do not change `Panel.tsx`.

- [ ] **Step 4: Type-check the build**

Run: `cd webdash/frontend && npm run build`
Expected: build succeeds with no TypeScript errors referencing `N8nView` or `N8nStatus`. (The view is not yet wired into a route — this step only proves it compiles.)

- [ ] **Step 5: Commit**

```bash
git add webdash/frontend/src/components/N8nView.tsx webdash/frontend/src/api.ts
git commit -m "feat(webdash): add N8nView with status + trigger form"
```

---

### Task 3: Wire the view into the sidebar and app switch

**Files:**
- Modify: `webdash/frontend/src/components/Sidebar.tsx` (add an `{ id: "n8n", label: "n8n Integration" }` NAV entry)
- Modify: `webdash/frontend/src/App.tsx` (import `N8nView`; add `case "n8n"` to the switch)

**Interfaces:**
- Consumes: `N8nView` (named export from Task 2).
- Produces: the `"n8n"` `activeView` value selectable from the sidebar and rendered in the main pane.

- [ ] **Step 1: Add the sidebar NAV entry**

Open `webdash/frontend/src/components/Sidebar.tsx`. It defines `const NAV: NavGroup[]` with groups such as Operations (`c2`, `engagements`, `playbooks`, `findings`, `agents`, `agents-roster`, `graph`, `apt`, `forge`) and Intelligence (`audit`, `cost`, `stix`, `cleanup`). Add the n8n entry to the **Intelligence** group's items array (it is an integration/telemetry surface, not an offensive op). Match the exact object shape the other items use — inspect a neighbor first:

Run: `sed -n '1,80p' webdash/frontend/src/components/Sidebar.tsx`

Then add, alongside the other Intelligence items:
```ts
{ id: "n8n", label: "n8n Integration" },
```
Use the identical property names the existing items use (they are `{ id, label }` per the confirmed pattern; if a neighbor carries an extra field like an icon, follow suit).

- [ ] **Step 2: Import and wire the view in `App.tsx`**

In `webdash/frontend/src/App.tsx`, add the import alongside the other component imports (keep the existing alphabetical-ish grouping):
```tsx
import { N8nView } from "./components/N8nView";
```

Add a case to the `switch (activeView)` block, next to the other `Solo`-wrapped views:
```tsx
                case "n8n":          return <Solo><N8nView /></Solo>;
```

- [ ] **Step 3: Build the frontend**

Run: `cd webdash/frontend && npm run build`
Expected: build succeeds, no unused-import or missing-case TypeScript errors.

- [ ] **Step 4: Manual smoke check (operator-run)**

Run: `python main.py dashboard --web` and open the printed `#token=…` URL.
Expected: the hamburger sidebar shows "n8n Integration" under Intelligence; selecting it renders the status badge (configured/not-configured) and the trigger form. This step is operator-verified — the plan executor reports the build result from Step 3 and hands the live smoke check to the user, since launching the dashboard and firing a real trigger has side effects.

- [ ] **Step 5: Commit**

```bash
git add webdash/frontend/src/components/Sidebar.tsx webdash/frontend/src/App.tsx
git commit -m "feat(webdash): wire n8n Integration view into sidebar + app switch"
```

---

## Self-Review

**1. Spec coverage** (spec = this document's Goal + Global Constraints):
- "n8n Integration view in the hamburger sidebar" → Task 3 Step 1 (Sidebar NAV entry) + Step 2 (App switch case). ✅
- "shows n8n connection/callback status" → Task 1 (status endpoint) + Task 2 status `Panel`. ✅
- "trigger engagements via `/api/n8n/trigger`" → Task 2 `submit()` POSTing to the existing route with `confirm: true`. ✅
- "display callback/coverage results" → Task 2 renders `run_id`/`status`; live per-run coverage arrives asynchronously via the existing WS stream / `/api/coverage` and is out of scope for this synchronous trigger view (the `run_id` is the operator's handle to it). Noted, not a gap. ✅
- Constraint "never leak allowlist hostnames" → Task 1 endpoint returns count only; Task 1 test asserts hostnames absent from response text. ✅
- Constraint "do not change existing `/trigger`" → Tasks touch only the new route/model + frontend. ✅

**2. Placeholder scan:** No "TBD"/"handle edge cases"/"add validation" placeholders. Each code step shows the actual code. The two "inspect a neighbor first" steps (Task 2 Step 3, Task 3 Step 1) are verification steps against real files, not deferred work — they exist because `Panel`/`Badge` and `Sidebar`'s exact item shape were not read in full during planning and must be matched, not assumed.

**3. Type consistency:** `N8nStatus` fields are identical across the Python model (Task 1), the TS type (Task 2 Step 1), and the test assertions (Task 1 Step 1): `allowlist_configured`, `allowlist_count`, `trigger_path`, `domains`. The component consumes `RunResp` (`{ run_id, status }`) — the real exported shape in `api.ts`. The view is exported as `N8nView` and imported/rendered under that exact name in Task 3.

**Known verification gaps handed to the executor (not planning failures):**
- The FastAPI app factory import path in the Task 1 test (`from webdash.app import create_app`) and the `require_token` override pattern must match how the other `tests/` files build their client — the executor checks `tests/conftest.py` / a sibling endpoint test first and uses the established fixture.
- `Panel.tsx`'s exact `Badge` API (whether it takes `tone` and which token names) is verified in Task 2 Step 3 before the build.
