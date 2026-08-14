# n8n Purple-Coverage Fan-out Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Also required:** Invoke `using-n8n-mcp-skills` (router) before any n8n action, and the specialist skill it names (`n8n-code-javascript` for Code-node edits, `n8n-validation-expert` before activation). Configure every node from the live schema (`get_node`), never from memory.

**Goal:** Repair the `openelia-completion-fanout` n8n workflow so OpenElia completion callbacks — including purple-run detection-coverage telemetry — validate correctly, flow through the pipeline, and reach the SIEM/alert layer.

**Architecture:** OpenElia's `webdash/runner.py::_notify` POSTs a completion payload to an n8n Webhook (`callback_url`). The receiver `openelia-completion-fanout` (id `PcWKMyPFco4cldot`) validates → redacts → fans out to `deliver-findings` (Splunk/TheHive/Slack) + a Data Table audit row → merges → responds. Two Code nodes rebuild `json` from a whitelist, and the validator requires a `target` field the emitter never sends (`targets` instead), so every callback currently fails validation and coverage fields are stripped. Fix = patch the two Code nodes and the success responder to accept `targets`, expose a compatibility `target` scalar, and carry coverage. No repo code changes — the OpenElia emitter already sends the correct payload (Task 7 of the purple-coverage feature, tested).

**Tech Stack:** n8n 2.69.0 (self-hosted, `http://localhost:5678`), n8n-mcp 2.69.0, JavaScript Code nodes (`runOnceForAllItems`).

## Global Constraints

- **This is a LIVE-INSTANCE change.** Every `n8n_update_partial_workflow` / activation writes to the running n8n at `http://localhost:5678`. Activation and any `n8n_test_workflow` are outward state changes — get explicit operator confirmation before Task 4's activation and before any test that can fire external deliveries.
- **Emitter payload is the contract; adapt the receiver to it, never the reverse.** `_notify` sends keys: `run_id, domain, task, targets, status, result, error, finished`, plus (purple only) `coverage_pct, caught_ttps, missed_ttps`. It sends `targets` (list), NOT `target`, and NEVER `severity`. Do not change `webdash/runner.py` — 779 passing tests depend on it.
- **Preserve a `target` scalar** in Code-node output (= `targets.join(', ')`) so the ACTIVE `deliver-findings` sub-workflow (id `cKF9ED2RshAsrRVh`) and the `Audit Archive` Data Table keep working unchanged — all four reference `{{ $json.target }}`.
- **Secrets stay in credentials.** The Webhook uses `httpHeaderAuth` credential "OpenElia Webhook Key" (`GMm9Bs5faYk93KQf`). Never inline the header value in a test or a text field.
- **Coverage fields are non-PII** (base MITRE TTP ids + an integer). They are injected after redaction on the OpenElia side on purpose. Keep them out of any free-text field that isn't already redacted.
- **Validate AND verify before activating:** run `n8n_validate_workflow` by id, then `n8n_get_workflow` (mode `structure`) to confirm `connections` are untouched. Validation passing ≠ correct wiring.
- Use `n8n_update_partial_workflow` diff ops (`patchNodeField`) for edits — never a full-workflow replace, which risks dropping the Webhook's `webhookId`/credential binding.

---

### Task 1: Fix the validator — accept `targets`, carry coverage

**Files (n8n instance, not repo):**
- Modify: workflow `PcWKMyPFco4cldot` (`openelia-completion-fanout`), node `Validate Payload` (id `cb615dd2-6538-4112-ba83-9879ae14a431`), parameter `jsCode`.

**Interfaces:**
- Consumes: the Webhook body at `$input.first().json.body` — keys per Global Constraints.
- Produces (for `Is Valid` + `Redact Payload`): `{ valid:true, run_id, domain, status, targets:[…], target:"…", result:{}, severity:"…" }`, plus for `domain==='purple'`: `coverage_pct:number|null, caught_ttps:[…], missed_ttps:[…]`. On failure: `{ valid:false, error:"missing fields: …" }`.

- [ ] **Step 1: Define the assertion (what "fixed" means)**

A purple completion callback body like:
```json
{ "run_id": "r1", "domain": "purple", "status": "complete",
  "targets": ["10.0.0.1"], "result": {"findings": []},
  "coverage_pct": 100, "caught_ttps": ["T1003"], "missed_ttps": [] }
```
must produce a `Validate Payload` output item with `valid === true`, `target === "10.0.0.1"`, `targets` an array, and `coverage_pct === 100`. Today it produces `{ valid:false, error:"missing fields: target" }`.

- [ ] **Step 2: Verify the current failure**

Run: `n8n_get_workflow` `{ id:"PcWKMyPFco4cldot", mode:"filtered", nodeNames:["Validate Payload"] }`
Expected: `jsCode` still lists `required = ['run_id','domain','status','target']` and outputs only `run_id/domain/status/target/result/severity` — confirming `targets` is rejected and coverage dropped.

- [ ] **Step 3: Patch the node**

Apply with `n8n_update_partial_workflow`:
```json
{ "id": "PcWKMyPFco4cldot",
  "operations": [
    { "type": "patchNodeField", "nodeName": "Validate Payload",
      "field": "parameters.jsCode",
      "value": "// Completion callbacks from OpenElia's RunManager._notify send `targets`\n// (a list), never `target`. Accept the list, expose both a `targets` array\n// and a joined `target` string so existing downstream consumers keep\n// working, and carry purple-run coverage telemetry through untouched.\nconst body = $input.first().json.body || {};\nconst required = ['run_id', 'domain', 'status'];\nconst missing = required.filter((k) => body[k] === undefined || body[k] === null);\nif (missing.length) {\n  return [{ json: { valid: false, error: `missing fields: ${missing.join(', ')}` } }];\n}\nconst targets = Array.isArray(body.targets)\n  ? body.targets\n  : (body.target ? [body.target] : []);\nconst out = {\n  valid: true,\n  run_id: body.run_id,\n  domain: body.domain,\n  status: body.status,\n  targets,\n  target: targets.join(', '),\n  result: body.result || {},\n  severity: body.severity || 'unknown',\n};\nif (body.domain === 'purple') {\n  out.coverage_pct = body.coverage_pct ?? null;\n  out.caught_ttps = Array.isArray(body.caught_ttps) ? body.caught_ttps : [];\n  out.missed_ttps = Array.isArray(body.missed_ttps) ? body.missed_ttps : [];\n}\nreturn [{ json: out }];" }
  ] }
```

- [ ] **Step 4: Verify the patch landed**

Run: `n8n_get_workflow` `{ id:"PcWKMyPFco4cldot", mode:"filtered", nodeNames:["Validate Payload"] }`
Expected: `required` is `['run_id','domain','status']`; body derives `targets`; the `domain === 'purple'` block is present. Connections and `onError:"continueErrorOutput"` unchanged.

- [ ] **Step 5: No commit (n8n instance state)** — n8n persists the node on write; there is no repo file to commit for this task. Proceed to Task 2.

---

### Task 2: Fix the redactor — carry `targets`/`target` + coverage

**Files (n8n instance, not repo):**
- Modify: workflow `PcWKMyPFco4cldot`, node `Redact Payload` (id `0aa5129e-d290-43ef-9bf8-e16210c3fa11`), parameter `jsCode`.

**Interfaces:**
- Consumes: the `Validate Payload` output from Task 1 (`targets`, `target`, coverage fields for purple).
- Produces (for `Deliver Findings` + `Audit Archive`): `{ run_id, domain, status, targets, target, result, severity, finding_count }`, plus for purple: `coverage_pct, caught_ttps, missed_ttps`.

- [ ] **Step 1: Define the assertion**

Given the Task 1 output for the purple example, `Redact Payload` must emit `target === "10.0.0.1"`, `finding_count === 0`, and `coverage_pct === 100`. Today it re-whitelists and drops `targets`/coverage and reads a nonexistent `target`.

- [ ] **Step 2: Verify current behavior**

Run: `n8n_get_workflow` `{ id:"PcWKMyPFco4cldot", mode:"filtered", nodeNames:["Redact Payload"] }`
Expected: output object lists `run_id/domain/status/target/result/severity/finding_count` with no coverage keys — confirming the gap.

- [ ] **Step 3: Patch the node**

Apply with `n8n_update_partial_workflow`:
```json
{ "id": "PcWKMyPFco4cldot",
  "operations": [
    { "type": "patchNodeField", "nodeName": "Redact Payload",
      "field": "parameters.jsCode",
      "value": "// Strip any result key that looks like a secret/PII, then forward the\n// record. Coverage fields (base MITRE TTP ids + an integer) are non-PII and\n// are carried through for purple runs so the SIEM/alert layer can act on\n// detection gaps. `target` is the joined-string form kept for downstream\n// consumers; `targets` is the raw list.\nconst DENY = /pass(word)?|secret|token|api[_-]?key|ssn|email|phone/i;\nconst item = $input.first().json;\nconst cleanResult = Object.fromEntries(\n  Object.entries(item.result || {}).filter(([k]) => !DENY.test(k))\n);\nconst out = {\n  run_id: item.run_id,\n  domain: item.domain,\n  status: item.status,\n  targets: item.targets,\n  target: item.target,\n  result: cleanResult,\n  severity: item.severity,\n  finding_count: Array.isArray(cleanResult.findings) ? cleanResult.findings.length : 0,\n};\nif (item.domain === 'purple') {\n  out.coverage_pct = item.coverage_pct ?? null;\n  out.caught_ttps = item.caught_ttps || [];\n  out.missed_ttps = item.missed_ttps || [];\n}\nreturn [{ json: out }];" }
  ] }
```

- [ ] **Step 4: Verify the patch landed**

Run: `n8n_get_workflow` `{ id:"PcWKMyPFco4cldot", mode:"filtered", nodeNames:["Redact Payload"] }`
Expected: output carries `targets`, `target`, and the purple coverage block; `DENY` regex unchanged.

- [ ] **Step 5: No commit (n8n instance state).** Proceed to Task 3.

---

### Task 3: Echo coverage in the success response

**Files (n8n instance, not repo):**
- Modify: workflow `PcWKMyPFco4cldot`, node `Respond Success` (id `16b06b99-2dcd-4c7f-82cb-e881d89bfbb5`), parameter `responseBody`.

**Interfaces:**
- Consumes: `$('Validate Payload').item.json.run_id`, `$('Redact Payload').item.json.coverage_pct`.
- Produces: the HTTP 200 JSON body returned to OpenElia's `_notify` POST — now including `coverage_pct` so the round-trip is observable from the caller side.

- [ ] **Step 1: Define the assertion**

The webhook's 200 response for a purple run must be `{ "status":"ok", "run_id":"r1", "coverage_pct":100 }`. Today it is `{ "status":"ok", "run_id":"r1" }`.

- [ ] **Step 2: Verify current body**

Run: `n8n_get_workflow` `{ id:"PcWKMyPFco4cldot", mode:"filtered", nodeNames:["Respond Success"] }`
Expected: `responseBody` is `={{ { status: "ok", run_id: $('Validate Payload').item.json.run_id } }}`.

- [ ] **Step 3: Patch the node**

Apply with `n8n_update_partial_workflow`:
```json
{ "id": "PcWKMyPFco4cldot",
  "operations": [
    { "type": "patchNodeField", "nodeName": "Respond Success",
      "field": "parameters.responseBody",
      "value": "={{ { status: \"ok\", run_id: $('Validate Payload').item.json.run_id, coverage_pct: $('Redact Payload').item.json.coverage_pct ?? null } }}" }
  ] }
```

- [ ] **Step 4: Verify the patch landed**

Run: `n8n_get_workflow` `{ id:"PcWKMyPFco4cldot", mode:"filtered", nodeNames:["Respond Success"] }`
Expected: `responseBody` now includes `coverage_pct`.

- [ ] **Step 5: No commit (n8n instance state).** Proceed to Task 4.

---

### Task 4: Validate, verify wiring, and activate

**Files (n8n instance, not repo):**
- Read/activate: workflow `PcWKMyPFco4cldot`.

**Interfaces:**
- Consumes: the three patched nodes from Tasks 1–3.
- Produces: an `active: true` workflow whose Webhook (`path: openelia-completion`) accepts live callbacks.

- [ ] **Step 1: Validate the deployed workflow**

Run: `n8n_validate_workflow` `{ id:"PcWKMyPFco4cldot" }`
Expected: no errors. Warnings about Code-node best practices are acceptable; there must be no connection or expression errors. If errors appear, fix the offending node before proceeding (see `n8n-validation-expert`).

- [ ] **Step 2: Verify connections are untouched**

Run: `n8n_get_workflow` `{ id:"PcWKMyPFco4cldot", mode:"structure" }`
Expected: 10 nodes, 7 connections, identical topology to before the edits (Webhook → Validate → Is Valid → Redact → Deliver Findings + Audit Archive → Merge → Respond Success; error branches to the two error responders). A dropped wire here means an edit corrupted the graph — stop and investigate.

- [ ] **Step 3: CONFIRM WITH OPERATOR, then activate**

State the action in one sentence and wait for explicit approval:

> "Activating `openelia-completion-fanout` on the live n8n instance so it accepts OpenElia completion callbacks. Proceed?"

On approval, apply:
```json
{ "id": "PcWKMyPFco4cldot",
  "operations": [ { "type": "activateWorkflow" } ] }
```
> If `activateWorkflow` is not a supported op on this n8n-mcp build, fall back to the n8n editor toggle or `n8n_update_full_workflow` with `active:true` — verify the tool surface with `tools_documentation` first; do not guess.

- [ ] **Step 4: Verify activation**

Run: `n8n_get_workflow` `{ id:"PcWKMyPFco4cldot", mode:"minimal" }`
Expected: `active: true`.

- [ ] **Step 5: No commit (n8n instance state).** Proceed to Task 5.

---

### Task 5: End-to-end test with a real purple run

**Files (n8n instance + OpenElia engine):**
- Exercise: `openelia-completion-fanout` via a live OpenElia purple engagement, OR a pinned-data test execution.
- Read: `n8n_executions` for the resulting run.

**Interfaces:**
- Consumes: the activated workflow (Task 4) and OpenElia's `/api/n8n/trigger` inbound route (`webdash/api/n8n.py`), which registers a `callback_url`.
- Produces: an n8n execution whose `Redact Payload` output contains `coverage_pct`, proving coverage reaches the fan-out.

> **Side-effect warning:** `Deliver Findings` calls the ACTIVE `deliver-findings` sub-workflow, which fires **real** Splunk HEC, TheHive case creation, and a Slack message. Do not run an uncontrolled test against production delivery endpoints without operator approval.

- [ ] **Step 1: Choose a safe test path — CONFIRM WITH OPERATOR**

Present two options and let the operator pick:
> "Test option A (isolated): temporarily disable the `Deliver Findings` node, pin a sample purple payload on the Webhook, run `n8n_test_workflow`, assert `Redact Payload` output has `coverage_pct`, then re-enable `Deliver Findings`. No external deliveries fire.
> Test option B (full E2E): trigger a real purple run through OpenElia so the callback hits the live webhook — this fires Splunk/TheHive/Slack. Which?"

- [ ] **Step 2 (Option A): Isolate delivery**

Apply:
```json
{ "id": "PcWKMyPFco4cldot",
  "operations": [ { "type": "updateNode", "nodeName": "Deliver Findings", "updates": { "disabled": true } } ] }
```
Verify with `n8n_get_workflow` `{ id:"PcWKMyPFco4cldot", mode:"structure" }` that `Deliver Findings` shows `disabled: true`.

- [ ] **Step 3 (Option A): Run the pinned test**

Run `n8n_test_workflow` for `PcWKMyPFco4cldot` with the Webhook input pinned to:
```json
{ "body": { "run_id": "test-purple-1", "domain": "purple", "status": "complete",
  "targets": ["10.0.0.1"], "result": { "findings": [] },
  "coverage_pct": 100, "caught_ttps": ["T1003"], "missed_ttps": [] } }
```
Expected: execution succeeds; `Is Valid` takes the true branch; `Respond Success` returns `coverage_pct: 100`.

- [ ] **Step 4 (Option A): Assert coverage survived redaction**

Run: `n8n_executions` `{ id:<execution id from Step 3> }` (or inspect the execution in the editor).
Expected: the `Redact Payload` node's output item contains `coverage_pct: 100`, `caught_ttps: ["T1003"]`, `missed_ttps: []`, and `target: "10.0.0.1"`.

- [ ] **Step 5 (Option A): Restore delivery**

Apply:
```json
{ "id": "PcWKMyPFco4cldot",
  "operations": [ { "type": "updateNode", "nodeName": "Deliver Findings", "updates": { "disabled": false } } ] }
```
Verify `Deliver Findings` is `disabled: false` again via `n8n_get_workflow` structure. This restores the production fan-out. **Do not skip** — leaving it disabled silently drops all Splunk/TheHive/Slack delivery.

- [ ] **Step 6: No commit (n8n instance state).** Report the execution id and the observed coverage fields to the operator.

---

## Optional follow-up tasks (operator opt-in, not part of the core fix)

These touch the ACTIVE `deliver-findings` sub-workflow or add persistence, so they carry more risk and are separated deliberately. Only pursue on explicit request.

- **O1 — Surface coverage in the SIEM event.** Add `coverage_pct` and `caught`/`missed` counts to the `Splunk HEC` node's `event` object (workflow `cKF9ED2RshAsrRVh`, node `Splunk HEC`). Makes detection gaps queryable in Splunk. Edits an active workflow that talks to a real HEC endpoint.
- **O2 — Persist coverage in the audit Data Table.** Add a `coverage_pct` column to Data Table `p42LugtpyniCOlwe` and map it in `Audit Archive`. This is a schema change to the Data Table, not just a node edit.
- **O3 — Version-control the workflows.** Export `openelia-completion-fanout` (and the other six OpenElia workflows) to committed JSON under a new `integrations/n8n/` directory so instance drift like the `targets`/`target` bug is caught in review. Establishes a repo convention that does not currently exist — confirm the directory name and export format first.

---

## Self-Review

**1. Spec coverage.** The user report ("coverage not showing / no workflow in n8n") decomposed to two root defects: (a) `targets`-vs-`target` validation failure — Task 1; (b) coverage fields stripped by whitelist Code nodes — Tasks 1 (validate) + 2 (redact), surfaced in Task 3 (response) and proven in Task 5. Activation gap (workflow inactive) — Task 4. "No workflow auto-created" is by design (documented in the diagnosis, not a bug). Covered.

**2. Placeholder scan.** No `TBD`/`TODO`/"handle edge cases". Every Code-node edit is a complete `jsCode` string. The one conditional instruction (Task 4 Step 3 `activateWorkflow` fallback) is a verified-tool-surface guard, not a placeholder — it names the exact fallback and requires confirming the tool surface first.

**3. Type/field consistency.** `targets` (array) and `target` (joined string) are produced by Task 1, forwarded verbatim by Task 2, and consumed by the unchanged `Audit Archive`/`Splunk HEC`/`TheHive Case`/`Slack` nodes via `{{ $json.target }}`. `coverage_pct` is `number|null` everywhere (Tasks 1→2→3, `?? null` guards throughout). `run_id`/`domain`/`status` names match the emitter payload and all downstream references. Consistent.
