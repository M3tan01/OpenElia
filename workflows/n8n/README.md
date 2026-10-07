# OpenElia n8n Playbooks

Four webhook-triggered n8n workflows that wrap the OpenElia engine and file results
into TheHive. They are the automation backbone: an operator (or another system) POSTs a
target to a webhook, n8n launches the engine over its REST API, and when the run
finishes the engine calls back so n8n can open a TheHive case or alert.

| File            | Webhook path  | Callback path      | What it does |
|-----------------|---------------|--------------------|--------------|
| `red.json`      | `/webhook/red`      | `/webhook/red-callback`      | Launch a red-team run → TheHive case on completion, alert on failure |
| `blue.json`     | `/webhook/blue`     | `/webhook/blue-callback`     | Launch a blue-team run → case / alert |
| `purple.json`   | `/webhook/purple`   | `/webhook/purple-callback`   | Launch a purple run → **gap case** if coverage < 80 %, else standard case; alert on failure |
| `reporting.json`| `/webhook/reporting`| _(none — synchronous)_       | Generate an executive brief → TheHive case **and** return the markdown in the 200 response |

## Architecture: two independent chains per playbook

Each of red/blue/purple is **two disconnected chains in one file**, linked only by a
`run_id`:

1. **Trigger chain** — `Webhook → Launch <domain> Engine (HTTP) → Respond`. The engine
   returns immediately with `{run_id, status:"started"}`; n8n answers the caller `202`.
   If the engine is unreachable the HTTP node's error output answers `502`.
2. **Callback chain** — `Callback Webhook → Run Completed? (IF) → TheHive`. The engine
   POSTs the finished result to the callback URL; the IF routes `status=="done"` to a
   TheHive **case**, anything else to a TheHive **alert**.

`reporting.json` is a single synchronous chain — the brief is generated inline and
returned in the response body, so there is no callback.

```
red / blue / purple:

  POST /webhook/red ─▶ Launch Red Engine ─┬─(ok)─▶ 202 {run_id}
                                          └─(err)▶ 502

  POST /webhook/red-callback ─▶ Run Completed? ─┬─(done)─▶ TheHive Case
                                                └─(else)─▶ TheHive Alert
      (purple adds: done ─▶ Coverage Gap? ─┬─(<80%)─▶ TheHive Gap Case
                                           └─(else)─▶ TheHive Case)

reporting:

  POST /webhook/reporting ─▶ Generate Brief ─┬─(ok)──▶ TheHive Report Case ─▶ 200 {markdown}
                                             └─(err)─▶ 502
```

## Importing

`deploy.sh` imports these automatically **when `N8N_API_KEY` is set** — see
`docs/DEPLOY.md` → "n8n workflow auto-import". In short: first bring-up leaves the key
blank (import skipped); create a key in n8n **Settings → n8n API**, put it in
`docker/soc-stack/.env`, re-run `./deploy.sh`. Import is idempotent by workflow name.

Manual alternative: **Import from File** in the n8n editor for each `*.json`.

## Wire credentials before activating (required)

Imported workflows are **inactive** and their HTTP nodes have **no credential bound** —
the JSON deliberately ships no credential IDs (a placeholder ID renders a permanently
disabled selector in the n8n UI). Open each workflow and set:

### 1. Engine credential (`Launch … Engine`, `Generate Brief` nodes)

- Type: **Header Auth** (`httpHeaderAuth`).
- Name: `Authorization`
- Value: `Bearer <dashboard token>`

> ⚠️ The dashboard token **rotates every time** you start `main.py dashboard --web` — it
> is printed in the `#token=…` URL. Update this credential's value after each restart, or
> the engine calls will 401. (This is the same `Authorization: Bearer` the web console
> uses; it is **not** the `X-N8N-API-KEY` used for importing.)

### 2. TheHive credential (`TheHive *` nodes)

- Type: **Header Auth** (`httpHeaderAuth`).
- Name: `Authorization`
- Value: `Bearer <TheHive API key>` (create in TheHive → your user → API key).

Bind the credential on every `TheHive …` HTTP node, then **activate** the workflow.

## Network + endpoints (hybrid topology)

The playbooks assume the [hybrid topology](../../docs/DEPLOY.md): n8n + TheHive in Docker,
engine on the host.

| Call | URL in the JSON | Why |
|------|-----------------|-----|
| n8n → engine (launch)     | `http://host.docker.internal:8765/api/n8n/trigger` | container reaching a host port |
| n8n → engine (report)     | `http://host.docker.internal:8765/api/report/brief` | same |
| engine → n8n (callback)   | `http://localhost:5678/webhook/<domain>-callback`   | host reaching the published n8n port |
| n8n → TheHive             | `http://thehive:9000/api/v1/{case,alert}`           | same Docker network, service name |

**If your dashboard runs on a port other than 8765**, edit the `Launch … Engine` and
`Generate Brief` node URLs to match.

### SSRF allowlist

The engine re-validates every callback URL against `N8N_WEBHOOK_ALLOWLIST` before POSTing
(SSRF guard). Ensure that env var (engine side) includes the n8n callback host — e.g.
`localhost:5678` — or callbacks are refused.

## Request payloads

`red` / `blue` / `purple` webhook body (only `target` is required; rest default):

```json
{
  "target": "10.0.0.0/24",
  "task": "Full assessment",
  "stealth": false,
  "brain_tier": "local",
  "apt_profile": null,
  "agent": null,
  "campaign_id": null
}
```
(`campaign_id` is purple-only.) `reporting` body: `{ "brain_tier": "local" }`.

The engine's callback body (what the callback chain reads under `$json.body`):
`{ run_id, domain, task, targets, status, result, error, finished }`, and for purple also
`{ coverage_pct, caught_ttps[], missed_ttps[] }`. Success is `status == "done"`.

## Secrets discipline

Tokens never live in workflow JSON or Set nodes — only in n8n's credential store
(`httpHeaderAuth`). The committed `*.json` files contain **no** credentials; that is by
design. Do not add API keys to these files.
