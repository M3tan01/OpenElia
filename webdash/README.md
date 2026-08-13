# webdash — OpenElia Web Dashboard

Browser **C2 console** for OpenElia: a FastAPI backend that wraps the existing engine
objects (no logic duplicated) plus a Vite/React frontend. Read-only monitoring **and**
gated control of red/blue/purple operations, the kill-switch, and brain-model selection.

## Launch

```bash
python main.py dashboard --web            # 127.0.0.1:8765 ; --port to change
```

On start it prints:

```
OpenElia dashboard →  http://127.0.0.1:8765/#token=<token>
```

Open the **full URL including the `#token=…` fragment** — that token authorizes every
`/api` call. Opening the bare host shows a "NO AUTH TOKEN" screen (expected).

The TUI remains the default (`python main.py dashboard` without `--web`).

## Build the frontend (first run / after frontend changes)

```bash
cd webdash/frontend && npm install && npm run build && cd ../..
```

`npm run build` outputs to `webdash/static/` (gitignored), which the server serves
same-origin. Without a build the API works but `/` has no UI.

## Security model

- Binds **127.0.0.1 only** (`run()` refuses any non-localhost host).
- Bearer **token** on every `/api/*`. Generated on launch, stored in the OS keychain via
  `SecretStore` (`WEBDASH_TOKEN`). The WebSocket carries it in the
  `Sec-WebSocket-Protocol` header (kept out of URLs/access logs).
- **Control endpoints** (`/api/run/*`, `/api/lock`, `/api/unlock`) require: token +
  `confirm: true` + RoE scope check (`ScopeValidator`, red/purple) + kill-switch unlocked.
- `/api/models` never returns API keys; `/api/models/auth` is write-only.
- Every control action is written to the HMAC-chained audit log.

### Limitations & hardening notes

This console is built for a **single operator on localhost**. The following are
accepted trade-offs at that scope — revisit every one before binding anywhere else:

- **No transport encryption.** Traffic is plain `http`/`ws`. The bearer token rides
  the WebSocket subprotocol (kept off URLs/logs) but is still sent in clear. This is
  safe *only* because the server binds `127.0.0.1`. **Never bind to `0.0.0.0` or a
  routable interface without terminating TLS in front of it** (e.g. a localhost-only
  reverse proxy). `run()` refuses non-localhost hosts to enforce this.
- **Token expires; rotation is launch-time only.** The bearer token carries an issue
  timestamp and is rejected once older than `WEBDASH_TOKEN_TTL` (default 8h; set `0` to
  disable). An expired token is **rotated on the next `dashboard --web` launch**, which
  prints a fresh `#token=` URL. There is no in-session refresh or revocation endpoint:
  when a token expires while a tab is open, every call returns `401 token expired` and the
  operator must relaunch and reopen the new URL. Legacy tokens minted before TTL existed
  (bare strings, no issue time) never expire until the next mint.
- **No per-endpoint rate limiting.** The auth + confirm + scope gates are the only
  throttle. Add rate limiting if the surface is ever exposed beyond localhost.

## Layout

| Component | Endpoints |
|---|---|
| `api/monitor.py` (read, token) | `/state /audit /tasks /graph /heatmap /cost /chain/verify /roe /engagements /adversaries /actors /agents /system` |
| `api/control.py` (control-gated) | `/run/red\|blue\|purple`, `/forge`, `/lock`, `/unlock`, `/run/{id}/status`, `/report/brief` |
| `api/control.py` (token, read-only parse) | `/stix/parse`, `/ioc/parse` — parse CTI into a hunt brief (no run; 8 MB cap) |
| `api/models.py` | GET `/models`; POST `/models/local\|cloud\|hybrid\|auth` |
| `stream.py` | WebSocket `/api/stream` — snapshot + live audit/task tail |
| `security.py` / `guards.py` | token auth / confirm + scope + unlocked guards |
| `runner.py` | `Orchestrator.route()` as a tracked background run (single active) |
| `data.py` | read adapters over StateManager / GraphManager / CostTracker / audit_chain |
| `frontend/` | Vite+React+Tailwind C2 console (panels + ControlBar + ModelSelector) |

## Threat Hunt (STIX / IOC list)

The **Threat Hunt** view turns CTI into a defensive hunt. Two read-only parse endpoints
(token-gated, no `confirm`, 8 MB cap) feed the same `StixBrief` shape:

- `POST /api/stix/parse` — a STIX 2.x bundle → IOCs (from indicator patterns), ATT&CK
  TTPs (attack-pattern refs), actor/malware context.
- `POST /api/ioc/parse` — a plain newline / simple-CSV IOC list → IOCs only
  (`detect_ioc_type` auto-types each line; CSV header + `#` comments + BOM stripped).

`core/stix_ingest.py` is stdlib-only (no `stix2` at runtime). All IOCs are **refanged**
(`hxxp`→`http`, `[.]`→`.`, `[at]`/`[dot]`, …) and **validated** by type on parse; IPs are
canonicalized so dedup is correct. Both parsers share one brief via `_make_brief`.

Frontend (`StixHuntView.tsx`): drag-drop / click / paste, auto-format routing, parsed-brief
**export** (JSON), IOC **search** + per-type **filter chips**, **defang display** with
**copy** (copies the real value) / **copy-all (N)**, and a `local`/`expensive` **brain-tier**
toggle. Launching a hunt posts the composed task to the control-gated `/api/run/blue`
(defensive — stealth N/A).

## Agents view

The **Agents** view (`AgentsView.tsx`, sidebar id `agents-roster`) lists every agent from
`GET /api/agents` (the enriched roster: `name, domain, description, supports_stealth`,
built by `agent_roster()` from `AGENT_REGISTRY` + `AGENT_META`). Each agent card has an
instruction box, target, a **mode** selector (passive / active / stealth — stealth only for
red agents, each mode prepends a directive shown inline), and a brain-tier toggle.

Run dispatches to the agent's **domain** endpoint — `red → /api/run/red`, `blue →
/api/run/blue` — with the chosen agent sent as `agent`. The orchestrator's `force_agent`
(a pure routing hint, no state) then enqueues just that one agent instead of the full
domain tier set; `control.py` validates `agent` against the domain's registry (400 on
mismatch). The reporter has no run endpoint — its card is disabled (reporting is driven
from Findings). The Threat Hunt view reuses the same mechanism via a blue-agent dropdown.

## Findings: attribution, export, brief

- **Attribution** — findings record the discovering agent (`source_agent`, persisted via an
  idempotent, race-safe column migration; `base_agent` log_finding passes `AGENT_NAME`),
  surfaced as a label and in every export.
- **Export** — JSON, CSV, Markdown (client-side), plus **Print / Save as PDF** (native
  browser print of a styled table). All disabled when there are no findings.
- **Reporter brief** — `POST /api/report/brief` (token + `confirm` + `require_unlocked`)
  runs `ReporterAgent.brief()` (one LLM completion, no artifact saved) over current findings
  and returns Markdown, rendered inline in the Findings view with a download-`.md` option.

## Config / env

- `--port` — server port (default 8765).
- `OPENELIA_STATE_DIR` — state directory the API reads (default `state`).
- `OPENELIA_ROE_PATH` — Rules-of-Engagement file for the scope gate (default `roe.json`).
- `WEBDASH_TOKEN` — override/seed the bearer token (else generated + kept in keychain).
- `WEBDASH_TOKEN_TTL` — token lifetime in seconds (default `28800` = 8h; `0` disables expiry).
  Expired tokens are rotated on the next launch.

## Tests

```bash
pytest tests/test_webdash_*.py -v          # auth, monitor, control, models, stream, runner
pytest tests/test_webdash_*.py --cov=webdash --cov-report=term-missing
```
