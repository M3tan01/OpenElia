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

## Layout

| Component | Endpoints |
|---|---|
| `api/monitor.py` (read, token) | `/state /audit /tasks /graph /heatmap /cost /chain/verify /roe /engagements /adversaries /actors /system` |
| `api/control.py` (control-gated) | `/run/red\|blue\|purple`, `/forge`, `/lock`, `/unlock`, `/run/{id}/status` |
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

## Config / env

- `--port` — server port (default 8765).
- `OPENELIA_STATE_DIR` — state directory the API reads (default `state`).
- `OPENELIA_ROE_PATH` — Rules-of-Engagement file for the scope gate (default `roe.json`).
- `WEBDASH_TOKEN` — override/seed the bearer token (else generated + kept in keychain).

## Tests

```bash
pytest tests/test_webdash_*.py -v          # auth, monitor, control, models, stream, runner
pytest tests/test_webdash_*.py --cov=webdash --cov-report=term-missing
```
