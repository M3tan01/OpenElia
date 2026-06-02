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
| `api/monitor.py` (read, token) | `/state /audit /tasks /graph /heatmap /cost /chain/verify` |
| `api/control.py` (control-gated) | `/run/red\|blue\|purple`, `/lock`, `/unlock`, `/run/{id}/status` |
| `api/models.py` | GET `/models`; POST `/models/local\|cloud\|hybrid\|auth` |
| `stream.py` | WebSocket `/api/stream` — snapshot + live audit/task tail |
| `security.py` / `guards.py` | token auth / confirm + scope + unlocked guards |
| `runner.py` | `Orchestrator.route()` as a tracked background run (single active) |
| `data.py` | read adapters over StateManager / GraphManager / CostTracker / audit_chain |
| `frontend/` | Vite+React+Tailwind C2 console (panels + ControlBar + ModelSelector) |

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
