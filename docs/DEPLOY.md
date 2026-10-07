# Deploying OpenElia (Hybrid Topology)

OpenElia runs **SOC services in Docker** and the **agent engine on the host**. The
local LLM brain (Ollama) stays host-native so it can use your GPU.

```
┌─ Docker (docker/soc-stack) ─────────────┐   ┌─ Host ───────────────────┐
│  TheHive   (case mgmt)      :9000        │   │  OpenElia engine (venv)  │
│  n8n       (workflows)      :5678        │   │  main.py / dashboard     │
│  Cortex*   (analyzers)      :9001        │   │  Ollama (local brain)    │
│  Elastic*  (Cortex backend)              │   │      :11434              │
└──────────────────────────────────────────┘   └──────────────────────────┘
        * only with --analyzers (heavy: ES needs ~2 GB)
All container ports bind to 127.0.0.1 only.
```

## One command

```bash
./deploy.sh                 # TheHive + n8n + host engine
./deploy.sh --analyzers     # also Cortex + Elasticsearch
./deploy.sh --no-engine     # containers only, skip setup.sh
```

`deploy.sh` will:
1. Preflight — verify Docker running, Compose v2, warn if host Ollama is down.
2. Auto-create `docker/soc-stack/.env` on first run, generating the n8n password
   (`openssl rand -hex 24`) and encryption key (`openssl rand -hex 32`), `chmod 600`.
   **The generated n8n password is printed once — save it.**
3. `docker compose up -d` the default services (add `--profile analyzers` if flagged).
4. Auto-import the n8n playbooks in `workflows/n8n/*.json` via the REST API — **only if
   `N8N_API_KEY` is set** in the `.env` (idempotent by workflow name; skipped otherwise).
   See "n8n workflow auto-import" below.
5. Run host `setup.sh` (venv, deps, sterile image, keyring) unless `--no-engine`.
6. Print service URLs + the dashboard command.

## n8n workflow auto-import

The red/blue/purple/reporting playbooks live in `workflows/n8n/*.json`. `deploy.sh`
imports them for you, but n8n's public REST API needs a key it only issues after the
first login:

1. First bring-up: leave `N8N_API_KEY` blank. Import is skipped (you'll see an `[i]`
   line). Log in at `http://127.0.0.1:5678`.
2. In n8n: **Settings → n8n API → Create an API key**. Paste it into
   `docker/soc-stack/.env` as `N8N_API_KEY=…`.
3. Re-run `./deploy.sh`. It POSTs each playbook (header `X-N8N-API-KEY`), skipping any
   already present by name.

Imported workflows are **inactive**. Before activating each in the n8n editor, wire two
credentials and activate:
- an **httpHeaderAuth** credential — `Authorization: Bearer <dashboard token>` for the
  engine calls (the token rotates each `main.py dashboard --web`, so update it per run);
- an **httpHeaderAuth** credential for TheHive's API on the HTTP nodes that POST to
  `thehive:9000`.

See `workflows/n8n/README.md` for the full credential + callback-URL walkthrough.

## Start the web console

```bash
./venv/bin/python main.py dashboard --web
```

Open the printed `http://0.0.0.0:PORT/#token=…` URL. LAN-exposed by default: binds
`0.0.0.0`, `PrivateClientMiddleware` 403s any non-RFC1918/non-loopback peer, bearer-token
gated. On a shared LAN the `#token` fragment is reachable — don't leak it; front with TLS
for anything beyond a trusted segment.
Switch brains in the sidebar **Brain Models** view — no restart, no hardcoded model.

## Local + expensive brains

- **Local** (default): Ollama on the host. `ollama serve`, then pull a model
  (e.g. `ollama pull qwen3.5:2b`). Reasoning models need `max_tokens ≥ 256`.
- **Expensive**: set a cloud provider + key via
  `./venv/bin/python main.py model auth google YOUR_KEY` (key goes to the OS keychain,
  never the repo). Verified provider/model: `google` / `gemini-3.6-flash`.

## Stop

```bash
docker compose --env-file docker/soc-stack/.env \
  -f docker/soc-stack/docker-compose.yml down
```

Add `-v` to also drop the named volumes (destroys TheHive/n8n data).

## Notes

- First run pulls multi-GB images — run `./deploy.sh` yourself; expect a wait.
- Image tags are pinned in `.env` (`*_VERSION`). Bump only after confirming the tag
  exists in the registry.
- macOS: containerized Ollama would be CPU-only and collide on `:11434`; that is why
  the local brain is host-native, not in Compose.
