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
4. Run host `setup.sh` (venv, deps, sterile image, keyring) unless `--no-engine`.
5. Print service URLs + the dashboard command.

## Start the web console

```bash
./venv/bin/python main.py dashboard --web
```

Open the printed `http://127.0.0.1:PORT/#token=…` URL (127.0.0.1 only, token-gated).
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
