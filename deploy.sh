#!/bin/bash
#
# deploy.sh — one-command OpenElia bring-up (hybrid topology).
#
#   Services in Docker : TheHive + n8n (default), Cortex + Elasticsearch (opt-in)
#   Engine on host     : Python venv via setup.sh; sterile sandbox spawns natively
#   Local brain        : Ollama on the HOST (GPU) — verified, not containerized
#
# Usage:
#   ./deploy.sh                 # bring up default stack + host engine
#   ./deploy.sh --analyzers     # also start Cortex + Elasticsearch (heavy)
#   ./deploy.sh --no-engine     # only start the Docker services, skip setup.sh
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK_DIR="$REPO_ROOT/docker/soc-stack"
ENV_FILE="$STACK_DIR/.env"
ENV_EXAMPLE="$STACK_DIR/.env.example"

WITH_ANALYZERS=0
RUN_ENGINE=1
for arg in "$@"; do
    case "$arg" in
        --analyzers) WITH_ANALYZERS=1 ;;
        --no-engine) RUN_ENGINE=0 ;;
        *) echo "[!] Unknown arg: $arg"; exit 2 ;;
    esac
done

echo "🛡️  OpenElia deploy — hybrid (Docker services + host engine)"
echo "------------------------------------------------------------"

# --- 1. Preflight -----------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
    echo "[x] docker not found. Install Docker Desktop / Engine first."; exit 1
fi
if ! docker info >/dev/null 2>&1; then
    echo "[x] Docker daemon not running. Start Docker and re-run."; exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
    echo "[x] 'docker compose' (v2) not available. Update Docker."; exit 1
fi

# Host Ollama (local brain) — warn only; the expensive brain still works without it.
if curl -fsS --max-time 2 http://localhost:11434/api/tags >/dev/null 2>&1; then
    echo "[+] Host Ollama reachable on :11434 (local brain ready)."
else
    echo "[!] Host Ollama NOT reachable on :11434."
    echo "    Local brain will be unavailable until you run:  ollama serve"
fi

# --- 2. soc-stack .env (auto-provision n8n secrets on first run) ------------
if [ ! -f "$ENV_FILE" ]; then
    echo "[+] Creating $ENV_FILE from template + generating n8n secrets..."
    cp "$ENV_EXAMPLE" "$ENV_FILE"
    N8N_PW="$(openssl rand -hex 24)"
    N8N_KEY="$(openssl rand -hex 32)"
    # Fill the two required blanks (portable sed: write to temp, move back).
    sed -e "s|^N8N_BASIC_AUTH_PASSWORD=.*|N8N_BASIC_AUTH_PASSWORD=${N8N_PW}|" \
        -e "s|^N8N_ENCRYPTION_KEY=.*|N8N_ENCRYPTION_KEY=${N8N_KEY}|" \
        "$ENV_FILE" > "$ENV_FILE.tmp" && mv "$ENV_FILE.tmp" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    echo "    n8n login → user: admin   password: ${N8N_PW}"
    echo "    (saved in $ENV_FILE, chmod 600)"
else
    echo "[+] Using existing $ENV_FILE"
fi

# --- 3. Bring up Docker services -------------------------------------------
echo "[+] Starting Docker services (TheHive + n8n)..."
COMPOSE=(docker compose --env-file "$ENV_FILE" -f "$STACK_DIR/docker-compose.yml")
if [ "$WITH_ANALYZERS" = "1" ]; then
    echo "    + analyzers profile (Cortex + Elasticsearch — heavy)"
    "${COMPOSE[@]}" --profile analyzers up -d
else
    "${COMPOSE[@]}" up -d
fi

# --- 4. Host engine (venv, deps, sterile image, keyring) -------------------
if [ "$RUN_ENGINE" = "1" ]; then
    echo "[+] Setting up host engine via setup.sh..."
    ( cd "$REPO_ROOT" && bash setup.sh )
fi

# --- 5. Summary -------------------------------------------------------------
source "$ENV_FILE" 2>/dev/null || true
echo ""
echo "✅ OpenElia is up."
echo "   TheHive   : http://127.0.0.1:${THEHIVE_PORT:-9000}"
echo "   n8n       : http://127.0.0.1:${N8N_PORT:-5678}  (user: ${N8N_BASIC_AUTH_USER:-admin})"
if [ "$WITH_ANALYZERS" = "1" ]; then
    echo "   Cortex    : http://127.0.0.1:${CORTEX_PORT:-9001}"
fi
echo ""
echo "   Start the web console:"
echo "     cd \"$REPO_ROOT\" && ./venv/bin/python main.py dashboard --web"
echo "   Then open the printed  http://127.0.0.1:PORT/#token=...  URL."
echo ""
echo "   Stop services:  docker compose --env-file \"$ENV_FILE\" -f \"$STACK_DIR/docker-compose.yml\" down"
