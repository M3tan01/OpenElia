#!/bin/bash

# --- OpenElia Setup Script ---

echo "🛡️ Starting OpenElia Setup..."

# 1. Python Environment
#    Canonical venv dir is ./venv (matches project convention and the repo's
#    existing environment). Set OPENELIA_DEV=1 to also install the dev extra
#    (pytest, pytest-asyncio, pip-tools) for running the test suite.
if [ ! -d "venv" ]; then
    echo "[+] Creating virtual environment..."
    python3 -m venv venv
fi

echo "[+] Installing dependencies..."
./venv/bin/pip install --upgrade pip
if [ -f "requirements.txt.lock" ]; then
    # Enforce hash-pinned installs when the lock carries hashes (production
    # posture). If the lock predates hash generation, fall back with a loud
    # warning rather than silently installing unpinned. Regenerate with:
    #   ./venv/bin/pip-compile --generate-hashes -o requirements.txt.lock requirements.txt
    if grep -q -- '--hash' requirements.txt.lock; then
        ./venv/bin/pip install --require-hashes -r requirements.txt.lock
    else
        echo "[!] WARNING: requirements.txt.lock has NO hashes — installing UNPINNED."
        echo "    Regenerate a hash-pinned lock before production deploy:"
        echo "    ./venv/bin/pip-compile --generate-hashes -o requirements.txt.lock requirements.txt"
        ./venv/bin/pip install -r requirements.txt.lock
    fi
else
    ./venv/bin/pip install -r requirements.txt
fi

# Dev/test dependencies (opt-in) — pytest, pytest-asyncio, pip-tools.
if [ "${OPENELIA_DEV:-0}" = "1" ]; then
    echo "[+] Installing dev extras (pytest, pytest-asyncio, pip-tools)..."
    ./venv/bin/pip install -e ".[dev]"
fi

# 2. State & Artifacts Initialization
echo "[+] Initializing directories..."
mkdir -p state artifacts
touch state/.gitkeep

# 3. Docker Offensive Image
if command -v docker &> /dev/null; then
    echo "[+] Building sterile offensive container (cyber-ops-recon:strict)..."
    docker build -t cyber-ops-recon:strict -f Dockerfile.offensive .
else
    echo "[!] WARNING: Docker not found. Offensive modules will not function in sterile mode."
fi

# 4. Configuration — store secrets in OS keyring, not .env
echo "[+] Bootstrapping OS keyring for secure secret storage..."
./venv/bin/python -c "from secret_store import SecretStore; SecretStore.bootstrap()"

# If a legacy .env exists, warn the user to delete it
if [ -f ".env" ]; then
    echo ""
    echo "[!] WARNING: A plaintext .env file exists."
    echo "    Your secrets are now stored in the OS keyring."
    echo "    Delete the .env file to prevent accidental secret exposure:"
    echo "    rm .env"
fi

echo ""
echo "✅ Setup complete! You are ready to operate."
echo "   Run 'python main.py check' to verify your environment."
echo "   See COMMANDS.txt for full command reference and model configuration."
