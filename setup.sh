#!/bin/bash

# --- OpenElia Setup Script ---

echo "🛡️ Starting OpenElia Setup..."

# 1. Python Environment
if [ ! -d ".venv" ]; then
    echo "[+] Creating virtual environment..."
    python3 -m venv .venv
fi

echo "[+] Installing dependencies..."
./.venv/bin/pip install --upgrade pip
if [ -f "requirements.txt.lock" ]; then
    ./.venv/bin/pip install -r requirements.txt.lock
else
    ./.venv/bin/pip install -r requirements.txt
fi

# 2. State Initialization
echo "[+] Initializing state directory..."
mkdir -p state
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
./.venv/bin/python -c "from secret_store import SecretStore; SecretStore.bootstrap()"

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
