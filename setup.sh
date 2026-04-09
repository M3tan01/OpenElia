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

# 4. Configuration
if [ ! -f ".env" ]; then
    echo "[+] Creating .env from template..."
    cp .env.example .env
    echo "[!] Action required: Update the .env file with your API keys."
fi

echo ""
echo "✅ Setup complete! You are ready to operate."
echo "   Run '/agent Pentester' to begin."
