# --- OpenElia Windows Setup Script ---

Write-Host "🛡️ Starting OpenElia Setup..." -ForegroundColor Cyan

# 1. Python Environment
if (!(Test-Path ".venv")) {
    Write-Host "[+] Creating virtual environment..."
    python -m venv .venv
}

Write-Host "[+] Installing dependencies..."
& ".\.venv\Scripts\pip.exe" install --upgrade pip
if (Test-Path "requirements.txt.lock") {
    & ".\.venv\Scripts\pip.exe" install -r requirements.txt.lock
} else {
    & ".\.venv\Scripts\pip.exe" install -r requirements.txt
}

# 2. State & Artifacts Initialization
Write-Host "[+] Initializing directories..."
if (!(Test-Path "state")) { New-Item -ItemType Directory -Path "state" }
if (!(Test-Path "artifacts")) { New-Item -ItemType Directory -Path "artifacts" }
New-Item -ItemType File -Path "state\.gitkeep" -Force | Out-Null

# 3. TypeScript CLI
if (Get-Command node -ErrorAction SilentlyContinue) {
    Write-Host "[+] Building TypeScript CLI..."
    Push-Location src
    npm install
    npm run build
    Pop-Location
} else {
    Write-Warning "[!] Node.js not found. TypeScript CLI (openelia-cli) will not be available."
    Write-Host "    Install Node.js from https://nodejs.org and re-run setup.ps1 to enable it."
}

# 4. Docker Offensive Image
if (Get-Command docker -ErrorAction SilentlyContinue) {
    Write-Host "[+] Building sterile offensive container (cyber-ops-recon:strict)..."
    docker build -t cyber-ops-recon:strict -f Dockerfile.offensive .
} else {
    Write-Warning "[!] Docker not found. Offensive modules will not function in sterile mode."
}

# 5. Configuration — store secrets in Windows Credential Manager via keyring
Write-Host "[+] Bootstrapping OS keyring for secure secret storage..."
& ".\.venv\Scripts\python.exe" -c "from secret_store import SecretStore; SecretStore.bootstrap()"

# If a legacy .env exists, warn the user
if (Test-Path ".env") {
    Write-Host ""
    Write-Warning "[!] A plaintext .env file exists. Your secrets are now stored in Windows Credential Manager."
    Write-Host "    Delete the .env file to prevent accidental secret exposure: del .env"
}

Write-Host "`n✅ Setup complete! You are ready to operate." -ForegroundColor Green
Write-Host "   Run 'python main.py check' to verify your environment."
Write-Host "   See COMMANDS.txt for full command reference and model configuration."
