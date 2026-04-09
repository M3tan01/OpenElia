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

# 2. State Initialization
Write-Host "[+] Initializing state directory..."
if (!(Test-Path "state")) { New-Item -ItemType Directory -Path "state" }
New-Item -ItemType File -Path "state\.gitkeep" -Force | Out-Null

# 3. Docker Offensive Image
if (Get-Command docker -ErrorAction SilentlyContinue) {
    Write-Host "[+] Building sterile offensive container (cyber-ops-recon:strict)..."
    docker build -t cyber-ops-recon:strict -f Dockerfile.offensive .
} else {
    Write-Warning "[!] Docker not found. Offensive modules will not function in sterile mode."
}

# 4. Configuration
if (!(Test-Path ".env")) {
    Write-Host "[+] Creating .env from template..."
    Copy-Item ".env.example" ".env"
    Write-Host "[!] Action required: Update the .env file with your API keys." -ForegroundColor Yellow
}

Write-Host "`n✅ Setup complete! You are ready to operate." -ForegroundColor Green
Write-Host "   Run '/agent Pentester' to begin."
