$ErrorActionPreference = "Stop"

Write-Host "CyberAI setup - Windows PowerShell" -ForegroundColor Cyan

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    throw "Python was not found. Install Python 3.12+ from https://www.python.org/downloads/windows/ and enable Add Python to PATH."
}

$pythonVersion = & python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
$parts = $pythonVersion.Split(".")
if ([int]$parts[0] -lt 3 -or ([int]$parts[0] -eq 3 -and [int]$parts[1] -lt 12)) {
    throw "CyberAI requires Python 3.12 or newer. Found $pythonVersion."
}

$ollama = Get-Command ollama -ErrorAction SilentlyContinue
if (-not $ollama) {
    throw "Ollama was not found. Install it from https://ollama.com/download/windows, reopen PowerShell, then rerun .\setup.ps1."
}

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    & python -m venv .venv
}

& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -r requirements.txt

Write-Host "Checking local Ollama model..." -ForegroundColor Cyan
& ollama pull qwen2.5:3b

Write-Host ""
Write-Host "Setup complete. Start CyberAI with .\run.ps1" -ForegroundColor Green
