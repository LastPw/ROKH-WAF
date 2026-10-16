# ==============================================================================
# ROKH WAF (دیواره آتش رُخ) - Easy Installer for Windows
# Author: Taha Vaziri (طاها وزیری)
# ==============================================================================

$ErrorActionPreference = "Stop"

Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host " 🛡️  ROKH WAF (دیواره آتش رُخ) - Automated Installation Protocol" -ForegroundColor Cyan
Write-Host "     توسعه‌دهنده: طاها وزیری (Taha Vaziri)" -ForegroundColor DarkCyan
Write-Host "======================================================================" -ForegroundColor Cyan

# 1. Check Python Toolchain
Write-Host "`n[1/4] Checking Python 3.10+ Environment..." -ForegroundColor Yellow
if (Get-Command python -ErrorAction SilentlyContinue) {
    $pyVer = python --version 2>&1
    Write-Host "  [+] Python Detected: $pyVer" -ForegroundColor Green
} else {
    Write-Host "  [-] Error: Python is not installed or not in PATH." -ForegroundColor Red
    Write-Host "      Please install Python from https://www.python.org/downloads/ or run: winget install Python.Python.3.11" -ForegroundColor Yellow
    exit 1
}

# 2. Check Rust & Cargo Toolchain
Write-Host "`n[2/4] Checking Rust & Cargo Toolchain..." -ForegroundColor Yellow
if (Get-Command cargo -ErrorAction SilentlyContinue) {
    $cargoVer = cargo --version 2>&1
    Write-Host "  [+] Cargo Detected: $cargoVer" -ForegroundColor Green
} else {
    Write-Host "  [-] Error: Rust/Cargo is not installed or not in PATH." -ForegroundColor Red
    Write-Host "      Please install Rust via https://rustup.rs or run: winget install Rustlang.Rustup" -ForegroundColor Yellow
    exit 1
}

# 3. Install Python Dependencies
Write-Host "`n[3/4] Installing Python Requirements (FastAPI, Uvicorn, Requests)..." -ForegroundColor Yellow
python -m pip install --upgrade pip --quiet
python -m pip install -r requirements.txt --quiet
if ($LASTEXITCODE -eq 0) {
    Write-Host "  [+] Python packages installed successfully." -ForegroundColor Green
} else {
    Write-Host "  [-] Warning: Some Python packages could not be installed. Check internet connection." -ForegroundColor Yellow
}

# 4. Compile High-Performance Rust Engine (Release Mode)
Write-Host "`n[4/4] Compiling Rust WAF Core Proxy in Release Mode (O3 Optimized)..." -ForegroundColor Yellow
cargo build --release
if ($LASTEXITCODE -eq 0) {
    Write-Host "  [+] Rust WAF Engine compiled successfully: target\release\waf_engine.exe" -ForegroundColor Green
} else {
    Write-Host "  [-] Error: Rust compilation failed." -ForegroundColor Red
    exit 1
}

Write-Host "`n======================================================================" -ForegroundColor Green
Write-Host " 🎉 INSTALLATION COMPLETED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Green
Write-Host " You can now launch and configure ROKH WAF anytime using:" -ForegroundColor White
Write-Host "   .\start_waf.ps1" -ForegroundColor Cyan
Write-Host " or:" -ForegroundColor White
Write-Host "   python start_waf.py" -ForegroundColor Cyan
Write-Host "======================================================================`n" -ForegroundColor Green
