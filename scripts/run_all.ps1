# AegisGuard WAF - Launch Orchestrator
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " 🛡️  AegisGuard WAF - Multi-Process Startup Protocol" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Start Python Management, SOC Dashboard & Target Backend (Port 9000)
Write-Host "[1/2] Starting Python SOC Dashboard & Target Backend on Port 9000..." -ForegroundColor Yellow
$PythonProc = Start-Process python -ArgumentList "python_soc/app.py" -PassThru -NoNewWindow
Start-Sleep -Seconds 2

# 2. Start Rust WAF Core Proxy (Port 8080)
Write-Host "[2/2] Starting Rust High-Performance WAF Engine on Port 8080..." -ForegroundColor Yellow
$RustProc = Start-Process cargo -ArgumentList "run" -PassThru -NoNewWindow

Write-Host "==========================================================" -ForegroundColor Green
Write-Host " ✅ All services online!" -ForegroundColor Green
Write-Host " 📊 SOC Dashboard & Simulator : http://127.0.0.1:9000" -ForegroundColor Green
Write-Host " 🛡️  WAF Proxy Entrypoint     : http://127.0.0.1:8080" -ForegroundColor Green
Write-Host " Press Ctrl+C in this terminal to stop." -ForegroundColor Gray
Write-Host "==========================================================" -ForegroundColor Green

try {
    Wait-Process -Id $RustProc.Id
} finally {
    Write-Host "`nStopping background processes..." -ForegroundColor Yellow
    Stop-Process -Id $PythonProc.Id -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $RustProc.Id -Force -ErrorAction SilentlyContinue
}
