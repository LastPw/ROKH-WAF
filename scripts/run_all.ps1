# AegisGuard / ROKH WAF - Pure Rust Orchestrator
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " 🛡️  ROKH WAF - Pure Rust 100% Native Startup Protocol" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$BinaryPath = ".\target\release\waf_engine.exe"
if (-not (Test-Path $BinaryPath)) {
    Write-Host "[*] Release binary not found. Compiling pure Rust engine..." -ForegroundColor Yellow
    cargo build --release --bin waf_engine
}

Write-Host "[*] Starting ROKH WAF Core (Proxy + Integrated SOC Console)..." -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Green
Write-Host " ✅ All services online in single native Rust process!" -ForegroundColor Green
Write-Host " 📊 Integrated SOC Dashboard : http://127.0.0.1:8080/dashboard" -ForegroundColor Green
Write-Host " 🛡️  WAF Proxy Entrypoint     : http://127.0.0.1:8080" -ForegroundColor Green
Write-Host " 🎯 Built-in Mock Target     : http://127.0.0.1:8080/target/search" -ForegroundColor Green
Write-Host " 🚀 Security Benchmark Tool   : cargo run --bin rokh_bench --release" -ForegroundColor Gray
Write-Host " Press Ctrl+C in this terminal to stop." -ForegroundColor Gray
Write-Host "==========================================================" -ForegroundColor Green

& $BinaryPath --port 8080 --mode PREVENTION --rpm 120

