# ==============================================================================
# ROKH WAF - Windows PowerShell Launcher (Pure Native Rust)
# ==============================================================================

$bin = ".\target\release\waf_engine.exe"
if (-not (Test-Path $bin)) {
    Write-Host "[*] Compiling ROKH WAF release binary..." -ForegroundColor Cyan
    cargo build --release --bin waf_engine
}

& $bin @args

