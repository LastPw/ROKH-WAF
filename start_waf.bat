@echo off
setlocal
cd /d "%~dp0"
title ROKH WAF - Enterprise Banking Shield

if not exist "target\release\waf_engine.exe" (
    echo [*] Binary not found. Building release binary...
    cargo build --release --bin waf_engine
    if errorlevel 1 (
        echo [!] Build failed. Please run install.bat first.
        pause
        exit /b 1
    )
)

echo [*] Starting ROKH WAF Enterprise Engine...
target\release\waf_engine.exe %*
if errorlevel 1 (
    pause
)
