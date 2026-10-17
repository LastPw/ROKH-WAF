@echo off
title ROKH WAF - Automated Universal Installer
cd /d "%~dp0"
cls
echo ======================================================================
echo  [ROKH WAF] Starting Automated Windows Setup...
echo ======================================================================
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
if %ERRORLEVEL% neq 0 (
    echo.
    echo [-] Installation encountered an issue (Exit Code: %ERRORLEVEL%).
)
echo.
pause
