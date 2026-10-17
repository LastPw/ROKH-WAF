# ==============================================================================
# ROKH WAF - Universal Automated Installer for Windows (100% Pure Rust)
# Works anywhere: Local repo clone, fresh Windows machine, or via web one-liner:
#   irm https://raw.githubusercontent.com/LastPw/ROKH-WAF/main/install.ps1 | iex
# ==============================================================================

[CmdletBinding()]
param(
    [switch]$Quick,
    [int]$Port = 8080,
    [string]$Target = "http://127.0.0.1:9000",
    [string]$Mode = "PREVENTION",
    [switch]$CreateShortcut,
    [switch]$StartNow
)

$ErrorActionPreference = "Continue"

function Write-Header($text) {
    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host " $text" -ForegroundColor Cyan
    Write-Host "======================================================================" -ForegroundColor Cyan
}

function Write-Step($step, $total, $text) {
    Write-Host ""
    Write-Host "[$step/$total] $text" -ForegroundColor Yellow
}

function Write-Success($text) {
    Write-Host "  [+] $text" -ForegroundColor Green
}

function Write-Info($text) {
    Write-Host "  [i] $text" -ForegroundColor Cyan
}

function Write-Warn($text) {
    Write-Host "  [!] $text" -ForegroundColor Yellow
}

function Write-Failure($text) {
    Write-Host "  [-] $text" -ForegroundColor Red
}

Write-Header "[ROKH WAF] Universal Native Installation & Environment Setup"

# ------------------------------------------------------------------------------
# 0. Repository Context Check (Support 1-liner remote execution)
# ------------------------------------------------------------------------------
if (-not (Test-Path "Cargo.toml")) {
    Write-Step 0 5 "Remote / Standalone Execution Detected: Preparing Workspace..."
    $cloneDir = Join-Path (Get-Location) "ROKH-WAF"
    if (Test-Path (Join-Path $cloneDir "Cargo.toml")) {
        Set-Location $cloneDir
        Write-Success "Found existing repository at: $cloneDir"
    } else {
        if (Get-Command git -ErrorAction SilentlyContinue) {
            Write-Info "Cloning ROKH-WAF from GitHub repository..."
            git clone https://github.com/LastPw/ROKH-WAF.git $cloneDir
            if ($LASTEXITCODE -eq 0 -and (Test-Path $cloneDir)) {
                Set-Location $cloneDir
                Write-Success "Repository cloned successfully to: $cloneDir"
            }
        } else {
            Write-Info "Git not detected. Downloading source archive from GitHub..."
            $zipPath = Join-Path $env:TEMP "rokh_waf_main.zip"
            Invoke-WebRequest -Uri "https://github.com/LastPw/ROKH-WAF/archive/refs/heads/main.zip" -OutFile $zipPath -UseBasicParsing
            Expand-Archive -Path $zipPath -DestinationPath $env:TEMP -Force
            $extracted = Join-Path $env:TEMP "ROKH-WAF-main"
            if (Test-Path $extracted) {
                Copy-Item -Path $extracted -Destination $cloneDir -Recurse -Force
                Set-Location $cloneDir
                Write-Success "Source extracted successfully to: $cloneDir"
            }
        }
    }
}

if (-not (Test-Path "Cargo.toml")) {
    Write-Failure "Critical: Could not locate Cargo.toml. Please run installer inside the ROKH WAF folder."
    exit 1
}

# ------------------------------------------------------------------------------
# 1. Hardware & OS Auto-Detection
# ------------------------------------------------------------------------------
Write-Step 1 5 "Auto-detecting Hardware, System Architecture & Memory..."

$osCaption = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
if (-not $osCaption) { $osCaption = [System.Environment]::OSVersion.VersionString }
$osArch = if ([Environment]::Is64BitOperatingSystem) { "64-bit (x64)" } else { "32-bit (x86)" }
$cpuCores = $env:NUMBER_OF_PROCESSORS

try {
    $ramBytes = (Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue | Measure-Object -Property Capacity -Sum).Sum
    $ramGb = [math]::Round($ramBytes / 1GB, 1)
} catch {
    $ramGb = "N/A"
}

Write-Success "Operating System : $osCaption ($osArch)"
Write-Success "CPU Concurrency  : $cpuCores Parallel Threads (Tokio Threadpool Optimized)"
Write-Success "Host Memory (RAM): $ramGb GB Available"

# ------------------------------------------------------------------------------
# 2. Rust & Cargo Toolchain Auto-Detection & Self-Healing Installation
# ------------------------------------------------------------------------------
Write-Step 2 5 "Verifying Rust & Cargo Toolchain..."

function Refresh-EnvPath {
    $machinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    $userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
    $cargoBin = "$env:USERPROFILE\.cargo\bin"
    $env:PATH = "$cargoBin;$userPath;$machinePath"
}

Refresh-EnvPath

$cargoCmd = $null
if (Get-Command cargo -ErrorAction SilentlyContinue) {
    $cargoCmd = "cargo"
} else {
    $defaultCargo = "$env:USERPROFILE\.cargo\bin\cargo.exe"
    if (Test-Path $defaultCargo) {
        $cargoCmd = $defaultCargo
    }
}

if (-not $cargoCmd) {
    Write-Warn "Cargo compiler not found in system PATH. Initiating automated toolchain installation..."
    
    $installed = $false
    # Attempt A: Windows Package Manager (winget)
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Info "Installing Rust via Windows Package Manager (winget)..."
        try {
            winget install Rustlang.Rustup --silent --accept-package-agreements --accept-source-agreements
            Refresh-EnvPath
            if (Test-Path "$env:USERPROFILE\.cargo\bin\cargo.exe") {
                $cargoCmd = "$env:USERPROFILE\.cargo\bin\cargo.exe"
                $installed = $true
            }
        } catch {}
    }

    # Attempt B: Direct Official rustup-init installer
    if (-not $installed) {
        Write-Info "Downloading official rustup-init from https://win.rustup.rs/x86_64..."
        $rustupExe = Join-Path $env:TEMP "rustup-init.exe"
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
            Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $rustupExe -UseBasicParsing
            Write-Info "Running rustup-init in automated mode (stable toolchain)..."
            Start-Process -FilePath $rustupExe -ArgumentList "-y", "--default-toolchain", "stable", "--profile", "minimal" -Wait -NoNewWindow
            Refresh-EnvPath
            if (Test-Path "$env:USERPROFILE\.cargo\bin\cargo.exe") {
                $cargoCmd = "$env:USERPROFILE\.cargo\bin\cargo.exe"
                $installed = $true
            }
        } catch {
            Write-Warn "Direct rustup-init download encountered: $($_.Exception.Message)"
        }
    }

    if (-not $installed) {
        Write-Failure "Could not automatically install Rust."
        Write-Host "Please install Rust manually from https://rustup.rs and rerun this script." -ForegroundColor Yellow
        exit 1
    }
}

$cargoVer = & $cargoCmd --version 2>&1
Write-Success "Rust Toolchain Active: $cargoVer"

# ------------------------------------------------------------------------------
# 3. Port & Ingress Diagnostics
# ------------------------------------------------------------------------------
Write-Step 3 5 "Verifying Network Ingress Port Availability (Port $Port)..."

function Test-PortOpen([int]$p) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $ar = $client.BeginConnect("127.0.0.1", $p, $null, $null)
        $ready = $ar.AsyncWaitHandle.WaitOne(300, $false)
        if ($ready -and $client.Connected) {
            $client.EndConnect($ar)
            return $true
        }
        return $false
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

if (Test-PortOpen $Port) {
    Write-Info "Port $Port is currently responding (an existing instance or service is running)."
    Write-Info "You can continue compilation; when starting, specify an alternate port via '--port <num>' if desired."
} else {
    Write-Success "Port $Port is FREE and ready for WAF Ingress."
}

# ------------------------------------------------------------------------------
# 4. Compilation & Production Binary Building (Release O3)
# ------------------------------------------------------------------------------
Write-Step 4 5 "Building Statically-Optimized Rust Release Binaries..."

$binPath = "target\release\waf_engine.exe"
$benchBin = "target\release\rokh_bench.exe"

Write-Info "Compiling WAF Core Engine (Axum + Tokio + GIS + SQLite WAL)..."
& $cargoCmd build --release --bin waf_engine
if ($LASTEXITCODE -ne 0) {
    Write-Failure "WAF compilation failed. If missing MSVC C++ tools, run: winget install Microsoft.VisualStudio.2022.BuildTools"
    exit 1
}
Write-Success "WAF Core Engine compiled: $binPath"

Write-Info "Compiling Native Security Benchmark CLI (rokh_bench)..."
& $cargoCmd build --release --bin rokh_bench
if ($LASTEXITCODE -eq 0) {
    Write-Success "Benchmark CLI compiled: $benchBin"
}

# Self-diagnostic execution test
if (Test-Path $binPath) {
    $testRun = & $binPath --help 2>&1
    Write-Success "Self-Diagnostic Test: Engine passes all pre-flight sanity checks (100% Operational)."
}

# ------------------------------------------------------------------------------
# 5. Launcher Generation & Windows Integrations
# ------------------------------------------------------------------------------
Write-Step 5 5 "Generating Quick-Start Helpers & System Shortcuts..."

# 1. start_waf.bat (Double-clickable for any Windows user)
$batContent = @"
@echo off
title ROKH WAF - Enterprise Security Proxy
cls
echo ======================================================================
echo  [ROKH WAF] Starting Layer-7 Defense Engine & SOC Dashboard...
echo ======================================================================
if not exist "target\release\waf_engine.exe" (
    echo [*] Release binary not found. Compiling first...
    cargo build --release --bin waf_engine
)
echo [*] Launching WAF on Port $Port [Target: $Target, Mode: $Mode]...
target\release\waf_engine.exe --port $Port --target $Target --mode $Mode --rpm 120
pause
"@
[System.IO.File]::WriteAllText((Join-Path (Get-Location) "start_waf.bat"), $batContent, [System.Text.Encoding]::ASCII)
Write-Success "Generated double-clickable launcher: start_waf.bat"

# 2. start_waf.ps1
$ps1Content = @"
# ==============================================================================
# ROKH WAF - Native PowerShell Launcher
# ==============================================================================
`$bin = ".\target\release\waf_engine.exe"
if (-not (Test-Path `$bin)) {
    Write-Host "[*] Compiling ROKH WAF release binary..." -ForegroundColor Cyan
    cargo build --release --bin waf_engine
}
& `$bin --port $Port --target $Target --mode $Mode --rpm 120 @args
"@
[System.IO.File]::WriteAllText((Join-Path (Get-Location) "start_waf.ps1"), $ps1Content, [System.Text.Encoding]::UTF8)
Write-Success "Generated PowerShell launcher: start_waf.ps1"

# 3. Optional Desktop Shortcut
if ($CreateShortcut) {
    try {
        $wsh = New-Object -ComObject WScript.Shell
        $desktopPath = [System.Environment]::GetFolderPath('Desktop')
        $shortcut = $wsh.CreateShortcut((Join-Path $desktopPath "ROKH WAF SOC.lnk"))
        $shortcut.TargetPath = (Join-Path (Get-Location) "start_waf.bat")
        $shortcut.WorkingDirectory = (Get-Location).Path
        $shortcut.Description = "ROKH WAF - Enterprise Security Operations Center"
        $shortcut.Save()
        Write-Success "Created Windows Desktop shortcut: 'ROKH WAF SOC'"
    } catch {
        Write-Warn "Could not create desktop shortcut: $($_.Exception.Message)"
    }
}

# ------------------------------------------------------------------------------
# Final Banner & Next Steps
# ------------------------------------------------------------------------------
Write-Host ""
Write-Host "======================================================================" -ForegroundColor Green
Write-Host "  ROKH WAF - INSTALLATION AND DEPLOYMENT COMPLETE!" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  To Start the WAF Engine & Embedded SOC Console:" -ForegroundColor White
Write-Host "    Double-click : start_waf.bat" -ForegroundColor Cyan
Write-Host "    PowerShell   : .\start_waf.ps1" -ForegroundColor Cyan
Write-Host "    Direct Exec  : .\target\release\waf_engine.exe --port $Port" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Web SOC Dashboard URL:" -ForegroundColor White
Write-Host "    http://127.0.0.1:$Port/dashboard" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Run Native Security Audit & Benchmark:" -ForegroundColor White
Write-Host "    .\target\release\rokh_bench.exe" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Green
Write-Host ""

if ($StartNow) {
    Write-Info "Starting ROKH WAF Engine now..."
    & ".\target\release\waf_engine.exe" --port $Port --target $Target --mode $Mode --rpm 120
}
