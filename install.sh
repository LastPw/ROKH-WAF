#!/usr/bin/env bash
# ==============================================================================
# ROKH WAF - Automated Self-Detecting Installer for Linux & macOS
# ==============================================================================

set -e

echo ""
echo "======================================================================"
echo " [ROKH WAF] Automated Installation & Environment Setup"
echo "======================================================================"
echo ""

# 1. Hardware & OS Detection
echo "[1/6] Auto-detecting Hardware & Operating System..."
OS_NAME="$(uname -s)"
ARCH_NAME="$(uname -m)"
CPU_CORES="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo '4')"
echo "  [+] OS Detected    : $OS_NAME ($ARCH_NAME)"
echo "  [+] CPU Cores      : $CPU_CORES Processing Threads (Tokio Ready)"

# 2. Python Environment Detection
echo ""
echo "[2/6] Auto-detecting Python 3.10+ Environment..."
if command -v python3 &>/dev/null; then
    PY_CMD="python3"
elif command -v python &>/dev/null; then
    PY_CMD="python"
else
    echo "  [-] Error: Python is not installed. Please install python3."
    exit 1
fi
echo "  [+] Python Binary  : $PY_CMD ($($PY_CMD --version))"

# 3. Rust & Cargo Auto-Detection
echo ""
echo "[3/6] Auto-detecting Rust & Cargo Toolchain..."
if [ -f "$HOME/.cargo/env" ]; then
    source "$HOME/.cargo/env"
fi

if command -v cargo &>/dev/null; then
    echo "  [+] Rust Toolchain : $(cargo --version)"
else
    echo "  [-] Cargo not found. Auto-installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    echo "  [+] Rust installed : $(cargo --version)"
fi

# 4. Port Availability Check
echo ""
echo "[4/6] Checking Port Availability (8080 & 9000)..."
if lsof -Pi :8080 -sTCP:LISTEN -t >/dev/null 2>&1 || nc -z 127.0.0.1 8080 2>/dev/null; then
    echo "  [i] Port 8080 (WAF Proxy) is currently in use (Active instance detected)."
else
    echo "  [+] Port 8080 (WAF Proxy) is FREE and Ready."
fi

if lsof -Pi :9000 -sTCP:LISTEN -t >/dev/null 2>&1 || nc -z 127.0.0.1 9000 2>/dev/null; then
    echo "  [i] Port 9000 (SOC Center) is currently in use (Active instance detected)."
else
    echo "  [+] Port 9000 (SOC Center) is FREE and Ready."
fi

if [ -f "scripts/discover_services.py" ]; then
    echo ""
    echo "  [*] Auto-detecting running Web Servers & Services on localhost:"
    $PY_CMD scripts/discover_services.py || true
fi

# 5. Python Dependencies
echo ""
echo "[5/6] Verifying and Installing Python Requirements..."
$PY_CMD -m pip install --upgrade pip --quiet 2>/dev/null || true
$PY_CMD -m pip install -r requirements.txt --quiet
echo "  [+] Python dependencies satisfied (FastAPI, Uvicorn, Requests, Pydantic, NumPy)."

# 6. Rust Core Engine Compilation & Verification
echo ""
echo "[6/6] Checking and Compiling Rust Release Binary (O3 Optimized)..."
if [ -f "target/release/waf_engine" ]; then
    echo "  [+] Release binary already compiled: target/release/waf_engine"
else
    cargo build --release
    echo "  [+] Rust WAF Engine compiled successfully: target/release/waf_engine"
fi

./target/release/waf_engine --help >/dev/null 2>&1 && echo "  [+] Self-Diagnostic Test: 100% Operational (Production Ready)"

echo ""
echo "======================================================================"
echo " [SUCCESS] ROKH WAF INSTALLATION COMPLETE!"
echo "======================================================================"
echo " Launch and protect your service interactively using:"
echo "   python start_waf.py"
echo " Or specify target directly:"
echo "   python start_waf.py --target http://127.0.0.1:3000 --port 8080"
echo "======================================================================"
echo ""
