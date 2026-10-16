#!/usr/bin/env bash
# ==============================================================================
# ROKH WAF (دیواره آتش رُخ) - Easy Installer for Linux & macOS
# Author: Taha Vaziri (طاها وزیری)
# ==============================================================================

set -e

echo ""
echo "======================================================================"
echo " 🛡️  ROKH WAF (دیواره آتش رُخ) - Automated Installation Protocol"
echo "     توسعه‌دهنده: طاها وزیری (Taha Vaziri)"
echo "======================================================================"
echo ""

# 1. Check Python
echo "[1/4] Checking Python Environment..."
if command -v python3 &>/dev/null; then
    echo "  [+] Python Detected: $(python3 --version)"
    PY_CMD="python3"
elif command -v python &>/dev/null; then
    echo "  [+] Python Detected: $(python --version)"
    PY_CMD="python"
else
    echo "  [-] Error: Python is not installed. Please install python3."
    exit 1
fi

# 2. Check Cargo
echo ""
echo "[2/4] Checking Rust & Cargo Toolchain..."
if command -v cargo &>/dev/null; then
    echo "  [+] Cargo Detected: $(cargo --version)"
else
    echo "  [-] Error: Cargo is not installed. Install via: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

# 3. Install Python Dependencies
echo ""
echo "[3/4] Installing Python Requirements..."
$PY_CMD -m pip install --upgrade pip --quiet || true
$PY_CMD -m pip install -r requirements.txt --quiet
echo "  [+] Python dependencies satisfied."

# 4. Compile Rust Engine
echo ""
echo "[4/4] Compiling Rust WAF Core Proxy in Release Mode..."
cargo build --release
echo "  [+] Rust WAF Engine compiled: target/release/waf_engine"

echo ""
echo "======================================================================"
echo " 🎉 INSTALLATION COMPLETED SUCCESSFULLY!"
echo "======================================================================"
echo " You can now launch and configure ROKH WAF using:"
echo "   python start_waf.py"
echo " or:"
echo "   ./target/release/waf_engine --target http://127.0.0.1:3000"
echo "======================================================================"
echo ""
