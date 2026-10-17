#!/usr/bin/env bash
# ==============================================================================
# ROKH WAF - Linux / macOS Launcher
# ==============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BIN="./target/release/waf_engine"

if [[ ! -f "$BIN" ]]; then
    echo "[*] Binary not found. Building release binary..."
    cargo build --release --bin waf_engine
fi

echo "[*] Starting ROKH WAF Enterprise Engine..."
exec "$BIN" "$@"
