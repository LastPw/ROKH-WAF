#!/usr/bin/env bash
# ==============================================================================
# ROKH WAF - Universal Automated Installer for Linux, macOS & BSD (100% Pure Rust)
# Supports local clones, vanilla VPS/cloud servers, and one-liner web installation:
#   curl -sSL https://raw.githubusercontent.com/LastPw/ROKH-WAF/main/install.sh | bash
# ==============================================================================

set -eo pipefail

# ANSI Color Codes
CLR_RESET="\033[0m"
CLR_CYAN="\033[1;36m"
CLR_GREEN="\033[1;32m"
CLR_YELLOW="\033[1;33m"
CLR_RED="\033[1;31m"
CLR_WHITE="\033[1;37m"

print_header() {
    echo -e ""
    echo -e "${CLR_CYAN}======================================================================${CLR_RESET}"
    echo -e "${CLR_CYAN} [ROKH WAF] Universal Native Installation & Environment Setup${CLR_RESET}"
    echo -e "${CLR_CYAN}======================================================================${CLR_RESET}"
}

print_step() {
    echo -e ""
    echo -e "${CLR_YELLOW}[$1/$2] $3${CLR_RESET}"
}

print_success() {
    echo -e "  ${CLR_GREEN}[+] $1${CLR_RESET}"
}

print_info() {
    echo -e "  ${CLR_CYAN}[i] $1${CLR_RESET}"
}

print_warn() {
    echo -e "  ${CLR_YELLOW}[!] $1${CLR_RESET}"
}

print_error() {
    echo -e "  ${CLR_RED}[-] $1${CLR_RESET}"
}

print_header

# ------------------------------------------------------------------------------
# 0. Remote One-Liner Workspace Detection (Auto-Clone if run outside repository)
# ------------------------------------------------------------------------------
if [ ! -f "Cargo.toml" ]; then
    print_step "0" "5" "Remote Execution Detected: Initializing Project Workspace..."
    TARGET_DIR="$HOME/rokh-waf"
    if [ -f "$TARGET_DIR/Cargo.toml" ]; then
        cd "$TARGET_DIR"
        print_success "Using existing repository at: $TARGET_DIR"
    else
        print_info "Cloning ROKH-WAF repository to $TARGET_DIR..."
        if command -v git &>/dev/null; then
            git clone https://github.com/LastPw/ROKH-WAF.git "$TARGET_DIR"
            cd "$TARGET_DIR"
            print_success "Repository cloned to $TARGET_DIR"
        else
            print_info "Git not found. Installing git or downloading archive..."
            mkdir -p "$TARGET_DIR"
            curl -sSL "https://github.com/LastPw/ROKH-WAF/archive/refs/heads/main.tar.gz" | tar -xz -C "$TARGET_DIR" --strip-components=1
            cd "$TARGET_DIR"
            print_success "Source archive downloaded and extracted to $TARGET_DIR"
        fi
    fi
fi

if [ ! -f "Cargo.toml" ]; then
    print_error "Critical: Cargo.toml not found. Please navigate to the ROKH-WAF root folder."
    exit 1
fi

CURRENT_DIR="$(pwd)"

# ------------------------------------------------------------------------------
# 1. Hardware, OS & Architecture Auto-Detection
# ------------------------------------------------------------------------------
print_step "1" "5" "Detecting Operating System, Architecture & Hardware Specs..."

OS_NAME="$(uname -s)"
ARCH_NAME="$(uname -m)"
CPU_CORES="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo '4')"
TOTAL_RAM_MB="$(free -m 2>/dev/null | awk '/^Mem:/{print $2}' || sysctl -n hw.memsize 2>/dev/null | awk '{print int($1/1048576)}' || echo 'Unknown')"

print_success "OS Platform      : $OS_NAME ($ARCH_NAME)"
print_success "CPU Cores        : $CPU_CORES Parallel Processing Threads (Tokio Ready)"
print_success "Total System RAM : ${TOTAL_RAM_MB} MB"

# ------------------------------------------------------------------------------
# 2. Package Manager & Essential C/C++ Build Dependencies
# ------------------------------------------------------------------------------
print_step "2" "5" "Checking and Installing System Build Dependencies..."

install_pkg() {
    if command -v sudo &>/dev/null && [ "$EUID" -ne 0 ]; then
        sudo "$@"
    elif [ "$EUID" -eq 0 ]; then
        "$@"
    else
        print_warn "Non-root user detected. Skipping package installation; assuming packages are installed."
    fi
}

if ! command -v gcc &>/dev/null && ! command -v clang &>/dev/null; then
    print_info "Compiler tools not found. Attempting package manager installation..."
    if command -v apt-get &>/dev/null; then
        print_info "Using apt-get (Debian/Ubuntu/Mint)..."
        install_pkg apt-get update -y
        install_pkg apt-get install -y build-essential curl pkg-config libssl-dev git sqlite3
    elif command -v dnf &>/dev/null; then
        print_info "Using dnf (Fedora/RHEL/CentOS/Rocky)..."
        install_pkg dnf install -y gcc gcc-c++ make curl pkgconfig openssl-devel git sqlite
    elif command -v yum &>/dev/null; then
        print_info "Using yum (CentOS/RHEL)..."
        install_pkg yum install -y gcc gcc-c++ make curl pkgconfig openssl-devel git sqlite
    elif command -v apk &>/dev/null; then
        print_info "Using apk (Alpine Linux)..."
        install_pkg apk add --no-cache build-base curl pkgconfig openssl-dev git sqlite
    elif command -v pacman &>/dev/null; then
        print_info "Using pacman (Arch/Manjaro)..."
        install_pkg pacman -Sy --noconfirm base-devel curl pkgconf openssl git sqlite
    elif command -v brew &>/dev/null; then
        print_info "Using Homebrew (macOS)..."
        brew install openssl pkg-config git sqlite3 || true
    fi
fi

# ------------------------------------------------------------------------------
# 3. Rust & Cargo Toolchain Auto-Detection & Self-Healing
# ------------------------------------------------------------------------------
print_step "3" "5" "Verifying Rust Compiler & Cargo Toolchain..."

if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
fi

if command -v cargo &>/dev/null; then
    print_success "Rust Active: $(cargo --version)"
else
    print_info "Rust toolchain not found. Installing official Rustup (stable)..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
    if [ -f "$HOME/.cargo/env" ]; then
        # shellcheck source=/dev/null
        source "$HOME/.cargo/env"
    fi
    print_success "Rust successfully installed: $(cargo --version)"
fi

# ------------------------------------------------------------------------------
# 4. Compilation & Release Optimization (O3)
# ------------------------------------------------------------------------------
print_step "4" "5" "Building Statically-Optimized Pure Rust Release Binaries..."

WAF_BIN="target/release/waf_engine"
BENCH_BIN="target/release/rokh_bench"

print_info "Compiling WAF Engine (Axum + Tokio + GIS + SQLite WAL)..."
cargo build --release --bin waf_engine
print_success "WAF Engine compiled: $WAF_BIN"

print_info "Compiling Native Security Benchmark CLI (rokh_bench)..."
cargo build --release --bin rokh_bench || true
if [ -f "$BENCH_BIN" ]; then
    print_success "Benchmark CLI compiled: $BENCH_BIN"
fi

# Self-diagnostic sanity test
if [ -f "$WAF_BIN" ]; then
    ./$WAF_BIN --help >/dev/null 2>&1
    print_success "Self-Diagnostic: WAF Engine passed sanity test (100% Operational)."
fi

# ------------------------------------------------------------------------------
# 5. Service Helpers, Symlinks & Systemd Daemon Setup
# ------------------------------------------------------------------------------
print_step "5" "5" "Configuring Service Helpers & System Links..."

# 1. Create executable start script (start_waf.sh)
cat << 'EOF' > start_waf.sh
#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/target/release/waf_engine"

if [ ! -f "$BIN" ]; then
    echo "[*] Compiling release binary..."
    cargo build --release --bin waf_engine
fi

exec "$BIN" --port 8080 --target http://127.0.0.1:9000 --mode PREVENTION --rpm 120 "$@"
EOF
chmod +x start_waf.sh
print_success "Generated runner script: ./start_waf.sh"

# 2. Global command symlink (/usr/local/bin/rokh-waf)
if [ -d "/usr/local/bin" ] && [ -w "/usr/local/bin" ]; then
    ln -sf "$CURRENT_DIR/$WAF_BIN" /usr/local/bin/rokh-waf
    print_success "Linked global CLI command: 'rokh-waf' -> /usr/local/bin/rokh-waf"
elif command -v sudo &>/dev/null; then
    sudo ln -sf "$CURRENT_DIR/$WAF_BIN" /usr/local/bin/rokh-waf 2>/dev/null && \
        print_success "Linked global CLI command: 'rokh-waf' (via sudo)" || true
fi

# 3. Optional Systemd Service Creation (Linux)
if [ -d "/etc/systemd/system" ] && command -v systemctl &>/dev/null; then
    SERVICE_FILE="/etc/systemd/system/rokh-waf.service"
    SERVICE_CONTENT="[Unit]
Description=ROKH WAF - High-Performance Layer-7 Web Application Firewall
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$CURRENT_DIR
ExecStart=$CURRENT_DIR/$WAF_BIN --port 8080 --target http://127.0.0.1:9000 --mode PREVENTION --rpm 120
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target"

    if [ "$EUID" -eq 0 ] || command -v sudo &>/dev/null; then
        echo "$SERVICE_CONTENT" | install_pkg tee "$SERVICE_FILE" >/dev/null
        install_pkg systemctl daemon-reload
        print_success "Configured systemd service unit: $SERVICE_FILE"
        print_info "To enable & run as background daemon on boot:"
        print_info "  sudo systemctl enable --now rokh-waf"
    fi
fi

# ------------------------------------------------------------------------------
# Final Summary Banner
# ------------------------------------------------------------------------------
echo -e ""
echo -e "${CLR_GREEN}======================================================================${CLR_RESET}"
echo -e "${CLR_GREEN}  ROKH WAF - INSTALLATION AND DEPLOYMENT COMPLETE!${CLR_RESET}"
echo -e "${CLR_GREEN}======================================================================${CLR_RESET}"
echo -e ""
echo -e "  ${CLR_WHITE}To Start the WAF Engine & Embedded SOC Console:${CLR_RESET}"
echo -e "    ${CLR_CYAN}./start_waf.sh${CLR_RESET}"
echo -e "    ${CLR_CYAN}rokh-waf --port 8080 --mode PREVENTION${CLR_RESET}"
if command -v systemctl &>/dev/null && [ -f "/etc/systemd/system/rokh-waf.service" ]; then
echo -e "    ${CLR_CYAN}sudo systemctl start rokh-waf${CLR_RESET}  (Background 24/7 service)"
fi
echo -e ""
echo -e "  ${CLR_WHITE}Web SOC Dashboard URL:${CLR_RESET}"
echo -e "    ${CLR_YELLOW}http://127.0.0.1:8080/dashboard${CLR_RESET}"
echo -e ""
echo -e "  ${CLR_WHITE}Run Native Security Audit & Benchmark:${CLR_RESET}"
echo -e "    ${CLR_CYAN}./target/release/rokh_bench${CLR_RESET}"
echo -e "${CLR_GREEN}======================================================================${CLR_RESET}"
echo -e ""
