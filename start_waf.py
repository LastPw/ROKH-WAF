#!/usr/bin/env python3
# ==============================================================================
# ROKH WAF - Smart Launcher & Target Configurator
# ==============================================================================

import os
import sys
import time
import signal
import argparse
import subprocess
import urllib.request
import urllib.error

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

def print_banner():
    banner = """
======================================================================
 [ROKH WAF] Advanced Layer-7 Reverse Proxy & Anti-DDoS Defense System
 Core Engine: Tokio Async Event-Loop | AI: Shannon Entropy Engine
======================================================================
"""
    print(banner)

def find_or_build_waf_binary():
    is_win = sys.platform == "win32"
    bin_name = "waf_engine.exe" if is_win else "waf_engine"
    rel_path = os.path.join(BASE_DIR, "target", "release", bin_name)
    dev_path = os.path.join(BASE_DIR, "target", "debug", bin_name)

    if os.path.exists(rel_path):
        return rel_path
    if os.path.exists(dev_path):
        return dev_path

    print(" [*] WAF binary not found. Compiling release binary with Cargo...")
    res = subprocess.run(["cargo", "build", "--release"], cwd=BASE_DIR)
    if res.returncode != 0:
        print(" [-] Error compiling Rust WAF core engine.")
        sys.exit(1)
    return rel_path

sys.path.insert(0, BASE_DIR)
try:
    from scripts.discover_services import scan_all_web_services
except ImportError:
    scan_all_web_services = None

def check_target_reachability(url):
    print(f" [*] Probing target server reachability ({url})...", end=" ", flush=True)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "RokhWAF-HealthProbe/1.0"})
        with urllib.request.urlopen(req, timeout=2) as resp:
            print(f"[OK: HTTP {resp.status}]")
            return True
    except urllib.error.HTTPError as e:
        print(f"[Target Responded: HTTP {e.code}]")
        return True
    except Exception:
        print("[Notice: Target offline or warming up - WAF will route traffic once live]")
        return False

def interactive_wizard():
    print("======================================================================")
    print(" [AUTO-DISCOVERY] Scanning Local Web Servers & Active Services")
    print("======================================================================")
    print(" [*] Inspecting active ports and web processes (Nginx, Apache, IIS, Node, Python)...", flush=True)

    services = []
    if scan_all_web_services:
        try:
            services = scan_all_web_services(exclude_ports=[8080])
        except Exception:
            pass

    target_url = "http://127.0.0.1:9000"

    if services:
        print(f"\n [+] Detected {len(services)} active web service(s) on localhost:\n")
        for idx, s in enumerate(services, 1):
            title_part = f" | Title: {s['title']}" if s.get('title') else ""
            print(f"  [{idx}] {s['service_type']}")
            print(f"      URL     : {s['url']}")
            print(f"      Server  : {s['server_banner']}{title_part}")
            print(f"      Process : {s['process_name']} (PID: {s['pid']})")
            print(f"      Status  : Online (HTTP {s['status_code']})")
            print("")

        print("  [A] Protect ALL (Select primary web gateway / all virtual hosts)")
        print("  [M] Manual Entry (Specify a custom URL)\n")

        sel = input(f" Select target service [1-{len(services)}, A for ALL, M for Manual] (Default: 1): ").strip().upper()

        if sel in ["A", "ALL"]:
            # Prefer standard gateway ports (80 or 443) if present
            gateway = next((s for s in services if s["port"] in [80, 443]), None)
            if gateway:
                target_url = gateway["url"]
                print(f" [+] Primary Web Gateway ({gateway['service_type']}) selected: {target_url}")
            else:
                target_url = services[0]["url"]
                print(f" [+] All services registered. Primary gateway set to: {target_url}")
        elif sel.isdigit() and 1 <= int(sel) <= len(services):
            target_url = services[int(sel) - 1]["url"]
            print(f" [+] Selected service: {target_url}")
        elif sel == "M" or sel.startswith("HTTP"):
            if sel.startswith("HTTP"):
                target_url = sel
            else:
                raw_target = input("     Target backend URL [Default: http://127.0.0.1:9000]: ").strip()
                target_url = raw_target if raw_target else "http://127.0.0.1:9000"
        else:
            target_url = services[0]["url"]
            print(f" [+] Defaulting to service [1]: {target_url}")
    else:
        print(" [i] No running HTTP web services automatically detected.")
        raw_target = input("     Target backend URL [Default: http://127.0.0.1:9000]: ").strip()
        target_url = raw_target if raw_target else "http://127.0.0.1:9000"

    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "http://" + target_url

    check_target_reachability(target_url)

    # 2. WAF Listen Port
    default_port = 8080
    print(f"\n [2] WAF Proxy Listen Port (Public Network Ingress):")
    raw_port = input(f"     [Default: {default_port}]: ").strip()
    try:
        waf_port = int(raw_port) if raw_port else default_port
    except ValueError:
        waf_port = default_port

    # 3. Security Mode
    print(f"\n [3] Operational Defense Mode:")
    print(f"     [1] PREVENTION - Active mitigation with HTTP 403 Forbidden [Recommended]")
    print(f"     [2] DETECTION  - Monitor mode (Pass traffic and record security logs)")
    raw_mode = input("     Select mode [1/2, Default: 1]: ").strip()
    waf_mode = "DETECTION" if raw_mode == "2" else "PREVENTION"

    # 4. Rate Limiting
    default_rpm = 60
    print(f"\n [4] Rate Limit Threshold (Requests per minute per client IP):")
    raw_rpm = input(f"     [Default: {default_rpm} req/min]: ").strip()
    try:
        rate_limit = int(raw_rpm) if raw_rpm else default_rpm
    except ValueError:
        rate_limit = default_rpm

    # 5. SOC Dashboard
    launch_soc = True

    return {
        "target_url": target_url,
        "waf_port": waf_port,
        "waf_mode": waf_mode,
        "rate_limit": rate_limit,
        "launch_soc": launch_soc,
    }

def main():
    parser = argparse.ArgumentParser(description="ROKH WAF - Smart Launcher (Pure Native Rust)")
    parser.add_argument("--target", "-t", type=str, help="Target backend service to protect")
    parser.add_argument("--port", "-p", type=int, default=None, help="WAF Proxy listen port")
    parser.add_argument("--mode", "-m", type=str, choices=["PREVENTION", "DETECTION"], help="Security mode")
    parser.add_argument("--rpm", type=int, help="Rate limit per minute per IP")
    args = parser.parse_args()

    print_banner()

    if args.target:
        cfg = {
            "target_url": args.target if args.target.startswith("http") else f"http://{args.target}",
            "waf_port": args.port or 8080,
            "waf_mode": args.mode or "PREVENTION",
            "rate_limit": args.rpm or 60,
            "launch_soc": True,
        }
    else:
        cfg = interactive_wizard()

    waf_binary = find_or_build_waf_binary()

    procs = []

    def shutdown(signum=None, frame=None):
        print("\n\n [*] Gracefully shutting down ROKH WAF services...")
        for p in procs:
            try:
                p.terminate()
                p.wait(timeout=2)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        print(" [+] All services stopped. Shutdown complete.")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, shutdown)

    # Start Rust WAF Engine (SOC Dashboard & Mock Target are built directly in pure Rust!)
    print(f" [*] Launching Native Rust WAF Core (Port {cfg['waf_port']}) -> Routing to {cfg['target_url']}...")
    waf_cmd = [
        waf_binary,
        "--target", cfg["target_url"],
        "--port", str(cfg["waf_port"]),
        "--mode", cfg["waf_mode"],
        "--rpm", str(cfg["rate_limit"]),
    ]
    waf_proc = subprocess.Popen(waf_cmd, cwd=BASE_DIR)
    procs.append(waf_proc)
    time.sleep(1.0)

    print("\n" + "=" * 70)
    print(" [ONLINE] ROKH WAF IS ACTIVELY PROTECTING YOUR SERVICES (100% PURE RUST)!")
    print("=" * 70)
    print(f" Target Backend Server     : {cfg['target_url']}")
    print(f" WAF Proxy Ingress         : http://127.0.0.1:{cfg['waf_port']}")
    print(f" Embedded SOC Dashboard    : http://127.0.0.1:{cfg['waf_port']}/dashboard")
    print(f" Built-in Mock Target Demo : http://127.0.0.1:{cfg['waf_port']}/target/search")
    print(f" Security Benchmark Tool   : cargo run --bin rokh_bench --release")
    print(f" Operational Mode          : {cfg['waf_mode']}")
    print(f" Anti-DDoS Rate Limit      : {cfg['rate_limit']} req/min per IP")
    print("=" * 70)
    print(" Press Ctrl+C at any time to stop the firewall.")
    print("=" * 70 + "\n")

    try:
        waf_proc.wait()
    except KeyboardInterrupt:
        shutdown()

if __name__ == "__main__":
    main()
