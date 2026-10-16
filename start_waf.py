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
 🛡️  ROKH WAF (دیواره آتش رُخ) - سامانه راه‌اندازی و مدیریت حفاظت
     هسته: Rust Tokio Zero-Copy · هوش مصنوعی: Shannon Entropy AI
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

    print(" [*] باینری WAF کامپایل نشده است. در حال کامپایل خودکار با Cargo...")
    res = subprocess.run(["cargo", "build", "--release"], cwd=BASE_DIR)
    if res.returncode != 0:
        print(" [-] خطا در کامپایل هسته Rust WAF.")
        sys.exit(1)
    return rel_path

def check_target_reachability(url):
    print(f" [*] در حال بررسی در دسترس بودن سرور مقصد ({url})...", end=" ", flush=True)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "RokhWAF-HealthProbe/1.0"})
        with urllib.request.urlopen(req, timeout=2) as resp:
            print(f"[OK: کد وضعیت {resp.status}]")
            return True
    except urllib.error.HTTPError as e:
        print(f"[پاسخ دریافت شد: کد {e.code}]")
        return True
    except Exception as e:
        print("[توجه: سرور مقصد هنوز روشن نیست، فایروال به محض بالا آمدن آن ترافیک را هدایت خواهد کرد]")
        return False

def interactive_wizard():
    print(" لطفاً پارامترهای حفاظتی سرویس خود را مشخص کنید:\n")

    # 1. Target Backend URL
    default_target = "http://127.0.0.1:9000"
    print(f" [1] آدرس سرور یا وب‌سایتی که می‌خواهید فایروال از آن محافظت کند:")
    print(f"     (مثال: http://localhost:3000 یا http://127.0.0.1:8000)")
    raw_target = input(f"     [پیش‌فرض: {default_target}]: ").strip()
    target_url = raw_target if raw_target else default_target
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "http://" + target_url

    # Check reachability
    check_target_reachability(target_url)

    # 2. WAF Listen Port
    default_port = 8080
    print(f"\n [2] پورت شنود پروکسی فایروال (ورودی کاربر و ترافیک شبکه):")
    raw_port = input(f"     [پیش‌فرض: {default_port}]: ").strip()
    try:
        waf_port = int(raw_port) if raw_port else default_port
    except ValueError:
        waf_port = default_port

    # 3. Security Mode
    print(f"\n [3] حالت عملیاتی فایروال رُخ:")
    print(f"     [1] حالت مسدودسازی کامل (PREVENTION - خنثی‌سازی حملات با 403 Forbidden) [توصیه‌شده]")
    print(f"     [2] حالت پایش و ثبت (DETECTION - عبور ترافیک و ثبت لاگ امنیتی)")
    raw_mode = input("     انتخاب شما [1/2, پیش‌فرض: 1]: ").strip()
    waf_mode = "DETECTION" if raw_mode == "2" else "PREVENTION"

    # 4. Rate Limiting
    default_rpm = 60
    print(f"\n [4] سقف مجاز درخواست در دقیقه برای هر آی‌پی (کنترل نرخ و ضد دیداس):")
    raw_rpm = input(f"     [پیش‌فرض: {default_rpm} req/min]: ").strip()
    try:
        rate_limit = int(raw_rpm) if raw_rpm else default_rpm
    except ValueError:
        rate_limit = default_rpm

    # 5. SOC Dashboard
    # If target is on port 9000 and is the built-in target, SOC is already part of it
    launch_soc = True
    soc_port = 9000
    if ":9000" in target_url:
        print("\n [5] مقصد شامل سرور SOC پورت 9000 است؛ داشبورد همزمان فعال خواهد بود.")
    else:
        print(f"\n [5] آیا مایلید داشبورد عملیات امنیت (SOC Dashboard) نیز فعال شود؟")
        raw_soc = input("     [Y/n, پیش‌فرض: Y]: ").strip().lower()
        launch_soc = False if raw_soc == "n" else True
        if launch_soc:
            soc_port = 9000
            if waf_port == 9000:
                soc_port = 9090

    return {
        "target_url": target_url,
        "waf_port": waf_port,
        "waf_mode": waf_mode,
        "rate_limit": rate_limit,
        "launch_soc": launch_soc,
        "soc_port": soc_port,
    }

def main():
    parser = argparse.ArgumentParser(description="ROKH WAF - Smart Launcher")
    parser.add_argument("--target", "-t", type=str, help="Target backend service to protect")
    parser.add_argument("--port", "-p", type=int, default=None, help="WAF Proxy listen port")
    parser.add_argument("--mode", "-m", type=str, choices=["PREVENTION", "DETECTION"], help="Security mode")
    parser.add_argument("--rpm", type=int, help="Rate limit per minute per IP")
    parser.add_argument("--no-soc", action="store_true", help="Do not launch SOC Dashboard")
    args = parser.parse_args()

    print_banner()

    if args.target:
        cfg = {
            "target_url": args.target if args.target.startswith("http") else f"http://{args.target}",
            "waf_port": args.port or 8080,
            "waf_mode": args.mode or "PREVENTION",
            "rate_limit": args.rpm or 60,
            "launch_soc": not args.no_soc,
            "soc_port": 9000 if (args.port or 8080) != 9000 else 9090,
        }
    else:
        cfg = interactive_wizard()

    waf_binary = find_or_build_waf_binary()

    procs = []

    def shutdown(signum=None, frame=None):
        print("\n\n [*] در حال متوقف‌سازی و خروج امن از دیواره آتش رُخ...")
        for p in procs:
            try:
                p.terminate()
                p.wait(timeout=2)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        print(" [+] تمامی سرویس‌ها خاموش شدند. خدانگهدار!")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, shutdown)

    # 1. Start Python SOC Dashboard if requested
    if cfg["launch_soc"]:
        print(f"\n [1/2] در حال راه‌اندازی مرکز عملیات امنیت (SOC Dashboard) روی پورت {cfg['soc_port']}...")
        env = os.environ.copy()
        soc_cmd = [sys.executable, "-m", "uvicorn", "python_soc.app:app", "--host", "127.0.0.1", "--port", str(cfg["soc_port"]), "--log-level", "warning"]
        soc_proc = subprocess.Popen(soc_cmd, cwd=BASE_DIR)
        procs.append(soc_proc)
        time.sleep(1.5)

    # 2. Start Rust WAF Engine
    print(f" [2/2] در حال راه‌اندازی هسته قدرتمند Rust WAF (پورت {cfg['waf_port']}) به سوی مقصد {cfg['target_url']}...")
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
    print(" ✅ دیواره آتش رُخ (ROKH WAF) با موفقیت فعال و مستقر شد!")
    print("=" * 70)
    print(f" 🎯 سرور تحت حفاظت (Backend Server) : {cfg['target_url']}")
    print(f" 🛡️  ورودی پروکسی فایروال (WAF Proxy) : http://127.0.0.1:{cfg['waf_port']}")
    if cfg["launch_soc"]:
        print(f" 📊 داشبورد رصد رویدادها (SOC Center)  : http://127.0.0.1:{cfg['soc_port']}")
    print(f" 🔒 وضعیت دفاعی (Security Mode)      : {cfg['waf_mode']}")
    print(f" ⚡ سقف نرخ مجاز (Rate Limiter)      : {cfg['rate_limit']} req/min per IP")
    print("=" * 70)
    print(" برای توقف فایروال، کلیدهای Ctrl+C را فشار دهید.")
    print("=" * 70 + "\n")

    try:
        waf_proc.wait()
    except KeyboardInterrupt:
        shutdown()

if __name__ == "__main__":
    main()
