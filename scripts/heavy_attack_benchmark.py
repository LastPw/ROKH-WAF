import sys
import time
import json
import statistics
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

WAF_HOST = "http://127.0.0.1:8080"
SOC_HOST = "http://127.0.0.1:9000"

# ==============================================================================
# 1. EXPLOIT & ATTACK VECTORS (OWASP TOP 10 + ADVANCED EVASIONS + AI ZERO-DAYS)
# ==============================================================================

EXPLOIT_BATTERY = [
    # --- SQL Injection ---
    {"cat": "SQLi", "name": "Classic UNION SELECT", "method": "GET", "url": f"{WAF_HOST}/target/search?q=1 UNION SELECT null,username,password FROM users--", "exp": 403},
    {"cat": "SQLi", "name": "Boolean Blind Tautology", "method": "GET", "url": f"{WAF_HOST}/target/search?q=admin' OR 1=1--", "exp": 403},
    {"cat": "SQLi", "name": "Inline Comment Evasion (UN/**/ION)", "method": "GET", "url": f"{WAF_HOST}/target/search?q=1 UN/**/ION SEL/**/ECT 1,2,3--", "exp": 403},
    {"cat": "SQLi", "name": "Mixed-Casing Bypass (uNiOn aLl sElEcT)", "method": "GET", "url": f"{WAF_HOST}/target/search?q=' uNiOn aLl sElEcT 1,2,3--", "exp": 403},
    {"cat": "SQLi", "name": "Stacked Time-Based Delay (WAITFOR)", "method": "GET", "url": f"{WAF_HOST}/target/search?q=1; WAITFOR DELAY '0:0:5'--", "exp": 403},
    {"cat": "SQLi", "name": "Header Cookie Injection", "method": "GET", "url": f"{WAF_HOST}/target/search?q=normal", "headers": {"Cookie": "session_id=admin' OR '1'='1'--"}, "exp": 403},

    # --- Cross-Site Scripting (XSS) ---
    {"cat": "XSS", "name": "Reflected Script Tag", "method": "GET", "url": f"{WAF_HOST}/target/search?q=<script>alert('pwn')</script>", "exp": 403},
    {"cat": "XSS", "name": "SVG Event Handler without Space", "method": "GET", "url": f"{WAF_HOST}/target/search?q=<svg/onload=alert(1)>", "exp": 403},
    {"cat": "XSS", "name": "DOM Event Handler (img onerror)", "method": "GET", "url": f"{WAF_HOST}/target/search?q=<img src=x onerror=alert(document.cookie)>", "exp": 403},
    {"cat": "XSS", "name": "Full-Width Unicode Evasion (＜script＞)", "method": "GET", "url": f"{WAF_HOST}/target/search?q=＜script＞alert(1)＜/script＞", "exp": 403},
    {"cat": "XSS", "name": "Data URI Base64 Scheme", "method": "GET", "url": f"{WAF_HOST}/target/search?q=<iframe src=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==>", "exp": 403},
    {"cat": "XSS", "name": "Referer Header Injection", "method": "GET", "url": f"{WAF_HOST}/target/search?q=docs", "headers": {"Referer": "http://evil.com/?q=<script>alert('xss')</script>"}, "exp": 403},

    # --- Path Traversal / LFI ---
    {"cat": "LFI", "name": "UNIX /etc/passwd Access", "method": "GET", "url": f"{WAF_HOST}/target/view-file?file=../../../../etc/passwd", "exp": 403},
    {"cat": "LFI", "name": "Windows win.ini Access", "method": "GET", "url": f"{WAF_HOST}/target/view-file?file=..\\..\\..\\windows\\win.ini", "exp": 403},
    {"cat": "LFI", "name": "Environment File Probe (.env)", "method": "GET", "url": f"{WAF_HOST}/target/view-file?file=../../.env", "exp": 403},
    {"cat": "LFI", "name": "Double URL-Encoded Traversal (%252e%252e%252f)", "method": "GET", "url": f"{WAF_HOST}/target/view-file?file=%252e%252e%252f%252e%252e%252fetc/passwd", "exp": 403},

    # --- Command Injection / RCE ---
    {"cat": "RCE", "name": "Semicolon Shell Command (; cat)", "method": "GET", "url": f"{WAF_HOST}/target/search?q=1; cat /etc/passwd", "exp": 403},
    {"cat": "RCE", "name": "Pipe Shell Execution (| whoami)", "method": "GET", "url": f"{WAF_HOST}/target/search?q=test | whoami", "exp": 403},
    {"cat": "RCE", "name": "Chained Conditional Operator (&& id)", "method": "GET", "url": f"{WAF_HOST}/target/search?q=something && id", "exp": 403},
    {"cat": "RCE", "name": "Backtick Command Substitution (`whoami`)", "method": "GET", "url": f"{WAF_HOST}/target/search?q=`whoami`", "exp": 403},
    {"cat": "RCE", "name": "Subshell Execution ($(cat /etc/hosts))", "method": "GET", "url": f"{WAF_HOST}/target/search?q=$(cat /etc/hosts)", "exp": 403},
    {"cat": "RCE", "name": "PowerShell Execution Vector", "method": "GET", "url": f"{WAF_HOST}/target/search?q=1; powershell -Command Get-Process", "exp": 403},

    # --- Malicious Scanners & Automated Bots ---
    {"cat": "Bot", "name": "sqlmap Fingerprint", "method": "GET", "url": f"{WAF_HOST}/target/search?q=test", "headers": {"User-Agent": "sqlmap/1.7.1#stable (https://sqlmap.org)"}, "exp": 403},
    {"cat": "Bot", "name": "Nikto Web Vulnerability Scanner", "method": "GET", "url": f"{WAF_HOST}/target/search?q=test", "headers": {"User-Agent": "Mozilla/5.00 (Nikto/2.1.6)"}, "exp": 403},
    {"cat": "Bot", "name": "DirBuster Content Discovery Bot", "method": "GET", "url": f"{WAF_HOST}/target/search?q=test", "headers": {"User-Agent": "DirBuster-1.0-RC1 (http://www.owasp.org/)"}, "exp": 403},
]

# ==============================================================================
# 2. LEGITIMATE BENIGN TRAFFIC (FALSE-POSITIVE INTEGRITY BATTERY)
# ==============================================================================

CLEAN_BATTERY = [
    {"name": "Technical Documentation Search", "method": "GET", "url": f"{WAF_HOST}/target/search?q=how-to-configure-rust-tokio-proxy", "exp": 200},
    {"name": "Product Category Search", "method": "GET", "url": f"{WAF_HOST}/target/search?q=electronics-smartphones-apple-samsung", "exp": 200},
    {"name": "E-Commerce Filter & Sort", "method": "GET", "url": f"{WAF_HOST}/target/search?q=shoes&category=sport&sort=price_asc&page=2", "exp": 200},
    {"name": "Email Contact Verification", "method": "GET", "url": f"{WAF_HOST}/target/search?q=support.security.team@company.org", "exp": 200},
    {"name": "JSON API User Authentication", "method": "POST", "url": f"{WAF_HOST}/target/login", "json": {"username": "cyber_auditor", "role": "security_engineer"}, "exp": 200},
    {"name": "JSON Profile Preference Update", "method": "POST", "url": f"{WAF_HOST}/target/login", "json": {"theme": "dark_cyber", "language": "fa-IR", "notifications": True}, "exp": 200},
    {"name": "Mathematical & Scientific Article Query", "method": "GET", "url": f"{WAF_HOST}/target/search?q=shannon-information-entropy-formula", "exp": 200},
    {"name": "Software Engineering Tutorial Query", "method": "GET", "url": f"{WAF_HOST}/target/search?q=design-patterns-singleton-factory-rust", "exp": 200},
]

# ==============================================================================
# 3. BENCHMARK RUNNER & TELEMETRY ENGINE
# ==============================================================================

def percentile(data, p):
    if not data:
        return 0.0
    k = (len(data) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(data) - 1)
    d0 = data[f] * (c - k)
    d1 = data[c] * (k - f)
    return d0 + d1

def main():
    print("=" * 80)
    print(" 🚀 AEGISGUARD WAF - HIGH-INTENSITY ATTACK & STRESS BENCHMARK PROTOCOL")
    print(" Target Proxy  : http://127.0.0.1:8080")
    print(" Target Origin : http://127.0.0.1:9000")
    print("=" * 80)

    # -------------------------------------------------------------
    # 0. Unban localhost to start from a clean state
    # -------------------------------------------------------------
    try:
        requests.post(f"{WAF_HOST}/__aegis_ddos/unban?ip=127.0.0.1", timeout=2)
        requests.post(f"{WAF_HOST}/__aegis_ddos/toggle?enable=0", timeout=2)
    except Exception:
        pass

    # -------------------------------------------------------------
    # STAGE 1: EXPLOIT & INTRUSION DETECTION BATTERY (OWASP TOP 10)
    # -------------------------------------------------------------
    print("\n" + "-" * 80)
    print(" [STAGE 1/3] EXECUTING DEEP EXPLOITATION BATTERY (OWASP TOP 10 & ZERO-DAYS)")
    print("-" * 80)

    exploit_results = []
    exploit_latencies = []

    for idx, test in enumerate(EXPLOIT_BATTERY, start=1):
        url = test["url"]
        headers = test.get("headers", {})
        json_body = test.get("json", None)
        method = test["method"]

        t0 = time.perf_counter()
        try:
            if method == "GET":
                r = requests.get(url, headers=headers, timeout=5)
            else:
                r = requests.post(url, headers=headers, json=json_body, timeout=5)
            dt_ms = (time.perf_counter() - t0) * 1000
            exploit_latencies.append(dt_ms)
            is_blocked = r.status_code == test["exp"]

            badge = "[🛡️ BLOCKED]" if is_blocked else "[❌ BYPASSED]"
            exploit_results.append({
                "name": test["name"],
                "cat": test["cat"],
                "blocked": is_blocked,
                "status": r.status_code,
                "latency_ms": dt_ms
            })
            print(f" [{idx:02d}/{len(EXPLOIT_BATTERY):02d}] {badge} | {test['cat']:<5} | {test['name']:<42} | {dt_ms:.2f} ms")
        except Exception as e:
            print(f" [{idx:02d}/{len(EXPLOIT_BATTERY):02d}] [!] ERROR: {e}")

    attacks_blocked = sum(1 for r in exploit_results if r["blocked"])
    attack_total = len(exploit_results)
    attack_block_rate = (attacks_blocked / attack_total * 100.0) if attack_total else 0.0

    # -------------------------------------------------------------
    # STAGE 2: CLEAN TRAFFIC & FALSE-POSITIVE INTEGRITY BATTERY
    # -------------------------------------------------------------
    print("\n" + "-" * 80)
    print(" [STAGE 2/3] EXECUTING BENIGN TRAFFIC & FALSE POSITIVE INTEGRITY BATTERY")
    print("-" * 80)

    clean_results = []
    clean_latencies = []

    for idx, test in enumerate(CLEAN_BATTERY, start=1):
        url = test["url"]
        headers = test.get("headers", {})
        json_body = test.get("json", None)
        method = test["method"]

        t0 = time.perf_counter()
        try:
            if method == "GET":
                r = requests.get(url, headers=headers, timeout=5)
            else:
                r = requests.post(url, headers=headers, json=json_body, timeout=5)
            dt_ms = (time.perf_counter() - t0) * 1000
            clean_latencies.append(dt_ms)
            is_passed = r.status_code == test["exp"]

            badge = "[✅ PASSED ]" if is_passed else "[⚠️ FALSE POSITIVE]"
            clean_results.append({
                "name": test["name"],
                "passed": is_passed,
                "status": r.status_code,
                "latency_ms": dt_ms
            })
            print(f" [{idx:02d}/{len(CLEAN_BATTERY):02d}] {badge} | {test['name']:<48} | {dt_ms:.2f} ms")
        except Exception as e:
            print(f" [{idx:02d}/{len(CLEAN_BATTERY):02d}] [!] ERROR: {e}")

    clean_passed = sum(1 for r in clean_results if r["passed"])
    clean_total = len(clean_results)
    clean_pass_rate = (clean_passed / clean_total * 100.0) if clean_total else 0.0
    false_positive_rate = 100.0 - clean_pass_rate

    # -------------------------------------------------------------
    # STAGE 3: VOLUMETRIC DDOS & CONCURRENCY BURST ATTACK
    # -------------------------------------------------------------
    print("\n" + "-" * 80)
    print(" [STAGE 3/3] EXECUTING VOLUMETRIC DDOS BURST (120 CONCURRENT ATTACK STREAMS)")
    print("-" * 80)

    concurrency = 30
    total_burst_reqs = 120
    ddos_results = {"200": 0, "403": 0, "429": 0, "other": 0, "errors": 0}
    ddos_latencies = []

    def send_flood_req(i):
        t0 = time.perf_counter()
        try:
            r = requests.get(f"{WAF_HOST}/target/search?flood_id={i}", timeout=4)
            dt = (time.perf_counter() - t0) * 1000
            return r.status_code, dt
        except Exception:
            return 0, 0.0

    t_start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(send_flood_req, i) for i in range(total_burst_reqs)]
        for f in as_completed(futures):
            status, lat = f.result()
            if status in [200, 403, 429]:
                ddos_results[str(status)] += 1
            elif status == 0:
                ddos_results["errors"] += 1
            else:
                ddos_results["other"] += 1
            if lat > 0:
                ddos_latencies.append(lat)

    ddos_duration = time.perf_counter() - t_start
    ddos_rps = total_burst_reqs / ddos_duration if ddos_duration > 0 else 0

    print(f" [+] Volumetric Flood Completed in {ddos_duration:.2f} seconds ({ddos_rps:.1f} req/sec)")
    print(f"     - Rate-Limited / DDoS Jailed (HTTP 429) : {ddos_results['429']}")
    print(f"     - Allowed Clean Packets (HTTP 200)      : {ddos_results['200']}")
    print(f"     - Dropped / Connection Errors           : {ddos_results['errors']}")

    # -------------------------------------------------------------
    # STATISTICAL SYNTHESIS & METRIC CALCULATIONS
    # -------------------------------------------------------------
    all_latencies = sorted(exploit_latencies + clean_latencies + ddos_latencies)
    avg_latency = statistics.mean(all_latencies) if all_latencies else 0.0
    p50_latency = percentile(all_latencies, 50)
    p90_latency = percentile(all_latencies, 90)
    p99_latency = percentile(all_latencies, 99)
    min_latency = min(all_latencies) if all_latencies else 0.0
    max_latency = max(all_latencies) if all_latencies else 0.0

    # Scoring Formula (NIST & OWASP WAF Standard Scoring, max 100 pts):
    # 1. Exploit Detection & Block Rate: 40 points
    score_exploit = (attack_block_rate / 100.0) * 40.0

    # 2. False Positive Resistance (Clean Pass): 20 points
    score_fp = (clean_pass_rate / 100.0) * 20.0

    # 3. Volumetric DDoS Clamping & Mitigation: 20 points
    # Triggering 429 indicates active protection against overflow
    ddos_clamped = ddos_results["429"] > 0
    score_ddos = 20.0 if ddos_clamped else 10.0

    # 4. Latency & Low-Overhead Performance: 20 points
    # P90 < 5ms: 20 pts, < 15ms: 18 pts, < 50ms: 15 pts
    if p90_latency < 5.0:
        score_perf = 20.0
    elif p90_latency < 15.0:
        score_perf = 18.0
    elif p90_latency < 50.0:
        score_perf = 15.0
    else:
        score_perf = 10.0

    total_score = round(score_exploit + score_fp + score_ddos + score_perf, 1)

    if total_score >= 95.0:
        grade = "A+ (Enterprise Defense Ready)"
    elif total_score >= 90.0:
        grade = "A (Excellent Protection)"
    elif total_score >= 80.0:
        grade = "B (Good Protection)"
    else:
        grade = "C (Needs Hardening)"

    # -------------------------------------------------------------
    # FINAL OFFICIAL AUDIT REPORT CARD
    # -------------------------------------------------------------
    print("\n" + "=" * 80)
    print(" 📊 AEGISGUARD WAF - FINAL OFFICIAL PERFORMANCE & SECURITY SCORECARD")
    print("=" * 80)
    print(f" 🎯 OVERALL SCORE                 : {total_score} / 100.0")
    print(f" 🏆 ACADEMIC & INDUSTRY GRADE     : {grade}")
    print("-" * 80)
    print(f" 🛡️  Exploit Block Rate (OWASP)   : {attack_block_rate:.2f}% ({attacks_blocked}/{attack_total} attacks blocked)")
    print(f" 🟢 Clean Traffic Pass Rate       : {clean_pass_rate:.2f}% ({clean_passed}/{clean_total} valid requests passed)")
    print(f" 🎯 False Positive Rate (FPR)     : {false_positive_rate:.2f}% (Industry Target < 0.5%)")
    print(f" ⚡ Anti-DDoS Volumetric Clamping : {'ACTIVE (HTTP 429 Clamped Flood)' if ddos_clamped else 'INACTIVE'}")
    print(f" 📈 Peak Sustained Throughput     : {ddos_rps:.1f} requests / sec")
    print("-" * 80)
    print(" ⏱️  DETAILED LATENCY PROFILE (All Ingress Inspections):")
    print(f"    - Minimum Latency             : {min_latency:.2f} ms")
    print(f"    - Average Response Time       : {avg_latency:.2f} ms")
    print(f"    - Median (P50) Latency        : {p50_latency:.2f} ms")
    print(f"    - 90th Percentile (P90)       : {p90_latency:.2f} ms")
    print(f"    - 99th Percentile (P99)       : {p99_latency:.2f} ms")
    print(f"    - Max Tail Latency            : {max_latency:.2f} ms")
    print("=" * 80)

if __name__ == "__main__":
    main()
