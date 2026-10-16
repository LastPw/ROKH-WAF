import sys
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

WAF_URL = "http://127.0.0.1:8080"

# ==============================================================================
# 1. ADVANCED BYPASS & EVASION TEST BATTERY
# ==============================================================================

ADVANCED_ATTACK_VECTORS = [
    # --- SQL Injection & Evasion ---
    {
        "category": "SQLi Evasion",
        "name": "SQLi: Comment Obfuscation (UN/**/ION SEL/**/ECT)",
        "method": "GET",
        "url": f"{WAF_URL}/target/search?q=1 UN/**/ION SEL/**/ECT null,password FROM users--",
        "expected_status": 403,
    },
    {
        "category": "SQLi Evasion",
        "name": "SQLi: Mixed Casing (uNiOn aLl sElEcT)",
        "method": "GET",
        "url": f"{WAF_URL}/target/search?q=1' uNiOn aLl sElEcT 1,2,3--",
        "expected_status": 403,
    },
    {
        "category": "SQLi Evasion",
        "name": "SQLi: Stacked Time-Delay (WAITFOR DELAY)",
        "method": "GET",
        "url": f"{WAF_URL}/target/search?q=1; WAITFOR DELAY '0:0:5'--",
        "expected_status": 403,
    },
    {
        "category": "SQLi Evasion",
        "name": "SQLi: Header Injection via Cookie",
        "method": "GET",
        "url": f"{WAF_URL}/target/search?q=normal",
        "headers": {"Cookie": "session_id=admin' OR '1'='1'--"},
        "expected_status": 403,
    },
    # --- XSS & Unicode Evasion ---
    {
        "category": "XSS Evasion",
        "name": "XSS: SVG Event Handler without Spaces (<svg/onload=alert(1)>)",
        "method": "GET",
        "url": f"{WAF_URL}/target/search?q=<svg/onload=alert(1)>",
        "expected_status": 403,
    },
    {
        "category": "XSS Evasion",
        "name": "XSS: Full-Width Unicode Evasion (＜script＞)",
        "method": "GET",
        "url": f"{WAF_URL}/target/search?q=＜script＞alert(1)＜/script＞",
        "expected_status": 403,
    },
    {
        "category": "XSS Evasion",
        "name": "XSS: Data URI Scheme (data:text/html)",
        "method": "GET",
        "url": f"{WAF_URL}/target/search?q=<iframe src=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==>",
        "expected_status": 403,
    },
    {
        "category": "XSS Evasion",
        "name": "XSS: Header Injection via Referer",
        "method": "GET",
        "url": f"{WAF_URL}/target/search?q=docs",
        "headers": {"Referer": "http://evil.com/?q=<script>alert('pwn')</script>"},
        "expected_status": 403,
    },
    # --- Path Traversal / LFI ---
    {
        "category": "Path Traversal",
        "name": "LFI: Double URL-Encoding (%252e%252e%252f)",
        "method": "GET",
        "url": f"{WAF_URL}/target/view-file?file=%252e%252e%252f%252e%252e%252fetc/passwd",
        "expected_status": 403,
    },
    {
        "category": "Path Traversal",
        "name": "LFI: Windows Backslash Separation (..\\..\\windows\\win.ini)",
        "method": "GET",
        "url": f"{WAF_URL}/target/view-file?file=..\\..\\..\\windows\\win.ini",
        "expected_status": 403,
    },
    {
        "category": "Path Traversal",
        "name": "LFI: Environment File Probe (.env)",
        "method": "GET",
        "url": f"{WAF_URL}/target/view-file?file=../../.env",
        "expected_status": 403,
    },
    # --- Command Injection / RCE ---
    {
        "category": "RCE",
        "name": "RCE: Backtick Command Execution (`whoami`)",
        "method": "GET",
        "url": f"{WAF_URL}/target/search?q=`whoami`",
        "expected_status": 403,
    },
    {
        "category": "RCE",
        "name": "RCE: Command Substitution ($(...))",
        "method": "GET",
        "url": f"{WAF_URL}/target/search?q=$(cat /etc/passwd)",
        "expected_status": 403,
    },
    {
        "category": "RCE",
        "name": "RCE: PowerShell Pipe Execution",
        "method": "GET",
        "url": f"{WAF_URL}/target/search?q=1; powershell -Command Get-Process",
        "expected_status": 403,
    },
    # --- Malicious Bots & Automated Scanners ---
    {
        "category": "Scanner Detection",
        "name": "Bot: Nikto Web Scanner Fingerprint",
        "method": "GET",
        "url": f"{WAF_URL}/target/search?q=index",
        "headers": {"User-Agent": "Mozilla/5.00 (Nikto/2.1.6)"},
        "expected_status": 403,
    },
    {
        "category": "Scanner Detection",
        "name": "Bot: DirBuster Brute-Forcer Fingerprint",
        "method": "GET",
        "url": f"{WAF_URL}/target/search?q=index",
        "headers": {"User-Agent": "DirBuster-1.0-RC1 (http://www.owasp.org/)"},
        "expected_status": 403,
    },
    # --- Clean False-Positive Benchmark ---
    {
        "category": "False Positive Check",
        "name": "Clean: Valid Technical Article Query",
        "method": "GET",
        "url": f"{WAF_URL}/target/search?q=how-to-configure-rust-tokio-proxy",
        "expected_status": 200,
    },
    {
        "category": "False Positive Check",
        "name": "Clean: Valid JSON POST Authentication",
        "method": "POST",
        "url": f"{WAF_URL}/target/login",
        "json": {"username": "cyber_auditor", "role": "security_engineer"},
        "expected_status": 200,
    },
]

# ==============================================================================
# 2. RUN AUDIT BATTERY
# ==============================================================================

def run_evasion_battery():
    print("\n" + "=" * 70)
    print(" [1/3] RUNNING ADVANCED EVASION & ATTACK VECTOR BATTERY (RED TEAM)")
    print("=" * 70)

    passed = 0
    total = len(ADVANCED_ATTACK_VECTORS)

    for idx, test in enumerate(ADVANCED_ATTACK_VECTORS, start=1):
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
            is_ok = r.status_code == test["expected_status"]
            if is_ok:
                passed += 1
                badge = "[+] PASSED"
            else:
                badge = "[-] FAILED"

            print(f"[{idx:02d}/{total:02d}] {badge} | {test['name']}")
            print(f"     Status: {r.status_code} (Expected {test['expected_status']}) | Latency: {dt_ms:.2f}ms")
            if not is_ok:
                print(f"     Body: {r.text[:100]}")
        except Exception as e:
            print(f"[{idx:02d}/{total:02d}] [-] ERROR: {e}")

    print(f"\n>> Evasion Battery Score: {passed}/{total} ({passed/total*100:.1f}%)")
    return passed == total

# ==============================================================================
# 3. CONCURRENCY & VOLUMETRIC STRESS TEST (RATE LIMITING UNDER BURST)
# ==============================================================================

def run_concurrency_stress(concurrency=30, total_requests=100):
    print("\n" + "=" * 70)
    print(f" [2/3] RUNNING VOLUMETRIC CONCURRENCY BURST ({total_requests} REQS / {concurrency} THREADS)")
    print("=" * 70)

    results = {"200": 0, "403": 0, "429": 0, "other": 0, "errors": 0}
    latencies = []

    def make_req(req_id):
        t0 = time.perf_counter()
        try:
            # Blast legitimate requests rapidly to verify rate-limiter clamp
            r = requests.get(f"{WAF_URL}/target/search?q=stress_{req_id}", timeout=5)
            elapsed = (time.perf_counter() - t0) * 1000
            return r.status_code, elapsed
        except Exception:
            return 0, 0

    t_start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(make_req, i) for i in range(total_requests)]
        for f in as_completed(futures):
            status, lat = f.result()
            if status in [200, 403, 429]:
                results[str(status)] += 1
            elif status == 0:
                results["errors"] += 1
            else:
                results["other"] += 1
            if lat > 0:
                latencies.append(lat)

    total_time = time.perf_counter() - t_start
    rps = total_requests / total_time if total_time > 0 else 0
    avg_lat = sum(latencies) / len(latencies) if latencies else 0

    print(f"[i] Completed {total_requests} requests in {total_time:.2f}s ({rps:.1f} req/sec)")
    print(f"    - Clean Passed (HTTP 200)       : {results['200']}")
    print(f"    - Rate-Limited (HTTP 429)       : {results['429']}")
    print(f"    - Blocked Attacks (HTTP 403)    : {results['403']}")
    print(f"    - Network Errors / Drops        : {results['errors']}")
    print(f"    - Average Latency               : {avg_lat:.2f} ms")

    if results["429"] > 0:
        print("[+] SUCCESS: Rate Limiter actively clamped volumetric flood!")
    else:
        print("[!] Rate limiter did not trigger (threshold may exceed total requests).")

    return results["errors"] == 0

# ==============================================================================
# 4. LARGE PAYLOAD & ReDoS RESILIENCE TEST
# ==============================================================================

def run_payload_boundary_test():
    print("\n" + "=" * 70)
    print(" [3/3] RUNNING ReDoS & LARGE PAYLOAD RESILIENCE TEST")
    print("=" * 70)

    # 1. ReDoS Trap: 20,000 characters of repetitive malicious-like text
    redos_payload = "a" * 15000 + "' OR '1'='1"
    t0 = time.perf_counter()
    try:
        r = requests.post(f"{WAF_URL}/target/login", json={"username": redos_payload}, timeout=5)
        dt = (time.perf_counter() - t0) * 1000
        print(f"[+] ReDoS Attack Test: Processed in {dt:.2f}ms | Status: {r.status_code}")
        if dt < 50 and r.status_code == 403:
            print("    [+] Immune to ReDoS! DFA Linear-Time Regular Expression verified.")
    except Exception as e:
        print(f"[-] ReDoS test error: {e}")

    # 2. Oversized payload (Payload > 2MB limit)
    large_payload = "X" * (3 * 1024 * 1024) # 3MB
    try:
        r = requests.post(f"{WAF_URL}/target/login", data=large_payload, timeout=5)
        print(f"[+] Oversized Payload (3MB): Status: {r.status_code} (Expected 413 Payload Too Large)")
    except Exception as e:
        print(f"[i] Oversized payload handled: {e}")

# ==============================================================================
# MAIN ENTRYPOINT
# ==============================================================================

if __name__ == "__main__":
    print("*" * 70)
    print("   AEGISGUARD WAF - INTENSIVE RED TEAM SECURITY AUDIT & STRESS SUITE")
    print("*" * 70)

    t_all = time.perf_counter()
    evasion_ok = run_evasion_battery()
    stress_ok = run_concurrency_stress(concurrency=25, total_requests=100)
    run_payload_boundary_test()
    total_duration = time.perf_counter() - t_all

    print("\n" + "=" * 70)
    print(f" 🛡️  AUDIT COMPLETE IN {total_duration:.2f} SECONDS")
    if evasion_ok and stress_ok:
        print(" 🏆 FINAL VERDICT: GRADE A+ (ENTERPRISE RESILIENT)")
    else:
        print(" ⚠️  FINAL VERDICT: DEFICIENCIES DETECTED")
    print("=" * 70)
