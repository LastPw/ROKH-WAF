import sys
import time
import hashlib
import urllib.request
import urllib.parse
import json

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

WAF_HOST = "http://127.0.0.1:8080"
SOC_HOST = "http://127.0.0.1:9000"

def log_step(title):
    print("\n" + "=" * 70)
    print(f" [TEST STEP] {title}")
    print("=" * 70)

def main():
    print("=" * 70)
    print(" 🛡️  AEGISGUARD CLOUDFLARE-GRADE ANTI-DDOS AUTOMATED VERIFICATION")
    print("=" * 70)

    # -------------------------------------------------------------
    # Step 1: Verify Normal Traffic
    # -------------------------------------------------------------
    log_step("1. Verifying Normal Clean Traffic")
    req = urllib.request.Request(f"{WAF_HOST}/target/search?q=normal_user", headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            body = resp.read().decode()
            print(f" [+] Status Code: {resp.status}")
            assert resp.status == 200
            assert "Processed search query successfully" in body
            print(" [+] Clean request successfully passed to backend target!")
    except Exception as e:
        print(f" [-] Failed normal request: {e}")
        sys.exit(1)

    # -------------------------------------------------------------
    # Step 2: Activate "Under Attack Mode" via API
    # -------------------------------------------------------------
    log_step("2. Activating 'Under Attack Mode' (Shields Up)")
    toggle_req = urllib.request.Request(f"{WAF_HOST}/__aegis_ddos/toggle?enable=1", method="POST")
    with urllib.request.urlopen(toggle_req, timeout=3) as resp:
        status_data = json.loads(resp.read().decode())
        print(f" [+] WAF Response: {status_data}")
        assert status_data["under_attack_mode"] is True
        print(" [+] 'Under Attack Mode' successfully activated on WAF Core!")

    # -------------------------------------------------------------
    # Step 3: Verify Unauthenticated Request gets Proof-of-Work Challenge
    # -------------------------------------------------------------
    log_step("3. Testing Unverified Client Under Attack Mode")
    challenge_req = urllib.request.Request(f"{WAF_HOST}/target/search?q=test_challenge", headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(challenge_req, timeout=3) as resp:
            html = resp.read().decode()
            status = resp.status
    except urllib.error.HTTPError as e:
        html = e.read().decode()
        status = e.code

    print(f" [+] Status Code: {status} (Challenge Intercept)")
    assert status == 403, f"Expected 403 Challenge status, got {status}"
    assert "AegisGuard DDoS Shield | Browser Verification" in html
    assert "crypto.subtle.digest" in html
    print(" [+] WAF intercepted unverified client and served Cloudflare-style PoW JS Challenge!")

    # Extract Nonce from challenge HTML
    import re
    nonce_match = re.search(r'const nonce = "([^"]+)"', html)
    assert nonce_match is not None, "Failed to extract challenge nonce from HTML"
    nonce = nonce_match.group(1)
    print(f" [+] Challenge Nonce Issued: {nonce}")

    # -------------------------------------------------------------
    # Step 4: Simulate Legitimate Browser Solving Proof-of-Work
    # -------------------------------------------------------------
    log_step("4. Browser Simulates Solving Proof-of-Work Puzzle (SHA-256 target '0000')")
    client_ip = "127.0.0.1"
    target_prefix = "0000"
    solution = 0
    t0 = time.perf_counter()

    while True:
        candidate = f"{client_ip}:{nonce}:{solution}"
        h = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
        if h.startswith(target_prefix):
            break
        solution += 1

    solve_time_ms = (time.perf_counter() - t0) * 1000
    print(f" [+] Puzzle Solved in {solve_time_ms:.2f} ms!")
    print(f"     Solution Nonce: {solution} | Resulting Hash: {h[:12]}...")

    # Submit verification solution to /__aegis_verify
    verify_url = f"{WAF_HOST}/__aegis_verify?nonce={urllib.parse.quote(nonce)}&solution={solution}&redirect={urllib.parse.quote('/target/search?q=post_verify')}"
    
    # Custom opener to intercept Set-Cookie and avoid auto-redirect if needed
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    try:
        resp = opener.open(verify_url)
        cookie_header = resp.headers.get("Set-Cookie")
        status_code = resp.status
    except urllib.error.HTTPError as e:
        cookie_header = e.headers.get("Set-Cookie")
        status_code = e.code

    print(f" [+] Verification Response Status: {status_code}")
    print(f" [+] Received Clearance Cookie: {cookie_header}")
    assert "__aegis_clearance=" in cookie_header, "Failed to obtain clearance cookie"

    clearance_cookie = cookie_header.split(";")[0]

    # -------------------------------------------------------------
    # Step 5: Verified Client accesses Backend under Attack Mode
    # -------------------------------------------------------------
    log_step("5. Verified Client browsing backend with __aegis_clearance Cookie")
    verified_req = urllib.request.Request(
        f"{WAF_HOST}/target/search?q=vip_client",
        headers={
            "User-Agent": "Mozilla/5.0",
            "Cookie": clearance_cookie
        }
    )
    with urllib.request.urlopen(verified_req, timeout=3) as resp:
        body = resp.read().decode()
        print(f" [+] Status Code: {resp.status}")
        assert resp.status == 200
        assert "Processed search query successfully" in body
        print(" [+] Legitimate client passed through instantly while 'Under Attack Mode' is ACTIVE!")

    # -------------------------------------------------------------
    # Step 6: Test HTTP Flood / Botnet Mitigation & Automatic Jail
    # -------------------------------------------------------------
    log_step("6. Simulating Botnet Layer 7 HTTP Flood (120 rapid requests without JS)")
    # Reset attack mode to normal first to test rate-limit escalation & jail
    urllib.request.urlopen(urllib.request.Request(f"{WAF_HOST}/__aegis_ddos/toggle?enable=0", method="POST"))
    
    # Unban 127.0.0.1 first so we start clean
    urllib.request.urlopen(urllib.request.Request(f"{WAF_HOST}/__aegis_ddos/unban?ip=127.0.0.1", method="POST"))

    flood_ip = "127.0.0.1"
    flood_count = 130
    blocked_count = 0
    jailed_detected = False

    t_flood_start = time.perf_counter()
    for i in range(flood_count):
        req = urllib.request.Request(
            f"{WAF_HOST}/target/search?flood_iter={i}",
            headers={"User-Agent": "MiraiBot/2.0"} # No clearance cookie
        )
        try:
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                pass
        except urllib.error.HTTPError as e:
            if e.code == 429:
                blocked_count += 1
                retry_after = e.headers.get("Retry-After")
                resp_json = json.loads(e.read().decode())
                if resp_json.get("attack_type") == "DDOS_FLOOD_JAIL":
                    jailed_detected = True
        except Exception:
            blocked_count += 1

    flood_duration = time.perf_counter() - t_flood_start
    print(f" [+] Sent {flood_count} flood requests in {flood_duration:.2f} seconds ({flood_count/flood_duration:.0f} req/sec)")
    print(f" [+] Total Dropped / Blocked: {blocked_count}")
    print(f" [+] Dynamic Jail Triggered: {jailed_detected}")
    assert jailed_detected, "WAF must place flood IP into dynamic jail"
    print(" [+] WAF successfully mitigated flood and blacklisted the attacking client IP in memory!")

    # -------------------------------------------------------------
    # Step 7: Telemetry & SOC Dashboard Metrics Check
    # -------------------------------------------------------------
    log_step("7. Checking Real-Time Anti-DDoS Telemetry Metrics")
    status_req = urllib.request.Request(f"{WAF_HOST}/__aegis_ddos/status")
    with urllib.request.urlopen(status_req, timeout=3) as resp:
        metrics = json.loads(resp.read().decode())
        print(f" [+] DDoS Telemetry Snapshot:")
        print(f"     - Global RPS                : {metrics['global_rps']}")
        print(f"     - Total Challenges Issued   : {metrics['total_challenges_issued']}")
        print(f"     - Total Challenges Solved   : {metrics['total_challenges_solved']}")
        print(f"     - Total Dropped Packets     : {metrics['total_blocked_ddos']}")
        print(f"     - Active Jailed IPs Count   : {metrics['jailed_ips_count']}")
        print(f"     - Jailed IPs Details        : {metrics['jailed_ips']}")

    # Clean up: Unban 127.0.0.1 so subsequent tests are clean
    urllib.request.urlopen(urllib.request.Request(f"{WAF_HOST}/__aegis_ddos/unban?ip=127.0.0.1", method="POST"))

    print("\n" + "=" * 70)
    print(" 🎉 ALL CLOUDFLARE-GRADE ANTI-DDOS TESTS PASSED WITH 100% SUCCESS!")
    print("=" * 70)

if __name__ == "__main__":
    main()
