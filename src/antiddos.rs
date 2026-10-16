use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const POW_DIFFICULTY_PREFIX: &str = "0000"; // 16 bits of leading zero entropy (~0.05s in browser)
const CLEARANCE_COOKIE_NAME: &str = "__aegis_clearance";
const CLEARANCE_DURATION_SECS: u64 = 1800; // 30 minutes clearance for verified browsers

#[derive(Debug, Clone)]
pub struct DdosConfig {
    pub normal_rpm_limit: u32,       // Normal max requests per minute (e.g. 60)
    pub burst_rpm_limit: u32,        // Burst limit triggering instant jail (e.g. 120)
    pub surge_rps_threshold: u64,    // Global RPS triggering Auto Under-Attack Mode (e.g. 100)
    pub base_jail_seconds: u64,      // Initial jail ban duration (e.g. 60s)
}

impl Default for DdosConfig {
    fn default() -> Self {
        Self {
            normal_rpm_limit: 60,
            burst_rpm_limit: 120,
            surge_rps_threshold: 80,
            base_jail_seconds: 60,
        }
    }
}

pub enum DdosVerdict {
    Allow,
    Challenge(Response),
    Jailed { remaining_secs: u64 },
    VerifySuccess(Response),
}

struct IpProfile {
    window_start: Instant,
    request_count: u32,
    violation_count: u32,
    jailed_until: Option<Instant>,
}

impl IpProfile {
    fn new(now: Instant) -> Self {
        Self {
            window_start: now,
            request_count: 0,
            violation_count: 0,
            jailed_until: None,
        }
    }
}

pub struct AntiDdosEngine {
    config: DdosConfig,
    profiles: Mutex<HashMap<String, IpProfile>>,
    last_cleanup: Mutex<Instant>,
    secret_key: String,
    pub under_attack_mode: AtomicBool,
    // Global Traffic Surge Tracking
    last_sec_timestamp: AtomicU64,
    current_sec_requests: AtomicU64,
    measured_global_rps: AtomicU64,
    // Telemetry
    total_challenges_issued: AtomicU64,
    total_challenges_solved: AtomicU64,
    total_blocked_ddos: AtomicU64,
}

impl AntiDdosEngine {
    pub fn new(config: DdosConfig) -> Self {
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Configurable or deterministic HMAC secret key (retains clearance cookies across restarts)
        let secret_key = std::env::var("AEGIS_HMAC_SECRET").unwrap_or_else(|_| {
            format!("aegis_ddos_key_{}_{}", now_sec, rand_u64())
        });

        Self {
            config,
            profiles: Mutex::new(HashMap::new()),
            last_cleanup: Mutex::new(Instant::now()),
            secret_key,
            under_attack_mode: AtomicBool::new(false),
            last_sec_timestamp: AtomicU64::new(now_sec),
            current_sec_requests: AtomicU64::new(0),
            measured_global_rps: AtomicU64::new(0),
            total_challenges_issued: AtomicU64::new(0),
            total_challenges_solved: AtomicU64::new(0),
            total_blocked_ddos: AtomicU64::new(0),
        }
    }

    /// Evaluates incoming request against DDoS defense policies
    pub fn check_request(
        &self,
        client_ip: &str,
        headers: &HeaderMap,
        uri: &Uri,
    ) -> DdosVerdict {
        let now = Instant::now();
        let now_unix = current_unix_timestamp();

        // 1. Measure and update Global RPS for auto-surge detection
        self.record_global_request(now_unix);

        // 2. Check if this is a Proof-of-Work Verification Submission
        if uri.path() == "/__aegis_verify" {
            return self.handle_verification(client_ip, uri, now_unix);
        }

        // 3. Fast-Path: Cryptographic Clearance Cookie Verification
        if self.is_clearance_valid(client_ip, headers, now_unix) {
            return DdosVerdict::Allow;
        }

        let mut map = self.profiles.lock().unwrap();

        // Memory cleanup: Evict old entries if table grows large, but throttle to at most once every 30 seconds
        if map.len() > 5_000 {
            let mut last_clean = self.last_cleanup.lock().unwrap();
            if now.duration_since(*last_clean) > Duration::from_secs(30) {
                let two_mins = Duration::from_secs(120);
                map.retain(|_, profile| {
                    if let Some(jailed) = profile.jailed_until {
                        jailed > now
                    } else {
                        now.duration_since(profile.window_start) < two_mins
                    }
                });
                *last_clean = now;
            }
        }

        let profile = map
            .entry(client_ip.to_string())
            .or_insert_with(|| IpProfile::new(now));

        // 4. Check if IP is currently in Jail
        if let Some(jail_end) = profile.jailed_until {
            if now < jail_end {
                self.total_blocked_ddos.fetch_add(1, Ordering::Relaxed);
                let remaining = jail_end.duration_since(now).as_secs();
                return DdosVerdict::Jailed {
                    remaining_secs: remaining.max(1),
                };
            } else {
                // Jail expired -> release IP with clean slate
                profile.jailed_until = None;
                profile.request_count = 1;
                profile.window_start = now;
            }
        }

        // 5. Update Sliding Window (1 minute)
        let elapsed = now.duration_since(profile.window_start);
        if elapsed > Duration::from_secs(60) {
            profile.window_start = now;
            profile.request_count = 1;
        } else {
            profile.request_count += 1;
        }

        // 6. Check for Extreme Flood -> Instant Jail
        if profile.request_count > self.config.burst_rpm_limit {
            profile.violation_count += 1;
            let multiplier = 1u64 << (profile.violation_count.min(4) - 1);
            let jail_time = self.config.base_jail_seconds * multiplier;
            profile.jailed_until = Some(now + Duration::from_secs(jail_time));

            self.total_blocked_ddos.fetch_add(1, Ordering::Relaxed);
            return DdosVerdict::Jailed {
                remaining_secs: jail_time,
            };
        }

        // 7. Check if Under Attack Mode is Active OR IP is exceeding normal limit
        let is_surge = self.under_attack_mode.load(Ordering::Relaxed);
        let exceeds_normal = profile.request_count > self.config.normal_rpm_limit;

        if is_surge || exceeds_normal {
            self.total_challenges_issued.fetch_add(1, Ordering::Relaxed);
            let challenge_response = self.render_pow_challenge(client_ip, uri);
            return DdosVerdict::Challenge(challenge_response);
        }

        DdosVerdict::Allow
    }

    /// Validates the cryptographic HMAC clearance cookie
    fn is_clearance_valid(&self, client_ip: &str, headers: &HeaderMap, now_unix: u64) -> bool {
        if let Some(cookie_hdr) = headers.get("cookie").and_then(|h| h.to_str().ok()) {
            for cookie in cookie_hdr.split(';') {
                let parts: Vec<&str> = cookie.trim().splitn(2, '=').collect();
                if parts.len() == 2 && parts[0] == CLEARANCE_COOKIE_NAME {
                    let val = parts[1];
                    let segments: Vec<&str> = val.split('_').collect();
                    if segments.len() == 3 {
                        if let (Ok(expiry), ip, hmac) = (segments[0].parse::<u64>(), segments[1], segments[2]) {
                            if now_unix <= expiry && ip == client_ip {
                                let expected_hmac = self.generate_hmac(client_ip, expiry);
                                if hmac == expected_hmac {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Handles submission of solved Proof-of-Work challenge
    fn handle_verification(&self, client_ip: &str, uri: &Uri, now_unix: u64) -> DdosVerdict {
        let query = uri.query().unwrap_or("");
        let params: HashMap<String, String> = query
            .split('&')
            .filter_map(|pair| {
                let mut s = pair.splitn(2, '=');
                Some((s.next()?.to_string(), s.next().unwrap_or("").to_string()))
            })
            .collect();

        let nonce = params.get("nonce").map(|s| s.as_str()).unwrap_or("");
        let solution = params.get("solution").map(|s| s.as_str()).unwrap_or("");
        let redirect_url = params
            .get("redirect")
            .map(|s| s.as_str())
            .unwrap_or("/");

        // Validate nonce format: <timestamp_unix>_<random_hex>
        let nonce_parts: Vec<&str> = nonce.split('_').collect();
        if nonce_parts.len() != 2 {
            return DdosVerdict::Challenge(
                (StatusCode::FORBIDDEN, "Invalid challenge nonce format.").into_response(),
            );
        }

        let nonce_time: u64 = match nonce_parts[0].parse() {
            Ok(t) => t,
            Err(_) => return DdosVerdict::Challenge(
                (StatusCode::FORBIDDEN, "Malformed challenge timestamp.").into_response(),
            ),
        };

        // Anti-replay: Nonce must be generated within the last 120 seconds
        if now_unix < nonce_time || now_unix - nonce_time > 120 {
            return DdosVerdict::Challenge(
                (StatusCode::FORBIDDEN, "Challenge expired. Please reload and solve again.").into_response(),
            );
        }

        // Verify Proof of Work: sha256(client_ip + ":" + nonce + ":" + solution) must start with "0000"
        let input = format!("{}:{}:{}", client_ip, nonce, solution);
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        let hash = hex::encode(hasher.finalize());

        if !hash.starts_with(POW_DIFFICULTY_PREFIX) {
            return DdosVerdict::Challenge(
                (StatusCode::FORBIDDEN, "Invalid Proof-of-Work solution.").into_response(),
            );
        }

        // Passed! Issue cryptographic clearance cookie for 30 minutes
        self.total_challenges_solved.fetch_add(1, Ordering::Relaxed);
        let expiry = now_unix + CLEARANCE_DURATION_SECS;
        let hmac = self.generate_hmac(client_ip, expiry);
        let cookie_val = format!("{}_{}_{}", expiry, client_ip, hmac);

        let safe_redirect = if redirect_url.starts_with('/') && !redirect_url.starts_with("//") {
            redirect_url
        } else {
            "/"
        };

        let response = Response::builder()
            .status(StatusCode::FOUND)
            .header("Location", safe_redirect)
            .header(
                "Set-Cookie",
                format!(
                    "{}={}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax",
                    CLEARANCE_COOKIE_NAME, cookie_val, CLEARANCE_DURATION_SECS
                ),
            )
            .body(axum::body::Body::from("Redirecting to protected destination..."))
            .unwrap();

        DdosVerdict::VerifySuccess(response)
    }

    /// Renders Cloudflare-style browser Proof-of-Work challenge page
    fn render_pow_challenge(&self, client_ip: &str, uri: &Uri) -> Response {
        let now_unix = current_unix_timestamp();
        let nonce = format!("{}_{}", now_unix, rand_u64());
        let current_target = format!("{}{}", uri.path(), uri.query().map(|q| format!("?{}", q)).unwrap_or_default());

        let html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AegisGuard DDoS Shield | Browser Verification</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background: #090d16;
            color: #f1f5f9;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 20px;
        }}
        .card {{
            background: #111827;
            border: 1px solid #1f2937;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7);
            border-radius: 16px;
            padding: 40px;
            max-width: 520px;
            width: 100%;
            text-align: center;
        }}
        .radar {{
            width: 80px;
            height: 80px;
            margin: 0 auto 24px;
            position: relative;
            border-radius: 50%;
            border: 3px solid #3b82f6;
            background: radial-gradient(circle, rgba(59, 130, 246, 0.2) 0%, transparent 70%);
        }}
        .radar::before {{
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            border-radius: 50%;
            border-top: 3px solid #60a5fa;
            animation: spin 1s linear infinite;
        }}
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
        h1 {{ font-size: 20px; font-weight: 700; color: #f8fafc; margin-bottom: 12px; }}
        p {{ color: #94a3b8; font-size: 14px; line-height: 1.6; margin-bottom: 20px; }}
        .badge {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: #1e293b;
            color: #38bdf8;
            padding: 6px 14px;
            border-radius: 9999px;
            font-size: 12px;
            font-family: monospace;
            margin-bottom: 24px;
            border: 1px solid #334155;
        }}
        .status {{
            color: #38bdf8;
            font-size: 13px;
            font-weight: 500;
        }}
        .footer {{
            border-top: 1px solid #1f2937;
            margin-top: 24px;
            padding-top: 16px;
            font-size: 11px;
            color: #64748b;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="radar"></div>
        <div class="badge">🛡️ AegisGuard Cloud-Edge Anti-DDoS</div>
        <h1>Checking your browser before accessing the destination...</h1>
        <p>This automated cryptographic verification protects our application against DDoS floods. You will be redirected in a moment.</p>
        <div class="status" id="status-msg">⚡ Computing Proof-of-Work puzzle...</div>
        <div class="footer">
            Target: <code>{target}</code> | IP: <code>{client_ip}</code>
        </div>
    </div>

    <script>
        (async function() {{
            const clientIp = "{client_ip}";
            const nonce = "{nonce}";
            const targetPrefix = "{prefix}";
            const redirectUrl = "{target}";
            const encoder = new TextEncoder();
            let counter = 0;

            const status = document.getElementById("status-msg");

            async function solve() {{
                const t0 = performance.now();
                while (true) {{
                    const payload = clientIp + ":" + nonce + ":" + counter;
                    const hashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(payload));
                    const hashArray = Array.from(new Uint8Array(hashBuffer));
                    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

                    if (hashHex.startsWith(targetPrefix)) {{
                        const duration = Math.round(performance.now() - t0);
                        status.innerText = " Verified in " + duration + "ms! Redirecting...";
                        window.location.href = "/__aegis_verify?nonce=" + encodeURIComponent(nonce) +
                                              "&solution=" + counter +
                                              "&redirect=" + encodeURIComponent(redirectUrl);
                        break;
                    }}
                    counter++;

                    // Yield to UI thread every 2000 iterations
                    if (counter % 2000 === 0) {{
                        await new Promise(r => setTimeout(r, 0));
                    }}
                }}
            }}

            if (window.crypto && window.crypto.subtle) {{
                solve();
            }} else {{
                status.innerText = "❌ Web Cryptography API not supported. Please use a modern browser.";
            }}
        }})();
    </script>
</body>
</html>"#,
            target = current_target,
            client_ip = client_ip,
            nonce = nonce,
            prefix = POW_DIFFICULTY_PREFIX
        );

        Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("Content-Type", "text/html; charset=utf-8")
            .header("Cache-Control", "no-cache, no-store, must-revalidate")
            .body(axum::body::Body::from(html))
            .unwrap()
    }

    /// Generates cryptographic HMAC token for clearance cookie
    fn generate_hmac(&self, client_ip: &str, expiry: u64) -> String {
        let input = format!("{}:{}:{}", self.secret_key, client_ip, expiry);
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        hex::encode(&hasher.finalize()[..16]) // 16-byte hex representation
    }

    /// Records a request to compute global real-time Requests Per Second (RPS)
    fn record_global_request(&self, now_unix: u64) {
        let last_sec = self.last_sec_timestamp.load(Ordering::Relaxed);
        if now_unix > last_sec {
            // New second started -> swap counter to measured_global_rps
            let count = self.current_sec_requests.swap(1, Ordering::SeqCst);
            self.measured_global_rps.store(count, Ordering::Relaxed);
            self.last_sec_timestamp.store(now_unix, Ordering::Relaxed);

            // Automatic Surge Detection Circuit Breaker
            if count >= self.config.surge_rps_threshold {
                self.under_attack_mode.store(true, Ordering::SeqCst);
            }
        } else {
            self.current_sec_requests.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Toggles manual Under Attack Mode
    pub fn set_under_attack_mode(&self, enabled: bool) {
        self.under_attack_mode.store(enabled, Ordering::SeqCst);
    }

    /// Checks if an IP is currently jailed, returning remaining seconds if so
    pub fn is_ip_jailed(&self, client_ip: &str) -> Option<u64> {
        let now = Instant::now();
        let map = self.profiles.lock().unwrap();
        if let Some(profile) = map.get(client_ip) {
            if let Some(jail_end) = profile.jailed_until {
                if now < jail_end {
                    return Some(jail_end.duration_since(now).as_secs().max(1));
                }
            }
        }
        None
    }

    /// Unbans an IP address from memory
    pub fn unban_ip(&self, ip: &str) -> bool {
        let mut map = self.profiles.lock().unwrap();
        if let Some(profile) = map.get_mut(ip) {
            profile.jailed_until = None;
            profile.request_count = 0;
            profile.violation_count = 0;
            true
        } else {
            false
        }
    }

    /// Telemetry & metrics snapshot for SOC Dashboard
    pub fn get_metrics(&self) -> serde_json::Value {
        let map = self.profiles.lock().unwrap();
        let now = Instant::now();

        let mut active_jails = Vec::new();
        for (ip, prof) in map.iter() {
            if let Some(end) = prof.jailed_until {
                if end > now {
                    active_jails.push(serde_json::json!({
                        "ip": ip,
                        "remaining_seconds": end.duration_since(now).as_secs(),
                        "violations": prof.violation_count
                    }));
                }
            }
        }

        serde_json::json!({
            "under_attack_mode": self.under_attack_mode.load(Ordering::Relaxed),
            "global_rps": self.measured_global_rps.load(Ordering::Relaxed),
            "surge_threshold_rps": self.config.surge_rps_threshold,
            "total_challenges_issued": self.total_challenges_issued.load(Ordering::Relaxed),
            "total_challenges_solved": self.total_challenges_solved.load(Ordering::Relaxed),
            "total_blocked_ddos": self.total_blocked_ddos.load(Ordering::Relaxed),
            "jailed_ips_count": active_jails.len(),
            "jailed_ips": active_jails
        })
    }
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn rand_u64() -> u64 {
    let now = Instant::now().elapsed().as_nanos() as u64;
    now ^ 0x517cc1b727220a95
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_traffic_allowed() {
        let engine = AntiDdosEngine::new(DdosConfig::default());
        let headers = HeaderMap::new();
        let uri: Uri = "/products".parse().unwrap();

        match engine.check_request("10.0.0.1", &headers, &uri) {
            DdosVerdict::Allow => {}
            _ => panic!("Normal request should be allowed"),
        }
    }

    #[test]
    fn test_under_attack_mode_triggers_challenge() {
        let engine = AntiDdosEngine::new(DdosConfig::default());
        engine.set_under_attack_mode(true);

        let headers = HeaderMap::new();
        let uri: Uri = "/api/data".parse().unwrap();

        match engine.check_request("10.0.0.2", &headers, &uri) {
            DdosVerdict::Challenge(_) => {}
            _ => panic!("Under Attack Mode should issue challenge"),
        }
    }

    #[test]
    fn test_burst_traffic_triggers_jail() {
        let config = DdosConfig {
            normal_rpm_limit: 5,
            burst_rpm_limit: 10,
            surge_rps_threshold: 50,
            base_jail_seconds: 30,
        };
        let engine = AntiDdosEngine::new(config);
        let headers = HeaderMap::new();
        let uri: Uri = "/search".parse().unwrap();

        // 1..5: Allowed
        for _ in 0..5 {
            assert!(matches!(engine.check_request("10.0.0.3", &headers, &uri), DdosVerdict::Allow));
        }

        // 6..10: Challenge mode
        for _ in 5..10 {
            assert!(matches!(engine.check_request("10.0.0.3", &headers, &uri), DdosVerdict::Challenge(_)));
        }

        // 11+: Instant Jail!
        match engine.check_request("10.0.0.3", &headers, &uri) {
            DdosVerdict::Jailed { remaining_secs } => {
                assert!(remaining_secs > 0);
            }
            _ => panic!("Burst traffic should trigger jail"),
        }
    }

    #[test]
    fn test_pow_solution_and_clearance() {
        let engine = AntiDdosEngine::new(DdosConfig::default());
        let client_ip = "10.0.0.4";
        let now_unix = current_unix_timestamp();
        let nonce = format!("{}_{}", now_unix, 12345);

        // Find solution
        let mut solution = 0;
        loop {
            let input = format!("{}:{}:{}", client_ip, nonce, solution);
            let mut hasher = Sha256::new();
            hasher.update(input.as_bytes());
            let hash = hex::encode(hasher.finalize());
            if hash.starts_with(POW_DIFFICULTY_PREFIX) {
                break;
            }
            solution += 1;
        }

        // Submit verification
        let verify_uri: Uri = format!("/__aegis_verify?nonce={}&solution={}&redirect=/admin", nonce, solution)
            .parse()
            .unwrap();

        let verdict = engine.handle_verification(client_ip, &verify_uri, now_unix);
        match verdict {
            DdosVerdict::VerifySuccess(res) => {
                let cookie = res.headers().get("set-cookie").unwrap().to_str().unwrap();
                assert!(cookie.contains(CLEARANCE_COOKIE_NAME));

                // Now verify that the cookie grants immediate clearance
                let mut headers = HeaderMap::new();
                let cookie_val = cookie.split(';').next().unwrap();
                headers.insert("cookie", cookie_val.parse().unwrap());

                engine.set_under_attack_mode(true); // Even under attack!
                let regular_uri: Uri = "/admin".parse().unwrap();
                let clearance_verdict = engine.check_request(client_ip, &headers, &regular_uri);
                assert!(matches!(clearance_verdict, DdosVerdict::Allow));
            }
            _ => panic!("Valid PoW solution must succeed"),
        }
    }
}
