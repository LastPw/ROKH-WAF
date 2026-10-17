use crate::antiddos::{AntiDdosEngine, DdosVerdict};
use crate::config::{WafConfig, WafMode};
use crate::deobfuscator::Deobfuscator;
use crate::logger::{LogEntry, WafLogger};
use crate::rules::{AttackType, DetectionResult, RuleEngine};

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;

pub struct AppState {
    pub config: WafConfig,
    pub rules: RuleEngine,
    pub antiddos: AntiDdosEngine,
    pub logger: WafLogger,
    pub http_client: reqwest::Client,
}

pub async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let (parts, body) = req.into_parts();

    // 1. Resolve client IP securely: only trust X-Forwarded-For if connecting peer is loopback/trusted proxy
    let is_trusted_peer = addr.ip().is_loopback();
    let client_ip = if is_trusted_peer {
        parts
            .headers
            .get("x-forwarded-for")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| addr.ip().to_string())
    } else {
        addr.ip().to_string()
    };

    let method = parts.method.to_string();
    let path = parts.uri.path().to_string();
    let query_string = parts.uri.query().map(|q| q.to_string());
    let is_html_client = parts
        .headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .map(|a| a.contains("text/html"))
        .unwrap_or(false);

    // 1.5 DDoS Management Endpoints (Restricted strictly to Authenticated Internal SOC Communication)
    if path.starts_with("/__aegis_ddos/") || path.starts_with("/__rokh_ddos/") {
        let has_forwarded_header = parts.headers.contains_key("x-forwarded-for")
            || parts.headers.contains_key("x-real-ip");

        let expected_secret = std::env::var("ROKH_SOC_SECRET")
            .or_else(|_| std::env::var("AEGIS_SOC_SECRET"))
            .unwrap_or_else(|_| "aegis_soc_secret_2026".to_string());

        let provided_key = parts
            .headers
            .get("x-aegis-internal-key")
            .or_else(|| parts.headers.get("x-rokh-internal-key"))
            .and_then(|h| h.to_str().ok());

        let has_valid_key = provided_key == Some(&expected_secret);

        // If request came from local loopback AND has NO proxy headers, it is a genuine direct local process (e.g. SOC).
        // If it has forwarded headers (e.g. from Nginx), it MUST supply the valid secret key.
        let is_authorized = (addr.ip().is_loopback() && !has_forwarded_header) || has_valid_key;

        if !is_authorized {
            return (
                StatusCode::FORBIDDEN,
                [("Content-Type", "application/json")],
                json!({
                    "waf": "ROKH WAF",
                    "error": "Forbidden",
                    "message": "Access Denied: DDoS management endpoints are restricted to authenticated internal SOC callers."
                })
                .to_string(),
            )
                .into_response();
        }

        if path == "/__aegis_ddos/status" {
            let metrics = state.antiddos.get_metrics();
            return (
                StatusCode::OK,
                [("Content-Type", "application/json")],
                metrics.to_string(),
            )
                .into_response();
        }
        if path == "/__aegis_ddos/toggle" {
            let query = parts.uri.query().unwrap_or("");
            let enable = if query.contains("enable=1") || query.contains("enable=true") {
                state.antiddos.set_under_attack_mode(true);
                true
            } else if query.contains("enable=0") || query.contains("enable=false") {
                state.antiddos.set_under_attack_mode(false);
                false
            } else {
                let current = state
                    .antiddos
                    .under_attack_mode
                    .load(std::sync::atomic::Ordering::Relaxed);
                state.antiddos.set_under_attack_mode(!current);
                !current
            };
            let res = json!({
                "status": "SUCCESS",
                "under_attack_mode": enable
            });
            return (
                StatusCode::OK,
                [("Content-Type", "application/json")],
                res.to_string(),
            )
                .into_response();
        }
        if path == "/__aegis_ddos/unban" {
            let query = parts.uri.query().unwrap_or("");
            let ip_to_unban = query
                .split('&')
                .find_map(|p| {
                    let mut s = p.splitn(2, '=');
                    if s.next()? == "ip" {
                        Some(s.next().unwrap_or(""))
                    } else {
                        None
                    }
                })
                .unwrap_or("");
            let unbanned = state.antiddos.unban_ip(ip_to_unban);
            let res = json!({
                "status": "SUCCESS",
                "ip": ip_to_unban,
                "unbanned": unbanned
            });
            return (
                StatusCode::OK,
                [("Content-Type", "application/json")],
                res.to_string(),
            )
                .into_response();
        }
    }

    // 1.8 Front-Door Fast-Path: Instant drop for Jailed DDoS Flooders in < 0.02ms
    if let Some(remaining_secs) = state.antiddos.is_ip_jailed(&client_ip) {
        state.logger.log_event(LogEntry {
            client_ip: &client_ip,
            method: &method,
            path: &path,
            headers: "{}",
            query_params: query_string.as_deref(),
            body_snippet: None,
            attack_type: AttackType::RateLimit.as_str(),
            rule_id: "DDOS-JAIL-001",
            severity: "CRITICAL",
            action_taken: "BLOCKED",
            status_code: 429,
            blocked_reason: Some("DDoS Flood Protection: Client IP Jailed"),
        });

        let retry_str = remaining_secs.to_string();
        let err_json = json!({
            "waf": "ROKH WAF v1.0",
            "status": "BLOCKED",
            "attack_type": "DDOS_FLOOD_JAIL",
            "rule_id": "DDOS-JAIL-001",
            "client_ip": client_ip,
            "retry_after_seconds": remaining_secs,
            "message": format!("Access Denied: Your IP has been temporarily blacklisted due to high-volume DDoS traffic. Retry after {} seconds.", remaining_secs)
        });

        if is_html_client {
            let html_body = crate::pages::render_security_block_page(
                &format!("ROKH-JAIL-{}", client_ip.replace('.', "")),
                &client_ip,
                "DDOS_FLOOD_MITIGATION",
                "DDOS-JAIL-001",
                "HIGH",
                &format!("Volumetric Rate Limit Exceeded: Jailed for {}s", remaining_secs),
                429,
                &format!("آی‌پی شما به دلیل ارسال بیش از حد و نامتعارف درخواست‌ها به مدت {} ثانیه به صورت موقت در فهرست سیاه قرار گرفته است.", remaining_secs),
            );
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [
                    ("Content-Type", "text/html; charset=utf-8"),
                    ("Retry-After", retry_str.as_str()),
                ],
                html_body,
            )
                .into_response();
        }

        return (
            StatusCode::TOO_MANY_REQUESTS,
            [
                ("Content-Type", "application/json"),
                ("Retry-After", retry_str.as_str()),
            ],
            err_json.to_string(),
        )
            .into_response();
    }

    // 1.9 Proof-of-Work Verification Endpoint
    if path == "/__aegis_verify" {
        return match state.antiddos.check_request(&client_ip, &parts.headers, &parts.uri) {
            DdosVerdict::VerifySuccess(res) => res,
            DdosVerdict::Challenge(res) => res,
            _ => (StatusCode::BAD_REQUEST, "Invalid verification request").into_response(),
        };
    }

    // 3. Inspect User-Agent for known scanners & bad bots
    let user_agent = parts
        .headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let bot_result = state.rules.inspect_user_agent(user_agent);
    if bot_result.is_threat {
        return handle_threat_response(
            &state,
            &client_ip,
            &method,
            &path,
            query_string.as_deref(),
            None,
            bot_result,
            is_html_client,
        )
        .await;
    }

    // 4. Read Request Body (with safety limit)
    let body_bytes = match to_bytes(body, state.config.max_body_size_bytes).await {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                [("Content-Type", "application/json")],
                json!({"error": "Payload exceeds maximum allowed size"}).to_string(),
            )
                .into_response();
        }
    };

    let body_str = String::from_utf8_lossy(&body_bytes);
    let body_snippet = if !body_str.is_empty() {
        let snippet = if body_str.len() > 256 {
            &body_str[..256]
        } else {
            &body_str
        };
        Some(snippet.to_string())
    } else {
        None
    };

    // 5. Deep Inspection with Deobfuscation
    // A) Inspect Path
    let norm_path = Deobfuscator::normalize(&path);
    let path_result = state.rules.inspect(&norm_path);
    if path_result.is_threat {
        return handle_threat_response(
            &state,
            &client_ip,
            &method,
            &path,
            query_string.as_deref(),
            body_snippet.as_deref(),
            path_result,
            is_html_client,
        )
        .await;
    }

    // B) Inspect Query String
    if let Some(ref q) = query_string {
        let norm_query = Deobfuscator::normalize(q);
        let query_result = state.rules.inspect(&norm_query);
        if query_result.is_threat {
            return handle_threat_response(
                &state,
                &client_ip,
                &method,
                &path,
                query_string.as_deref(),
                body_snippet.as_deref(),
                query_result,
                is_html_client,
            )
            .await;
        }
    }

    // C) Inspect Body
    if !body_str.is_empty() {
        let norm_body = Deobfuscator::normalize(&body_str);
        let body_result = state.rules.inspect(&norm_body);
        if body_result.is_threat {
            return handle_threat_response(
                &state,
                &client_ip,
                &method,
                &path,
                query_string.as_deref(),
                body_snippet.as_deref(),
                body_result,
                is_html_client,
            )
            .await;
        }
    }

    // D) Inspect Headers (Cookie, Referer, Origin) to prevent Header Injection & smuggling
    for header_key in &["cookie", "referer", "origin"] {
        if let Some(header_val) = parts.headers.get(*header_key).and_then(|v| v.to_str().ok()) {
            let norm_val = Deobfuscator::normalize(header_val);
            let header_res = state.rules.inspect(&norm_val);
            if header_res.is_threat {
                let trigger_desc = format!("Header [{}]: {}", header_key, header_val);
                return handle_threat_response(
                    &state,
                    &client_ip,
                    &method,
                    &path,
                    query_string.as_deref(),
                    Some(&trigger_desc),
                    header_res,
                    is_html_client,
                )
                .await;
            }
        }
    }

    // 6. Anti-DDoS Traffic Policy (Challenges / Rate-Limit / Dynamic Jail)
    match state.antiddos.check_request(&client_ip, &parts.headers, &parts.uri) {
        DdosVerdict::Challenge(challenge_res) => {
            return challenge_res;
        }
        DdosVerdict::VerifySuccess(verify_res) => {
            return verify_res;
        }
        DdosVerdict::Jailed { remaining_secs } => {
            state.logger.log_event(LogEntry {
                client_ip: &client_ip,
                method: &method,
                path: &path,
                headers: "{}",
                query_params: query_string.as_deref(),
                body_snippet: None,
                attack_type: AttackType::RateLimit.as_str(),
                rule_id: "DDOS-JAIL-001",
                severity: "CRITICAL",
                action_taken: "BLOCKED",
                status_code: 429,
                blocked_reason: Some("DDoS Flood Protection: Client IP Jailed"),
            });

            let retry_str = remaining_secs.to_string();
            let err_json = json!({
                "waf": "ROKH WAF v1.0",
                "status": "BLOCKED",
                "attack_type": "DDOS_FLOOD_JAIL",
                "rule_id": "DDOS-JAIL-001",
                "client_ip": client_ip,
                "retry_after_seconds": remaining_secs,
                "message": format!("Access Denied: Your IP has been temporarily blacklisted due to high-volume DDoS traffic. Retry after {} seconds.", remaining_secs)
            });

            if is_html_client {
                let html_body = crate::pages::render_security_block_page(
                    &format!("ROKH-JAIL-{}", client_ip.replace('.', "")),
                    &client_ip,
                    "DDOS_FLOOD_MITIGATION",
                    "DDOS-JAIL-001",
                    "HIGH",
                    &format!("Volumetric Rate Limit Exceeded: Jailed for {}s", remaining_secs),
                    429,
                    &format!("آی‌پی شما به دلیل ارسال بیش از حد و نامتعارف درخواست‌ها به مدت {} ثانیه به صورت موقت در فهرست سیاه قرار گرفته است.", remaining_secs),
                );
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    [
                        ("Content-Type", "text/html; charset=utf-8"),
                        ("Retry-After", retry_str.as_str()),
                    ],
                    html_body,
                )
                    .into_response();
            }

            return (
                StatusCode::TOO_MANY_REQUESTS,
                [
                    ("Content-Type", "application/json"),
                    ("Retry-After", retry_str.as_str()),
                ],
                err_json.to_string(),
            )
                .into_response();
        }
        DdosVerdict::Allow => {
            // Traffic allowed through to target backend!
        }
    }

    // 7. Request is CLEAN: Log & Forward to Target Backend
    state.logger.log_event(LogEntry {
        client_ip: &client_ip,
        method: &method,
        path: &path,
        headers: "{}",
        query_params: query_string.as_deref(),
        body_snippet: body_snippet.as_deref(),
        attack_type: AttackType::Clean.as_str(),
        rule_id: "NONE",
        severity: "INFO",
        action_taken: "PASSED",
        status_code: 200,
        blocked_reason: None,
    });

    forward_to_backend(&state, parts.method, &path, query_string.as_deref(), parts.headers, body_bytes, &client_ip).await
}

async fn handle_threat_response(
    state: &Arc<AppState>,
    client_ip: &str,
    method: &str,
    path: &str,
    query_params: Option<&str>,
    body_snippet: Option<&str>,
    detection: DetectionResult,
    is_html_client: bool,
) -> Response {
    let mode_str = state.logger.get_config_mode();
    let current_mode = WafMode::from(mode_str.as_str());

    let (action_taken, status_code) = match current_mode {
        WafMode::Prevention => ("BLOCKED", 403),
        WafMode::Detection => ("FLAGGED", 200),
    };

    let incident_id = format!("SEC-{}", &chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0));

    state.logger.log_event(LogEntry {
        client_ip,
        method,
        path,
        headers: "{}",
        query_params,
        body_snippet,
        attack_type: detection.attack_type.as_str(),
        rule_id: detection.rule_id,
        severity: detection.severity,
        action_taken,
        status_code,
        blocked_reason: Some(&detection.matched_pattern),
    });

    if current_mode == WafMode::Prevention {
        let err_json = json!({
            "waf": "ROKH WAF v1.0",
            "status": "BLOCKED",
            "incident_id": incident_id,
            "attack_type": detection.attack_type.as_str(),
            "rule_id": detection.rule_id,
            "severity": detection.severity,
            "client_ip": client_ip,
            "matched_trigger": detection.matched_pattern,
            "message": "Access Denied: Malicious request blocked by ROKH WAF Security Core."
        });

        if is_html_client {
            let html_body = crate::pages::render_security_block_page(
                &incident_id,
                client_ip,
                detection.attack_type.as_str(),
                detection.rule_id,
                detection.severity,
                &detection.matched_pattern,
                403,
                "بسته ارسالی با پایگاه امضاها و الگوهای ضد نفوذ OWASP CRS مطابقت داشته و بلافاصله دفع شد.",
            );
            return (
                StatusCode::FORBIDDEN,
                [
                    ("Content-Type", "text/html; charset=utf-8"),
                    ("X-WAF-Incident-ID", incident_id.as_str()),
                ],
                html_body,
            )
                .into_response();
        }

        return (
            StatusCode::FORBIDDEN,
            [
                ("Content-Type", "application/json"),
                ("X-WAF-Incident-ID", incident_id.as_str()),
            ],
            err_json.to_string(),
        )
            .into_response();
    }

    // In Detection/Monitor mode, log but proceed to forward
    (
        StatusCode::OK,
        [("X-WAF-Flagged", "true")],
        "Request flagged by ROKH WAF Monitor Mode",
    )
        .into_response()
}

async fn forward_to_backend(
    state: &Arc<AppState>,
    method: axum::http::Method,
    path: &str,
    query: Option<&str>,
    headers: HeaderMap,
    body: Bytes,
    client_ip: &str,
) -> Response {
    let mut target_url = format!("{}{}", state.config.backend_url, path);
    if let Some(q) = query {
        target_url.push('?');
        target_url.push_str(q);
    }

    let mut req_builder = state.http_client.request(
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap(),
        &target_url,
    );

    // Forward relevant headers while avoiding hop-by-hop conflicts
    for (name, val) in headers.iter() {
        let name_str = name.as_str().to_lowercase();
        if name_str != "host" && name_str != "connection" && name_str != "transfer-encoding" {
            if let Ok(v) = val.to_str() {
                req_builder = req_builder.header(name.as_str(), v);
            }
        }
    }

    // Standard reverse proxy headers for backend origin awareness
    req_builder = req_builder
        .header("X-Forwarded-For", client_ip)
        .header("X-Real-IP", client_ip)
        .header("X-Forwarded-Proto", "http");

    req_builder = req_builder.body(body);

    match req_builder.send().await {
        Ok(backend_res) => {
            let status = StatusCode::from_u16(backend_res.status().as_u16())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

            let mut response_builder = Response::builder().status(status);

            for (k, v) in backend_res.headers() {
                let k_str = k.as_str().to_lowercase();
                if k_str != "connection" && k_str != "transfer-encoding" {
                    response_builder = response_builder.header(k.as_str(), v.as_bytes());
                }
            }

            // Inject security headers on outgoing traffic
            response_builder = response_builder
                .header("X-Protected-By", "ROKH-WAF/1.0")
                .header("X-Content-Type-Options", "nosniff")
                .header("X-Frame-Options", "DENY");

            let res_bytes = backend_res.bytes().await.unwrap_or_default();
            response_builder
                .body(Body::from(res_bytes))
                .unwrap_or_else(|_| (StatusCode::BAD_GATEWAY, "Response Build Error").into_response())
        }
        Err(err) => {
            let err_body = json!({
                "waf": "ROKH WAF v1.0",
                "error": "Bad Gateway",
                "message": format!("Backend service unavailable at {}: {}", target_url, err)
            });
            (
                StatusCode::BAD_GATEWAY,
                [("Content-Type", "application/json")],
                err_body.to_string(),
            )
                .into_response()
        }
    }
}
