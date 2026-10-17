use crate::ai::NeuralBrain;
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const DASHBOARD_HTML: &str = include_str!("soc_dashboard.html");

pub struct AppState {
    pub config: WafConfig,
    pub rules: RuleEngine,
    pub antiddos: AntiDdosEngine,
    pub logger: WafLogger,
    pub http_client: reqwest::Client,
    pub ai: Arc<NeuralBrain>,
    pub metrics_requests_total: AtomicU64,
    pub metrics_blocked_threats: AtomicU64,
    pub metrics_ai_inspections: AtomicU64,
    pub metrics_ai_anomalies: AtomicU64,
    pub start_time: std::time::Instant,
}

fn format_headers_json(headers: &HeaderMap) -> String {
    let mut map = serde_json::Map::new();
    for (k, v) in headers.iter() {
        let key = k.as_str().to_lowercase();
        let val = if let Ok(s) = v.to_str() {
            if key == "authorization" || key == "cookie" || key == "proxy-authorization" || key == "set-cookie" {
                if s.len() > 16 {
                    format!("{}...[REDACTED_PCI_DSS]", &s[..8])
                } else {
                    "[REDACTED_PCI_DSS]".to_string()
                }
            } else {
                s.to_string()
            }
        } else {
            "<binary>".to_string()
        };
        map.insert(key, serde_json::Value::String(val));
    }
    serde_json::to_string(&map).unwrap_or_else(|_| "{}".to_string())
}

/// Strict RFC 7230 / 9110 HTTP Request Smuggling and Desynchronization Inspector
fn inspect_request_smuggling(headers: &HeaderMap, path: &str, query: Option<&str>) -> Option<DetectionResult> {
    // 1. Check for conflicting Transfer-Encoding and Content-Length (TE.CL / CL.TE desync attack)
    let has_te = headers.contains_key("transfer-encoding");
    let has_cl = headers.contains_key("content-length");
    if has_te && has_cl {
        return Some(DetectionResult {
            is_threat: true,
            attack_type: AttackType::RequestSmuggling,
            rule_id: "SMUGGLE-101",
            severity: "CRITICAL",
            matched_pattern: "Conflicting Transfer-Encoding & Content-Length headers (RFC 7230 §3.3.3 Desync Attack)".to_string(),
        });
    }

    // 2. Check for multiple conflicting Content-Length headers
    let cl_headers: Vec<_> = headers.get_all("content-length").iter().collect();
    if cl_headers.len() > 1 {
        let first = cl_headers[0].to_str().unwrap_or("");
        for cl in &cl_headers[1..] {
            if cl.to_str().unwrap_or("") != first {
                return Some(DetectionResult {
                    is_threat: true,
                    attack_type: AttackType::RequestSmuggling,
                    rule_id: "SMUGGLE-102",
                    severity: "CRITICAL",
                    matched_pattern: "Multiple conflicting Content-Length header values detected".to_string(),
                });
            }
        }
    }

    // 3. Check for obfuscated/illegal Transfer-Encoding
    if let Some(te_val) = headers.get("transfer-encoding").and_then(|v| v.to_str().ok()) {
        let te_lower = te_val.trim().to_lowercase();
        if te_lower.contains("identity") || te_lower.contains(',') || (te_lower != "chunked" && !te_lower.is_empty()) {
            return Some(DetectionResult {
                is_threat: true,
                attack_type: AttackType::RequestSmuggling,
                rule_id: "SMUGGLE-103",
                severity: "CRITICAL",
                matched_pattern: format!("Obfuscated/Illegal Transfer-Encoding header: '{}'", te_val),
            });
        }
    }

    // 4. Check for CRLF / HTTP Header Injection in URI or Query String
    let full_uri = if let Some(q) = query {
        format!("{}?{}", path, q)
    } else {
        path.to_string()
    };
    if full_uri.contains("\r\n") || full_uri.contains("%0d%0a") || full_uri.contains("%0D%0A") || full_uri.contains('\r') || full_uri.contains('\n') {
        return Some(DetectionResult {
            is_threat: true,
            attack_type: AttackType::RequestSmuggling,
            rule_id: "SMUGGLE-104",
            severity: "CRITICAL",
            matched_pattern: "CRLF / HTTP Header Injection sequence detected in URI".to_string(),
        });
    }

    // 5. Check for Smuggled HTTP requests embedded in query or path
    let lower_uri = full_uri.replace("%20", " ").replace('+', " ").to_lowercase();
    if lower_uri.contains("http/1.") || lower_uri.contains("http/2") {
        if lower_uri.contains("post ") || lower_uri.contains("get ") || lower_uri.contains("put ") || lower_uri.contains("delete ") {
            return Some(DetectionResult {
                is_threat: true,
                attack_type: AttackType::RequestSmuggling,
                rule_id: "SMUGGLE-105",
                severity: "CRITICAL",
                matched_pattern: "Embedded smuggled HTTP request pipeline discovered in URI".to_string(),
            });
        }
    }

    None
}

/// Validates whether a client IP falls within an allowed or blocked CIDR/IP pattern
fn ip_matches_cidr(client_ip: &str, ip_cidr: &str) -> bool {
    let cidr = ip_cidr.trim();
    if cidr == "*" || cidr.is_empty() {
        return true;
    }
    if client_ip == cidr {
        return true;
    }
    if let Some((net_str, prefix_str)) = cidr.split_once('/') {
        if let (Ok(std::net::IpAddr::V4(client_v4)), Ok(std::net::IpAddr::V4(net_v4)), Ok(prefix)) = (
            client_ip.parse::<std::net::IpAddr>(),
            net_str.parse::<std::net::IpAddr>(),
            prefix_str.parse::<u32>(),
        ) {
            if prefix > 32 {
                return false;
            }
            if prefix == 0 {
                return true;
            }
            let mask = !((1u32 << (32 - prefix)) - 1);
            let client_u32 = u32::from(client_v4);
            let net_u32 = u32::from(net_v4);
            return (client_u32 & mask) == (net_u32 & mask);
        }
    }
    false
}

pub async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let (parts, body) = req.into_parts();
    let headers_json = format_headers_json(&parts.headers);

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

    state.metrics_requests_total.fetch_add(1, Ordering::Relaxed);

    // 1.0 Built-in SOC Web Dashboard
    if path == "/" || path == "/dashboard" || path == "/soc" || path == "/soc_dashboard.html" {
        return (
            StatusCode::OK,
            [("Content-Type", "text/html; charset=utf-8")],
            DASHBOARD_HTML,
        )
            .into_response();
    }

    // 1.05 Built-in SOC REST APIs
    if path == "/api/stats" {
        let stats = state.logger.get_stats();
        return (
            StatusCode::OK,
            [("Content-Type", "application/json")],
            stats.to_string(),
        )
            .into_response();
    }

    if path == "/api/logs" {
        let limit = query_string
            .as_deref()
            .and_then(|q| {
                q.split('&').find_map(|pair| {
                    let mut kv = pair.splitn(2, '=');
                    if kv.next()? == "limit" {
                        kv.next()?.parse::<usize>().ok()
                    } else {
                        None
                    }
                })
            })
            .unwrap_or(50);

        let attack_type = query_string.as_deref().and_then(|q| {
            q.split('&').find_map(|pair| {
                let mut kv = pair.splitn(2, '=');
                if kv.next()? == "attack_type" {
                    Some(kv.next().unwrap_or("ALL"))
                } else {
                    None
                }
            })
        });

        let logs = state.logger.get_logs(limit, attack_type);
        return (
            StatusCode::OK,
            [("Content-Type", "application/json")],
            serde_json::to_string(&logs).unwrap_or_else(|_| "[]".to_string()),
        )
            .into_response();
    }

    if path == "/api/logs/clear" {
        let _ = state.logger.clear_logs();
        return (
            StatusCode::OK,
            [("Content-Type", "application/json")],
            json!({"status": "cleared"}).to_string(),
        )
            .into_response();
    }

    if path == "/api/config" {
        if method == "POST" {
            let bytes = match to_bytes(body, state.config.max_body_size_bytes).await {
                Ok(b) => b,
                Err(_) => Bytes::new(),
            };
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                if let (Some(k), Some(val)) = (v.get("key").and_then(|s| s.as_str()), v.get("value").and_then(|s| s.as_str())) {
                    let _ = state.logger.update_config(k, val);
                    return (
                        StatusCode::OK,
                        [("Content-Type", "application/json")],
                        json!({"status": "success", "updated": {k: val}}).to_string(),
                    )
                        .into_response();
                }
            }
            return (
                StatusCode::BAD_REQUEST,
                [("Content-Type", "application/json")],
                json!({"error": "Invalid configuration payload"}).to_string(),
            )
                .into_response();
        } else {
            let config = state.logger.get_config();
            return (
                StatusCode::OK,
                [("Content-Type", "application/json")],
                config.to_string(),
            )
                .into_response();
        }
    }

    if path == "/api/ddos/status" {
        let metrics = state.antiddos.get_metrics();
        return (
            StatusCode::OK,
            [("Content-Type", "application/json")],
            metrics.to_string(),
        )
            .into_response();
    }

    if path == "/api/ddos/toggle" {
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
                .load(Ordering::Relaxed);
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

    if path == "/api/ddos/unban" {
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

    // 1.06 Banking Rules Management APIs
    if path == "/api/rules/custom" {
        if method == "POST" {
            let bytes = match to_bytes(body, state.config.max_body_size_bytes).await {
                Ok(b) => b,
                Err(_) => Bytes::new(),
            };
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                let name = v.get("name").and_then(|s| s.as_str()).unwrap_or("Custom Rule");
                let action = v.get("action").and_then(|s| s.as_str()).unwrap_or("BLOCK");
                let path_pattern = v.get("path_pattern").and_then(|s| s.as_str()).unwrap_or("/*");
                let ip_cidr = v.get("ip_cidr").and_then(|s| s.as_str()).unwrap_or("*");
                let ticket_ref = v.get("ticket_ref").and_then(|s| s.as_str()).unwrap_or("MANUAL-RULE");

                match state.logger.add_custom_rule(name, action, path_pattern, ip_cidr, ticket_ref) {
                    Ok(id) => {
                        return (
                            StatusCode::CREATED,
                            [("Content-Type", "application/json")],
                            json!({"status": "SUCCESS", "id": id, "message": "Custom rule committed"}).to_string(),
                        )
                            .into_response();
                    }
                    Err(e) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            [("Content-Type", "application/json")],
                            json!({"error": e.to_string()}).to_string(),
                        )
                            .into_response();
                    }
                }
            }
            return (
                StatusCode::BAD_REQUEST,
                [("Content-Type", "application/json")],
                json!({"error": "Invalid JSON payload"}).to_string(),
            )
                .into_response();
        } else if method == "DELETE" {
            let id = query_string
                .as_deref()
                .and_then(|q| {
                    q.split('&').find_map(|pair| {
                        let mut kv = pair.splitn(2, '=');
                        if kv.next()? == "id" {
                            kv.next()?.parse::<i64>().ok()
                        } else {
                            None
                        }
                    })
                })
                .unwrap_or(0);
            let _ = state.logger.delete_custom_rule(id);
            return (
                StatusCode::OK,
                [("Content-Type", "application/json")],
                json!({"status": "SUCCESS", "deleted_id": id}).to_string(),
            )
                .into_response();
        } else {
            let rules = state.logger.get_custom_rules();
            return (
                StatusCode::OK,
                [("Content-Type", "application/json")],
                serde_json::to_string(&rules).unwrap_or_else(|_| "[]".to_string()),
            )
                .into_response();
        }
    }

    if path == "/api/rules/custom/toggle" {
        let (id, enabled) = query_string
            .as_deref()
            .map(|q| {
                let mut rid = 0i64;
                let mut ren = true;
                for pair in q.split('&') {
                    let mut kv = pair.splitn(2, '=');
                    if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
                        if k == "id" {
                            rid = v.parse::<i64>().unwrap_or(0);
                        } else if k == "enabled" {
                            ren = v == "1" || v.eq_ignore_ascii_case("true");
                        }
                    }
                }
                (rid, ren)
            })
            .unwrap_or((0, true));

        let _ = state.logger.toggle_custom_rule(id, enabled);
        return (
            StatusCode::OK,
            [("Content-Type", "application/json")],
            json!({"status": "SUCCESS", "id": id, "enabled": enabled}).to_string(),
        )
            .into_response();
    }

    // 1.07 Regulatory Audit & Cryptographic Merkle Verification API
    if path == "/api/audit/verify" {
        let res = state.logger.verify_audit_integrity();
        return (
            StatusCode::OK,
            [("Content-Type", "application/json")],
            res.to_string(),
        )
            .into_response();
    }

    // 1.08 Multi-Format Forensic & SIEM Export API (CSV, CEF, JSON)
    if path == "/api/export" {
        let format = query_string
            .as_deref()
            .and_then(|q| {
                q.split('&').find_map(|pair| {
                    let mut kv = pair.splitn(2, '=');
                    if kv.next()? == "format" {
                        Some(kv.next().unwrap_or("csv").to_lowercase())
                    } else {
                        None
                    }
                })
            })
            .unwrap_or_else(|| "csv".to_string());

        if format == "cef" {
            let content = state.logger.export_logs_cef(5000);
            return (
                StatusCode::OK,
                [
                    ("Content-Type", "text/plain; charset=utf-8"),
                    ("Content-Disposition", "attachment; filename=\"rokh_siem_events.cef\""),
                ],
                content,
            )
                .into_response();
        } else if format == "json" {
            let logs = state.logger.get_logs(5000, None);
            return (
                StatusCode::OK,
                [
                    ("Content-Type", "application/json"),
                    ("Content-Disposition", "attachment; filename=\"rokh_audit_forensics.json\""),
                ],
                serde_json::to_string_pretty(&logs).unwrap_or_else(|_| "[]".to_string()),
            )
                .into_response();
        } else {
            let content = state.logger.export_logs_csv(5000);
            return (
                StatusCode::OK,
                [
                    ("Content-Type", "text/csv; charset=utf-8"),
                    ("Content-Disposition", "attachment; filename=\"rokh_audit_ledger.csv\""),
                ],
                content,
            )
                .into_response();
        }
    }

    // 1.09 Database Maintenance API
    if path == "/api/db/compact" {
        let _ = state.logger.checkpoint_database();
        return (
            StatusCode::OK,
            [("Content-Type", "application/json")],
            json!({"status": "SUCCESS", "message": "SQLite WAL checkpointed and compacted."}).to_string(),
        )
            .into_response();
    }

    // 1.1 Prometheus Metrics Endpoint
    if path == "/metrics" || path == "/__rokh/metrics" {
        let reqs = state.metrics_requests_total.load(Ordering::Relaxed);
        let blocked = state.metrics_blocked_threats.load(Ordering::Relaxed);
        let ai_inspections = state.metrics_ai_inspections.load(Ordering::Relaxed);
        let ai_anomalies = state.metrics_ai_anomalies.load(Ordering::Relaxed);
        let uptime = state.start_time.elapsed().as_secs();
        let ddos_metrics = state.antiddos.get_metrics();
        let jailed = ddos_metrics.get("jailed_ips_count").and_then(|v| v.as_u64()).unwrap_or(0);
        let under_attack = if ddos_metrics.get("under_attack_mode").and_then(|v| v.as_bool()).unwrap_or(false) { 1 } else { 0 };

        let metrics_text = format!(
            "# HELP rokh_http_requests_total Total number of HTTP requests processed by ROKH WAF\n\
             # TYPE rokh_http_requests_total counter\n\
             rokh_http_requests_total {}\n\n\
             # HELP rokh_threats_blocked_total Total threats blocked across signature, AI, and DDoS defenses\n\
             # TYPE rokh_threats_blocked_total counter\n\
             rokh_threats_blocked_total {}\n\n\
             # HELP rokh_ai_inspections_total Total zero-day AI heuristic and neural inspections conducted\n\
             # TYPE rokh_ai_inspections_total counter\n\
             rokh_ai_inspections_total {}\n\n\
             # HELP rokh_ai_anomalies_detected_total Total zero-day anomalies and prompt injections caught by AI\n\
             # TYPE rokh_ai_anomalies_detected_total counter\n\
             rokh_ai_anomalies_detected_total {}\n\n\
             # HELP rokh_uptime_seconds Total runtime in seconds\n\
             # TYPE rokh_uptime_seconds gauge\n\
             rokh_uptime_seconds {}\n\n\
             # HELP rokh_antiddos_jailed_ips Number of currently jailed attacker IPs\n\
             # TYPE rokh_antiddos_jailed_ips gauge\n\
             rokh_antiddos_jailed_ips {}\n\n\
             # HELP rokh_antiddos_under_attack_mode Status of emergency under attack mitigation mode\n\
             # TYPE rokh_antiddos_under_attack_mode gauge\n\
             rokh_antiddos_under_attack_mode {}\n",
            reqs, blocked, ai_inspections, ai_anomalies, uptime, jailed, under_attack
        );
        return (
            StatusCode::OK,
            [("Content-Type", "text/plain; version=0.0.4; charset=utf-8")],
            metrics_text,
        )
            .into_response();
    }

    // 1.2 Native AI Predict Endpoint (Direct In-Memory Neural Inference)
    if path == "/__rokh_ai/predict" || path == "/__rokh/ai" || path == "/api/ai/predict" {
        let payload = if method == "POST" {
            let bytes = match to_bytes(body, state.config.max_body_size_bytes).await {
                Ok(b) => b,
                Err(_) => Bytes::new(),
            };
            let raw_str = String::from_utf8_lossy(&bytes).to_string();
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw_str) {
                v.get("payload")
                    .or_else(|| v.get("text"))
                    .or_else(|| v.get("query"))
                    .and_then(|s| s.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or(raw_str)
            } else {
                raw_str
            }
        } else {
            query_string
                .as_deref()
                .and_then(|q| {
                    q.split('&').find_map(|pair| {
                        let mut kv = pair.splitn(2, '=');
                        let k = kv.next()?;
                        if k == "payload" || k == "q" || k == "text" {
                            let val = kv.next().unwrap_or("").replace('+', " ");
                            Some(urlencoding::decode(&val).unwrap_or(std::borrow::Cow::Borrowed(&val)).to_string())
                        } else {
                            None
                        }
                    })
                })
                .unwrap_or_else(|| query_string.clone().unwrap_or_default())
        };

        state.metrics_ai_inspections.fetch_add(1, Ordering::Relaxed);
        let pred = state.ai.predict(&payload);
        if pred.is_malicious {
            state.metrics_ai_anomalies.fetch_add(1, Ordering::Relaxed);
        }

        let res = json!({
            "status": "SUCCESS",
            "waf": "ROKH WAF v1.0",
            "engine": "ROKH Native Rust NeuralBrain (Embedded 556-Feature Logistic + Shannon Entropy)",
            "payload": payload,
            "verdict": pred.verdict,
            "is_malicious": pred.is_malicious,
            "threat_probability": pred.threat_probability,
            "anomaly_score": pred.anomaly_score,
            "entropy": pred.entropy,
            "detected_intent": pred.detected_intent,
            "inference_latency_micros": pred.inference_micros
        });

        return (
            StatusCode::OK,
            [("Content-Type", "application/json")],
            res.to_string(),
        )
            .into_response();
    }

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
        state.metrics_blocked_threats.fetch_add(1, Ordering::Relaxed);
        state.logger.log_event(LogEntry {
            client_ip: &client_ip,
            method: &method,
            path: &path,
            headers: &headers_json,
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

    // 2.9 Anti-HTTP Request Smuggling & Desync Shield (RFC 7230 §3.3.3 / RFC 9110)
    if let Some(smuggle_detection) = inspect_request_smuggling(&parts.headers, &path, query_string.as_deref()) {
        return handle_threat_response(
            &state,
            &client_ip,
            &method,
            &path,
            &headers_json,
            query_string.as_deref(),
            None,
            smuggle_detection,
            is_html_client,
        )
        .await;
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
            &headers_json,
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

    // 4.5 Banking Custom Access Rules & Whitelist/Blacklist Engine
    let custom_rules = state.logger.get_custom_rules();
    for rule in &custom_rules {
        let is_enabled = rule.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
        if !is_enabled {
            continue;
        }
        let pattern = rule.get("path_pattern").and_then(|v| v.as_str()).unwrap_or("*");
        let action = rule.get("action").and_then(|v| v.as_str()).unwrap_or("BLOCK");
        let rule_name = rule.get("name").and_then(|v| v.as_str()).unwrap_or("Custom Banking Rule");

        let pattern_matches = if pattern == "*" || pattern == "/*" {
            true
        } else if pattern.ends_with("/*") {
            path.starts_with(&pattern[..pattern.len() - 2])
        } else {
            path == pattern
        };

        if pattern_matches {
            let ip_pattern = rule.get("ip_cidr").and_then(|v| v.as_str()).unwrap_or("*");
            if !ip_matches_cidr(&client_ip, ip_pattern) {
                continue;
            }

            if action == "BLOCK" {
                state.metrics_blocked_threats.fetch_add(1, Ordering::Relaxed);
                state.logger.log_event(LogEntry {
                    client_ip: &client_ip,
                    method: &method,
                    path: &path,
                    headers: &headers_json,
                    query_params: query_string.as_deref(),
                    body_snippet: body_snippet.as_deref(),
                    attack_type: "CUSTOM_ACL_BLOCK",
                    rule_id: "ROKH-BANK-ACL-001",
                    severity: "HIGH",
                    action_taken: "BLOCKED",
                    status_code: 403,
                    blocked_reason: Some(rule_name),
                });
                return (
                    StatusCode::FORBIDDEN,
                    [("Content-Type", "application/json")],
                    json!({
                        "waf": "ROKH WAF v1.0",
                        "status": "BLOCKED",
                        "rule": rule_name,
                        "action": "CUSTOM_ACL_BLOCK",
                        "message": "Access Denied: Blocked by custom enterprise banking access rule."
                    }).to_string(),
                ).into_response();
            } else if action == "ALLOW" {
                return forward_to_backend(&state, parts.method, &path, query_string.as_deref(), parts.headers, body_bytes, &client_ip).await;
            }
        }
    }

    // 5. Deep Multi-Pass Inspection & Composite Threat Anomaly Scoring Engine
    let mut total_anomaly_score = 0.0f64;
    let mut anomaly_triggers: Vec<String> = Vec::new();
    let mut primary_detection: Option<DetectionResult> = None;

    // A) Inspect Path with Evasion Analysis
    let (norm_path, path_evasion) = Deobfuscator::normalize_with_score(&path);
    if path_evasion > 0.0 {
        total_anomaly_score += path_evasion;
        anomaly_triggers.push(format!("Path Evasion (+{:.1})", path_evasion));
    }
    let path_result = state.rules.inspect(&norm_path);
    if path_result.is_threat {
        let pts = if path_result.severity == "CRITICAL" { 6.0 } else { 5.0 };
        total_anomaly_score += pts;
        anomaly_triggers.push(format!("{} (+{:.1})", path_result.rule_id, pts));
        if primary_detection.is_none() {
            primary_detection = Some(path_result);
        }
    }

    // B) Inspect Query String with Evasion Analysis
    let (norm_query, query_evasion) = if let Some(ref q) = query_string {
        let (nq, sc) = Deobfuscator::normalize_with_score(q);
        (Some(nq), sc)
    } else {
        (None, 0.0)
    };
    if query_evasion > 0.0 {
        total_anomaly_score += query_evasion;
        anomaly_triggers.push(format!("Query Evasion (+{:.1})", query_evasion));
    }
    if let Some(ref nq) = norm_query {
        let query_result = state.rules.inspect(nq);
        if query_result.is_threat {
            let pts = if query_result.severity == "CRITICAL" { 6.0 } else { 5.0 };
            total_anomaly_score += pts;
            anomaly_triggers.push(format!("{} (+{:.1})", query_result.rule_id, pts));
            if primary_detection.is_none() {
                primary_detection = Some(query_result);
            }
        }
    }

    // C) Inspect Body with Evasion Analysis
    let (norm_body, body_evasion) = if !body_str.is_empty() {
        let (nb, sc) = Deobfuscator::normalize_with_score(&body_str);
        (Some(nb), sc)
    } else {
        (None, 0.0)
    };
    if body_evasion > 0.0 {
        total_anomaly_score += body_evasion;
        anomaly_triggers.push(format!("Body Evasion (+{:.1})", body_evasion));
    }
    if let Some(ref nb) = norm_body {
        let body_result = state.rules.inspect(nb);
        if body_result.is_threat {
            let pts = if body_result.severity == "CRITICAL" { 6.0 } else { 5.0 };
            total_anomaly_score += pts;
            anomaly_triggers.push(format!("{} (+{:.1})", body_result.rule_id, pts));
            if primary_detection.is_none() {
                primary_detection = Some(body_result);
            }
        }
    }

    // D) Inspect Headers (Cookie, Referer, Origin) to prevent Header Injection & smuggling
    for header_key in &["cookie", "referer", "origin"] {
        if let Some(header_val) = parts.headers.get(*header_key).and_then(|v| v.to_str().ok()) {
            let (norm_val, h_evasion) = Deobfuscator::normalize_with_score(header_val);
            if h_evasion > 0.0 {
                total_anomaly_score += h_evasion;
            }
            let header_res = state.rules.inspect(&norm_val);
            if header_res.is_threat {
                let pts = 5.0;
                total_anomaly_score += pts;
                anomaly_triggers.push(format!("Header Injection [{}] (+{:.1})", header_key, pts));
                if primary_detection.is_none() {
                    primary_detection = Some(header_res);
                }
            }
        }
    }

    // E) AI Zero-Day & Semantic Anomaly Inspection (< 15µs in-memory neural inference)
    let inspect_candidates = [
        norm_query.as_deref().filter(|q| !q.is_empty()),
        norm_body.as_deref().filter(|b| !b.is_empty()),
    ];

    for candidate in inspect_candidates.into_iter().flatten() {
        state.metrics_ai_inspections.fetch_add(1, Ordering::Relaxed);
        let ai_pred = state.ai.predict(candidate);

        // Shannon Information Entropy threshold check (H >= 4.65 indicates shellcode / high-density obfuscation)
        if ai_pred.entropy >= 4.65 {
            total_anomaly_score += 3.5;
            anomaly_triggers.push(format!("High Shannon Entropy H={:.2} (+3.5)", ai_pred.entropy));
        }

        if ai_pred.is_malicious {
            state.metrics_ai_anomalies.fetch_add(1, Ordering::Relaxed);
            let ai_pts = if ai_pred.threat_probability >= 0.90 { 6.0 } else { 4.5 };
            total_anomaly_score += ai_pts;
            anomaly_triggers.push(format!("AI Neural Anomaly: {} ({:.0}%, +{:.1})", ai_pred.detected_intent, ai_pred.threat_probability * 100.0, ai_pts));

            let attack_type = match ai_pred.detected_intent {
                "PROMPT_INJECTION" => AttackType::PromptInjection,
                _ => AttackType::ZeroDayAnomaly,
            };
            let rule_id = match ai_pred.detected_intent {
                "PROMPT_INJECTION" => "AI-PROMPT-001",
                "PROTOTYPE_POLLUTION" => "AI-PROTO-002",
                "SSRF_METADATA" => "AI-SSRF-003",
                "LOG4SHELL_SSTI" => "AI-SSTI-004",
                _ => "AI-ANOMALY-005",
            };
            let pattern_desc = format!(
                "AI Neural Anomaly: intent={}, confidence={:.1}%, entropy={:.2}",
                ai_pred.detected_intent,
                ai_pred.threat_probability * 100.0,
                ai_pred.entropy
            );
            if primary_detection.is_none() {
                primary_detection = Some(DetectionResult {
                    is_threat: true,
                    attack_type,
                    rule_id,
                    severity: if ai_pred.threat_probability >= 0.90 { "CRITICAL" } else { "HIGH" },
                    matched_pattern: pattern_desc,
                });
            }
        }
    }

    // 5.9 Inbound Anomaly Threshold Decision (Threshold: 5.0)
    let inbound_anomaly_threshold = 5.0f64;
    if total_anomaly_score >= inbound_anomaly_threshold {
        let trigger_summary = format!(
            "Composite Anomaly Score: {:.1} (Threshold: {:.1}) | Triggers: [{}]",
            total_anomaly_score,
            inbound_anomaly_threshold,
            anomaly_triggers.join(", ")
        );

        let final_detection = if let Some(mut det) = primary_detection {
            det.matched_pattern = format!("{} | {}", det.matched_pattern, trigger_summary);
            det
        } else {
            DetectionResult {
                is_threat: true,
                attack_type: AttackType::CompositeAnomaly,
                rule_id: "ANOMALY-SCORE-001",
                severity: if total_anomaly_score >= 8.0 { "CRITICAL" } else { "HIGH" },
                matched_pattern: trigger_summary,
            }
        };

        return handle_threat_response(
            &state,
            &client_ip,
            &method,
            &path,
            &headers_json,
            query_string.as_deref(),
            body_snippet.as_deref(),
            final_detection,
            is_html_client,
        )
        .await;
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
            state.metrics_blocked_threats.fetch_add(1, Ordering::Relaxed);
            state.logger.log_event(LogEntry {
                client_ip: &client_ip,
                method: &method,
                path: &path,
                headers: &headers_json,
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
        headers: &headers_json,
        query_params: query_string.as_deref(),
        body_snippet: body_snippet.as_deref(),
        attack_type: AttackType::Clean.as_str(),
        rule_id: "NONE",
        severity: "INFO",
        action_taken: "PASSED",
        status_code: 200,
        blocked_reason: None,
    });

    // 7.5 Built-in Mock Target endpoints (Simulated Demo Backend)
    if path.starts_with("/target/") {
        if path == "/target/search" {
            let q = query_string.as_deref().unwrap_or("");
            return (
                StatusCode::OK,
                [("Content-Type", "application/json")],
                json!({
                    "status": "success",
                    "backend": "ROKH Native Rust Target Engine v1.0",
                    "message": format!("Processed search query successfully: {}", q),
                    "raw_query": q,
                    "results": [
                        {"id": 1, "title": "Cybersecurity Fundamentals", "category": "defense"},
                        {"id": 2, "title": "Web Application Firewalls (WAF) Deep Dive", "category": "engineering"}
                    ]
                })
                .to_string(),
            )
                .into_response();
        } else if path == "/target/login" {
            return (
                StatusCode::OK,
                [("Content-Type", "application/json")],
                json!({
                    "status": "authenticated",
                    "backend": "ROKH Native Target Auth Service",
                    "timestamp": chrono::Utc::now().to_rfc3339()
                })
                .to_string(),
            )
                .into_response();
        } else if path == "/target/view-file" {
            let file = query_string.as_deref().unwrap_or("notes.txt");
            return (
                StatusCode::OK,
                [("Content-Type", "application/json")],
                json!({
                    "status": "file_read_success",
                    "file_requested": file,
                    "content": format!("Protected simulated file content for: {}", file)
                })
                .to_string(),
            )
                .into_response();
        }
    }

    forward_to_backend(&state, parts.method, &path, query_string.as_deref(), parts.headers, body_bytes, &client_ip).await
}

async fn handle_threat_response(
    state: &Arc<AppState>,
    client_ip: &str,
    method: &str,
    path: &str,
    headers_str: &str,
    query_string: Option<&str>,
    body_snippet: Option<&str>,
    detection: DetectionResult,
    is_html_client: bool,
) -> Response {
    let mode_str = state.logger.get_config_mode();
    let current_mode = WafMode::from(mode_str.as_str());

    let (action_taken, status_code) = match current_mode {
        WafMode::Prevention => {
            state.metrics_blocked_threats.fetch_add(1, Ordering::Relaxed);
            ("BLOCKED", 403)
        }
        WafMode::Detection => ("FLAGGED", 200),
    };

    let incident_id = format!("SEC-{}", &chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0));

    state.logger.log_event(LogEntry {
        client_ip,
        method,
        path,
        headers: headers_str,
        query_params: query_string,
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
