use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WafMode {
    Prevention, // Blocks attacks with 403 Forbidden
    Detection,  // Logs attacks but allows request to reach backend
}

impl Default for WafMode {
    fn default() -> Self {
        WafMode::Prevention
    }
}

impl From<&str> for WafMode {
    fn from(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "DETECTION" => WafMode::Detection,
            _ => WafMode::Prevention,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WafConfig {
    pub listen_addr: SocketAddr,
    pub backend_url: String,
    pub db_path: String,
    pub mode: WafMode,
    pub rate_limit_rpm: u32,
    pub max_body_size_bytes: usize,
}

impl Default for WafConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8080".parse().unwrap(),
            backend_url: "http://127.0.0.1:9000".to_string(),
            db_path: "waf_data.db".to_string(),
            mode: WafMode::Prevention,
            rate_limit_rpm: 60,
            max_body_size_bytes: 2 * 1024 * 1024, // 2 MB limit
        }
    }
}
