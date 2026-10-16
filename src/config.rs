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

impl WafConfig {
    pub fn from_env_and_args() -> Self {
        let mut cfg = Self::default();

        // 1. Environment variables
        if let Ok(b) = std::env::var("ROKH_BACKEND_URL")
            .or_else(|_| std::env::var("BACKEND_URL"))
            .or_else(|_| std::env::var("TARGET_URL"))
        {
            let trimmed = b.trim();
            if !trimmed.is_empty() {
                cfg.backend_url = trimmed.to_string();
            }
        }
        if let Ok(p) = std::env::var("ROKH_LISTEN_ADDR")
            .or_else(|_| std::env::var("LISTEN_ADDR"))
            .or_else(|_| std::env::var("WAF_PORT"))
        {
            let trimmed = p.trim();
            if let Ok(port) = trimmed.parse::<u16>() {
                cfg.listen_addr = format!("0.0.0.0:{}", port).parse().unwrap_or(cfg.listen_addr);
            } else if let Ok(addr) = trimmed.parse() {
                cfg.listen_addr = addr;
            }
        }
        if let Ok(m) = std::env::var("ROKH_MODE").or_else(|_| std::env::var("WAF_MODE")) {
            cfg.mode = WafMode::from(m.as_str());
        }
        if let Ok(r) = std::env::var("ROKH_RATE_LIMIT").or_else(|_| std::env::var("RATE_LIMIT_RPM")) {
            if let Ok(val) = r.trim().parse::<u32>() {
                cfg.rate_limit_rpm = val;
            }
        }

        // 2. Command-Line Arguments
        let args: Vec<String> = std::env::args().collect();
        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--target" | "--backend" | "-t" | "-b" => {
                    if i + 1 < args.len() {
                        cfg.backend_url = args[i + 1].trim().to_string();
                        i += 1;
                    }
                }
                "--listen" | "--port" | "-l" | "-p" => {
                    if i + 1 < args.len() {
                        let arg = args[i + 1].trim();
                        if let Ok(port) = arg.parse::<u16>() {
                            cfg.listen_addr = format!("0.0.0.0:{}", port).parse().unwrap_or(cfg.listen_addr);
                        } else if let Ok(addr) = arg.parse() {
                            cfg.listen_addr = addr;
                        }
                        i += 1;
                    }
                }
                "--mode" | "-m" => {
                    if i + 1 < args.len() {
                        cfg.mode = WafMode::from(args[i + 1].as_str());
                        i += 1;
                    }
                }
                "--rpm" => {
                    if i + 1 < args.len() {
                        if let Ok(val) = args[i + 1].trim().parse::<u32>() {
                            cfg.rate_limit_rpm = val;
                        }
                        i += 1;
                    }
                }
                "--help" | "-h" => {
                    println!("============================================================");
                    println!(" 🛡️  ROKH WAF (دیواره آتش رُخ) - Options Manual");
                    println!("============================================================");
                    println!("Usage:");
                    println!("  waf_engine [OPTIONS] [TARGET_URL]");
                    println!("");
                    println!("Options:");
                    println!("  --target, -t <URL>    Target backend service to protect (e.g. http://127.0.0.1:3000)");
                    println!("  --listen, -l <ADDR>   Listening address/port (e.g. 127.0.0.1:8080 or 8080)");
                    println!("  --mode, -m <MODE>     Security mode: PREVENTION (default) or DETECTION");
                    println!("  --rpm <COUNT>         Rate limit requests per minute per IP (default: 60)");
                    println!("  --help, -h            Show this help manual");
                    println!("");
                    println!("Examples:");
                    println!("  waf_engine --target http://127.0.0.1:3000 --port 8080");
                    println!("  waf_engine http://localhost:8000");
                    std::process::exit(0);
                }
                pos if !pos.starts_with('-') => {
                    cfg.backend_url = pos.trim().to_string();
                }
                _ => {}
            }
            i += 1;
        }

        // Normalize URL format
        if !cfg.backend_url.starts_with("http://") && !cfg.backend_url.starts_with("https://") {
            cfg.backend_url = format!("http://{}", cfg.backend_url);
        }

        cfg
    }
}
