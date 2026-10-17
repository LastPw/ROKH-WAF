mod ai;
mod antiddos;
mod config;
mod deobfuscator;
mod geoip;
mod loadbalancer;
mod logger;
mod pages;
mod proxy;
mod ratelimit;
mod rules;

use ai::NeuralBrain;
use config::WafConfig;
use logger::WafLogger;
use proxy::{proxy_handler, AppState};
use rules::RuleEngine;

use axum::routing::any;
use axum::Router;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "waf_engine=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = WafConfig::from_env_and_args();
    let db_path = config.db_path.clone();

    println!("============================================================");
    println!(" [ROKH WAF] High-Performance Layer-7 Defense Engine");
    println!("============================================================");
    println!(" [+] Listening Proxy Address : http://{}", config.listen_addr);
    println!(" [+] Target Backend Server   : {}", config.backend_url);
    println!(" [+] Active Security Mode    : {:?}", config.mode);
    println!(" [+] Rate Limiter Threshold  : {} req/min per IP", config.rate_limit_rpm);
    println!(" [+] Telemetry Database     : {}", db_path);
    println!(" [+] AI Neural Engine        : In-Memory Native Rust Loaded (< 15µs)");
    println!("------------------------------------------------------------");

    let logger = WafLogger::new(&db_path)?;
    let rules = RuleEngine::new();
    let ai = Arc::new(NeuralBrain::new());
    let antiddos = antiddos::AntiDdosEngine::new(antiddos::DdosConfig {
        normal_rpm_limit: config.rate_limit_rpm,
        burst_rpm_limit: config.rate_limit_rpm * 2,
        surge_rps_threshold: 80,
        base_jail_seconds: 60,
    });
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .pool_max_idle_per_host(256)
        .pool_idle_timeout(std::time::Duration::from_secs(90))
        .tcp_nodelay(true)
        .build()?;

    let load_balancer = loadbalancer::LoadBalancer::new(
        vec![config.backend_url.clone()],
        loadbalancer::BalancingAlgorithm::RoundRobin,
    );

    let state = Arc::new(AppState {
        config: config.clone(),
        rules,
        antiddos,
        logger,
        http_client,
        load_balancer,
        ai,
        metrics_requests_total: AtomicU64::new(0),
        metrics_blocked_threats: AtomicU64::new(0),
        metrics_ai_inspections: AtomicU64::new(0),
        metrics_ai_anomalies: AtomicU64::new(0),
        start_time: std::time::Instant::now(),
    });

    let app = Router::new()
        .fallback(any(proxy_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    println!(" [*] WAF Proxy Engine started. Intercepting incoming traffic...");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
