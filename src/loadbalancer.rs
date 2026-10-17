use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BalancingAlgorithm {
    RoundRobin,
    LeastConnections,
    IpHash,
    Failover,
}

impl BalancingAlgorithm {
    pub fn from_str_name(name: &str) -> Self {
        match name.to_lowercase().as_str() {
            "least_conn" | "leastconnections" => Self::LeastConnections,
            "ip_hash" | "iphash" => Self::IpHash,
            "failover" | "active_standby" => Self::Failover,
            _ => Self::RoundRobin,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RoundRobin => "RoundRobin",
            Self::LeastConnections => "LeastConnections",
            Self::IpHash => "IpHash",
            Self::Failover => "Failover",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitState {
    Closed,   // Normal healthy operation
    Open,     // Tripped: consecutive failures exceeded threshold
    HalfOpen, // Probing: trial canary request in progress
}

impl CircuitState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Closed => "CLOSED",
            Self::Open => "OPEN",
            Self::HalfOpen => "HALF-OPEN",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendNode {
    pub id: String,
    pub url: String,
    pub weight: u32,
    pub is_alive: bool,
    pub circuit_state: CircuitState,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub active_connections: usize,
    pub total_requests: u64,
    pub total_failures: u64,
    pub total_successes: u64,
    pub last_latency_ms: u64,
    pub last_error: Option<String>,
    #[serde(skip, default = "Instant::now")]
    pub last_state_change: Instant,
}

#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: u32,
    pub success_threshold: u32,
    pub cooloff_duration: Duration,
    pub request_timeout: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 3,
            success_threshold: 2,
            cooloff_duration: Duration::from_secs(10),
            request_timeout: Duration::from_millis(3500),
        }
    }
}

pub struct LoadBalancer {
    nodes: Arc<RwLock<Vec<BackendNode>>>,
    algorithm: Arc<RwLock<BalancingAlgorithm>>,
    round_robin_idx: AtomicUsize,
    pub cb_config: CircuitBreakerConfig,
    http_client: reqwest::Client,
}

impl LoadBalancer {
    pub fn new(initial_urls: Vec<String>, algorithm: BalancingAlgorithm) -> Arc<Self> {
        let mut nodes = Vec::new();
        for (i, url) in initial_urls.into_iter().enumerate() {
            let clean_url = url.trim_end_matches('/').to_string();
            nodes.push(BackendNode {
                id: format!("node-{}", i + 1),
                url: clean_url,
                weight: 1,
                is_alive: true,
                circuit_state: CircuitState::Closed,
                consecutive_failures: 0,
                consecutive_successes: 0,
                active_connections: 0,
                total_requests: 0,
                total_failures: 0,
                total_successes: 0,
                last_latency_ms: 0,
                last_error: None,
                last_state_change: Instant::now(),
            });
        }

        // If empty, add default localhost origin
        if nodes.is_empty() {
            nodes.push(BackendNode {
                id: "node-1".to_string(),
                url: "http://127.0.0.1:9000".to_string(),
                weight: 1,
                is_alive: true,
                circuit_state: CircuitState::Closed,
                consecutive_failures: 0,
                consecutive_successes: 0,
                active_connections: 0,
                total_requests: 0,
                total_failures: 0,
                total_successes: 0,
                last_latency_ms: 0,
                last_error: None,
                last_state_change: Instant::now(),
            });
        }

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_millis(2500))
            .pool_max_idle_per_host(64)
            .build()
            .unwrap_or_default();

        let lb = Arc::new(Self {
            nodes: Arc::new(RwLock::new(nodes)),
            algorithm: Arc::new(RwLock::new(algorithm)),
            round_robin_idx: AtomicUsize::new(0),
            cb_config: CircuitBreakerConfig::default(),
            http_client,
        });

        // Launch background active health checks
        let lb_clone = Arc::clone(&lb);
        tokio::spawn(async move {
            lb_clone.run_health_check_loop().await;
        });

        lb
    }

    /// Selects an eligible backend node based on circuit state and load balancing algorithm
    pub async fn select_backend(&self, client_ip: &str) -> Option<BackendNode> {
        let mut nodes = self.nodes.write().await;
        if nodes.is_empty() {
            return None;
        }

        let now = Instant::now();

        // 1. Evaluate Circuit Breaker Cool-off Transitions (Open -> HalfOpen)
        for node in nodes.iter_mut() {
            if node.circuit_state == CircuitState::Open {
                if now.duration_since(node.last_state_change) >= self.cb_config.cooloff_duration {
                    node.circuit_state = CircuitState::HalfOpen;
                    node.last_state_change = now;
                    node.consecutive_successes = 0;
                }
            }
        }

        // 2. Filter available candidate nodes (Closed or HalfOpen)
        let candidates_idx: Vec<usize> = nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.is_alive && (n.circuit_state == CircuitState::Closed || n.circuit_state == CircuitState::HalfOpen))
            .map(|(i, _)| i)
            .collect();

        if candidates_idx.is_empty() {
            // All nodes are either dead or have open circuit breakers
            return None;
        }

        let algo = *self.algorithm.read().await;
        let chosen_idx = match algo {
            BalancingAlgorithm::RoundRobin => {
                let idx = self.round_robin_idx.fetch_add(1, Ordering::Relaxed) % candidates_idx.len();
                candidates_idx[idx]
            }
            BalancingAlgorithm::LeastConnections => {
                let mut min_conn = usize::MAX;
                let mut best_i = candidates_idx[0];
                for &idx in &candidates_idx {
                    if nodes[idx].active_connections < min_conn {
                        min_conn = nodes[idx].active_connections;
                        best_i = idx;
                    }
                }
                best_i
            }
            BalancingAlgorithm::IpHash => {
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                client_ip.hash(&mut hasher);
                let hash_val = hasher.finish() as usize;
                let idx = hash_val % candidates_idx.len();
                candidates_idx[idx]
            }
            BalancingAlgorithm::Failover => {
                // Strict priority: pick the lowest index candidate
                candidates_idx[0]
            }
        };

        // Increment active connection count
        nodes[chosen_idx].active_connections += 1;
        nodes[chosen_idx].total_requests += 1;

        Some(nodes[chosen_idx].clone())
    }

    /// Records the execution outcome of an upstream request to update circuit breaker state
    pub async fn record_outcome(&self, node_id: &str, is_success: bool, latency_ms: u64, error_msg: Option<&str>) {
        let mut nodes = self.nodes.write().await;
        if let Some(node) = nodes.iter_mut().find(|n| n.id == node_id) {
            if node.active_connections > 0 {
                node.active_connections -= 1;
            }
            node.last_latency_ms = latency_ms;

            if is_success {
                node.total_successes += 1;
                node.consecutive_failures = 0;
                node.last_error = None;

                match node.circuit_state {
                    CircuitState::HalfOpen => {
                        node.consecutive_successes += 1;
                        if node.consecutive_successes >= self.cb_config.success_threshold {
                            node.circuit_state = CircuitState::Closed;
                            node.last_state_change = Instant::now();
                            node.is_alive = true;
                        }
                    }
                    CircuitState::Open => {
                        // Unexpected success while open, close circuit
                        node.circuit_state = CircuitState::Closed;
                        node.last_state_change = Instant::now();
                        node.is_alive = true;
                    }
                    CircuitState::Closed => {
                        node.consecutive_successes += 1;
                    }
                }
            } else {
                node.total_failures += 1;
                node.consecutive_failures += 1;
                node.consecutive_successes = 0;
                if let Some(err) = error_msg {
                    node.last_error = Some(err.to_string());
                }

                match node.circuit_state {
                    CircuitState::Closed => {
                        if node.consecutive_failures >= self.cb_config.failure_threshold {
                            node.circuit_state = CircuitState::Open;
                            node.last_state_change = Instant::now();
                            node.is_alive = false;
                        }
                    }
                    CircuitState::HalfOpen => {
                        // Canary failure trips back to open immediately
                        node.circuit_state = CircuitState::Open;
                        node.last_state_change = Instant::now();
                        node.is_alive = false;
                    }
                    CircuitState::Open => {}
                }
            }
        }
    }

    /// Background Active Health Check Loop: Probes all configured backends every 5s
    async fn run_health_check_loop(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;

            let node_snapshots = {
                let nodes = self.nodes.read().await;
                nodes.clone()
            };

            for node in node_snapshots {
                let health_url = format!("{}/health", node.url);
                let fallback_url = node.url.clone();
                let start = Instant::now();

                let res = match self.http_client.get(&health_url).send().await {
                    Ok(r) => Ok(r),
                    Err(_) => self.http_client.get(&fallback_url).send().await,
                };

                let latency = start.elapsed().as_millis() as u64;

                match res {
                    Ok(resp) if resp.status().is_success() || resp.status().as_u16() < 500 => {
                        let mut nodes = self.nodes.write().await;
                        if let Some(n) = nodes.iter_mut().find(|n| n.id == node.id) {
                            n.last_latency_ms = latency;
                            n.consecutive_failures = 0;
                            n.consecutive_successes += 1;
                            n.last_error = None;

                            if n.circuit_state != CircuitState::Closed && n.consecutive_successes >= self.cb_config.success_threshold {
                                n.circuit_state = CircuitState::Closed;
                                n.is_alive = true;
                                n.last_state_change = Instant::now();
                            }
                        }
                    }
                    Ok(resp) => {
                        let mut nodes = self.nodes.write().await;
                        if let Some(n) = nodes.iter_mut().find(|n| n.id == node.id) {
                            n.last_latency_ms = latency;
                            n.consecutive_failures += 1;
                            n.last_error = Some(format!("HTTP {}", resp.status().as_u16()));
                            if n.consecutive_failures >= self.cb_config.failure_threshold {
                                n.circuit_state = CircuitState::Open;
                                n.is_alive = false;
                                n.last_state_change = Instant::now();
                            }
                        }
                    }
                    Err(e) => {
                        let mut nodes = self.nodes.write().await;
                        if let Some(n) = nodes.iter_mut().find(|n| n.id == node.id) {
                            n.last_latency_ms = latency;
                            n.consecutive_failures += 1;
                            n.last_error = Some(e.to_string());
                            if n.consecutive_failures >= self.cb_config.failure_threshold {
                                n.circuit_state = CircuitState::Open;
                                n.is_alive = false;
                                n.last_state_change = Instant::now();
                            }
                        }
                    }
                }
            }
        }
    }

    /// Adds a new upstream backend node dynamically
    pub async fn add_node(&self, url: &str, weight: u32) -> Result<BackendNode, String> {
        let clean_url = url.trim_end_matches('/').to_string();
        if !clean_url.starts_with("http://") && !clean_url.starts_with("https://") {
            return Err("URL must start with http:// or https://".to_string());
        }

        let mut nodes = self.nodes.write().await;
        if nodes.iter().any(|n| n.url == clean_url) {
            return Err("Backend node URL already exists in cluster".to_string());
        }

        let new_id = format!("node-{}", nodes.len() + 1);
        let node = BackendNode {
            id: new_id,
            url: clean_url,
            weight: weight.max(1),
            is_alive: true,
            circuit_state: CircuitState::Closed,
            consecutive_failures: 0,
            consecutive_successes: 0,
            active_connections: 0,
            total_requests: 0,
            total_failures: 0,
            total_successes: 0,
            last_latency_ms: 0,
            last_error: None,
            last_state_change: Instant::now(),
        };

        nodes.push(node.clone());
        Ok(node)
    }

    /// Removes an upstream backend node by ID or URL
    pub async fn remove_node(&self, id_or_url: &str) -> bool {
        let mut nodes = self.nodes.write().await;
        let initial_len = nodes.len();
        let clean = id_or_url.trim_end_matches('/');
        nodes.retain(|n| n.id != id_or_url && n.url != id_or_url && n.url.trim_end_matches('/') != clean);
        nodes.len() < initial_len
    }

    /// Updates the balancing algorithm dynamically
    pub async fn set_algorithm(&self, algo: BalancingAlgorithm) {
        let mut a = self.algorithm.write().await;
        *a = algo;
    }

    /// Returns telemetry and health metrics of all upstream backends
    pub async fn get_status(&self) -> serde_json::Value {
        let nodes = self.nodes.read().await;
        let algo = self.algorithm.read().await;

        let total_nodes = nodes.len();
        let healthy_nodes = nodes.iter().filter(|n| n.is_alive && n.circuit_state == CircuitState::Closed).count();
        let total_requests: u64 = nodes.iter().map(|n| n.total_requests).sum();
        let total_failures: u64 = nodes.iter().map(|n| n.total_failures).sum();

        let circuit_health = if healthy_nodes == total_nodes {
            "ALL_HEALTHY"
        } else if healthy_nodes > 0 {
            "DEGRADED"
        } else {
            "CRITICAL_OUTAGE"
        };

        serde_json::json!({
            "algorithm": algo.as_str(),
            "circuit_health": circuit_health,
            "total_nodes": total_nodes,
            "healthy_nodes": healthy_nodes,
            "total_requests": total_requests,
            "total_failures": total_failures,
            "circuit_config": {
                "failure_threshold": self.cb_config.failure_threshold,
                "success_threshold": self.cb_config.success_threshold,
                "cooloff_seconds": self.cb_config.cooloff_duration.as_secs(),
                "timeout_ms": self.cb_config.request_timeout.as_millis()
            },
            "nodes": nodes.iter().map(|n| serde_json::json!({
                "id": n.id,
                "url": n.url,
                "weight": n.weight,
                "is_alive": n.is_alive,
                "circuit_state": n.circuit_state.as_str(),
                "active_connections": n.active_connections,
                "total_requests": n.total_requests,
                "total_failures": n.total_failures,
                "total_successes": n.total_successes,
                "last_latency_ms": n.last_latency_ms,
                "last_error": n.last_error,
            })).collect::<Vec<_>>()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_round_robin_selection() {
        let lb = LoadBalancer::new(
            vec!["http://127.0.0.1:9001".to_string(), "http://127.0.0.1:9002".to_string()],
            BalancingAlgorithm::RoundRobin,
        );

        let n1 = lb.select_backend("1.1.1.1").await.unwrap();
        let n2 = lb.select_backend("1.1.1.1").await.unwrap();
        assert_ne!(n1.url, n2.url);
    }

    #[tokio::test]
    async fn test_circuit_breaker_tripping() {
        let lb = LoadBalancer::new(
            vec!["http://127.0.0.1:9001".to_string()],
            BalancingAlgorithm::RoundRobin,
        );

        // Record 3 consecutive failures
        lb.record_outcome("node-1", false, 50, Some("Connection Refused")).await;
        lb.record_outcome("node-1", false, 50, Some("Connection Refused")).await;
        lb.record_outcome("node-1", false, 50, Some("Connection Refused")).await;

        let status = lb.get_status().await;
        let node = &status["nodes"][0];
        assert_eq!(node["circuit_state"], "OPEN");
        assert_eq!(node["is_alive"], false);

        // Since the only node is OPEN, select_backend should fail fast (None)
        let selection = lb.select_backend("1.1.1.1").await;
        assert!(selection.is_none());
    }

    #[tokio::test]
    async fn test_least_connections_selection() {
        let lb = LoadBalancer::new(
            vec!["http://127.0.0.1:9001".to_string(), "http://127.0.0.1:9002".to_string()],
            BalancingAlgorithm::LeastConnections,
        );

        // Pick node 1 (its active connections becomes 1)
        let _ = lb.select_backend("1.1.1.1").await.unwrap();

        // Second pick must be node 2 because it has 0 active connections
        let n2 = lb.select_backend("1.1.1.1").await.unwrap();
        assert_eq!(n2.url, "http://127.0.0.1:9002");
    }

    #[tokio::test]
    async fn test_ip_hash_stickiness() {
        let lb = LoadBalancer::new(
            vec!["http://127.0.0.1:9001".to_string(), "http://127.0.0.1:9002".to_string()],
            BalancingAlgorithm::IpHash,
        );

        let ip = "192.168.1.100";
        let n1 = lb.select_backend(ip).await.unwrap();
        let n2 = lb.select_backend(ip).await.unwrap();
        assert_eq!(n1.url, n2.url);
    }
}
