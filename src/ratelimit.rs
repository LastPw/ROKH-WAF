#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct RateLimitEntry {
    window_start: Instant,
    count: u32,
}

pub struct RateLimiter {
    records: Mutex<HashMap<String, RateLimitEntry>>,
    window_duration: Duration,
    max_requests_per_window: u32,
}

impl RateLimiter {
    pub fn new(max_requests_per_minute: u32) -> Self {
        Self {
            records: Mutex::new(HashMap::new()),
            window_duration: Duration::from_secs(60),
            max_requests_per_window: max_requests_per_minute,
        }
    }

    /// Checks if a client IP is allowed. Returns true if allowed, false if rate limited.
    pub fn check(&self, client_ip: &str) -> bool {
        let now = Instant::now();
        let mut map = self.records.lock().unwrap();

        // Memory hygiene: clean entries older than 2 minutes if map is getting large
        if map.len() > 1000 {
            let two_mins = Duration::from_secs(120);
            map.retain(|_, entry| now.duration_since(entry.window_start) < two_mins);
        }

        let entry = map.entry(client_ip.to_string()).or_insert(RateLimitEntry {
            window_start: now,
            count: 0,
        });

        if now.duration_since(entry.window_start) > self.window_duration {
            entry.window_start = now;
            entry.count = 1;
            true
        } else {
            entry.count += 1;
            entry.count <= self.max_requests_per_window
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_threshold() {
        let limiter = RateLimiter::new(3);
        let ip = "192.168.1.100";

        assert!(limiter.check(ip));
        assert!(limiter.check(ip));
        assert!(limiter.check(ip));
        assert!(!limiter.check(ip)); // 4th request in the same window is blocked
    }
}
