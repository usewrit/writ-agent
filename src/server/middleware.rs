use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use dashmap::DashMap;
use serde_json::json;

use super::auth;
use crate::config::constants;
use crate::config::env::AppConfig;

pub async fn auth_middleware(
    request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();

    if constants::AUTH_EXEMPT_PATHS.contains(&path.as_str()) {
        return next.run(request).await;
    }

    let config = request
        .extensions()
        .get::<Arc<AppConfig>>()
        .cloned();

    let (secret, is_dev_bypass) = match config {
        Some(cfg) => (cfg.auth_secret.clone(), cfg.auth_bypass_enabled()),
        None => (String::new(), false),
    };

    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if let Some(_claims) = auth::authenticate_request(auth_header, &secret) {
        return next.run(request).await;
    }

    if is_dev_bypass {
        tracing::warn!("Recorder auth bypassed — no RECORDER_AUTH_SECRET set (dev mode)");
        return next.run(request).await;
    }

    (
        StatusCode::UNAUTHORIZED,
        axum::Json(json!({"detail": "Authentication required"})),
    )
        .into_response()
}

pub struct RateLimiter {
    windows: DashMap<String, VecDeque<Instant>>,
    max_actions_per_sec: usize,
}

const EXEMPT_ACTION_TYPES: &[&str] = &["scroll", "mousemove", "hover"];

impl RateLimiter {
    pub fn new(max_actions_per_sec: usize) -> Self {
        Self {
            windows: DashMap::new(),
            max_actions_per_sec,
        }
    }

    pub fn check_rate(&self, session_id: &str, action_type: &str) -> bool {
        if EXEMPT_ACTION_TYPES.contains(&action_type) {
            return true;
        }

        let now = Instant::now();
        let window = std::time::Duration::from_secs(1);

        let mut entry = self.windows.entry(session_id.to_string()).or_default();
        let timestamps = entry.value_mut();

        while timestamps.front().is_some_and(|t| now.duration_since(*t) > window) {
            timestamps.pop_front();
        }

        if timestamps.len() >= self.max_actions_per_sec {
            return false;
        }

        timestamps.push_back(now);
        true
    }

    pub fn remove_session(&self, session_id: &str) {
        self.windows.remove(session_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_allows_under_limit() {
        let limiter = RateLimiter::new(5);
        for _ in 0..5 {
            assert!(limiter.check_rate("s1", "click"));
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let limiter = RateLimiter::new(3);
        assert!(limiter.check_rate("s1", "click"));
        assert!(limiter.check_rate("s1", "click"));
        assert!(limiter.check_rate("s1", "click"));
        assert!(!limiter.check_rate("s1", "click"));
    }

    #[test]
    fn test_rate_limiter_exempt_actions() {
        let limiter = RateLimiter::new(1);
        assert!(limiter.check_rate("s1", "click"));
        assert!(!limiter.check_rate("s1", "click")); // blocked

        // Exempt types always pass
        assert!(limiter.check_rate("s1", "scroll"));
        assert!(limiter.check_rate("s1", "mousemove"));
        assert!(limiter.check_rate("s1", "hover"));
    }

    #[test]
    fn test_rate_limiter_separate_sessions() {
        let limiter = RateLimiter::new(1);
        assert!(limiter.check_rate("s1", "click"));
        assert!(limiter.check_rate("s2", "click"));
        assert!(!limiter.check_rate("s1", "click"));
        assert!(!limiter.check_rate("s2", "click"));
    }

    #[test]
    fn test_rate_limiter_remove_session() {
        let limiter = RateLimiter::new(1);
        assert!(limiter.check_rate("s1", "click"));
        limiter.remove_session("s1");
        assert!(limiter.check_rate("s1", "click"));
    }
}
