// Re-export the rate limiter from server middleware
// since both gateway and direct WS endpoints use the same logic
pub use crate::server::middleware::RateLimiter;
