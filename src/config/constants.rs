use std::time::Duration;

pub const SERVER_VERSION: &str = "1.0.0";

// Screenshot streaming
pub const SCREENSHOT_INTERVAL: Duration = Duration::from_millis(50); // 20 FPS
pub const SCREENSHOT_QUALITY: u8 = 60;
pub const SCREENSHOT_MAX_WIDTH: u32 = 1280;
pub const SCREENSHOT_MAX_HEIGHT: u32 = 800;

// Viewport defaults
pub const VIEWPORT_WIDTH: u32 = 1280;
pub const VIEWPORT_HEIGHT: u32 = 800;

// Session limits
pub const MAX_SESSIONS: usize = 5;
pub const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(1800); // 30 minutes
pub const MAX_STEPS: usize = 5000;
pub const MIN_WAIT_THRESHOLD_MS: u64 = 500;
pub const MAX_WAIT_CAP_MS: u64 = 10_000;
pub const MAX_SPECTATORS: usize = 10;

// WebSocket
pub const WS_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(300);

// Rate limiting
pub const RATE_LIMIT_ACTIONS_PER_SEC: usize = 30;

// Cleanup
pub const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

// AI defaults
pub const AI_COMPLETION_TIMEOUT: Duration = Duration::from_secs(120);
pub const AI_MAX_STEPS_STANDARD: usize = 20;
pub const AI_MAX_ACTIONS_INTELLIGENT: usize = 50;

// Streaming engine
pub const STREAMING_IDLE_TIMEOUT: Duration = Duration::from_secs(10_800); // 3 hours
pub const STREAMING_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
pub const STREAMING_MAX_THREADS: usize = 5;
pub const STREAMING_MAX_SETUP_RETRIES: usize = 2;

// Network capture
pub const NETWORK_CAPTURE_MAX_BODY_SIZE: usize = 10_240; // 10 KB

// Browser
pub const BROWSER_INSTALL_TIMEOUT: Duration = Duration::from_secs(300);

// Auth-exempt paths
pub const AUTH_EXEMPT_PATHS: &[&str] = &["/health", "/docs", "/openapi.json"];
