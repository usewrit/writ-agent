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
/// Idle window for a HUMAN-driven recording session (`/ws/record`). Generous on
/// purpose: a person recording a workflow legitimately stops to think, read the
/// page, or go find a value, and pulling the browser out from under them loses the
/// recording. Stamped by `action_handler::handle_action`, so it measures real
/// idleness rather than age.
pub const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(1800); // 30 minutes
/// Idle window for an MCP-driven connected browser session.
///
/// Deliberately MUCH shorter than the human window above, because the two have
/// nothing in common but the underlying browser. A connected model calls a tool
/// every few seconds while it works; the only pauses are a page read (5-60s) or a
/// question it asked the user in chat (a few minutes). Nothing healthy pauses
/// longer, so a long TTL does not protect a live session — it only lets an
/// abandoned one (user redirected the AI, client crashed) pin a Chromium context.
///
/// The error is asymmetric: reaping too early costs one `writ_browser_use` call,
/// which restores the persona's warm session and lands back on the same page.
pub const MCP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes
/// How often the MCP connected-session reaper sweeps. The sweep interval adds
/// directly to the leak window, so it must divide the idle window several times.
pub const MCP_REAPER_INTERVAL: Duration = Duration::from_secs(60);

// The reaper must sweep several times inside the idle window, or an abandoned
// session outlives its TTL by up to a whole interval. Same invariant the cloud
// record bridge asserts in local/record/bridge.rs.
const _: () = assert!(
    MCP_REAPER_INTERVAL.as_secs() * 4 <= MCP_SESSION_IDLE_TIMEOUT.as_secs()
);
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
