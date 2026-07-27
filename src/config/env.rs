use std::env;

#[derive(Debug, Clone)]
pub struct AppConfig {
    // Server
    pub port: u16,
    pub environment: String,

    // Browser
    pub headless: bool,
    pub display: String,
    pub log_file: String,

    // Browser security (DANGEROUS, opt-in — default false = secure). Threaded from the daemon's
    // `local::config` runtime settings into the warm-browser launch argv (see
    // `browser::context::build_launch_args`). Enabling any of these disables a real OS/browser
    // protection; they are surfaced ONLY behind the Settings → Runtime "Browser security" toggles.
    /// Disable Chromium's OS-level renderer sandbox (`--no-sandbox` …).
    pub disable_sandbox: bool,
    /// Accept any TLS certificate in the automation browser (`--ignore-certificate-errors`).
    pub ignore_certificate_errors: bool,
    /// Disable the same-origin policy in the automation browser (`--disable-web-security`).
    pub disable_web_security: bool,
    /// Opt-in (default false): seed the browser baseline from the user's REAL local Chrome profile
    /// (cookies/storage) so sessions look like a returning user. Off = a clean generated baseline.
    /// Surfaced only behind the Settings → Runtime "Browser security (advanced)" toggle; the copied
    /// profile is stored inside the profile-isolated `~/.writ` home (0700), never a shared/cwd dir.
    pub use_local_chrome: bool,

    // Auth
    pub auth_secret: String,

    // Gateway
    pub backend_ws_url: Option<String>,
    pub recorder_host: String,
    pub recorder_self_url: Option<String>,
    pub recorder_max_sessions: usize,

    // Encryption
    pub fernet_key: Option<String>,

    // AI (legacy fallbacks)
    pub anthropic_api_key: Option<String>,
    pub openai_api_key: Option<String>,
    pub openai_model: String,

    // Proxy
    pub proxy_server: Option<String>,
    pub proxy_username: Option<String>,
    pub proxy_password: Option<String>,

    // Profile
    pub baseline_profile_dir: Option<String>,
}

impl AppConfig {
    pub fn from_env() -> Self {
        let port = env::var("RECORDER_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8081);

        let headless = env::var("RECORDER_HEADLESS")
            .map(|v| v.to_lowercase() != "false")
            .unwrap_or(true);

        let recorder_host = env::var("RECORDER_HOST")
            .unwrap_or_else(|_| "playwright-recorder".to_string());

        let recorder_self_url = env::var("RECORDER_SELF_URL").ok().or_else(|| {
            Some(format!("http://{}:{}", recorder_host, port))
        });

        Self {
            port,
            environment: env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string()),
            headless,
            // Default OFF (secure). The daemon overwrites these from its own runtime config at boot
            // (`local::app::lifecycle`); the env fallbacks exist for the legacy/CLI path only.
            disable_sandbox: env::var("RECORDER_DISABLE_SANDBOX").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false),
            ignore_certificate_errors: env::var("RECORDER_IGNORE_CERT_ERRORS").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false),
            disable_web_security: env::var("RECORDER_DISABLE_WEB_SECURITY").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false),
            use_local_chrome: env::var("RECORDER_USE_LOCAL_CHROME").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false),
            display: env::var("DISPLAY").unwrap_or_else(|_| ":99".to_string()),
            log_file: env::var("RECORDER_LOG_FILE")
                .unwrap_or_else(|_| "recorder.log".to_string()),
            auth_secret: env::var("RECORDER_AUTH_SECRET").unwrap_or_default(),
            backend_ws_url: env::var("BACKEND_WS_URL").ok(),
            recorder_host,
            recorder_self_url,
            recorder_max_sessions: env::var("RECORDER_MAX_SESSIONS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            fernet_key: env::var("FERNET_KEY").ok(),
            anthropic_api_key: env::var("ANTHROPIC_API_KEY").ok(),
            openai_api_key: env::var("OPENAI_API_KEY").ok(),
            openai_model: env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o".to_string()),
            proxy_server: env::var("PROXY_SERVER").ok(),
            proxy_username: env::var("PROXY_USERNAME").ok(),
            proxy_password: env::var("PROXY_PASSWORD").ok(),
            baseline_profile_dir: env::var("BASELINE_PROFILE_DIR").ok(),
        }
    }

    pub fn is_dev(&self) -> bool {
        self.environment == "development"
    }

    /// Whether unauthenticated WebSocket access is permitted (dev bypass).
    /// SECURITY: this must NOT default to true. Previously `is_dev() && secret
    /// empty` silently allowed unauthenticated access in the default
    /// "development" environment with no secret configured. Now it requires the
    /// operator to explicitly opt in via `RECORDER_AUTH_BYPASS=1` (and only in a
    /// dev environment). Production never bypasses.
    pub fn auth_bypass_enabled(&self) -> bool {
        if !self.is_dev() {
            return false;
        }
        std::env::var("RECORDER_AUTH_BYPASS")
            .map(|v| {
                let v = v.to_lowercase();
                v == "1" || v == "true" || v == "yes"
            })
            .unwrap_or(false)
    }
}
