use clap::{Parser, Subcommand};

use super::display;
use super::setup;
use crate::config::constants;

#[derive(Parser)]
#[command(
    name = "writ-agent",
    version = constants::SERVER_VERSION,
    about = "Writ Agent — run browser automation on your machine",
    long_about = "Writ Agent — run browser automation on your machine, linked to your Writ account.\n\nCommands:\n  setup           - Interactive configuration (AI provider, display mode, recorder)\n  start           - Launch the recorder server\n  status          - Show current configuration and connection status\n  config          - View or update configuration values"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Interactive configuration (AI provider, display mode, recorder settings)
    Setup,

    /// Link to your Writ account (OAuth device flow)
    Login,

    /// Link as infrastructure recorder (admin approval via device flow)
    Link,

    /// Clear SaaS credentials
    Logout,

    /// Launch the recorder server
    Start {
        /// Run in headless mode (override config)
        #[arg(long)]
        headless: bool,

        /// Run in headed mode (override config)
        #[arg(long)]
        headed: bool,

        /// Use Xvfb virtual display (Linux only, override config)
        #[arg(long)]
        xvfb: bool,

        /// Port to listen on
        #[arg(short, long, default_value_t = 0)]
        port: u16,

        /// Show verbose debug logs
        #[arg(long)]
        debug: bool,
    },

    /// Show current configuration and connection status
    Status,

    /// View or update configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Set a config value (e.g. writ config set ai.model gpt-4o)
    Set {
        /// Dotted config key
        key: String,
        /// Value to set
        value: String,
    },
    /// Get a config value
    Get {
        /// Dotted config key
        key: String,
    },
}

pub async fn run() {
    // Resolve the Playwright driver override (a process-ENVIRONMENT write) at the earliest point this
    // binary reaches code we own. `src/main.rs` is a bare `#[tokio::main]` shell, so this is as early
    // as it gets here; `writ-agentd` / `writ` prime it in a fully synchronous `main` prologue instead.
    // Idempotent — see `browser::manager::init_driver_env` for why the write must not happen from a
    // multi-threaded async context.
    crate::browser::manager::init_driver_env();

    let cli = Cli::parse();

    match cli.command {
        None => {
            // No subcommand — print help
            use clap::CommandFactory;
            Cli::command().print_help().ok();
            println!();
        }
        Some(Commands::Setup) => {
            setup::run_interactive_setup();
        }
        Some(Commands::Login) => {
            let config = setup::load_config();
            let saas_url = &config.saas.url;
            crate::bridge::auth::device_flow_login(saas_url, None).await;
        }
        Some(Commands::Link) => {
            let config = setup::load_config();
            let saas_url = &config.saas.url;
            crate::bridge::auth::device_flow_login(saas_url, Some("infrastructure")).await;
        }
        Some(Commands::Logout) => {
            crate::bridge::auth::clear_credentials();
            println!("\x1b[32m✓ Logged out. Credentials cleared.\x1b[0m");
        }
        Some(Commands::Start {
            headless,
            headed,
            xvfb,
            port,
            debug,
        }) => {
            run_start(headless, headed, xvfb, port, debug).await;
        }
        Some(Commands::Status) => {
            run_status();
        }
        Some(Commands::Config { action }) => match action {
            ConfigAction::Set { key, value } => {
                // Only claim success when the key was actually recognised —
                // `set_config_value` prints its own reason on rejection, and a
                // tick beside it is how a typo'd key reads as saved. Non-zero
                // exit so a script can tell, too.
                if !setup::set_config_value(&key, &value) {
                    std::process::exit(1);
                }
                println!("\x1b[32m✓\x1b[0m Set {} = {}", key, value);
            }
            ConfigAction::Get { key } => {
                let value = setup::get_config_value(&key);
                match value {
                    Some(v) => {
                        if key.ends_with("api_key") || key.ends_with("secret") {
                            println!("{} = {}", key, setup::mask_key(Some(&v)));
                        } else {
                            println!("{} = {}", key, v);
                        }
                    }
                    None => println!("{} = (not set)", key),
                }
            }
        },
    }
}

async fn run_start(
    headless_flag: bool,
    headed_flag: bool,
    xvfb_flag: bool,
    port: u16,
    debug: bool,
) {
    let config = setup::load_config();

    // Resolve display mode from flags or config
    let (is_headless, xvfb_started) = if headed_flag {
        (false, false)
    } else if headless_flag {
        (true, false)
    } else if xvfb_flag {
        match display::start_xvfb() {
            Ok(()) => {
                println!("\x1b[32m[OK]\x1b[0m Xvfb started on display :99");
                (false, true)
            }
            Err(e) => {
                println!("\x1b[31m[FAIL]\x1b[0m Xvfb: {}", e);
                println!("Falling back to headless mode");
                (true, false)
            }
        }
    } else {
        // Use config value
        match config.recorder.display_mode.as_str() {
            "headed" => (false, false),
            "headless" => (true, false),
            "xvfb" => match display::start_xvfb() {
                Ok(()) => (false, true),
                Err(_) => {
                    let auto = display::determine_headless_mode();
                    (auto, false)
                }
            },
            _ => {
                // "auto" — detect display
                let auto = display::determine_headless_mode();
                (auto, false)
            }
        }
    };

    // Resolve the BYO AI provider settings from the IN-MEMORY config. The provider KEYS are returned
    // here and are no longer written into the process environment — the browser subprocess inherits
    // that environment and exposes it via `/proc/<pid>/environ`. Only the non-secret model/base-url
    // hints are staged. See the security note on `setup::apply_ai_env_vars`.
    let staged_ai_keys = setup::apply_ai_env_vars(&config);
    let staged_key = |name: &str| {
        staged_ai_keys
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.clone())
    };

    // Set recorder env vars
    std::env::set_var("RECORDER_HEADLESS", if is_headless { "true" } else { "false" });
    if !debug {
        std::env::set_var("RUST_LOG", "info");
    } else {
        std::env::set_var("RUST_LOG", "debug");
    }

    let listen_port = if port > 0 { port } else { config.app.port };

    // Resolve the baseline profile source, in priority order:
    //   1. --use-local-chrome (opt-in) — copy the user's real Chrome "Default".
    //   2. recorder.chrome_profile_source — a profile imported via
    //      `import-profile` (any Chromium browser/profile the user picked).
    //   3. BASELINE_PROFILE_DIR env var (clean baseline if none is set).
    // (1) and (2) copy into the working .browser_profile dir, which is what the
    // BrowserManager then loads as the baseline.
    // Baseline source: a clean generated baseline by default. Importing the user's real local Chrome
    // profile is no longer a CLI flag / auto-import — it is an explicit, opt-in Settings → Runtime
    // toggle on the desktop app (`browser.use_local_chrome`), stored in the profile-isolated
    // `~/.writ` home. An operator can still point the recorder at an already-prepared profile via
    // the `BASELINE_PROFILE_DIR` env var.
    let baseline_profile_dir: Option<String> = std::env::var("BASELINE_PROFILE_DIR").ok();

    println!();
    println!("\x1b[1mWrit\x1b[0m v{}", constants::SERVER_VERSION);
    println!("{}", "─".repeat(40));
    println!("  Mode:     {}", if is_headless { "headless" } else { "headed" });
    if xvfb_started {
        println!("  Display:  Xvfb :99");
    }
    println!("  Port:     {}", listen_port);
    println!("  AI:       {}", config.ai.provider.as_deref().unwrap_or("not configured"));
    println!("  SaaS:     {}", config.saas.url);
    println!();

    // Build the AppConfig and start the server
    let app_config = crate::config::env::AppConfig {
        port: listen_port,
        environment: std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string()),
        headless: is_headless,
        // Browser-security flags default OFF (secure). This CLI path predates the desktop runtime
        // settings; leave the OS sandbox / TLS validation / SOP intact unless explicitly overridden.
        disable_sandbox: std::env::var("RECORDER_DISABLE_SANDBOX").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false),
        ignore_certificate_errors: std::env::var("RECORDER_IGNORE_CERT_ERRORS").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false),
        disable_web_security: std::env::var("RECORDER_DISABLE_WEB_SECURITY").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false),
        display: std::env::var("DISPLAY").unwrap_or_else(|_| ":99".to_string()),
        log_file: std::env::var("RECORDER_LOG_FILE")
            .unwrap_or_else(|_| "recorder.log".to_string()),
        auth_secret: std::env::var("RECORDER_AUTH_SECRET").unwrap_or_default(),
        backend_ws_url: std::env::var("BACKEND_WS_URL").ok(),
        recorder_host: std::env::var("RECORDER_HOST")
            .unwrap_or_else(|_| "playwright-recorder".to_string()),
        recorder_self_url: std::env::var("RECORDER_SELF_URL").ok(),
        recorder_max_sessions: config.recorder.max_sessions as usize,
        fernet_key: std::env::var("FERNET_KEY").ok(),
        // Prefer the key we just resolved from `config.yaml` (held in memory, never re-read from the
        // process environment); fall back to a pre-existing env var for operator/container setups.
        anthropic_api_key: staged_key("ANTHROPIC_API_KEY")
            .or_else(|| std::env::var("ANTHROPIC_API_KEY").ok()),
        openai_api_key: staged_key("OPENAI_API_KEY")
            .or_else(|| std::env::var("OPENAI_API_KEY").ok()),
        openai_model: std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o".to_string()),
        proxy_server: std::env::var("PROXY_SERVER").ok(),
        proxy_username: std::env::var("PROXY_USERNAME").ok(),
        proxy_password: std::env::var("PROXY_PASSWORD").ok(),
        // Local-Chrome import is a desktop Settings toggle now, not a CLI/auto path — off here.
        use_local_chrome: false,
        baseline_profile_dir,
    };

    // Initialize logging
    crate::util::logging::init(&app_config);

    // ---- Exact Python startup flow (cli.py _start) ----

    // Step 1: Check auth mode
    let service_mode = crate::bridge::auth::is_service_mode();

    if service_mode {
        println!("\x1b[1mRunning in infrastructure mode\x1b[0m");
    } else {
        // User-hosted: check AI config
        if config.ai.provider.is_none() || config.ai.api_key.is_none() {
            println!("\x1b[31m✗ AI provider not configured. Run: writ-agent setup\x1b[0m");
            std::process::exit(1);
        }

        // Check auth credentials
        match crate::bridge::auth::get_user_token() {
            Some(_) => {
                let creds = crate::bridge::auth::load_credentials().unwrap_or_default();
                let email = creds["email"].as_str().unwrap_or("unknown");
                let org = creds["org_name"].as_str().unwrap_or("");
                println!("Account: {} ({})", email, org);
            }
            None => {
                println!("\x1b[31m✗ Not logged in. Run: writ-agent login\x1b[0m");
                std::process::exit(1);
            }
        }
    }

    // Step 2: Ensure browser is installed
    match crate::browser::install::ensure_browser_installed().await {
        Ok(true) => tracing::info!("Browser ready"),
        Ok(false) => tracing::warn!("Browser install returned false"),
        Err(e) => {
            println!("  ⚠ Browser install failed: {}", e);
            if debug {
                tracing::error!(error = %e, "Browser install failed");
            }
        }
    }

    // Step 2.5: Stealth driver — use patchright if present; otherwise let the user
    // choose to install it (stealth) or continue with regular Playwright. Must run
    // BEFORE initialize() (which selects the driver at Playwright::launch).
    crate::browser::install::ensure_stealth_driver().await;

    // Step 3: Initialize recorder engine (warm browser)
    let browser_manager = std::sync::Arc::new(
        crate::browser::manager::BrowserManager::new(std::sync::Arc::new(app_config.clone()))
    );

    if let Err(e) = browser_manager.initialize().await {
        println!("  ⚠ Playwright initialization failed: {}", e);
        if debug {
            tracing::error!(error = %e, "Playwright init failed");
        }
    }

    if let Err(e) = browser_manager.ensure_warm_browser().await {
        println!("  ⚠ Browser warm-up failed: {}", e);
        if debug {
            tracing::error!(error = %e, "Browser warm-up failed");
        }
    }

    let mut recorder = crate::recorder::core::PlaywrightRecorder::new(browser_manager.clone());
    recorder.start_cleanup_loop();
    let recorder = std::sync::Arc::new(recorder);

    println!("Connecting to {}...", config.saas.url);

    // Step 4: Start the SaaS bridge (connects to gateway, runs listen loop)
    let bridge = crate::bridge::saas_bridge::SaaSBridge::new(
        config.clone(),
        service_mode,
        recorder.clone(),
    );

    // Run bridge (blocks until shutdown or Ctrl+C)
    tokio::select! {
        _ = bridge.run() => {}
        _ = tokio::signal::ctrl_c() => {
            println!("\nShutting down...");
        }
    }

    // Cleanup
    bridge.shutdown();
    // recorder.shutdown() would go here but it takes &mut self
    if let Err(e) = browser_manager.shutdown().await {
        tracing::warn!(error = %e, "Browser shutdown error");
    }
    println!("Agent stopped.");
}

fn run_status() {
    let config = setup::load_config();
    let display_info = display::check_display_available();

    println!();
    println!("\x1b[1mWrit Status\x1b[0m");
    println!("{}", "─".repeat(40));

    // AI provider
    println!(
        "  AI Provider:   {}",
        config.ai.provider.as_deref().unwrap_or("not configured")
    );
    println!(
        "  API Key:       {}",
        setup::mask_key(config.ai.api_key.as_deref())
    );
    if let Some(ref url) = config.ai.base_url {
        println!("  Base URL:      {}", url);
    }
    if let Some(ref model) = config.ai.model {
        println!("  Model:         {}", model);
    }

    // Recorder
    println!();
    println!("  Display Mode:  {}", config.recorder.display_mode);
    println!("  Headless:      {}", config.recorder.headless);
    println!("  Max Sessions:  {}", config.recorder.max_sessions);
    match config.recorder.chrome_profile_source.as_deref().filter(|s| !s.is_empty()) {
        Some(src) => println!("  Profile:       imported ({})", src),
        None => println!("  Profile:       clean baseline"),
    }

    // Display detection
    println!();
    if display_info.available {
        println!(
            "  \x1b[32mDisplay:\x1b[0m {} ({})",
            display_info.message,
            format_args!("{:?}", display_info.display_type)
        );
    } else {
        println!("  \x1b[33mDisplay:\x1b[0m {}", display_info.message);
    }

    // SaaS connection
    println!();
    println!("  SaaS URL:      {}", config.saas.url);
    let creds_path = setup::get_credentials_path();
    if creds_path.exists() {
        println!("  \x1b[32mSaaS: Linked\x1b[0m");
    } else {
        println!("  \x1b[33mSaaS: Not linked\x1b[0m");
        println!("    Run: writ setup");
    }

    // Config file location
    println!();
    println!("  Config: {}", setup::get_config_path().display());
    println!();
}
