use std::io::Write;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::display::{self, DisplayMode};

// ---------------------------------------------------------------------------
// Config structure — mirrors Python config.py DEFAULT_CONFIG exactly
// ---------------------------------------------------------------------------

/// The whole `~/.writ/config.yaml` document.
///
/// `Debug` is hand-written only because it nests [`AiConfig`], which redacts its key — a derived
/// `Debug` here would print the key through it.
#[derive(Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    #[serde(default = "default_ai")]
    pub ai: AiConfig,
    #[serde(default = "default_recorder")]
    pub recorder: RecorderConfig,
    #[serde(default = "default_app")]
    pub app: AppUiConfig,
    #[serde(default = "default_saas")]
    pub saas: SaasConfig,
}

impl std::fmt::Debug for AgentConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentConfig")
            .field("ai", &self.ai) // AiConfig's own Debug redacts the key
            .field("recorder", &self.recorder)
            .field("app", &self.app)
            .field("saas", &self.saas)
            .finish()
    }
}

/// BYO AI provider settings, including the raw provider API key.
///
/// `Debug` is hand-written: a derived one prints `api_key` in full, and this struct reaches
/// `tracing`/panic messages (it is a field of [`AgentConfig`], which `cli::commands` carries around).
/// The pattern matches `local::ai::provider::AiConfig`, `local::cloud::token::TokenPair` and
/// `local::vault` — key material is reported only as present/absent.
#[derive(Clone, Serialize, Deserialize)]
pub struct AiConfig {
    pub provider: Option<String>,
    pub api_key: Option<String>,
    pub base_url: Option<String>,
    pub model: Option<String>,
}

impl std::fmt::Debug for AiConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AiConfig")
            .field("provider", &self.provider)
            .field("model", &self.model)
            .field("base_url", &self.base_url)
            // NEVER print key material — only whether one is configured.
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecorderConfig {
    #[serde(default = "default_true")]
    pub headless: bool,
    #[serde(default = "default_display_mode")]
    pub display_mode: String,
    #[serde(default = "default_max_sessions")]
    pub max_sessions: u32,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    /// Source path of an imported local browser profile (set by
    /// `writ-agent import-profile`). When present, `start` seeds the baseline
    /// from a copy of it so sessions look like a returning user. None = clean.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chrome_profile_source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppUiConfig {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_true")]
    pub auto_open: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaasConfig {
    #[serde(default = "default_saas_url")]
    pub url: String,
    /// Permit plaintext ws://_/http:// to a NON-loopback host. Off by default —
    /// plaintext exposes the agent token + all session traffic on the wire. Only
    /// enable on a trusted private network you accept the risk on.
    #[serde(default)]
    pub allow_insecure: bool,
}

fn default_ai() -> AiConfig {
    AiConfig { provider: None, api_key: None, base_url: None, model: None }
}
fn default_recorder() -> RecorderConfig {
    RecorderConfig {
        headless: true,
        display_mode: "auto".to_string(),
        max_sessions: 2,
        timeout_ms: 120_000,
        chrome_profile_source: None,
    }
}
fn default_app() -> AppUiConfig {
    AppUiConfig { port: 9090, auto_open: true }
}
fn default_saas() -> SaasConfig {
    SaasConfig { url: "http://localhost:8000".to_string(), allow_insecure: false }
}
fn default_true() -> bool { true }
fn default_display_mode() -> String { "auto".to_string() }
fn default_max_sessions() -> u32 { 2 }
fn default_timeout() -> u64 { 120_000 }
fn default_port() -> u16 { 9090 }
fn default_saas_url() -> String { "http://localhost:8000".to_string() }

// ---------------------------------------------------------------------------
// Provider definitions — mirrors Python config.py PROVIDERS exactly
// ---------------------------------------------------------------------------

pub struct ProviderInfo {
    pub key: &'static str,
    pub label: &'static str,
    pub env_key: &'static str,
    pub default_model: &'static str,
}

pub const PROVIDERS: &[ProviderInfo] = &[
    ProviderInfo {
        key: "anthropic",
        label: "Anthropic (Claude)",
        env_key: "ANTHROPIC_API_KEY",
        default_model: "claude-sonnet-4-20250514",
    },
    ProviderInfo {
        key: "openai",
        label: "OpenAI",
        env_key: "OPENAI_API_KEY",
        default_model: "gpt-4o",
    },
    ProviderInfo {
        key: "ollama",
        label: "Ollama (local)",
        env_key: "OPENAI_API_KEY",
        default_model: "llama3",
    },
    ProviderInfo {
        key: "custom",
        label: "Custom (OpenAI-compatible)",
        env_key: "OPENAI_API_KEY",
        default_model: "",
    },
];

// ---------------------------------------------------------------------------
// Config file I/O — mirrors Python config.py paths + permissions
// ---------------------------------------------------------------------------

pub fn get_config_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".writ")
}

pub fn get_config_path() -> PathBuf {
    get_config_dir().join("config.yaml")
}

pub fn get_credentials_path() -> PathBuf {
    get_config_dir().join("credentials.json")
}

fn ensure_config_dir() {
    let dir = get_config_dir();
    if !dir.exists() {
        let _ = std::fs::create_dir_all(&dir);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
    }
}

pub fn load_config() -> AgentConfig {
    let path = get_config_path();
    if path.exists() {
        let content = std::fs::read_to_string(&path).unwrap_or_default();
        serde_yaml::from_str(&content).unwrap_or_else(|_| AgentConfig {
            ai: default_ai(),
            recorder: default_recorder(),
            app: default_app(),
            saas: default_saas(),
        })
    } else {
        AgentConfig {
            ai: default_ai(),
            recorder: default_recorder(),
            app: default_app(),
            saas: default_saas(),
        }
    }
}

/// Write `~/.writ/config.yaml`.
///
/// The file holds `ai.api_key` in the clear, so it must never exist at umask-default permissions —
/// not even briefly. The previous `File::create` → write → `set_permissions(0600)` sequence created it
/// world-readable (0644 under a typical umask) and only tightened it afterwards, leaving a window in
/// which any local user could open it; if another process held it open across the chmod, the tightened
/// mode did not apply to that descriptor at all.
///
/// This is the `O_CREAT|O_EXCL` + `.mode(0o600)` + rename pattern already used by
/// `local::vault::write_secret_file` (that helper lives behind the `local` feature, which this
/// cloud-only CLI module cannot depend on, so the pattern is reproduced rather than called):
/// perms are set AT CREATION on a private sibling temp, the bytes are fsynced, then the temp is
/// renamed over the target. No observer ever sees the contents at loose permissions, and a crash
/// mid-write leaves the previous config intact instead of a truncated one.
pub fn save_config(config: &AgentConfig) {
    ensure_config_dir();
    let path = get_config_path();
    let yaml = serde_yaml::to_string(config).unwrap_or_default();

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let tmp = path.with_file_name(format!(".config.yaml.tmp.{}", std::process::id()));
        let _ = std::fs::remove_file(&tmp); // a stale temp from a prior crash would fail create_new
        let opened = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true) // O_EXCL: never adopt a file someone else planted here
            .mode(0o600) // perms at creation → no world-readable window
            .open(&tmp);
        match opened {
            Ok(mut f) => {
                if f.write_all(yaml.as_bytes()).and_then(|_| f.sync_all()).is_err() {
                    let _ = std::fs::remove_file(&tmp);
                    eprintln!("  Could not write {}", path.display());
                    return;
                }
                drop(f);
                if std::fs::rename(&tmp, &path).is_err() {
                    let _ = std::fs::remove_file(&tmp);
                    eprintln!("  Could not write {}", path.display());
                }
            }
            Err(e) => eprintln!("  Could not write {} ({e})", path.display()),
        }
    }
    #[cfg(not(unix))]
    {
        // Windows: file permissions come from the parent directory's ACL, which `ensure_config_dir`
        // creates under the user's profile.
        if let Ok(mut f) = std::fs::File::create(&path) {
            let _ = f.write_all(yaml.as_bytes());
        }
    }
}

pub fn mask_key(key: Option<&str>) -> String {
    match key {
        None | Some("") => "(not set)".to_string(),
        Some(k) if k.len() <= 8 => "****".to_string(),
        Some(k) => format!("****{}", &k[k.len() - 4..]),
    }
}

pub fn set_config_value(key: &str, value: &str) {
    let mut config = load_config();
    let parts: Vec<&str> = key.split('.').collect();

    let _parsed_value: serde_yaml::Value = match value {
        "true" | "True" => serde_yaml::Value::Bool(true),
        "false" | "False" => serde_yaml::Value::Bool(false),
        v if v.parse::<i64>().is_ok() => {
            serde_yaml::Value::Number(serde_yaml::Number::from(v.parse::<i64>().unwrap()))
        }
        v => serde_yaml::Value::String(v.to_string()),
    };

    // Apply to the right field
    match (parts.first(), parts.get(1)) {
        (Some(&"ai"), Some(&"provider")) => config.ai.provider = Some(value.to_string()),
        (Some(&"ai"), Some(&"api_key")) => config.ai.api_key = Some(value.to_string()),
        (Some(&"ai"), Some(&"base_url")) => config.ai.base_url = Some(value.to_string()),
        (Some(&"ai"), Some(&"model")) => config.ai.model = Some(value.to_string()),
        (Some(&"recorder"), Some(&"headless")) => config.recorder.headless = value == "true",
        (Some(&"recorder"), Some(&"display_mode")) => config.recorder.display_mode = value.to_string(),
        (Some(&"recorder"), Some(&"max_sessions")) => {
            config.recorder.max_sessions = value.parse().unwrap_or(2);
        }
        (Some(&"recorder"), Some(&"chrome_profile_source")) => {
            config.recorder.chrome_profile_source =
                if value.is_empty() { None } else { Some(value.to_string()) };
        }
        (Some(&"saas"), Some(&"url")) => config.saas.url = value.to_string(),
        (Some(&"app"), Some(&"port")) => {
            config.app.port = value.parse().unwrap_or(9090);
        }
        _ => {
            eprintln!("Unknown config key: {}", key);
            return;
        }
    }

    save_config(&config);
}

pub fn get_config_value(key: &str) -> Option<String> {
    let config = load_config();
    let parts: Vec<&str> = key.split('.').collect();

    match (parts.first(), parts.get(1)) {
        (Some(&"ai"), Some(&"provider")) => config.ai.provider,
        (Some(&"ai"), Some(&"api_key")) => config.ai.api_key,
        (Some(&"ai"), Some(&"base_url")) => config.ai.base_url,
        (Some(&"ai"), Some(&"model")) => config.ai.model,
        (Some(&"recorder"), Some(&"headless")) => Some(config.recorder.headless.to_string()),
        (Some(&"recorder"), Some(&"display_mode")) => Some(config.recorder.display_mode),
        (Some(&"recorder"), Some(&"max_sessions")) => Some(config.recorder.max_sessions.to_string()),
        (Some(&"recorder"), Some(&"chrome_profile_source")) => config.recorder.chrome_profile_source,
        (Some(&"saas"), Some(&"url")) => Some(config.saas.url),
        (Some(&"app"), Some(&"port")) => Some(config.app.port.to_string()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Apply AI env vars — mirrors Python config.py apply_ai_env_vars()
// ---------------------------------------------------------------------------

/// Resolve the configured BYO AI provider settings for the caller, and stage only the NON-SECRET ones
/// into the process environment.
///
/// # The key no longer goes into the environment
///
/// This function used to `set_var("ANTHROPIC_API_KEY" | "OPENAI_API_KEY", …)`. The agent then spawns
/// the Playwright node driver, Chromium and (on Linux) Xvfb; none of those get an `env_clear`, so the
/// key was INHERITED by the browser subprocess — the least-trusted component in the whole system — and
/// readable via `ps e` / `/proc/<pid>/environ` by any process running as the same user. Redacting the
/// key in logs does nothing about that: the environment is not a log.
///
/// A previous pass added [`crate::cli::display::command_without_ai_keys`], which scrubs both variables
/// from every child this crate spawns itself. That closes the processes we launch, but NOT the browser
/// launch inside the vendored `playwright-rs` crate, which builds its own `Command` we do not touch.
/// The only real close is therefore to stop putting the key in the environment at all — which is
/// possible now that [`crate::ai::client::direct_ai_config_from`] accepts the key as a parameter
/// instead of reading it back out of the environment.
///
/// The returned `(env_var_name, key)` pairs let `cli::commands::start` build `AppConfig` from the
/// IN-MEMORY config (that is what it already did with them). `OPENAI_BASE_URL`/`*_MODEL` are still
/// staged — they are not secrets, and the env fallback in `ai::client::detect_direct_ai_config` needs
/// them when a key legitimately comes from the user's own shell environment.
///
/// Mirrors Python `config.py apply_ai_env_vars()` minus the key staging.
pub fn apply_ai_env_vars(config: &AgentConfig) -> Vec<(&'static str, String)> {
    let mut staged: Vec<(&'static str, String)> = Vec::new();
    let ai = &config.ai;
    let provider = match &ai.provider {
        Some(p) => p.as_str(),
        None => return staged,
    };
    let api_key = match &ai.api_key {
        Some(k) if !k.is_empty() => k.as_str(),
        _ => return staged,
    };

    if provider == "anthropic" {
        // Returned to the caller, NOT `set_var`'d — see the note above.
        staged.push(("ANTHROPIC_API_KEY", api_key.to_string()));
        if let Some(model) = &ai.model {
            std::env::set_var("ANTHROPIC_MODEL", model);
        }
    } else {
        staged.push(("OPENAI_API_KEY", api_key.to_string()));
        if let Some(base_url) = &ai.base_url {
            std::env::set_var("OPENAI_BASE_URL", base_url);
        } else {
            // Set default base_url for known providers
            for p in PROVIDERS {
                if p.key == provider {
                    if p.key == "ollama" {
                        std::env::set_var("OPENAI_BASE_URL", "http://localhost:11434/v1");
                    }
                    break;
                }
            }
        }
        if let Some(model) = &ai.model {
            std::env::set_var("OPENAI_MODEL", model);
        }
    }
    staged
}

// ---------------------------------------------------------------------------
// Interactive setup — mirrors Python cli.py _setup_interactive() exactly
// + adds display mode selector from start.sh
// ---------------------------------------------------------------------------

pub fn run_interactive_setup() {
    let mut config = load_config();

    println!();
    println!("\x1b[1mWrit Setup\x1b[0m");
    println!("{}", "─".repeat(40));
    println!();

    // --- AI provider selection ---
    println!("Select your AI provider:");
    for (i, p) in PROVIDERS.iter().enumerate() {
        let extra = if p.key == "ollama" {
            " (auto-detects local instance)"
        } else {
            ""
        };
        println!("  {}. {}{}", i + 1, p.label, extra);
    }

    let choice = prompt_number("Choice", 1, 1, PROVIDERS.len() as u32);
    let provider = &PROVIDERS[(choice - 1) as usize];
    config.ai.provider = Some(provider.key.to_string());
    println!("  → {}", provider.label);
    println!();

    match provider.key {
        "ollama" => {
            let base_url = config.ai.base_url.clone()
                .unwrap_or_else(|| "http://localhost:11434".to_string());
            println!("Checking Ollama at {}...", base_url);
            // Simple connectivity check
            let check_url = format!("{}/api/tags", base_url);
            let reachable = reqwest::blocking::get(&check_url).is_ok();
            if reachable {
                println!("  \x1b[32m✓ Ollama detected\x1b[0m");
            } else {
                println!("  \x1b[31m✗ Ollama not detected. Make sure it's running.\x1b[0m");
            }
            config.ai.base_url = Some(format!("{}/v1", base_url.trim_end_matches('/')));
            config.ai.api_key = Some("ollama".to_string());
            config.ai.model = Some(prompt_string("Model", "llama3"));
        }
        "custom" => {
            let base_url = prompt_string("Base URL (OpenAI-compatible)", "http://localhost:8080/v1");
            config.ai.base_url = Some(base_url.trim_end_matches('/').to_string());
            let api_key = prompt_string_hidden("API key (leave empty if not required)");
            config.ai.api_key = Some(if api_key.is_empty() { "none".to_string() } else { api_key });
            config.ai.model = Some(prompt_string("Model name", ""));
        }
        _ => {
            // Cloud providers (Anthropic / OpenAI)
            if let Some(ref current) = config.ai.api_key {
                println!("  Current key: {}", mask_key(Some(current)));
                let change = prompt_yn("  Change API key?", false);
                if change {
                    config.ai.api_key = Some(prompt_string_hidden("  API key"));
                }
            } else {
                config.ai.api_key = Some(prompt_string_hidden("  API key"));
            }

            println!("  Validating key...");
            let key_to_validate = config.ai.api_key.as_deref().unwrap_or("");
            validate_api_key(provider.key, key_to_validate);

            config.ai.model = Some(prompt_string("  Model", provider.default_model));
        }
    }

    // --- Display mode selector (from start.sh) ---
    println!();
    println!("Display mode:");
    let (mode, _xvfb_started) = display::interactive_display_mode_select();

    match mode {
        DisplayMode::Headed => {
            config.recorder.headless = false;
            config.recorder.display_mode = "headed".to_string();
        }
        DisplayMode::Headless => {
            config.recorder.headless = true;
            config.recorder.display_mode = "headless".to_string();
        }
        DisplayMode::Xvfb => {
            config.recorder.headless = false;
            config.recorder.display_mode = "xvfb".to_string();
        }
    }

    // --- Recorder settings ---
    println!();
    println!("Recorder settings:");
    let max_sessions = prompt_number("  Max concurrent browser sessions", 2, 1, 10);
    config.recorder.max_sessions = max_sessions;

    // --- SaaS URL ---
    println!();
    let saas_url = prompt_string("SaaS URL", &config.saas.url);
    config.saas.url = saas_url.trim_end_matches('/').to_string();

    // --- Save ---
    save_config(&config);
    println!();
    println!("\x1b[32m✓ Configuration saved to {}\x1b[0m",
        get_config_path().display());
    println!();
    println!("Next steps:");
    println!("  1. Run: writ-agent start");
    println!();
}

// ---------------------------------------------------------------------------
// API key validation
// ---------------------------------------------------------------------------

fn validate_api_key(provider_key: &str, api_key: &str) {
    if api_key.is_empty() {
        println!("  \x1b[33m(no key provided, skipping validation)\x1b[0m");
        return;
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build();
    let client = match client {
        Ok(c) => c,
        Err(_) => {
            println!("  \x1b[33m\u{2717} Could not create HTTP client (may still work)\x1b[0m");
            return;
        }
    };

    let result = match provider_key {
        "anthropic" => {
            client
                .post("https://api.anthropic.com/v1/messages")
                .header("x-api-key", api_key)
                .header("anthropic-version", "2023-06-01")
                .header("content-type", "application/json")
                .body(r#"{"model":"claude-sonnet-4-20250514","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}"#)
                .send()
        }
        "openai" => {
            client
                .get("https://api.openai.com/v1/models")
                .header("Authorization", format!("Bearer {}", api_key))
                .send()
        }
        _ => {
            println!("  \x1b[33m\u{2717} Validation not supported for this provider\x1b[0m");
            return;
        }
    };

    match result {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if status == 401 || status == 403 {
                println!("  \x1b[31m\u{2717} Invalid API key (HTTP {})\x1b[0m", status);
            } else {
                // Any non-auth-error means the key is accepted (even 400 means auth passed)
                println!("  \x1b[32m\u{2713} Valid\x1b[0m");
            }
        }
        Err(e) => {
            println!("  \x1b[33m\u{2717} Could not validate ({})\x1b[0m", e);
        }
    }
}

// ---------------------------------------------------------------------------
// Prompt helpers
// ---------------------------------------------------------------------------

fn prompt_string(prompt: &str, default: &str) -> String {
    if default.is_empty() {
        eprint!("{}: ", prompt);
    } else {
        eprint!("{} [{}]: ", prompt, default);
    }
    std::io::stderr().flush().ok();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();
    let input = input.trim();
    if input.is_empty() {
        default.to_string()
    } else {
        input.to_string()
    }
}

/// Read a SECRET from the terminal without echoing it.
///
/// Used for the Anthropic/OpenAI API key ([`run_interactive_setup`]) and for the pasted `wto_` account
/// token ([`crate::bridge::auth::device_flow_login`]). It previously did a plain `read_line`, despite a
/// comment saying "in a real implementation, use rpassword" — so every key and token the user typed
/// landed in terminal scrollback, in `tmux`/`script` capture files, in a screen share, and in CI job
/// output. `rpassword` is now a dependency; this is the one entry point for secret input.
///
/// Non-TTY stdin (a pipe / heredoc / CI) still works: there is no terminal to echo to, so we read a
/// plain line. Scripted `echo "$KEY" | writ setup` therefore behaves exactly as before. When stdin IS
/// a terminal we never echo — no flag, no override.
pub fn prompt_string_hidden(prompt: &str) -> String {
    use std::io::IsTerminal;

    if std::io::stdin().is_terminal() {
        // rpassword writes the prompt to the TTY itself and disables echo for the read.
        match rpassword::prompt_password(format!("{}: ", prompt)) {
            Ok(s) => return s.trim().to_string(),
            Err(e) => {
                // Terminal control failed (an exotic terminal). FAIL CLOSED rather than silently
                // falling back to an echoing read — a visible key is the thing we are preventing.
                eprintln!("\n  Could not disable terminal echo ({e}); refusing to read a secret in the clear.");
                eprintln!("  Set the value non-interactively instead (e.g. `writ-agent config set ai.api_key …`).");
                return String::new();
            }
        }
    }

    // Piped/redirected stdin: nothing is echoed to a terminal, so a plain line read is safe.
    eprint!("{}: ", prompt);
    std::io::stderr().flush().ok();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();
    input.trim().to_string()
}

fn prompt_number(prompt: &str, default: u32, min: u32, max: u32) -> u32 {
    loop {
        eprint!("{} [{}]: ", prompt, default);
        std::io::stderr().flush().ok();
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
        let input = input.trim();
        if input.is_empty() {
            return default;
        }
        if let Ok(n) = input.parse::<u32>() {
            if n >= min && n <= max {
                return n;
            }
        }
        println!("  Please enter a number between {} and {}", min, max);
    }
}

fn prompt_yn(prompt: &str, default: bool) -> bool {
    let suffix = if default { "[Y/n]" } else { "[y/N]" };
    eprint!("{} {}: ", prompt, suffix);
    std::io::stderr().flush().ok();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();
    let input = input.trim().to_lowercase();
    if input.is_empty() {
        return default;
    }
    input == "y" || input == "yes"
}
