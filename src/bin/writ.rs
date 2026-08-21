//! `writ` — the user-facing CLI for the Writ Desktop OSS daemon.
//!
//! A thin clap shell: it parses subcommands and dispatches into [`writ_agent::local::cli`], which
//! owns all the logic. Only builds with the `local` cargo feature (`required-features = ["local"]`);
//! the default cloud `writ-agent` build never sees this binary.
//!
//! Subcommands:
//!   writ init                       — scaffold ~/.writ (dirs + config.toml + mint the wlt_ token)
//!   writ start [--foreground]       — launch the daemon (detached by default; attached with -f)
//!   writ status [--json]            — read agentd.json/runtime.json (+ a live /v1/agent probe)
//!   writ token show|rotate          — print or re-mint the loopback wlt_ token
//!   writ config get [key]           — read a config field (or the whole config)
//!   writ config set <key> <value>   — write a config field to ~/.writ/config.toml
//!   writ cloud login|logout|status  — device-flow link / unlink / reflection (via the daemon)
//!   writ mcp stdio                  — MCP over stdin/stdout (proxies to a running daemon, else boots)
//!
//! Diagnostics go to `tracing` (stderr); the only token that reaches stdout is from the explicit
//! `writ token show`/`rotate` commands. NEVER logs a token through `tracing`.

use clap::{Args, Parser, Subcommand};
use writ_agent::local::cli;
use writ_agent::local::config::Paths;
use writ_agent::local::error::LocalResult;

#[derive(Parser)]
#[command(
    name = "writ",
    version,
    about = "Writ Desktop — run browser automation locally",
    long_about = "Control the local Writ daemon (writ-agentd): scaffold the home, start/inspect the \
                  daemon, manage the loopback token + config, link a Writ Cloud account, and run the \
                  MCP server over stdio."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// First-run scaffold of ~/.writ (directories, default config.toml, loopback token).
    Init,

    /// Launch the local daemon (writ-agentd). Detached by default.
    Start(StartArgs),

    /// Show daemon health from the on-disk descriptors (+ a best-effort live probe).
    Status(StatusArgs),

    /// Manage the loopback wlt_ API token.
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },

    /// Read or write ~/.writ/config.toml fields.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Link / unlink a Writ Cloud account (drives the running daemon).
    Cloud {
        #[command(subcommand)]
        action: CloudAction,
    },

    /// Inspect or change anonymous usage telemetry (on by default; counts only, never content).
    Telemetry {
        #[command(subcommand)]
        action: TelemetryAction,
    },

    /// Run the MCP server.
    Mcp {
        #[command(subcommand)]
        action: McpAction,
    },
}

#[derive(Args)]
struct StartArgs {
    /// Run the daemon attached to this terminal (block until it exits) instead of detaching it.
    #[arg(short, long)]
    foreground: bool,
}

#[derive(Args)]
struct StatusArgs {
    /// Emit the merged status snapshot as JSON (for scripts). The wlt_ token is never included.
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand)]
enum TokenAction {
    /// Print the loopback wlt_ token (so you can wire a local client).
    Show,
    /// Mint a fresh loopback wlt_ token, replacing the persisted one.
    Rotate,
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Print one config value, or the whole config when KEY is omitted.
    Get {
        /// Config key, e.g. port, html_floor_ms, use_keyring. Omit to print everything.
        key: Option<String>,
    },
    /// Set a config field and persist config.toml.
    Set {
        /// Config key (port, html_floor_ms, js_floor_ms, telemetry_opt_in, use_keyring, cloud_expose_workflows).
        key: String,
        /// New value (type-checked against the field).
        value: String,
    },
}

#[derive(Subcommand)]
enum CloudAction {
    /// Run the OAuth device-authorization flow to link this desktop to a Writ Cloud account.
    Login,
    /// Unlink this desktop (clear the keyring token + link metadata).
    Logout,
    /// Show whether this desktop is linked, and to whom.
    Status,
}

#[derive(Subcommand)]
enum TelemetryAction {
    /// Show whether the anonymous usage summary is on, and what it has sent.
    Status,
    /// Turn it on.
    On,
    /// Turn it off (also drops the random report id, so re-enabling is unlinkable).
    Off,
    /// Print the EXACT report that would be sent, WITHOUT sending it.
    Preview {
        /// Day to summarize, `YYYY-MM-DD`. Defaults to yesterday.
        #[arg(long)]
        day: Option<String>,
    },
    /// Build and SEND a report now, instead of waiting for the daily tick.
    Send {
        /// Day to summarize, `YYYY-MM-DD`. Defaults to yesterday.
        #[arg(long)]
        day: Option<String>,
    },
}

#[derive(Subcommand)]
enum McpAction {
    /// Run the MCP server over stdin/stdout (line-delimited JSON-RPC). Proxies to a running daemon
    /// when one is discovered; boots a headless backend in-process otherwise.
    Stdio,
}

/// SYNCHRONOUS prologue: every process-ENVIRONMENT mutation happens here, before the tokio runtime
/// (and therefore any worker thread) exists. `std::env::set_var` is an unsynchronized write to the
/// libc `environ` block — UB once another thread may be in `getenv` (Rust 1.80+ marks it `unsafe`).
/// `dotenvy::dotenv()` sets every var from `.env`, and `init_driver_env` sets the Playwright driver
/// override that `BrowserManager::initialize()` used to set from inside the runtime.
fn main() -> std::process::ExitCode {
    dotenvy::dotenv().ok();
    writ_agent::browser::manager::init_driver_env();

    match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt.block_on(async_main()),
        Err(e) => {
            eprintln!("writ: could not start the async runtime: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn async_main() -> std::process::ExitCode {
    init_tracing();

    // Install the scrubbed panic hook early so a CLI panic is captured to ~/.writ/logs/crash-*.json
    // and reported to stderr as a REDACTED line (the hook replaces the default hook, which printed the
    // payload verbatim). Same hook as the daemon; the `binary` label distinguishes the source in a
    // diagnostics bundle. NEVER records a token/secret/path.
    writ_agent::local::crash::install_panic_hook("writ");

    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            // Friendly one-line error to stderr (stdout stays clean for piped output like `token show`).
            eprintln!("writ: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Parse args, resolve the home, and dispatch. All logic lives in `local::cli`.
async fn run() -> LocalResult<()> {
    let cli = Cli::parse();
    let paths = Paths::resolve()?;

    match cli.command {
        Command::Init => cli::init(&paths),
        Command::Start(a) => cli::start(&paths, a.foreground),
        Command::Status(a) => cli::status(&paths, a.json),
        Command::Token { action } => match action {
            TokenAction::Show => cli::token_show(&paths),
            TokenAction::Rotate => cli::token_rotate(&paths),
        },
        Command::Config { action } => match action {
            ConfigAction::Get { key } => cli::config_get(&paths, key.as_deref()),
            ConfigAction::Set { key, value } => cli::config_set(&paths, &key, &value),
        },
        Command::Cloud { action } => match action {
            CloudAction::Login => cli::cloud_login(&paths),
            CloudAction::Logout => cli::cloud_logout(&paths),
            CloudAction::Status => cli::cloud_status(&paths),
        },
        Command::Telemetry { action } => match action {
            TelemetryAction::Status => cli::telemetry_status(&paths),
            TelemetryAction::On => cli::telemetry_set(&paths, true),
            TelemetryAction::Off => cli::telemetry_set(&paths, false),
            TelemetryAction::Preview { day } => cli::telemetry_report(&paths, false, day.as_deref()),
            TelemetryAction::Send { day } => cli::telemetry_report(&paths, true, day.as_deref()),
        },
        Command::Mcp { action } => match action {
            // The stdio runner reserves stdout for the JSON-RPC stream (proxy-or-boot; see cli::mcp_stdio).
            McpAction::Stdio => cli::mcp_stdio::run().await,
        },
    }
}

/// Console tracing for the CLI → stderr (stdout is reserved for command output / the MCP stream).
/// Honors `RUST_LOG`, defaulting to `warn` so the CLI is quiet by default. Quiets the playwright-rs
/// `Disposable` channel spam the same way the daemon does, since `writ mcp stdio` drives the same
/// vendored engine.
///
/// The stderr sink goes through the SAME redacting writer as the daemon's stdout — it used to be raw
/// `std::io::stderr`, so `writ mcp stdio` (whose stderr an AI IDE captures into its own log files) and
/// any `writ … 2> file` had no scrub at all.
fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("warn"))
        .add_directive(
            "playwright_rs::server::object_factory=off"
                .parse()
                .expect("static directive"),
        )
        .add_directive(
            "playwright_rs::server::connection=off"
                .parse()
                .expect("static directive"),
        );
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_ansi(false)
        .with_writer(writ_agent::local::logging::Redacting(std::io::stderr))
        .init();
}
