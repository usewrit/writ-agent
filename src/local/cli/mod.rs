//! `writ` CLI logic — the user-facing command surface for the desktop daemon.
//!
//! This module holds ALL the command implementations so the `src/bin/writ.rs` binary is a thin clap
//! shell that parses args and dispatches here. Layout:
//!   * [`client`]    — a blocking loopback HTTP client (discovery + `wlt_` bearer from `runtime.json`).
//!   * [`commands`]  — synchronous subcommands (`init` / `start` / `status` / `token` / `config` /
//!                      `cloud login|logout|status`).
//!   * [`mcp_stdio`] — the async `mcp stdio` runner (bootstraps an `AppState`, then `run_stdio`).
//!   * [`service`]   — thin wrappers over [`crate::local::app::supervisor`] for service install/uninstall
//!                      (also reachable from `writ-agentd install-service`/`uninstall-service`).
//!
//! House style: module-local error reuse, `tracing` only, NEVER log a token/secret, no `async-trait`.

pub mod client;
pub mod commands;
pub mod mcp_stdio;
pub mod service;

pub use commands::{
    cloud_login, cloud_logout, cloud_status, config_get, config_set, init, start, status,
    telemetry_report, telemetry_set, telemetry_status, token_rotate, token_show,
};
