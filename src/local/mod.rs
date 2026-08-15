//! Writ Desktop — local backend (single-user, offline-first, SQLCipher-encrypted).
//!
//! This module tree is the OSS desktop app's backend, built net-new in Rust inside the
//! `writ-agent` crate behind the `local` cargo feature. It extends this crate
//! (the engine) — it does NOT port or bundle the legacy Python `desktop-agent`.
//!
//! Layers (built foundation-first per ENGINEERING_GUIDELINES.md): error → config → db → vault →
//! storage → engine → scheduler → api. House style: module-local `thiserror` where callers
//! branch + `anyhow` glue; no `async-trait` (boxed-future); `tracing` only; serde snake_case.

pub mod error;
pub mod config;
pub mod crash;
pub mod logging;
pub mod data_query;
pub mod db;
pub mod backup;
pub mod retention;
// The single seam every OS-keyring entry is opened through (vault root, cloud token, channel key,
// relay credential). Production is a pass-through; `cfg(test)` swaps in an in-memory store so unit
// tests neither touch the developer's real Keychain nor contend on it under the parallel run.
pub mod keyring_store;
pub mod vault;
pub mod vault_lock;
pub mod vault_recovery;
pub mod vault_rotate;
pub mod storage;
pub mod governor;
pub mod engine;
pub mod flow;
// The crawl module moved to the ungated `crate::crawl_shard` (so a shard runs on any agent
// build); re-export it here as `crate::local::crawl` so local callers (mcp/concierge/api,
// and the `local`-gated daemon control loop) keep their existing paths. The daemon-only
// entry points (start_crawl/run_crawl/…) are `local`-gated inside that module.
pub use crate::crawl_shard as crawl;
pub mod monitor;
pub mod runtime_setup;
pub mod update;
pub mod record;
// Backend-orchestrated interactive/AI browsing session handler (`session_open`/`ai_session_open`/
// `agent_action`/`ai_session_close` + spectate screencast). Relocated here from
// `local::cloud::agent::ai_browsing` so it is available to the OSS fleet worker as well as the
// desktop cloud-link (which reaches it via a re-export shim at `local::cloud::agent::ai_browsing`).
// Transport-agnostic (reuses the shared `automation::run_agent_actions` + `extract_session_state`),
// so it carries no cloud coupling — gated only on `local`.
pub mod browse;
pub mod scheduler;
pub mod mcp;
pub mod ai;
pub mod auth;
pub mod authenticator_import;
pub mod persona_login;
pub mod runtime_token;
pub mod ws_ticket;
pub mod tls;
// Desktop cloud-link (managed product): the cloud dispatch bridge. Gated behind `cloud`;
// physically OMITTED from the OSS self-host export.
#[cfg(feature = "cloud")]
pub mod cloud;
// IP-relay node — a cloud-link capability DEFERRED to phase 2, behind its own default-off
// `ip_relay` feature so no default build (managed desktop included) compiles it.
#[cfg(feature = "ip_relay")]
pub mod relay;
pub mod shutdown;
pub mod server;
pub mod store;
pub mod api;
pub mod app;
pub mod cli;
