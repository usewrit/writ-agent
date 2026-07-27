// `cloud` (managed agent) and `fleet` (OSS self-host coordinator) are mutually exclusive: the
// self-host build MUST be physically incapable of carrying cloud code. Enabling both is a
// configuration error, not a runtime toggle.
#[cfg(all(feature = "cloud", feature = "fleet"))]
compile_error!(
    "features `cloud` and `fleet` are mutually exclusive: `fleet` is the cloud-free OSS \
     self-host build and cannot coexist with the managed-cloud `cloud` feature"
);

pub mod config;
pub mod models;
pub mod browser;
pub mod recorder;
pub mod ai;
pub mod automation;
// `streaming` is SHARED (the local engine's `local::engine::streaming` drives the same
// `streaming::manager`/`streaming::runtime_bridge`), so it stays ungated. It carries no cloud
// coupling of its own.
pub mod streaming;
pub mod dom;
pub mod codegen;
pub mod security;
pub mod util;
pub mod monitor;
// `bridge` is MIXED and stays UNGATED: its neutral `otp_entry` submodule (used by the recorder and
// by the extracted `automation::agent_actions`) must remain available in the cloud-free `fleet`
// build. The cloud submodules (`auth`/`saas_bridge`/`session_relay`/`speed_profile`) are gated
// INSIDE `bridge/mod.rs` behind `cloud`.
pub mod bridge;

// Cloud standalone-agent surfaces (managed product). Physically OMITTED from the OSS self-host
// export; gated so `--features local,fleet` compiles with zero cloud code.
#[cfg(feature = "cloud")]
pub mod server;
#[cfg(feature = "cloud")]
pub mod api;
#[cfg(feature = "cloud")]
pub mod gateway;
#[cfg(feature = "cloud")]
pub mod cli;

// Dragnet crawl shard runner — the per-shard fetch+extract+link-harvest that BOTH the
// cloud `writ-agent` (SaaSBridge) and the OSS fleet agent (FleetBridge) execute. Ungated
// (base deps only: reqwest + scraper + BrowserManager) so a crawl shard runs on every
// agent build. The local daemon's full-crawl control loop stays `local`-gated inside this
// module (it needs the SQLite store); see `crate::local::crawl` (aliased below).
pub mod crawl_shard;

// Writ Desktop OSS local backend (single Rust process). Feature-gated so the default/cloud
// `writ-agent` build is byte-unchanged. See the local-backend spec / the implementation plan.
#[cfg(feature = "local")]
pub mod local;
