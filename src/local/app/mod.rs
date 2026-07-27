//! App lifecycle — the cold-start bootstrap that assembles a live [`crate::local::server::AppState`]
//! from `~/.writ/`, the singleton guard, and the `runtime.json` discovery descriptor.
//!
//! This is the glue between the already-built layers (config → vault → db → engine → server) and a
//! runnable process (`src/bin/writ-agentd.rs`). Net-new Rust — NOT ported from the legacy Python
//! `desktop-agent`.

pub mod health;
pub mod heartbeat;
pub mod lifecycle;
pub mod runtime_file;
pub mod supervisor;

pub use health::{DaemonHealth, SharedHealth};
pub use heartbeat::{spawn_heartbeat, HeartbeatHandle};
pub use lifecycle::{bootstrap, release};
pub use runtime_file::RuntimeInfo;
