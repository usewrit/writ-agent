//! Scheduled, parallel target-monitoring subsystem.
//!
//! The submodules below (`capacity`/`checker`/`grouping`/`scheduler`/…) are the NEUTRAL scheduling
//! primitives, reused by both the cloud recorder-agent monitoring loop and the local desktop
//! monitor engine (`local::monitor`, `local::api::v1::extractors`). They carry no cloud coupling.
//!
//! The autonomous, coordinator-driven monitoring LOOP (`MonitorState` / `run_monitor_loop`) lives in
//! [`cloud_loop`]. It depends only on `bridge::session_relay` (the ungated `BridgeOutgoing`) + the
//! shared `wire_exec` execute path + these neutral primitives, so it compiles for BOTH the managed
//! cloud recorder (`cloud`) AND the OSS self-host fleet worker (`fleet,local`) — a fleet worker is a
//! shared monitoring-fleet node (unlike a user's desktop), so it runs coordinator-assigned checks.

pub mod capacity;
pub mod checker;
pub mod extract;
pub mod grouping;
pub mod incremental;
pub mod models;
pub mod scheduler;
pub mod workflow_scheduler;

// Available to the managed cloud recorder AND the OSS fleet worker (both dispatch monitor targets
// to their connected agents); omitted only from a build with neither feature.
#[cfg(any(feature = "cloud", all(feature = "fleet", feature = "local")))]
mod cloud_loop;
#[cfg(any(feature = "cloud", all(feature = "fleet", feature = "local")))]
pub use cloud_loop::{run_monitor_loop, MonitorState};
