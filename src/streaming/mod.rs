pub mod manager;
pub mod health;
pub mod commands;
pub mod handlers;
pub mod threads;
pub mod runtime_bridge;
pub mod background;

/// Frames the streaming session emits toward whatever transport is wired to it (the cloud bridge WS
/// in the managed build, or nothing in the local daemon). Defined here — in the always-compiled
/// `streaming` module — because the streaming keepalive/idle loops (CR-2) depend on it in the
/// cloud-free `fleet` build where `bridge::session_relay` is omitted. The cloud `session_relay`
/// re-exports this type so its own callers are unchanged.
pub enum BridgeOutgoing {
    Json(serde_json::Value),
    Binary(Vec<u8>),
}
