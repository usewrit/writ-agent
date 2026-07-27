//! Local recording WebSocket — the STANDALONE desktop recorder.
//!
//! This is the fully-local recording subsystem for the Writ Desktop OSS app. On a `/ws/record`
//! connection the daemon spins up a [`crate::recorder::core::PlaywrightRecorder`] session on its
//! OWN warm Chromium (shared with the run engine via the same [`BrowserManager`]), drives it over
//! CDP, and carries the live session — screencast frames + recorded steps + page events — to the
//! desktop UI over a LOOPBACK WebSocket.
//!
//! There is NO ws-gateway transport, NO remote agent, NO cloud streaming relay, and NO
//! `/api/ws-ticket` here. The app is fully local with zero cloud. (The one exception is a single
//! pure helper — `automation::run_agent_actions` — reused so the local AI-assist agent
//! loop drives the page with the exact same action/observation contract the brain expects; it
//! touches no cloud transport or session state.)
//!
//! ## Protocol (identical to the cloud recorder, so the UI is transport-only)
//! The wire protocol is exactly what the desktop app's `BrowserRecorder` view already
//! speaks against the cloud recorder — the only thing that changes is the transport (a direct
//! loopback socket instead of the gateway relay). Frames are FLAT JSON (no `{channel:"session"}`
//! envelope — that envelope only existed so the cloud gateway could multiplex many sessions over one
//! socket; one loopback socket carries exactly one session, so frames go on the wire as-is).
//!
//! ### client → server (commands)
//!   * `{type:"start", url, options:{record_wait_steps?, capture_api?}}` — open a recording session
//!   * `{type:"action", action:"<click|type|press|scroll|navigate|wait|evaluate_js|...>", ...}` —
//!     a recorded interaction (flat: the `action` string names the type, params are siblings)
//!   * `{type:"agent_action", request_id, actions:[...]}` — ephemeral scraper-builder actions
//!   * `{type:"replay_steps", request_id, steps:[...], up_to_index, step_delay_ms?}` — "play to here"
//!   * `{type:"replay_cancel"}` — cancel an in-flight replay
//!   * `{type:"stop"}` — finalize + return the recorded steps
//!   * `{type:"ping"}` — heartbeat
//!
//! ### server → client (frames)
//!   * binary screencast frame: `[4B BE url_len][url UTF-8][JPEG]` (raw `ScreencastStream::encode_frame`)
//!   * `{type:"started", sessionId, url}`
//!   * `{type:"step_recorded", step}` / `{type:"step_updated", id, step}` (from the recorder event bus)
//!   * `{type:"navigation", url}` / `{type:"tab_list", tabs}` / `{type:"twofa_detected", ...}` (event bus)
//!   * `{type:"select_options", ...}` / `{type:"native_picker", ...}` (overlays)
//!   * `{type:"eval_result", result, error}` (script test) / `{type:"element_info", ...}` /
//!     `{type:"elements_in_region", elements}` / `{type:"dom_content", html}` (live picker)
//!   * `{type:"api_captured", call}` / `{type:"page_no_api", url, message}` (live API capture)
//!   * `{type:"agent_action_result", request_id, results, observation, error?}`
//!   * `{type:"replay_progress", request_id, index, status, reason?, total}` / `{type:"replay_done", ...}` /
//!     `{type:"replay_error", request_id, error}`
//!   * `{type:"stopped", steps, stepCount, raw_replay, rawReplayCount, network_calls, network_calls_count}`
//!   * `{type:"error", message}` / `{type:"pong"}`
//!
//! ## Auth (loopback only)
//! A browser cannot set an `Authorization` header on a WebSocket, so the connect carries the `wlt_`
//! UI token as a `?token=` query param (constant-time compared to the daemon's runtime token), and
//! the same loopback Origin/Host guard the bearer middleware enforces is applied here too
//! (DNS-rebind defense). The route is mounted OUTSIDE the header-bearer `auth_mw` layer (it does its
//! own query-token auth), exactly like the webhook bearer-exemption.

// `pub(crate)` so the cloud-agent `record` module can compose a `SessionDriver<CloudRecordSink>`
// over the SAME recorder driver the loopback `/ws/record` uses (single source of truth for the
// recorder-protocol frame dispatch — the transport / sink varies, not the semantics).
pub(crate) mod session;
// Transport-agnostic recording ROUTER/SINK (`CloudRecordSink`-style envelope + per-session
// registry). Relocated here from `local::cloud::agent::record` so BOTH the desktop cloud-link
// bridge AND the OSS fleet worker compose the SAME `SessionDriver` over their own outbound WS
// (the desktop cloud path reaches it via a re-export shim at `local::cloud::agent::record`). Gated
// only on `local`, so the fleet build (`local,fleet`) gets it without any cloud coupling.
pub mod bridge;
mod ws;

pub use ws::router;

#[cfg(test)]
mod tests;
