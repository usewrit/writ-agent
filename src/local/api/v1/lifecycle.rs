//! `/v1/shutdown` — ask the daemon to stop ITSELF, gracefully.
//!
//! Route (FIXED CONTRACT — the Tauri shell's "Quit" calls it; loopback + bearer gated by `server.rs`):
//!   POST /v1/shutdown  → { "stopping": true }
//!
//! ## Why this exists
//! The desktop shell used to stop the daemon by killing the process. On unix that is SIGTERM, which
//! the daemon handles and unwinds cleanly. On Windows there is no SIGTERM, and the shell's
//! `taskkill /PID <pid> /T` **could not stop it at all**: without `/F`, taskkill asks by posting to
//! the target's console or windows, and a daemon spawned as a sidecar by a GUI-subsystem shell has
//! neither — so "Quit" exited the app and left `writ-agentd` running. Adding `/F` would only trade
//! that for a `TerminateProcess`: no cleanup, so `runtime.json` and the singleton lock survive and
//! the next boot has to sweep them ("removing stale singleton lock (owner not alive)").
//!
//! Asking the daemon to stop itself is the only approach that is both reliable and clean, and it is
//! identical on every platform.
//!
//! ## Ordering
//! The handler RETURNS FIRST and requests the stop a moment later, from a detached task. Requesting
//! inline would resolve `writ-agentd`'s shutdown `select!` while this very response is still being
//! written, and the caller would see a dropped connection rather than a confirmation — so the shell
//! could not tell "the daemon accepted and is stopping" from "the daemon was already dead".
//!
//! ## Security
//! This is a remote "stop the service" button, so it is exactly as protected as the rest of `/v1`:
//! loopback-bound, bearer-gated, with the Origin/Host guard applied once in `server.rs`. It takes no
//! parameters, so there is nothing to inject; the only capability it grants a caller who already
//! holds the runtime token is one they already have (that token also authorizes running browsers).

use crate::local::error::LocalResult;
use crate::local::server::AppState;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};

/// How long to let the HTTP response flush before entering the shutdown path.
///
/// Small enough that "Quit" stays instant, long enough for a loopback response to reach a client
/// that is already connected. The shell does not depend on the exact value — it waits for the
/// PROCESS to disappear and force-kills if it does not — this only makes the common path clean.
const RESPONSE_GRACE: std::time::Duration = std::time::Duration::from_millis(250);

/// Mount `/v1/shutdown`. Auth is applied by `server.rs`.
pub fn router() -> Router<AppState> {
    Router::new().route("/v1/shutdown", post(shutdown))
}

/// `POST /v1/shutdown` — begin a graceful stop. Idempotent: calling it twice is not an error, and a
/// stop already in progress simply stays in progress.
///
/// Returns immediately. The daemon then drains the scheduler, stops the cloud-agent/relay
/// supervisors, removes `agentd.json`, and releases the singleton lock + `runtime.json` — the same
/// teardown a SIGTERM performs, because it is literally the same code path.
async fn shutdown() -> LocalResult<Json<Value>> {
    tokio::spawn(async move {
        tokio::time::sleep(RESPONSE_GRACE).await;
        crate::local::shutdown::request("POST /v1/shutdown");
    });
    Ok(Json(json!({ "stopping": true })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::shutdown;

    /// The response must come back BEFORE the shutdown is requested, or the caller sees a dropped
    /// connection instead of a confirmation and cannot distinguish "accepted" from "already dead".
    #[tokio::test]
    async fn responds_before_requesting_the_stop() {
        let body = shutdown().await.expect("handler succeeds");
        assert_eq!(body.0["stopping"], json!(true));
        // Still not requested at the instant the response is produced.
        assert!(
            !shutdown::is_requested(),
            "the stop must be deferred until after the response has had time to flush"
        );
        // …and it does land shortly after.
        tokio::time::timeout(std::time::Duration::from_secs(5), shutdown::requested())
            .await
            .expect("the deferred request must fire");
    }
}
