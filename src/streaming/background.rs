//! Background maintenance loops for a live streaming session.
//!
//! These run for the lifetime of a [`StreamingSessionManager`] session and are
//! aborted in `end()`. Unlike the earlier no-op stubs, `hard_timeout` now
//! actually enforces `max_duration_seconds`: when a session's coordinator dies,
//! nothing else would ever close the browser, so Chromium would live forever.
//! The timeout closes the owned context handle (which tears down the page +
//! Chromium) and, if wired, emits a terminal `streaming_session_ended` frame so
//! the coordinator learns the session is gone.

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;

use crate::streaming::BridgeOutgoing;
use crate::config::constants;

/// Shared handles the background loops need to observe activity and act on the
/// live session without holding a borrow on the (Mutex-guarded) manager.
#[derive(Clone)]
pub struct BackgroundCtx {
    pub session_key: String,
    /// Epoch-millis of the last touch(); bumped by `StreamingSessionManager::touch`.
    /// The idle loop compares `now - last_activity` against the idle timeout.
    pub last_activity_ms: Arc<AtomicI64>,
    /// Set true once the idle loop has emitted `__session_idle`, so it fires once.
    pub idle: Arc<AtomicBool>,
    /// Context handle to tear down on hard timeout (closes page + Chromium).
    pub context: Option<playwright_rs::BrowserContext>,
    /// Optional outgoing WS sender so the loops can emit keepalive / idle /
    /// terminal frames to the coordinator. Absent on the standalone/local path
    /// (there is no coordinator to notify — the timeout still closes the browser).
    pub outgoing: Option<tokio::sync::mpsc::UnboundedSender<BridgeOutgoing>>,
    /// Best-effort current URL for the keepalive frame; static start URL is fine.
    pub url: Option<String>,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Emit periodic keepalive frames so the coordinator's liveness view stays warm.
pub async fn keepalive_loop(ctx: BackgroundCtx) {
    loop {
        tokio::time::sleep(constants::STREAMING_KEEPALIVE_INTERVAL).await;

        let idle = ctx.idle.load(Ordering::Relaxed);
        tracing::trace!(session_key = %ctx.session_key, idle, "Streaming keepalive");

        if let Some(ref tx) = ctx.outgoing {
            let frame = serde_json::json!({
                "type": "streaming_keepalive",
                "session_key": ctx.session_key,
                "url": ctx.url,
                "idle": idle,
                "timestamp": now_ms(),
            });
            if tx.send(BridgeOutgoing::Json(frame)).is_err() {
                break; // WS gone — nothing to keep alive
            }
        }
    }
}

/// Flip the session to idle after `STREAMING_IDLE_TIMEOUT` of no activity and
/// emit `__session_idle` exactly once. Activity (`touch`) bumps `last_activity_ms`
/// and clears `idle`, so a later burst re-arms this.
pub async fn idle_timeout_loop(ctx: BackgroundCtx) {
    let timeout_ms = constants::STREAMING_IDLE_TIMEOUT.as_millis() as i64;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;

        let elapsed = now_ms() - ctx.last_activity_ms.load(Ordering::Relaxed);
        if elapsed < timeout_ms {
            continue;
        }
        // Only emit on the transition into idle (compare_exchange guards the edge).
        if ctx
            .idle
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
            .is_err()
        {
            continue; // already idle
        }

        tracing::info!(session_key = %ctx.session_key, elapsed_ms = elapsed, "Streaming session idle");
        if let Some(ref tx) = ctx.outgoing {
            let frame = serde_json::json!({
                "type": "streaming_event",
                "session_key": ctx.session_key,
                "event_name": "__session_idle",
                "data": { "idle_ms": elapsed },
            });
            let _ = tx.send(BridgeOutgoing::Json(frame));
        }
    }
}

/// Enforce the absolute session ceiling. A session whose coordinator has died
/// never receives an end command, so without this the browser leaks forever.
/// On expiry we close the context (tears down Chromium) and emit a terminal
/// frame so the coordinator, if still listening, marks the session ended.
pub async fn hard_timeout(ctx: BackgroundCtx, max_seconds: u64) {
    tokio::time::sleep(std::time::Duration::from_secs(max_seconds)).await;

    tracing::warn!(
        session_key = %ctx.session_key,
        max_seconds,
        "Hard timeout reached — ending session and tearing down browser"
    );

    // Close the browser context directly. The manager is Mutex-guarded and owned
    // by the caller, so we cannot call `manager.end()` from here; closing the
    // owned context handle is equivalent for the resource-leak (it closes the
    // page + Chromium). A driving loop that later touches the page observes the
    // closure and cleans up its own bookkeeping.
    if let Some(ctx_handle) = ctx.context {
        if let Err(e) = ctx_handle.close().await {
            tracing::warn!(session_key = %ctx.session_key, error = %e, "Hard-timeout context close failed");
        }
    }

    if let Some(ref tx) = ctx.outgoing {
        let frame = serde_json::json!({
            "type": "streaming_session_ended",
            "session_key": ctx.session_key,
            "reason": "timeout",
            "session_state": serde_json::Value::Null,
        });
        let _ = tx.send(BridgeOutgoing::Json(frame));
    }
}
