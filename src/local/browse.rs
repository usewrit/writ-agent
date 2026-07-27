//! `session_open` / `session_close` / `ai_session_open` / `ai_session_close` / `agent_action` —
//! backend-orchestrated interactive browsing over the warm browser (Workstream A, Stage 2 — REAL).
//!
//! These frames belong to the cloud's *interactive session* protocol: the backend opens a live
//! browsing session on the agent and then drives it step-by-step (`agent_action`) — for human-in-the-
//! loop / AI-agent browsing where the ORCHESTRATION lives server-side and each atomic action round-
//! trips the gateway. (The desktop's own one-shot AI browsing, `execute_ai_task`, instead runs the
//! WHOLE agent loop on-device and returns a single `task_result`.)
//!
//! DESKTOP IMPLEMENTATION: the cloud's own reference (`bridge/saas_bridge`) drives this through the
//! cloud RECORDER's `AgentSessionRelay` + `run_session_loop` + `PlaywrightRecorder` session store —
//! machinery the desktop daemon does not have (it runs on `RealEngine` + a single warm
//! [`BrowserManager`], never `PlaywrightRecorder`). So this module implements the SAME wire protocol
//! natively: a process-global registry of live sessions, each holding a persistent context+page on
//! the SAME warm browser as runs/record/streaming (never a second Chromium). The per-action
//! interpreter is REUSED verbatim from the shared engine — [`crate::automation::run_agent_actions`]
//! is `pub`, page-based (not recorder-bound), and produces the exact `(results, observation)`
//! the backend expects — so the desktop and cloud agents can never diverge on action semantics.
//!
//! Frame contract (mirrors saas_bridge):
//!   * `session_open`/`ai_session_open` → create a context+page (SSRF-vet any auto-navigate url),
//!     store under `session_id`, reply `session_opened`/`ai_session_opened` (`success:true`).
//!   * `agent_action` → run [`run_agent_actions`] on the session page, reply `agent_action_result`
//!     with `{results, observation}`. `ai_session` sessions get READ-ONLY `evaluate_js` (autonomous),
//!     plain `session` sessions get full JS (parity with saas_bridge `read_only = is_ai_session`).
//!   * `session_close`/`ai_session_close` → close the context; `ai_session_close` first harvests the
//!     `auth_session` (cookies/localStorage) via [`extract_session_state`], reply `*_closed`.
//!
//! SECURITY (the never-trust-a-BYO-agent rule): no identity/creds are trusted from these frames; the
//! foreign-tenant supply-pool gate is applied by the router BEFORE this runs. Navigation is SSRF-vetted
//! with the SAME `url_guard` the local engine uses; the warm browser is shared (never a 2nd Chromium);
//! nothing is persisted.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use dashmap::DashMap;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use crate::browser::manager::BrowserManager;

/// One live backend-orchestrated browsing session: a persistent context+page on the warm browser.
/// `read_only` mirrors saas_bridge's `read_only = ai_session_browser_map.is_some()` — an AI (autonomous)
/// session gets read-only `evaluate_js`; a plain interactive session keeps full JS.
struct BrowsingSession {
    context: playwright_rs::BrowserContext,
    page: playwright_rs::Page,
    read_only: bool,
    /// Monotonic ms of the last `open`/`agent_action` touch. Read by the idle reaper
    /// (see [`start_reaper`]) — an orphaned session is otherwise invisible.
    last_used_ms: Arc<AtomicI64>,
}

impl BrowsingSession {
    fn touch(&self) {
        self.last_used_ms.store(now_ms(), Ordering::Relaxed);
    }
}

/// Process-global registry of live browsing sessions, keyed by the cloud `session_id`. Mirrors the
/// other agent process-globals (`runs`, `streaming_map`). Entries are created on open and removed on
/// close.
///
/// LIFETIME: each entry pins a live `BrowserContext` + `Page`, i.e. real Chromium memory. A
/// coordinator that drops the WS without sending `*_close` (crash, network partition, or simply a
/// self-host coordinator that does not implement the close leg) used to leave the session here until
/// process exit — an unbounded leak driven entirely by the peer. [`start_reaper`] now closes sessions
/// idle past [`SESSION_IDLE_TIMEOUT_SECS`], and [`close_all`] clears the registry when the owning
/// listen loop exits. Same shape as `streaming_session`'s idle + hard-timeout teardown.
static SESSIONS: OnceLock<DashMap<String, BrowsingSession>> = OnceLock::new();

fn sessions() -> &'static DashMap<String, BrowsingSession> {
    SESSIONS.get_or_init(DashMap::new)
}

/// Idle window before the reaper closes a browsing session. Generous: a
/// human-in-the-loop session can legitimately sit untouched between actions, but an
/// hour of total silence means the peer is gone.
const SESSION_IDLE_TIMEOUT_SECS: i64 = 3600;

/// How often the reaper sweeps.
const REAPER_INTERVAL_SECS: u64 = 60;

/// Hard ceiling on concurrent browsing sessions. Each is a Chromium context, so an
/// unbounded peer must not be able to open them without limit.
const MAX_LIVE_SESSIONS: usize = 32;

/// Longest `session_id` we accept from the wire. Ids are gateway-minted uuids; a
/// multi-megabyte id would otherwise be copied into the registry key, every log
/// line, and every reply frame.
const MAX_SESSION_ID_CHARS: usize = 128;

// Compile-time invariants on the bounds above.
const _: () = assert!(MAX_LIVE_SESSIONS > 0 && MAX_LIVE_SESSIONS <= 256);
const _: () = assert!(MAX_SESSION_ID_CHARS > 0);
// The reaper must sweep several times inside the idle window, or a stale session
// outlives its timeout by up to a whole interval.
const _: () = assert!((REAPER_INTERVAL_SECS as i64) * 4 <= SESSION_IDLE_TIMEOUT_SECS);

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Whether a session last touched at `last_used` is stale as of `now`.
///
/// `saturating_sub` matters: `now_ms` is wall-clock, so an NTP step backwards (or a
/// `now_ms()` that fell back to 0) can make `last_used` be in the future. Saturating
/// yields 0 there, i.e. "not stale" — a clock adjustment must never reap live
/// sessions out from under the coordinator.
fn is_idle_past(last_used_ms: i64, now_ms: i64, idle_ms: i64) -> bool {
    now_ms.saturating_sub(last_used_ms) > idle_ms
}

/// Start the idle-session reaper (idempotent — only the first call spawns it).
///
/// Closes any session untouched for [`SESSION_IDLE_TIMEOUT_SECS`], releasing its
/// Chromium context. Without this an orphaned session (WS dropped before
/// `*_close`) lived until process exit.
pub fn start_reaper() {
    static STARTED: OnceLock<()> = OnceLock::new();
    if STARTED.set(()).is_err() {
        return; // already running
    }
    tokio::spawn(async move {
        let idle_ms = SESSION_IDLE_TIMEOUT_SECS.saturating_mul(1000);
        loop {
            tokio::time::sleep(Duration::from_secs(REAPER_INTERVAL_SECS)).await;
            let now = now_ms();
            // Collect first, then close: never hold a DashMap guard across `.await`.
            let stale: Vec<String> = sessions()
                .iter()
                .filter(|e| is_idle_past(e.last_used_ms.load(Ordering::Relaxed), now, idle_ms))
                .map(|e| e.key().clone())
                .collect();
            for sid in stale {
                stop_spectate(&sid);
                if let Some((_, session)) = sessions().remove(&sid) {
                    tracing::warn!(session_id = %truncate_id(&sid), "Reaping idle browsing session");
                    let _ = session.context.close().await;
                }
            }
        }
    });
}

/// Close and forget EVERY live browsing session. Called when the owning listen loop
/// exits: the peer that could have closed them is gone, so nothing will ever
/// reference these contexts again.
pub async fn close_all() {
    let ids: Vec<String> = sessions().iter().map(|e| e.key().clone()).collect();
    for sid in ids {
        stop_spectate(&sid);
        if let Some((_, session)) = sessions().remove(&sid) {
            let _ = session.context.close().await;
        }
    }
}

/// Char-safe truncation for wire-derived ids before they reach a log line.
fn truncate_id(s: &str) -> String {
    s.chars().take(16).collect()
}

/// Active spectate screencasts, keyed by `session_id` → a cancel flag. A backend spectator hitting
/// `/ws/ai-spectate/ai-<id>` makes the coordinator send us `spectate_start`; we screencast the
/// session's page back as `spectate_frame`s until `spectate_stop` (last watcher left) or the session
/// closes. One task per session regardless of watcher count (the coordinator fans out).
static SPECTATE: OnceLock<DashMap<String, Arc<AtomicBool>>> = OnceLock::new();
fn spectate_tasks() -> &'static DashMap<String, Arc<AtomicBool>> {
    SPECTATE.get_or_init(DashMap::new)
}

/// Screencast cadence (~2.5 fps) + JPEG quality — parity with the local `live_preview` screencast.
const SPECTATE_INTERVAL_MS: u64 = 400;
const SPECTATE_QUALITY: u8 = 55;

/// Start screencasting `session_id`'s page to the coordinator over `outgoing_tx` (idempotent — a
/// second `spectate_start` for a live session is a no-op). Frames are deduped (identical JPEG bytes
/// dropped) so a static page costs nothing on the wire. Stops when the cancel flag flips
/// (`stop_spectate` / session close) or the page/send fails.
pub fn start_spectate(session_id: &str, outgoing_tx: mpsc::UnboundedSender<Message>) {
    let sid = session_id.to_string();
    if spectate_tasks().contains_key(&sid) {
        return; // already streaming this session
    }
    let page = match sessions().get(&sid) {
        Some(s) => s.page.clone(),
        None => return, // no such live session
    };
    let cancel = Arc::new(AtomicBool::new(false));
    spectate_tasks().insert(sid.clone(), cancel.clone());
    tokio::spawn(async move {
        let mut last_hash: u64 = 0;
        let mut misses = 0u32;
        while !cancel.load(Ordering::Relaxed) {
            match crate::local::ai::observation::capture_screenshot_jpeg(&page, SPECTATE_QUALITY).await {
                Some(bytes) => {
                    misses = 0;
                    let h = crate::browser::screenshot::ScreencastStream::frame_hash(&bytes);
                    if h != last_hash {
                        last_hash = h;
                        let b64 = base64::Engine::encode(
                            &base64::engine::general_purpose::STANDARD,
                            &bytes,
                        );
                        let frame = json!({
                            "type": "spectate_frame",
                            "session_id": sid,
                            "data": b64,
                            "url": page.url(),
                        });
                        if outgoing_tx.send(Message::Text(frame.to_string())).is_err() {
                            break; // coordinator link gone
                        }
                    }
                }
                None => {
                    misses += 1;
                    if misses > 20 {
                        break; // page/context went away
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(SPECTATE_INTERVAL_MS)).await;
        }
        spectate_tasks().remove(&sid);
    });
}

/// Stop screencasting `session_id` (last spectator left, or the session is closing).
pub fn stop_spectate(session_id: &str) {
    if let Some((_, cancel)) = spectate_tasks().remove(session_id) {
        cancel.store(true, Ordering::Relaxed);
    }
}

/// Number of live browsing sessions (diagnostics / status).
pub fn live_count() -> usize {
    SESSIONS.get().map(|m| m.len()).unwrap_or(0)
}

/// The `session_id` / `session_key` a session/action frame addresses (checked in that order, then
/// nested under `config`). Empty when the frame carries none.
///
/// BOUNDED at ingest: the id is entirely peer-controlled and becomes a registry key, a log field,
/// and part of every reply frame, so it is truncated (char-safe, never mid-UTF-8) rather than
/// carried at whatever length the wire chose. Truncation is applied on EVERY read of the id so
/// lookup and insertion always agree on the same key.
fn session_id_of(msg: &Value) -> String {
    let raw = msg["session_id"]
        .as_str()
        .or(msg["session_key"].as_str())
        .or(msg["config"]["session_id"].as_str())
        .unwrap_or("");
    raw.chars().take(MAX_SESSION_ID_CHARS).collect()
}

/// The reply frame type the backend awaits for a given inbound frame type.
fn reply_type_for(inbound: &str) -> &'static str {
    match inbound {
        "session_open" => "session_opened",
        "session_close" => "session_closed",
        "ai_session_open" => "ai_session_opened",
        "ai_session_close" => "ai_session_closed",
        "agent_action" => "agent_action_result",
        _ => "agent_action_result",
    }
}

/// Build a refusal/error ack of the correct reply type for an inbound interactive-browsing frame. Used
/// by the router's foreign-tenant supply-pool gate (the capability IS supported here — the work is just
/// refused), so the backend correlates by `session_id`/`request_id` and degrades cleanly. Never panics,
/// carries no secret.
pub fn refusal_ack(msg: &Value, error: &str) -> Value {
    let msg_type = msg["type"].as_str().unwrap_or("");
    ack(
        reply_type_for(msg_type),
        &session_id_of(msg),
        &msg.get("request_id").cloned().unwrap_or(Value::Null),
        false,
        Some(error.to_string()),
    )
}

/// A minimal lifecycle ack (`*_opened` / `*_closed`) — success flag + optional error. `agent_action`
/// builds its own richer frame (results + observation) directly.
fn ack(reply_type: &str, session_id: &str, request_id: &Value, success: bool, error: Option<String>) -> Value {
    json!({
        "type": reply_type,
        "session_id": session_id,
        "request_id": request_id,
        "success": success,
        "error": error,
    })
}

/// Handle a backend-orchestrated interactive-browsing frame. `msg_type` is the inbound frame's `type`;
/// returns `Some(reply_frame)` for the frames this handler owns, `None` for anything else (so the router
/// can fall through). `browser` is the daemon's single warm [`BrowserManager`] (`None` on a
/// browserless StubEngine — an `*_open` then fails closed with a matching ack; action/close operate on
/// the registry). Never panics.
pub async fn handle(msg: &Value, browser: Option<&Arc<BrowserManager>>) -> Option<Value> {
    let msg_type = msg["type"].as_str().unwrap_or("");
    let frame = match msg_type {
        "session_open" => open(msg, browser, false).await,
        "ai_session_open" => open(msg, browser, true).await,
        "agent_action" => action(msg).await,
        "session_close" => close(msg, false).await,
        "ai_session_close" => close(msg, true).await,
        _ => return None,
    };
    tracing::info!(msg_type, session_id = %session_id_of(msg), live = live_count(),
        "LinkedAgentBridge handled interactive-browsing frame");
    Some(frame)
}

/// `session_open` / `ai_session_open`: create a persistent context+page on the warm browser (SSRF-vet
/// any auto-navigate url first), store under the session id, reply `*_opened`.
async fn open(msg: &Value, browser: Option<&Arc<BrowserManager>>, ai: bool) -> Value {
    let session_id = {
        let s = session_id_of(msg);
        if s.is_empty() { uuid::Uuid::new_v4().to_string() } else { s }
    };
    let request_id = msg.get("request_id").cloned().unwrap_or(Value::Null);
    let reply_type = reply_type_for(if ai { "ai_session_open" } else { "session_open" });

    let browser = match browser {
        Some(b) => b,
        // Browserless (StubEngine): fail closed with the matching ack so the backend degrades.
        None => return ack(reply_type, &session_id, &request_id, false, Some("no browser available on this agent".into())),
    };

    // Make sure the idle reaper is running before the first session can be stranded.
    start_reaper();

    // Refuse rather than open an unbounded number of Chromium contexts. The reaper
    // drains genuinely dead sessions, so a peer that keeps its sessions alive and
    // in use is the only way to sit at the ceiling.
    if !sessions().contains_key(&session_id) && sessions().len() >= MAX_LIVE_SESSIONS {
        return ack(
            reply_type,
            &session_id,
            &request_id,
            false,
            Some(format!("too many live browsing sessions on this agent (max {MAX_LIVE_SESSIONS})")),
        );
    }

    // SSRF-vet the auto-navigate url (if any) BEFORE opening anything — same guard the local engine
    // applies. A blocked url refuses the open rather than opening an un-navigated blank session.
    let url = msg["url"].as_str().or(msg["config"]["url"].as_str()).unwrap_or("").to_string();
    if !url.is_empty() && !crate::security::url_guard::is_navigation_url_safe_async(&url).await {
        return ack(reply_type, &session_id, &request_id, false, Some("blocked: unsafe/internal navigation URL".into()));
    }

    if let Err(e) = browser.ensure_warm_browser().await {
        return ack(reply_type, &session_id, &request_id, false, Some(format!("warm browser unavailable: {e}")));
    }
    let (context, page) = match browser.create_stealth_context().await {
        Ok(cp) => cp,
        Err(e) => return ack(reply_type, &session_id, &request_id, false, Some(format!("could not open session context: {e}"))),
    };

    // Optional auto-navigate (already SSRF-vetted). A navigation failure is non-fatal — the session is
    // open and the backend can drive it (or navigate explicitly) via agent_action.
    if !url.is_empty() {
        let _ = crate::browser::navigation::goto(
            &page, &url, "domcontentloaded", std::time::Duration::from_secs(30),
        )
        .await;
    }

    sessions().insert(
        session_id.clone(),
        BrowsingSession {
            context,
            page,
            read_only: ai,
            last_used_ms: Arc::new(AtomicI64::new(now_ms())),
        },
    );
    ack(reply_type, &session_id, &request_id, true, None)
}

/// `agent_action`: run the SHARED action interpreter on the session's live page and reply
/// `agent_action_result` with `{results, observation}` (the exact frame saas_bridge emits). An unknown
/// session id yields a well-formed result with `error:"Session not found"` (never a hang/panic).
async fn action(msg: &Value) -> Value {
    let session_id = session_id_of(msg);
    let request_id = msg.get("request_id").cloned().unwrap_or(Value::Null);

    // Clone the page out under a BRIEF lock, then DROP the DashMap ref before any async page I/O
    // (holding a `get()` guard across `.await` starves tokio workers — mirrors saas_bridge).
    // Stamp `last_used` while we hold the ref so the idle reaper never closes a session the
    // coordinator is actively driving.
    let looked = sessions().get(&session_id).map(|s| {
        s.touch();
        (s.page.clone(), s.read_only)
    });

    match looked {
        Some((page, read_only)) => {
            let (results, observation) =
                crate::automation::run_agent_actions(&page, msg, read_only).await;
            json!({
                "type": "agent_action_result",
                "session_id": session_id,
                "request_id": request_id,
                "results": results,
                "observation": observation,
            })
        }
        None => json!({
            "type": "agent_action_result",
            "session_id": session_id,
            "request_id": request_id,
            "results": [],
            "observation": Value::Null,
            "error": "Session not found",
        }),
    }
}

/// `session_close` / `ai_session_close`: remove the session and close its context. An `ai_session_close`
/// first harvests the `auth_session` (cookies + localStorage) so the backend can persist the warm
/// login, exactly like saas_bridge. Idempotent: closing an unknown/already-closed session still replies
/// a clean `*_closed`.
async fn close(msg: &Value, ai: bool) -> Value {
    let session_id = session_id_of(msg);
    let request_id = msg.get("request_id").cloned().unwrap_or(Value::Null);
    let reply_type = reply_type_for(if ai { "ai_session_close" } else { "session_close" });

    // Stop any live spectate screencast for this session before the page is torn down.
    stop_spectate(&session_id);

    let mut auth_session = Value::Null;
    if let Some((_, session)) = sessions().remove(&session_id) {
        // Harvest auth state BEFORE teardown (ai sessions only — the interactive session's auth is
        // captured by the run/record paths, not here). Never hold a lock across this await: `session`
        // is already owned (removed from the map).
        if ai {
            let headers: HashMap<String, String> = HashMap::new();
            let state = crate::automation::session_state::extract_session_state(
                &session.page, &session.context, &headers,
            )
            .await;
            auth_session = serde_json::to_value(&state).unwrap_or(Value::Null);
        }
        let _ = session.context.close().await;
    }

    let mut frame = ack(reply_type, &session_id, &request_id, true, None);
    // ai_session_closed carries the harvested auth_session (null for a plain session_close).
    frame["auth_session"] = auth_session;
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_precedence() {
        assert_eq!(session_id_of(&json!({"session_id": "a"})), "a");
        assert_eq!(session_id_of(&json!({"session_key": "b"})), "b");
        assert_eq!(session_id_of(&json!({"config": {"session_id": "c"}})), "c");
        assert_eq!(session_id_of(&json!({})), "");
    }

    #[test]
    fn reply_type_mapping_matches_contract() {
        assert_eq!(reply_type_for("session_open"), "session_opened");
        assert_eq!(reply_type_for("session_close"), "session_closed");
        assert_eq!(reply_type_for("ai_session_open"), "ai_session_opened");
        assert_eq!(reply_type_for("ai_session_close"), "ai_session_closed");
        assert_eq!(reply_type_for("agent_action"), "agent_action_result");
    }

    #[test]
    fn refusal_ack_uses_matching_reply_type_and_carries_no_secret() {
        for (inbound, reply) in [
            ("session_open", "session_opened"),
            ("ai_session_open", "ai_session_opened"),
            ("agent_action", "agent_action_result"),
        ] {
            let ack = refusal_ack(
                &json!({"type": inbound, "session_id": "s1", "request_id": "r1"}),
                "agent not opted into the shared supply pool",
            );
            assert_eq!(ack["type"], reply, "{inbound} → {reply}");
            assert_eq!(ack["success"], false);
            assert_eq!(ack["session_id"], "s1");
            assert_eq!(ack["request_id"], "r1");
            assert!(ack["error"].as_str().unwrap().contains("supply pool"));
        }
    }

    #[test]
    fn unrelated_frame_type_is_not_owned() {
        // A synchronous check of the dispatch guard: a type this module doesn't own must fall through.
        // (Exercised via the async `handle` in the integration test below; here we assert the mapper's
        // default is the action-result type so a stray call still produces a well-formed frame.)
        assert_eq!(reply_type_for("ping"), "agent_action_result");
    }

    #[tokio::test]
    async fn handle_returns_none_for_unowned_type() {
        assert!(handle(&json!({"type": "ping"}), None).await.is_none());
        assert!(handle(&json!({"type": "run_local_workflow"}), None).await.is_none());
        assert!(handle(&json!({}), None).await.is_none());
    }

    #[tokio::test]
    async fn open_without_browser_fails_closed_with_matching_ack() {
        let frame = handle(&json!({"type": "ai_session_open", "session_id": "s9", "request_id": "r9"}), None)
            .await
            .expect("owned");
        assert_eq!(frame["type"], "ai_session_opened");
        assert_eq!(frame["success"], false);
        assert_eq!(frame["session_id"], "s9");
        assert!(frame["error"].as_str().unwrap().contains("no browser"));
    }

    #[tokio::test]
    async fn agent_action_on_unknown_session_reports_not_found_without_panic() {
        // No browser needed: the registry has no such session, so the interpreter is never reached.
        let frame = handle(
            &json!({"type": "agent_action", "session_id": "nope", "request_id": "r0", "action": "get_screenshot"}),
            None,
        )
        .await
        .expect("owned");
        assert_eq!(frame["type"], "agent_action_result");
        assert_eq!(frame["results"], json!([]));
        assert!(frame["observation"].is_null());
        assert_eq!(frame["error"], "Session not found");
    }

    // ── Item 3: unbounded registry, no reaper ────────────────────────────────

    #[test]
    fn idle_predicate_reaps_only_genuinely_silent_sessions() {
        let idle = 3_600_000; // 1 h
        let now = 10_000_000;
        assert!(!is_idle_past(now, now, idle), "just touched");
        assert!(!is_idle_past(now - idle, now, idle), "exactly at the boundary is still live");
        assert!(is_idle_past(now - idle - 1, now, idle), "one ms past → reap");
        // Clock stepped backwards / last_used in the future: never reap.
        assert!(!is_idle_past(now + 60_000, now, idle));
        // now_ms() fell back to 0 (SystemTime before UNIX_EPOCH): never reap.
        assert!(!is_idle_past(now, 0, idle));
    }

    #[test]
    fn session_id_is_bounded_and_char_safe_at_ingest() {
        // The id is wholly peer-controlled and becomes a registry key + log field.
        let long = "x".repeat(MAX_SESSION_ID_CHARS * 5);
        assert_eq!(session_id_of(&json!({"session_id": long})).chars().count(), MAX_SESSION_ID_CHARS);
        // Multibyte must not be split mid-codepoint (a byte slice would panic).
        let multi = "🙂".repeat(MAX_SESSION_ID_CHARS * 2);
        let got = session_id_of(&json!({"session_key": multi}));
        assert_eq!(got.chars().count(), MAX_SESSION_ID_CHARS);
        assert!(got.chars().all(|c| c == '🙂'));
        // Truncation is stable, so a lookup key always equals the insertion key.
        assert_eq!(session_id_of(&json!({"session_id": got.clone()})), got);
        // Short ids are untouched (precedence tests above still hold).
        assert_eq!(session_id_of(&json!({"session_id": "s1"})), "s1");
    }

    #[tokio::test]
    async fn close_all_is_safe_on_an_empty_registry() {
        close_all().await;
        assert_eq!(live_count(), 0);
        close_all().await; // idempotent
    }

    #[tokio::test]
    async fn start_reaper_is_idempotent() {
        // Called on every `open`; must never spawn a second sweeper.
        start_reaper();
        start_reaper();
        start_reaper();
    }

    #[test]
    fn truncate_id_is_char_safe() {
        assert_eq!(truncate_id("ééééééééééééééééééé").chars().count(), 16);
        assert_eq!(truncate_id("short"), "short");
    }

    #[tokio::test]
    async fn close_unknown_session_is_idempotent() {
        let frame = handle(&json!({"type": "ai_session_close", "session_id": "gone", "request_id": "r"}), None)
            .await
            .expect("owned");
        assert_eq!(frame["type"], "ai_session_closed");
        assert_eq!(frame["success"], true);
        assert!(frame["auth_session"].is_null(), "no session → null auth_session");
    }
}
