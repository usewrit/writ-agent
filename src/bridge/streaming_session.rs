//! Shared streaming-session orchestration (extracted from `saas_bridge`) so BOTH the cloud
//! `saas_bridge` and the OSS `fleet_bridge` reuse the SAME tested handler. Each caller resolves
//! credentials + the BYO proxy its own way (cloud vs channel-key decrypt) and passes them in; the
//! body is otherwise the verbatim handler. Every helper it drives lives in feature-ungated modules.
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::browser::manager::BrowserManager;
use crate::models::workflow::WorkflowStepConfig;
use super::session_relay::{AgentSessionRelay, BridgeOutgoing};

fn truncate_str(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

/// Hard ceiling on turns awaiting a page `ps.respond` at once.
///
/// Each in-flight turn owns a spawned watchdog task and a map entry. A coordinator
/// dispatching unique `request_id`s at loop rate would otherwise accumulate
/// hundreds of thousands of live tasks over the 3 h idle window. Well above any
/// legitimate concurrency for one browser tab, so hitting it means something is
/// wrong upstream and the turn is failed fast instead of queued forever.
const MAX_INFLIGHT_TURNS: usize = 256;

/// Cap on remembered timed-out request ids (see [`RecentIds`]).
const MAX_TIMED_OUT_IDS: usize = 1024;

// Compile-time invariants on the two bounds above. Each in-flight turn owns a spawned
// watchdog task, so the in-flight cap is what stops a peer dispatching unique
// `request_id`s from spawning tasks without limit; and since every in-flight turn may
// time out at once, the recent-id set must be able to absorb a whole wave without
// evicting entries that are still needed to suppress late responses.
const _: () = assert!(MAX_INFLIGHT_TURNS > 0);
const _: () = assert!(MAX_INFLIGHT_TURNS <= 1024);
const _: () = assert!(MAX_TIMED_OUT_IDS >= MAX_INFLIGHT_TURNS);

/// A bounded, TTL'd set of request ids — "turns we already answered with a
/// timeout, so drop a late `ps.respond` for them".
///
/// This replaces an unbounded `DashSet`. An entry there was removed ONLY by a
/// matching late `ps.respond`, which for the common failure (a handler that hangs,
/// throws, or filters the action and never responds at all) never arrives — so the
/// set grew without limit for the lifetime of the session. Both bounds here are
/// memory hygiene rather than correctness: forgetting an entry early just means a
/// very late response is forwarded instead of suppressed, and the coordinator
/// already ignores a second response for a resolved turn.
struct RecentIds {
    ttl: std::time::Duration,
    cap: usize,
    inner: std::sync::Mutex<RecentIdsInner>,
}

#[derive(Default)]
struct RecentIdsInner {
    /// id → insertion instant (membership + expiry check).
    seen: HashMap<String, std::time::Instant>,
    /// Insertion order, so the oldest entry is evicted when `cap` is reached.
    order: std::collections::VecDeque<String>,
}

impl RecentIds {
    fn new(ttl: std::time::Duration, cap: usize) -> Self {
        Self {
            ttl,
            cap,
            inner: std::sync::Mutex::new(RecentIdsInner::default()),
        }
    }

    /// Remember `id`, pruning expired entries and evicting the oldest if full.
    fn insert(&self, id: String) {
        let now = std::time::Instant::now();
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            // A poisoned mutex must not take the session down: the worst case is a
            // late response getting forwarded instead of dropped.
            Err(e) => e.into_inner(),
        };
        // Amortised TTL sweep from the front (order is insertion order, so the
        // front is always the oldest).
        while let Some(front) = g.order.front() {
            let expired = g
                .seen
                .get(front)
                .map(|t| now.duration_since(*t) >= self.ttl)
                .unwrap_or(true);
            if !expired {
                break;
            }
            let front = g.order.pop_front().expect("front checked above");
            g.seen.remove(&front);
        }
        while g.order.len() >= self.cap {
            let Some(front) = g.order.pop_front() else { break };
            g.seen.remove(&front);
        }
        if g.seen.insert(id.clone(), now).is_none() {
            g.order.push_back(id);
        }
    }

    /// Remove `id` and report whether it was present AND still within the TTL.
    fn take(&self, id: &str) -> bool {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        match g.seen.remove(id) {
            Some(at) => {
                g.order.retain(|x| x != id);
                at.elapsed() < self.ttl
            }
            None => false,
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        match self.inner.lock() {
            Ok(g) => g.seen.len(),
            Err(e) => e.into_inner().seen.len(),
        }
    }
}

pub(crate) async fn handle_start_streaming_session(
    task_id: &str,
    session_key: &str,
    msg: &serde_json::Value,
    browser_manager: &Arc<BrowserManager>,
    outgoing: &mpsc::UnboundedSender<BridgeOutgoing>,
    relays: &Arc<dashmap::DashMap<String, Arc<AgentSessionRelay>>>,
    credentials: HashMap<String, String>,
    proxy_override: Option<playwright_rs::protocol::ProxySettings>,
) {
    tracing::info!(task_id, session_key, "Starting streaming session");

    let config = &msg["config"];
    let target_url = config["target_url"].as_str()
        .or(msg["target_url"].as_str())
        .unwrap_or("about:blank");

    // SECURITY (SSRF): vet the tenant-supplied target URL BEFORE we register the relay / ack success /
    // open a browser. inject_session_state and goto below navigate the top frame to target_url with no
    // route-blocker on that first navigation, so an internal/metadata target must be refused up front
    // (fail-closed), mirroring the workflow and AI-task lanes.
    if !crate::security::url_guard::is_navigation_url_safe_async(target_url).await {
        let _ = outgoing.send(BridgeOutgoing::Json(serde_json::json!({
            "type": "task_result",
            "task_id": task_id,
            "success": false,
            "error": format!("Refused unsafe URL: {}", target_url),
        })));
        println!("  ✗ Streaming session refused unsafe URL: {}", target_url);
        return;
    }

    // Decrypt credentials if present and merge into form_data
    let mut form_data: HashMap<String, String> = config.get("form_data")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    for (k, v) in &credentials {
        form_data.entry(k.clone()).or_insert_with(|| v.clone());
    }

    // Create a relay for this streaming session, registering it ATOMICALLY so a
    // duplicate dispatch can't open a second browser. The streaming service
    // re-queues a session whose start wasn't acked in time, and start_session
    // still re-dispatches a session in "starting" (service.py guards only
    // "running"). So the same session_key can arrive twice — before the first
    // start flipped it to "running" — which without this guard spawns duplicate
    // parallel sessions (each its own browser context) for one logical session.
    // If one is already registered, re-ack so the (re-)dispatcher unblocks and
    // return without opening another. The DashMap entry lock makes the
    // check-and-insert atomic against two concurrently-spawned handlers.
    let relay = Arc::new(AgentSessionRelay::new(
        session_key.to_string(),
        outgoing.clone(),
    ));
    match relays.entry(session_key.to_string()) {
        dashmap::mapref::entry::Entry::Occupied(_) => {
            tracing::warn!(
                task_id, session_key,
                "Duplicate start_streaming_session — session already active; re-acking, NOT opening a new browser"
            );
            let _ = outgoing.send(BridgeOutgoing::Json(serde_json::json!({
                "type": "task_result",
                "task_id": task_id,
                "success": true,
                "result_data": { "session_key": session_key, "status": "running" },
            })));
            return;
        }
        dashmap::mapref::entry::Entry::Vacant(e) => {
            e.insert(relay.clone());
        }
    }

    // Parse saved session state up-front (warm session) to reuse the captured
    // fingerprint. Fresh session (session_persistence off) → no saved_state → random.
    let saved_state: Option<crate::models::session::SessionState> = config
        .get("session_state")
        .filter(|v| !v.is_null())
        .and_then(|v| serde_json::from_value(v.clone()).ok());
    let restored_fp: Option<crate::browser::context::Fingerprint> = saved_state
        .as_ref()
        .and_then(|s| s.fingerprint.clone())
        .and_then(|v| serde_json::from_value(v).ok());

    // Per-run BYO persona proxy: read the reserved `__proxy__` object from the run
    // credentials (backend-gated). When present this context egresses through the
    // consumer's residential proxy; None → env proxy / direct. Parity with Python.

    // Create stealth browser context, reusing the captured fingerprint on a warm session.
    match browser_manager.create_stealth_context_with_fingerprint_proxy(restored_fp, proxy_override).await {
        Ok((context, page, fp_used)) => {
            // Ack the dispatch IMMEDIATELY — BEFORE navigation/setup/runtime injection.
            // The streaming service only waits ~30s for this task_result before it
            // re-queues the session (so it would otherwise NEVER flip to "running"
            // while we load a heavy site like chatgpt.com). This matches the Python
            // agent ordering (saas_bridge.py: "Send success result IMMEDIATELY so
            // streaming service unblocks"). Incoming session commands buffer in this
            // session's relay (registered above) until the command loop drains them,
            // so acking before setup completes is safe. A setup failure below ends
            // the session (cleanup + return) rather than re-sending a task_result —
            // the ack is already out, so the service relies on its start/activity
            // timeout, same as Python.
            let _ = outgoing.send(BridgeOutgoing::Json(serde_json::json!({
                "type": "task_result",
                "task_id": task_id,
                "success": true,
                "result_data": {
                    "session_key": session_key,
                    "status": "running",
                },
            })));

            // Wire the runtime bridge BEFORE the first navigation.
            // SECURITY: `setup_runtime_bridge` installs the trusted runtime with
            // `page.add_init_script`, which only governs documents created AFTER it is
            // registered. Registering it here (rather than after navigation + setup
            // steps, as this used to) is what guarantees the runtime runs before ANY
            // script of the target page: it captures the genuine binding functions
            // into its closure, so page script cannot wrap one and steal the
            // capability token from a legitimate call, and its main-frame gate reads
            // an unshadowed `window.top`. The bindings themselves survive navigation.
            let (bridge_event_tx, mut bridge_event_rx) = tokio::sync::mpsc::unbounded_channel();
            // Keep a clone so the session manager can wire bridges onto new
            // per-conversation thread tabs (multi-conversation mode).
            let bridge_event_tx_for_mgr = bridge_event_tx.clone();
            // Capture the per-session capability secret so the session manager can
            // reuse it when re-injecting the runtime across navigations.
            let mut streaming_bridge_token = String::new();
            match crate::streaming::runtime_bridge::setup_runtime_bridge(&page, bridge_event_tx).await {
                Ok(tok) => {
                    streaming_bridge_token = tok;
                    tracing::info!(session_key, "Runtime bridge injected (pre-navigation)");
                }
                Err(e) => tracing::warn!(error = %e, "Runtime bridge setup failed (non-fatal)"),
            }

            // Restore saved session state (cookies + localStorage) if provided, then navigate.
            // 1:1 port of Python StreamingSessionManager.start() session_state restore.
            // inject_session_state adds cookies BEFORE navigation, navigates to target_url,
            // then injects localStorage/sessionStorage and reloads — matching Python ordering.
            let nav_result = if let Some(ref state) = saved_state {
                tracing::info!(
                    session_key,
                    cookies = state.cookies.len(),
                    local_storage = state.local_storage.len(),
                    "Restoring saved streaming session state"
                );
                crate::automation::session_state::inject_session_state(
                    &page, &context, state, Some(target_url), 30_000,
                ).await
            } else {
                crate::browser::navigation::goto(
                    &page, target_url, "domcontentloaded",
                    std::time::Duration::from_secs(30),
                ).await
            };

            if let Err(e) = nav_result {
                // Dispatch was already acked above — end the session instead of
                // re-sending a task_result (the service ignores a second result for
                // an already-resolved task_id; it ends the session on its own timeout).
                tracing::error!(error = %e, "Streaming session navigation/restore failed — ending session");
                let _ = context.close().await;
                relays.remove(session_key);
                return;
            }

            // Execute setup steps (login forms, initial navigation)
            let setup_steps = config.get("setup_steps")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let timeout_ms = config.get("timeout_ms").and_then(|v| v.as_u64()).unwrap_or(60000);
            let _empty_creds: HashMap<String, String> = HashMap::new();
            // Streaming setup steps carry no run-level files map (streaming file
            // attachments are handled separately, §9.2); an inert RunFiles makes any
            // upload/wait_for_download setup step fail closed (File assets §6.3).
            let run_files = crate::automation::files::RunFiles::from_config(&serde_json::Value::Null, None);

            // Tracks whether an explicit `twofa` setup step already served the
            // challenge, so the detect-during-login fallback below runs at most once.
            let mut twofa_served = false;

            for (i, raw_step) in setup_steps.iter().enumerate() {
                let step_type = raw_step["type"].as_str().unwrap_or("");
                if step_type.is_empty() {
                    continue;
                }

                // Cloud-only 2FA setup step: mint the live code/magic-link SERVER-SIDE
                // (via config["persona"].otp_token) and enter it — the SAME shared
                // machinery the run path uses (handle_twofa_step + shared otp_*.js).
                // The agent never holds the TOTP seed / mailbox creds.
                if step_type == "twofa" {
                    match crate::bridge::wire_exec::handle_twofa_step(&page, raw_step, config, timeout_ms).await {
                        Ok(()) => { twofa_served = true; }
                        Err(e) => {
                            // Fail CLOSED: a streaming login that needs 2FA must not
                            // continue unauthenticated. Dispatch was already acked above,
                            // so end the session (cleanup + return) rather than re-send
                            // a task_result.
                            tracing::error!(step = i, error = %e, "twofa setup step failed — ending session");
                            let _ = context.close().await;
                            relays.remove(session_key);
                            return;
                        }
                    }
                    continue;
                }

                let step_config: WorkflowStepConfig = match serde_json::from_value(
                    raw_step.get("config").cloned().unwrap_or(raw_step.clone())
                ) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(step = i, error = %e, "Failed to parse setup step, skipping");
                        continue;
                    }
                };

                if let Err(e) = crate::automation::step_executor::execute_step(
                    &page, step_type, &step_config, &credentials, &form_data,
                    &run_files, timeout_ms, true,
                ).await {
                    tracing::warn!(step = i, error = %e, "Setup step failed, continuing");
                }
            }

            // Detect-during-login FALLBACK: a 2FA/code challenge can appear WITHOUT a
            // recorded `twofa` step (inline step-2, modal, or post-password redirect).
            // If one is showing and no explicit step handled it, serve it once via the
            // SAME shared machinery (otp_detect.js → SERVER-SIDE mint → otp_entry.js,
            // all inside handle_twofa_step). Fail CLOSED on a real failure.
            if !twofa_served && config.get("persona").map(|p| !p.is_null()).unwrap_or(false) {
                if let Ok(det) = crate::browser::page_query::evaluate::<serde_json::Value>(
                    &page, &crate::bridge::otp_entry::detect_invocation(),
                ).await {
                    if det.get("is_twofa").and_then(|v| v.as_bool()).unwrap_or(false) {
                        tracing::info!(session_key, "2FA challenge detected during login — serving via persona OTP");
                        // Synthesize a bare twofa step; handle_twofa_step re-detects the
                        // field/submit selectors itself when the step carries none.
                        let synth = serde_json::json!({ "type": "twofa" });
                        if let Err(e) = crate::bridge::wire_exec::handle_twofa_step(&page, &synth, config, timeout_ms).await {
                            // Already acked above — end the session rather than re-send.
                            tracing::error!(error = %e, "2FA during login failed — ending session");
                            let _ = context.close().await;
                            relays.remove(session_key);
                            return;
                        }
                    }
                }
            }

            let has_advanced_script = config
                .get("advanced_script")
                .and_then(|v| v.get("enabled"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            // Per-turn watchdog state (parity with Python _dispatch_to_page). A page
            // dispatch relies on the advanced script calling ps.respond; if the handler
            // errors, filters the action, or hangs, NO command_response is ever sent and
            // the caller hangs forever. `pending_turns` tracks each in-flight turn's
            // deadline so a watchdog returns an error when a turn goes silent;
            // `timed_out` drops a late ps.respond for a turn we already errored.
            let turn_timeout = std::time::Duration::from_secs(
                std::env::var("WRIT_STREAMING_TURN_TIMEOUT_SECS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(120),
            );
            let pending_turns: Arc<dashmap::DashMap<String, std::time::Instant>> =
                Arc::new(dashmap::DashMap::new());
            // Bounded + TTL'd (was an unbounded DashSet that only a matching late
            // ps.respond ever drained). A response arriving more than 2× the turn
            // timeout late is not worth remembering.
            let timed_out = Arc::new(RecentIds::new(turn_timeout * 2, MAX_TIMED_OUT_IDS));

            // Spawn task to route bridge events (respond/emit/stream/log) back through relay
            let relay_for_events = relay.clone();
            let sk_for_events = session_key.to_string();
            let pending_ev = pending_turns.clone();
            let timed_out_ev = timed_out.clone();
            let turn_timeout_ev = turn_timeout;
            tokio::spawn(async move {
                while let Some(event) = bridge_event_rx.recv().await {
                    match event {
                        crate::streaming::runtime_bridge::BridgeEvent::Respond { request_id, data } => {
                            // Drop a late response whose turn already timed out; otherwise
                            // forward it and cancel its watchdog (remove from pending).
                            if !request_id.is_empty() && timed_out_ev.take(&request_id) {
                                tracing::warn!(request_id = %request_id, "Dropping late ps.respond — turn already timed out");
                                continue;
                            }
                            pending_ev.remove(&request_id);
                            relay_for_events.send_json(serde_json::json!({
                                "type": "command_response",
                                "session_key": sk_for_events,
                                "request_id": request_id,
                                "data": data,
                            })).await;
                        }
                        crate::streaming::runtime_bridge::BridgeEvent::Emit { name, data } => {
                            relay_for_events.send_json(serde_json::json!({
                                "type": "streaming_event",
                                "session_key": sk_for_events,
                                "event_name": name,
                                "data": data,
                            })).await;
                        }
                        crate::streaming::runtime_bridge::BridgeEvent::Stream { request_id, chunk } => {
                            // A stream chunk means the turn is alive — extend its deadline.
                            if let Some(mut d) = pending_ev.get_mut(&request_id) {
                                *d = std::time::Instant::now() + turn_timeout_ev;
                            }
                            relay_for_events.send_json(serde_json::json!({
                                "type": "stream_chunk",
                                "session_key": sk_for_events,
                                "request_id": request_id,
                                "data": chunk,
                            })).await;
                        }
                        crate::streaming::runtime_bridge::BridgeEvent::Log { message } => {
                            tracing::info!(session_key = %sk_for_events, "[ps.log] {}", message);
                        }
                    }
                }
            });

            // Inject advanced script if present
            if has_advanced_script {
                if let Some(code) = config
                    .get("advanced_script")
                    .and_then(|v| v.get("code"))
                    .and_then(|v| v.as_str())
                {
                    // Use evaluate_expression for side-effect scripts (no return value needed)
                    match page.evaluate_expression(code).await {
                        Ok(_) => {
                            // Mark the document so the first re-inject pass does not run
                            // the script a second time (registering every ps.on twice).
                            crate::streaming::runtime_bridge::mark_advanced_injected(&page).await;
                            tracing::info!("Advanced script injected successfully");
                            println!("  ✓ Advanced script injected ({} bytes)", code.len());
                        }
                        Err(e) => {
                            tracing::error!(error = %e, code_len = code.len(), "Advanced script injection FAILED");
                            println!("  ✗ Advanced script injection failed: {}", e);
                        }
                    }
                }
            }

            // Build handler names from config
            let handler_names: Vec<String> = config.get("handlers")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|h| h.get("name").and_then(|n| n.as_str()).map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            // (task_result was already sent up-front, before navigation/setup, so the
            // streaming service flips the session to "running" without waiting on the
            // heavy setup above.)

            // Send session started confirmation — runtime is now injected and ready.
            relay.send_json(serde_json::json!({
                "type": "streaming_session_started",
                "session_key": session_key,
                "url": target_url,
                "handlers": handler_names,
                "has_advanced_script": has_advanced_script,
            })).await;

            println!("  ✓ Streaming session {} started — {}", truncate_str(session_key, 8), target_url);

            // Create a StreamingSessionManager for command routing.
            // Note: the saas_bridge manages page/context lifecycle directly
            // (navigation, setup steps, runtime injection were done above),
            // so we use `start_attached` to skip duplicated work.
            let mut session_mgr = crate::streaming::manager::StreamingSessionManager::new(
                session_key.to_string(),
                config.clone(),
            );
            // The manager needs to know about handlers for command routing
            // but doesn't take ownership of the page (saas_bridge keeps it).
            // Set the bridge token BEFORE start_attached so its reinject listeners
            // re-inject the runtime with the correct per-session secret.
            session_mgr.set_bridge_token(streaming_bridge_token.clone());
            // Wire the outgoing WS sender BEFORE start_attached so the background
            // loops (keepalive / idle / hard-timeout) can emit frames to the
            // coordinator. The hard-timeout loop also closes the context, so a
            // session whose coordinator dies can't leak Chromium forever.
            session_mgr.set_outgoing(outgoing.clone());
            if let Err(e) = session_mgr.start_attached(page.clone(), context.clone()).await {
                tracing::warn!(error = %e, "Streaming session manager start failed (non-fatal)");
            }
            // Give the manager the bridge sender so it can wire window.ps onto
            // new thread tabs created for additional conversations.
            session_mgr.set_bridge_event_tx(bridge_event_tx_for_mgr);
            // Give it the browser manager so isolated context_mode can create
            // fresh contexts per conversation thread.
            session_mgr.set_browser_manager(browser_manager.clone());

            // Run the streaming session command loop
            let session_key_owned = session_key.to_string();
            let relay_clone = relay.clone();
            let outgoing_clone = outgoing.clone();
            let relays_clone = relays.clone();

            // Listen for commands dispatched to this session's relay
            loop {
                let cmd = match tokio::time::timeout(
                    std::time::Duration::from_secs(10800), // 3-hour idle timeout
                    relay_clone.receive_json(),
                ).await {
                    Ok(Some(cmd)) => cmd,
                    Ok(None) => break,
                    Err(_) => {
                        tracing::info!(session_key = %session_key_owned, "Streaming session idle timeout");
                        break;
                    }
                };

                let cmd_type = cmd["type"].as_str().unwrap_or("");
                tracing::info!(
                    cmd_type,
                    session_key = %session_key_owned,
                    "Streaming session received command from relay"
                );

                if cmd_type == "__session_closed__" || cmd_type == "end_streaming" {
                    tracing::info!("Streaming session ending: {}", cmd_type);
                    break;
                }

                match cmd_type {
                    "streaming_command" => {
                        let action = cmd["action"].as_str().unwrap_or("").to_string();
                        let request_id = cmd["request_id"].as_str().unwrap_or("").to_string();
                        let raw_data = cmd.get("data").cloned().unwrap_or(serde_json::json!({}));
                        // If data arrived as a JSON string, parse it to an object
                        // (the gateway may serialize it as a string)
                        let data = match &raw_data {
                            serde_json::Value::String(s) => {
                                serde_json::from_str(s).unwrap_or(raw_data.clone())
                            }
                            other => other.clone(),
                        };
                        // Log hygiene: command data may carry user input; log only
                        // the action + id at info and the (truncated) preview at debug.
                        tracing::info!(action = %action, request_id = %request_id, "Streaming command received");
                        tracing::debug!(
                            action = %action,
                            request_id = %request_id,
                            data_type = ?std::mem::discriminant(&raw_data),
                            data_preview = %serde_json::to_string(&data).unwrap_or_default().chars().take(200).collect::<String>(),
                            "Streaming command data"
                        );

                        session_mgr.touch();

                        // Check if there's a registered handler for this action
                        if session_mgr.get_handler(&action).is_some() {
                            // Dispatch to the streaming step handler. A steps-type
                            // handler returns its extracted fields SYNCHRONOUSLY
                            // (no async ps.respond), so we MUST answer the turn
                            // here or the caller hangs until its watchdog fires.
                            match crate::streaming::commands::handle_command(
                                &mut session_mgr, &cmd,
                            ).await {
                                Ok(data) => {
                                    relay_clone.send_json(serde_json::json!({
                                        "type": "command_response",
                                        "session_key": session_key_owned,
                                        "request_id": request_id,
                                        "data": data.unwrap_or(serde_json::Value::Null),
                                    })).await;
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, action = %action, "Streaming command handler error");
                                    relay_clone.send_json(serde_json::json!({
                                        "type": "command_response",
                                        "session_key": session_key_owned,
                                        "request_id": request_id,
                                        "error": e.to_string(),
                                    })).await;
                                }
                            }
                        } else {
                            // Dispatch to page via ps._dispatch — EXACT same as Python:
                            // Python: page.evaluate("([action, data, requestId]) => { ... }", [action, data, request_id])
                            // Pass args via evaluate parameter, NOT string interpolation
                            let dispatch_js = r#"([action, data, requestId]) => {
                                if (!window.ps) return {error: 'ps runtime not injected'};
                                if (!window.ps._dispatch) return {error: 'ps._dispatch not available'};
                                const handlers = window.ps._handlers || {};
                                const named = handlers[action] && handlers[action].length > 0;
                                const hasMsg = handlers.message && handlers.message.length > 0;
                                if (!named && !hasMsg) return {error: 'no handler registered for action: ' + action};
                                try {
                                    // A named handler (ps.on("<action>", ...) / ps.fn) takes
                                    // priority; the handler name IS the action so we do NOT
                                    // re-wrap action in the payload. Otherwise fall back to the
                                    // "message" catch-all (legacy, backwards compatible).
                                    if (named) ps._dispatch(action, {data, requestId});
                                    else ps._dispatch('message', {action, data, requestId});
                                    return {ok: true, dispatched: named ? action : 'message'};
                                } catch(e) {
                                    return {error: 'dispatch error: ' + e.message};
                                }
                            }"#;

                            let args = serde_json::json!([action, data, request_id]);

                            // Route to the conversation's tab (multi-conversation).
                            // Falls back to the main page when multi-conv is off or
                            // no _thread_id is present.
                            let thread_id = data.get("_thread_id").and_then(|v| v.as_str());
                            let target_page = match session_mgr.get_thread_page(thread_id).await {
                                Ok(p) => p,
                                Err(e) => {
                                    tracing::warn!(error = %e, "Thread page resolve failed; using main page");
                                    page.clone()
                                }
                            };

                            let dispatch_result: serde_json::Value = target_page.evaluate(
                                dispatch_js, Some(&args),
                            ).await.unwrap_or(serde_json::json!({"error": "evaluate failed"}));

                            tracing::info!(
                                action = %action,
                                request_id = %request_id,
                                result = %dispatch_result,
                                "ps._dispatch result"
                            );

                            // If dispatch returned an error, send it as command_response.
                            // Otherwise the handler is now running ASYNCHRONOUSLY and will
                            // call ps.respond → __ps_respond_bridge → BridgeEvent::Respond →
                            // the event router above → command_response. Arm a per-turn
                            // watchdog so a handler that errors, filters the action, or hangs
                            // returns an error to the caller instead of hanging forever
                            // (parity with Python _dispatch_to_page). Stream chunks extend
                            // the deadline; a real ps.respond cancels it.
                            if let Some(err) = dispatch_result.get("error").and_then(|v| v.as_str()) {
                                tracing::warn!(error = err, action = %action, "Page dispatch error");
                                relay_clone.send_json(serde_json::json!({
                                    "type": "command_response",
                                    "session_key": session_key_owned,
                                    "request_id": request_id,
                                    "error": err,
                                })).await;
                            } else if !request_id.is_empty()
                                && pending_turns.len() >= MAX_INFLIGHT_TURNS
                            {
                                // Back-pressure: every in-flight turn owns a live
                                // watchdog task, so an unbounded stream of unanswered
                                // turns would spawn tasks without limit. Fail this one
                                // immediately (the caller gets a real answer) rather
                                // than growing the set.
                                tracing::warn!(
                                    action = %action,
                                    request_id = %request_id,
                                    in_flight = pending_turns.len(),
                                    "Refusing streaming turn — too many turns awaiting ps.respond"
                                );
                                relay_clone.send_json(serde_json::json!({
                                    "type": "command_response",
                                    "session_key": session_key_owned,
                                    "request_id": request_id,
                                    "error": "too many in-flight turns on this session",
                                })).await;
                            } else if !request_id.is_empty() {
                                pending_turns.insert(request_id.clone(), std::time::Instant::now() + turn_timeout);
                                let pt = pending_turns.clone();
                                let to = timed_out.clone();
                                let relay_wd = relay_clone.clone();
                                let sk_wd = session_key_owned.clone();
                                let rid = request_id.clone();
                                let action_wd = action.clone();
                                tokio::spawn(async move {
                                    loop {
                                        let deadline = match pt.get(&rid) {
                                            Some(d) => *d.value(),
                                            None => return, // ps.respond fired — watchdog cancelled
                                        };
                                        let now = std::time::Instant::now();
                                        if deadline > now {
                                            tokio::time::sleep(deadline - now).await;
                                            continue; // re-check — a stream chunk may have extended it
                                        }
                                        // Deadline reached and still pending → time the turn out.
                                        if pt.remove(&rid).is_some() {
                                            to.insert(rid.clone());
                                            tracing::warn!(
                                                request_id = %rid, action = %action_wd,
                                                "Streaming turn timed out — handler never called ps.respond; returning error"
                                            );
                                            relay_wd.send_json(serde_json::json!({
                                                "type": "command_response",
                                                "session_key": sk_wd,
                                                "request_id": rid,
                                                "error": "handler did not respond (timed out)",
                                            })).await;
                                        }
                                        return;
                                    }
                                });
                            }
                        }
                    }

                    "add_handler" => {
                        if let Err(e) = crate::streaming::commands::handle_command(
                            &mut session_mgr, &cmd,
                        ).await {
                            tracing::warn!(error = %e, "Failed to add handler");
                        }
                    }

                    "remove_handler" => {
                        if let Err(e) = crate::streaming::commands::handle_command(
                            &mut session_mgr, &cmd,
                        ).await {
                            tracing::warn!(error = %e, "Failed to remove handler");
                        }
                    }

                    "ping" => {
                        relay_clone.send_json(serde_json::json!({"type": "pong"})).await;
                    }

                    _ => {
                        tracing::debug!(cmd_type, "Unknown streaming command type");
                    }
                }
            }

            // The command loop is over: drop every in-flight turn so the watchdog
            // tasks still sleeping on a deadline observe "no longer pending" and
            // return on their next wake instead of lingering for up to the turn
            // timeout holding Arc clones of the relay.
            pending_turns.clear();

            // Extract session state (cookies + localStorage + sessionStorage) BEFORE
            // closing the context — 1:1 port of Python StreamingSessionManager.end()
            // which returns session_state so the coordinator can persist auth for resume.
            let saved_session_state = {
                let empty_headers: HashMap<String, String> = HashMap::new();
                let state = crate::automation::session_state::extract_session_state(
                    &page, &context, &empty_headers,
                ).await;
                serde_json::json!({
                    "cookies": state.cookies,
                    "localStorage": state.local_storage,
                    "sessionStorage": state.session_storage,
                    // Persist the fingerprint so the next warm session reuses it.
                    "fingerprint": serde_json::to_value(&fp_used).ok(),
                })
            };

            // Cleanup
            session_mgr.end("bridge_cleanup").await;
            let _ = context.close().await;
            relays_clone.remove(&session_key_owned);

            // Send session ended WITH the saved session state so the coordinator
            // can restore auth on the next session (Python sends session_state here).
            let _ = outgoing_clone.send(BridgeOutgoing::Json(serde_json::json!({
                "type": "streaming_session_ended",
                "session_key": session_key_owned,
                "reason": "ended",
                "session_state": saved_session_state,
            })));

            println!("  ■ Streaming session {} ended", truncate_str(&session_key_owned, 8));
        }
        Err(e) => {
            tracing::error!(error = %e, "Streaming session browser context failed");
            let _ = outgoing.send(BridgeOutgoing::Json(serde_json::json!({
                "type": "task_result",
                "task_id": task_id,
                "success": false,
                "error": format!("Browser context failed: {}", e),
            })));
            // The session is dead — also emit a streaming_session_ended terminal
            // frame. The task_result above only unblocks the initial dispatch
            // waiter; without this frame the streaming-service never learns the
            // session died and leaves the row "running" until the 30-min janitor.
            // No session_state: the context failed, so there's nothing fresh to
            // save (the last good state stays in the affinity table). Authoritative
            // liveness still lives in the gateway+backend; this is the fast signal.
            let _ = outgoing.send(BridgeOutgoing::Json(serde_json::json!({
                "type": "streaming_session_ended",
                "session_key": session_key,
                "reason": "error",
                "session_state": serde_json::Value::Null,
            })));
            relays.remove(session_key);
            println!("  ✗ Streaming session {} failed: {}", truncate_str(session_key, 8), e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ids(ttl_ms: u64, cap: usize) -> RecentIds {
        RecentIds::new(Duration::from_millis(ttl_ms), cap)
    }

    #[test]
    fn recent_ids_suppresses_a_late_response_exactly_once() {
        let r = ids(60_000, 8);
        r.insert("req-1".into());
        assert!(r.take("req-1"), "the late ps.respond for a timed-out turn is dropped");
        assert!(!r.take("req-1"), "…and only once — the entry is consumed");
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn recent_ids_never_grows_past_its_cap() {
        // The old `timed_out` DashSet was drained ONLY by a matching late ps.respond, so a
        // handler that hangs (the common case) left the entry forever. Unique request ids at
        // loop rate then grew it without limit for the 3 h session lifetime.
        let r = ids(60_000, 4);
        for i in 0..1_000 {
            r.insert(format!("req-{i}"));
        }
        assert!(r.len() <= 4, "bounded, got {}", r.len());
        // Oldest evicted first, newest retained.
        assert!(r.take("req-999"));
        assert!(!r.take("req-0"));
    }

    #[test]
    fn recent_ids_expire_so_a_hung_turn_does_not_pin_memory() {
        let r = ids(1, 1024);
        r.insert("stale".into());
        std::thread::sleep(Duration::from_millis(5));
        // Expired: a response this late is forwarded rather than suppressed (harmless — the
        // coordinator ignores a second response for a resolved turn) and the entry is gone.
        assert!(!r.take("stale"));
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn recent_ids_ttl_sweep_reclaims_entries_nobody_ever_answers() {
        let r = ids(1, 1024);
        for i in 0..50 {
            r.insert(format!("never-answered-{i}"));
        }
        std::thread::sleep(Duration::from_millis(5));
        // The next insert sweeps the expired front of the queue.
        r.insert("fresh".into());
        assert_eq!(r.len(), 1, "expired entries are reclaimed without any take()");
        assert!(r.take("fresh"));
    }

    #[test]
    fn recent_ids_reinsert_does_not_double_count_order() {
        let r = ids(60_000, 4);
        r.insert("dup".into());
        r.insert("dup".into());
        assert_eq!(r.len(), 1);
        assert!(r.take("dup"));
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn truncate_str_is_char_safe() {
        // Wire-derived session keys reach log lines through this; a byte slice would panic
        // mid-codepoint.
        assert_eq!(truncate_str("ééééé", 3).chars().count(), 3);
        assert_eq!(truncate_str("ab", 8), "ab");
    }
}
