use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::sync::{broadcast, Mutex};
use tokio::task::JoinHandle;

use crate::browser::manager::BrowserManager;
use crate::browser::screenshot::ScreencastStream;
use crate::config::constants;
use crate::models::session::{RecordingSession, SessionInfo, SessionResult};
use crate::models::step::{RecordedStep, StepType};

pub struct PlaywrightRecorder {
    sessions: Arc<DashMap<String, RecordingSession>>,
    sessions_lock: Arc<Mutex<()>>,
    cleanup_task: Option<JoinHandle<()>>,
    pub browser_manager: Arc<BrowserManager>,
}

impl PlaywrightRecorder {
    pub fn new(browser_manager: Arc<BrowserManager>) -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            sessions_lock: Arc::new(Mutex::new(())),
            cleanup_task: None,
            browser_manager,
        }
    }

    pub fn start_cleanup_loop(&mut self) {
        let sessions = self.sessions.clone();
        self.cleanup_task = Some(tokio::spawn(async move {
            loop {
                tokio::time::sleep(constants::CLEANUP_INTERVAL).await;
                Self::cleanup_idle_sessions(&sessions).await;
            }
        }));
    }

    async fn cleanup_idle_sessions(sessions: &DashMap<String, RecordingSession>) {
        let now = Instant::now();
        let idle_ids: Vec<String> = sessions
            .iter()
            .filter(|entry| {
                now.duration_since(entry.value().last_activity)
                    > constants::SESSION_IDLE_TIMEOUT
            })
            .map(|entry| entry.key().clone())
            .collect();

        for id in &idle_ids {
            tracing::info!(session_id = %id, "Cleaning up idle session");
            if let Some((_, mut session)) = sessions.remove(id) {
                // Stop screenshot streaming
                session.is_recording = false;
                if let Some(task) = session.screenshot_task.take() {
                    task.abort();
                }
                if let Err(e) = session.context.close().await {
                    tracing::warn!(session_id = %id, error = %e, "Failed to close context for idle session");
                }
            }
        }
    }

    pub async fn start_session(
        &self,
        start_url: String,
        record_wait_steps: bool,
        tenant_id: Option<String>,
    ) -> Result<String, StartSessionError> {
        let _lock = self.sessions_lock.lock().await;

        if self.sessions.len() >= constants::MAX_SESSIONS {
            return Err(StartSessionError::SessionLimit(constants::MAX_SESSIONS));
        }

        // SECURITY: vet the start URL BEFORE we create a context / goto it. The
        // per-request route blocker only inspects subresource URLs once navigation
        // is underway; the initial start_url (server/gateway-supplied) must be
        // rejected up front if it targets file:/data:/internal hosts or cloud
        // metadata. Fail CLOSED on DNS error. ("about:blank", relative URLs, and
        // the safe internal prefixes are allowed by the guard.)
        if !crate::security::url_guard::is_navigation_url_safe_async(&start_url).await {
            return Err(StartSessionError::UnsafeUrl(start_url));
        }

        // Create a stealth browser context with a new page
        let (context, page) = self
            .browser_manager
            .create_stealth_context()
            .await
            .map_err(|e| StartSessionError::Browser(e.to_string()))?;

        // A context exists in Chromium from here on, and `BrowserContext` has no `Drop` — returning
        // `Err` below without closing it would strand the context + its renderer for the life of the
        // browser. The navigation failure path is exactly that: a bad/slow start URL leaked one
        // context per attempt, and each leak also holds a slot in the manager's context ceiling. The
        // guard is disarmed once the session OWNS the context (`end_session` / the idle reaper /
        // `shutdown` close it from there).
        let mut ctx_guard = crate::browser::context::ContextCloseGuard::new(context.clone());

        // Navigate to the start URL
        if let Err(e) = crate::browser::navigation::goto(
            &page,
            &start_url,
            "domcontentloaded",
            Duration::from_secs(30),
        )
        .await
        {
            ctx_guard.close().await;
            return Err(StartSessionError::Browser(format!(
                "Navigation to start_url failed: {e}"
            )));
        }

        // Re-inject stealth after navigation (matches Python: await inject_stealth(page))
        let stealth_js = crate::browser::stealth::STEALTH_SCRIPTS;
        let _: Result<serde_json::Value, _> = page.evaluate(stealth_js, None::<&()>).await;

        let session_id = uuid::Uuid::new_v4().to_string();
        let mut session = RecordingSession::new(
            session_id.clone(),
            start_url.clone(),
            tenant_id,
            page.clone(),
            context.clone(),
        );
        session.record_wait_steps = record_wait_steps;

        // Update current_url to the actual page URL after navigation (may have redirected)
        session.current_url = page.url();

        // Record the initial navigate step
        let now_ts = super::step_recording::current_timestamp();
        let initial_step = RecordedStep {
            step_type: StepType::Navigate,
            timestamp: now_ts,
            id: uuid::Uuid::new_v4().to_string(),
            selector: None,
            url: Some(start_url.clone()),
            value: None,
            description: Some(format!("Navigate to {start_url}")),
            coordinates: None,
            viewport: None,
            options: None,
        };
        session.steps.push(initial_step);
        session.last_step_timestamp = now_ts;

        // Setup event channel for JSON events (step_recorded, navigation, etc.)
        // Keep the receiver — the WebSocket handler takes it and forwards events to the
        // frontend. Dropping it here would silently discard all recorded steps.
        let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel::<serde_json::Value>();
        session.event_tx = Some(event_tx);
        session.event_rx = Some(event_rx);

        // Setup screenshot broadcast channel
        let (screenshot_tx, _) = broadcast::channel::<Vec<u8>>(16);
        session.screenshot_tx = Some(screenshot_tx.clone());

        // Start CDP screencast (event-driven, pushes frames on screen changes — exact same as Python)
        let screenshot_page = page.clone();
        let screenshot_context = context.clone();
        let session_id_clone = session_id.clone();
        let screenshot_task = tokio::spawn(async move {
            Self::screenshot_loop_cdp(screenshot_page, screenshot_context, screenshot_tx, session_id_clone).await;
        });
        session.screenshot_task = Some(screenshot_task);

        // Inject helper script on the page
        if let Err(e) = Self::inject_helper_script(&page).await {
            tracing::debug!(error = %e, "Could not inject helper script");
        }

        // The session table now owns the context (closed by `end_session`, the idle reaper, or
        // `shutdown`), so the construction-time guard must not also close it.
        ctx_guard.disarm();
        self.sessions.insert(session_id.clone(), session);

        // Setup page listeners (navigation, console, new tab, close, network capture)
        // Exact port of Python _setup_page_listeners (recorder.py line 2043)
        super::page_listeners::setup_page_listeners(
            self.sessions.clone(),
            session_id.clone(),
            page,
            context,
        )
        .await;

        tracing::info!(session_id = %session_id, "Session started");
        Ok(session_id)
    }

    /// CDP screencast streaming — exact port of Python recorder._screenshot_loop.
    /// Uses CDP Page.startScreencast for event-driven frame delivery (no polling).
    /// Falls back to page.screenshot() polling if CDP fails.
    async fn screenshot_loop_cdp(
        page: playwright_rs::Page,
        context: playwright_rs::BrowserContext,
        tx: broadcast::Sender<Vec<u8>>,
        session_id: String,
    ) {
        // Try CDP screencast first (event-driven, higher FPS, exact same as Python)
        match context.new_cdp_session(&page).await {
            Ok(cdp) => {
                tracing::info!(session_id = %session_id, "CDP screencast started");

                // Register frame handler — fires on every screen change
                let tx_clone = tx.clone();
                let page_clone = page.clone();
                let cdp_clone = cdp.clone();
                // Last-sent frame hash, shared across handler invocations, so we
                // can drop CDP frames that are byte-identical to the previous one
                // (e.g. caret blink / repaint with no visible change).
                let last_hash = std::sync::Arc::new(std::sync::Mutex::new(None::<u64>));
                cdp.on("Page.screencastFrame", move |params: serde_json::Value| {
                    let tx = tx_clone.clone();
                    let page = page_clone.clone();
                    let cdp = cdp_clone.clone();
                    let last_hash = last_hash.clone();
                    async move {
                        // ACK every frame regardless of whether we forward it —
                        // CDP stalls the screencast until the prior frame is acked.
                        if let Some(sid) = params.get("sessionId").and_then(|v| v.as_i64()) {
                            let _ = cdp.send(
                                "Page.screencastFrameAck",
                                Some(serde_json::json!({"sessionId": sid})),
                            ).await;
                        }

                        if let Some(b64_data) = params.get("data").and_then(|v| v.as_str()) {
                            if let Ok(jpeg_bytes) = base64::Engine::decode(
                                &base64::engine::general_purpose::STANDARD, b64_data
                            ) {
                                // Skip the send if this frame is identical to the
                                // last one we forwarded (no new bytes on the wire).
                                let h = ScreencastStream::frame_hash(&jpeg_bytes);
                                {
                                    let mut lh = last_hash.lock().unwrap();
                                    if *lh == Some(h) {
                                        return Ok(());
                                    }
                                    *lh = Some(h);
                                }
                                let url = page.url();
                                let frame = ScreencastStream::encode_frame(&url, &jpeg_bytes);
                                let _ = tx.send(frame);
                            }
                        }
                        Ok(())
                    }
                });

                // Start screencast with same params as Python
                let start_result = cdp.send("Page.startScreencast", Some(serde_json::json!({
                    "format": "jpeg",
                    "quality": 60,
                    "maxWidth": constants::VIEWPORT_WIDTH,
                    "maxHeight": constants::VIEWPORT_HEIGHT,
                    "everyNthFrame": 1
                }))).await;

                match start_result {
                    Ok(_) => {
                        // Keep alive until the broadcast sender is dropped (session ends)
                        loop {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            // When all receivers drop, tx.send() returns error but we keep going
                            // The task will be aborted by end_session()
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "CDP startScreencast failed, falling back to polling");
                        Self::screenshot_loop_fallback(page, tx, session_id).await;
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "CDP session creation failed, falling back to polling");
                Self::screenshot_loop_fallback(page, tx, session_id).await;
            }
        }
    }

    /// Fallback screenshot loop using page.screenshot() polling at 20fps.
    async fn screenshot_loop_fallback(
        page: playwright_rs::Page,
        tx: broadcast::Sender<Vec<u8>>,
        session_id: String,
    ) {
        tracing::info!(session_id = %session_id, "Screenshot fallback: polling at 20fps (adaptive)");
        let mut consecutive_errors: u32 = 0;
        // Dedup + adaptive cadence: when the captured frame is identical to the
        // last one we sent, the page is static — skip the send and progressively
        // back off the poll interval (50ms → 500ms) so an idle tab doesn't burn
        // 20 screenshots/sec of CPU+bandwidth. Any change snaps back to 20fps.
        let mut last_hash: Option<u64> = None;
        let mut idle_streak: u32 = 0;
        // Resend at least one frame every 2s even on a static page, so a
        // spectator that joins mid-session gets a current frame instead of a
        // blank view (the unconditional 20fps stream used to guarantee this).
        let keyframe_interval = Duration::from_secs(2);
        let mut last_send = std::time::Instant::now();

        loop {
            match crate::browser::page_query::screenshot_jpeg(&page, constants::SCREENSHOT_QUALITY).await {
                Ok(jpeg_data) => {
                    consecutive_errors = 0;
                    let h = ScreencastStream::frame_hash(&jpeg_data);
                    let changed = Some(h) != last_hash;
                    if changed {
                        idle_streak = 0;
                    } else {
                        idle_streak = idle_streak.saturating_add(1);
                    }
                    if changed || last_send.elapsed() >= keyframe_interval {
                        last_hash = Some(h);
                        last_send = std::time::Instant::now();
                        let url = page.url();
                        let frame = ScreencastStream::encode_frame(&url, &jpeg_data);
                        let _ = tx.send(frame);
                    }
                }
                Err(e) => {
                    let msg = e.to_string().to_lowercase();
                    if msg.contains("execution context") || msg.contains("target closed") {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                    consecutive_errors += 1;
                    if consecutive_errors > 10 {
                        tracing::error!(session_id = %session_id, "Too many screenshot errors, stopping");
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(if consecutive_errors > 5 { 1000 } else { 300 })).await;
                    continue;
                }
            }
            // 50ms base; double per idle frame up to a 500ms ceiling (50→100→200→400→500).
            let interval = if idle_streak == 0 {
                constants::SCREENSHOT_INTERVAL
            } else {
                let factor = 1u64 << idle_streak.min(4); // 2,4,8,16
                Duration::from_millis((50 * factor).min(500))
            };
            tokio::time::sleep(interval).await;
        }
    }

    /// Inject the recording helper script into the page.
    async fn inject_helper_script(page: &playwright_rs::Page) -> Result<(), anyhow::Error> {
        let helper = super::helpers::HELPER_SCRIPT_JS;
        let _: serde_json::Value = page.evaluate(helper, None::<&()>).await
            .map_err(|e| anyhow::anyhow!("Helper script injection failed: {}", e))?;
        Ok(())
    }

    pub async fn end_session(&self, session_id: &str) -> Result<SessionResult, EndSessionError> {
        let (_, mut session) = self
            .sessions
            .remove(session_id)
            .ok_or(EndSessionError::NotFound(session_id.to_string()))?;

        // Stop recording flag first (prevents screenshot loop from sending on closed ws)
        session.is_recording = false;

        // Stop screenshot task
        if let Some(task) = session.screenshot_task.take() {
            task.abort();
            // Give it a moment to stop
            let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
        }

        // Drop the broadcast sender so subscribers get errors
        session.screenshot_tx = None;

        // Flush any pending input steps
        super::pending::flush_all_pending(&mut session).await;

        // Snapshot any captured API traffic before closing the context.
        let network_calls = session.network_capture.lock().await.get_all_calls().to_vec();

        let step_count = session.steps.len();
        let raw_count = session.raw_replay_steps.len();

        // Close the browser context (not the shared browser)
        if let Err(e) = session.context.close().await {
            tracing::warn!(
                session_id = %session_id,
                error = %e,
                "Failed to close browser context on session end"
            );
        }

        tracing::info!(
            session_id = %session_id,
            steps = step_count,
            raw_replay = raw_count,
            "Session ended"
        );

        Ok(SessionResult {
            step_count,
            raw_replay_count: raw_count,
            steps: session.steps,
            raw_replay: session.raw_replay_steps,
            network_calls,
        })
    }

    pub fn list_sessions(&self, tenant_id: Option<&str>) -> Vec<SessionInfo> {
        self.sessions
            .iter()
            .filter(|entry| {
                tenant_id.is_none()
                    || entry.value().tenant_id.as_deref() == tenant_id
            })
            .map(|entry| {
                let s = entry.value();
                SessionInfo {
                    session_id: s.session_id.clone(),
                    start_url: s.start_url.clone(),
                    current_url: s.current_url.clone(),
                    step_count: s.steps.len(),
                    idle_seconds: s.last_activity.elapsed().as_secs(),
                    tenant_id: s.tenant_id.clone(),
                }
            })
            .collect()
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn get_session_mut(
        &self,
        session_id: &str,
    ) -> Option<dashmap::mapref::one::RefMut<'_, String, RecordingSession>> {
        self.sessions.get_mut(session_id)
    }

    /// Take the JSON event receiver for a session so the WebSocket handler can
    /// forward step_recorded/navigation/etc. events to the frontend.
    /// Returns None if already taken or session not found.
    pub fn take_event_rx(
        &self,
        session_id: &str,
    ) -> Option<tokio::sync::mpsc::UnboundedReceiver<serde_json::Value>> {
        self.sessions
            .get_mut(session_id)
            .and_then(|mut s| s.event_rx.take())
    }

    pub async fn shutdown(&mut self) {
        if let Some(task) = self.cleanup_task.take() {
            task.abort();
        }

        // Close all browser contexts
        let ids: Vec<String> = self.sessions.iter().map(|e| e.key().clone()).collect();
        for id in ids {
            if let Some((_, mut session)) = self.sessions.remove(&id) {
                session.is_recording = false;
                if let Some(task) = session.screenshot_task.take() {
                    task.abort();
                }
                if let Err(e) = session.context.close().await {
                    tracing::warn!(session_id = %id, error = %e, "Failed to close context during shutdown");
                }
            }
        }

        tracing::info!("Recorder shut down");
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StartSessionError {
    #[error("Session limit reached (max {0})")]
    SessionLimit(usize),
    #[error("Browser error: {0}")]
    Browser(String),
    #[error("Refused unsafe start URL: {0}")]
    UnsafeUrl(String),
}

#[derive(Debug, thiserror::Error)]
pub enum EndSessionError {
    #[error("Session not found: {0}")]
    NotFound(String),
}
