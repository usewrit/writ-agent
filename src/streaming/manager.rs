use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio::task::JoinHandle;

use crate::streaming::BridgeOutgoing;
use crate::browser::manager::BrowserManager;
use crate::config::constants;

pub struct StreamingSessionManager {
    pub session_key: String,
    pub running: bool,
    config: serde_json::Value,

    /// Playwright page used for automation.  Set during `start()`.
    pub page: Option<playwright_rs::Page>,
    /// Browser context that owns the page.  Closed during `end()`.
    pub context: Option<playwright_rs::BrowserContext>,

    step_handlers: HashMap<String, HandlerDef>,
    has_advanced_script: bool,
    advanced_script_code: Option<String>,

    /// Per-session capability token guarding the privileged streaming bridges
    /// (eval + file upload). Set when the SaaS bridge runs `setup_runtime_bridge`
    /// (via `set_bridge_token`); used so re-injected runtimes carry the same secret.
    bridge_token: Option<String>,

    /// Multi-conversation gate. When false, every request reuses the single main
    /// tab regardless of the `_thread_id` the coordinator sends.
    multi_conv: bool,
    context_mode: String,
    max_threads: usize,
    /// URL new thread tabs navigate to (from config `url`/`target_url`).
    target_url: Option<String>,

    /// thread_id → its dedicated Playwright page (multi-conversation mode).
    thread_pages: HashMap<String, playwright_rs::Page>,
    /// thread_id → its own browser context (isolated context_mode only).
    thread_contexts: HashMap<String, playwright_rs::BrowserContext>,
    thread_activity: HashMap<String, Instant>,

    /// Bridge event sender, needed to wire `window.ps` callbacks onto newly
    /// created thread tabs. Set by the SaaS bridge via `set_bridge_event_tx`.
    bridge_event_tx: Option<tokio::sync::mpsc::UnboundedSender<super::runtime_bridge::BridgeEvent>>,

    /// Browser manager, used to spin up isolated contexts for new threads when
    /// `context_mode == "isolated"`. Set by the SaaS bridge via
    /// `set_browser_manager`; absent → isolated falls back to a shared tab.
    browser_manager: Option<Arc<BrowserManager>>,

    pub setup_steps_count: usize,
    /// SECRET login credentials the setup steps resolve `{{secret:...}}` against
    /// (persona username/password + minted TOTP under `otp`). Empty by default —
    /// a caller that runs an authenticated session (the local daemon's persona
    /// path) sets these via [`set_setup_credentials`] before `start`. Never logged.
    setup_credentials: HashMap<String, String>,
    /// Epoch-millis of the last activity, SHARED with the background loops so the
    /// idle loop can observe `touch()` without holding a borrow on the manager.
    last_activity_ms: Arc<AtomicI64>,
    /// Idle flag, SHARED with the background loops (they set it on the idle edge;
    /// `touch()` clears it). Mirrored by `is_idle()`.
    idle: Arc<AtomicBool>,
    /// Optional outgoing WS sender given by the SaaS bridge so the background
    /// loops can emit keepalive/idle/terminal frames to the coordinator. Absent
    /// on the standalone/local path (no coordinator to notify).
    outgoing: Option<tokio::sync::mpsc::UnboundedSender<BridgeOutgoing>>,
    setup_retries: usize,
    max_setup_retries: usize,

    login_patterns: Vec<regex::Regex>,

    keepalive_task: Option<JoinHandle<()>>,
    idle_timeout_task: Option<JoinHandle<()>>,
    hard_timeout_task: Option<JoinHandle<()>>,

    /// Bridge drain polling task.
    bridge_drain_task: Option<JoinHandle<()>>,

    /// Session state (cookies + localStorage + sessionStorage) extracted during
    /// `end()` so the caller can persist auth for the next session.
    /// 1:1 with Python StreamingSessionManager.end() returning session_state.
    pub last_session_state: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct HandlerDef {
    pub handler_type: String,
    pub name: String,
    pub step_range: Option<(usize, usize)>,
    pub extract_fields: Vec<String>,
    pub code: Option<String>,
}

impl StreamingSessionManager {
    pub fn new(session_key: String, config: serde_json::Value) -> Self {
        let streaming_config = config.get("streaming_config");
        let multi_conv = streaming_config
            .and_then(|c| c.get("multi_conversation"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let context_mode = streaming_config
            .and_then(|c| c.get("context_mode"))
            .and_then(|v| v.as_str())
            .unwrap_or("shared")
            .to_string();
        let max_threads = streaming_config
            .and_then(|c| c.get("max_concurrent_threads"))
            .and_then(|v| v.as_u64())
            .unwrap_or(constants::STREAMING_MAX_THREADS as u64) as usize;
        let target_url = config
            .get("url")
            .or_else(|| config.get("target_url"))
            .and_then(|v| v.as_str())
            .map(String::from);

        let mut login_patterns: Vec<regex::Regex> = crate::streaming::health::DEFAULT_LOGIN_PATTERNS
            .iter()
            .filter_map(|p| regex::Regex::new(p).ok())
            .collect();

        if let Some(extra) = config
            .get("login_url_patterns")
            .and_then(|v| v.as_array())
        {
            for pattern in extra {
                if let Some(p) = pattern.as_str() {
                    if let Ok(re) = regex::Regex::new(p) {
                        login_patterns.push(re);
                    }
                }
            }
        }

        let setup_steps_count = config
            .get("setup_steps_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;

        Self {
            session_key,
            running: false,
            config,
            page: None,
            context: None,
            step_handlers: HashMap::new(),
            has_advanced_script: false,
            advanced_script_code: None,
            bridge_token: None,
            multi_conv,
            context_mode,
            max_threads,
            target_url,
            thread_pages: HashMap::new(),
            thread_contexts: HashMap::new(),
            thread_activity: HashMap::new(),
            bridge_event_tx: None,
            browser_manager: None,
            setup_steps_count,
            setup_credentials: HashMap::new(),
            last_activity_ms: Arc::new(AtomicI64::new(now_ms())),
            idle: Arc::new(AtomicBool::new(false)),
            outgoing: None,
            setup_retries: 0,
            max_setup_retries: constants::STREAMING_MAX_SETUP_RETRIES,
            login_patterns,
            keepalive_task: None,
            idle_timeout_task: None,
            hard_timeout_task: None,
            bridge_drain_task: None,
            last_session_state: None,
        }
    }

    /// Start the streaming session.
    ///
    /// `page` and `context` are the Playwright handles created by the caller
    /// (typically via `BrowserManager::create_stealth_context()`).
    pub async fn start(
        &mut self,
        page: playwright_rs::Page,
        context: playwright_rs::BrowserContext,
    ) -> Result<(), anyhow::Error> {
        self.running = true;
        self.page = Some(page);
        self.context = Some(context);

        // 1. Navigate to the start URL, restoring saved session state if present.
        // 1:1 port of Python StreamingSessionManager.start() — cookies are injected
        // before navigation, then localStorage after, via inject_session_state.
        let start_url = self
            .config
            .get("url")
            .or_else(|| self.config.get("target_url"))
            .and_then(|v| v.as_str())
            .map(String::from);

        if let Some(url) = start_url {
            let saved_state: Option<crate::models::session::SessionState> = self
                .config
                .get("session_state")
                .filter(|v| !v.is_null())
                .and_then(|v| serde_json::from_value(v.clone()).ok());

            if let (Some(page), Some(context)) = (self.page.clone(), self.context.clone()) {
                if let Some(ref state) = saved_state {
                    tracing::info!(
                        cookies = state.cookies.len(),
                        local_storage = state.local_storage.len(),
                        "Restoring saved streaming session state"
                    );
                    crate::automation::session_state::inject_session_state(
                        &page, &context, state, Some(&url), 30_000,
                    ).await
                    .map_err(|e| anyhow::anyhow!("Session restore failed: {}", e))?;
                } else {
                    page.goto(&url, None).await
                        .map_err(|e| anyhow::anyhow!("Navigation to start URL failed: {}", e))?;
                    // Re-inject stealth on the fresh document (no context add_init_script).
                    crate::browser::navigation::reinject_stealth(&page).await;
                    tracing::info!(url = %url, "Navigated to start URL");
                }
            }
        }

        // 2. Run setup steps (prerequisite steps like login).
        self.run_setup_steps().await?;

        // 3. Set up the runtime bridge.
        // When called from the SaaS bridge, the bridge sets up expose_function
        // callbacks directly. Here we just inject the runtime JS as fallback.
        if let Some(ref page) = self.page {
            // Render with the session's OWN secrets when the caller already ran
            // `setup_runtime_bridge` (it calls `set_bridge_token` before `start`).
            // Rendering with a blank token here used to CLOBBER a working runtime —
            // `window.ps` was replaced by one whose closure held no capability
            // token, so every bridge then failed the token check. With no token set
            // the runtime renders inert, which is correct: this path exposes no
            // bindings of its own.
            let js = super::runtime_bridge::render_runtime_js_for_token(&self.bridge_token());
            let _: Result<(), _> = page.evaluate_expression(&js).await;
            tracing::debug!("Streaming runtime JS injected via manager");
        }

        // 4. Register step handlers from config.
        self.register_handlers_from_config();

        // 5. Inject advanced script if enabled.
        if let Some(script) = self.config.get("advanced_script") {
            if script.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false) {
                self.has_advanced_script = true;
                self.advanced_script_code = script.get("code").and_then(|v| v.as_str()).map(String::from);

                if let (Some(ref page), Some(ref code)) = (&self.page, &self.advanced_script_code) {
                    let _: Result<serde_json::Value, _> =
                        page.evaluate(code, None::<&()>).await;
                    // Mark the document so the first re-inject pass does not run the
                    // script a second time (registering every ps.on handler twice).
                    super::runtime_bridge::mark_advanced_injected(page).await;
                    tracing::info!("Advanced script injected");
                }
            }
        }

        // 5b. Register navigation re-inject listeners so window.ps + the advanced
        // script survive page changes/reloads (1:1 with Python page.on load/domcontentloaded).
        if let Some(ref page) = self.page {
            super::runtime_bridge::setup_reinject_listeners(
                page, self.advanced_script_code.clone(), self.bridge_token(),
            ).await;
        }

        // 6. Start background tasks (keepalive, idle timeout, hard timeout).
        let max_duration = self
            .config
            .get("max_duration_seconds")
            .and_then(|v| v.as_u64())
            .unwrap_or(86400);

        self.start_background_tasks(max_duration);

        tracing::info!(
            session_key = %self.session_key,
            handlers = self.step_handlers.len(),
            has_script = self.has_advanced_script,
            "Streaming session started"
        );

        Ok(())
    }

    /// Attach a pre-configured page/context and start background tasks
    /// without re-running navigation, setup steps, or runtime injection.
    ///
    /// Use this when the caller (e.g. saas_bridge) has already performed
    /// the browser setup itself.
    pub async fn start_attached(
        &mut self,
        page: playwright_rs::Page,
        context: playwright_rs::BrowserContext,
    ) -> Result<(), anyhow::Error> {
        self.running = true;
        self.page = Some(page);
        self.context = Some(context);

        // Register step handlers from config.
        self.register_handlers_from_config();

        // Parse advanced script flag.
        if let Some(script) = self.config.get("advanced_script") {
            if script.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false) {
                self.has_advanced_script = true;
                self.advanced_script_code = script.get("code").and_then(|v| v.as_str()).map(String::from);
            }
        }

        // Register navigation re-inject listeners (window.ps + advanced script
        // survive page changes/reloads). Caller (saas_bridge) injected them initially.
        if let Some(ref page) = self.page {
            super::runtime_bridge::setup_reinject_listeners(
                page, self.advanced_script_code.clone(), self.bridge_token(),
            ).await;
        }

        // Start background tasks.
        let max_duration = self
            .config
            .get("max_duration_seconds")
            .and_then(|v| v.as_u64())
            .unwrap_or(86400);
        self.start_background_tasks(max_duration);

        tracing::info!(
            session_key = %self.session_key,
            handlers = self.step_handlers.len(),
            has_script = self.has_advanced_script,
            "Streaming session started (attached)"
        );

        Ok(())
    }

    /// Register handler definitions from config JSON.
    fn register_handlers_from_config(&mut self) {
        if let Some(handlers) = self.config.get("handlers").and_then(|v| v.as_array()) {
            for h in handlers {
                let name = h.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let handler = HandlerDef {
                    handler_type: h.get("type").and_then(|v| v.as_str()).unwrap_or("steps").to_string(),
                    name: name.clone(),
                    step_range: h.get("step_range").and_then(|v| {
                        let arr = v.as_array()?;
                        Some((arr.first()?.as_u64()? as usize, arr.get(1)?.as_u64()? as usize))
                    }),
                    extract_fields: h
                        .get("extract_fields")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default(),
                    code: h.get("code").and_then(|v| v.as_str()).map(String::from),
                };
                self.step_handlers.insert(name, handler);
            }
        }
    }

    /// Execute setup/prerequisite steps (steps 0..setup_steps_count).
    ///
    /// Uses a retry loop instead of recursion to avoid async boxing.
    async fn run_setup_steps(&mut self) -> Result<(), anyhow::Error> {
        if self.setup_steps_count == 0 {
            return Ok(());
        }

        let steps = self.config.get("steps").and_then(|v| v.as_array()).cloned();
        let Some(steps) = steps else {
            return Ok(());
        };

        let form_data: HashMap<String, String> = self
            .config
            .get("form_data")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        // Persona login secrets (username/password/otp) so a setup `fill`/`twofa`
        // step resolves `{{secret:...}}`. Empty unless a caller attached a persona.
        let credentials: HashMap<String, String> = self.setup_credentials.clone();
        // Streaming setup steps carry no run-level files map (file attachments in
        // streaming are handled separately, §9.2); an inert RunFiles makes an
        // upload/wait_for_download setup step fail closed (File assets §6.3).
        let run_files = crate::automation::files::RunFiles::from_config(&serde_json::Value::Null, None);
        let end = self.setup_steps_count.min(steps.len());

        loop {
            let page = self.page.as_ref().ok_or_else(|| {
                anyhow::anyhow!("No page available for setup steps")
            })?;

            let mut failed = false;
            let mut fail_info: Option<(usize, String, String)> = None;

            for (i, step) in steps.iter().enumerate().take(end) {
                let step_type = step
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                let step_config: crate::models::workflow::WorkflowStepConfig =
                    serde_json::from_value(
                        step.get("config").cloned().unwrap_or(serde_json::json!({})),
                    )
                    .unwrap_or_else(|_| serde_json::from_value(serde_json::json!({})).unwrap());

                tracing::debug!(step_index = i, step_type = step_type, "Running setup step");

                if let Err(e) = crate::automation::step_executor::execute_step(
                    page,
                    step_type,
                    &step_config,
                    &credentials,
                    &form_data,
                    &run_files,
                    30_000,
                    true,
                )
                .await
                {
                    tracing::error!(
                        step_index = i,
                        step_type = step_type,
                        error = %e,
                        "Setup step failed"
                    );
                    failed = true;
                    fail_info = Some((i, step_type.to_string(), e.to_string()));
                    break;
                }
            }

            if !failed {
                tracing::info!(count = end, "Setup steps completed successfully");
                return Ok(());
            }

            // Retry logic
            if self.setup_retries < self.max_setup_retries {
                self.setup_retries += 1;
                tracing::info!(
                    retry = self.setup_retries,
                    max = self.max_setup_retries,
                    "Retrying setup steps"
                );
                continue; // retry from the top of the loop
            }

            let (idx, stype, err) = fail_info.unwrap();
            return Err(anyhow::anyhow!(
                "Setup step {} ({}) failed after {} retries: {}",
                idx,
                stype,
                self.max_setup_retries,
                err
            ));
        }
    }

    /// Detect whether the live session has been logged out — either the page
    /// navigated to a login URL, or the DOM shows a "session expired" notice.
    /// Uses the shared [`crate::streaming::health`] heuristics (login-URL patterns
    /// from config + a phrase list). Best-effort: any read error → assume healthy
    /// so a transient page glitch doesn't trigger a needless re-login.
    pub async fn is_session_expired(&self) -> bool {
        let Some(page) = self.page.as_ref() else {
            return false;
        };
        let url = page.url();
        if super::health::is_on_login_page(&url, &self.login_patterns) {
            return true;
        }
        // Cheap body-text probe for an expiry notice.
        if let Ok(body) = page
            .evaluate::<(), serde_json::Value>("document.body ? document.body.innerText : ''", None::<&()>)
            .await
        {
            if let Some(text) = body.as_str() {
                if super::health::has_session_expired_text(text) {
                    return true;
                }
            }
        }
        false
    }

    /// Re-establish auth for a session that was detected as logged-out: re-navigate
    /// to the start URL, then re-run the setup (login) steps and re-inject the
    /// runtime bridge. Unlike the previous "restore" that only re-injected
    /// `window.ps`, this actually re-authenticates. Resets the setup-retry budget
    /// so a restore isn't blocked by earlier setup retries.
    pub async fn restore_session(&mut self) -> Result<(), anyhow::Error> {
        let start_url = self
            .config
            .get("url")
            .or_else(|| self.config.get("target_url"))
            .and_then(|v| v.as_str())
            .map(String::from);

        if let (Some(page), Some(url)) = (self.page.clone(), start_url) {
            if let Err(e) = page.goto(&url, None).await {
                tracing::warn!(error = %e, "Restore navigation failed");
            }
            crate::browser::navigation::reinject_stealth(&page).await;
        }

        // Allow the login steps a fresh retry budget for this restore attempt.
        self.setup_retries = 0;
        self.run_setup_steps().await?;

        // Re-inject the runtime bridge on the freshly authenticated page.
        if let Some(ref page) = self.page {
            let adv = self.advanced_script_code.clone();
            super::runtime_bridge::reinject_runtime(page, adv.as_deref(), &self.bridge_token()).await?;
        }
        tracing::info!(session_key = %self.session_key, "Streaming session restored (re-authenticated)");
        Ok(())
    }

    fn start_background_tasks(&mut self, max_duration_seconds: u64) {
        // Build the shared context the loops observe/act on. Call this AFTER
        // page/context are set (both `start` and `start_attached` do) so the
        // hard-timeout task holds a real context handle to tear down.
        let ctx = super::background::BackgroundCtx {
            session_key: self.session_key.clone(),
            last_activity_ms: self.last_activity_ms.clone(),
            idle: self.idle.clone(),
            context: self.context.clone(),
            outgoing: self.outgoing.clone(),
            url: self.target_url.clone(),
        };

        let ctx_ka = ctx.clone();
        self.keepalive_task = Some(tokio::spawn(async move {
            super::background::keepalive_loop(ctx_ka).await;
        }));

        let ctx_idle = ctx.clone();
        self.idle_timeout_task = Some(tokio::spawn(async move {
            super::background::idle_timeout_loop(ctx_idle).await;
        }));

        self.hard_timeout_task = Some(tokio::spawn(async move {
            super::background::hard_timeout(ctx, max_duration_seconds).await;
        }));
    }

    pub async fn end(&mut self, reason: &str) {
        if !self.running {
            return;
        }
        self.running = false;

        if let Some(t) = self.keepalive_task.take() {
            t.abort();
        }
        if let Some(t) = self.idle_timeout_task.take() {
            t.abort();
        }
        if let Some(t) = self.hard_timeout_task.take() {
            t.abort();
        }
        if let Some(t) = self.bridge_drain_task.take() {
            t.abort();
        }

        // Close all thread pages/contexts
        let thread_ids: Vec<String> = self.thread_pages.keys().cloned().collect();
        for tid in thread_ids {
            super::threads::close_thread(
                &mut self.thread_pages,
                &mut self.thread_contexts,
                &mut self.thread_activity,
                &tid,
            )
            .await;
        }

        // Extract session state (cookies + localStorage + sessionStorage) BEFORE
        // closing the context. 1:1 port of Python StreamingSessionManager.end().
        if let (Some(page), Some(context)) = (self.page.as_ref(), self.context.as_ref()) {
            let empty_headers: HashMap<String, String> = HashMap::new();
            let state = crate::automation::session_state::extract_session_state(
                page, context, &empty_headers,
            ).await;
            self.last_session_state = Some(serde_json::json!({
                "cookies": state.cookies,
                "localStorage": state.local_storage,
                "sessionStorage": state.session_storage,
            }));
            tracing::info!(
                session_key = %self.session_key,
                cookies = state.cookies.len(),
                "Saved streaming session state on end"
            );
        }

        // Close the browser context (which also closes the page).
        if let Some(context) = self.context.take() {
            if let Err(e) = context.close().await {
                tracing::warn!(error = %e, "Failed to close browser context");
            } else {
                tracing::debug!("Browser context closed");
            }
        }
        self.page = None;

        tracing::info!(
            session_key = %self.session_key,
            reason = reason,
            "Streaming session ended"
        );
    }

    /// Get a reference to the Playwright page.
    pub fn page_ref(&self) -> Option<&playwright_rs::Page> {
        self.page.as_ref()
    }

    /// Store the bridge event sender so newly created thread tabs can wire their
    /// own `window.ps` callbacks (emit/respond/stream/log + pw_* actions).
    pub fn set_bridge_event_tx(
        &mut self,
        tx: tokio::sync::mpsc::UnboundedSender<super::runtime_bridge::BridgeEvent>,
    ) {
        self.bridge_event_tx = Some(tx);
    }

    /// Store the per-session bridge capability token (set by the SaaS bridge after
    /// it runs `setup_runtime_bridge`) so reinject + thread-tab wiring reuse it.
    pub fn set_bridge_token(&mut self, token: String) {
        self.bridge_token = Some(token);
    }

    /// The per-session bridge token, or empty string if the bridges were never
    /// wired (standalone/fallback path — privileged bridges are absent there).
    pub fn bridge_token(&self) -> String {
        self.bridge_token.clone().unwrap_or_default()
    }

    /// Provide the browser manager so isolated `context_mode` can spin up fresh
    /// contexts for new conversation threads. Without it, isolated falls back to
    /// a shared tab.
    pub fn set_browser_manager(&mut self, mgr: Arc<BrowserManager>) {
        self.browser_manager = Some(mgr);
    }

    /// Attach the SECRET login credentials the setup steps resolve `{{secret:...}}`
    /// against (persona username/password + minted TOTP under `otp`). Call BEFORE
    /// `start` so the login setup pass can authenticate. Values are never logged.
    pub fn set_setup_credentials(&mut self, credentials: HashMap<String, String>) {
        self.setup_credentials = credentials;
    }

    /// Whether multi-conversation routing is enabled for this session.
    pub fn multi_conv(&self) -> bool {
        self.multi_conv
    }

    /// Resolve the Playwright page for a conversation thread, creating a new tab
    /// on first use and enforcing the max-concurrent-tabs cap with LRU eviction.
    ///
    /// Mirrors Python `StreamingSessionManager._get_thread_page`:
    /// - multi-conversation off, or `thread_id` empty/"default" → the main page
    /// - existing live thread → its page (activity touched)
    /// - new thread → a fresh tab (shared context; isolated falls back to shared)
    ///
    /// Returns an owned `Page` clone (Playwright pages are cheap handles) so the
    /// caller can drop the `&mut self` borrow before doing page I/O.
    pub async fn get_thread_page(
        &mut self,
        thread_id: Option<&str>,
    ) -> Result<playwright_rs::Page, anyhow::Error> {
        let main = self
            .page
            .clone()
            .ok_or_else(|| anyhow::anyhow!("No main page available"))?;

        let tid = match thread_id {
            Some(t) if !t.is_empty() && t != "default" => t.to_string(),
            _ => return Ok(main),
        };
        if !self.multi_conv {
            return Ok(main);
        }

        // Reuse an existing live tab.
        if let Some(existing) = self.thread_pages.get(&tid) {
            if !existing.is_closed() {
                let page = existing.clone();
                self.thread_activity.insert(tid, Instant::now());
                return Ok(page);
            }
            // Stale (closed) — drop it and recreate below.
            super::threads::close_thread(
                &mut self.thread_pages,
                &mut self.thread_contexts,
                &mut self.thread_activity,
                &tid,
            )
            .await;
        }

        // Enforce the cap — evict the least-recently-used tab if at capacity.
        if super::threads::should_evict(&self.thread_pages, self.max_threads) {
            if let Some(lru) = super::threads::get_lru_thread(&self.thread_activity) {
                tracing::info!(
                    session_key = %self.session_key,
                    evict = %lru,
                    max = self.max_threads,
                    "Evicting LRU thread tab"
                );
                super::threads::close_thread(
                    &mut self.thread_pages,
                    &mut self.thread_contexts,
                    &mut self.thread_activity,
                    &lru,
                )
                .await;
            }
        }

        // Create a new tab. Isolated mode gets its own browser context (falling
        // back to a shared tab if no browser manager was wired in).
        let (page, ctx_opt) = if self.context_mode == "isolated" {
            match self.create_isolated_thread(&tid).await {
                Ok((p, c)) => (p, Some(c)),
                Err(e) => {
                    tracing::warn!(
                        session_key = %self.session_key,
                        error = %e,
                        "Isolated thread creation failed; falling back to shared tab"
                    );
                    (self.create_shared_thread(&tid).await?, None)
                }
            }
        } else {
            (self.create_shared_thread(&tid).await?, None)
        };

        self.thread_pages.insert(tid.clone(), page.clone());
        if let Some(ctx) = ctx_opt {
            self.thread_contexts.insert(tid.clone(), ctx);
        }
        self.thread_activity.insert(tid, Instant::now());
        Ok(page)
    }

    /// Create a new tab in the existing browser context (shared cookies/auth),
    /// navigate it to the target URL, and wire its runtime bridge + re-inject
    /// listeners + advanced script. Mirrors Python `_create_shared_thread`.
    async fn create_shared_thread(
        &self,
        thread_id: &str,
    ) -> Result<playwright_rs::Page, anyhow::Error> {
        let context = self
            .context
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No browser context for thread creation"))?;

        let page = context
            .new_page()
            .await
            .map_err(|e| anyhow::anyhow!("new_page failed for thread {}: {}", thread_id, e))?;

        if let Some(ref url) = self.target_url {
            if let Err(e) = page.goto(url, None).await {
                tracing::warn!(thread_id, error = %e, "Thread tab navigation failed");
            }
            // Re-inject stealth on the fresh document (no context add_init_script).
            crate::browser::navigation::reinject_stealth(&page).await;
        }

        self.wire_thread_runtime(&page, thread_id).await;

        tracing::info!(session_key = %self.session_key, thread_id, "Created shared thread tab");
        Ok(page)
    }

    /// Create a fully isolated thread: its own stealth browser context + page
    /// (independent cookies/localStorage), with the main session's cookies copied
    /// in so it stays authenticated. Mirrors Python `_create_isolated_thread`.
    /// Returns both the page and the new context (so the caller can track/close it).
    async fn create_isolated_thread(
        &self,
        thread_id: &str,
    ) -> Result<(playwright_rs::Page, playwright_rs::BrowserContext), anyhow::Error> {
        let mgr = self
            .browser_manager
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No browser manager for isolated thread"))?;

        let (new_context, page) = mgr
            .create_stealth_context()
            .await
            .map_err(|e| anyhow::anyhow!("isolated context creation failed: {}", e))?;

        // Copy login cookies from the main context so the isolated thread is
        // authenticated (Python copies context.cookies() → new_context.add_cookies()).
        if let Some(main_ctx) = self.context.as_ref() {
            match main_ctx.cookies(None).await {
                Ok(cookies) if !cookies.is_empty() => {
                    let n = cookies.len();
                    if let Err(e) = new_context.add_cookies(&cookies).await {
                        tracing::warn!(thread_id, error = %e, "Cookie copy to isolated context failed");
                    } else {
                        tracing::info!(thread_id, count = n, "Copied cookies to isolated context");
                    }
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(thread_id, error = %e, "Reading main cookies failed"),
            }
        }

        if let Some(ref url) = self.target_url {
            if let Err(e) = page.goto(url, None).await {
                tracing::warn!(thread_id, error = %e, "Isolated thread navigation failed");
            }
            // Re-inject stealth on the fresh document (no context add_init_script).
            crate::browser::navigation::reinject_stealth(&page).await;
        }

        self.wire_thread_runtime(&page, thread_id).await;

        tracing::info!(session_key = %self.session_key, thread_id, "Created isolated thread context");
        Ok((page, new_context))
    }

    /// Wire window.ps + pw_* bridges, navigation re-inject listeners, and the
    /// initial advanced-script injection onto a freshly created thread page.
    async fn wire_thread_runtime(&self, page: &playwright_rs::Page, thread_id: &str) {
        // Wire window.ps + pw_* bridges onto the new tab (needs the bridge sender).
        // All tabs in a session share the SAME capability token so a single
        // re-inject secret works on every tab. Reuse the session token if set.
        let mut thread_token = self.bridge_token();
        let pinned = if thread_token.is_empty() { None } else { Some(thread_token.clone()) };
        if let Some(ref tx) = self.bridge_event_tx {
            match super::runtime_bridge::setup_runtime_bridge_with_token(page, tx.clone(), pinned).await {
                Ok(tok) => thread_token = tok,
                Err(e) => tracing::warn!(thread_id, error = %e, "Thread tab runtime bridge setup failed"),
            }
        } else {
            // Fallback: at least inject the runtime JS so window.ps exists. This
            // tab has no bridges of its own, so render with the session token if we
            // have one (the bindings may already be inherited) and inert otherwise —
            // never with a half-blank secret, which would break every bridge call.
            let js = super::runtime_bridge::render_runtime_js_for_token(&thread_token);
            let _: Result<(), _> = page.evaluate_expression(&js).await;
        }

        // Re-inject runtime + advanced script across navigations/reloads.
        super::runtime_bridge::setup_reinject_listeners(
            page,
            self.advanced_script_code.clone(),
            thread_token,
        )
        .await;

        // Inject the advanced script once now (initial state).
        if let Some(ref code) = self.advanced_script_code {
            if !code.is_empty() {
                if let Err(e) = page.evaluate_expression(code).await {
                    tracing::warn!(thread_id, error = %e, "Advanced script inject failed on thread tab");
                } else {
                    // Mark the document so the first re-inject pass does not run the
                    // script a second time on this tab.
                    super::runtime_bridge::mark_advanced_injected(page).await;
                }
            }
        }
    }

    /// Get a reference to the workflow steps from the config.
    pub fn config_steps(&self) -> Option<&Vec<serde_json::Value>> {
        self.config.get("steps").and_then(|v| v.as_array())
    }

    /// Get the advanced script code (if enabled) for re-injection after navigation.
    pub fn advanced_script_code(&self) -> Option<&str> {
        self.advanced_script_code.as_deref()
    }

    /// Get the base form_data from the config.
    pub fn base_form_data(&self) -> HashMap<String, String> {
        self.config
            .get("form_data")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default()
    }

    pub fn handler_names(&self) -> Vec<String> {
        self.step_handlers.keys().cloned().collect()
    }

    pub fn get_handler(&self, name: &str) -> Option<&HandlerDef> {
        self.step_handlers.get(name)
    }

    pub fn add_handler(&mut self, name: String, handler: HandlerDef) {
        self.step_handlers.insert(name, handler);
    }

    pub fn remove_handler(&mut self, name: &str) -> Option<HandlerDef> {
        self.step_handlers.remove(name)
    }

    pub fn is_idle(&self) -> bool {
        self.idle.load(Ordering::Relaxed)
    }

    pub fn touch(&mut self) {
        self.last_activity_ms.store(now_ms(), Ordering::Relaxed);
        self.idle.store(false, Ordering::Relaxed);
    }

    /// Provide the outgoing WS sender so the background loops can emit
    /// keepalive/idle/terminal frames to the coordinator. Call BEFORE `start`/
    /// `start_attached` (which spawn the loops) for the frames to be wired.
    pub fn set_outgoing(
        &mut self,
        tx: tokio::sync::mpsc::UnboundedSender<BridgeOutgoing>,
    ) {
        self.outgoing = Some(tx);
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
