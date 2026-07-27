use std::collections::HashMap;
use std::sync::Arc;

use dashmap::DashMap;
use playwright_rs::protocol::Frame;

use crate::models::session::RecordingSession;
use crate::models::step::{RecordedStep, StepType};
use super::step_recording;

/// 1:1 port of Python _setup_page_listeners (recorder.py line 2043).
///
/// Registers Playwright event handlers for:
/// 1. framenavigated → record navigate step, re-inject stealth + helper
/// 2. console → debug log browser console messages
/// 3. context.on_page → handle new tab, switch session to it, record wait_for_tab
/// 4. page.on_close → switch back to remaining page, record tab_closed
/// 5. context.on_request / on_response → passive NetworkCapture
/// 6. add_init_script → auto-inject helper on every navigation
pub async fn setup_page_listeners(
    sessions: Arc<DashMap<String, RecordingSession>>,
    session_id: String,
    page: playwright_rs::Page,
    context: playwright_rs::BrowserContext,
) {
    // 1. framenavigated — record navigation steps (Python line 2048)
    {
        let sessions = sessions.clone();
        let sid = session_id.clone();
        let page_clone = page.clone();
        let _ = page.on_framenavigated(move |frame: Frame| {
            let sessions = sessions.clone();
            let sid = sid.clone();
            let page_ref = page_clone.clone();
            async move {
                // Only handle main frame navigations (Python: if frame != session.page.main_frame: return)
                let frame_url = frame.url();
                if let Ok(main_frame) = page_ref.main_frame().await {
                    if frame_url != main_frame.url() {
                        return Ok(());
                    }
                }
                if frame_url == "about:blank" {
                    return Ok(());
                }

                // IMPORTANT: never hold the DashMap lock across an await. A CAPTCHA /
                // Cloudflare challenge page navigates in a tight loop, firing this
                // handler rapidly; holding the session lock across page.evaluate would
                // starve tokio workers and hang the agent. So: brief read to dedup +
                // clone the page, evaluate UNLOCKED, then brief write to record.
                let page_for_eval = {
                    match sessions.get(&sid) {
                        Some(s) => {
                            if frame_url == s.current_url {
                                return Ok(()); // same URL (challenge reload) — skip
                            }
                            s.page.clone()
                        }
                        None => return Ok(()),
                    }
                }; // lock released here

                // Re-inject stealth + helper after navigation WITHOUT holding the lock
                // (Python lines 2764-2768). Errors (destroyed context) are ignored.
                let stealth_js = crate::browser::stealth::STEALTH_SCRIPTS;
                let _: Result<serde_json::Value, _> = page_for_eval.evaluate(stealth_js, None::<&()>).await;
                let helper = super::helpers::HELPER_SCRIPT_JS;
                let _: Result<serde_json::Value, _> = page_for_eval.evaluate(helper, None::<&()>).await;

                // Brief write lock to update URL + record the step (no await held).
                if let Some(mut session) = sessions.get_mut(&sid) {
                    if frame_url == session.current_url {
                        return Ok(());
                    }
                    session.current_url = frame_url.clone();
                    step_recording::send_navigation_event(&session, &frame_url);
                    let step = RecordedStep {
                        step_type: StepType::Navigate,
                        timestamp: step_recording::current_timestamp(),
                        id: uuid::Uuid::new_v4().to_string(),
                        selector: None,
                        url: Some(frame_url.clone()),
                        value: None,
                        description: Some(format!("Navigate to {}", &frame_url)),
                        coordinates: None,
                        viewport: None,
                        options: None,
                    };
                    step_recording::record_step_with_delay(&mut session, step);
                }
                Ok(())
            }
        }).await;
    }

    // 2. console — debug log browser console messages (Python line 2053)
    {
        let _ = page.on_console(move |msg: playwright_rs::ConsoleMessage| {
            async move {
                tracing::debug!(browser_console = %msg.text(), "Browser console");
                Ok(())
            }
        }).await;
    }

    // 2b/2c. download + filechooser listeners (File assets §6.2). Factored into a
    // shared helper so new tabs (context.on_page) get the same coverage as the
    // initial page (mirrors Python _switch_to_page re-registering listeners).
    register_file_listeners(&page, sessions.clone(), session_id.clone()).await;

    // 3. context.on_page — handle new tab opened (Python line 2063)
    {
        let sessions = sessions.clone();
        let sid = session_id.clone();
        let _ = context.on_page(move |new_page: playwright_rs::Page| {
            let sessions = sessions.clone();
            let sid = sid.clone();
            async move {
                // Wait for domcontentloaded (Python line 2077)
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    new_page.wait_for_load_state(Some(playwright_rs::WaitUntil::DomContentLoaded)),
                ).await;

                let url = new_page.url();
                tracing::info!(session_id = %sid, url = %url, "New page opened");

                // Distinguish a tab the SITE opened (popup / target=_blank / window.open)
                // from one the USER opened themselves (Ctrl+T). A site-opened page has an
                // opener; a user-opened blank tab does not. These map to two different
                // replay actions: wait_for_tab (we wait for it) vs open_tab (we open it).
                let site_opened = matches!(new_page.opener().await, Ok(Some(_)));

                // Wire close listener on the new page (Python line 2085)
                {
                    let sessions_inner = sessions.clone();
                    let sid_inner = sid.clone();
                    let new_page_url = url.clone();
                    let _ = new_page.on_close(move || {
                        let sessions = sessions_inner.clone();
                        let sid = sid_inner.clone();
                        let closed_url = new_page_url.clone();
                        async move {
                            on_page_closed(&sessions, &sid, &closed_url).await;
                            Ok(())
                        }
                    }).await;
                }

                // Wire framenavigated on new page (Python line 2164)
                {
                    let sessions_nav = sessions.clone();
                    let sid_nav = sid.clone();
                    let np = new_page.clone();
                    let _ = new_page.on_framenavigated(move |frame: Frame| {
                        let sessions = sessions_nav.clone();
                        let sid = sid_nav.clone();
                        let page = np.clone();
                        async move {
                            let frame_url = frame.url();
                            if let Ok(main_frame) = page.main_frame().await {
                                if frame_url != main_frame.url() {
                                    return Ok(());
                                }
                            }
                            if frame_url == "about:blank" {
                                return Ok(());
                            }
                            if let Some(mut session) = sessions.get_mut(&sid) {
                                if frame_url != session.current_url {
                                    session.current_url = frame_url.clone();
                                    step_recording::send_navigation_event(&session, &frame_url);
                                    let step = RecordedStep {
                                        step_type: StepType::Navigate,
                                        timestamp: step_recording::current_timestamp(),
                                        id: uuid::Uuid::new_v4().to_string(),
                                        selector: None,
                                        url: Some(frame_url.clone()),
                                        value: None,
                                        description: Some(format!("Navigate to {}", &frame_url)),
                                        coordinates: None,
                                        viewport: None,
                                        options: None,
                                    };
                                    step_recording::record_step_with_delay(&mut session, step);
                                }
                            }
                            Ok(())
                        }
                    }).await;
                }

                // Wire download + filechooser listeners on the new tab so uploads /
                // downloads triggered in it are recorded too (File assets §6.2).
                register_file_listeners(&new_page, sessions.clone(), sid.clone()).await;

                // Switch the session to the new page (brief lock, no await held).
                {
                    match sessions.get_mut(&sid) {
                        Some(mut session) => {
                            if !session.is_recording {
                                return Ok(());
                            }
                            // Switch session to the new page (Python line 2090)
                            session.page = new_page.clone();
                            session.current_url = url.clone();
                        }
                        None => return Ok(()),
                    }
                } // lock released before evaluate

                // Inject stealth + helper on the new page WITHOUT holding the lock
                // (Python line 2167-2171). Avoids worker starvation on tab-heavy pages.
                let stealth_js = crate::browser::stealth::STEALTH_SCRIPTS;
                let _: Result<serde_json::Value, _> = new_page.evaluate(stealth_js, None::<&()>).await;
                let helper = super::helpers::HELPER_SCRIPT_JS;
                let _: Result<serde_json::Value, _> = new_page.evaluate(helper, None::<&()>).await;

                // Brief write lock to record the wait_for_tab step + tab list (no await held).
                if let Some(mut session) = sessions.get_mut(&sid) {
                    let pages = session.context.pages();
                    let tab_index = pages.len().saturating_sub(1);
                    let step = RecordedStep {
                        step_type: if site_opened { StepType::WaitForTab } else { StepType::OpenTab },
                        timestamp: step_recording::current_timestamp(),
                        id: uuid::Uuid::new_v4().to_string(),
                        selector: None,
                        url: Some(url.clone()),
                        value: None,
                        description: Some(if site_opened {
                            format!("New tab opened by site: {}", &url)
                        } else {
                            format!("Opened new tab: {}", &url)
                        }),
                        coordinates: None,
                        viewport: None,
                        options: Some({
                            let mut opts = HashMap::new();
                            opts.insert("tab_index".to_string(), serde_json::json!(tab_index));
                            opts
                        }),
                    };
                    step_recording::record_step_with_delay(&mut session, step);
                    send_tab_list_from_context(&session);
                }
                Ok(())
            }
        }).await;
    }

    // 4. page.on_close — handle page closed (Python line 2068)
    {
        let sessions = sessions.clone();
        let sid = session_id.clone();
        let page_url = page.url();
        let _ = page.on_close(move || {
            let sessions = sessions.clone();
            let sid = sid.clone();
            let closed_url = page_url.clone();
            async move {
                on_page_closed(&sessions, &sid, &closed_url).await;
                Ok(())
            }
        }).await;
    }

    // NOTE: Python _setup_page_listeners does NOT attach network request/response
    // capture in the recording path — NetworkCapture is attached only in api_discovery
    // mode (see ai/api_discovery_mode.rs::attach_network_capture). Registering
    // high-frequency context-level on_request/on_response here caused every network
    // request to spawn a task calling sessions.get_mut(), which blocks on the same
    // DashMap shard lock the action handler holds across its page I/O — starving
    // tokio worker threads and deadlocking the first user action. Intentionally omitted.

    // add_init_script — auto-inject helper on every navigation (Python line 2057)
    let helper = super::helpers::HELPER_SCRIPT_JS;
    if let Err(e) = context.add_init_script(helper).await {
        tracing::debug!(error = %e, "Could not add init script to context");
    }
}

/// Handle a page/tab being closed — switch back to remaining page.
/// 1:1 port of Python _on_page_closed (recorder.py line 2104).
async fn on_page_closed(
    sessions: &DashMap<String, RecordingSession>,
    session_id: &str,
    closed_url: &str,
) {
    if let Some(mut session) = sessions.get_mut(session_id) {
        if !session.is_recording {
            return;
        }

        tracing::info!(session_id = %session_id, url = %closed_url, "Page closed");

        // If the closed page is still the active one, switch to another (Python line 2114)
        let active_url = session.page.url();
        if active_url == closed_url || session.page.is_closed() {
            let pages: Vec<playwright_rs::Page> = session
                .context
                .pages()
                .into_iter()
                .filter(|p| !p.is_closed())
                .collect();

            if let Some(last_page) = pages.last() {
                session.page = last_page.clone();
                session.current_url = last_page.url();

                let step = RecordedStep {
                    step_type: StepType::TabClosed,
                    timestamp: step_recording::current_timestamp(),
                    id: uuid::Uuid::new_v4().to_string(),
                    selector: None,
                    url: Some(session.current_url.clone()),
                    value: None,
                    description: Some("Tab closed — returned to previous tab".to_string()),
                    coordinates: None,
                    viewport: None,
                    options: None,
                };
                step_recording::record_step_with_delay(&mut session, step);

                tracing::info!(
                    session_id = %session_id,
                    url = %session.current_url,
                    "Switched back to previous tab"
                );
            }
        }

        // Send updated tab list (Python line 2131)
        send_tab_list_from_context(&session);
    }
}

/// Register `download` + `filechooser` listeners on a page (File assets §6.2).
///
/// * download → record a `wait_for_download` step, then DELETE the recording-time
///   artifact so nothing is persisted (§10.5). The replay-side wait_for_download
///   step re-captures the file at run time direct-to-storage.
/// * filechooser → record an `upload` step (derive a selector for the file input +
///   capture its `multiple` flag), then DISMISS the chooser with empty files so
///   recording continues without uploading anything (v1 = dismiss-empty; the
///   buyer/owner binds a real file at replay time).
///
/// Called for the initial page and for every new tab so coverage matches Python.
async fn register_file_listeners(
    page: &playwright_rs::Page,
    sessions: Arc<DashMap<String, RecordingSession>>,
    session_id: String,
) {
    // download
    {
        let sessions = sessions.clone();
        let sid = session_id.clone();
        let _ = page.on_download(move |dl: playwright_rs::protocol::Download| {
            let sessions = sessions.clone();
            let sid = sid.clone();
            async move {
                let suggested = dl.suggested_filename().to_string();
                tracing::info!(session_id = %sid, filename = %suggested, "Download detected during recording");

                // Brief write lock to record the step (no await held while locked).
                if let Some(mut session) = sessions.get_mut(&sid) {
                    if !session.is_recording {
                        return Ok(());
                    }
                    let step = RecordedStep {
                        step_type: StepType::WaitForDownload,
                        timestamp: step_recording::current_timestamp(),
                        id: uuid::Uuid::new_v4().to_string(),
                        selector: None,
                        url: None,
                        value: None,
                        description: Some("File download".to_string()),
                        coordinates: None,
                        viewport: None,
                        options: Some({
                            let mut opts = HashMap::new();
                            opts.insert(
                                "suggested_filename".to_string(),
                                serde_json::json!(suggested),
                            );
                            opts
                        }),
                    };
                    step_recording::record_step_with_delay(&mut session, step);
                } // lock released before the await below

                // Never keep the recording-time artifact (§10.5 temp-file hygiene).
                if let Err(e) = dl.delete().await {
                    tracing::debug!(error = %e, "Failed to delete recording-time download artifact (ignored)");
                }
                Ok(())
            }
        }).await;
    }

    // filechooser
    {
        let sessions = sessions.clone();
        let sid = session_id.clone();
        let _ = page.on_filechooser(move |fc: playwright_rs::protocol::FileChooser| {
            let sessions = sessions.clone();
            let sid = sid.clone();
            async move {
                let is_multiple = fc.is_multiple();
                // The crate's ElementHandle cannot evaluate JS, so we derive a stable
                // selector for the file input by running the recorder's selector
                // strategy (id > name > placeholder > tag) against the live page's
                // file input — same id/name/tag heuristic the helper uses for clicks.
                let selector = derive_file_input_selector(fc.page(), is_multiple).await;
                tracing::info!(session_id = %sid, selector = %selector, is_multiple, "File chooser detected during recording");

                if let Some(mut session) = sessions.get_mut(&sid) {
                    if session.is_recording {
                        let step = RecordedStep {
                            step_type: StepType::Upload,
                            timestamp: step_recording::current_timestamp(),
                            id: uuid::Uuid::new_v4().to_string(),
                            selector: Some(selector.clone()),
                            url: None,
                            value: None,
                            description: Some("Upload file".to_string()),
                            coordinates: None,
                            viewport: None,
                            options: Some({
                                let mut opts = HashMap::new();
                                opts.insert("is_multiple".to_string(), serde_json::json!(is_multiple));
                                // mode=input: the derived selector targets the
                                // <input type=file> directly (set_input_files at replay).
                                opts.insert("mode".to_string(), serde_json::json!("input"));
                                opts
                            }),
                        };
                        step_recording::record_step_with_delay(&mut session, step);
                    }
                    // else: not recording — still dismiss so the page isn't left waiting.
                } // lock released before the await below

                // Dismiss with empty files so recording continues without uploading a
                // recording-time file (v1 = dismiss-empty; no throwaway file stored).
                if let Err(e) = fc.set_files(&[]).await {
                    tracing::debug!(error = %e, "Failed to dismiss file chooser with empty files (ignored)");
                }
                Ok(())
            }
        }).await;
    }
}

/// Derive a stable selector for the `<input type="file">` that triggered a file
/// chooser (File assets §6.2). The crate's `ElementHandle` (from `fc.element()`)
/// cannot evaluate JS, so we run the recorder's selector strategy (id > name >
/// placeholder > tag) against the page's file input in-page — the same id/name/tag
/// heuristic the click/fill helper uses (action_handler.rs `getSelector`). When more
/// than one file input matches, prefer the one whose `multiple` flag matches the
/// chooser's `is_multiple`, falling back to the first. Returns `input[type=file]`
/// as a last resort so the replay step always has a usable selector.
async fn derive_file_input_selector(page: &playwright_rs::Page, is_multiple: bool) -> String {
    let js = format!(
        r#"(() => {{
            const wantMultiple = {want_multiple};
            const inputs = Array.from(document.querySelectorAll('input[type="file"]'));
            if (inputs.length === 0) return 'input[type="file"]';
            // Prefer an input whose `multiple` matches the chooser; else the first.
            let el = inputs.find(i => !!i.multiple === wantMultiple) || inputs[0];
            const getSelector = (e) => {{
                if (e.id) return '#' + e.id;
                if (e.name) return e.tagName.toLowerCase() + '[name="' + e.name + '"]';
                if (e.placeholder) return e.tagName.toLowerCase() + '[placeholder="' + e.placeholder + '"]';
                // Disambiguate by index when there are several bare file inputs.
                if (inputs.length > 1) {{
                    const idx = inputs.indexOf(e);
                    return 'input[type="file"]:nth-of-type(' + (idx + 1) + ')';
                }}
                return 'input[type="file"]';
            }};
            return getSelector(el);
        }})()"#,
        want_multiple = if is_multiple { "true" } else { "false" },
    );
    match page.evaluate::<(), String>(&js, None::<&()>).await {
        Ok(sel) if !sel.is_empty() => sel,
        _ => "input[type=\"file\"]".to_string(),
    }
}

/// Send the current list of open tabs to the frontend.
/// 1:1 port of Python _send_tab_list (recorder.py line 2133).
fn send_tab_list_from_context(session: &RecordingSession) {
    let pages = session.context.pages();
    let active_url = session.page.url();
    let tabs: Vec<crate::models::session::TabInfo> = pages
        .iter()
        .enumerate()
        .filter(|(_, p)| !p.is_closed())
        .map(|(i, p)| {
            let url = p.url();
            let title = url.chars().take(60).collect::<String>();
            let active = url == active_url;
            crate::models::session::TabInfo {
                index: i,
                url,
                title,
                active,
            }
        })
        .collect();

    step_recording::send_tab_list(session, &tabs);
}
