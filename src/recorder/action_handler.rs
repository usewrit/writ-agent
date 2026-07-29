use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::models::session::{
    PendingFill, PendingScroll, RecordingSession,
};
use crate::models::step::{RecordedStep, StepType};

#[derive(Debug, Clone, Deserialize)]
pub struct IncomingAction {
    #[serde(rename = "type")]
    pub action_type: String,
    #[serde(flatten)]
    pub data: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActionResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// `ActionResult::data` payloads that are ALREADY a complete frontend frame (they
/// carry their own `type`) and are forwarded to the UI verbatim.
///
/// Both transports that surface action results — the local/fleet record driver
/// (`local::record::session`) and the cloud bridge (`bridge::saas_bridge`) — gate
/// on this one list, so a new overlay frame can never reach one UI and not the
/// other.
pub const PASSTHROUGH_FRAME_TYPES: &[&str] = &[
    "select_options",
    "native_picker",
    // Extraction lane: hover highlight box, and the live "test this extraction" result.
    "highlight",
    "extract_test_result",
];

/// Whether `frame_type` is a complete UI frame to forward verbatim (see
/// [`PASSTHROUGH_FRAME_TYPES`]).
pub fn is_passthrough_frame(frame_type: &str) -> bool {
    PASSTHROUGH_FRAME_TYPES.contains(&frame_type)
}

impl ActionResult {
    pub fn ok() -> Self {
        Self {
            success: true,
            error: None,
            data: None,
        }
    }

    pub fn ok_with_data(data: serde_json::Value) -> Self {
        Self {
            success: true,
            error: None,
            data: Some(data),
        }
    }

    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            error: Some(msg.into()),
            data: None,
        }
    }
}

pub fn handle_action(
    session: &mut RecordingSession,
    action: IncomingAction,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ActionResult> + Send + '_>> {
    Box::pin(handle_action_inner(session, action))
}

async fn handle_action_inner(
    session: &mut RecordingSession,
    action: IncomingAction,
) -> ActionResult {
    let result = match action.action_type.as_str() {
        "batch" => handle_batch(session, &action).await,
        "click" => handle_click(session, &action).await,
        "mousemove" => handle_mousemove(session, &action).await,
        "type" => handle_type(session, &action).await,
        "press" => handle_press(session, &action).await,
        "scroll" => handle_scroll(session, &action).await,
        "navigate" => handle_navigate(session, &action).await,
        "back" => handle_back(session).await,
        "forward" => handle_forward(session).await,
        "reload" => handle_reload(session).await,
        "wait" => handle_wait(session, &action).await,
        "evaluate_js" => handle_evaluate_js(session, &action).await,
        "get_element_info" => handle_get_element_info(session, &action).await,
        "get_elements_in_region" => handle_get_elements_in_region(session, &action).await,
        "get_dom" => handle_get_dom(session).await,
        "select_option" => handle_select_option(session, &action).await,
        "set_picker_value" => handle_set_picker_value(session, &action).await,
        "switch_tab" => handle_switch_tab(session, &action).await,
        "close_tab" => handle_close_tab(session, &action).await,
        "test_streaming_script" => handle_test_streaming_script(session, &action).await,
        "add_wait_for_change_step" => handle_add_wait_for_change_step(session, &action).await,
        // Extraction lane (the recorder's "Extract" mode). Every one of these was
        // missing, so the UI's own frames fell to the `Unknown action type` arm
        // below: hovering in extraction mode raised an error toast every 100ms and
        // "Add Step" silently recorded nothing.
        "highlight_element" => handle_highlight_element(session, &action).await,
        "clear_highlight" => handle_clear_highlight().await,
        "add_extract_step" => handle_add_extract_step(session, &action).await,
        "test_extract" => handle_test_extract(session, &action).await,
        other => {
            tracing::warn!(action_type = other, "Unknown action type");
            ActionResult::err(format!("Unknown action type: {}", other))
        }
    };

    session.last_activity = std::time::Instant::now();
    result
}

async fn handle_batch(session: &mut RecordingSession, action: &IncomingAction) -> ActionResult {
    let actions = action
        .data
        .get("actions")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    for sub_action_value in actions {
        if let Ok(sub_action) = serde_json::from_value::<IncomingAction>(sub_action_value) {
            let result = handle_action(session, sub_action).await;
            if !result.success {
                return result;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    ActionResult::ok()
}

async fn handle_click(session: &mut RecordingSession, action: &IncomingAction) -> ActionResult {
    super::click_handler::handle_click(session, action).await
}

/// Human-behavior layer capture (parity with the Python recorder): the frontend
/// streams `mousemove` as the operator moves over the screencast. Buffer a
/// downsampled trajectory (with per-sample time offsets) so the NEXT recorded
/// click carries the real motion, and move the real cursor so hover-triggered
/// UI still appears. Must never surface an error to the frontend.
async fn handle_mousemove(session: &mut RecordingSession, action: &IncomingAction) -> ActionResult {
    let x = action.data.get("x").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let y = action.data.get("y").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let now = super::step_recording::current_timestamp();

    if session.mouse_path_buf.is_empty() {
        session.mouse_path_started_at = now;
    }
    // Downsample: drop samples closer than ~16px (manhattan) to the last one,
    // but still move the cursor for hover fidelity.
    if let Some(last) = session.mouse_path_buf.last() {
        if (x - last.x).abs() + (y - last.y).abs() < 16.0 {
            let _ = crate::browser::page_actions::hover_at(&session.page, x, y).await;
            return ActionResult::ok();
        }
    }
    session.mouse_path_buf.push(crate::models::step::MousePathSample {
        x,
        y,
        t: ((now - session.mouse_path_started_at) * 1000.0).max(0.0) as u64,
    });
    // Cap buffer length; keep the most recent samples (tail matters for a click).
    let len = session.mouse_path_buf.len();
    if len > 60 {
        session.mouse_path_buf.drain(..len - 60);
    }
    let _ = crate::browser::page_actions::hover_at(&session.page, x, y).await;
    ActionResult::ok()
}

async fn handle_type(session: &mut RecordingSession, action: &IncomingAction) -> ActionResult {
    let text = action
        .data
        .get("text")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Human-behavior layer: the frontend may attach the real per-character
    // keystroke deltas (ms). Accumulate them across the `type` actions that
    // make up one field; drained into the flushed raw step in record_raw_step.
    if let Some(kts) = action.data.get("key_timings").and_then(|v| v.as_array()) {
        session
            .key_timing_buf
            .extend(kts.iter().filter_map(|v| v.as_f64()).map(|ms| ms.clamp(0.0, 5000.0) as u64));
    }

    if text.is_empty() {
        return ActionResult::ok();
    }

    // Get focused element metadata BEFORE typing
    let field_info: Option<serde_json::Value> = match crate::browser::page_query::evaluate(
        &session.page,
        r#"(() => {
            const el = document.activeElement;
            if (!el || el === document.body) return null;

            const type = (el.type || '').toLowerCase();
            const name = (el.name || '').toLowerCase();
            const id = (el.id || '').toLowerCase();
            const placeholder = (el.placeholder || '');
            const autocomplete = (el.autocomplete || '').toLowerCase();

            // Get associated label text
            let labelText = '';
            if (el.labels && el.labels.length > 0) {
                labelText = el.labels[0].textContent.trim();
            } else if (el.id) {
                const labelEl = document.querySelector('label[for="' + el.id + '"]');
                if (labelEl) labelText = labelEl.textContent.trim();
            }
            if (!labelText) {
                labelText = el.getAttribute('aria-label') || '';
            }

            // Detect sensitive fields
            const sensitiveTypes = ['password'];
            const sensitiveNames = ['password', 'pwd', 'pass', 'secret', 'token', 'api_key', 'apikey', 'auth', 'credential'];
            const isSensitive = sensitiveTypes.includes(type) ||
                sensitiveNames.some(s => name.includes(s) || id.includes(s) || autocomplete.includes(s));

            // Detect field semantic type
            let fieldCategory = 'text';
            const allText = name + ' ' + id + ' ' + placeholder.toLowerCase() + ' ' + labelText.toLowerCase() + ' ' + autocomplete;

            if (type === 'email' || allText.includes('email') || allText.includes('e-mail')) fieldCategory = 'email';
            else if (type === 'password' || isSensitive) fieldCategory = 'password';
            else if (type === 'tel' || allText.includes('phone') || allText.includes('mobile') || allText.includes('tel')) fieldCategory = 'phone';
            else if (allText.includes('user') || allText.includes('login') || allText.includes('username')) fieldCategory = 'username';
            else if (allText.includes('first') && allText.includes('name')) fieldCategory = 'first_name';
            else if (allText.includes('last') && allText.includes('name')) fieldCategory = 'last_name';
            else if (allText.includes('name') && !allText.includes('user')) fieldCategory = 'name';
            else if (allText.includes('address') || allText.includes('street')) fieldCategory = 'address';
            else if (allText.includes('city')) fieldCategory = 'city';
            else if (allText.includes('zip') || allText.includes('postal')) fieldCategory = 'zip';
            else if (allText.includes('country')) fieldCategory = 'country';
            else if (allText.includes('search')) fieldCategory = 'search';
            else if (allText.includes('comment') || allText.includes('message') || allText.includes('description')) fieldCategory = 'text_area';
            else if (type === 'date') fieldCategory = 'date';
            else if (type === 'time') fieldCategory = 'time';
            else if (type === 'number') fieldCategory = 'number';
            else if (type === 'url') fieldCategory = 'url';

            const displayName = labelText || placeholder || el.name || el.id || '';

            // Selector generation.
            //
            // PREFER the injected helper: it verifies UNIQUENESS and walks
            // id → data-testid → name → aria-label → placeholder → title → nth path.
            // The local fallback below does not check uniqueness at all, so on a page
            // with a duplicated field (a WordPress header/body `input[name="s"]` pair
            // is the everyday case) it hands back a selector that resolves to the
            // WRONG element — the fill is then read from, and replayed into, the twin.
            // The Python recorder has always preferred the helper here; this handler
            // was the one place that did not.
            const getFallbackSelector = () => {
                if (el.id) return '#' + el.id;
                if (el.name) return el.tagName.toLowerCase() + '[name="' + el.name + '"]';
                if (el.placeholder) return el.tagName.toLowerCase() + '[placeholder="' + el.placeholder + '"]';
                return el.tagName.toLowerCase();
            };
            const getSelector = () => {
                if (window.__psRecorder && window.__psRecorder.getSelector) {
                    try {
                        const s = window.__psRecorder.getSelector(el);
                        if (s && s !== 'body') return s;
                    } catch (e) { /* fall through */ }
                }
                return getFallbackSelector();
            };

            // Recognition metadata
            let formIndex = -1;
            let fieldIndex = -1;
            const form = el.closest('form');
            if (form) {
                const allForms = Array.from(document.querySelectorAll('form'));
                formIndex = allForms.indexOf(form);
                const formInputs = Array.from(form.querySelectorAll('input, textarea, select'));
                fieldIndex = formInputs.indexOf(el);
            } else {
                const allInputs = Array.from(document.querySelectorAll('input, textarea, select'));
                fieldIndex = allInputs.indexOf(el);
            }

            const ariaLabel = el.getAttribute('aria-label') || null;

            const getNearbyText = () => {
                const texts = [];
                let parent = el.parentElement;
                for (let i = 0; i < 3 && parent; i++) {
                    // Direct text nodes of the container carry the visible label on
                    // plenty of forms that never use a <label> element.
                    Array.from(parent.childNodes)
                        .filter(n => n.nodeType === 3)
                        .map(n => n.textContent.trim())
                        .filter(t => t.length > 0 && t.length < 50)
                        .forEach(t => texts.push(t));
                    parent.querySelectorAll(':scope > label, :scope > span, :scope > div > label').forEach(e => {
                        const t = e.textContent.trim();
                        if (t && t.length < 50) texts.push(t);
                    });
                    parent = parent.parentElement;
                }
                let prev = el.previousElementSibling;
                for (let i = 0; i < 2 && prev; i++) {
                    const t = prev.textContent.trim();
                    if (t && t.length < 50) texts.push(t);
                    prev = prev.previousElementSibling;
                }
                return [...new Set(texts)].slice(0, 5);
            };

            const getParentPath = () => {
                const path = [];
                let p = el.parentElement;
                for (let i = 0; i < 3 && p && p !== document.body; i++) {
                    // Drop framework-generated state classes (ng-*, is-*, …) — they
                    // change between runs and poison the breadcrumb match.
                    const classes = Array.from(p.classList || [])
                        .filter(c => c.length > 2 && !/^(ng-|v-|js-|is-|has-)/.test(c))
                        .slice(0, 2);
                    if (classes.length) path.push(classes.join('.'));
                    p = p.parentElement;
                }
                return path;
            };

            const getDataAttributes = () => {
                const dataAttrs = {};
                for (const attr of el.attributes) {
                    if (attr.name.startsWith('data-')) {
                        dataAttrs[attr.name] = attr.value;
                    }
                }
                return dataAttrs;
            };

            // Recognition fallback attributes. The replay-side scorer
            // (js/recognition_scorer.js) reads `stable_attributes` and scores it,
            // and clicks already supply it via element_at_coordinates.js — typed
            // fills were the only steps recording recognition data WITHOUT it, so
            // they re-matched worse than everything else after a page changed.
            const getStableAttributes = () => ({
                'role': el.getAttribute('role'),
                'aria-label': el.getAttribute('aria-label'),
                'aria-describedby': el.getAttribute('aria-describedby'),
                'aria-labelledby': el.getAttribute('aria-labelledby'),
                'inputmode': el.inputMode || null,
                'pattern': el.pattern || null,
                'required': el.required || false,
                'readonly': el.readOnly || false,
                'maxlength': el.maxLength > 0 ? el.maxLength : null,
                'minlength': el.minLength > 0 ? el.minLength : null,
            });

            return {
                selector: getSelector(),
                name: el.name || null,
                id: el.id || null,
                placeholder: placeholder || null,
                label: labelText || null,
                field_type: type || 'text',
                field_category: fieldCategory,
                display_name: displayName,
                is_sensitive: isSensitive,
                autocomplete: el.autocomplete || null,
                recognition: {
                    formIndex: formIndex,
                    fieldIndex: fieldIndex,
                    ariaLabel: ariaLabel,
                    nearbyText: getNearbyText(),
                    parentPath: getParentPath(),
                    tagName: el.tagName.toLowerCase(),
                    dataAttributes: getDataAttributes(),
                    stableAttributes: getStableAttributes(),
                }
            };
        })()"#,
    )
    .await
    {
        Ok(info) => info,
        Err(e) => {
            tracing::debug!(error = %e, "Could not get focused element info");
            None
        }
    };

    // `None` here means the probe found no usable focused element —
    // `document.activeElement` was absent or still `<body>`. The text is typed
    // into the page below either way, but there is nothing to attribute it to, so
    // NO fill step is recorded. That used to happen in complete silence, and it is
    // indistinguishable from the recorder being broken: the characters appear on
    // screen and the step list stays empty.
    //
    // We deliberately do NOT invent a selector to hang the step on — a fill step
    // whose selector does not resolve is worse than none, because it fails at
    // replay instead of at record time, long after the user could have fixed it.
    // Say so loudly instead.
    if field_info.is_none() {
        tracing::warn!(
            session_id = %session.session_id,
            chars = text.chars().count(),
            "Typed text is not being recorded: no focused form field. The keystrokes \
             reached the page, but nothing had focus to attribute them to — click \
             directly into the field in the live view before typing."
        );
    }

    // Type the text into the page
    if let Err(e) = crate::browser::page_actions::keyboard_type(&session.page, text, 0.0).await {
        return ActionResult::err(format!("Keyboard type failed: {}", e));
    }

    // Accumulate typing into pending_fill
    if let Some(ref info) = field_info {
        let current_selector = info
            .get("selector")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        if current_selector.is_empty() {
            return ActionResult::ok();
        }

        let same_field = session
            .pending_fill
            .as_ref()
            .is_some_and(|pf| pf.selector == current_selector);

        if same_field {
            // Append to existing pending fill
            if let Some(ref mut pf) = session.pending_fill {
                pf.value.push_str(text);
            }
        } else {
            // Flush any previous fill and start new one
            super::pending::flush_pending_fill(session).await;

            let display_name = info
                .get("display_name")
                .and_then(|v| v.as_str())
                .or_else(|| info.get("name").and_then(|v| v.as_str()))
                .or_else(|| info.get("placeholder").and_then(|v| v.as_str()))
                .map(String::from);

            let data_key = info
                .get("field_category")
                .and_then(|v| v.as_str())
                .map(String::from);

            let recognition = info.get("recognition").cloned();

            let element_id = info
                .get("id")
                .and_then(|v| v.as_str())
                .map(String::from);

            let element_name = info
                .get("name")
                .and_then(|v| v.as_str())
                .map(String::from);

            let is_sensitive = info
                .get("is_sensitive")
                .and_then(|v| v.as_bool());

            let field_type = info
                .get("field_type")
                .and_then(|v| v.as_str())
                .map(String::from);

            let label = info
                .get("label")
                .and_then(|v| v.as_str())
                .map(String::from);

            let placeholder = info
                .get("placeholder")
                .and_then(|v| v.as_str())
                .map(String::from);

            let autocomplete = info
                .get("autocomplete")
                .and_then(|v| v.as_str())
                .map(String::from);

            let field_category_str = info
                .get("field_category")
                .and_then(|v| v.as_str())
                .map(String::from);

            session.pending_fill = Some(PendingFill {
                selector: current_selector,
                value: text.to_string(),
                field_name: display_name,
                data_key,
                recognition,
                element_id,
                element_name,
                is_sensitive,
                field_type,
                field_category: field_category_str,
                label,
                placeholder,
                autocomplete,
                timestamp: super::step_recording::current_timestamp(),
            });
        }
    }

    ActionResult::ok()
}

async fn handle_press(session: &mut RecordingSession, action: &IncomingAction) -> ActionResult {
    let key = action
        .data
        .get("key")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if key.is_empty() {
        return ActionResult::ok();
    }

    // Flush pending inputs before Tab/Enter/Escape (field change)
    if key == "Tab" || key == "Enter" || key == "Escape" {
        super::pending::flush_all_pending(session).await;
    }

    // Press the key in the browser
    if let Err(e) = crate::browser::page_actions::keyboard_press(&session.page, key).await {
        return ActionResult::err(format!("Keyboard press '{}' failed: {}", key, e));
    }

    // Determine what to record based on context
    match key {
        "ArrowUp" | "ArrowDown" | "ArrowLeft" | "ArrowRight" => {
            // Check if navigating in a dropdown/select context
            let in_dropdown: bool = crate::browser::page_query::evaluate(
                &session.page,
                r#"(() => {
                    const el = document.activeElement;
                    if (!el) return false;
                    const tag = el.tagName.toLowerCase();
                    const role = el.getAttribute('role');
                    if (tag === 'select') return true;
                    if (el.getAttribute('aria-expanded') === 'true') return true;
                    if (document.querySelector('[role="listbox"]:not([hidden])')) return true;
                    return false;
                })()"#,
            )
            .await
            .unwrap_or(false);

            if in_dropdown {
                // Arrow keys in dropdown - track navigation, don't record each press
                session.pending_dropdown_nav = Some(crate::models::session::PendingDropdown {
                    selector: String::new(),
                    dropdown_type: "keyboard_nav".to_string(),
                });
                tracing::debug!("Arrow navigation in dropdown, waiting for selection");
            }
            // Arrow keys outside dropdown context - don't record
        }

        " " | "Space" => {
            // Space might toggle checkboxes, select dropdown items
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Check if it toggled a checkbox/radio
            let check_result: Option<serde_json::Value> = crate::browser::page_query::evaluate(
                &session.page,
                r#"(() => {
                    const el = document.activeElement;
                    if (el && (el.type === 'checkbox' || el.type === 'radio')) {
                        return {
                            checked: el.checked,
                            type: el.type,
                            label: (el.labels && el.labels[0]) ? el.labels[0].textContent.trim() :
                                   el.getAttribute('aria-label') || el.name || el.id || '',
                            selector: el.id ? '#' + el.id : (el.name ? 'input[name="' + el.name + '"]' : 'input')
                        };
                    }
                    return null;
                })()"#,
            )
            .await
            .unwrap_or(None);

            if let Some(ref cr) = check_result {
                let checked = cr.get("checked").and_then(|v| v.as_bool()).unwrap_or(false);
                let label = cr
                    .get("label")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let selector = cr
                    .get("selector")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let step_type = if checked {
                    StepType::Check
                } else {
                    StepType::Uncheck
                };
                let step = RecordedStep {
                    step_type,
                    timestamp: super::step_recording::current_timestamp(),
                    id: uuid::Uuid::new_v4().to_string(),
                    selector: Some(selector.to_string()),
                    url: None,
                    value: None,
                    description: Some(format!(
                        "{} '{}' (keyboard)",
                        if checked { "Check" } else { "Uncheck" },
                        label
                    )),
                    coordinates: None,
                    viewport: None,
                    options: Some({
                        let mut opts = HashMap::new();
                        opts.insert("tag".to_string(), serde_json::json!("input"));
                        opts.insert("via_keyboard".to_string(), serde_json::json!(true));
                        opts
                    }),
                };
                super::step_recording::record_step_with_delay(session, step);
            }
        }

        "Enter" => {
            // Check dropdown/autocomplete context
            let has_dropdown_context = session.pending_dropdown.is_some()
                || session.pending_dropdown_nav.is_some();

            if has_dropdown_context {
                // Try to get selected value from dropdown
                let selected: Option<serde_json::Value> = crate::browser::page_query::evaluate(
                    &session.page,
                    r#"(() => {
                        const el = document.activeElement;
                        if (el && el.tagName.toLowerCase() === 'select') {
                            return { value: el.value, text: el.options[el.selectedIndex] ? el.options[el.selectedIndex].text : el.value };
                        }
                        const highlighted = document.querySelector('[role="listbox"] [aria-selected="true"], [role="option"][aria-selected="true"]');
                        if (highlighted) {
                            return { value: highlighted.getAttribute('data-value') || highlighted.textContent.trim(), text: highlighted.textContent.trim() };
                        }
                        return null;
                    })()"#,
                )
                .await
                .unwrap_or(None);

                if let Some(ref sel) = selected {
                    let value = sel
                        .get("value")
                        .or_else(|| sel.get("text"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let text_val = sel
                        .get("text")
                        .and_then(|v| v.as_str())
                        .unwrap_or(value);

                    let selector = session
                        .pending_dropdown
                        .as_ref()
                        .map(|pd| pd.selector.clone())
                        .unwrap_or_default();

                    let step = RecordedStep {
                        step_type: StepType::Select,
                        timestamp: super::step_recording::current_timestamp(),
                        id: uuid::Uuid::new_v4().to_string(),
                        selector: Some(selector),
                        url: None,
                        value: Some(value.to_string()),
                        description: Some(format!("Select '{}' (keyboard)", text_val)),
                        coordinates: None,
                        viewport: None,
                        options: Some({
                            let mut opts = HashMap::new();
                            opts.insert("via_keyboard".to_string(), serde_json::json!(true));
                            opts
                        }),
                    };
                    super::step_recording::record_step_with_delay(session, step);
                    session.pending_dropdown = None;
                    session.pending_dropdown_nav = None;
                } else {
                    // No dropdown selection - record as regular Enter press
                    record_press_step(session, key);
                }
            } else {
                // Regular Enter press (form submission, etc.)
                record_press_step(session, key);
            }
        }

        "Tab" => {
            // Record Tab only if not consecutive with previous Tab
            let should_record = session
                .steps
                .last()
                .is_none_or(|last| {
                    !(last.step_type == StepType::Press
                        && last.value.as_deref() == Some("Tab"))
                });
            if should_record {
                record_press_step(session, key);
            }
        }

        "Escape" => {
            // Clear dropdown state, record press
            session.pending_dropdown = None;
            session.pending_dropdown_nav = None;
            record_press_step(session, key);
        }

        "Backspace" | "Delete" => {
            // Modifies text - handled by fill accumulation
            if let Some(ref mut pf) = session.pending_fill {
                if !pf.value.is_empty() {
                    pf.value.pop();
                }
            }
        }

        _ => {
            // Other keys - don't record individually
        }
    }

    ActionResult::ok()
}

fn record_press_step(session: &mut RecordingSession, key: &str) {
    let step = RecordedStep {
        step_type: StepType::Press,
        timestamp: super::step_recording::current_timestamp(),
        id: uuid::Uuid::new_v4().to_string(),
        selector: None,
        url: None,
        value: Some(key.to_string()),
        description: Some(format!("Press {}", key)),
        coordinates: None,
        viewport: None,
        options: None,
    };
    super::step_recording::record_step_with_delay(session, step);
}

async fn handle_scroll(session: &mut RecordingSession, action: &IncomingAction) -> ActionResult {
    let delta_x = action.data.get("deltaX").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let delta_y = action.data.get("deltaY").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let mouse_x = action.data.get("x").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let mouse_y = action.data.get("y").and_then(|v| v.as_f64()).unwrap_or(0.0);

    // Detect scrollable container at mouse position
    let scroll_context: Option<serde_json::Value> = {
        let js = format!(
            r#"(() => {{
                const el = document.elementFromPoint({}, {});
                if (!el) return null;

                let scrollable = null;
                let current = el;
                while (current && current !== document.body && current !== document.documentElement) {{
                    const tag = current.tagName.toLowerCase();
                    if (tag === 'textarea' && current.scrollHeight > current.clientHeight) {{
                        scrollable = current;
                        break;
                    }}
                    const style = window.getComputedStyle(current);
                    const overflowY = style.overflowY;
                    if ((overflowY === 'scroll' || overflowY === 'auto' || overflowY === 'overlay') &&
                        current.scrollHeight > current.clientHeight) {{
                        scrollable = current;
                        break;
                    }}
                    current = current.parentElement;
                }}
                if (!scrollable) return null;

                const getSelector = (e) => e.id ? '#' + e.id : (e.name ? e.tagName.toLowerCase() + '[name="' + e.name + '"]' : e.tagName.toLowerCase());
                return {{
                    selector: getSelector(scrollable),
                    tag: scrollable.tagName.toLowerCase(),
                    isAtBottom: scrollable.scrollTop + scrollable.clientHeight >= scrollable.scrollHeight - 10,
                }};
            }})()"#,
            mouse_x, mouse_y,
        );
        crate::browser::page_query::evaluate(&session.page, &js)
            .await
            .unwrap_or(None)
    };

    // Perform the scroll
    if let Err(e) = crate::browser::page_actions::mouse_wheel(&session.page, delta_x, delta_y).await
    {
        return ActionResult::err(format!("Mouse wheel failed: {}", e));
    }

    // Report the resulting window scroll so the frontend can stamp visual zones
    // with the scroll offset they were drawn at. Visual monitors re-scroll to that
    // position at check time; without it a zone drawn below the fold clips the
    // wrong pixels (the top-of-page region at the same viewport offset). Best-
    // effort — a failed read just leaves the frontend at its last known scroll.
    if let Ok(pos) = crate::browser::page_query::evaluate::<serde_json::Value>(
        &session.page,
        "() => ({ x: Math.round(window.scrollX), y: Math.round(window.scrollY) })",
    )
    .await
    {
        session.send_event(serde_json::json!({
            "type": "scroll_position",
            "scrollX": pos.get("x").and_then(|v| v.as_f64()).unwrap_or(0.0),
            "scrollY": pos.get("y").and_then(|v| v.as_f64()).unwrap_or(0.0),
        }));
    }

    let current_container = scroll_context
        .as_ref()
        .and_then(|sc| sc.get("selector").and_then(|v| v.as_str()))
        .map(String::from);

    let is_at_bottom = scroll_context
        .as_ref()
        .and_then(|sc| sc.get("isAtBottom").and_then(|v| v.as_bool()))
        .unwrap_or(false);

    // Check if scrolling a different container than before - flush previous
    let container_changed = session.pending_scroll.as_ref().is_some_and(|ps| {
        ps.container_selector != current_container
    });
    if container_changed {
        super::pending::flush_pending_scroll(session).await;
    }

    // Accumulate scroll
    if let Some(ref mut ps) = session.pending_scroll {
        ps.total_delta_y += delta_y;
    } else {
        session.pending_scroll = Some(PendingScroll {
            total_delta_y: delta_y,
            container_selector: current_container.clone(),
            x: mouse_x,
            y: mouse_y,
            start_time: super::step_recording::current_timestamp(),
        });
    }

    // Flush immediately if user reached bottom of a container scroll
    if is_at_bottom && current_container.is_some() {
        super::pending::flush_pending_scroll(session).await;
        tracing::info!("Recording scroll-to-bottom");
    }

    ActionResult::ok()
}

async fn handle_navigate(
    session: &mut RecordingSession,
    action: &IncomingAction,
) -> ActionResult {
    let url = action
        .data
        .get("url")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if url.is_empty() {
        return ActionResult::err("No URL provided for navigate action");
    }

    // Guard against SSRF
    if !crate::security::url_guard::is_url_safe(url) {
        return ActionResult::err(format!("URL blocked by security policy: {}", url));
    }

    // Navigate with domcontentloaded and 30s timeout
    if let Err(e) = crate::browser::navigation::goto(
        &session.page,
        url,
        "domcontentloaded",
        Duration::from_secs(30),
    )
    .await
    {
        return ActionResult::err(format!("Navigation failed: {}", e));
    }

    session.current_url = url.to_string();

    // Record navigate step
    let step = RecordedStep {
        step_type: StepType::Navigate,
        timestamp: super::step_recording::current_timestamp(),
        id: uuid::Uuid::new_v4().to_string(),
        selector: None,
        url: Some(url.to_string()),
        value: None,
        description: Some(format!("Navigate to {}", url)),
        coordinates: None,
        viewport: None,
        options: None,
    };
    super::step_recording::record_step_with_delay(session, step);

    ActionResult::ok()
}

/// Browser back/forward — history navigation from the recorder's controls. Mirrors the Python
/// recorder (`recorder.py`): perform the history move, then RECORD it as a `navigate` to the
/// resulting URL (only if the URL changed) so a monitor's setup steps reproduce the page the user
/// reached — the engine replays `navigate` reliably, whereas a literal back/forward step would not.
/// A history move that had nowhere to go is reported to the user rather than
/// swallowed — an unexplained no-op reads as a dead button.
async fn handle_back(session: &mut RecordingSession) -> ActionResult {
    let prev_url = session.page.url();
    match crate::browser::navigation::go_back(&session.page, Duration::from_secs(30)).await {
        Err(e) => return ActionResult::err(format!("Go back failed: {}", e)),
        Ok(false) => return ActionResult::err("Nothing to go back to — this is the first page of the session"),
        Ok(true) => {}
    }
    record_history_nav(session, &prev_url, "Back");
    ActionResult::ok_with_data(serde_json::json!({ "url": session.current_url }))
}

async fn handle_forward(session: &mut RecordingSession) -> ActionResult {
    let prev_url = session.page.url();
    match crate::browser::navigation::go_forward(&session.page, Duration::from_secs(30)).await {
        Err(e) => return ActionResult::err(format!("Go forward failed: {}", e)),
        Ok(false) => return ActionResult::err("Nothing to go forward to"),
        Ok(true) => {}
    }
    record_history_nav(session, &prev_url, "Forward");
    ActionResult::ok_with_data(serde_json::json!({ "url": session.current_url }))
}

/// Reload — drive the live page; not recorded as a step (it returns to the SAME url, which the
/// existing navigate steps already reach). The frontend's Reload button sends a `navigate` to the
/// current URL anyway; this handler is the explicit-action fallback.
async fn handle_reload(session: &mut RecordingSession) -> ActionResult {
    if let Err(e) = crate::browser::navigation::reload(&session.page, Duration::from_secs(30)).await {
        return ActionResult::err(format!("Reload failed: {}", e));
    }
    session.current_url = session.page.url();
    ActionResult::ok_with_data(serde_json::json!({ "url": session.current_url }))
}

/// Update `current_url` after a history move and, when the URL changed, record a `navigate` step to
/// the destination (so setup-steps replay reaches the same page).
fn record_history_nav(session: &mut RecordingSession, prev_url: &str, label: &str) {
    let new_url = session.page.url();
    session.current_url = new_url.clone();
    if new_url != prev_url {
        let step = RecordedStep {
            step_type: StepType::Navigate,
            timestamp: super::step_recording::current_timestamp(),
            id: uuid::Uuid::new_v4().to_string(),
            selector: None,
            url: Some(new_url.clone()),
            value: None,
            description: Some(format!("{label} to {new_url}")),
            coordinates: None,
            viewport: None,
            options: None,
        };
        super::step_recording::record_step_with_delay(session, step);
    }
}

async fn handle_wait(_session: &mut RecordingSession, action: &IncomingAction) -> ActionResult {
    let duration_ms = action
        .data
        .get("duration")
        .and_then(|v| v.as_f64())
        .unwrap_or(1000.0);

    tokio::time::sleep(Duration::from_millis(duration_ms as u64)).await;
    ActionResult::ok()
}

async fn handle_evaluate_js(
    session: &mut RecordingSession,
    action: &IncomingAction,
) -> ActionResult {
    let script = action
        .data
        .get("script")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if script.is_empty() {
        return ActionResult::ok_with_data(serde_json::json!({
            "eval_result": null,
            "error": "No script provided"
        }));
    }

    // Run with 10s timeout
    match tokio::time::timeout(
        Duration::from_secs(10),
        crate::browser::page_query::evaluate_value(&session.page, script),
    )
    .await
    {
        Ok(Ok(result)) => ActionResult::ok_with_data(serde_json::json!({
            "eval_result": result
        })),
        Ok(Err(e)) => {
            let error_msg = e.to_string();
            ActionResult::ok_with_data(serde_json::json!({
                "eval_result": null,
                "error": error_msg
            }))
        }
        Err(_) => ActionResult::ok_with_data(serde_json::json!({
            "eval_result": null,
            "error": "Script timed out (10s)"
        })),
    }
}

/// Element-picker JS, vendored in-crate under `js/` so the crate is self-contained and buildable in
/// isolation — the same approach `bridge/otp_entry.rs` uses for the OTP scripts. Do NOT repoint this
/// to an out-of-crate path: an out-of-crate `include_str!` breaks the standalone build.
/// Takes {mode, x, y, w, h}; "point" returns the element info at the coordinates, "region" returns
/// {elements: [...]}.
const ELEMENT_PICKER_JS: &str = include_str!("../../js/element_picker.js");

/// Live element picker (check wizard): read-only inspection of the element at
/// viewport coordinates. Mirrors Python recorder.py `get_element_info`.
async fn handle_get_element_info(
    session: &mut RecordingSession,
    action: &IncomingAction,
) -> ActionResult {
    let x = action.data.get("x").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let y = action.data.get("y").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let args = serde_json::json!({"mode": "point", "x": x, "y": y});
    match tokio::time::timeout(
        Duration::from_secs(5),
        crate::browser::page_query::evaluate_with_args::<Option<serde_json::Value>>(
            &session.page,
            ELEMENT_PICKER_JS,
            args,
        ),
    )
    .await
    {
        // None = click landed on empty page chrome — not an error.
        Ok(Ok(info)) => ActionResult::ok_with_data(serde_json::json!({"element_info": info})),
        Ok(Err(e)) => ActionResult::ok_with_data(serde_json::json!({
            "element_info": null,
            "error": format!("Element inspection failed: {}", e),
        })),
        Err(_) => ActionResult::ok_with_data(serde_json::json!({
            "element_info": null,
            "error": "Element inspection timed out",
        })),
    }
}

/// Live element picker, area mode: all top-level visible elements fully inside
/// the dragged viewport rect. Mirrors Python `get_elements_in_region`.
async fn handle_get_elements_in_region(
    session: &mut RecordingSession,
    action: &IncomingAction,
) -> ActionResult {
    let num = |k: &str| action.data.get(k).and_then(|v| v.as_f64());
    let args = serde_json::json!({
        "mode": "region",
        "x": num("x").unwrap_or(0.0),
        "y": num("y").unwrap_or(0.0),
        "w": num("width").or_else(|| num("w")).unwrap_or(0.0),
        "h": num("height").or_else(|| num("h")).unwrap_or(0.0),
    });
    match tokio::time::timeout(
        Duration::from_secs(8),
        crate::browser::page_query::evaluate_with_args::<Option<serde_json::Value>>(
            &session.page,
            ELEMENT_PICKER_JS,
            args,
        ),
    )
    .await
    {
        Ok(Ok(result)) => {
            let elements = result
                .and_then(|v| v.get("elements").cloned())
                .unwrap_or_else(|| serde_json::json!([]));
            ActionResult::ok_with_data(serde_json::json!({"elements_in_region": elements}))
        }
        Ok(Err(e)) => ActionResult::ok_with_data(serde_json::json!({
            "elements_in_region": [],
            "error": format!("Region scan failed: {}", e),
        })),
        Err(_) => ActionResult::ok_with_data(serde_json::json!({
            "elements_in_region": [],
            "error": "Region scan timed out",
        })),
    }
}

/// Read-only DOM snapshot — powers the wizard's AI selector finder.
/// Mirrors Python `get_dom` (capped at 600 KB).
async fn handle_get_dom(session: &mut RecordingSession) -> ActionResult {
    match tokio::time::timeout(
        Duration::from_secs(8),
        crate::browser::page_query::evaluate::<Option<String>>(
            &session.page,
            "() => document.documentElement ? document.documentElement.outerHTML : ''",
        ),
    )
    .await
    {
        Ok(Ok(html)) => {
            let mut html = html.unwrap_or_default();
            if html.len() > 600_000 {
                let mut end = 600_000;
                while !html.is_char_boundary(end) {
                    end -= 1;
                }
                html.truncate(end);
            }
            ActionResult::ok_with_data(serde_json::json!({"dom_content": html}))
        }
        Ok(Err(e)) => ActionResult::ok_with_data(serde_json::json!({
            "dom_content": null,
            "error": format!("DOM extraction failed: {}", e),
        })),
        Err(_) => ActionResult::ok_with_data(serde_json::json!({
            "dom_content": null,
            "error": "DOM extraction timed out",
        })),
    }
}

async fn handle_select_option(
    session: &mut RecordingSession,
    action: &IncomingAction,
) -> ActionResult {
    let selector = action
        .data
        .get("selector")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let value = action
        .data
        .get("value")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let text = action
        .data
        .get("text")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if selector.is_empty() {
        return ActionResult::err("No selector provided for select_option");
    }

    let select_value = if !value.is_empty() { value } else { text };

    // Perform the select via Playwright
    if let Err(e) =
        crate::browser::page_actions::select_option(&session.page, selector, select_value).await
    {
        return ActionResult::err(format!("Failed to select option: {}", e));
    }

    // Get recognition data from pending dropdown if available
    let pending_name = session
        .pending_dropdown
        .as_ref()
        .map(|pd| pd.dropdown_type.clone())
        .unwrap_or_else(|| "dropdown".to_string());

    // Record select step
    let step = RecordedStep {
        step_type: StepType::Select,
        timestamp: super::step_recording::current_timestamp(),
        id: uuid::Uuid::new_v4().to_string(),
        selector: Some(selector.to_string()),
        url: None,
        value: Some(select_value.to_string()),
        description: Some(format!(
            "Select '{}' in {}",
            if !text.is_empty() { text } else { value },
            pending_name
        )),
        coordinates: None,
        viewport: None,
        options: Some({
            let mut opts = HashMap::new();
            opts.insert("tag".to_string(), serde_json::json!("select"));
            if !text.is_empty() {
                opts.insert(
                    "optionText".to_string(),
                    serde_json::json!(text),
                );
            }
            if !value.is_empty() {
                opts.insert(
                    "optionValue".to_string(),
                    serde_json::json!(value),
                );
            }
            opts
        }),
    };
    super::step_recording::record_step_with_delay(session, step);

    // Clear pending dropdown
    session.pending_dropdown = None;

    tracing::debug!(selector, value = select_value, "Selected option");
    ActionResult::ok()
}

async fn handle_set_picker_value(
    session: &mut RecordingSession,
    action: &IncomingAction,
) -> ActionResult {
    let selector = action
        .data
        .get("selector")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let value = action
        .data
        .get("value")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let picker_type = action
        .data
        .get("pickerType")
        .and_then(|v| v.as_str())
        .unwrap_or("text");

    if selector.is_empty() || value.is_empty() {
        return ActionResult::err("Selector and value required for set_picker_value");
    }

    // Set the value via JavaScript (trigger input + change events).
    // SECURITY: BOTH the selector and the value are evaluate ARGUMENTS. The value
    // already was; the selector used to be interpolated into the JS source with
    // `replace('\'', "\\'")`, which never escapes pre-existing backslashes — so a
    // selector containing `\'` closed the literal and the remainder ran as code
    // (see helpers::eval_selector_probe).
    let js = r#"(([sel, value]) => {
            let input = null;
            try { input = document.querySelector(sel); } catch (e) { return false; }
            if (input) {
                input.value = value;
                input.dispatchEvent(new Event('input', { bubbles: true }));
                input.dispatchEvent(new Event('change', { bubbles: true }));
                return true;
            }
            return false;
        })"#;

    let args = serde_json::json!([selector, value]);
    match crate::browser::page_query::evaluate_with_args::<bool>(&session.page, js, args).await {
        Ok(true) => {}
        Ok(false) => {
            return ActionResult::err(format!("Element not found: {}", selector));
        }
        Err(e) => {
            return ActionResult::err(format!("Failed to set picker value: {}", e));
        }
    }

    // Record fill step
    let step = RecordedStep {
        step_type: StepType::Fill,
        timestamp: super::step_recording::current_timestamp(),
        id: uuid::Uuid::new_v4().to_string(),
        selector: Some(selector.to_string()),
        url: None,
        value: Some(value.to_string()),
        description: Some(format!("Set {} to '{}'", picker_type, value)),
        coordinates: None,
        viewport: None,
        options: Some({
            let mut opts = HashMap::new();
            opts.insert("tag".to_string(), serde_json::json!("input"));
            opts.insert(
                "input_type".to_string(),
                serde_json::json!(picker_type),
            );
            opts
        }),
    };
    super::step_recording::record_step_with_delay(session, step);

    // Clear pending picker
    session.pending_picker = None;

    tracing::debug!(selector, value, picker_type, "Set picker value");
    ActionResult::ok()
}

async fn handle_switch_tab(
    session: &mut RecordingSession,
    action: &IncomingAction,
) -> ActionResult {
    let tab_index = match action.data.get("tab_index").and_then(|v| v.as_u64()) {
        Some(idx) => idx as usize,
        None => return ActionResult::err("tab_index required"),
    };

    let pages = session.context.pages();

    if tab_index >= pages.len() {
        return ActionResult::err(format!(
            "tab_index {} out of range (0-{})",
            tab_index,
            pages.len().saturating_sub(1)
        ));
    }

    let target = &pages[tab_index];

    // Bring target tab to front
    if let Err(e) = target.bring_to_front().await {
        return ActionResult::err(format!("Failed to bring tab to front: {}", e));
    }

    // Update session page reference
    let target_url = target.url();
    session.current_url = target_url.clone();

    // Record switch tab step
    let step = RecordedStep {
        step_type: StepType::WaitForTab,
        timestamp: super::step_recording::current_timestamp(),
        id: uuid::Uuid::new_v4().to_string(),
        selector: None,
        url: Some(target_url),
        value: None,
        description: Some(format!("Switch to tab {}", tab_index)),
        coordinates: None,
        viewport: None,
        options: Some({
            let mut opts = HashMap::new();
            opts.insert("tab_index".to_string(), serde_json::json!(tab_index));
            opts
        }),
    };
    super::step_recording::record_step_with_delay(session, step);

    ActionResult::ok()
}

async fn handle_close_tab(
    session: &mut RecordingSession,
    action: &IncomingAction,
) -> ActionResult {
    let pages = session.context.pages();

    if pages.len() <= 1 {
        return ActionResult::err("Cannot close the only tab");
    }

    let tab_index = action
        .data
        .get("tab_index")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize);

    let target_index = if let Some(idx) = tab_index {
        if idx < pages.len() {
            idx
        } else {
            return ActionResult::err(format!("tab_index {} out of range", idx));
        }
    } else {
        // Close current page - find its index
        0
    };

    // Close the target page
    if let Err(e) = pages[target_index].close().await {
        return ActionResult::err(format!("Failed to close tab: {}", e));
    }

    // Switch to remaining tab
    let remaining = session.context.pages();

    if let Some(last_page) = remaining.last() {
        if let Err(e) = last_page.bring_to_front().await {
            tracing::warn!(error = %e, "Failed to bring remaining tab to front");
        }
        session.current_url = last_page.url();
    }

    // Record tab closed step
    let step = RecordedStep {
        step_type: StepType::TabClosed,
        timestamp: super::step_recording::current_timestamp(),
        id: uuid::Uuid::new_v4().to_string(),
        selector: None,
        url: Some(session.current_url.clone()),
        value: None,
        description: Some("Close tab and return".to_string()),
        coordinates: None,
        viewport: None,
        options: None,
    };
    super::step_recording::record_step_with_delay(session, step);

    ActionResult::ok()
}

/// Record a `wait_for_change` step from the recorder UI. This does NOT watch live —
/// the surveil/poll happens at replay time in `step_change::execute_wait_for_change`.
/// Recording is a cheap synchronous step-append (no long `.await`), so it is safe under
/// the action-branch DashMap RefMut without risking tokio-worker starvation.
async fn handle_add_wait_for_change_step(
    session: &mut RecordingSession,
    action: &IncomingAction,
) -> ActionResult {
    let d = &action.data;
    let get_str = |k: &str| d.get(k).and_then(|v| v.as_str()).map(String::from);

    let region = d.get("region").cloned().filter(|v| v.is_object());
    let selector = get_str("selector");
    let watch_kind = get_str("watch_kind").unwrap_or_else(|| {
        if region.is_some() {
            "region".into()
        } else {
            "selector".into()
        }
    });

    if watch_kind == "selector" && selector.as_deref().unwrap_or("").is_empty() {
        return ActionResult::err("wait_for_change: selector required for selector watch");
    }
    if watch_kind == "region" && region.is_none() {
        return ActionResult::err("wait_for_change: region required for region watch");
    }

    let change_kind = get_str("change_kind").unwrap_or_else(|| {
        if watch_kind == "region" {
            "visual".into()
        } else {
            "text".into()
        }
    });
    let output_name = get_str("output_name")
        .or_else(|| get_str("variable"))
        .unwrap_or_else(|| "change".into());
    let baseline_mode = get_str("baseline_mode").unwrap_or_else(|| "in_run".into());

    let mut opts: HashMap<String, serde_json::Value> = HashMap::new();
    opts.insert("watch_kind".into(), serde_json::json!(watch_kind));
    opts.insert("change_kind".into(), serde_json::json!(change_kind));
    opts.insert("output_name".into(), serde_json::json!(output_name));
    // `variable` mirrors the extract convention so downstream merge keys line up.
    opts.insert("variable".into(), serde_json::json!(output_name));
    opts.insert("baseline_mode".into(), serde_json::json!(baseline_mode));
    if let Some(r) = &region {
        opts.insert("region".into(), r.clone());
    }
    for key in ["attribute", "ignore_regex", "on_no_change"] {
        if let Some(v) = get_str(key) {
            if !v.is_empty() {
                opts.insert(key.into(), serde_json::json!(v));
            }
        }
    }
    for key in ["timeout_ms", "poll_interval_ms"] {
        if let Some(n) = d.get(key).and_then(|v| v.as_u64().or_else(|| v.as_f64().map(|f| f as u64))) {
            opts.insert(key.into(), serde_json::json!(n));
        }
    }

    let desc = if watch_kind == "region" {
        format!("Wait for change in region → {}", output_name)
    } else {
        format!(
            "Wait for change in '{}' ({}) → {}",
            selector.as_deref().unwrap_or(""),
            change_kind,
            output_name
        )
    };

    let step = RecordedStep {
        step_type: StepType::WaitForChange,
        timestamp: super::step_recording::current_timestamp(),
        id: uuid::Uuid::new_v4().to_string(),
        selector,
        url: None,
        value: None,
        description: Some(desc),
        coordinates: None,
        viewport: None,
        options: Some(opts),
    };
    super::step_recording::record_step_with_delay(session, step);

    ActionResult::ok()
}

// ---------------------------------------------------------------------------
// Extraction lane
// ---------------------------------------------------------------------------
// The recorder's "Extract" mode: hover to highlight the element under the cursor,
// click to inspect it (`get_element_info`), confirm to record an `extract` step,
// and optionally run that extraction live to see what it would yield.
//
// The UI has always sent these four frames; no agent implemented them, so they
// hit the `Unknown action type` arm and came back as `error` frames — a red toast
// per hover sample, and an "Add Step" button that recorded nothing.

/// The attribute an `extract_type: "attribute"` step reads when the UI didn't name
/// one. The picker offers the type without an attribute field, so fall back to the
/// attribute that actually carries the value for that tag.
pub fn default_extract_attribute(tag: &str) -> &'static str {
    match tag.to_lowercase().as_str() {
        "a" | "area" | "link" => "href",
        "img" | "script" | "iframe" | "source" | "audio" | "video" | "embed" => "src",
        "input" | "option" | "param" => "value",
        "meta" => "content",
        "time" => "datetime",
        "form" => "action",
        _ => "title",
    }
}

/// `highlight_element {x, y}` — the element under the cursor, as a `highlight` frame
/// the UI draws as an overlay box over the screencast. Rect is in CSS-viewport
/// pixels, the same space the incoming x/y are in.
///
/// This runs on every throttled mouse sample, so it must stay cheap and must never
/// surface an error: a transient failure (mid-navigation teardown) just clears the
/// box rather than raising a toast the user cannot act on.
async fn handle_highlight_element(
    session: &mut RecordingSession,
    action: &IncomingAction,
) -> ActionResult {
    let x = action.data.get("x").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let y = action.data.get("y").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let args = serde_json::json!({"mode": "point", "x": x, "y": y});
    // Short deadline on purpose. The record driver handles frames SERIALLY, so a
    // probe that blocks on a busy page's JS thread also delays the click behind it
    // — and a highlight the user waited a second for is stale anyway, since the
    // cursor has already moved. `get_element_info` (click-driven, rare) can afford
    // its 5s; a 10-per-second hover stream cannot.
    let info = match tokio::time::timeout(
        Duration::from_millis(750),
        crate::browser::page_query::evaluate_with_args::<Option<serde_json::Value>>(
            &session.page,
            ELEMENT_PICKER_JS,
            args,
        ),
    )
    .await
    {
        Ok(Ok(Some(info))) => info,
        // Empty page chrome, a probe failure, or a timeout — all mean "nothing to
        // highlight right now". A frame with no `rect` clears the UI's overlay.
        _ => return ActionResult::ok_with_data(serde_json::json!({"type": "highlight"})),
    };

    ActionResult::ok_with_data(serde_json::json!({
        "type": "highlight",
        "rect": info.get("rect").cloned().unwrap_or(serde_json::Value::Null),
        "selector": info.get("selector").cloned().unwrap_or(serde_json::Value::Null),
    }))
}

/// `clear_highlight` — drop the overlay (the user left extraction mode or moved off
/// the canvas). The box is drawn by the UI, not injected into the page, so this is
/// just the "no rect" frame; it exists so the UI's own teardown frame isn't an error.
async fn handle_clear_highlight() -> ActionResult {
    ActionResult::ok_with_data(serde_json::json!({"type": "highlight"}))
}

/// Build the recorded `options` for an extract step from the UI's payload. Shared by
/// `add_extract_step` and `test_extract` so a test runs EXACTLY the step that gets
/// recorded.
///
/// `variable` mirrors `output_name` because replay reads `variable`
/// (`automation::step_eval::execute_extract`) while the UI shows `output_name`.
fn extract_step_options(action: &IncomingAction) -> HashMap<String, serde_json::Value> {
    let d = &action.data;
    let get_str = |k: &str| d.get(k).and_then(|v| v.as_str()).unwrap_or("");

    let output_name = {
        let n = get_str("output_name");
        if n.is_empty() { "extracted_data" } else { n }
    };
    let extract_type = {
        let t = get_str("extract_type");
        if t.is_empty() { "text" } else { t }
    };

    let mut opts: HashMap<String, serde_json::Value> = HashMap::new();
    opts.insert("output_name".into(), serde_json::json!(output_name));
    opts.insert("variable".into(), serde_json::json!(output_name));
    opts.insert("extract_type".into(), serde_json::json!(extract_type));

    if extract_type == "attribute" {
        let attr = get_str("attribute");
        let attr = if attr.is_empty() {
            // The picker's tag, when it sent one, decides the sensible default.
            default_extract_attribute(get_str("tag")).to_string()
        } else {
            attr.to_string()
        };
        opts.insert("attribute".into(), serde_json::json!(attr));
    }
    if let Some(script) = d.get("script").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
        opts.insert("script".into(), serde_json::json!(script));
    }
    opts
}

/// A `WorkflowStepConfig` equivalent to the recorded extract step, so a live test
/// goes through the REAL replay executor rather than a second implementation that
/// could drift from it.
fn extract_step_config(
    selector: &str,
    opts: &HashMap<String, serde_json::Value>,
) -> crate::models::workflow::WorkflowStepConfig {
    let mut config = crate::models::workflow::WorkflowStepConfig {
        selector: Some(selector.to_string()),
        script: opts.get("script").and_then(|v| v.as_str()).map(String::from),
        ..Default::default()
    };
    // `extra` is the flattened catch-all the executor reads (`variable`,
    // `extract_type`, `attribute`, …).
    for (k, v) in opts {
        config.extra.insert(k.clone(), v.clone());
    }
    config
}

/// `add_extract_step` — record an `extract` step for the element the user confirmed
/// in the picker popover. The recorded step is what replay runs, so its options are
/// built by the shared `extract_step_options`.
async fn handle_add_extract_step(
    session: &mut RecordingSession,
    action: &IncomingAction,
) -> ActionResult {
    let d = &action.data;
    let selector = d.get("selector").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let extract_type = d
        .get("extract_type")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("text");

    // A `computed` extract carries its own script and needs no selector; every other
    // type reads a DOM element, so a missing selector could only ever fail at replay.
    let has_script = d
        .get("script")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.is_empty());
    if extract_type == "computed" && !has_script {
        // Replay falls back to a plain text extract when a computed step has no
        // script — it would "succeed" while extracting something else entirely.
        // Refuse it here instead, where the user can still fix it.
        return ActionResult::err("add_extract_step: a custom-script extract needs a script");
    }
    if selector.is_empty() && !(extract_type == "computed" && has_script) {
        return ActionResult::err("add_extract_step: selector required");
    }

    let opts = extract_step_options(action);
    let output_name = opts
        .get("output_name")
        .and_then(|v| v.as_str())
        .unwrap_or("extracted_data")
        .to_string();

    let desc = d
        .get("description")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(|| format!("Extract {extract_type} → {output_name}"));

    let step = RecordedStep {
        step_type: StepType::Extract,
        timestamp: super::step_recording::current_timestamp(),
        id: uuid::Uuid::new_v4().to_string(),
        selector: if selector.is_empty() { None } else { Some(selector) },
        url: None,
        value: None,
        description: Some(desc),
        coordinates: None,
        viewport: None,
        options: Some(opts),
    };
    super::step_recording::record_step_with_delay(session, step);

    ActionResult::ok()
}

/// `test_extract` — run an extraction against the LIVE page and return what it
/// yields, so the user can check a selector before trusting it in a run. Goes
/// through the same executor as replay; nothing is recorded.
async fn handle_test_extract(
    session: &mut RecordingSession,
    action: &IncomingAction,
) -> ActionResult {
    let selector = action
        .data
        .get("selector")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let opts = extract_step_options(action);
    let output_name = opts
        .get("output_name")
        .and_then(|v| v.as_str())
        .unwrap_or("extracted_data")
        .to_string();
    let config = extract_step_config(&selector, &opts);

    let outcome = tokio::time::timeout(
        Duration::from_secs(15),
        crate::automation::step_eval::execute_extract(&session.page, &config),
    )
    .await;

    let (value, error) = match outcome {
        Ok(Ok(Some(map))) => (
            map.get(&output_name).cloned().unwrap_or(serde_json::Value::Null),
            None,
        ),
        Ok(Ok(None)) => (serde_json::Value::Null, None),
        Ok(Err(e)) => (serde_json::Value::Null, Some(e.to_string())),
        Err(_) => (serde_json::Value::Null, Some("Extraction timed out".to_string())),
    };

    ActionResult::ok_with_data(serde_json::json!({
        "type": "extract_test_result",
        "selector": selector,
        "output_name": output_name,
        "extract_type": opts.get("extract_type").cloned().unwrap_or(serde_json::Value::Null),
        "success": error.is_none(),
        "value": value,
        "error": error,
    }))
}

async fn handle_test_streaming_script(
    _session: &mut RecordingSession,
    _action: &IncomingAction,
) -> ActionResult {
    // Expose Playwright bridge functions, run script in eval harness
    // This is a complex feature that will be ported in a future iteration
    ActionResult::ok()
}

#[cfg(test)]
mod extraction_tests {
    use super::*;
    use serde_json::json;

    fn action(data: serde_json::Value) -> IncomingAction {
        serde_json::from_value(data).expect("action frame")
    }

    /// The field probe that runs before a keystroke burst must resolve the selector
    /// the SAME way the rest of the recorder does — through the injected helper,
    /// which verifies uniqueness. Its local fallback checks nothing, so on a page
    /// carrying two `input[name="s"]` (a WordPress header/body search pair) it hands
    /// back a selector matching both: the flush then reads the value off the wrong
    /// twin, and replay types into it. Clicks were never affected — they resolve via
    /// element_at_coordinates.js, which does check uniqueness.
    #[test]
    fn the_typing_probe_prefers_the_uniqueness_checked_selector() {
        let src = include_str!("action_handler.rs");
        let probe = src
            .split("async fn handle_type(")
            .nth(1)
            .and_then(|s| s.split("async fn handle_press(").next())
            .expect("handle_type body");
        assert!(
            probe.contains("window.__psRecorder.getSelector(el)"),
            "handle_type must prefer __psRecorder.getSelector over its raw fallback"
        );
        assert!(
            probe.contains("getFallbackSelector"),
            "the fallback must survive for pages where the helper failed to inject"
        );
        // The replay-side scorer reads `stable_attributes`; a fill recorded without
        // it re-matches worse than every other step type after the page changes.
        assert!(
            probe.contains("stableAttributes: getStableAttributes()"),
            "typed fills must carry stableAttributes in their recognition metadata"
        );
    }

    #[test]
    fn passthrough_covers_the_extraction_frames() {
        // These two are the reason the allowlist is shared: a frame the agent emits
        // but neither transport forwards is invisible, with nothing in any log.
        assert!(is_passthrough_frame("highlight"));
        assert!(is_passthrough_frame("extract_test_result"));
        // Pre-existing overlays must keep working.
        assert!(is_passthrough_frame("select_options"));
        assert!(is_passthrough_frame("native_picker"));
        // A step/event frame is NOT an overlay — it has its own emit path.
        assert!(!is_passthrough_frame("step_recorded"));
    }

    #[test]
    fn attribute_default_follows_the_tag() {
        assert_eq!(default_extract_attribute("a"), "href");
        assert_eq!(default_extract_attribute("A"), "href");
        assert_eq!(default_extract_attribute("img"), "src");
        assert_eq!(default_extract_attribute("input"), "value");
        assert_eq!(default_extract_attribute("meta"), "content");
        assert_eq!(default_extract_attribute("div"), "title");
    }

    #[test]
    fn options_mirror_output_name_into_variable() {
        // Replay reads `variable`; the UI shows `output_name`. A step that set only
        // one of them extracts into the wrong key.
        let opts = extract_step_options(&action(json!({
            "type": "action", "action": "add_extract_step",
            "selector": "h1", "output_name": "title", "extract_type": "text",
        })));
        assert_eq!(opts["output_name"], json!("title"));
        assert_eq!(opts["variable"], json!("title"));
        assert_eq!(opts["extract_type"], json!("text"));
        assert!(!opts.contains_key("attribute"));
    }

    #[test]
    fn options_default_a_blank_output_name_and_type() {
        let opts = extract_step_options(&action(json!({
            "type": "action", "action": "add_extract_step",
            "selector": "h1", "output_name": "", "extract_type": "",
        })));
        assert_eq!(opts["output_name"], json!("extracted_data"));
        assert_eq!(opts["variable"], json!("extracted_data"));
        assert_eq!(opts["extract_type"], json!("text"));
    }

    #[test]
    fn attribute_extract_resolves_from_the_tag_when_unnamed() {
        let opts = extract_step_options(&action(json!({
            "type": "action", "action": "add_extract_step",
            "selector": "a.result", "output_name": "link",
            "extract_type": "attribute", "attribute": "", "tag": "a",
        })));
        assert_eq!(opts["attribute"], json!("href"));
    }

    #[test]
    fn an_explicit_attribute_wins_over_the_tag_default() {
        let opts = extract_step_options(&action(json!({
            "type": "action", "action": "add_extract_step",
            "selector": "a.result", "output_name": "link",
            "extract_type": "attribute", "attribute": "data-id", "tag": "a",
        })));
        assert_eq!(opts["attribute"], json!("data-id"));
    }

    #[test]
    fn step_config_carries_the_options_replay_reads() {
        // `test_extract` must exercise the SAME config replay builds, or a green
        // test would say nothing about the recorded step.
        let opts = extract_step_options(&action(json!({
            "type": "action", "action": "test_extract",
            "selector": "a", "output_name": "link",
            "extract_type": "attribute", "attribute": "href",
        })));
        let config = extract_step_config("a", &opts);
        assert_eq!(config.selector.as_deref(), Some("a"));
        assert_eq!(config.extra["variable"], json!("link"));
        assert_eq!(config.extra["extract_type"], json!("attribute"));
        assert_eq!(config.extra["attribute"], json!("href"));
    }

    #[test]
    fn computed_extract_carries_its_script_into_the_config() {
        let opts = extract_step_options(&action(json!({
            "type": "action", "action": "test_extract",
            "selector": "", "output_name": "rows",
            "extract_type": "computed", "script": "() => 1 + 1",
        })));
        let config = extract_step_config("", &opts);
        assert_eq!(config.script.as_deref(), Some("() => 1 + 1"));
        assert_eq!(config.extra["extract_type"], json!("computed"));
    }
}
