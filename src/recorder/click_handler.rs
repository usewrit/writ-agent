use std::collections::HashMap;

use crate::models::session::{PendingDropdown, PendingSlider, RecordingSession};
use crate::models::step::{Coordinates, RawReplayStep, RecordedStep, StepType};

use super::action_handler::{ActionResult, IncomingAction};
use super::helpers;
use super::step_recording;

pub async fn handle_click(
    session: &mut RecordingSession,
    action: &IncomingAction,
) -> ActionResult {
    // Flush all pending inputs before any click
    super::pending::flush_all_pending(session).await;

    let x = action.data.get("x").and_then(|v| v.as_f64());
    let y = action.data.get("y").and_then(|v| v.as_f64());

    let (cx, cy) = match (x, y) {
        (Some(x), Some(y)) => (x, y),
        _ => return ActionResult::err("Click requires x and y coordinates"),
    };

    // Wait for element stability before interacting (Python line 3037)
    helpers::wait_for_element_stable(&session.page, cx, cy, 300).await;

    // Get element info at click coordinates via JS evaluation
    let element_info: Option<serde_json::Value> = {
        let args = serde_json::json!({"x": cx, "y": cy});
        match crate::browser::page_query::evaluate_with_args(
            &session.page,
            helpers::ELEMENT_AT_COORDINATES_JS,
            args,
        )
        .await
        {
            Ok(info) => info,
            Err(e) => {
                tracing::debug!(error = %e, "Could not get element info before click");
                None
            }
        }
    };

    // Check for captcha first (from incoming action flags)
    let is_captcha = action
        .data
        .get("isCaptcha")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if is_captcha {
        return handle_captcha_click(session, action, cx, cy).await;
    }

    // Check for select element
    let is_select = action
        .data
        .get("isSelect")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if is_select {
        return handle_select_click(session, action, &element_info).await;
    }

    // Check for checkbox/radio
    let is_checkbox = action
        .data
        .get("isCheckbox")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let is_radio = action
        .data
        .get("isRadio")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if is_checkbox || is_radio {
        return handle_checkable_click(session, action, cx, cy, is_checkbox).await;
    }

    // Check for native picker
    let is_native_picker = action
        .data
        .get("isNativePicker")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if is_native_picker {
        return handle_native_picker_click(session, action).await;
    }

    // Check for range slider
    let is_range_slider = action
        .data
        .get("isRangeSlider")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if is_range_slider {
        return handle_slider_click(session, action, cx, cy).await;
    }

    // If element_info was retrieved from JS, also check those flags
    if let Some(ref info) = element_info {
        if info.get("isSelectable").and_then(|v| v.as_bool()).unwrap_or(false)
            && info.get("tag").and_then(|v| v.as_str()) == Some("select")
        {
            return handle_select_click(session, action, &element_info).await;
        }

        if info.get("isCheckable").and_then(|v| v.as_bool()).unwrap_or(false) {
            let is_cb = info
                .get("inputType")
                .and_then(|v| v.as_str()) == Some("checkbox");
            return handle_checkable_click(session, action, cx, cy, is_cb).await;
        }
    }

    // Check if clicking elsewhere closes a pending dropdown
    if session.pending_dropdown.is_some() {
        tracing::debug!("Dropdown abandoned: clicked elsewhere");
        session.pending_dropdown = None;
    }

    handle_default_click(session, action, &element_info, cx, cy).await
}

async fn handle_captcha_click(
    session: &mut RecordingSession,
    action: &IncomingAction,
    x: f64,
    y: f64,
) -> ActionResult {
    // Allow the click to proceed through to the page
    if let Err(e) = crate::browser::page_actions::click_at(&session.page, x, y).await {
        return ActionResult::err(format!("Captcha click failed: {}", e));
    }

    // Rate limit: only record one captcha step per 5 seconds
    let now = step_recording::current_timestamp();
    if let Some(last_ts) = session.last_captcha_step {
        if now - last_ts < 5.0 {
            return ActionResult::ok();
        }
    }

    let captcha_type = action
        .data
        .get("captchaType")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let selector = action
        .data
        .get("selector")
        .and_then(|v| v.as_str())
        .unwrap_or("N/A");

    let step = RecordedStep {
        step_type: StepType::Captcha,
        timestamp: now,
        id: uuid::Uuid::new_v4().to_string(),
        selector: Some(selector.to_string()),
        url: None,
        value: None,
        description: Some(format!("Captcha interaction ({})", captcha_type)),
        coordinates: Some(Coordinates {
            x: x as i32,
            y: y as i32,
        }),
        viewport: None,
        options: Some({
            let mut opts = HashMap::new();
            opts.insert(
                "captcha_type".to_string(),
                serde_json::json!(captcha_type),
            );
            opts
        }),
    };
    step_recording::record_step_with_delay(session, step);
    session.last_captcha_step = Some(now);

    tracing::info!(captcha_type, "Recorded captcha step");
    ActionResult::ok()
}

async fn handle_select_click(
    session: &mut RecordingSession,
    action: &IncomingAction,
    element_info: &Option<serde_json::Value>,
) -> ActionResult {
    // Get the select element's selector
    let select_selector = action
        .data
        .get("selector")
        .and_then(|v| v.as_str())
        .or_else(|| {
            element_info
                .as_ref()
                .and_then(|info| info.get("selector").and_then(|v| v.as_str()))
        })
        .unwrap_or("select")
        .to_string();

    // Extract options from the select element via JS
    let options_data: Option<serde_json::Value> = {
        let js = r#"((sel) => {
            const select = document.querySelector(sel);
            if (!select) return null;

            const rect = select.getBoundingClientRect();
            const options = Array.from(select.options).map((opt, idx) => ({
                value: opt.value,
                text: opt.textContent.trim(),
                selected: opt.selected,
                disabled: opt.disabled,
                index: idx
            }));

            return {
                options: options,
                position: {
                    x: rect.left,
                    y: rect.bottom,
                    width: Math.max(rect.width, 150),
                    height: rect.height,
                    selectTop: rect.top
                },
                selectedIndex: select.selectedIndex,
                name: select.name || select.id || ''
            };
        })"#;
        let args = serde_json::json!(select_selector);
        crate::browser::page_query::evaluate_with_args(&session.page, js, args)
            .await
            .unwrap_or(None)
    };

    if options_data.is_some() {
        // Track pending select for when frontend sends selection
        session.pending_dropdown = Some(PendingDropdown {
            selector: select_selector.clone(),
            dropdown_type: "native".to_string(),
        });

        // Return the options data to send to frontend
        ActionResult::ok_with_data(serde_json::json!({
            "type": "select_options",
            "selector": select_selector,
            "options_data": options_data
        }))
    } else {
        // Fallback: click to open native dropdown
        let x = action.data.get("x").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let y = action.data.get("y").and_then(|v| v.as_f64()).unwrap_or(0.0);
        if let Err(e) = crate::browser::page_actions::click_at(&session.page, x, y).await {
            return ActionResult::err(format!("Select click fallback failed: {}", e));
        }
        ActionResult::ok()
    }
}

async fn handle_checkable_click(
    session: &mut RecordingSession,
    action: &IncomingAction,
    x: f64,
    y: f64,
    is_checkbox: bool,
) -> ActionResult {
    // Get state BEFORE clicking
    let was_checked = action
        .data
        .get("checked")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Click through
    if let Err(e) = crate::browser::page_actions::click_at(&session.page, x, y).await {
        return ActionResult::err(format!("Checkbox click failed: {}", e));
    }

    // After click, checkbox toggles; radio stays checked
    let will_be_checked = if is_checkbox { !was_checked } else { true };

    let step_type = if will_be_checked {
        StepType::Check
    } else {
        StepType::Uncheck
    };

    let selector = action
        .data
        .get("selector")
        .and_then(|v| v.as_str())
        .unwrap_or("input");

    let label = action
        .data
        .get("label")
        .and_then(|v| v.as_str())
        .unwrap_or(selector);

    let step = RecordedStep {
        step_type,
        timestamp: step_recording::current_timestamp(),
        id: uuid::Uuid::new_v4().to_string(),
        selector: Some(selector.to_string()),
        url: None,
        value: None,
        description: Some(format!(
            "{} '{}'",
            if will_be_checked { "Check" } else { "Uncheck" },
            label
        )),
        coordinates: Some(Coordinates {
            x: x as i32,
            y: y as i32,
        }),
        viewport: None,
        options: Some({
            let mut opts = HashMap::new();
            opts.insert("tag".to_string(), serde_json::json!("input"));
            opts.insert(
                "input_type".to_string(),
                serde_json::json!(if is_checkbox { "checkbox" } else { "radio" }),
            );
            opts.insert("label".to_string(), serde_json::json!(label));
            opts
        }),
    };
    step_recording::record_step_with_delay(session, step);

    ActionResult::ok()
}

async fn handle_native_picker_click(
    session: &mut RecordingSession,
    action: &IncomingAction,
) -> ActionResult {
    let picker_type = action
        .data
        .get("pickerType")
        .and_then(|v| v.as_str())
        .unwrap_or("text");

    let selector = action
        .data
        .get("selector")
        .and_then(|v| v.as_str())
        .unwrap_or("input");

    let current_value = action
        .data
        .get("currentValue")
        .and_then(|v| v.as_str())
        .map(String::from);

    // Set pending picker for the session - don't click, let frontend handle via overlay
    session.pending_picker = Some(crate::models::session::PendingPicker {
        selector: selector.to_string(),
        picker_type: picker_type.to_string(),
        old_value: current_value,
    });

    // Return picker info for frontend overlay
    ActionResult::ok_with_data(serde_json::json!({
        "type": "native_picker",
        "pickerType": picker_type,
        "selector": selector,
    }))
}

async fn handle_slider_click(
    session: &mut RecordingSession,
    action: &IncomingAction,
    x: f64,
    y: f64,
) -> ActionResult {
    // Click through to engage the slider
    if let Err(e) = crate::browser::page_actions::click_at(&session.page, x, y).await {
        return ActionResult::err(format!("Slider click failed: {}", e));
    }

    let selector = action
        .data
        .get("selector")
        .and_then(|v| v.as_str())
        .unwrap_or("input[type=range]");

    let range_value = action
        .data
        .get("rangeValue")
        .and_then(|v| v.as_str())
        .map(String::from);

    // Set pending slider - final value captured when mouseup or next action flushes
    session.pending_slider = Some(PendingSlider {
        selector: selector.to_string(),
        old_value: range_value,
    });

    ActionResult::ok()
}

async fn handle_default_click(
    session: &mut RecordingSession,
    _action: &IncomingAction,
    element_info: &Option<serde_json::Value>,
    x: f64,
    y: f64,
) -> ActionResult {
    let viewport = helpers::get_viewport(&session.page).await;

    // Helper closures for extracting element_info fields
    let get_str = |info: &serde_json::Value, key: &str| -> Option<String> {
        info.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
    };
    let get_bool = |info: &serde_json::Value, key: &str| -> bool {
        info.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
    };

    // === Complex element handling (Python lines 3664-3792) ===
    if let Some(ref info) = element_info {
        // 4. Custom date picker day (Python line 3665)
        if get_bool(info, "isDatePickerDay") {
            if let Err(e) = crate::browser::page_actions::click_at(&session.page, x, y).await {
                return ActionResult::err(format!("Date picker click failed: {}", e));
            }
            step_recording::record_raw_step(session, RawReplayStep {
                step_type: "click".to_string(), x: Some(x), y: Some(y),
                value: None, key: None, url: None, duration: None, delta_y: None,
                wait_before: None, mouse_path: None, key_timings: None, viewport: Some(viewport.clone()),
                timestamp: step_recording::current_timestamp(),
            });
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;

            let selected_date = get_str(info, "selectedDate").unwrap_or_default();
            let target_sel = get_str(info, "datePickerInputSelector")
                .or_else(|| get_str(info, "selector"))
                .unwrap_or_default();

            // Try to get final value from the input
            let final_value = if !target_sel.is_empty() {
                // SECURITY: `datePickerInputSelector` is built IN-PAGE from
                // page-controlled attributes, so it must be an evaluate ARGUMENT,
                // not interpolated into the JS source — see
                // helpers::eval_selector_probe for the breakout the old escaping
                // (`replace('\'', "\\'")`, which ignores backslashes) allowed.
                super::helpers::eval_selector_probe::<Option<String>>(
                    &session.page,
                    r#"((sel) => {
                        let i = null;
                        try { i = document.querySelector(sel); } catch (e) { return null; }
                        return i ? i.value : null;
                    })"#,
                    &target_sel,
                ).await.ok().flatten()
            } else {
                None
            };
            let value = final_value.unwrap_or(selected_date);

            let step = RecordedStep {
                step_type: StepType::Fill,
                timestamp: step_recording::current_timestamp(),
                id: uuid::Uuid::new_v4().to_string(),
                selector: Some(target_sel),
                url: None,
                value: Some(value.clone()),
                description: Some(format!("Set date to '{}'", value)),
                coordinates: Some(Coordinates { x: x as i32, y: y as i32 }),
                viewport: Some(viewport),
                options: Some({
                    let mut opts = HashMap::new();
                    opts.insert("tag".to_string(), serde_json::json!("input"));
                    opts.insert("input_type".to_string(), serde_json::json!("date"));
                    opts.insert("from_datepicker".to_string(), serde_json::json!(true));
                    opts
                }),
            };
            step_recording::record_step_with_delay(session, step);
            return ActionResult::ok();
        }

        // 5. Autocomplete / ARIA option (Python line 3726)
        if get_bool(info, "isAriaOption") && get_str(info, "comboboxSelector").is_some() {
            if let Err(e) = crate::browser::page_actions::click_at(&session.page, x, y).await {
                return ActionResult::err(format!("Autocomplete click failed: {}", e));
            }
            step_recording::record_raw_step(session, RawReplayStep {
                step_type: "click".to_string(), x: Some(x), y: Some(y),
                value: None, key: None, url: None, duration: None, delta_y: None,
                wait_before: None, mouse_path: None, key_timings: None, viewport: Some(viewport.clone()),
                timestamp: step_recording::current_timestamp(),
            });
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;

            let combobox_sel = get_str(info, "comboboxSelector").unwrap();
            let option_value = get_str(info, "ariaOptionValue").unwrap_or_default();
            let coords = helpers::get_element_center(&session.page, &combobox_sel).await;

            let step = RecordedStep {
                step_type: StepType::Fill,
                timestamp: step_recording::current_timestamp(),
                id: uuid::Uuid::new_v4().to_string(),
                selector: Some(combobox_sel),
                url: None,
                value: Some(option_value.clone()),
                description: Some(format!("Select '{}' from autocomplete", option_value)),
                coordinates: coords.map(|(cx, cy)| Coordinates { x: cx, y: cy }),
                viewport: Some(viewport),
                options: Some({
                    let mut opts = HashMap::new();
                    opts.insert("tag".to_string(), serde_json::json!("input"));
                    opts.insert("from_autocomplete".to_string(), serde_json::json!(true));
                    opts
                }),
            };
            step_recording::record_step_with_delay(session, step);
            session.pending_dropdown = None;
            return ActionResult::ok();
        }

        // 6. Custom dropdown option — React Select, MUI, etc. (Python line 3759)
        if get_bool(info, "isCustomDropdownOption") {
            if let Err(e) = crate::browser::page_actions::click_at(&session.page, x, y).await {
                return ActionResult::err(format!("Dropdown option click failed: {}", e));
            }
            let target_sel = get_str(info, "customDropdownSelector")
                .or_else(|| get_str(info, "selector"))
                .unwrap_or_default();
            let value = get_str(info, "customOptionValue").unwrap_or_default();

            step_recording::record_raw_step(session, RawReplayStep {
                step_type: "click".to_string(), x: Some(x), y: Some(y),
                value: None, key: None, url: None, duration: None, delta_y: None,
                wait_before: None, mouse_path: None, key_timings: None, viewport: Some(viewport.clone()),
                timestamp: step_recording::current_timestamp(),
            });
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;

            let step = RecordedStep {
                step_type: StepType::Select,
                timestamp: step_recording::current_timestamp(),
                id: uuid::Uuid::new_v4().to_string(),
                selector: Some(target_sel),
                url: None,
                value: Some(value.clone()),
                description: Some(format!("Select '{}' in dropdown", value)),
                coordinates: Some(Coordinates { x: x as i32, y: y as i32 }),
                viewport: Some(viewport),
                options: Some({
                    let mut opts = HashMap::new();
                    opts.insert("tag".to_string(), serde_json::json!("custom-select"));
                    opts.insert("from_custom_dropdown".to_string(), serde_json::json!(true));
                    opts
                }),
            };
            step_recording::record_step_with_delay(session, step);
            session.pending_dropdown = None;
            return ActionResult::ok();
        }

        // Scroll element into view if needed before click (Python line 3797)
        if get_bool(info, "needsScroll") {
            let sel = get_str(info, "selector").unwrap_or_default();
            let text = get_str(info, "text").unwrap_or_default();
            let scroll_step = RecordedStep {
                step_type: StepType::ScrollIntoView,
                timestamp: step_recording::current_timestamp(),
                id: uuid::Uuid::new_v4().to_string(),
                selector: Some(sel.clone()),
                url: None,
                value: None,
                description: Some(format!("Scroll to {}", if text.is_empty() { &sel } else { &text })),
                coordinates: None,
                viewport: None,
                options: get_str(info, "scrollContainerSelector").map(|c| {
                    let mut opts = HashMap::new();
                    opts.insert("container".to_string(), serde_json::json!(c));
                    opts
                }),
            };
            step_recording::record_step_with_delay(session, scroll_step);
            helpers::scroll_element_into_view(&session.page, &sel).await;
        }
    }

    // Normal click (Python line 3812)
    if let Err(e) = crate::browser::page_actions::click_at(&session.page, x, y).await {
        return ActionResult::err(format!("Click failed: {}", e));
    }

    // ALWAYS record raw click for fallback replay (Python line 3818)
    step_recording::record_raw_step(session, RawReplayStep {
        step_type: "click".to_string(),
        x: Some(x),
        y: Some(y),
        value: None, key: None, url: None, duration: None, delta_y: None,
        wait_before: None, mouse_path: None, key_timings: None, viewport: Some(viewport.clone()),
        timestamp: step_recording::current_timestamp(),
    });

    // Determine element type from element_info to decide what step to record
    if let Some(ref info) = element_info {
        let tag = info.get("tag").and_then(|v| v.as_str()).unwrap_or("");
        let input_type = info.get("inputType").and_then(|v| v.as_str()).unwrap_or("");
        let selector = info.get("selector").and_then(|v| v.as_str()).unwrap_or("N/A");
        let text = info.get("text").and_then(|v| v.as_str()).unwrap_or("");
        let is_button = info.get("isButton").and_then(|v| v.as_bool()).unwrap_or(false);
        let is_link = info.get("isLink").and_then(|v| v.as_bool()).unwrap_or(false);

        // === Buttons and Links - ALWAYS record click step (Python line 3827) ===
        if is_button || is_link {
            let click_rec = info.get("clickableRecognition").cloned().unwrap_or(serde_json::json!({}));
            let step = RecordedStep {
                step_type: StepType::Click,
                timestamp: step_recording::current_timestamp(),
                id: uuid::Uuid::new_v4().to_string(),
                selector: Some(selector.to_string()),
                url: None,
                value: None,
                description: Some(format!("Click {}", if !text.is_empty() { text } else { selector })),
                coordinates: Some(Coordinates { x: x as i32, y: y as i32 }),
                viewport: Some(viewport),
                options: {
                    let mut opts = HashMap::new();
                    opts.insert("tag".to_string(), serde_json::json!(tag));
                    if let Some(href) = info.get("href") { opts.insert("href".to_string(), href.clone()); }
                    if let Some(t) = click_rec.get("text") { opts.insert("text".to_string(), t.clone()); }
                    if let Some(l) = click_rec.get("label") { opts.insert("label".to_string(), l.clone()); }
                    if let Some(eid) = click_rec.get("element_id") { opts.insert("element_id".to_string(), eid.clone()); }
                    if let Some(en) = click_rec.get("element_name") { opts.insert("element_name".to_string(), en.clone()); }
                    if let Some(al) = click_rec.get("ariaLabel") { opts.insert("aria_label".to_string(), al.clone()); }
                    if let Some(r) = click_rec.get("role") { opts.insert("role".to_string(), r.clone()); }
                    if let Some(rec) = click_rec.get("recognition") { opts.insert("recognition".to_string(), rec.clone()); }
                    Some(opts)
                },
            };
            step_recording::record_step_with_delay(session, step);
            return ActionResult::ok();
        }

        // === Focus clicks on text inputs - don't record (Python line 3854) ===
        if tag == "input" || tag == "textarea" {
            let text_input_types = ["", "text", "email", "password", "search", "tel", "url", "number"];
            let is_focus_click = tag == "textarea" || text_input_types.contains(&input_type);

            if is_focus_click {
                session.last_focus_click = Some(crate::models::session::FocusClick {
                    selector: selector.to_string(),
                    timestamp: step_recording::current_timestamp(),
                });
                return ActionResult::ok();
            }

            // Other input types (file, etc.) - record click
            let step = RecordedStep {
                step_type: StepType::Click,
                timestamp: step_recording::current_timestamp(),
                id: uuid::Uuid::new_v4().to_string(),
                selector: Some(selector.to_string()),
                url: None, value: None,
                description: Some(format!("Click {}", if !text.is_empty() { text } else { selector })),
                coordinates: Some(Coordinates { x: x as i32, y: y as i32 }),
                viewport: Some(viewport),
                options: Some({
                    let mut opts = HashMap::new();
                    opts.insert("tag".to_string(), serde_json::json!(tag));
                    opts.insert("type".to_string(), serde_json::json!(input_type));
                    opts
                }),
            };
            step_recording::record_step_with_delay(session, step);
            return ActionResult::ok();
        }

        // === Other elements (divs, spans, etc.) - record click (Python line 3885) ===
        let step = RecordedStep {
            step_type: StepType::Click,
            timestamp: step_recording::current_timestamp(),
            id: uuid::Uuid::new_v4().to_string(),
            selector: Some(selector.to_string()),
            url: None, value: None,
            description: Some(format!("Click {}", if !text.is_empty() { text } else { selector })),
            coordinates: Some(Coordinates { x: x as i32, y: y as i32 }),
            viewport: Some(viewport),
            options: {
                let mut opts = HashMap::new();
                opts.insert("tag".to_string(), serde_json::json!(tag));
                if let Some(href) = info.get("href") { opts.insert("href".to_string(), href.clone()); }
                if let Some(rec) = info.get("recognition") { opts.insert("recognition".to_string(), rec.clone()); }
                Some(opts)
            },
        };
        step_recording::record_step_with_delay(session, step);
    } else {
        // No element info - generic coordinate-based click
        let step = RecordedStep {
            step_type: StepType::Click,
            timestamp: step_recording::current_timestamp(),
            id: uuid::Uuid::new_v4().to_string(),
            selector: None,
            url: None, value: None,
            description: Some(format!("Click at ({}, {})", x as i32, y as i32)),
            coordinates: Some(Coordinates { x: x as i32, y: y as i32 }),
            viewport: Some(viewport),
            options: None,
        };
        step_recording::record_step_with_delay(session, step);
    }

    ActionResult::ok()
}
