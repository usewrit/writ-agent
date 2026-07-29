use crate::models::session::RecordingSession;
use crate::models::step::{Coordinates, RawReplayStep, RecordedStep, StepType};

/// Read the current `.value` of the element a picker/slider is bound to.
/// SECURITY: parameterised (`(sel) => …`) and invoked through
/// `helpers::eval_selector_probe`, so the page-derived selector is a serialized
/// evaluate argument and can never terminate a JS string literal.
pub(super) const PICKER_VALUE_PROBE_JS: &str = r#"((sel) => {
    let input = null;
    try { input = document.querySelector(sel); } catch (e) { return null; }
    return input ? input.value : null;
})"#;

pub async fn flush_all_pending(session: &mut RecordingSession) {
    flush_pending_fill(session).await;
    flush_pending_picker(session).await;
    flush_pending_slider(session).await;
    flush_pending_scroll(session).await;
}

pub async fn flush_pending_fill(session: &mut RecordingSession) {
    let pending = match session.pending_fill.take() {
        Some(p) => p,
        None => return,
    };

    let selector = &pending.selector;
    if selector.is_empty() {
        return;
    }

    // Get the ACTUAL current value from the DOM rather than trusting only the
    // accumulated keystrokes — that is what catches "typed a bit, went away, came
    // back and finished", autofill, and input masking.
    //
    // The probe deliberately prefers the FOCUSED element when it matches the
    // selector. `handle_type` derives selectors as `#id` → `[name=…]` →
    // `[placeholder=…]` → bare tag name, and the last two are routinely ambiguous:
    // a WordPress search page has the same `input[name="s"]` in the header and in
    // the page body, so `querySelector` returns the header's empty one and we read
    // "" for a field the user demonstrably typed into.
    //
    // SECURITY: the selector goes in as an evaluate ARGUMENT, never interpolated
    // into the JS source — see helpers::eval_selector_probe for the breakout the
    // old `replace('\'', "\\'")` escaping allowed.
    let actual_value = match super::helpers::eval_selector_probe::<Option<String>>(
        &session.page,
        r#"((sel) => {
                let matches = [];
                try { matches = Array.from(document.querySelectorAll(sel)); } catch (e) { return null; }
                if (matches.length === 0) return null;
                // 1. The element still focused, when it is one of the matches.
                const active = document.activeElement;
                if (active && matches.includes(active)) return active.value;
                // 2. Otherwise the first match that actually holds a value — an
                //    ambiguous selector should not resolve to an empty twin.
                const filled = matches.find(el => el && el.value);
                if (filled) return filled.value;
                return matches[0].value;
            })"#,
        selector,
    )
    .await
    {
        Ok(Some(val)) => val,
        Ok(None) => pending.value.clone(),
        Err(e) => {
            tracing::debug!(error = %e, selector = %selector, "Could not get actual input value");
            pending.value.clone()
        }
    };

    // NEVER discard text the user actually typed because the DOM read came back
    // empty. It used to `return` here, silently dropping the whole fill step —
    // which is why typing into a search box and hitting Enter produced a workflow
    // with a `press Enter` and no `fill` before it. An empty read means the probe
    // resolved to the wrong element, or the page had already begun navigating away
    // and torn the field down; in both cases the keystrokes we accumulated are the
    // better answer. A genuine "user cleared the field" is still empty here,
    // because Backspace/Delete pop `pending.value` too (see handle_press).
    let actual_value = if actual_value.is_empty() {
        if !pending.value.is_empty() {
            tracing::debug!(
                selector = %selector,
                "DOM read for the fill came back empty; falling back to the typed value"
            );
        }
        pending.value.clone()
    } else {
        actual_value
    };

    if actual_value.is_empty() {
        return;
    }

    // 2FA AUTO-DETECT: if the user typed into a one-time-code / verification field
    // (step-2 after password, modal, or redirected page), record a resilient
    // `twofa` step instead of a literal code fill — the code is minted fresh from
    // the persona at run time, and we never persist the typed code (avoids
    // double-entry). Segmented (maxlength=1) boxes emit ONE step on the first box
    // and the rest are suppressed by the session flag.
    if field_is_otp(&session.page, selector).await {
        if !session.twofa_emitted {
            emit_twofa_step(session, selector).await;
            session.twofa_emitted = true;
        }
        return; // never record the literal code value
    }

    // Detect sensitive fields (password type)
    let is_sensitive = pending
        .is_sensitive
        .unwrap_or(false)
        || super::helpers::is_sensitive_field(
            pending.field_type.as_deref().unwrap_or(""),
            pending.element_name.as_deref().unwrap_or(""),
        );

    // Check if there's already a fill step for this field — deduplicate by
    // element_id, element_name, or selector (matching Python behavior).
    let existing_fill_idx = {
        let element_id = pending.element_id.as_deref();
        let element_name = pending.element_name.as_deref();
        let mut found: Option<usize> = None;

        for (i, existing_step) in session.steps.iter().enumerate() {
            if existing_step.step_type != StepType::Fill {
                continue;
            }

            // Match by element ID first (most reliable)
            if let Some(eid) = element_id {
                if let Some(opts) = &existing_step.options {
                    if opts.get("element_id").and_then(|v| v.as_str()) == Some(eid) {
                        found = Some(i);
                        break;
                    }
                }
            }

            // Match by element name
            if let Some(ename) = element_name {
                if let Some(opts) = &existing_step.options {
                    if opts.get("element_name").and_then(|v| v.as_str()) == Some(ename) {
                        found = Some(i);
                        break;
                    }
                }
            }

            // Match by selector (fallback)
            if existing_step.selector.as_deref() == Some(selector) {
                found = Some(i);
                break;
            }
        }

        found
    };

    if let Some(idx) = existing_fill_idx {
        // Update the existing fill step with the new (final) value, and TELL THE UI.
        // Mutating `session.steps[idx]` in place left the recorder's step list
        // showing the stale value until the session was saved.
        //
        // No raw click+type pair is recorded here: the first flush for this field
        // already emitted one, and appending a second would make the raw-replay
        // lane type the value twice.
        let mut updated = session.steps[idx].clone();
        updated.value = Some(actual_value.clone());
        updated.selector = Some(selector.clone());
        tracing::debug!(
            step_id = %updated.id,
            selector = %selector,
            "Updated existing fill step with final value"
        );
        super::step_recording::update_step(session, idx, &updated);
        // These keystrokes belong to THIS field, and no raw step is emitted here to
        // drain them. Left in place they would ride along on the next field's raw
        // `type` step, giving it a cadence recorded from different text.
        session.key_timing_buf.clear();
    } else {
        // Record raw steps for fallback replay (Python line 1680-1694):
        // a click to focus the field, then the typing. Coordinates are also
        // attached to the recorded step itself so the structured replay can fall
        // back to click-to-focus when the selector no longer resolves.
        let coords: Option<(f64, f64)> = match super::helpers::eval_selector_probe::<Option<serde_json::Value>>(
            &session.page,
            r#"((sel) => {
                    let el = null;
                    try { el = document.querySelector(sel); } catch (e) { return null; }
                    if (!el) return null;
                    const rect = el.getBoundingClientRect();
                    return { x: Math.round(rect.left + rect.width / 2), y: Math.round(rect.top + rect.height / 2) };
                })"#,
            selector,
        ).await {
            Ok(Some(val)) => {
                let cx = val.get("x").and_then(|v| v.as_f64());
                let cy = val.get("y").and_then(|v| v.as_f64());
                match (cx, cy) {
                    (Some(x), Some(y)) => Some((x, y)),
                    _ => None,
                }
            }
            _ => None,
        };

        // The REAL viewport, not a 1280x720 guess: replay scales raw coordinates by
        // the ratio of run-time viewport to recorded viewport, so a wrong value here
        // lands every fallback click in the wrong place.
        let viewport = super::helpers::get_viewport(&session.page).await;

        if let Some((rx, ry)) = coords {
            let now = super::step_recording::current_timestamp();
            // Raw click to focus
            super::step_recording::record_raw_step(session, RawReplayStep {
                step_type: "click".to_string(),
                x: Some(rx),
                y: Some(ry),
                value: None,
                key: None,
                url: None,
                duration: None,
                delta_y: None,
                wait_before: None,
                mouse_path: None,
                key_timings: None,
                viewport: Some(viewport.clone()),
                timestamp: now,
            });
            // Raw type
            super::step_recording::record_raw_step(session, RawReplayStep {
                step_type: "type".to_string(),
                x: None,
                y: None,
                value: Some(actual_value.clone()),
                key: None,
                url: None,
                duration: None,
                delta_y: None,
                wait_before: None,
                mouse_path: None,
                key_timings: None,
                viewport: Some(viewport.clone()),
                timestamp: now,
            });
        }

        // Create new fill step with recognition metadata
        let field_name = pending.field_name.clone();
        let description = format!(
            "Fill {}",
            field_name.as_deref().unwrap_or(selector)
        );

        let mut opts = std::collections::HashMap::new();
        if is_sensitive {
            opts.insert(
                "is_sensitive".to_string(),
                serde_json::json!(true),
            );
        }
        if let Some(ref ft) = pending.field_type {
            opts.insert("field_type".to_string(), serde_json::json!(ft));
        }
        if let Some(ref fn_val) = pending.field_name {
            opts.insert("field_name".to_string(), serde_json::json!(fn_val));
        }
        if let Some(ref fc) = pending.field_category {
            opts.insert("field_category".to_string(), serde_json::json!(fc));
        }
        if let Some(ref dk) = pending.data_key {
            opts.insert("data_key".to_string(), serde_json::json!(dk));
        }
        if let Some(ref label) = pending.label {
            opts.insert("label".to_string(), serde_json::json!(label));
        }
        if let Some(ref ph) = pending.placeholder {
            opts.insert("placeholder".to_string(), serde_json::json!(ph));
        }
        if let Some(ref ac) = pending.autocomplete {
            opts.insert("autocomplete".to_string(), serde_json::json!(ac));
        }
        if let Some(ref eid) = pending.element_id {
            opts.insert("element_id".to_string(), serde_json::json!(eid));
        }
        if let Some(ref ename) = pending.element_name {
            opts.insert("element_name".to_string(), serde_json::json!(ename));
        }
        if let Some(rec) = pending.recognition {
            opts.insert("recognition".to_string(), rec);
        }

        let step = RecordedStep {
            step_type: StepType::Fill,
            timestamp: pending.timestamp,
            id: uuid::Uuid::new_v4().to_string(),
            selector: Some(selector.clone()),
            url: None,
            value: Some(actual_value.clone()),
            description: Some(description),
            // Click-to-focus fallback for replay when the selector stops resolving,
            // plus the viewport those coordinates are relative to.
            coordinates: coords.map(|(x, y)| Coordinates { x: x as i32, y: y as i32 }),
            viewport: Some(viewport),
            options: if opts.is_empty() { None } else { Some(opts) },
        };

        // `record_step_with_delay`, NOT `steps.push`. Pushing straight onto the vec
        // skipped the `step_recorded` frame, so a typed fill never appeared in the
        // recorder's step list — clicks did, because every other handler goes
        // through here. From the operator's seat that is indistinguishable from
        // "typing is not recorded at all". It also skipped the step cap and left
        // `last_step_timestamp` stale, so the next step recorded a bogus wait.
        super::step_recording::record_step_with_delay(session, step);
    }

    // Credentials: hand the typed value to the UI so it can be stored encrypted
    // against the workflow instead of living as a literal in the step. Sent after
    // both branches — a password re-typed into an existing fill needs it too.
    if is_sensitive {
        super::step_recording::send_sensitive_field(
            session,
            selector,
            pending
                .field_name
                .as_deref()
                .or(pending.field_type.as_deref())
                .unwrap_or("password"),
            pending.field_type.as_deref().unwrap_or("password"),
            &actual_value,
        );
    }
}

/// True if `selector` targets a one-time-code / 2FA verification field. Precise by
/// design (attrs + segmented structure only, no page-text guess) so normal fills
/// (CVV, zip, coupon code) are NOT misclassified. Mirrors the Python recorder.
async fn field_is_otp(page: &playwright_rs::Page, selector: &str) -> bool {
    if selector.is_empty() {
        return false;
    }
    let js = r#"((sel) => {
            var el=null; try{el=document.querySelector(sel);}catch(e){}
            if(!el) return false;
            var t=((el.getAttribute('name')||'')+' '+(el.id||'')+' '+(el.getAttribute('placeholder')||'')+' '+(el.getAttribute('aria-label')||'')+' '+(el.getAttribute('autocomplete')||'')).toLowerCase();
            if(t.indexOf('one-time-code')>=0) return true;
            var kws=['otp','one-time','onetime','passcode','mfa','2fa','two-factor','two factor','verification','authentication code','login code','security code','auth code'];
            for(var i=0;i<kws.length;i++){ if(t.indexOf(kws[i])>=0) return true; }
            var ml=el.getAttribute('maxlength'); if(ml==='1'||el.maxLength===1) return true;
            return false;
        })"#;
    matches!(
        super::helpers::eval_selector_probe::<bool>(page, js, selector).await,
        Ok(true)
    )
}

/// Record a resilient `twofa` step (selector + verify button) and tell the UI. The
/// step's options carry selector/submit_selector/method; steps_to_workflow_json maps
/// an unknown-type step's options into config, which the replay handler reads.
async fn emit_twofa_step(session: &mut RecordingSession, selector: &str) {
    let mut sel = selector.to_string();
    let mut submit: Option<String> = None;
    // Delivery hint (totp|email_otp|sms|unknown) for the UI persona prefill.
    let mut channel: Option<String> = None;
    if let Ok(det) = crate::browser::page_query::evaluate::<serde_json::Value>(
        &session.page,
        &crate::bridge::otp_entry::detect_invocation(),
    )
    .await
    {
        if let Some(s) = det
            .get("selector")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        {
            sel = s.to_string();
        }
        submit = det.get("submit_selector").and_then(|v| v.as_str()).map(|s| s.to_string());
        channel = det.get("channel").and_then(|v| v.as_str()).map(|s| s.to_string());
    }
    let mut opts = std::collections::HashMap::new();
    opts.insert("selector".to_string(), serde_json::json!(sel));
    opts.insert("submit_selector".to_string(), serde_json::json!(submit));
    opts.insert("method".to_string(), serde_json::json!(""));
    let step = RecordedStep {
        step_type: StepType::Twofa,
        timestamp: super::step_recording::current_timestamp(),
        id: uuid::Uuid::new_v4().to_string(),
        selector: Some(sel.clone()),
        url: None,
        value: None,
        description: Some("Enter the one-time 2FA verification code".to_string()),
        coordinates: None,
        viewport: None,
        options: Some(opts),
    };
    super::step_recording::record_step_with_delay(session, step);
    session.send_event(serde_json::json!({
        "type": "twofa_detected",
        "selector": sel,
        "submit_selector": submit,
        "channel_hint": channel,
    }));
}

pub async fn flush_pending_picker(session: &mut RecordingSession) {
    let pending = match session.pending_picker.take() {
        Some(p) => p,
        None => return,
    };

    // Get current value from the picker input
    let new_value = match super::helpers::eval_selector_probe::<Option<String>>(
        &session.page,
        PICKER_VALUE_PROBE_JS,
        &pending.selector,
    )
    .await
    {
        Ok(Some(val)) if !val.is_empty() => val,
        _ => {
            // Use old_value as fallback
            match pending.old_value.clone() {
                Some(v) if !v.is_empty() => v,
                _ => return,
            }
        }
    };

    // Only record if value actually changed (compare before the old_value is moved)
    if pending.old_value.as_deref() == Some(new_value.as_str()) {
        return;
    }

    let step = RecordedStep {
        step_type: StepType::Fill,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64(),
        id: uuid::Uuid::new_v4().to_string(),
        selector: Some(pending.selector),
        url: None,
        value: Some(new_value),
        description: Some(format!("{} picker", pending.picker_type)),
        coordinates: None,
        viewport: None,
        options: None,
    };

    super::step_recording::record_step_with_delay(session, step);
}

pub async fn flush_pending_slider(session: &mut RecordingSession) {
    let pending = match session.pending_slider.take() {
        Some(p) => p,
        None => return,
    };

    // Get the current slider value from DOM
    let current_value = match super::helpers::eval_selector_probe::<Option<String>>(
        &session.page,
        PICKER_VALUE_PROBE_JS,
        &pending.selector,
    )
    .await
    {
        Ok(Some(val)) if !val.is_empty() => val,
        _ => {
            match pending.old_value {
                Some(v) if !v.is_empty() => v,
                _ => return,
            }
        }
    };

    let step = RecordedStep {
        step_type: StepType::Fill,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64(),
        id: uuid::Uuid::new_v4().to_string(),
        selector: Some(pending.selector),
        url: None,
        value: Some(current_value),
        description: Some("range slider".to_string()),
        coordinates: None,
        viewport: None,
        options: None,
    };

    super::step_recording::record_step_with_delay(session, step);
}

pub async fn flush_pending_scroll(session: &mut RecordingSession) {
    let pending = match session.pending_scroll.take() {
        Some(p) => p,
        None => return,
    };

    // Discard tiny scrolls (< 20px) and non-finite deltas (NaN/Infinity would
    // panic serde_json::Number::from_f64 → crash the session).
    if !pending.total_delta_y.is_finite() || pending.total_delta_y.abs() < 20.0 {
        return;
    }

    let mut opts = std::collections::HashMap::new();
    if let Some(num) = serde_json::Number::from_f64(pending.total_delta_y) {
        opts.insert("deltaY".to_string(), serde_json::Value::Number(num));
    }

    if let Some(container) = &pending.container_selector {
        opts.insert(
            "container".to_string(),
            serde_json::Value::String(container.clone()),
        );
    }

    // The UI labels a step by its description; without one the consolidated scroll
    // rendered as a bare "scroll" row (the Python recorder names the direction and
    // the container).
    let direction = if pending.total_delta_y > 0.0 { "down" } else { "up" };
    let description = match &pending.container_selector {
        Some(container) => format!("Scroll {} in {}", direction, container),
        None => format!("Scroll {}", direction),
    };

    let step = RecordedStep {
        step_type: StepType::Scroll,
        timestamp: pending.start_time,
        id: uuid::Uuid::new_v4().to_string(),
        selector: pending.container_selector,
        url: None,
        value: None,
        description: Some(description),
        coordinates: None,
        viewport: None,
        options: Some(opts),
    };

    super::step_recording::record_step_with_delay(session, step);
}

#[cfg(test)]
mod tests {
    /// Every flush here MUST go through `record_step_with_delay`, never
    /// `session.steps.push`.
    ///
    /// This is not style. `record_step_with_delay` is the only thing that emits the
    /// `step_recorded` frame, and that frame is the ONLY way a step reaches the
    /// recorder's step list. All four flushes used to push directly, so typing into
    /// a field produced a fill that existed in the saved workflow but never showed
    /// up while recording — while clicks, which take the normal path, appeared
    /// instantly. That asymmetry reads as "the recorder does not record typing".
    /// Pushing directly also skips the step cap and leaves `last_step_timestamp`
    /// stale, which mis-times the wait step before whatever comes next.
    #[test]
    fn no_flush_pushes_onto_the_step_list_directly() {
        let src = include_str!("pending.rs");
        // Trim this file's own test module so the strings below cannot match themselves.
        let body = src.split("#[cfg(test)]").next().unwrap_or(src);
        assert!(
            !body.contains("session.steps.push("),
            "a flush in pending.rs pushes a step directly; use \
             step_recording::record_step_with_delay so the UI gets `step_recorded`"
        );
        // The fill UPDATE path has the same requirement, via `update_step`.
        assert!(
            body.contains("step_recording::update_step("),
            "the existing-fill branch must notify the UI through update_step"
        );
        assert!(
            body.contains("step_recording::send_sensitive_field("),
            "a typed credential must be offered to the UI for encrypted capture"
        );
    }
}
