use crate::config::constants;
use crate::models::session::RecordingSession;
use crate::models::step::{RecordedStep, RawReplayStep, StepType, ViewportSize};

pub fn record_step_with_delay(
    session: &mut RecordingSession,
    step: RecordedStep,
) {
    if session.steps.len() >= constants::MAX_STEPS {
        tracing::warn!(
            session_id = %session.session_id,
            "Step limit reached ({}), ignoring new step",
            constants::MAX_STEPS
        );
        return;
    }

    let now_ms = step.timestamp;

    // Insert a wait step if significant delay since last step
    if session.record_wait_steps && session.last_step_timestamp > 0.0 {
        let delay_ms = ((now_ms - session.last_step_timestamp) * 1000.0) as u64;
        if delay_ms >= session.min_wait_threshold_ms {
            let capped_ms = delay_ms.min(constants::MAX_WAIT_CAP_MS);
            let wait_step = RecordedStep {
                step_type: StepType::Wait,
                timestamp: session.last_step_timestamp,
                id: uuid::Uuid::new_v4().to_string(),
                selector: None,
                url: None,
                value: None,
                description: None,
                coordinates: None,
                viewport: None,
                options: Some({
                    let mut opts = std::collections::HashMap::new();
                    opts.insert(
                        "duration".to_string(),
                        serde_json::json!(capped_ms),
                    );
                    opts
                }),
            };
            session.steps.push(wait_step);
        }
    }

    session.last_step_timestamp = now_ms;

    // Send step_recorded event to frontend (exact same as Python session.websocket.send_json)
    let step_json = serde_json::to_value(&step).unwrap_or_default();
    let step_count = session.steps.len() + 1;
    session.send_event(serde_json::json!({
        "type": "step_recorded",
        "step": step_json,
        "stepCount": step_count,
    }));

    session.steps.push(step);
}

/// Update an existing step and notify the frontend
pub fn update_step(session: &mut RecordingSession, index: usize, step: &RecordedStep) {
    if index < session.steps.len() {
        let step_json = serde_json::to_value(step).unwrap_or_default();
        session.send_event(serde_json::json!({
            "type": "step_updated",
            "step": step_json,
            "index": index,
        }));
        session.steps[index] = step.clone();
    }
}

/// Send a navigation event to the frontend
pub fn send_navigation_event(session: &RecordingSession, url: &str) {
    session.send_event(serde_json::json!({
        "type": "navigation",
        "url": url,
    }));
}

/// Send select_options event to frontend for dropdown overlay
pub fn send_select_options(session: &RecordingSession, selector: &str, options: &serde_json::Value) {
    session.send_event(serde_json::json!({
        "type": "select_options",
        "selector": selector,
        "options": options,
    }));
}

/// Send native_picker event to frontend
pub fn send_native_picker(session: &RecordingSession, selector: &str, picker_type: &str, value: &str) {
    session.send_event(serde_json::json!({
        "type": "native_picker",
        "selector": selector,
        "pickerType": picker_type,
        "value": value,
    }));
}

/// Send sensitive_field_detected event to frontend
pub fn send_sensitive_field(session: &RecordingSession, selector: &str, field_name: &str) {
    session.send_event(serde_json::json!({
        "type": "sensitive_field_detected",
        "selector": selector,
        "fieldName": field_name,
    }));
}

/// Send tab_list event to frontend
pub fn send_tab_list(session: &RecordingSession, tabs: &[crate::models::session::TabInfo]) {
    session.send_event(serde_json::json!({
        "type": "tab_list",
        "tabs": tabs,
    }));
}

pub fn record_raw_step(session: &mut RecordingSession, mut raw_step: RawReplayStep) {
    if session.last_raw_step_timestamp > 0.0 {
        raw_step.wait_before =
            Some((raw_step.timestamp - session.last_raw_step_timestamp) * 1000.0);
    }
    // Human-behavior layer (same drain rules as the Python recorder): a click
    // consumes the buffered mouse trajectory; a typing burst consumes the
    // keystroke cadence and ends any in-flight mouse gesture. A focus click and
    // the type it precedes are recorded back-to-back, so the click must not
    // drain the key-timing buffer that belongs to the type.
    match raw_step.step_type.as_str() {
        "click" => {
            if raw_step.mouse_path.is_none() && !session.mouse_path_buf.is_empty() {
                raw_step.mouse_path = Some(std::mem::take(&mut session.mouse_path_buf));
            }
            session.mouse_path_buf.clear();
            session.mouse_path_started_at = 0.0;
        }
        "type" | "fill" => {
            if !session.key_timing_buf.is_empty() {
                raw_step.key_timings = Some(std::mem::take(&mut session.key_timing_buf));
            }
            session.mouse_path_buf.clear();
            session.mouse_path_started_at = 0.0;
        }
        _ => {}
    }
    session.last_raw_step_timestamp = raw_step.timestamp;
    session.raw_replay_steps.push(raw_step);
}

pub fn current_timestamp() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

pub fn make_viewport(width: u32, height: u32) -> ViewportSize {
    ViewportSize { width, height }
}
