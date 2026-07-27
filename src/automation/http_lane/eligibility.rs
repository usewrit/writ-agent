//! Deciding whether a workflow can run on the browserless HTTP lane.
//!
//! Phase 1: a workflow is eligible when every ENABLED step is a pure-HTTP step (api_call / login_post
//! / return / a duration-based wait) and at least one is an actual request. A `{{file:}}` placeholder
//! anywhere forces the browser lane (file uploads need a real page). Disabled steps are ignored (they
//! are skipped in both lanes). `workflow_type` is only a log hint — the steps array is the truth.

use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub struct HttpEligibility {
    pub eligible: bool,
    pub reason: &'static str,
}

/// The env kill-switch: when set to a truthy value, no workflow uses the HTTP lane (ops can force the
/// whole fleet back onto the browser without a redeploy). Checked here so both the local engine and
/// the saas bridge honor it through the single gate.
pub fn kill_switch_engaged() -> bool {
    matches!(
        std::env::var("WRIT_HTTP_LANE_DISABLED").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes")
    )
}

/// True for a step type the HTTP lane can execute in phase 1.
fn is_http_step_type(step_type: &str) -> bool {
    matches!(step_type, "api_call" | "login_post" | "return" | "wait")
}

fn step_enabled(raw: &Value) -> bool {
    raw.get("enabled").and_then(Value::as_bool).unwrap_or(true)
}

fn step_type(raw: &Value) -> &str {
    raw.get("type").and_then(Value::as_str).unwrap_or("")
}

/// A `wait` step is HTTP-runnable only when it waits for a DURATION (not a DOM condition).
fn wait_is_duration_only(raw: &Value) -> bool {
    let cfg = raw.get("config").unwrap_or(raw);
    let cond = cfg
        .get("condition")
        .and_then(Value::as_str)
        .or_else(|| raw.get("condition").and_then(Value::as_str));
    matches!(cond, None | Some("duration") | Some("timeout"))
}

/// Does any string field of the step (or its config) contain a `{{file:...}}` placeholder?
fn references_file_asset(raw: &Value) -> bool {
    fn scan(v: &Value) -> bool {
        match v {
            Value::String(s) => s.contains("{{file:"),
            Value::Array(a) => a.iter().any(scan),
            Value::Object(o) => o.values().any(scan),
            _ => false,
        }
    }
    scan(raw)
}

/// Evaluate the phase-1 gate over the raw step list.
pub fn http_lane_eligible(raw_steps: &[Value]) -> HttpEligibility {
    if kill_switch_engaged() {
        return HttpEligibility { eligible: false, reason: "kill_switch" };
    }
    let mut saw_request = false;
    for raw in raw_steps {
        if !step_enabled(raw) {
            continue; // disabled steps are skipped in both lanes
        }
        let st = step_type(raw);
        if st.is_empty() {
            continue; // empty/unparseable step types are skipped by both run loops
        }
        if !is_http_step_type(st) {
            return HttpEligibility { eligible: false, reason: "dom_step" };
        }
        if st == "wait" && !wait_is_duration_only(raw) {
            return HttpEligibility { eligible: false, reason: "wait_condition" };
        }
        if references_file_asset(raw) {
            return HttpEligibility { eligible: false, reason: "file_asset" };
        }
        if st == "api_call" || st == "login_post" {
            saw_request = true;
        }
    }
    if !saw_request {
        // An all-wait / all-return workflow gains nothing from the HTTP lane.
        return HttpEligibility { eligible: false, reason: "no_request" };
    }
    HttpEligibility { eligible: true, reason: "eligible" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn pure_api_workflow_eligible() {
        let steps = vec![
            json!({"type": "login_post", "config": {"url": "https://x/login"}}),
            json!({"type": "api_call", "config": {"url": "https://x/data"}}),
        ];
        assert!(http_lane_eligible(&steps).eligible);
    }

    #[test]
    fn dom_step_ineligible() {
        let steps = vec![
            json!({"type": "api_call", "config": {"url": "https://x/data"}}),
            json!({"type": "click", "config": {"selector": "#go"}}),
        ];
        let e = http_lane_eligible(&steps);
        assert!(!e.eligible && e.reason == "dom_step");
    }

    #[test]
    fn disabled_dom_step_ignored() {
        let steps = vec![
            json!({"type": "api_call", "config": {"url": "https://x/data"}}),
            json!({"type": "click", "enabled": false, "config": {"selector": "#go"}}),
        ];
        assert!(http_lane_eligible(&steps).eligible);
    }

    #[test]
    fn wait_duration_ok_condition_not() {
        let ok = vec![
            json!({"type": "api_call", "config": {"url": "https://x"}}),
            json!({"type": "wait", "config": {"condition": "duration", "duration": 500}}),
        ];
        assert!(http_lane_eligible(&ok).eligible);
        let bad = vec![
            json!({"type": "api_call", "config": {"url": "https://x"}}),
            json!({"type": "wait", "config": {"condition": "selector", "selector": "#x"}}),
        ];
        assert_eq!(http_lane_eligible(&bad).reason, "wait_condition");
    }

    #[test]
    fn file_asset_forces_browser() {
        let steps = vec![
            json!({"type": "api_call", "config": {"url": "https://x", "body": "f={{file:doc}}"}}),
        ];
        assert_eq!(http_lane_eligible(&steps).reason, "file_asset");
    }

    #[test]
    fn no_request_ineligible() {
        let steps = vec![json!({"type": "wait", "config": {"condition": "duration", "duration": 100}})];
        assert_eq!(http_lane_eligible(&steps).reason, "no_request");
    }

    #[test]
    fn empty_type_skipped() {
        let steps = vec![
            json!({"type": "", "config": {}}),
            json!({"type": "api_call", "config": {"url": "https://x"}}),
        ];
        assert!(http_lane_eligible(&steps).eligible);
    }
}
