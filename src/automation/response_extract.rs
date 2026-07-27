//! `response_extractions` — pull named values out of an api_call / login_post response body so later
//! steps can reference them as `{{extracted:name}}`.
//!
//! Shared by both request lanes: the browser in-page fetch (`step_eval`) and the browserless HTTP
//! lane. The concierge and cloud emit this as a `{name: "$.json.path"}` MAP; an older shape is a LIST
//! of `{key, path}` objects. Both are accepted so a workflow behaves identically whichever lane runs it
//! and whichever surface authored it.

use crate::models::workflow::WorkflowStepConfig;
use crate::monitor::extract::json_value_path;
use serde_json::Value;

/// Apply a step's `response_extractions` to its already-parsed response `data`, returning
/// `(name, value)` pairs to merge into the run's extracted-data map. A path that resolves to nothing
/// is skipped (the placeholder stays unresolved downstream, same as a missing form key).
///
/// Accepts both shapes:
///   * map:  `{"token": "$.data.token", "id": "$.data.id"}`  (canonical)
///   * list: `[{"key": "token", "path": "$.data.token"}, ...]`
pub fn apply_response_extractions(
    config: &WorkflowStepConfig,
    data: &Value,
) -> Vec<(String, Value)> {
    let Some(spec) = config.extra.get("response_extractions") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    match spec {
        Value::Object(map) => {
            for (name, path) in map {
                if let Some(path) = path.as_str() {
                    if let Some(v) = json_value_path(data, path) {
                        out.push((name.clone(), v));
                    }
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                let name = item.get("key").or_else(|| item.get("name")).and_then(Value::as_str);
                let path = item.get("path").and_then(Value::as_str);
                if let (Some(name), Some(path)) = (name, path) {
                    if let Some(v) = json_value_path(data, path) {
                        out.push((name.to_string(), v));
                    }
                }
            }
        }
        _ => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg(extractions: Value) -> WorkflowStepConfig {
        let mut c = WorkflowStepConfig::default();
        c.extra.insert("response_extractions".to_string(), extractions);
        c
    }

    #[test]
    fn map_shape() {
        let data = json!({"data": {"token": "abc", "id": 7}});
        let c = cfg(json!({"token": "$.data.token", "id": "$.data.id"}));
        let mut got = apply_response_extractions(&c, &data);
        got.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(got, vec![("id".to_string(), json!(7)), ("token".to_string(), json!("abc"))]);
    }

    #[test]
    fn list_shape() {
        let data = json!({"token": "xyz"});
        let c = cfg(json!([{"key": "t", "path": "$.token"}]));
        assert_eq!(apply_response_extractions(&c, &data), vec![("t".to_string(), json!("xyz"))]);
    }

    #[test]
    fn missing_path_skipped() {
        let data = json!({"a": 1});
        let c = cfg(json!({"gone": "$.b.c"}));
        assert!(apply_response_extractions(&c, &data).is_empty());
    }

    #[test]
    fn no_extractions_empty() {
        let data = json!({"a": 1});
        let c = WorkflowStepConfig::default();
        assert!(apply_response_extractions(&c, &data).is_empty());
    }
}
