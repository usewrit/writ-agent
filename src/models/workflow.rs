use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::session::SessionState;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AINavigationStatus {
    Completed,
    Partial,
    Failed,
    MissingData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowResult {
    pub success: bool,
    #[serde(default)]
    pub cookies: Vec<serde_json::Value>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub local_storage: HashMap<String, String>,
    #[serde(default)]
    pub session_storage: HashMap<String, String>,
    #[serde(default)]
    pub extracted_data: HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub screenshots: Vec<ScreenshotData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub steps_completed: usize,
    #[serde(default)]
    pub captcha_detected: bool,
    #[serde(default)]
    pub session_expired: bool,
    #[serde(default)]
    pub ai_repair_attempted: bool,
    #[serde(default)]
    pub ai_repair_success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_repair_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_repair_data: Option<serde_json::Value>,
}

impl WorkflowResult {
    pub fn to_auth_session(&self) -> SessionState {
        SessionState {
            cookies: self.cookies.clone(),
            headers: self.headers.clone(),
            local_storage: self.local_storage.clone(),
            session_storage: self.session_storage.clone(),
            extracted_at: Some(chrono::Utc::now().to_rfc3339()),
            fingerprint: None,
            tokens: None,
        }
    }

    pub fn failure(error: String) -> Self {
        Self {
            success: false,
            error: Some(error),
            cookies: Vec::new(),
            headers: HashMap::new(),
            local_storage: HashMap::new(),
            session_storage: HashMap::new(),
            extracted_data: HashMap::new(),
            screenshots: Vec::new(),
            steps_completed: 0,
            captcha_detected: false,
            session_expired: false,
            ai_repair_attempted: false,
            ai_repair_success: false,
            ai_repair_type: None,
            ai_repair_data: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenshotData {
    pub step: usize,
    #[serde(rename = "type")]
    pub screenshot_type: String,
    pub timestamp: f64,
    #[serde(with = "base64_bytes")]
    pub data: Vec<u8>,
}

mod base64_bytes {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(&s)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AINavigationResult {
    pub status: AINavigationStatus,
    #[serde(default)]
    pub steps_executed: Vec<ExecutedStep>,
    #[serde(default)]
    pub form_data_used: HashMap<String, String>,
    #[serde(default)]
    pub missing_data: Vec<String>,
    #[serde(default)]
    pub extracted_data: HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub screenshots: Vec<ScreenshotData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutedStep {
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowConfig {
    pub url: String,
    pub goal: String,
    #[serde(default)]
    pub user_context: Option<String>,
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub available_data: HashMap<String, String>,
    #[serde(default)]
    pub form_data: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials_encrypted: Option<String>,
    #[serde(default)]
    pub secure_keys: Vec<String>,
    #[serde(default = "default_max_steps")]
    pub max_steps: usize,
    #[serde(default = "default_max_actions")]
    pub max_actions: usize,
    #[serde(default = "default_true")]
    pub use_vision: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress_callback_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

fn default_mode() -> String {
    "standard".to_string()
}
fn default_max_steps() -> usize {
    20
}
fn default_max_actions() -> usize {
    50
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointResult {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    #[serde(default)]
    pub success_indicators: Vec<String>,
    #[serde(default)]
    pub error_indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    pub id: String,
    #[serde(rename = "type")]
    pub step_type: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub config: WorkflowStepConfig,
}

/// Deserialize an `Option<String>` that TOLERATES a JSON number or bool in the slot, coercing it to
/// its plain text form. Recorded/imported `wait` steps mirror the duration into `value` as well as
/// `duration`; older desktop builds and cloud recipes wrote `value` as the RAW number (e.g. `10000`),
/// which a strict `Option<String>` rejects — and because ONE bad field fails the WHOLE
/// `WorkflowStepConfig`, the step is silently skipped at run time. Coercing keeps such steps runnable
/// (the wait executor parses `value` back to f64). A real string passes through unchanged; null /
/// absent → `None`.
fn de_opt_string_lenient<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct LenientString;
    impl<'de> serde::de::Visitor<'de> for LenientString {
        type Value = Option<String>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a string, number, boolean, or null")
        }
        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
            Ok(Some(v.to_string()))
        }
        fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
            Ok(Some(v))
        }
        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
            Ok(Some(v.to_string()))
        }
        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
            Ok(Some(v.to_string()))
        }
        fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E> {
            Ok(Some(v.to_string()))
        }
        fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
            Ok(Some(v.to_string()))
        }
        fn visit_none<E>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_unit<E>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_some<D2>(self, d: D2) -> Result<Self::Value, D2::Error>
        where
            D2: serde::Deserializer<'de>,
        {
            d.deserialize_any(self)
        }
    }
    deserializer.deserialize_option(LenientString)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkflowStepConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    // Tolerate a numeric/bool `value` (e.g. a `wait` step's `value: 10000`) — see
    // `de_opt_string_lenient`. Without this the whole step config fails to parse and is skipped.
    #[serde(
        default,
        deserialize_with = "de_opt_string_lenient",
        skip_serializing_if = "Option::is_none"
    )]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coordinates: Option<super::step::Coordinates>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub viewport: Option<super::step::ViewportSize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recognition: Option<serde_json::Value>,
    // --- File-asset step fields (upload / wait_for_download). See FILE_ASSETS_IMPLEMENTATION_PLAN §6.1. ---
    /// Stored-file handle ("file_<id>") bound to an upload step (owner runs only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_id: Option<String>,
    /// File SLOT name for shared/marketplace workflows; the buyer binds slot -> their own file_id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_slot: Option<String>,
    /// Whether the target file input accepts multiple files.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_multiple: Option<bool>,
    /// Upload mode: "input" (set on an <input type=file>) or "chooser" (click a trigger, intercept the chooser).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Name a captured download so it can be reused (chained) in a later step/workflow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_key: Option<String>,
    /// Optional selector to click inside expect_download to trigger a download.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger_selector: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workflow {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_workflow_type")]
    pub workflow_type: String,
    pub steps: Vec<WorkflowStep>,
    #[serde(default)]
    pub form_data: HashMap<String, String>,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_retry")]
    pub retry_count: u32,
    #[serde(default = "default_true")]
    pub headless: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_replay: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub session_persistence: bool,
    /// Human-behavior layer config from the dispatch (same field the Python
    /// engine reads: truthy → replay recorded mouse_path/key_timings, synthesize
    /// otherwise). Absent/false → unchanged legacy behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_layer: Option<serde_json::Value>,
}

fn default_workflow_type() -> String {
    "recorded".to_string()
}
fn default_timeout() -> u64 {
    60000
}
fn default_retry() -> u32 {
    2
}

#[cfg(test)]
mod step_config_tests {
    use super::WorkflowStepConfig;

    /// A `wait` step recorded/imported with a NUMERIC `value` (the historical bug source) must still
    /// parse — `value` is coerced to its string form rather than failing the whole step config.
    #[test]
    fn numeric_value_is_coerced_to_string() {
        let cfg: WorkflowStepConfig =
            serde_json::from_value(serde_json::json!({ "duration": 10000, "value": 10000 })).unwrap();
        assert_eq!(cfg.value.as_deref(), Some("10000"));
        assert_eq!(cfg.duration, Some(10000.0));
    }

    /// A real string `value`, a bool, and an absent `value` are all handled.
    #[test]
    fn string_bool_and_absent_value() {
        let s: WorkflowStepConfig =
            serde_json::from_value(serde_json::json!({ "value": "hello" })).unwrap();
        assert_eq!(s.value.as_deref(), Some("hello"));

        let b: WorkflowStepConfig =
            serde_json::from_value(serde_json::json!({ "value": true })).unwrap();
        assert_eq!(b.value.as_deref(), Some("true"));

        let none: WorkflowStepConfig =
            serde_json::from_value(serde_json::json!({ "selector": "#x" })).unwrap();
        assert_eq!(none.value, None);
    }
}
