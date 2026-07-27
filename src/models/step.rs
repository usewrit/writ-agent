use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StepType {
    Navigate,
    Click,
    Fill,
    Type,
    Press,
    Select,
    Check,
    Uncheck,
    Scroll,
    Wait,
    Screenshot,
    Hover,
    Focus,
    Captcha,
    SolveCaptcha,
    EndPoint,
    Evaluate,
    Extract,
    WaitForChange,
    ApiCall,
    AiFillForm,
    AiFill,
    AiContinue,
    AiNavigate,
    Codegen,
    Return,
    ScrollIntoView,
    NavigatedTo,
    WaitForTab,
    OpenTab,
    TabClosed,
    SwitchTab,
    Twofa,
    Upload,
    WaitForDownload,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordedStep {
    #[serde(rename = "type")]
    pub step_type: StepType,
    pub timestamp: f64,
    #[serde(default = "generate_id")]
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coordinates: Option<Coordinates>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub viewport: Option<ViewportSize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<HashMap<String, serde_json::Value>>,
}

fn generate_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Coordinates {
    pub x: i32,
    pub y: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewportSize {
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayStep {
    pub index: usize,
    #[serde(rename = "type")]
    pub step_type: String,
    pub icon: String,
    pub title: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default = "default_true")]
    pub editable: bool,
}

fn default_true() -> bool {
    true
}

pub const STEP_ICONS: &[(&str, &str)] = &[
    ("navigate", "🌐"),
    ("click", "👆"),
    ("fill", "✏️"),
    ("type", "⌨️"),
    ("press", "⏎"),
    ("select", "📋"),
    ("check", "☑️"),
    ("uncheck", "⬜"),
    ("scroll", "📜"),
    ("wait", "⏳"),
    ("screenshot", "📷"),
    ("hover", "🖱️"),
    ("focus", "🎯"),
    ("captcha", "🤖"),
    ("evaluate", "⚡"),
    ("extract", "📤"),
    ("wait_for_change", "👁️"),
    ("api_call", "🔌"),
    ("login_post", "🔑"),
    ("end_point", "🏁"),
    ("upload", "📎"),
    ("wait_for_download", "📥"),
];

pub fn icon_for_step(step_type: &str) -> &'static str {
    STEP_ICONS
        .iter()
        .find(|(t, _)| *t == step_type)
        .map(|(_, icon)| *icon)
        .unwrap_or("▶️")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawReplayStep {
    #[serde(rename = "type")]
    pub step_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta_y: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_before: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub viewport: Option<ViewportSize>,
    /// Human-behavior layer: the operator's real cursor trajectory captured
    /// before a `click` step (same `{x, y, t}` shape as the Python recorder).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mouse_path: Option<Vec<MousePathSample>>,
    /// Human-behavior layer: real inter-key delays (ms) for a `type`/`fill` burst.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_timings: Option<Vec<u64>>,
    pub timestamp: f64,
}

/// One sample of the operator's mouse trajectory; `t` is ms since the first
/// sample of the gesture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MousePathSample {
    pub x: f64,
    pub y: f64,
    pub t: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepsInput {
    pub steps: Vec<serde_json::Value>,
    #[serde(default = "default_workflow_name")]
    pub name: String,
    #[serde(default)]
    pub description: String,
}

fn default_workflow_name() -> String {
    "Recorded Workflow".to_string()
}
