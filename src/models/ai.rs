use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action")]
#[serde(rename_all = "snake_case")]
pub enum AiAction {
    Fill {
        #[serde(skip_serializing_if = "Option::is_none")]
        field_index: Option<usize>,
        #[serde(skip_serializing_if = "Option::is_none")]
        data_key: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        value: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        x: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        y: Option<f64>,
    },
    Select {
        #[serde(skip_serializing_if = "Option::is_none")]
        field_index: Option<usize>,
        #[serde(skip_serializing_if = "Option::is_none")]
        value: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        x: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        y: Option<f64>,
    },
    Check {
        #[serde(skip_serializing_if = "Option::is_none")]
        field_index: Option<usize>,
        #[serde(skip_serializing_if = "Option::is_none")]
        x: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        y: Option<f64>,
    },
    Click {
        #[serde(skip_serializing_if = "Option::is_none")]
        x: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        y: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        button_index: Option<usize>,
        #[serde(skip_serializing_if = "Option::is_none")]
        button_text: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    Submit {
        #[serde(skip_serializing_if = "Option::is_none")]
        button_index: Option<usize>,
        #[serde(skip_serializing_if = "Option::is_none")]
        button_text: Option<String>,
    },
    Scroll {
        #[serde(default)]
        direction: String,
        #[serde(default = "default_scroll_amount")]
        amount: i32,
    },
    ScrollToField {
        field_index: usize,
    },
    Hover {
        #[serde(skip_serializing_if = "Option::is_none")]
        field_index: Option<usize>,
        #[serde(skip_serializing_if = "Option::is_none")]
        x: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        y: Option<f64>,
    },
    PressKey {
        key: String,
    },
    EvaluateJs {
        script: String,
    },
    ExtractData {
        #[serde(skip_serializing_if = "Option::is_none")]
        selector: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        variable: Option<String>,
    },
    Wait {
        #[serde(default = "default_wait_seconds")]
        seconds: f64,
    },
    WaitFor {
        #[serde(skip_serializing_if = "Option::is_none")]
        selector: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        condition: Option<String>,
    },
    SolveCaptcha,
    InspectField {
        field_index: usize,
    },
    ReadText {
        #[serde(skip_serializing_if = "Option::is_none")]
        selector: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        region: Option<[f64; 4]>,
    },
    ListTabs,
    SwitchTab {
        #[serde(default)]
        tab_index: usize,
    },
    WaitForTab {
        #[serde(skip_serializing_if = "Option::is_none")]
        url_contains: Option<String>,
        #[serde(default = "default_timeout_sec")]
        timeout_sec: f64,
    },
    CloseTab {
        #[serde(default)]
        tab_index: usize,
    },
    Batch {
        actions: Vec<serde_json::Value>,
    },
    Complete {
        #[serde(skip_serializing_if = "Option::is_none")]
        success: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    Blocked {
        reason: String,
    },
    Retry {
        #[serde(skip_serializing_if = "Option::is_none")]
        x: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        y: Option<f64>,
    },
}

fn default_scroll_amount() -> i32 {
    300
}
fn default_wait_seconds() -> f64 {
    1.0
}
fn default_timeout_sec() -> f64 {
    10.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAnalysisResult {
    pub status: String,
    #[serde(default)]
    pub actions: Vec<serde_json::Value>,
    #[serde(default)]
    pub needs_scroll: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub submit_button: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionVerification {
    pub verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionHistoryEntry {
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub step_number: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiCompletionRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub messages: Vec<AiMessage>,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    #[serde(default = "default_purpose")]
    pub purpose: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
}

fn default_max_tokens() -> u32 {
    500
}
fn default_purpose() -> String {
    "workflow".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiMessage {
    pub role: String,
    pub content: AiMessageContent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AiMessageContent {
    Text(String),
    Parts(Vec<AiContentPart>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum AiContentPart {
    Text { text: String },
    Image { source: ImageSource },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageSource {
    #[serde(rename = "type")]
    pub source_type: String,
    pub media_type: String,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiFunction {
    pub name: String,
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default)]
    pub response_extractions: Vec<ResponseExtraction>,
    #[serde(default)]
    pub is_auth: bool,
    #[serde(default)]
    pub order: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseExtraction {
    pub key: String,
    pub path: String,
}
