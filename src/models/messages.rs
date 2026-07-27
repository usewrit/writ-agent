use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ============================================================
// Client → Server (WS /ws/record)
// ============================================================

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum IncomingRecordMessage {
    Start {
        url: String,
        #[serde(default)]
        options: StartOptions,
    },
    Action {
        action: serde_json::Value,
    },
    Stop,
    AiStart {
        url: String,
        goal: String,
        #[serde(default)]
        data: HashMap<String, String>,
        #[serde(default = "default_max_steps")]
        max_steps: usize,
    },
    Ping,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct StartOptions {
    #[serde(default = "default_true")]
    pub record_wait_steps: bool,
}

fn default_true() -> bool {
    true
}
fn default_max_steps() -> usize {
    20
}

// ============================================================
// Server → Client (WS /ws/record)
// ============================================================

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum OutgoingRecordMessage {
    Started {
        #[serde(rename = "sessionId")]
        session_id: String,
        url: String,
    },
    StepRecorded {
        step: serde_json::Value,
        #[serde(rename = "stepCount")]
        step_count: usize,
    },
    StepUpdated {
        step: serde_json::Value,
        index: usize,
    },
    Navigation {
        url: String,
    },
    SelectOptions {
        selector: String,
        options: Vec<serde_json::Value>,
    },
    NativePicker {
        selector: String,
        #[serde(rename = "pickerType")]
        picker_type: String,
        value: String,
    },
    SensitiveFieldDetected {
        selector: String,
        #[serde(rename = "fieldName")]
        field_name: String,
    },
    TabList {
        tabs: Vec<super::session::TabInfo>,
    },
    AiStatus {
        message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        step: Option<usize>,
        #[serde(skip_serializing_if = "Option::is_none")]
        total: Option<usize>,
    },
    AiComplete {
        steps: Vec<serde_json::Value>,
        #[serde(rename = "stepCount")]
        step_count: usize,
        raw_replay: Vec<serde_json::Value>,
        #[serde(rename = "rawReplayCount")]
        raw_replay_count: usize,
    },
    AiError {
        error: String,
    },
    Stopped {
        steps: Vec<serde_json::Value>,
        #[serde(rename = "stepCount")]
        step_count: usize,
        raw_replay: Vec<serde_json::Value>,
        #[serde(rename = "rawReplayCount")]
        raw_replay_count: usize,
    },
    Pong,
    Error {
        error: String,
    },
}

// ============================================================
// Gateway AI messages
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum GatewayOutgoing {
    AiCompletion {
        request_id: String,
        payload: serde_json::Value,
    },
    SessionOpened {
        session_id: String,
    },
    SessionOpenFailed {
        session_id: String,
        reason: String,
    },
    Pong,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayIncoming {
    #[serde(rename = "type")]
    pub msg_type: Option<String>,
    #[serde(default)]
    pub channel: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub config: Option<serde_json::Value>,
    #[serde(default)]
    pub payload: Option<serde_json::Value>,
    #[serde(default)]
    pub msg: Option<serde_json::Value>,
}

// ============================================================
// Gateway session relay messages (session_id scoped)
// ============================================================

#[derive(Debug, Clone, Deserialize)]
pub struct GatewaySessionCommand {
    #[serde(rename = "type")]
    pub cmd_type: String,
    #[serde(flatten)]
    pub data: HashMap<String, serde_json::Value>,
}

// ============================================================
// Streaming engine messages
// ============================================================

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum StreamingMessage {
    StreamingSessionStarted {
        session_key: String,
        url: String,
        handlers: Vec<String>,
        has_advanced_script: bool,
    },
    StreamingSessionEnded {
        session_key: String,
        reason: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        session_state: Option<serde_json::Value>,
        url: String,
    },
    StreamingError {
        session_key: String,
        error: String,
    },
    StreamingKeepalive {
        session_key: String,
        url: String,
        idle: bool,
        timestamp: f64,
    },
    StreamingEvent {
        session_key: String,
        event_name: String,
        data: serde_json::Value,
        timestamp: f64,
    },
    CommandResponse {
        session_key: String,
        request_id: String,
        data: serde_json::Value,
    },
    StreamChunk {
        session_key: String,
        request_id: String,
        data: serde_json::Value,
    },
}

// ============================================================
// AI task request/response
// ============================================================

#[derive(Debug, Clone, Deserialize)]
pub struct AiTaskRequest {
    pub config: super::workflow::WorkflowConfig,
    #[serde(default)]
    pub task_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiTaskResponse {
    pub success: bool,
    #[serde(default)]
    pub steps: Vec<serde_json::Value>,
    pub step_count: usize,
    #[serde(default)]
    pub raw_replay: Vec<serde_json::Value>,
    pub raw_replay_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_functions: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
