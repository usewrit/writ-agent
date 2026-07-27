use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, Mutex};

use super::step::{RecordedStep, RawReplayStep};
use crate::automation::network_capture::NetworkCapture;
use crate::models::network::NetworkCall;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingFill {
    pub selector: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recognition: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub element_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub element_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_sensitive: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autocomplete: Option<String>,
    pub timestamp: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingPicker {
    pub selector: String,
    #[serde(rename = "type")]
    pub picker_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingSlider {
    pub selector: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingDropdown {
    pub selector: String,
    #[serde(rename = "type")]
    pub dropdown_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingScroll {
    pub total_delta_y: f64,
    pub container_selector: Option<String>,
    pub x: f64,
    pub y: f64,
    pub start_time: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FocusClick {
    pub selector: String,
    pub timestamp: f64,
}

pub struct RecordingSession {
    pub session_id: String,
    pub page: playwright_rs::Page,
    pub context: playwright_rs::BrowserContext,
    pub steps: Vec<RecordedStep>,
    pub raw_replay_steps: Vec<RawReplayStep>,
    pub is_recording: bool,
    pub start_url: String,
    pub current_url: String,
    pub created_at: Instant,

    pub last_step_timestamp: f64,
    pub last_raw_step_timestamp: f64,
    pub min_wait_threshold_ms: u64,
    pub record_wait_steps: bool,

    pub pending_fill: Option<PendingFill>,
    pub pending_picker: Option<PendingPicker>,
    pub pending_slider: Option<PendingSlider>,
    pub pending_dropdown: Option<PendingDropdown>,
    pub pending_dropdown_nav: Option<PendingDropdown>,
    pub pending_scroll: Option<PendingScroll>,
    pub last_focus_click: Option<FocusClick>,
    pub last_captcha_step: Option<f64>,
    /// True once a 2FA `twofa` step has been auto-emitted for this recording, so we
    /// emit exactly one (and suppress the literal-code fills, incl. segmented boxes).
    pub twofa_emitted: bool,

    /// Human-behavior layer: downsampled cursor trajectory streamed by the
    /// frontend as `mousemove` actions; drained into the next `click` raw step.
    pub mouse_path_buf: Vec<crate::models::step::MousePathSample>,
    /// Wall-clock (secs) of the first buffered mouse sample; 0.0 when empty.
    pub mouse_path_started_at: f64,
    /// Human-behavior layer: real inter-key delays (ms) accumulated across the
    /// `type` actions of one field; drained into the flushed `type`/`fill` raw step.
    pub key_timing_buf: Vec<u64>,

    pub last_activity: Instant,
    pub tenant_id: Option<String>,

    /// Broadcast channel for screenshot frames (binary: [4B url_len][url_utf8][jpeg_bytes]).
    pub screenshot_tx: Option<broadcast::Sender<Vec<u8>>>,

    /// Handle for the background screenshot streaming task so we can abort it on stop.
    pub screenshot_task: Option<tokio::task::JoinHandle<()>>,

    /// Channel for JSON events sent to the frontend (step_recorded, navigation, select_options, etc.)
    /// Exact same events Python sends via session.websocket.send_json()
    pub event_tx: Option<tokio::sync::mpsc::UnboundedSender<serde_json::Value>>,

    /// Receiver half of the event channel. The WebSocket handler takes this after
    /// start_session and spawns a task to forward JSON events to the frontend.
    /// Without this, all step_recorded/navigation events are silently discarded.
    pub event_rx: Option<tokio::sync::mpsc::UnboundedReceiver<serde_json::Value>>,

    /// Passive network traffic capture (XHR/Fetch + document POSTs).
    /// Shared `Arc<Mutex<>>` so the context request/response listeners can record
    /// into it without ever touching the session `DashMap` (the listeners hold a
    /// clone of this Arc, never `sessions.get_mut()` — avoids the documented
    /// recording-path worker-starvation deadlock). Attached only when API capture
    /// is enabled for the session.
    pub network_capture: Arc<Mutex<NetworkCapture>>,

    /// Spectator broadcast channel for read-only live preview WebSockets.
    /// Python uses session.spectators: List[WebSocket]; we use a broadcast channel.
    pub spectator_tx: Option<broadcast::Sender<Vec<u8>>>,

    /// Cooperative cancel flag for an in-flight visual replay ("play to here").
    /// A `replay_cancel` frame flips this true; the replay loop (running in its
    /// own task) checks it between steps. Mirrors Python's `session._replay_cancel`.
    pub replay_cancel: Arc<std::sync::atomic::AtomicBool>,
}

impl std::fmt::Debug for RecordingSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordingSession")
            .field("session_id", &self.session_id)
            .field("start_url", &self.start_url)
            .field("current_url", &self.current_url)
            .field("steps", &self.steps.len())
            .field("is_recording", &self.is_recording)
            .finish()
    }
}

impl RecordingSession {
    pub fn new(
        session_id: String,
        start_url: String,
        tenant_id: Option<String>,
        page: playwright_rs::Page,
        context: playwright_rs::BrowserContext,
    ) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            page,
            context,
            steps: Vec::new(),
            raw_replay_steps: Vec::new(),
            is_recording: true,
            start_url: start_url.clone(),
            current_url: start_url,
            created_at: now,
            last_step_timestamp: 0.0,
            last_raw_step_timestamp: 0.0,
            min_wait_threshold_ms: 500,
            record_wait_steps: true,
            pending_fill: None,
            pending_picker: None,
            pending_slider: None,
            pending_dropdown: None,
            pending_dropdown_nav: None,
            pending_scroll: None,
            last_focus_click: None,
            last_captcha_step: None,
            twofa_emitted: false,
            mouse_path_buf: Vec::new(),
            mouse_path_started_at: 0.0,
            key_timing_buf: Vec::new(),
            last_activity: now,
            tenant_id,
            screenshot_tx: None,
            screenshot_task: None,
            event_tx: None,
            event_rx: None,
            network_capture: Arc::new(Mutex::new(NetworkCapture::new())),
            spectator_tx: None,
            replay_cancel: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Send a JSON event to the frontend (step_recorded, navigation, etc.)
    /// Exact same as Python's session.websocket.send_json()
    pub fn send_event(&self, event: serde_json::Value) {
        if let Some(ref tx) = self.event_tx {
            let _ = tx.send(event);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionResult {
    pub steps: Vec<RecordedStep>,
    pub raw_replay: Vec<RawReplayStep>,
    pub step_count: usize,
    pub raw_replay_count: usize,
    /// API calls (XHR/fetch + document POSTs) captured while recording, when API
    /// capture was enabled. The backend synthesizes these into callable api_functions.
    #[serde(default)]
    pub network_calls: Vec<NetworkCall>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub start_url: String,
    pub current_url: String,
    pub step_count: usize,
    pub idle_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TabInfo {
    pub index: usize,
    pub url: String,
    pub title: String,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    #[serde(default)]
    pub cookies: Vec<serde_json::Value>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default, rename = "localStorage")]
    pub local_storage: HashMap<String, String>,
    #[serde(default, rename = "sessionStorage")]
    pub session_storage: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extracted_at: Option<String>,
    /// Browser fingerprint (user_agent/locale/timezone) used when this auth was
    /// captured. Restored on "warm" runs so the session stays a returning user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<serde_json::Value>,
    /// HTTP-lane token store (AuthRecipe): `{NAME: {value, expires_at?, header?, prefix?, cookie_name?}}`.
    /// Bearer/refresh/csrf tokens a browserless login produced, replayed on later requests and re-minted
    /// by the refresh ladder. Additive & optional — the cloud persists the whole auth_session blob
    /// opaquely, so this rides through save/load without a schema change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<serde_json::Value>,
}
