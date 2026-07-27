//! Live AI-preview streaming — a process-global fan-out of screencast frames + "thinking" events
//! for in-flight AI sessions / concierge missions, so the FE `GET /ws/ai-preview/:key` WebSocket can
//! WATCH what the AI is doing without ever touching the DB.
//!
//! A running loop calls [`register`] (keyed `ai-{id}` / `concierge-{id}`), spawns a screencast task
//! ([`spawn_screencast`]) on a clone of its live page, and emits per-step `thought` events. The
//! returned [`PreviewHandle`] deregisters the channel on drop (spectators then see the broadcast
//! close). A late-joining spectator gets the retained last frame immediately.
//!
//! Frames reuse the recorder's binary wire format
//! (`crate::browser::screenshot::ScreencastStream::encode_frame` = `[4B BE url_len][url][jpeg]`) so
//! the FE decodes AI-preview frames with the exact same code path as recording spectate. Nothing is
//! persisted here — this is the ephemeral LIVE channel; replay keyframes are stored separately
//! (`crate::local::store::ai_preview_steps`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use dashmap::DashMap;
use playwright_rs::Page;
use tokio::sync::{broadcast, Mutex};

use crate::browser::screenshot::ScreencastStream;
use crate::local::ai::observation;
use crate::local::auth;
use crate::local::server::AppState;

/// Screencast cadence — ~2.5 fps. Cheap enough to run alongside the AI loop's own page calls, smooth
/// enough to read as a live view (parity intent with the recorder spectate feel).
const FRAME_INTERVAL_MS: u64 = 400;
/// Broadcast ring size. Screenshot frames are lossy-droppable (a lagged spectator just skips to the
/// newest), so a small ring is fine and bounds memory.
const CHANNEL_CAP: usize = 8;
/// Screencast JPEG quality for the LIVE stream (smaller than the model-facing q70; smoothness > fidelity).
const LIVE_QUALITY: u8 = 55;

/// One live event on a preview channel.
#[derive(Clone)]
pub enum PreviewEvent {
    /// A screencast frame already in the binary wire format `[4B BE url_len][url][jpeg]`.
    Frame(Arc<Vec<u8>>),
    /// A JSON text line (a `thought` / `status` event) forwarded to the spectator as a WS Text frame.
    Text(Arc<String>),
}

struct Channel {
    tx: broadcast::Sender<PreviewEvent>,
    /// The most recent encoded frame, replayed to a spectator the instant it connects so the preview
    /// is never blank while waiting for the next screencast tick.
    last_frame: Mutex<Option<Arc<Vec<u8>>>>,
    /// Hash of the last frame's JPEG bytes — identical frames are not re-broadcast (static page → no
    /// bytes on the wire).
    last_hash: Mutex<u64>,
    /// The live page to screencast. Set at register (AI session / streaming — a stable page) or
    /// swapped per browse tool (concierge). `None` → the lazy screencast idles (nothing to shoot).
    page: Mutex<Option<Page>>,
    /// Guards a SINGLE lazy screencast task. It is NOT started at session registration — only when the
    /// first spectator connects (`ensure_screencast`), and it self-stops when the last one leaves. So a
    /// session that nobody watches never pays a screenshot, and the browser isn't shot until asked.
    screencast_running: AtomicBool,
}

static REGISTRY: OnceLock<DashMap<String, Arc<Channel>>> = OnceLock::new();
fn registry() -> &'static DashMap<String, Arc<Channel>> {
    REGISTRY.get_or_init(DashMap::new)
}

/// A cloneable producer for a preview channel — the loop keeps one and clones another into the
/// screencast task. Dropping a sender has no side effects (the [`PreviewHandle`] owns deregistration).
#[derive(Clone)]
pub struct PreviewSender {
    channel: Arc<Channel>,
}

impl PreviewSender {
    /// Broadcast a screencast frame (raw JPEG bytes + the page URL). Deduped against the previous
    /// frame (identical bytes dropped) and retained as the "last frame" for late joiners.
    pub async fn send_frame(&self, url: &str, jpeg: &[u8]) {
        if jpeg.is_empty() {
            return;
        }
        let h = ScreencastStream::frame_hash(jpeg);
        {
            let mut last = self.channel.last_hash.lock().await;
            if *last == h {
                return;
            }
            *last = h;
        }
        let framed = Arc::new(ScreencastStream::encode_frame(url, jpeg));
        *self.channel.last_frame.lock().await = Some(framed.clone());
        let _ = self.channel.tx.send(PreviewEvent::Frame(framed));
    }

    /// Broadcast an already-serialized JSON text event.
    pub fn send_text(&self, json: String) {
        let _ = self.channel.tx.send(PreviewEvent::Text(Arc::new(json)));
    }

    /// Broadcast a per-step thinking event: the model's `thought`, a short human `action` summary,
    /// the page `url`, and the session `status`. This is the LIVE half of "see AI thinking" (the same
    /// data is persisted as a replay step).
    pub fn send_thought(&self, step: i64, thought: &str, action: &str, url: &str, status: &str) {
        self.send_text(
            serde_json::json!({
                "type": "thought",
                "step": step,
                "thought": thought,
                "action": action,
                "url": url,
                "status": status,
            })
            .to_string(),
        );
    }

    /// Broadcast a status change (e.g. `running` → `complete`).
    pub fn send_status(&self, status: &str) {
        self.send_text(serde_json::json!({ "type": "status", "status": status }).to_string());
    }

    /// How many spectators are currently subscribed — the screencast loop skips the screenshot cost
    /// entirely when nobody is watching.
    pub fn watcher_count(&self) -> usize {
        self.channel.tx.receiver_count()
    }
}

/// The primary producer handle. Dropping it removes the channel from the registry, closing the
/// broadcast so every spectator's socket ends cleanly. Not `Clone` — clone [`PreviewSender`] instead.
pub struct PreviewHandle {
    key: String,
    sender: PreviewSender,
}

impl PreviewHandle {
    /// A cloneable sender for the screencast task / step reporter.
    pub fn sender(&self) -> PreviewSender {
        self.sender.clone()
    }

    pub fn key(&self) -> &str {
        &self.key
    }
}

impl Drop for PreviewHandle {
    fn drop(&mut self) {
        registry().remove(&self.key);
    }
}

/// Register a fresh preview channel for `key` (no page yet — the producer feeds frames itself, e.g.
/// the concierge via [`set_page`]), replacing any stale entry under the same key.
pub fn register(key: impl Into<String>) -> PreviewHandle {
    register_inner(key, None)
}

/// Register a preview channel bound to a stable live `page` (AI session / streaming). The screencast
/// is NOT started here — it starts lazily on the first spectator ([`ensure_screencast`]) and stops
/// when the last one leaves, so an unwatched session never pays a screenshot.
pub fn register_with_page(key: impl Into<String>, page: Page) -> PreviewHandle {
    register_inner(key, Some(page))
}

fn register_inner(key: impl Into<String>, page: Option<Page>) -> PreviewHandle {
    let key = key.into();
    let (tx, _rx) = broadcast::channel(CHANNEL_CAP);
    let channel = Arc::new(Channel {
        tx,
        last_frame: Mutex::new(None),
        last_hash: Mutex::new(0),
        page: Mutex::new(page),
        screencast_running: AtomicBool::new(false),
    });
    registry().insert(key.clone(), Arc::clone(&channel));
    PreviewHandle {
        key,
        sender: PreviewSender { channel },
    }
}

/// Swap the live page a channel screencasts. The concierge calls this per browse tool — `Some(page)`
/// when a tool opens one, `None` when it closes — so the lazy screencast follows the active page and
/// idles between tools. No-op if `key` isn't registered.
pub async fn set_page(key: &str, page: Option<Page>) {
    if let Some(channel) = registry().get(key).map(|r| Arc::clone(r.value())) {
        *channel.page.lock().await = page;
    }
}

/// Clear a channel's dedup hash so the screencast's NEXT tick emits a frame even if the page is
/// unchanged. Called when a spectator connects: a fresh viewer of a STATIC page would otherwise see
/// nothing (every screenshot deduped against the prior session's), so the preview would stay black on
/// reopen. Resetting forces one current frame to (re)paint the viewport.
async fn force_next_frame(key: &str) {
    if let Some(channel) = registry().get(key).map(|r| Arc::clone(r.value())) {
        *channel.last_hash.lock().await = 0;
    }
}

/// Look up the live sender for `key`, if a session is registered under it. Lets a producer that
/// doesn't hold the [`PreviewHandle`] (e.g. the concierge's per-tool page functions) feed the
/// mission's channel. The handle's `Drop` deregisters unconditionally, so a sender kept alive by an
/// in-flight screencast task never keeps a finished mission in the registry.
pub fn sender_for(key: &str) -> Option<PreviewSender> {
    registry().get(key).map(|r| PreviewSender {
        channel: Arc::clone(r.value()),
    })
}

/// A spectator's view of a channel: a fresh receiver + the retained last frame (if any).
struct Subscription {
    rx: broadcast::Receiver<PreviewEvent>,
    last_frame: Option<Arc<Vec<u8>>>,
}

/// Subscribe to a live channel, if one is registered. Grabs a receiver + a snapshot of the last frame
/// without holding the registry shard lock across the await.
async fn subscribe(key: &str) -> Option<Subscription> {
    let channel = registry().get(key).map(|r| Arc::clone(r.value()))?;
    let rx = channel.tx.subscribe();
    let last_frame = channel.last_frame.lock().await.clone();
    Some(Subscription { rx, last_frame })
}

/// How many consecutive zero-watcher ticks end the lazy screencast — a short grace so a spectator
/// reconnecting (or a quick close→open) doesn't tear the task down and re-spawn it. ~2s at 400ms.
const IDLE_STOP_TICKS: u32 = 5;

/// Ensure a lazy screencast task is running for `key` — called when a spectator CONNECTS, so the
/// browser is only ever shot while someone is watching (never from session start). Idempotent: the
/// `screencast_running` flag guards a single task. The task reads the channel's CURRENT page each
/// tick (so a concierge page swap is picked up), dedups frames, and self-terminates after
/// [`IDLE_STOP_TICKS`] with no watchers — the next spectator restarts it.
fn ensure_screencast(key: &str) {
    let Some(channel) = registry().get(key).map(|r| Arc::clone(r.value())) else {
        return;
    };
    if channel.screencast_running.swap(true, Ordering::AcqRel) {
        return; // already streaming this channel
    }
    let sender = PreviewSender { channel: Arc::clone(&channel) };
    tokio::spawn(async move {
        let mut idle = 0u32;
        loop {
            if sender.watcher_count() == 0 {
                idle += 1;
                if idle >= IDLE_STOP_TICKS {
                    break; // last spectator gone — stop until the next one connects
                }
            } else {
                idle = 0;
                let page = channel.page.lock().await.clone();
                if let Some(page) = page {
                    if let Some(bytes) = observation::capture_screenshot_jpeg(&page, LIVE_QUALITY).await {
                        let url = page.url();
                        sender.send_frame(&url, &bytes).await;
                    }
                    // A failed shot (page navigating / not ready) just retries next tick — the page
                    // handle is refreshed from the channel each iteration, so this survives nav.
                }
                // else: no page bound yet (concierge between tools) — idle a tick.
            }
            tokio::time::sleep(Duration::from_millis(FRAME_INTERVAL_MS)).await;
        }
        channel.screencast_running.store(false, Ordering::Release);
    });
}

/// Downscale + re-encode a JPEG for disk-cheap replay storage: fit within `max_edge` px (long edge,
/// never upscales) and re-encode at `quality`. On any decode/encode failure, returns the original
/// bytes unchanged (still deduped + capped downstream). Keeping this here (not the store) means the
/// store layer takes already-small bytes.
pub fn downscale_jpeg(jpeg: &[u8], max_edge: u32, quality: u8) -> Vec<u8> {
    let Ok(img) = image::load_from_memory_with_format(jpeg, image::ImageFormat::Jpeg) else {
        return jpeg.to_vec();
    };
    let (w, h) = (img.width(), img.height());
    let scaled = if w.max(h) > max_edge {
        img.thumbnail(max_edge, max_edge) // preserves aspect ratio, fast box filter
    } else {
        img
    };
    let mut out = Vec::new();
    let mut enc = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, quality);
    match enc.encode_image(&scaled) {
        Ok(()) => out,
        Err(_) => jpeg.to_vec(),
    }
}

// ── WebSocket route ──────────────────────────────────────────────────────────

/// The AI-preview sub-router. Mounted OUTSIDE the bearer-header `auth_mw` layer (see
/// `server::build_router`) exactly like `/ws/record`: a browser can't set an `Authorization` header
/// on a WebSocket, so this does its own SINGLE-USE `?ticket=` + loopback Origin/Host auth.
pub fn router() -> Router<AppState> {
    Router::new().route("/ws/ai-preview/:key", get(handler))
}

/// `GET /ws/ai-preview/:key` — authenticate (single-use ticket scoped to THIS `key` + loopback
/// guard), then stream the live channel for `key` (`ai-{id}` / `concierge-{id}`). 401 on auth
/// failure; 404 (as a JSON error frame then close) when no session is streaming under that key.
async fn handler(
    ws: WebSocketUpgrade,
    Path(key): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    // Loopback guard, then atomically consume the single-use ticket — scoped to this exact channel
    // key, so a ticket for one session can't be used to watch another. Spent regardless of outcome.
    let ticket = query.get("ticket").map(|s| s.as_str()).unwrap_or("");
    if !auth::ws_origin_allowed(origin, host, state.config.port)
        || !crate::local::ws_ticket::consume(ticket, crate::local::ws_ticket::WsRoute::AiPreview, Some(&key))
    {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    ws.on_upgrade(move |socket| stream_to_spectator(socket, key)).into_response()
}

/// Forward channel events to the spectator socket until the channel closes or the peer disconnects.
async fn stream_to_spectator(mut socket: WebSocket, key: String) {
    let Some(sub) = subscribe(&key).await else {
        let _ = socket
            .send(Message::Text(
                serde_json::json!({ "type": "error", "message": "not streaming" }).to_string(),
            ))
            .await;
        let _ = socket.close().await;
        return;
    };
    let Subscription { mut rx, last_frame } = sub;

    // A spectator is here — start the screencast lazily (no-op if it's already running for another
    // watcher). This is why the browser is never shot until someone opens the preview.
    ensure_screencast(&key);
    // Force the next tick to emit a frame even on a static page, so a REOPENED preview repaints
    // instead of staying black (every screenshot would otherwise dedup against the prior session's).
    force_next_frame(&key).await;

    // Greet + hand over the retained frame immediately so the viewport paints without waiting a tick.
    let _ = socket
        .send(Message::Text(
            serde_json::json!({ "type": "preview_started", "key": key }).to_string(),
        ))
        .await;
    if let Some(frame) = last_frame {
        if socket.send(Message::Binary((*frame).clone())).await.is_err() {
            return;
        }
    }

    loop {
        tokio::select! {
            evt = rx.recv() => match evt {
                Ok(PreviewEvent::Frame(bytes)) => {
                    if socket.send(Message::Binary((*bytes).clone())).await.is_err() {
                        break;
                    }
                }
                Ok(PreviewEvent::Text(txt)) => {
                    if socket.send(Message::Text((*txt).clone())).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    // A slow spectator missed frames — harmless, resume at the newest.
                }
                Err(broadcast::error::RecvError::Closed) => {
                    let _ = socket
                        .send(Message::Text(
                            serde_json::json!({ "type": "preview_ended" }).to_string(),
                        ))
                        .await;
                    break;
                }
            },
            msg = socket.recv() => match msg {
                Some(Ok(Message::Text(text)))
                    if serde_json::from_str::<serde_json::Value>(&text)
                        .ok()
                        .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(str::to_string))
                        .as_deref()
                        == Some("ping")
                    => {
                        let _ = socket
                            .send(Message::Text(serde_json::json!({ "type": "pong" }).to_string()))
                            .await;
                    }
                Some(Ok(Message::Ping(_))) => {
                    let _ = socket.send(Message::Pong(vec![])).await;
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                _ => {}
            },
        }
    }
}
