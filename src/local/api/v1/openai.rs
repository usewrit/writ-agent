//! OpenAI-compatible surface for the Writ desktop local backend.
//!
//! Lets any OpenAI client (SDK, `curl`, an agent framework) call a recorded workflow as if it were
//! a chat model. Each enabled workflow becomes one "model" id `writ:workflow:<id>`; a
//! `chat/completions` or `responses` request whose `model` names that workflow runs it through the
//! in-process [`LocalEngine`] and returns the extracted data as the assistant turn.
//!
//! ## Two modes
//! - **`stream:false`** (default) — run the workflow ONCE via `engine.run(...)` and return a single
//!   completion object whose assistant message carries the extracted data (one shot, non-incremental).
//! - **`stream:true`** — drive ONE turn of a long-lived STREAMING session via `engine.run_streaming`
//!   and proxy the page's `ps.stream(...)` chunks into an SSE `text/event-stream`. The wire format
//!   depends on the surface: `chat/completions` emits OpenAI `chat.completion.chunk` objects
//!   terminated by `data: [DONE]`; `responses` emits the OpenAI **Responses** event sequence
//!   (`response.created` → `response.output_text.delta`* → `response.completed`) — a Responses client
//!   validates every event against that union and rejects chat chunks, so the two must not be mixed
//!   (mirrors the cloud `streaming-service` `_stream_responses`). Only meaningful for a workflow whose
//!   recipe is a streaming chat (advanced_script + handlers); a plain workflow with no handler yields
//!   a single terminal event.
//!
//! ## Inputs (so `{{input.*}}` resolves)
//! A chat request is not just a model selector — its `messages` / an `input` object / tool-call
//! arguments carry the run's INPUTS. We derive a flat `{message, messages, input.NAME, NAME}` object
//! from the request and pass it as the run `inputs` so the engine's `resolve.rs` fills `{{input.*}}`
//! and bare `{{NAME}}` placeholders. Honors `streaming_config.openai_compat.response_field` for which
//! key of the result becomes the assistant content.
//!
//! Model id contract: `writ:workflow:<id>` where `<id>` is the workflows-table primary key. We parse
//! the suffix, 404 if no such (active) workflow exists, and build a `RunRequest{source:Api,
//! lane:Interactive}` — the same seam the REST `/v1/workflows/:id/run` path uses. No auth layer here
//! — `server.rs` applies the loopback bearer + Origin/Host guard at the router level.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use crate::local::engine::streaming::{turn_timeout, LocalStreamingManager};
use crate::local::engine::{Lane, RunRequest, RunResult, RunSource, RunStatus, StreamEvent};
use crate::local::error::{LocalError, LocalResult};
use crate::local::server::AppState;
use crate::local::store::workflows;
use axum::extract::{Path, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::stream::{self, Stream};
use futures_util::StreamExt as _;
use serde::Deserialize;
use serde_json::{json, Value};

/// Prefix that marks an OpenAI `model` string as "run this Writ workflow".
const MODEL_PREFIX: &str = "writ:workflow:";

/// Mount the OpenAI-compat routes onto the shared `AppState` router. Auth is applied by `server.rs`.
pub fn router() -> Router<AppState> {
    Router::new()
        // The OpenAI CALL surface is PER-WORKFLOW only (cloud parity): each workflow has its OWN base
        // URL `…/v1/workflows/{id}/v1`, so an SDK is pointed straight at a single workflow (the
        // workflow comes from the PATH; the request `model` field is optional). There is deliberately
        // NO global `/v1/chat/completions` — that diverged from the cloud, where you call a workflow
        // at its own slug. Toggling a workflow's OpenAI surface OFF (Connect tab) makes these 404 /
        // list nothing.
        .route("/v1/workflows/:id/v1/models", get(wf_models))
        .route("/v1/workflows/:id/v1/chat/completions", post(wf_chat_completions))
        .route("/v1/workflows/:id/v1/responses", post(wf_responses))
        // `/v1/models` is kept ONLY as a local DISCOVERY list of callable workflows (it backs the
        // app's Endpoints page + MCP overview). It is NOT paired with a global execute endpoint.
        .route("/v1/models", get(list_models))
}

// ── Request shapes ──────────────────────────────────────────────────────────
//
// We accept the OpenAI request envelopes and consume the fields that map onto a workflow run:
// `model` (selects the workflow), `stream` (SSE vs one-shot), and the inputs surfaces (`messages`,
// `input`, tool/function `tools`). Sampling fields (temperature, …) are accepted-and-ignored so
// off-the-shelf clients don't error on extra keys; serde drops unknown fields by default.

/// `POST /v1/chat/completions` body. `messages` (+ optional `input`/`tools`) carry the run inputs;
/// `stream` selects SSE vs one-shot.
#[derive(Debug, Deserialize)]
struct ChatRequest {
    /// Optional on the per-workflow base (the workflow comes from the path); required on the global
    /// `/v1/chat/completions` route (validated by `parse_model`).
    #[serde(default)]
    model: String,
    #[serde(default)]
    stream: bool,
    /// Chat transcript. The LAST user message's text becomes the `message` input + bare `{{NAME}}`
    /// is filled from a structured `input` object / tool args (see [`derive_inputs`]).
    #[serde(default)]
    messages: Vec<Value>,
    /// Optional structured inputs object (`{NAME: value}`) — a convenience alongside `messages`.
    #[serde(default)]
    input: Option<Value>,
    /// OpenAI tool/function declarations; when a message carries a tool_call we lift its arguments
    /// into the inputs (so a tool-calling agent can pass named fields).
    #[serde(default)]
    tools: Option<Value>,
}

/// `POST /v1/responses` body (OpenAI Responses API envelope). Same model-selection + inputs contract.
/// The Responses API uses `input` (string or array of items) rather than `messages`.
#[derive(Debug, Deserialize)]
struct ResponsesRequest {
    /// Optional on the per-workflow base (the workflow comes from the path); required on the global
    /// `/v1/responses` route (validated by `parse_model`).
    #[serde(default)]
    model: String,
    #[serde(default)]
    stream: bool,
    /// Responses-API input: a bare string, or an array of input items (`{role, content}`).
    #[serde(default)]
    input: Option<Value>,
    /// Some clients send `messages` to the Responses endpoint too — accept it as a fallback.
    #[serde(default)]
    messages: Vec<Value>,
    /// Responses-API SYSTEM prompt. It is a TOP-LEVEL field here (not an input item), so without
    /// capturing it the run never sees it — the caller's agent/tool protocol lives in this prompt, so
    /// dropping it makes the model reply with prose. We surface it into the run inputs (see
    /// [`derive_responses_inputs`]).
    #[serde(default)]
    instructions: Option<String>,
}

// ── Token metering (live usage gauge) ────────────────────────────────────────
//
// When a workflow's OpenAI surface is called through its live streaming session, we meter the turn's
// input/output tokens onto the session so the desktop live page shows running in/out consumption.
// This is a ROUGH count (≈4 chars/token, the cloud's tiktoken-less fallback) — a live operator gauge,
// not a billing figure. Metering is a no-op when there is no live streaming session (e.g. a one-shot
// engine with no warm browser, or a not-yet-started session).

/// Rough token count for the live usage gauge: ≈4 chars/token, matching the cloud
/// `_count_tokens` fallback (`max(1, (len+3)/4)` for non-empty text).
fn count_tokens(text: &str) -> u64 {
    if text.is_empty() {
        return 0;
    }
    text.len().div_ceil(4) as u64
}

/// The input text a request carries, for the input-token count: the full transcript's message text
/// when present (`inputs.messages`), else the last-user `inputs.message`. Works for both the chat and
/// responses surfaces since both derive the same `{message, messages}` inputs shape.
fn input_text_of(inputs: &Value) -> String {
    if let Some(arr) = inputs.get("messages").and_then(|v| v.as_array()) {
        let joined = arr
            .iter()
            .map(|m| content_text(m.get("content")))
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        if !joined.is_empty() {
            return joined;
        }
    }
    inputs
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// Meters one turn's token usage onto a workflow's live streaming session. `tokens_in` is fixed for
/// the turn (the request text, counted up front); [`Self::record`] adds it together with the
/// output-token count when the reply text is known (stream terminal / one-shot result).
struct TokenMeter {
    mgr: Arc<LocalStreamingManager>,
    workflow_id: i64,
    tokens_in: u64,
}

impl TokenMeter {
    fn record(&self, output_text: &str) {
        self.mgr
            .record_tokens(self.workflow_id, self.tokens_in, count_tokens(output_text));
    }
}

/// Build a [`TokenMeter`] for a turn, or `None` when the engine has no streaming manager (no live
/// session to meter onto). `inputs` is counted here so the input tokens are captured before dispatch.
fn token_meter(st: &AppState, workflow_id: i64, inputs: &Value) -> Option<TokenMeter> {
    st.engine.streaming().map(|mgr| TokenMeter {
        mgr,
        workflow_id,
        tokens_in: count_tokens(&input_text_of(inputs)),
    })
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// `GET /v1/models` — a local DISCOVERY list of callable workflows (one entry per active workflow,
/// id `writ:workflow:<id>`), shaped like the OpenAI models list. This is NOT an OpenAI execute
/// pairing (there is no global completion endpoint); it backs the app's Endpoints page + MCP
/// overview, so it lists every active workflow regardless of per-surface toggles. The actual
/// per-surface gating happens at each workflow's own call endpoints.
async fn list_models(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    // active_only=true → soft-deleted workflows never surface.
    let rows = workflows::list(&st.db, true, 1000).await?;
    let created = chrono::Utc::now().timestamp();
    let data: Vec<Value> = rows
        .iter()
        .map(|wf| {
            json!({
                "id": format!("{MODEL_PREFIX}{}", wf.id),
                "object": "model",
                "created": created,
                "owned_by": "writ",
                "name": wf.name,
                "description": wf.description,
            })
        })
        .collect();
    Ok(Json(json!({ "object": "list", "data": data })))
}

// ── Per-workflow OpenAI base (cloud parity) ──────────────────────────────────────
//
// Each workflow has its OWN OpenAI base URL `…/v1/workflows/{id}/v1`, so an SDK can be pointed at a
// single workflow (the cloud's `…/streaming/workflows/{id}/v1` shape). The workflow comes from the
// PATH — `body.model` is optional and only used as the echoed response label. The same surface
// toggle gates these: with OpenAI OFF the model lists nothing and execution 404s.

/// Resolve the path workflow and assert its OpenAI surface is enabled, or map to a 404 (so a disabled
/// per-workflow base behaves like a non-existent model).
async fn require_openai_workflow(st: &AppState, id: i64) -> LocalResult<workflows::Workflow> {
    let wf = workflows::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("workflow {id}")))?;
    if !wf.connect_surfaces().openai {
        return Err(LocalError::NotFound(format!("workflow {id} is not exposed via OpenAI")));
    }
    Ok(wf)
}

/// `GET /v1/workflows/:id/v1/models` — the workflow's own model list: exactly this workflow when its
/// OpenAI surface is on (and it's active), else an empty list.
async fn wf_models(State(st): State<AppState>, Path(id): Path<i64>) -> LocalResult<Json<Value>> {
    let created = chrono::Utc::now().timestamp();
    let data: Vec<Value> = match workflows::get_by_id(&st.db, id).await? {
        Some(wf) if wf.is_active != 0 && wf.connect_surfaces().openai => vec![json!({
            "id": format!("{MODEL_PREFIX}{}", wf.id),
            "object": "model",
            "created": created,
            "owned_by": "writ",
            "name": wf.name,
            "description": wf.description,
        })],
        _ => Vec::new(),
    };
    Ok(Json(json!({ "object": "list", "data": data })))
}

/// `POST /v1/workflows/:id/v1/chat/completions` — workflow taken from the path (not `model`).
async fn wf_chat_completions(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<ChatRequest>,
) -> LocalResult<Response> {
    let wf = require_openai_workflow(&st, id).await?;
    let label = if body.model.is_empty() { format!("{MODEL_PREFIX}{id}") } else { body.model.clone() };
    let inputs = derive_inputs(&body.messages, body.input.as_ref(), body.tools.as_ref());
    let meter = token_meter(&st, id, &inputs);
    if body.stream {
        return chat_stream(&st, wf, inputs, label, meter).await;
    }
    let field = response_field(&wf);
    // A STREAMING (chat) workflow's whole point is its warm long-lived session — ALWAYS drive a turn
    // on that session (launching it on first use via run_streaming's find-or-start), never a one-off
    // run. A plain (non-streaming) workflow still runs one-off, unless it already has a live session.
    let result = if wf.workflow_type == "streaming" || has_live_session(&st, id) {
        drive_streaming_turn(&st, wf, inputs).await?
    } else {
        run_workflow(&st, id, inputs).await?
    };
    if let Some(m) = &meter {
        m.record(&assistant_content(&result, field.as_deref()));
    }
    Ok(Json(chat_completion_object(&label, &result, field.as_deref())).into_response())
}

/// `POST /v1/workflows/:id/v1/responses` — Responses-API sibling, workflow from the path.
async fn wf_responses(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<ResponsesRequest>,
) -> LocalResult<Response> {
    let wf = require_openai_workflow(&st, id).await?;
    let label = if body.model.is_empty() { format!("{MODEL_PREFIX}{id}") } else { body.model.clone() };
    let inputs = derive_responses_inputs(body.input.as_ref(), &body.messages, body.instructions.as_deref());
    let meter = token_meter(&st, id, &inputs);
    if body.stream {
        // The Responses surface streams Responses-API *events*, NOT chat.completion.chunk objects.
        return responses_stream(&st, wf, inputs, label, meter).await;
    }
    let field = response_field(&wf);
    // Same as chat/completions: a STREAMING workflow always drives a turn on its session (launched on
    // first use), never a one-off run; a plain workflow runs one-off unless a session is already live.
    let result = if wf.workflow_type == "streaming" || has_live_session(&st, id) {
        drive_streaming_turn(&st, wf, inputs).await?
    } else {
        run_workflow(&st, id, inputs).await?
    };
    if let Some(m) = &meter {
        m.record(&assistant_content(&result, field.as_deref()));
    }
    Ok(Json(response_object(&label, &result, field.as_deref())).into_response())
}

// ── Streaming (SSE) ────────────────────────────────────────────────────────────

/// Drive ONE streamed turn and return an SSE `text/event-stream` of OpenAI `chat.completion.chunk`
/// objects. Each [`StreamEvent::Chunk`] becomes a delta chunk (`choices[0].delta.content`); the
/// terminal [`StreamEvent::Done`] flushes the final content (the `response_field` of the payload,
/// if not already streamed) + a `finish_reason:"stop"` chunk; an [`StreamEvent::Error`] becomes a
/// `finish_reason:"error"` chunk. The stream always ends with `data: [DONE]`.
async fn chat_stream(
    st: &AppState,
    wf: workflows::Workflow,
    inputs: Value,
    model: String,
    meter: Option<TokenMeter>,
) -> LocalResult<Response> {
    let (rx, field) = st.engine.run_streaming(wf, inputs).await?;
    let completion_id = format!("chatcmpl-writ-{}", uuid::Uuid::new_v4().simple());
    let created = chrono::Utc::now().timestamp();
    let timeout = turn_timeout();

    // The chunk stream yields `Value`s (testable); map each to an SSE `data:` event here.
    let sse = chunk_value_stream(rx, completion_id, created, model, field, timeout, meter)
        .map(|v| Ok::<Event, Infallible>(Event::default().data(value_to_sse_data(&v))));
    Ok(Sse::new(sse)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response())
}

/// Serialize a chunk `Value` to its SSE `data:` payload: the terminal sentinel `Value::String("[DONE]")`
/// becomes the literal `[DONE]`; any other value is its JSON encoding (a `chat.completion.chunk`).
fn value_to_sse_data(v: &Value) -> String {
    match v {
        Value::String(s) if s == DONE_SENTINEL => DONE_SENTINEL.to_string(),
        other => other.to_string(),
    }
}

/// The terminal SSE payload OpenAI clients expect after the last chunk.
const DONE_SENTINEL: &str = "[DONE]";

/// Build the chunk stream (as JSON `Value`s) from a turn receiver. State machine over
/// [`StreamEvent`]s, yielding `chat.completion.chunk` objects then a final `[DONE]` sentinel:
/// - `Chunk{content}` → a delta chunk; record that text was streamed so the terminal `Done` does
///   not duplicate a `response_field` value the page already streamed token-by-token.
/// - `Done{data}` → if NOTHING was streamed yet, flush the resolved final content as one delta; then
///   always a `finish_reason:"stop"` chunk.
/// - `Error{message}` → the message as a delta with `finish_reason:"error"`.
/// - receiver closed without a terminal → a defensive `stop` chunk.
/// - per-turn timeout → an `error` chunk.
/// Every path ends with the `[DONE]` sentinel.
fn chunk_value_stream(
    rx: tokio::sync::mpsc::UnboundedReceiver<StreamEvent>,
    completion_id: String,
    created: i64,
    model: String,
    response_field: String,
    timeout: Duration,
    meter: Option<TokenMeter>,
) -> impl Stream<Item = Value> {
    // `pending` holds a buffered chunk to emit on the NEXT poll (used to emit a stop chunk after an
    // all-at-once content delta, without the rx.close() hack). `done` ends the body stream. `out`
    // accumulates the assistant text so the terminal can meter output tokens; `meter` fires once.
    struct S {
        rx: tokio::sync::mpsc::UnboundedReceiver<StreamEvent>,
        streamed: bool,
        done: bool,
        pending: Option<Value>,
        out: String,
        meter: Option<TokenMeter>,
    }
    let init = S { rx, streamed: false, done: false, pending: None, out: String::new(), meter };

    stream::unfold(init, move |mut s| {
        let completion_id = completion_id.clone();
        let model = model.clone();
        let response_field = response_field.clone();
        async move {
            // Flush a buffered chunk first (the owed stop chunk after an all-at-once content delta).
            if let Some(buffered) = s.pending.take() {
                return Some((buffered, s));
            }
            if s.done {
                return None;
            }
            let mk = |content: &str, finish: Option<&str>| {
                delta_chunk(&completion_id, created, &model, content, finish)
            };
            match tokio::time::timeout(timeout, s.rx.recv()).await {
                Ok(Some(StreamEvent::Chunk { content })) => {
                    s.streamed = true;
                    s.out.push_str(&content);
                    Some((mk(&content, None), s))
                }
                Ok(Some(StreamEvent::Done { data })) => {
                    s.done = true;
                    let final_content = final_content_of(&data, &response_field);
                    // Meter the delivered assistant text (streamed chunks, or the all-at-once flush).
                    let delivered = if s.streamed { s.out.clone() } else { final_content.clone() };
                    if let Some(m) = s.meter.take() {
                        m.record(&delivered);
                    }
                    if !s.streamed && !final_content.is_empty() {
                        // All-at-once: emit the content delta now, buffer the stop chunk for next poll.
                        s.pending = Some(mk("", Some("stop")));
                        Some((mk(&final_content, None), s))
                    } else {
                        Some((mk("", Some("stop")), s))
                    }
                }
                Ok(Some(StreamEvent::Error { message })) => {
                    s.done = true;
                    // Record only what was genuinely streamed as content (not the error text).
                    if let Some(m) = s.meter.take() {
                        m.record(&s.out);
                    }
                    Some((mk(&message, Some("error")), s))
                }
                Ok(None) => {
                    s.done = true;
                    if let Some(m) = s.meter.take() {
                        m.record(&s.out);
                    }
                    Some((mk("", Some("stop")), s))
                }
                Err(_) => {
                    s.done = true;
                    if let Some(m) = s.meter.take() {
                        m.record(&s.out);
                    }
                    Some((mk("handler did not respond (timed out)", Some("error")), s))
                }
            }
        }
    })
    // Always terminate with the literal `[DONE]` sentinel OpenAI clients expect.
    .chain(stream::once(async { Value::String(DONE_SENTINEL.to_string()) }))
}

/// Build one `chat.completion.chunk` object. `content` goes into `choices[0].delta.content` (omitted
/// when empty so a pure `finish_reason` chunk has an empty delta); `finish` sets
/// `choices[0].finish_reason` (None mid-stream).
fn delta_chunk(id: &str, created: i64, model: &str, content: &str, finish: Option<&str>) -> Value {
    let mut delta = serde_json::Map::new();
    if !content.is_empty() {
        delta.insert("content".into(), Value::String(content.to_string()));
    }
    json!({
        "id": id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [{
            "index": 0,
            "delta": Value::Object(delta),
            "finish_reason": finish,
        }],
    })
}

/// Resolve the final assistant content from a terminal `Done` payload: the configured
/// `response_field`, else `content`, else the whole payload pretty-printed (so the client always
/// gets SOMETHING). A bare-string payload is returned as-is.
fn final_content_of(data: &Value, response_field: &str) -> String {
    match data {
        Value::String(s) => s.clone(),
        Value::Object(obj) => {
            if let Some(v) = obj.get(response_field).filter(|v| !v.is_null()) {
                return value_as_text(v);
            }
            if let Some(v) = obj.get("content").filter(|v| !v.is_null()) {
                return value_as_text(v);
            }
            pretty(data)
        }
        // A bare blocks-array payload (`ps.respond(id, [{type:"text", …}])`) → flatten to its text.
        other => value_as_text(other),
    }
}

/// A JSON value as assistant text: a string stays bare; a multimodal content-blocks list is
/// flattened to its text; anything else is pretty-JSON.
fn value_as_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => blocks_to_text(other).unwrap_or_else(|| pretty(other)),
    }
}

/// If `v` is a recognizable multimodal content-blocks list — `[{type:"text", text:"…"}, …]` (also
/// `input_text` / `output_text`) or bare strings, the shape a chat handler yields via `ps.respond` —
/// concatenate the text of its text blocks (newline-joined, mirroring the cloud
/// `_extract_text_from_content`). Returns `None` for anything that is NOT a blocks list, so a plain
/// data array like `[1, 2, 3]` still renders as JSON.
fn blocks_to_text(v: &Value) -> Option<String> {
    let arr = v.as_array()?;
    // A blocks list = non-empty and every element is a string or an object carrying a `type` tag.
    // This keeps plain data arrays (numbers, untyped objects) out of this path.
    let is_blocks = !arr.is_empty()
        && arr
            .iter()
            .all(|b| b.is_string() || b.get("type").and_then(|t| t.as_str()).is_some());
    if !is_blocks {
        return None;
    }
    let parts: Vec<String> = arr
        .iter()
        .filter_map(|b| match b {
            Value::String(s) => Some(s.clone()),
            _ => {
                let t = b.get("type").and_then(|t| t.as_str());
                if matches!(t, Some("text") | Some("input_text") | Some("output_text")) {
                    Some(b.get("text").and_then(|v| v.as_str()).unwrap_or("").to_string())
                } else {
                    None
                }
            }
        })
        .collect();
    Some(parts.join("\n"))
}

// ── Responses API streaming (SSE) ────────────────────────────────────────────────
//
// The Responses API is a DIFFERENT wire protocol from chat/completions: a Responses client validates
// every SSE event against the Responses event union and rejects `chat.completion.chunk` objects. We
// therefore emit the same event sequence the cloud `streaming-service` `_stream_responses` does:
//   response.created
//   → response.output_item.added (the assistant message item)
//   → response.content_part.added (an empty output_text part)
//   → response.output_text.delta*  (one per streamed chunk; or one all-at-once flush on Done)
//   → response.output_text.done → response.content_part.done → response.output_item.done
//   → response.completed
// Every event carries a monotonic `sequence_number` and its SSE `event:` name mirrors the payload
// `type`. A dispatch failure / timeout collapses to a single `response.failed` (after the always-first
// prologue). We do NOT emit image-generation items — the local engine never produces them.

/// Drive ONE streamed turn and return an SSE `text/event-stream` of OpenAI *Responses API* events.
/// This is the Responses-API sibling of [`chat_stream`] — same turn seam, different wire protocol.
async fn responses_stream(
    st: &AppState,
    wf: workflows::Workflow,
    inputs: Value,
    model: String,
    meter: Option<TokenMeter>,
) -> LocalResult<Response> {
    let (rx, field) = st.engine.run_streaming(wf, inputs).await?;
    let response_id = format!("resp-writ-{}", uuid::Uuid::new_v4().simple());
    let created = chrono::Utc::now().timestamp();
    let timeout = turn_timeout();

    let sse = response_event_stream(rx, response_id, created, model, field, timeout, meter).map(|v| {
        // OpenAI sets BOTH the SSE `event:` name and a `type` inside `data`; the SDK switches on the
        // `type`, other clients on the event name — so we mirror `type` into the event name.
        let name = v.get("type").and_then(|t| t.as_str()).unwrap_or("message").to_string();
        Ok::<Event, Infallible>(Event::default().event(name).data(v.to_string()))
    });
    Ok(Sse::new(sse)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response())
}

/// Build the Responses-API event stream (as JSON `Value`s) from a turn receiver. The three prologue
/// events are queued up front (drained before we ever wait on the handler); each [`StreamEvent`] then
/// appends deltas or a terminal group, and the queue is drained in order. No `[DONE]` sentinel — the
/// Responses protocol ends on `response.completed` / `response.failed`.
fn response_event_stream(
    rx: tokio::sync::mpsc::UnboundedReceiver<StreamEvent>,
    response_id: String,
    created: i64,
    model: String,
    response_field: String,
    timeout: Duration,
    meter: Option<TokenMeter>,
) -> impl Stream<Item = Value> {
    let msg_id = format!("msg-writ-{}", uuid::Uuid::new_v4().simple());

    struct S {
        rx: tokio::sync::mpsc::UnboundedReceiver<StreamEvent>,
        queue: std::collections::VecDeque<Value>,
        seq: i64,
        streamed: bool,
        accumulated: String,
        ended: bool,
        meter: Option<TokenMeter>,
    }

    // Prologue: created → output_item.added → content_part.added, queued so the first polls drain
    // them before the handler is even awaited (OpenAI always leads with `response.created`).
    let mut queue = std::collections::VecDeque::new();
    let mut seq = 0i64;
    seq += 1;
    queue.push_back(json!({
        "type": "response.created",
        "sequence_number": seq,
        "response": response_object_skeleton(&response_id, &model, created, "in_progress", json!([]), None),
    }));
    seq += 1;
    queue.push_back(json!({
        "type": "response.output_item.added",
        "sequence_number": seq,
        "output_index": 0,
        "item": message_item(&msg_id, "in_progress", None),
    }));
    seq += 1;
    queue.push_back(json!({
        "type": "response.content_part.added",
        "sequence_number": seq,
        "item_id": msg_id,
        "output_index": 0,
        "content_index": 0,
        "part": { "type": "output_text", "text": "", "annotations": [] },
    }));

    let init = S { rx, queue, seq, streamed: false, accumulated: String::new(), ended: false, meter };

    stream::unfold(init, move |mut s| {
        let response_id = response_id.clone();
        let msg_id = msg_id.clone();
        let model = model.clone();
        let response_field = response_field.clone();
        async move {
            // Drain any queued events first (prologue, then the terminal group).
            if let Some(ev) = s.queue.pop_front() {
                return Some((ev, s));
            }
            if s.ended {
                return None;
            }
            match tokio::time::timeout(timeout, s.rx.recv()).await {
                Ok(Some(StreamEvent::Chunk { content })) => {
                    s.streamed = true;
                    s.accumulated.push_str(&content);
                    s.seq += 1;
                    Some((json!({
                        "type": "response.output_text.delta",
                        "sequence_number": s.seq,
                        "item_id": msg_id,
                        "output_index": 0,
                        "content_index": 0,
                        "delta": content,
                    }), s))
                }
                Ok(Some(StreamEvent::Done { data })) => {
                    let ft = final_content_of(&data, &response_field);
                    let final_text = if ft.is_empty() { s.accumulated.clone() } else { ft };
                    if let Some(m) = s.meter.take() {
                        m.record(&final_text);
                    }
                    enqueue_completion(
                        &mut s.queue, &mut s.seq, &response_id, &msg_id, &model, created,
                        s.streamed, &final_text,
                    );
                    s.ended = true;
                    s.queue.pop_front().map(|ev| (ev, s))
                }
                Ok(Some(StreamEvent::Error { message })) => {
                    // Record only what genuinely streamed as content (the error itself is not output).
                    if let Some(m) = s.meter.take() {
                        m.record(&s.accumulated);
                    }
                    enqueue_failed(&mut s.queue, &mut s.seq, &response_id, &model, created, &message);
                    s.ended = true;
                    s.queue.pop_front().map(|ev| (ev, s))
                }
                Ok(None) => {
                    // Receiver closed without a terminal — complete with whatever streamed so far.
                    let acc = s.accumulated.clone();
                    if let Some(m) = s.meter.take() {
                        m.record(&acc);
                    }
                    enqueue_completion(
                        &mut s.queue, &mut s.seq, &response_id, &msg_id, &model, created,
                        s.streamed, &acc,
                    );
                    s.ended = true;
                    s.queue.pop_front().map(|ev| (ev, s))
                }
                Err(_) => {
                    if let Some(m) = s.meter.take() {
                        m.record(&s.accumulated);
                    }
                    enqueue_failed(
                        &mut s.queue, &mut s.seq, &response_id, &model, created,
                        "handler did not respond (timed out)",
                    );
                    s.ended = true;
                    s.queue.pop_front().map(|ev| (ev, s))
                }
            }
        }
    })
}

/// Queue the terminal group for a successful turn: an all-at-once `output_text.delta` (only when the
/// page returned everything in the `Done` payload without streaming a token), then the closing
/// `output_text.done` → `content_part.done` → `output_item.done` → `response.completed`.
fn enqueue_completion(
    queue: &mut std::collections::VecDeque<Value>,
    seq: &mut i64,
    response_id: &str,
    msg_id: &str,
    model: &str,
    created: i64,
    streamed: bool,
    final_text: &str,
) {
    if !final_text.is_empty() && !streamed {
        *seq += 1;
        queue.push_back(json!({
            "type": "response.output_text.delta",
            "sequence_number": *seq,
            "item_id": msg_id, "output_index": 0, "content_index": 0,
            "delta": final_text,
        }));
    }
    *seq += 1;
    queue.push_back(json!({
        "type": "response.output_text.done",
        "sequence_number": *seq,
        "item_id": msg_id, "output_index": 0, "content_index": 0,
        "text": final_text,
    }));
    *seq += 1;
    queue.push_back(json!({
        "type": "response.content_part.done",
        "sequence_number": *seq,
        "item_id": msg_id, "output_index": 0, "content_index": 0,
        "part": { "type": "output_text", "text": final_text, "annotations": [] },
    }));
    *seq += 1;
    queue.push_back(json!({
        "type": "response.output_item.done",
        "sequence_number": *seq,
        "output_index": 0,
        "item": message_item(msg_id, "completed", Some(final_text)),
    }));
    // The completed response's `output` omits the message when there is no text (cloud parity).
    let output = if final_text.is_empty() {
        json!([])
    } else {
        json!([message_item(msg_id, "completed", Some(final_text))])
    };
    *seq += 1;
    queue.push_back(json!({
        "type": "response.completed",
        "sequence_number": *seq,
        "response": response_object_skeleton(response_id, model, created, "completed", output, None),
    }));
}

/// Queue a single `response.failed` terminal (dispatch failure / timeout), carrying the error message.
fn enqueue_failed(
    queue: &mut std::collections::VecDeque<Value>,
    seq: &mut i64,
    response_id: &str,
    model: &str,
    created: i64,
    message: &str,
) {
    *seq += 1;
    queue.push_back(json!({
        "type": "response.failed",
        "sequence_number": *seq,
        "response": response_object_skeleton(response_id, model, created, "failed", json!([]), Some(message)),
    }));
}

// ── Inputs derivation ────────────────────────────────────────────────────────

/// Derive the run `inputs` object from a chat request so `{{input.*}}` / bare `{{NAME}}` resolve.
///
/// Produces a flat object combining:
///   - `message`: the LAST user message's text (chat handlers read this).
///   - `messages`: the full transcript (so a streaming advanced script can see history).
///   - each key of a structured `input` object, AND every tool-call argument object found in the
///     transcript, flattened so a bare `{{NAME}}` resolves (resolve.rs also exposes `input.NAME`).
fn derive_inputs(messages: &[Value], input: Option<&Value>, _tools: Option<&Value>) -> Value {
    let mut obj = serde_json::Map::new();

    let last_user = last_user_text(messages);
    if !last_user.is_empty() {
        obj.insert("message".into(), Value::String(last_user));
    }
    if !messages.is_empty() {
        obj.insert("messages".into(), Value::Array(messages.to_vec()));
    }

    // Structured `input` object → flatten its keys.
    if let Some(Value::Object(map)) = input {
        for (k, v) in map {
            obj.insert(k.clone(), v.clone());
        }
    } else if let Some(Value::String(s)) = input {
        // A bare string `input` is an alias for the user message.
        obj.entry("message".to_string())
            .or_insert_with(|| Value::String(s.clone()));
    }

    // Tool-call arguments anywhere in the transcript → flatten (assistant tool_calls or a function
    // message). Arguments are JSON-stringified per the OpenAI schema, so parse then merge.
    for m in messages {
        merge_tool_call_args(m, &mut obj);
    }

    // Surface the SYSTEM prompt (a `role:"system"` message) as `inputs.system` so a streaming
    // advanced_script can forward it to the LLM it proxies. The agent/tool protocol lives in the
    // system prompt; without it the model replies with prose (chat/completions carries system as a
    // message, so it's already in `messages` — this just also exposes it as a named field).
    let sys = system_text(messages);
    if !sys.is_empty() {
        obj.entry("system".to_string()).or_insert_with(|| Value::String(sys.clone()));
        obj.entry("instructions".to_string()).or_insert_with(|| Value::String(sys));
    }

    Value::Object(obj)
}

/// The text of the first `role:"system"` message, or "" if none. Mirrors [`last_user_text`].
fn system_text(messages: &[Value]) -> String {
    for m in messages {
        if m.get("role").and_then(|v| v.as_str()) == Some("system") {
            return content_text(m.get("content"));
        }
    }
    String::new()
}

/// Responses-API inputs: `input` may be a bare string (the user turn) or an array of items
/// (`{role, content}`), falling back to `messages`. Reuses [`derive_inputs`] once normalized.
///
/// `instructions` is the Responses-API SYSTEM prompt (a top-level field, NOT an input item). We inject
/// it into the derived inputs — as `inputs.system`/`inputs.instructions` AND as a prepended
/// `role:"system"` message — so the workflow (and the LLM it proxies) actually receives it. Without
/// this a caller's agent/tool-protocol system prompt is silently dropped and the model returns prose.
fn derive_responses_inputs(input: Option<&Value>, messages: &[Value], instructions: Option<&str>) -> Value {
    let mut v = match input {
        Some(Value::Array(items)) => derive_inputs(items, None, None),
        Some(Value::String(s)) => {
            // A single user turn.
            let synth = vec![json!({ "role": "user", "content": s })];
            derive_inputs(&synth, None, None)
        }
        Some(obj @ Value::Object(_)) => derive_inputs(messages, Some(obj), None),
        _ => derive_inputs(messages, None, None),
    };
    if let Some(sys) = instructions.map(str::trim).filter(|s| !s.is_empty()) {
        if let Value::Object(obj) = &mut v {
            obj.insert("system".into(), json!(sys));
            obj.insert("instructions".into(), json!(sys));
            // Prepend a system message so a script that forwards `messages` includes it (unless the
            // input already carried its own system turn).
            let mut msgs = obj.get("messages").and_then(|m| m.as_array()).cloned().unwrap_or_default();
            let has_system = msgs.iter().any(|m| m.get("role").and_then(|r| r.as_str()) == Some("system"));
            if !has_system {
                msgs.insert(0, json!({ "role": "system", "content": sys }));
            }
            obj.insert("messages".into(), Value::Array(msgs));
        }
    }
    v
}

/// The text of the last `role:"user"` message. `content` may be a plain string OR a multimodal
/// array of parts (`[{type:"text", text:"..."}, ...]`); we concatenate the text parts.
fn last_user_text(messages: &[Value]) -> String {
    for m in messages.iter().rev() {
        if m.get("role").and_then(|v| v.as_str()) == Some("user") {
            return content_text(m.get("content"));
        }
    }
    // No explicit user turn → fall back to the last message's text (whatever its role).
    messages
        .last()
        .map(|m| content_text(m.get("content")))
        .unwrap_or_default()
}

/// Flatten a message `content` to plain text: a string is returned as-is; a parts array
/// concatenates the `text` of each `{type:"text", text}` (and `{type:"input_text", text}`) part.
fn content_text(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(parts)) => parts
            .iter()
            .filter_map(|p| {
                let t = p.get("type").and_then(|v| v.as_str());
                if matches!(t, Some("text") | Some("input_text") | None) {
                    p.get("text").and_then(|v| v.as_str()).map(String::from)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join(""),
        _ => String::new(),
    }
}

/// If `m` carries tool/function call arguments, parse them (the args are a JSON STRING per the
/// OpenAI schema) and merge each key into `obj` (so a tool-calling agent can pass named inputs).
/// Existing keys are NOT overwritten (an explicit `input`/message field wins).
fn merge_tool_call_args(m: &Value, obj: &mut serde_json::Map<String, Value>) {
    // Modern: assistant message with `tool_calls: [{function: {arguments: "<json>"}}]`.
    if let Some(calls) = m.get("tool_calls").and_then(|v| v.as_array()) {
        for c in calls {
            if let Some(args) = c.get("function").and_then(|f| f.get("arguments")) {
                merge_args_value(args, obj);
            }
        }
    }
    // Legacy: a single `function_call: {arguments: "<json>"}`.
    if let Some(args) = m.get("function_call").and_then(|f| f.get("arguments")) {
        merge_args_value(args, obj);
    }
}

/// Merge a tool-call `arguments` value (a JSON string, or already an object) into `obj` without
/// clobbering existing keys.
fn merge_args_value(args: &Value, obj: &mut serde_json::Map<String, Value>) {
    let parsed = match args {
        Value::String(s) => serde_json::from_str::<Value>(s).ok(),
        other => Some(other.clone()),
    };
    if let Some(Value::Object(map)) = parsed {
        for (k, v) in map {
            obj.entry(k).or_insert(v);
        }
    }
}

// ── Run + result mapping ───────────────────────────────────────────────────────

/// Run the workflow once via the shared engine seam with `source:Api, lane:Interactive`, passing the
/// derived `inputs` so `{{input.*}}` resolves. The workflow's existence was already checked by the
/// caller (so a missing workflow surfaced a clean 404 before this).
async fn run_workflow(st: &AppState, id: i64, inputs: Value) -> LocalResult<RunResult> {
    let req = RunRequest {
        workflow_id: id,
        inputs,
        source: RunSource::Api,
        lane: Lane::Interactive,
        dry_run: false,
        persona_id: None,
        allow_local_secret_refs: true,
    };
    st.engine.run(req).await
}

/// Whether this workflow currently has a LIVE streaming session (a warm chat tab). A non-streaming
/// (`stream:false`) request for such a workflow should drive a TURN on that session rather than spawn
/// a fresh one-off run — the chat/streaming state lives in the warm session.
fn has_live_session(st: &AppState, id: i64) -> bool {
    st.engine.streaming().and_then(|m| m.get_session(id)).is_some()
}

/// Drive ONE turn on the workflow's LIVE streaming session (reused via `run_streaming`, which is
/// find-or-start) and AGGREGATE the streamed chunks + terminal payload into a single [`RunResult`], so
/// the ordinary non-streaming completion builders can render it. This is what lets a `stream:false`
/// caller (e.g. the desktop's own AI provider client pointed at this workflow) reuse the user's already-
/// running chat session instead of starting a new short run.
async fn drive_streaming_turn(st: &AppState, wf: workflows::Workflow, inputs: Value) -> LocalResult<RunResult> {
    let (mut rx, field) = st.engine.run_streaming(wf, inputs).await?;
    let timeout = turn_timeout();
    let mut text = String::new();
    let mut done: Option<Value> = None;
    loop {
        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(Some(StreamEvent::Chunk { content })) => text.push_str(&content),
            Ok(Some(StreamEvent::Done { data })) => {
                done = Some(data);
                break;
            }
            Ok(Some(StreamEvent::Error { message })) => return Err(LocalError::Internal(message)),
            Ok(None) => break, // channel closed without a terminal event
            Err(_) => return Err(LocalError::Internal("streaming turn timed out".into())),
        }
    }
    // Prefer the structured terminal payload (`ps.respond`); fall back to the concatenated chunk text
    // when the payload doesn't carry the response field. `field` from run_streaming is "" when the
    // recipe declares no response field.
    let key = if field.trim().is_empty() { "response".to_string() } else { field.clone() };
    let extracted = match done {
        Some(d) => {
            let has_content = if field.trim().is_empty() { !d.is_null() } else { d.get(&field).is_some() };
            if !has_content && !text.is_empty() {
                json!({ key: text })
            } else {
                d
            }
        }
        None => json!({ key: text }),
    };
    Ok(RunResult {
        run_id: 0,
        status: RunStatus::Success,
        success: true,
        error: None,
        extracted_data: extracted,
        duration_ms: 0,
    })
}

/// The configured OpenAI `response_field` (`streaming_config.openai_compat.response_field`), if any.
/// Selects which key of a result/extracted_data object becomes the assistant content. `None` →
/// fall back to the generic single-key/whole-object rendering.
fn response_field(wf: &workflows::Workflow) -> Option<String> {
    let sc: Value = wf
        .streaming_config
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(Value::Null);
    sc.get("openai_compat")
        .and_then(|o| o.get("response_field"))
        .and_then(|v| v.as_str())
        .map(String::from)
}

/// Flatten a [`RunResult`] into the assistant message text:
/// - failure → `{"success":false,"error":...}` so the caller always gets structured signal;
/// - a configured `response_field` present in `extracted_data` → that key's value (bare string / JSON);
/// - success with exactly one extracted key → that key's value (pretty-JSON if non-string);
/// - success with 0 or 2+ keys → pretty-JSON of the whole `extracted_data` object.
fn assistant_content(result: &RunResult, response_field: Option<&str>) -> String {
    if !result.success {
        let body = json!({ "success": false, "error": result.error });
        return pretty(&body);
    }
    if let Some(obj) = result.extracted_data.as_object() {
        // Honor the configured response_field first.
        if let Some(field) = response_field {
            if let Some(v) = obj.get(field).filter(|v| !v.is_null()) {
                return value_as_text(v);
            }
        }
        if obj.len() == 1 {
            let only = obj.values().next().expect("len==1 has one value");
            return value_as_text(only);
        }
    }
    // Non-object extracted data (e.g. a bare content-blocks array) → flatten/JSON via value_as_text.
    value_as_text(&result.extracted_data)
}

/// Pretty-print JSON, falling back to the compact `Display` form if serialization somehow fails
/// (it won't for an in-memory `Value`, but we never want this helper to panic).
fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
}

/// Map an OpenAI `finish_reason` from the run outcome (`stop` on success, `error` otherwise).
fn finish_reason(result: &RunResult) -> &'static str {
    if result.success {
        "stop"
    } else {
        "error"
    }
}

/// Build a single `chat.completion` object (non-streamed). `id` carries the engine `run_id` for
/// traceability; usage is zeroed (a workflow run has no token accounting).
fn chat_completion_object(model: &str, result: &RunResult, response_field: Option<&str>) -> Value {
    json!({
        "id": format!("chatcmpl-writ-{}", result.run_id),
        "object": "chat.completion",
        "created": chrono::Utc::now().timestamp(),
        "model": model,
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": assistant_content(result, response_field),
            },
            "finish_reason": finish_reason(result),
        }],
        "usage": {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        },
    })
}

/// Build a single (non-streamed) Responses-API `response` object with one assistant `message` item
/// carrying an `output_text` part. Mirrors the chat-completion content rules and the same full-shape
/// `response` envelope the streaming `response.completed` event uses (so a strict Responses client
/// validates both paths identically).
fn response_object(model: &str, result: &RunResult, response_field: Option<&str>) -> Value {
    let content = assistant_content(result, response_field);
    let msg_id = format!("msg-writ-{}", result.run_id);
    let item_status = if result.success { "completed" } else { "incomplete" };
    let output = if content.is_empty() {
        json!([])
    } else {
        json!([message_item(&msg_id, item_status, Some(&content))])
    };
    let status = if result.success { "completed" } else { "failed" };
    let error = if result.success { None } else { result.error.as_deref() };
    response_object_skeleton(
        &format!("resp-writ-{}", result.run_id),
        model,
        chrono::Utc::now().timestamp(),
        status,
        output,
        error,
    )
}

/// One assistant `message` output item (`{type:"message", …, content:[{type:"output_text", …}]}`).
/// `text: None` yields an empty `content` array (the in-progress placeholder used at stream start).
fn message_item(msg_id: &str, status: &str, text: Option<&str>) -> Value {
    let content = match text {
        Some(t) => json!([{ "type": "output_text", "text": t, "annotations": [] }]),
        None => json!([]),
    };
    json!({
        "type": "message",
        "id": msg_id,
        "status": status,
        "role": "assistant",
        "content": content,
    })
}

/// Build a complete OpenAI Responses-API `response` object (mirrors the cloud `_build_response_object`
/// so a strict client's schema validation passes). `status` is `in_progress` / `completed` / `failed`;
/// `output` is the (possibly empty) output-item array; `error` populates `error` on failure.
fn response_object_skeleton(
    id: &str,
    model: &str,
    created: i64,
    status: &str,
    output: Value,
    error: Option<&str>,
) -> Value {
    json!({
        "id": id,
        "object": "response",
        "created_at": created,
        "status": status,
        "completed_at": if status == "completed" { Value::from(created) } else { Value::Null },
        "error": error.map(|e| json!({ "code": "run_failed", "message": e })).unwrap_or(Value::Null),
        "incomplete_details": Value::Null,
        "instructions": Value::Null,
        "max_output_tokens": Value::Null,
        "model": model,
        "output": output,
        "parallel_tool_calls": true,
        "previous_response_id": Value::Null,
        "reasoning": { "effort": Value::Null, "summary": Value::Null },
        "store": false,
        "temperature": 1.0,
        "text": { "format": { "type": "text" } },
        "tool_choice": "auto",
        "tools": [],
        "top_p": 1.0,
        "truncation": "disabled",
        "usage": {
            "input_tokens": 0,
            "input_tokens_details": { "cached_tokens": 0 },
            "output_tokens": 0,
            "output_tokens_details": { "reasoning_tokens": 0 },
            "total_tokens": 0,
        },
        "user": Value::Null,
        "metadata": {},
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::engine::RunStatus;

    fn ok_result(data: Value) -> RunResult {
        RunResult {
            run_id: 7,
            status: RunStatus::Success,
            success: true,
            error: None,
            extracted_data: data,
            duration_ms: 12,
        }
    }

    #[test]
    fn single_key_returns_bare_value() {
        let r = ok_result(json!({ "title": "Hello" }));
        // Exactly one string key → bare string, no JSON wrapping.
        assert_eq!(assistant_content(&r, None), "Hello");
    }

    #[test]
    fn single_non_string_key_is_pretty_json() {
        let r = ok_result(json!({ "rows": [1, 2, 3] }));
        assert_eq!(assistant_content(&r, None), "[\n  1,\n  2,\n  3\n]");
    }

    #[test]
    fn multi_key_returns_pretty_object() {
        let r = ok_result(json!({ "a": 1, "b": 2 }));
        let out = assistant_content(&r, None);
        assert!(out.contains("\"a\": 1"));
        assert!(out.contains("\"b\": 2"));
    }

    #[test]
    fn response_field_selects_key() {
        // Multiple keys, but the configured response_field wins.
        let r = ok_result(json!({ "answer": "42", "debug": { "x": 1 } }));
        assert_eq!(assistant_content(&r, Some("answer")), "42");
        // A missing response_field falls back to whole-object rendering.
        let out = assistant_content(&r, Some("missing"));
        assert!(out.contains("\"answer\""));
    }

    #[test]
    fn failure_returns_success_error_shape() {
        let r = RunResult {
            run_id: 9,
            status: RunStatus::Failed,
            success: false,
            error: Some("boom".into()),
            extracted_data: json!({}),
            duration_ms: 3,
        };
        let out = assistant_content(&r, None);
        assert!(out.contains("\"success\": false"));
        assert!(out.contains("\"error\": \"boom\""));
        assert_eq!(finish_reason(&r), "error");
    }

    #[test]
    fn chat_object_has_assistant_choice() {
        let r = ok_result(json!({ "title": "Hi" }));
        let obj = chat_completion_object("writ:workflow:7", &r, None);
        assert_eq!(obj["object"], "chat.completion");
        assert_eq!(obj["choices"][0]["message"]["role"], "assistant");
        assert_eq!(obj["choices"][0]["message"]["content"], "Hi");
        assert_eq!(obj["choices"][0]["finish_reason"], "stop");
    }

    #[test]
    fn response_object_has_output_text() {
        let r = ok_result(json!({ "title": "Hi" }));
        let obj = response_object("writ:workflow:7", &r, None);
        assert_eq!(obj["object"], "response");
        assert_eq!(obj["status"], "completed");
        assert_eq!(obj["output"][0]["content"][0]["type"], "output_text");
        assert_eq!(obj["output"][0]["content"][0]["text"], "Hi");
    }

    // ── Inputs derivation ──────────────────────────────────────────────────

    #[test]
    fn derive_inputs_pulls_last_user_message() {
        let msgs = vec![
            json!({ "role": "system", "content": "be nice" }),
            json!({ "role": "user", "content": "first" }),
            json!({ "role": "assistant", "content": "ok" }),
            json!({ "role": "user", "content": "second" }),
        ];
        let inputs = derive_inputs(&msgs, None, None);
        assert_eq!(inputs["message"], json!("second"));
        // The full transcript is carried for streaming scripts.
        assert_eq!(inputs["messages"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn derive_inputs_concatenates_multimodal_text_parts() {
        let msgs = vec![json!({
            "role": "user",
            "content": [
                { "type": "text", "text": "hello " },
                { "type": "image_url", "image_url": { "url": "x" } },
                { "type": "text", "text": "world" },
            ]
        })];
        let inputs = derive_inputs(&msgs, None, None);
        assert_eq!(inputs["message"], json!("hello world"));
    }

    #[test]
    fn derive_inputs_flattens_structured_input_object() {
        let msgs = vec![json!({ "role": "user", "content": "go" })];
        let input = json!({ "city": "Paris", "limit": 5 });
        let inputs = derive_inputs(&msgs, Some(&input), None);
        assert_eq!(inputs["city"], json!("Paris"));
        assert_eq!(inputs["limit"], json!(5));
        assert_eq!(inputs["message"], json!("go"));
    }

    #[test]
    fn derive_inputs_lifts_tool_call_arguments() {
        let msgs = vec![json!({
            "role": "assistant",
            "tool_calls": [{
                "type": "function",
                "function": { "name": "search", "arguments": "{\"query\":\"rust\",\"page\":2}" }
            }]
        })];
        let inputs = derive_inputs(&msgs, None, None);
        assert_eq!(inputs["query"], json!("rust"));
        assert_eq!(inputs["page"], json!(2));
    }

    #[test]
    fn structured_input_does_not_clobber_tool_args_or_vice_versa() {
        // An explicit `input` field wins over a tool-call arg of the same name.
        let msgs = vec![json!({
            "role": "assistant",
            "function_call": { "name": "f", "arguments": "{\"city\":\"Berlin\"}" }
        })];
        let input = json!({ "city": "Paris" });
        let inputs = derive_inputs(&msgs, Some(&input), None);
        assert_eq!(inputs["city"], json!("Paris"), "explicit input wins over tool arg");
    }

    #[test]
    fn responses_inputs_handle_string_array_and_object() {
        // Bare string → a single user turn.
        let i = derive_responses_inputs(Some(&json!("hi there")), &[], None);
        assert_eq!(i["message"], json!("hi there"));

        // Array of items.
        let arr = json!([{ "role": "user", "content": "from array" }]);
        let i = derive_responses_inputs(Some(&arr), &[], None);
        assert_eq!(i["message"], json!("from array"));

        // Object → flattened, with messages fallback.
        let obj = json!({ "name": "Bob" });
        let msgs = vec![json!({ "role": "user", "content": "obj-msg" })];
        let i = derive_responses_inputs(Some(&obj), &msgs, None);
        assert_eq!(i["name"], json!("Bob"));
        assert_eq!(i["message"], json!("obj-msg"));
    }

    #[test]
    fn responses_instructions_reach_inputs_as_system() {
        // The Responses-API `instructions` (system prompt) must NOT be dropped — it lands as
        // `inputs.system`/`inputs.instructions` AND as a prepended system message so a proxy script
        // can forward it. Without this the agent/tool-protocol prompt never reaches the model.
        let i = derive_responses_inputs(Some(&json!("do the thing")), &[], Some("You are a JSON tool agent."));
        assert_eq!(i["system"], json!("You are a JSON tool agent."));
        assert_eq!(i["instructions"], json!("You are a JSON tool agent."));
        let msgs = i["messages"].as_array().unwrap();
        assert_eq!(msgs[0]["role"], json!("system"));
        assert_eq!(msgs[0]["content"], json!("You are a JSON tool agent."));
        assert_eq!(msgs[1]["role"], json!("user"));
        // No instructions → no synthetic system message.
        let j = derive_responses_inputs(Some(&json!("hi")), &[], None);
        assert!(j.get("system").is_none());
    }

    // ── Streaming chunk shaping ─────────────────────────────────────────────

    #[test]
    fn final_content_honors_response_field_then_content_then_whole() {
        assert_eq!(final_content_of(&json!({ "answer": "A" }), "answer"), "A");
        assert_eq!(final_content_of(&json!({ "content": "C" }), "answer"), "C");
        let whole = final_content_of(&json!({ "x": 1 }), "answer");
        assert!(whole.contains("\"x\""));
        assert_eq!(final_content_of(&json!("bare"), "answer"), "bare");
    }

    #[test]
    fn blocks_list_content_is_flattened_to_text() {
        // The shape a chat handler returns: `content` is a multimodal blocks list, not a string.
        let data = json!({ "content": [{ "type": "text", "text": "Hello! How can I help you today?" }] });
        assert_eq!(final_content_of(&data, "content"), "Hello! How can I help you today?");
        // A bare blocks array (ps.respond(id, [...])) flattens too.
        let bare = json!([{ "type": "text", "text": "one" }, { "type": "text", "text": "two" }]);
        assert_eq!(final_content_of(&bare, "content"), "one\ntwo");
        // Non-text blocks (e.g. an image part) contribute no text.
        let img = json!([{ "type": "image_url", "image_url": { "url": "x" } }]);
        assert_eq!(final_content_of(&img, "content"), "");
    }

    #[test]
    fn plain_data_array_still_renders_as_json() {
        // A non-blocks array must NOT be mistaken for content blocks.
        assert_eq!(blocks_to_text(&json!([1, 2, 3])), None);
        // Single-key extracted data holding a data array stays pretty-JSON (existing contract).
        let r = ok_result(json!({ "rows": [1, 2, 3] }));
        assert_eq!(assistant_content(&r, None), "[\n  1,\n  2,\n  3\n]");
    }

    #[test]
    fn assistant_content_flattens_bare_blocks_array() {
        // Non-streaming path: extracted_data is itself a blocks array.
        let r = ok_result(json!([{ "type": "output_text", "text": "Hi there" }]));
        assert_eq!(assistant_content(&r, None), "Hi there");
    }

    /// Collect a chunk stream into the Vec of `Value`s it yields (last is the `[DONE]` sentinel).
    async fn collect_chunks(
        rx: tokio::sync::mpsc::UnboundedReceiver<StreamEvent>,
        response_field: &str,
    ) -> Vec<Value> {
        chunk_value_stream(
            rx,
            "id".into(),
            1,
            "m".into(),
            response_field.into(),
            Duration::from_secs(5),
            None,
        )
        .collect()
        .await
    }

    #[tokio::test]
    async fn sse_stream_chunks_then_done_terminates() {
        use tokio::sync::mpsc;
        let (tx, rx) = mpsc::unbounded_channel();
        tx.send(StreamEvent::Chunk { content: "Hel".into() }).unwrap();
        tx.send(StreamEvent::Chunk { content: "lo".into() }).unwrap();
        // Done payload duplicates what was already streamed → must NOT re-emit it.
        tx.send(StreamEvent::Done { data: json!({ "content": "Hello" }) }).unwrap();
        drop(tx);

        let chunks = collect_chunks(rx, "content").await;
        // Two content deltas, a stop chunk, then the [DONE] sentinel.
        assert_eq!(chunks[0]["choices"][0]["delta"]["content"], json!("Hel"));
        assert_eq!(chunks[1]["choices"][0]["delta"]["content"], json!("lo"));
        // The stop chunk has no content (we already streamed it) and finish_reason stop.
        let stop = &chunks[2];
        assert_eq!(stop["choices"][0]["finish_reason"], json!("stop"));
        assert!(stop["choices"][0]["delta"].get("content").is_none(), "no duplicate content");
        assert_eq!(chunks.last().unwrap(), &Value::String("[DONE]".into()));
        // Each non-sentinel chunk is shaped as a chat.completion.chunk.
        assert_eq!(chunks[0]["object"], json!("chat.completion.chunk"));
    }

    #[tokio::test]
    async fn sse_stream_all_at_once_done_emits_content_then_stop() {
        use tokio::sync::mpsc;
        let (tx, rx) = mpsc::unbounded_channel();
        // No incremental chunks — the page returns everything in the Done payload.
        tx.send(StreamEvent::Done { data: json!({ "answer": "42" }) }).unwrap();
        drop(tx);

        let chunks = collect_chunks(rx, "answer").await;
        // content delta (the all-at-once flush), stop chunk, [DONE].
        assert_eq!(chunks[0]["choices"][0]["delta"]["content"], json!("42"));
        assert_eq!(chunks[1]["choices"][0]["finish_reason"], json!("stop"));
        assert_eq!(chunks.last().unwrap(), &Value::String("[DONE]".into()));
    }

    #[tokio::test]
    async fn sse_stream_error_event_terminates() {
        use tokio::sync::mpsc;
        let (tx, rx) = mpsc::unbounded_channel();
        tx.send(StreamEvent::Error { message: "no handler".into() }).unwrap();
        drop(tx);

        let chunks = collect_chunks(rx, "content").await;
        assert_eq!(chunks[0]["choices"][0]["delta"]["content"], json!("no handler"));
        assert_eq!(chunks[0]["choices"][0]["finish_reason"], json!("error"));
        assert_eq!(chunks.last().unwrap(), &Value::String("[DONE]".into()));
    }

    #[tokio::test]
    async fn sse_stream_closed_without_terminal_emits_defensive_stop() {
        use tokio::sync::mpsc;
        let (tx, rx) = mpsc::unbounded_channel::<StreamEvent>();
        // Drop the sender with no events at all.
        drop(tx);
        let chunks = collect_chunks(rx, "content").await;
        assert_eq!(chunks[0]["choices"][0]["finish_reason"], json!("stop"));
        assert_eq!(chunks.last().unwrap(), &Value::String("[DONE]".into()));
    }

    #[test]
    fn value_to_sse_data_passes_done_literally() {
        assert_eq!(value_to_sse_data(&Value::String("[DONE]".into())), "[DONE]");
        let chunk = json!({ "object": "chat.completion.chunk" });
        assert_eq!(value_to_sse_data(&chunk), chunk.to_string());
    }

    // ── Responses-API streaming shaping ─────────────────────────────────────

    /// Collect a Responses event stream into the Vec of event `Value`s it yields.
    async fn collect_response_events(
        rx: tokio::sync::mpsc::UnboundedReceiver<StreamEvent>,
        response_field: &str,
    ) -> Vec<Value> {
        response_event_stream(
            rx,
            "resp-writ-test".into(),
            1,
            "writ:workflow:7".into(),
            response_field.into(),
            Duration::from_secs(5),
            None,
        )
        .collect()
        .await
    }

    /// Every event carries a `type` (used as the SSE event name) and a monotonic `sequence_number`.
    fn assert_well_formed_sequence(events: &[Value]) {
        for (i, e) in events.iter().enumerate() {
            assert!(e.get("type").and_then(|t| t.as_str()).is_some(), "event {i} has a string type");
            assert_eq!(
                e["sequence_number"], json!((i + 1) as i64),
                "sequence_number is 1-based monotonic at event {i}"
            );
        }
    }

    #[tokio::test]
    async fn responses_stream_incremental_chunks_emit_deltas() {
        use tokio::sync::mpsc;
        let (tx, rx) = mpsc::unbounded_channel();
        tx.send(StreamEvent::Chunk { content: "Hel".into() }).unwrap();
        tx.send(StreamEvent::Chunk { content: "lo".into() }).unwrap();
        // Done payload duplicates the streamed text → must NOT re-emit an all-at-once delta.
        tx.send(StreamEvent::Done { data: json!({ "content": "Hello" }) }).unwrap();
        drop(tx);

        let ev = collect_response_events(rx, "content").await;
        let types: Vec<&str> = ev.iter().map(|e| e["type"].as_str().unwrap()).collect();
        assert_eq!(types, vec![
            "response.created",
            "response.output_item.added",
            "response.content_part.added",
            "response.output_text.delta",
            "response.output_text.delta",
            "response.output_text.done",
            "response.content_part.done",
            "response.output_item.done",
            "response.completed",
        ]);
        assert_eq!(ev[3]["delta"], json!("Hel"));
        assert_eq!(ev[4]["delta"], json!("lo"));
        // output_text.done + completed carry the full assembled text; no duplicate delta.
        assert_eq!(ev[5]["text"], json!("Hello"));
        let completed = ev.last().unwrap();
        assert_eq!(completed["response"]["status"], json!("completed"));
        assert_eq!(completed["response"]["output"][0]["content"][0]["text"], json!("Hello"));
        assert_well_formed_sequence(&ev);
    }

    #[tokio::test]
    async fn responses_stream_all_at_once_done_flushes_one_delta() {
        use tokio::sync::mpsc;
        let (tx, rx) = mpsc::unbounded_channel();
        // No incremental chunks — the page returns everything in the Done payload.
        tx.send(StreamEvent::Done { data: json!({ "answer": "42" }) }).unwrap();
        drop(tx);

        let ev = collect_response_events(rx, "answer").await;
        let types: Vec<&str> = ev.iter().map(|e| e["type"].as_str().unwrap()).collect();
        // The all-at-once flush inserts exactly one delta before the closing events.
        assert_eq!(types, vec![
            "response.created",
            "response.output_item.added",
            "response.content_part.added",
            "response.output_text.delta",
            "response.output_text.done",
            "response.content_part.done",
            "response.output_item.done",
            "response.completed",
        ]);
        assert_eq!(ev[3]["delta"], json!("42"));
        assert_eq!(ev.last().unwrap()["response"]["status"], json!("completed"));
        assert_well_formed_sequence(&ev);
    }

    #[tokio::test]
    async fn responses_stream_error_event_yields_response_failed() {
        use tokio::sync::mpsc;
        let (tx, rx) = mpsc::unbounded_channel();
        tx.send(StreamEvent::Error { message: "no handler".into() }).unwrap();
        drop(tx);

        let ev = collect_response_events(rx, "content").await;
        // Prologue still leads, then a single response.failed terminal (no [DONE]).
        assert_eq!(ev.last().unwrap()["type"], json!("response.failed"));
        assert_eq!(ev.last().unwrap()["response"]["status"], json!("failed"));
        assert_eq!(ev.last().unwrap()["response"]["error"]["message"], json!("no handler"));
        assert_well_formed_sequence(&ev);
    }

    #[test]
    fn count_tokens_matches_cloud_fallback() {
        assert_eq!(count_tokens(""), 0);
        assert_eq!(count_tokens("a"), 1); // (1+3)/4
        assert_eq!(count_tokens("abcd"), 1); // (4+3)/4
        assert_eq!(count_tokens("abcde"), 2); // (5+3)/4
    }

    #[test]
    fn input_text_of_prefers_transcript_then_message() {
        // Full transcript's message text is joined.
        let inputs = json!({
            "message": "second",
            "messages": [
                { "role": "user", "content": "first" },
                { "role": "assistant", "content": "reply" },
                { "role": "user", "content": "second" },
            ],
        });
        assert_eq!(input_text_of(&inputs), "first\nreply\nsecond");
        // No transcript → the bare `message`.
        assert_eq!(input_text_of(&json!({ "message": "solo" })), "solo");
        // Neither → empty.
        assert_eq!(input_text_of(&json!({})), "");
    }

    #[test]
    fn response_object_uses_full_responses_envelope() {
        let r = ok_result(json!({ "title": "Hi" }));
        let obj = response_object("writ:workflow:7", &r, None);
        assert_eq!(obj["object"], "response");
        assert_eq!(obj["status"], "completed");
        assert_eq!(obj["output"][0]["content"][0]["type"], "output_text");
        assert_eq!(obj["output"][0]["content"][0]["text"], "Hi");
        // Full envelope fields a strict Responses client validates.
        assert_eq!(obj["text"]["format"]["type"], "text");
        assert_eq!(obj["tool_choice"], "auto");
        assert!(obj["usage"]["input_tokens_details"].is_object());
    }
}
