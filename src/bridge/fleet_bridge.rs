//! `FleetBridge` — the SELF-HOST OSS fleet worker's outbound link to a self-host **coordinator**.
//!
//! A cloud-free twin of [`crate::bridge::saas_bridge::SaaSBridge`] and a structural mirror of the
//! desktop [`crate::local::cloud::gateway::LinkedAgentBridge`], but with NO cloud auth/token/relay
//! machinery. It connects to the coordinator over the SAME two-step handshake
//! (`POST {base}/api/recorder/connect` → dial the returned `/ws/ai-gateway` WS with the gateway JWT
//! in the `Authorization` header), then serves the frozen fleet-local wire contract:
//!
//!   * `save_local_workflow` / `save_local_secret` / `save_local_persona` — the coordinator DEPLOYS
//!     a workflow / secret / persona to this agent. Secret material crosses the wire ONCE, Fernet-
//!     sealed under this agent's per-agent CHANNEL KEY; the agent re-seals every field under its OWN
//!     local [`Vault`] and persists it via the `local` store. After any save the agent re-emits the
//!     `local_catalog` frame so the coordinator refreshes its `LocalWorkflow` rows.
//!   * `run_local_workflow` — run a deployed workflow BY ID, fully locally (definition + secrets +
//!     persona + extracted data resolved on this machine), headless. Streaming / AI-loop /
//!     automation-block workflows and email/SMS-2FA personas are pre-flight REJECTED (clear error,
//!     no browser launch).
//!   * `request_local_catalog` — advertise the `cloud_callable` catalog (METADATA ONLY).
//!   * `ping` / control frames — as `saas_bridge`.
//!
//! SECURITY INVARIANTS (the never-trust-a-BYO-agent rule / project trust rules):
//!   * The coordinator STAMPS the authenticated `agent_id` onto every frame it ingests; this agent
//!     never trusts an id/tenant in a payload. Everything it persists is its OWN local data.
//!   * The catalog advertised to the coordinator is METADATA ONLY — declared inputs + declared
//!     output fields. Workflow STEPS and CREDENTIALS never enter a catalog frame.
//!   * The channel key arrives from the coordinator in the post-auth `auth_ok` frame (mirroring the
//!     device-flow path). It is a per-agent Fernet key used ONLY to open the sealed deploy blobs;
//!     the agent immediately re-seals every opened field under its local vault. Runs never re-send
//!     secrets — `run_local_workflow(id)` resolves from the local vault.
//!
//! Net-new Rust in this crate, behind BOTH the `fleet` and `local` cargo features
//! (the OSS self-host build: `--no-default-features --features local,fleet,openai`).

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use sqlx::sqlite::SqlitePool;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;

use crate::bridge::session_relay::{shed_backlog, ProbeAction, ShedOutcome, WsLiveness};
use crate::local::engine::{Lane, LocalEngine, RunRequest, RunSource};
use crate::local::store::{config_kv, personas, vault_secrets, workflows};
use crate::local::vault::Vault;

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// `config` kv key under which the coordinator-assigned agent id is persisted (non-secret routing
/// metadata), so the same id is re-presented across restarts for warm affinity.
const FLEET_AGENT_ID_KEY: &str = "fleet.agent_id";
/// `config` kv key caching the per-agent Fernet CHANNEL KEY the coordinator issues in `auth_ok`.
/// This is a SECRET (it opens the deploy blobs) but it lives in the SQLCipher-encrypted `config`
/// table (Layer-A at rest), never in plaintext. Cached so a save frame that races ahead of a fresh
/// `auth_ok` (e.g. an immediate redeploy after reconnect) can still be opened.
const FLEET_CHANNEL_KEY_KEY: &str = "fleet.channel_key";

// --- transport limits ------------------------------------------------------
//
// tungstenite's defaults are "trust the peer": 64 MiB max message, 16 MiB max frame, and an
// UNBOUNDED (`usize::MAX`) write buffer. A 64 MiB text frame of `[],[],[]…` inflates roughly 20× as
// `serde_json::Value` (~1.3 GB resident), so the coordinator — or anyone who can reach the WS — can
// OOM a worker with one frame. Cap deliberately instead.
//
// Sizing: the largest LEGITIMATE inbound frames are (a) `save_local_workflow` (steps + form_data +
// a Fernet-sealed persona `session_state`, i.e. gzipped cookies/localStorage — hundreds of KiB in
// the worst real case), (b) `execute_workflow` with a full wire definition (`config.files` carries
// signed URLs, never bytes), and (c) `assign_targets` for a monitoring node (a few KiB per target).
// 8 MiB is ~10× the worst observed frame while bounding the JSON-expansion blast radius to ~160 MB
// instead of 1.3 GB. `max_frame_size` at 2 MiB still permits those frames (a browser/proxy may
// fragment; tungstenite reassembles up to `max_message_size`).
const WS_MAX_MESSAGE_SIZE: usize = 8 * 1024 * 1024;
const WS_MAX_FRAME_SIZE: usize = 2 * 1024 * 1024;
/// Cap on tungstenite's own write buffer (its default is `usize::MAX`). It must exceed the largest
/// frame we SEND — a crawl-shard `task_result` carries per-page markdown plus base64 thumbnails, so
/// several MiB is normal — hence a generous but finite 32 MiB. The app-level bound on how much can
/// queue up BEHIND this is `OUTGOING_*_CAP` below.
const WS_MAX_WRITE_BUFFER: usize = 32 * 1024 * 1024;

// --- read-loop liveness ----------------------------------------------------
/// No inbound frame for this long → send a client-initiated `Ping`. Must be comfortably longer than
/// the coordinator's own ping/heartbeat cadence so a healthy link never probes.
const READ_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// A probe unanswered for this long means the path is gone (half-open flow) → reconnect.
const PONG_GRACE: Duration = Duration::from_secs(15);
/// A single WS write that cannot complete in this long means the peer's receive window is shut.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

// --- outgoing queue bounds (see `session_relay::shed_backlog`) -------------
/// Above this many queued outgoing frames we run a shed pass (screencast frames dropped, control
/// frames kept).
const OUTGOING_SOFT_CAP: usize = 256;
/// Control frames alone above this = the peer stopped reading → drop the session instead of growing.
const OUTGOING_HARD_CAP: usize = 4096;

// --- deploy input caps (`save_local_workflow`) -----------------------------
// A deployed workflow PERSISTS to this worker's disk and survives restarts, so a buggy or hostile
// coordinator must not be able to turn `save_local_workflow` into unbounded storage. These ceilings
// are far above any real recipe (the largest recorded workflows in the product are tens of KiB).
const MAX_STEPS_BYTES: usize = 512 * 1024;
const MAX_FORM_DATA_BYTES: usize = 256 * 1024;
const MAX_NAME_CHARS: usize = 200;
const MAX_DESCRIPTION_BYTES: usize = 8 * 1024;
/// Ceiling on total stored workflow rows (the catalog itself is already capped at 1000 by
/// `list_cloud_callable`; this stops the table growing behind it).
const MAX_STORED_WORKFLOWS: i64 = 2_000;

// --- catalog rebuild cost --------------------------------------------------
/// `request_local_catalog` is a ~40-byte frame that costs a full sha256 + placeholder scan over
/// EVERY stored workflow. Serve a cached frame within this window instead of recomputing, and
/// invalidate on any local mutation.
const CATALOG_CACHE_TTL: Duration = Duration::from_secs(30);
/// Minimum spacing between coordinator-requested catalog sends (flood guard).
const CATALOG_MIN_INTERVAL: Duration = Duration::from_secs(1);

// --- cooperative teardown --------------------------------------------------
/// How long the monitoring loop is given to finish its current check and exit on its own after
/// `monitor_running` is cleared, before we resort to `abort()`.
///
/// WHY it is not just `abort()` (which is what this used to be): the monitor loop drives real browser
/// contexts, and `BrowserContext`/`Page` have NO `Drop` in the playwright crate — closing is only ever
/// manual. Aborting the task drops those handles WITHOUT closing them, so the context, its renderer
/// processes and its memory stay alive inside Chromium. This fires on EVERY connection loss, so over a
/// month of flappy connectivity each interrupted check strands a context and RSS climbs until the
/// governor's memory watermark sheds all background work — a worker that "accepts dispatch and rejects
/// everything" with nothing in the logs explaining why. The loop already polls the `monitor_running`
/// flag, so a bounded cooperative wait lets it close what it opened.
const MONITOR_SHUTDOWN_GRACE: Duration = Duration::from_secs(20);

/// The same grace, but for a DELIBERATE stop (`shutdown()` / a coordinator `disconnect`) instead of a
/// reconnect. Much shorter on purpose: the warm browser is closed wholesale immediately afterwards, so
/// waiting for one check to close its own context buys nothing — while a supervisor is holding a stop
/// deadline over us and every second here risks its own abort.
const MONITOR_STOP_GRACE: Duration = Duration::from_secs(2);

// ---------------------------------------------------------------------------
// Small self-contained helpers (copies of the gateway/saas_bridge equivalents;
// the cloud-gated originals are physically absent from the fleet build).
// ---------------------------------------------------------------------------

/// Char-safe truncation for logging wire-derived strings (a malicious coordinator could otherwise
/// crash the agent with a multibyte id sliced mid-codepoint).
fn truncate_str(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

/// Refuse a plaintext endpoint outside local dev: plaintext would expose the bearer token and every
/// frame on the wire. Accept `wss://`/`https://`, a loopback host, or an explicit opt-in.
fn require_secure_url(url: &str, allow_insecure: bool, what: &str) -> anyhow::Result<()> {
    let lower = url.trim().to_lowercase();
    if lower.starts_with("wss://") || lower.starts_with("https://") {
        return Ok(());
    }
    let after = lower.split_once("://").map(|x| x.1).unwrap_or(lower.as_str());
    let authority = after.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = authority.rsplit('@').next().unwrap_or(authority);
    // Bare host (strip the port), then compare EXACTLY — a prefix match would let
    // `localhost.attacker.com` pass as "local".
    let host = if let Some(rest) = hostport.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        hostport.split_once(':').map(|(h, _)| h).unwrap_or(hostport)
    };
    let is_local = host == "localhost"
        || host.parse::<std::net::IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false);
    if allow_insecure || is_local {
        return Ok(());
    }
    anyhow::bail!(
        "Refusing insecure {what} URL '{url}': plaintext would expose the fleet token and all \
         session traffic on the wire. Use a wss://https:// endpoint, or set \
         WRIT_FLEET_ALLOW_INSECURE=1 only on a trusted private network."
    )
}

/// Minimal percent-encoding for the `agent_id` query-string routing hint.
fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Coerce a wire `task_id`/`request_id` (string OR number) to a String faithfully.
fn id_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Fernet-decrypt a channel-key-sealed blob to RAW BYTES (for `session_state`/`totp` blobs whose
/// inner framing — gzip / base32 — is NOT a JSON map and must be re-sealed byte-for-byte). Mirrors
/// the Python `json.loads(fernet.decrypt(...))` opener minus the JSON parse.
fn channel_decrypt_bytes(channel_key: &str, encrypted: &str) -> Option<Vec<u8>> {
    if channel_key.is_empty() || encrypted.is_empty() {
        return None;
    }
    let fernet = fernet::Fernet::new(channel_key)?;
    fernet.decrypt(encrypted).ok()
}

/// Fernet-decrypt a channel-key-sealed blob to an arbitrary JSON value (for the persona `proxy`
/// OBJECT, which a `HashMap<String,String>` decrypt could not hold). Returns the raw JSON text so
/// the caller re-seals the exact bytes the local run path parses.
fn channel_decrypt_json_text(channel_key: &str, encrypted: &str) -> Option<String> {
    let bytes = channel_decrypt_bytes(channel_key, encrypted)?;
    let s = String::from_utf8(bytes).ok()?;
    // Validate it parses as JSON so a corrupt blob is rejected before we seal it locally.
    serde_json::from_str::<Value>(&s).ok()?;
    Some(s)
}

/// Fernet-decrypt a channel-key-sealed `{name: value}` credential MAP into a canonical JSON-object
/// TEXT (the exact shape [`crate::local::engine::resolve::decrypt_workflow_credentials`] /
/// `engine::persona` parse locally). Uses the UNGATED Fernet opener the agent already has.
fn channel_decrypt_map_text(channel_key: &str, encrypted: &str) -> Option<String> {
    let map = crate::security::crypto::decrypt_credentials(encrypted, channel_key).ok()?;
    serde_json::to_string(&map).ok()
}

// --- catalog projection (metadata only) — copied from gateway.rs; cloud-gated original is absent ---

/// AAD column tag for a vault secret's `value_encrypted` blob. MUST match
/// `engine::resolve::secret_value_aad` (the run-time opener) or a sealed secret is un-openable.
fn secret_value_aad(key: &str) -> String {
    format!("vault_secrets|value_encrypted|{key}")
}

/// AAD for a persona's sealed column (`personas|<column>|<id>`). MUST match `engine::persona`.
fn persona_aad(column: &str, id: i64) -> String {
    format!("personas|{column}|{id}")
}

/// The metadata-only catalog entry for a workflow: `local_id` is the INTEGER PK rendered as a string
/// (the coordinator stores it opaquely and echoes it back on `run_local_workflow`, where this agent
/// parses it as i64 — so the round-trip stays self-consistent). NO steps, NO credentials.
fn catalog_entry(wf: &workflows::Workflow) -> Value {
    json!({
        "local_id": wf.id.to_string(),
        "name": wf.name,
        "description": wf.description,
        "input_schema": input_schema_metadata(wf),
        "recipe_hash": recipe_hash(wf),
        "cloud_callable": true,
    })
}

/// Declared `{{input.NAME}}` placeholders as required string properties, plus declared output fields.
fn input_schema_metadata(wf: &workflows::Workflow) -> Value {
    let inputs = scan_input_placeholders(&wf.steps);
    let mut properties = serde_json::Map::new();
    let mut required = Vec::with_capacity(inputs.len());
    for name in &inputs {
        properties.insert(
            name.clone(),
            json!({ "type": "string", "description": format!("Input: {name}") }),
        );
        required.push(Value::String(name.clone()));
    }
    json!({
        "type": "object",
        "properties": Value::Object(properties),
        "required": required,
        "output_fields": declared_output_fields(wf),
    })
}

/// Content hash of the workflow recipe (steps + functions + form_data). The hash leaves the device;
/// the recipe does not. Hex sha256.
fn recipe_hash(wf: &workflows::Workflow) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(wf.steps.as_bytes());
    if let Some(f) = wf.functions.as_deref() {
        h.update(b"\x00");
        h.update(f.as_bytes());
    }
    if let Some(fd) = wf.form_data.as_deref() {
        h.update(b"\x00");
        h.update(fd.as_bytes());
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Distinct `{{input.NAME}}` names referenced in a steps TEXT blob (order-preserving, first-seen).
/// `{{secret:...}}` is never matched.
fn scan_input_placeholders(steps_text: &str) -> Vec<String> {
    const OPEN: &str = "{{";
    const PREFIX: &str = "input.";
    let mut names: Vec<String> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let bytes = steps_text.as_bytes();
    let mut i = 0usize;
    while let Some(rel) = steps_text[i..].find(OPEN) {
        let mut p = i + rel + OPEN.len();
        while p < bytes.len() && bytes[p].is_ascii_whitespace() {
            p += 1;
        }
        if steps_text[p..].starts_with(PREFIX) {
            let name_start = p + PREFIX.len();
            let mut q = name_start;
            while q < bytes.len() {
                let c = bytes[q];
                if c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-') {
                    q += 1;
                } else {
                    break;
                }
            }
            let name = &steps_text[name_start..q];
            let mut r = q;
            while r < bytes.len() && bytes[r].is_ascii_whitespace() {
                r += 1;
            }
            if !name.is_empty() && steps_text[r..].starts_with("}}") && seen.insert(name.to_string()) {
                names.push(name.to_string());
            }
        }
        i = i + rel + OPEN.len();
    }
    names
}

/// Declared output fields = union of `functions[].output_fields` (bare string or `{"name": ...}`).
fn declared_output_fields(wf: &workflows::Workflow) -> Vec<String> {
    let parsed: Value = match wf.functions.as_deref() {
        None => return Vec::new(),
        Some(s) if s.trim().is_empty() => return Vec::new(),
        Some(s) => serde_json::from_str(s).unwrap_or(Value::Null),
    };
    let fns = match parsed.as_array() {
        Some(a) => a,
        None => return Vec::new(),
    };
    let mut fields: Vec<String> = Vec::new();
    for fnv in fns {
        let ofs = match fnv.get("output_fields").and_then(|v| v.as_array()) {
            Some(a) => a,
            None => continue,
        };
        for f in ofs {
            match f {
                Value::String(s) => fields.push(s.clone()),
                Value::Object(o) => {
                    if let Some(Value::String(name)) = o.get("name") {
                        fields.push(name.clone());
                    }
                }
                _ => {}
            }
        }
    }
    fields
}

/// Build the fixed-contract `task_result` frame. `error` is `null` on success.
fn task_result_frame(
    task_id: &str,
    success: bool,
    extracted_data: Value,
    error: Option<String>,
    duration_ms: u64,
) -> Value {
    json!({
        "type": "task_result",
        "task_id": task_id,
        "success": success,
        "extracted_data": extracted_data,
        "error": error,
        "duration_ms": duration_ms,
    })
}

/// Best-effort non-secret host display name for the connect body.
fn device_name() -> String {
    sysinfo::System::host_name()
        .map(|h| truncate_str(h.trim(), 128))
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

// ---------------------------------------------------------------------------
// Task idempotency ledger
// ---------------------------------------------------------------------------

/// How long a terminal `task_result` stays cached so a duplicate dispatch can be ANSWERED instead of
/// re-executed. Comfortably longer than any coordinator dispatch timeout.
const TASK_RESULT_TTL: Duration = Duration::from_secs(900);
/// Defensive age-out for a slot still marked running. A real run is bounded by the engine; a slot
/// this old means the handler vanished without dropping its guard (runtime teardown), and holding it
/// forever would refuse every legitimate retry of that id.
const TASK_RUNNING_TTL: Duration = Duration::from_secs(6 * 3600);
/// Hard cap on ledger entries. Terminal results are evicted oldest-first past this; in-flight slots
/// are never evicted for size (dropping one would re-open the double-run window).
const TASK_LEDGER_CAP: usize = 512;

enum TaskSlot {
    Running { since: Instant },
    Done { at: Instant, result: Value },
}

/// What to do with an arriving dispatch.
#[derive(Debug, PartialEq, Eq)]
pub enum Claim {
    /// Not seen (or long forgotten) — execute it.
    Fresh,
    /// The same `task_id` is executing right now — do NOT start a second run.
    AlreadyRunning,
    /// The same `task_id` already finished — re-send the cached terminal result.
    Replay(Value),
}

/// Bounded idempotency ledger for coordinator-dispatched tasks.
///
/// WHY: dispatch is at-least-once. A coordinator whose awaited future times out (because the result
/// frame was lost, the link flapped, or the run simply took longer than its patience) re-dispatches
/// the SAME `task_id`. Without a ledger every handler `tokio::spawn`s unconditionally, so the
/// workflow runs a second time — and these workflows submit forms, place orders and move money. A
/// duplicate dispatch must be answered, never re-executed.
///
/// Keyed per task id; entries are dropped when they age out (`TASK_RESULT_TTL` /
/// `TASK_RUNNING_TTL`) and, past `TASK_LEDGER_CAP`, oldest-terminal-first — the map is a cache, not
/// a log, so it must not become its own leak.
pub struct TaskLedger {
    slots: dashmap::DashMap<String, TaskSlot>,
}

impl TaskLedger {
    pub fn new() -> Self {
        Self { slots: dashmap::DashMap::new() }
    }

    /// Claim `task_id` for execution, or report why it must not run.
    pub fn claim(&self, task_id: &str) -> Claim {
        self.evict();
        use dashmap::mapref::entry::Entry;
        // Decided under a short immutable borrow, then applied — the occupied entry cannot be
        // re-inserted into while the previous value is still borrowed.
        enum Decision {
            Running,
            Replay(Value),
            /// A terminal result too old to replay: treat the id as brand new.
            Restart,
        }
        match self.slots.entry(task_id.to_string()) {
            Entry::Occupied(mut e) => {
                let decision = match e.get() {
                    TaskSlot::Running { .. } => Decision::Running,
                    TaskSlot::Done { at, result } if at.elapsed() <= TASK_RESULT_TTL => {
                        Decision::Replay(result.clone())
                    }
                    TaskSlot::Done { .. } => Decision::Restart,
                };
                match decision {
                    Decision::Running => Claim::AlreadyRunning,
                    Decision::Replay(frame) => Claim::Replay(frame),
                    Decision::Restart => {
                        e.insert(TaskSlot::Running { since: Instant::now() });
                        Claim::Fresh
                    }
                }
            }
            Entry::Vacant(e) => {
                e.insert(TaskSlot::Running { since: Instant::now() });
                Claim::Fresh
            }
        }
    }

    /// Record a terminal result for `task_id` (replayed on a duplicate dispatch).
    pub fn complete(&self, task_id: &str, result: Value) {
        self.slots
            .insert(task_id.to_string(), TaskSlot::Done { at: Instant::now(), result });
    }

    /// Release an in-flight claim WITHOUT a result — the handler died (panic/abort) before producing
    /// one. Never touches a recorded terminal result.
    pub fn abandon_running(&self, task_id: &str) {
        self.slots
            .remove_if(task_id, |_, slot| matches!(slot, TaskSlot::Running { .. }));
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Age + size eviction. Cheap: the map is capped in the hundreds.
    fn evict(&self) {
        self.slots.retain(|_, slot| match slot {
            TaskSlot::Done { at, .. } => at.elapsed() <= TASK_RESULT_TTL,
            TaskSlot::Running { since } => since.elapsed() <= TASK_RUNNING_TTL,
        });
        if self.slots.len() <= TASK_LEDGER_CAP {
            return;
        }
        // Over the cap: drop the OLDEST terminal results until we fit. In-flight slots are kept —
        // evicting one would let a duplicate dispatch start a second concurrent run.
        let mut done: Vec<(String, Instant)> = self
            .slots
            .iter()
            .filter_map(|r| match r.value() {
                TaskSlot::Done { at, .. } => Some((r.key().clone(), *at)),
                TaskSlot::Running { .. } => None,
            })
            .collect();
        done.sort_by_key(|(_, at)| *at);
        let mut over = self.slots.len().saturating_sub(TASK_LEDGER_CAP);
        for (key, _) in done {
            if over == 0 {
                break;
            }
            self.slots.remove(&key);
            over -= 1;
        }
    }
}

impl Default for TaskLedger {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII holder for an in-flight [`TaskLedger`] claim.
///
/// Held by the spawned handler for the whole run. On drop it releases a still-`Running` slot, so a
/// handler that PANICS (or is aborted) does not leave the id permanently answered with
/// `already_running` — the coordinator's retry can then legitimately run. A slot that reached a
/// terminal result is untouched.
struct TaskClaim {
    ledger: Arc<TaskLedger>,
    task_id: String,
}

impl TaskClaim {
    fn new(ledger: Arc<TaskLedger>, task_id: String) -> Self {
        Self { ledger, task_id }
    }

    /// Cache the terminal result and emit it. This is the ONLY place a `task_result` is both
    /// recorded and sent, so the cached replay always matches what the coordinator was told.
    fn settle(&self, out: &mpsc::UnboundedSender<Message>, frame: Value) {
        self.ledger.complete(&self.task_id, frame.clone());
        send_task_result(out, &self.task_id, &frame);
    }
}

impl Drop for TaskClaim {
    fn drop(&mut self) {
        self.ledger.abandon_running(&self.task_id);
    }
}

/// RAII counter for a unit of coordinator-dispatched work in flight (see `FleetBridge::inflight`).
///
/// Every spawned dispatch handler holds one for its whole life, so the heartbeat's `active_sessions`
/// counts ALL work — not just engine runs — and the coordinator stops pushing at a saturated worker.
/// RAII rather than an increment/decrement pair specifically because these handlers are aborted and
/// dropped on connection loss, which is exactly when a manual decrement would be skipped.
struct InflightGuard {
    counter: Arc<std::sync::atomic::AtomicUsize>,
}

impl InflightGuard {
    fn new(counter: Arc<std::sync::atomic::AtomicUsize>) -> Self {
        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self { counter }
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        // Saturating: a wrapped `usize` gauge would advertise ~1.8e19 active sessions and exclude this
        // worker from dispatch forever.
        let _ = self.counter.fetch_update(
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
            |v| Some(v.saturating_sub(1)),
        );
    }
}

/// RAII entry in the `task_id → run_id` cancel map: registered when the engine allocates the run row,
/// removed when the handler ends (settled, panicked, or aborted). A stale entry would let a later
/// `cancel_task` for a recycled task id cancel an unrelated run, so removal must not be skippable.
struct DispatchedRunGuard {
    map: Arc<dashmap::DashMap<String, i64>>,
    task_id: String,
}

impl Drop for DispatchedRunGuard {
    fn drop(&mut self) {
        self.map.remove(&self.task_id);
    }
}

/// Send a terminal `task_result`-shaped frame, SURFACING a failure to send.
///
/// Every other outbound site is `let _ = send` — acceptable for a heartbeat, not for a task result:
/// a dropped result makes the coordinator's awaited future hang until its own timeout and then
/// redispatch work that already ran. With the stable outgoing channel this should be unreachable,
/// which is exactly why it must be loud if it ever happens.
fn send_task_result(out: &mpsc::UnboundedSender<Message>, task_id: &str, frame: &Value) {
    if out.send(Message::Text(frame.to_string())).is_err() {
        tracing::error!(
            task_id,
            "LOST task_result — outgoing WS channel is closed. The coordinator will time out this \
             task and may redispatch it (the idempotency ledger will replay this result)."
        );
    }
}

/// Forward a running crawl shard's page tally to the coordinator.
///
/// The coalescing + frame shape live in `crawl_shard` so this bridge and the saas bridge put the
/// IDENTICAL frame on the wire; only the hop onto this socket differs.
fn spawn_crawl_progress_forwarder(
    out: mpsc::UnboundedSender<Message>,
    task_id: String,
) -> crate::crawl_shard::ProgressSink {
    crate::crawl_shard::spawn_progress_forwarder(task_id, move |frame| {
        let _ = out.send(Message::Text(frame.to_string()));
    })
}

// ---------------------------------------------------------------------------
// Catalog cache
// ---------------------------------------------------------------------------

/// Cached `local_catalog` frame.
///
/// Building it hashes (sha256) every stored workflow's recipe and scans it for `{{input.*}}`
/// placeholders. That used to run SYNCHRONOUSLY IN THE READ LOOP on every `request_local_catalog`
/// frame — a ~40-byte request buying unbounded CPU and stalling all frame I/O. Now it is cached for
/// [`CATALOG_CACHE_TTL`], invalidated on every local mutation, and always built off the read loop.
struct CatalogCache {
    inner: Mutex<Option<(Instant, Value)>>,
}

impl CatalogCache {
    fn new() -> Self {
        Self { inner: Mutex::new(None) }
    }

    /// Forget the cached frame (a save/record changed the corpus).
    async fn invalidate(&self) {
        *self.inner.lock().await = None;
    }

    /// The `local_catalog` frame, rebuilt only when stale.
    async fn frame(&self, db: &SqlitePool) -> Value {
        {
            let guard = self.inner.lock().await;
            if let Some((built, frame)) = guard.as_ref() {
                if built.elapsed() < CATALOG_CACHE_TTL {
                    return frame.clone();
                }
            }
        }
        let entries = match workflows::list_cloud_callable(db).await {
            Ok(rows) => rows.iter().map(catalog_entry).collect::<Vec<_>>(),
            Err(e) => {
                tracing::error!(error = %e, "failed to read cloud_callable workflows; sending empty catalog");
                Vec::new()
            }
        };
        tracing::info!(count = entries.len(), "FleetBridge built local catalog");
        // Emitted under BOTH the frozen-contract `workflows` key AND the legacy `catalog` key so it
        // is ingested by every coordinator dialect (`_handle_local_catalog` accepts either).
        let frame = json!({ "type": "local_catalog", "workflows": entries.clone(), "catalog": entries });
        *self.inner.lock().await = Some((Instant::now(), frame.clone()));
        frame
    }
}

// ---------------------------------------------------------------------------
// Bridge
// ---------------------------------------------------------------------------

/// The self-host fleet worker's link to a coordinator. Holds the in-process [`LocalEngine`] (to run
/// workflows by id), the encrypted [`SqlitePool`] (catalog + config kv), and the local [`Vault`]
/// (to re-seal deployed secrets under this machine's own root).
pub struct FleetBridge {
    engine: Arc<dyn LocalEngine>,
    db: SqlitePool,
    vault: Arc<Vault>,
    /// Coordinator HTTP base url (e.g. `https://coordinator.example.com`). Plain HTTP(S) base — the
    /// `/api/recorder/connect` path + the returned WS url are derived from it.
    base_url: String,
    /// Long-lived fleet service token (from `WRIT_SERVICE_TOKEN`) sent as the connect Bearer.
    token: String,
    /// Whether this agent advertises its own AI provider keys (drives coordinator BYO-AI routing).
    ai_keys_configured: bool,
    /// Allow plaintext endpoints (loopback-equivalent dev only).
    allow_insecure: bool,
    running: std::sync::atomic::AtomicBool,
    reconnect_delay: Mutex<f64>,
    /// STABLE outgoing frame channel (raw WS `Message`).
    ///
    /// The sender lives here — NOT in `listen()` — because it is cloned into every long-running
    /// spawned handler (a 90s workflow, a crawl shard, an AI session). When `listen` minted a fresh
    /// channel per connection and aborted the writer task, the receiver was dropped and EVERY sender
    /// a spawned handler still held began failing silently: the run completed, produced its side
    /// effects, and its `task_result` evaporated. `saas_bridge` fixed exactly this (CR-1) by keeping
    /// the sender stable and having the writer task HAND THE RECEIVER BACK on exit; this is the same
    /// pattern, so the two bridges converge.
    outgoing_tx: mpsc::UnboundedSender<Message>,
    outgoing_rx: Mutex<Option<mpsc::UnboundedReceiver<Message>>>,
    /// STABLE `BridgeOutgoing` channel for the shared streaming/monitor code paths, forwarded onto
    /// `outgoing_tx`. Also stable: streaming relays and the monitor loop outlive a single connection.
    bridge_out_tx: mpsc::UnboundedSender<crate::streaming::BridgeOutgoing>,
    bridge_out_rx: Mutex<Option<mpsc::UnboundedReceiver<crate::streaming::BridgeOutgoing>>>,
    /// Dispatch idempotency: answers a duplicate `task_id` instead of running the workflow twice.
    tasks: Arc<TaskLedger>,
    /// Cached `local_catalog` frame (see [`CatalogCache`]).
    catalog_cache: Arc<CatalogCache>,
    /// Last time a catalog frame was sent (flood guard for `request_local_catalog`).
    last_catalog_send: Mutex<Option<Instant>>,
    /// Set when the coordinator answered `/connect` with 401/403. A fleet worker keeps retrying (an
    /// operator re-minting the token is a legitimate recovery), but the state is distinct from
    /// "transient 5xx": it backs off much harder and `/healthz` reports it so an operator can SEE
    /// that the worker is idle because its token is dead rather than because the coordinator is down.
    auth_rejected: std::sync::atomic::AtomicBool,
    /// Consecutive auth rejections (drives the escalating auth backoff).
    auth_failures: std::sync::atomic::AtomicU32,
    /// Human-readable last auth rejection, surfaced by `/healthz`.
    last_auth_error: Mutex<Option<String>>,
    /// The coordinator-assigned agent_id for THIS connection (persisted across restarts).
    agent_id: Mutex<Option<String>>,
    /// The per-agent Fernet channel key the coordinator issued in `auth_ok`. Cached in memory for
    /// the life of the connection AND persisted to the encrypted `config` kv so a redeploy that
    /// races a fresh `auth_ok` still opens.
    channel_key: Mutex<Option<String>>,
    /// Poked whenever the local catalog should be re-advertised without waiting for a WS reconnect.
    catalog_refresh: Notify,
    /// True while a gateway WS session is live (set after the post-auth handshake, cleared whenever
    /// `connect_and_listen` returns). Read by the loopback `/healthz` status listener.
    connected: std::sync::atomic::AtomicBool,
    /// Unix seconds of the last task-ish frame handled (`run_local_workflow` / `execute_workflow` /
    /// `ai_session_start`); 0 = never. Best-effort observability for `/healthz`.
    last_task_at: std::sync::atomic::AtomicI64,
    /// Unix seconds of the last COMPLETED read-loop iteration. See the stamp in `listen` for why
    /// this is the only signal that detects a wedged frame handler.
    last_frame_at: std::sync::atomic::AtomicI64,
    /// Concurrent-session CAPACITY this worker advertises to the coordinator
    /// (drives dispatch fan-in + autoscale utilization math). Auto-detected from
    /// the host (CPU cores + RAM) at startup, overridable via env, and MODIFIABLE
    /// at runtime by a coordinator `set_capacity` frame — the next connect body +
    /// heartbeat report the live value. `Arc` so the heartbeat task can read it.
    max_sessions: Arc<std::sync::atomic::AtomicUsize>,
    /// Hard ceiling `set_capacity` (and the auto-detected value) is clamped to: what this machine can
    /// actually ADMIT, derived from the resource governor. Advertising more than this is what made a
    /// 16-core worker accept 16 dispatches, run 2 and fail 14 with "background ceiling reached".
    capacity_ceiling: usize,
    /// EVERY unit of coordinator-dispatched work currently in flight on this worker.
    ///
    /// The heartbeat used to report `engine.active_runs()`, which is incremented only by the engine's
    /// `run_body` — so crawl shards, raw `execute_workflow`, streaming sessions, AI/browse sessions and
    /// monitor checks were all INVISIBLE. The coordinator saw an idle worker and kept pushing work at a
    /// box that was already saturated. This counter is incremented by an RAII guard at every dispatch
    /// site, so "busy" means busy.
    inflight: Arc<std::sync::atomic::AtomicUsize>,
    /// `task_id → run_id` for by-id runs currently executing, so a coordinator `cancel_task` can be
    /// routed into the engine's cooperative cancel instead of being logged and dropped. Populated the
    /// moment the engine allocates the run row (see `LocalEngine::run_tracked`) and removed when the
    /// run settles, so it only ever holds genuinely-live runs.
    dispatched_runs: Arc<dashmap::DashMap<String, i64>>,
    /// Live streaming sessions this worker hosts, keyed by session_key. Each relay
    /// routes inbound commands to its session loop and outbound frames to the WS.
    /// Shared with the cloud path via the ungated `session_relay` module.
    active_relays: Arc<dashmap::DashMap<String, Arc<crate::bridge::session_relay::AgentSessionRelay>>>,
    /// Scheduled, parallel target-monitoring subsystem — fed by the coordinator's
    /// `assign_targets`/`target_sync`/`check_target_now`/`assign_workflows` frames.
    /// A fleet worker is a SHARED monitoring-fleet node, so (unlike a user's desktop,
    /// which only ACKs cloud-pushed monitors) it RUNS coordinator-assigned checks —
    /// parity with the cloud recorder, via the SAME `monitor::run_monitor_loop`.
    monitor: Arc<crate::monitor::MonitorState>,
}

/// The capacity this worker may advertise: what the resource governor can actually ADMIT.
///
/// Every coordinator-dispatched unit of work runs on [`Lane::Background`], and that lane REJECTS
/// rather than queues — so the only honest number to publish is the governor's background
/// sub-ceiling. The host-derived [`detect_max_sessions`] hint (CPU cores / RAM) is applied only as an
/// upper bound on top: a machine with fewer cores than the configured ceiling should still advertise
/// the smaller number, but a big machine must NOT advertise more than the governor will admit.
///
/// Falls back to the host hint alone for an engine with no governor (the stub/test engines), which is
/// the pre-existing behavior for those.
fn advertised_capacity(engine: &Arc<dyn LocalEngine>) -> usize {
    let host_hint = detect_max_sessions();
    match engine.governor() {
        Some(gov) => {
            let admissible = gov.config().dispatchable_sessions();
            let advertised = admissible.min(host_hint).max(1);
            tracing::info!(
                advertised,
                governor_admissible = admissible,
                host_hint,
                "fleet capacity derived from the resource governor (not raw CPU/RAM)"
            );
            advertised
        }
        None => host_hint,
    }
}

/// Auto-detect a sane concurrent-session capacity for THIS host: bounded by both
/// CPU parallelism and RAM (each warm Chromium ≈ ~1.3 GB budget), honoring an
/// explicit `WRIT_MAX_SESSIONS` / `RECORDER_MAX_SESSIONS` override. Clamped to
/// [1, 50] so a mis-sized box can't advertise absurd capacity.
///
/// NOTE: this is only a HOST hint now — see [`advertised_capacity`], which caps it by what the
/// resource governor can admit. On its own it says nothing about whether a dispatched task will be
/// accepted.
pub fn detect_max_sessions() -> usize {
    if let Some(v) = std::env::var("WRIT_MAX_SESSIONS")
        .ok()
        .or_else(|| std::env::var("RECORDER_MAX_SESSIONS").ok())
        .and_then(|s| s.trim().parse::<usize>().ok())
    {
        return v.clamp(1, 50);
    }
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    // RAM budget: ~1.3 GB per concurrent browser session.
    let mem_sessions = detect_total_memory_gb()
        .map(|gb| (gb / 1.3).floor() as usize)
        .unwrap_or(cores);
    cores.min(mem_sessions).clamp(1, 50)
}

/// Best-effort total physical RAM in GB (Linux `/proc/meminfo`; None elsewhere so
/// the caller falls back to a CPU-only estimate).
fn detect_total_memory_gb() -> Option<f64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb: f64 = rest.trim().trim_end_matches(" kB").trim().parse().ok()?;
            return Some(kb / 1024.0 / 1024.0);
        }
    }
    None
}

impl FleetBridge {
    /// Minimum listen()-time before a session counts as HEALTHY (a close inside this window is
    /// treated as a rapid rejection and cycles through backoff rather than hot-looping).
    const MIN_HEALTHY_SESSION: std::time::Duration = std::time::Duration::from_secs(5);

    /// Build a fleet bridge. `base_url` is the coordinator HTTP base; `token` the fleet service
    /// token; `allow_insecure` for loopback dev only.
    pub fn new(
        engine: Arc<dyn LocalEngine>,
        db: SqlitePool,
        vault: Arc<Vault>,
        base_url: String,
        token: String,
        ai_keys_configured: bool,
        allow_insecure: bool,
    ) -> Self {
        // Profile host capacity once (advertised on connect + `monitor_register`; drives the
        // coordinator's target distribution). Same primitive the cloud recorder uses.
        let capacity = crate::monitor::capacity::CapacityReport::profile(60_000);
        let monitor = Arc::new(crate::monitor::MonitorState::new(capacity));
        let (outgoing_tx, outgoing_rx) = mpsc::unbounded_channel();
        let (bridge_out_tx, bridge_out_rx) = mpsc::unbounded_channel();
        // The advertised number and the admissible number must be the SAME number.
        let capacity_ceiling = advertised_capacity(&engine);
        Self {
            engine,
            db,
            vault,
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
            ai_keys_configured,
            allow_insecure,
            running: std::sync::atomic::AtomicBool::new(false),
            reconnect_delay: Mutex::new(1.0),
            outgoing_tx,
            outgoing_rx: Mutex::new(Some(outgoing_rx)),
            bridge_out_tx,
            bridge_out_rx: Mutex::new(Some(bridge_out_rx)),
            tasks: Arc::new(TaskLedger::new()),
            catalog_cache: Arc::new(CatalogCache::new()),
            last_catalog_send: Mutex::new(None),
            auth_rejected: std::sync::atomic::AtomicBool::new(false),
            auth_failures: std::sync::atomic::AtomicU32::new(0),
            last_auth_error: Mutex::new(None),
            agent_id: Mutex::new(None),
            channel_key: Mutex::new(None),
            catalog_refresh: Notify::new(),
            connected: std::sync::atomic::AtomicBool::new(false),
            last_task_at: std::sync::atomic::AtomicI64::new(0),
            last_frame_at: std::sync::atomic::AtomicI64::new(0),
            max_sessions: Arc::new(std::sync::atomic::AtomicUsize::new(capacity_ceiling)),
            capacity_ceiling,
            inflight: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            dispatched_runs: Arc::new(dashmap::DashMap::new()),
            active_relays: Arc::new(dashmap::DashMap::new()),
            monitor,
        }
    }

    /// Live advertised capacity (concurrent sessions).
    pub fn max_sessions(&self) -> usize {
        self.max_sessions.load(std::sync::atomic::Ordering::Relaxed).max(1)
    }

    /// Total units of coordinator-dispatched work in flight right now — by-id runs, crawl shards, raw
    /// wire workflows, AI/browse sessions and streaming starts. Takes the max with the engine's own
    /// run gauge so an engine run started outside the bridge (a local scheduler tick) still counts.
    pub fn active_units(&self) -> usize {
        self.inflight
            .load(std::sync::atomic::Ordering::SeqCst)
            .max(self.engine.active_runs())
    }

    /// Update advertised capacity at runtime (coordinator `set_capacity` frame)
    /// and re-advertise immediately so dispatch/autoscale see it without waiting
    /// for a reconnect.
    ///
    /// Clamped to `1..=capacity_ceiling` — the governor-derived admissible count. A coordinator (or an
    /// admin UI) asking for more than this cannot make the worker able to RUN more; it would only
    /// restore the over-advertising bug, where the surplus dispatches fail instantly with a cryptic
    /// ceiling error. Raising real capacity is an `[engine]` config change on the worker.
    pub fn set_max_sessions(&self, n: usize) {
        let clamped = n.clamp(1, self.capacity_ceiling.max(1));
        if clamped < n {
            tracing::warn!(
                requested = n,
                granted = clamped,
                "coordinator asked for more capacity than this worker's resource governor can admit — \
                 clamped (raise [engine] max_background_runs / max_concurrent_runs to lift it)"
            );
        }
        self.max_sessions
            .store(clamped, std::sync::atomic::Ordering::Relaxed);
        self.catalog_refresh.notify_one();
        tracing::info!(max_sessions = clamped, "fleet capacity updated by coordinator");
    }

    /// Stop the loop (graceful shutdown).
    pub fn shutdown(&self) {
        self.running.store(false, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether a coordinator WS session is currently live (post-handshake). Drives `/healthz`.
    pub fn is_connected(&self) -> bool {
        self.connected.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Unix seconds of the last task frame handled, `None` if no task has arrived yet.
    pub fn last_task_at(&self) -> Option<i64> {
        match self.last_task_at.load(std::sync::atomic::Ordering::Relaxed) {
            0 => None,
            ts => Some(ts),
        }
    }

    /// Unix seconds of the last COMPLETED read-loop iteration, `None` before the first one.
    ///
    /// This is the WEDGE detector `/healthz` needs. A stuck frame handler never returns to the top of
    /// the loop, so this stops advancing while `is_connected()` stays true and `last_task_at()` looks
    /// merely idle. An idle-but-healthy link keeps it fresh on its own (the read-idle ping probe
    /// re-enters the loop every `READ_IDLE_TIMEOUT`), so staleness means stuck, not quiet.
    pub fn last_frame_at(&self) -> Option<i64> {
        match self.last_frame_at.load(std::sync::atomic::Ordering::Relaxed) {
            0 => None,
            ts => Some(ts),
        }
    }

    /// Force the `connected` flag down.
    ///
    /// `run()` clears it on every normal cycle, but a PANIC inside the loop task unwinds past that
    /// — and a stale `connected == true` makes `/healthz` answer `200` for a bridge that is dead,
    /// which is worse than no health check at all (a supervisor keeps a zombie alive). `run()`
    /// installs a drop guard that calls this during unwind, and `main` calls it when the loop task
    /// joins for any reason.
    pub fn mark_disconnected(&self) {
        self.connected.store(false, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether the coordinator rejected this worker's fleet token (401/403 on `/connect`). Distinct
    /// from a plain disconnect: the fix is an operator action (re-mint / re-export the token), not
    /// waiting. Reported by `/healthz` so that distinction is visible without reading logs.
    pub fn is_auth_rejected(&self) -> bool {
        self.auth_rejected.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Consecutive auth rejections (0 when the last connect attempt was not an auth failure).
    pub fn auth_failure_count(&self) -> u32 {
        self.auth_failures.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The last auth rejection message, for `/healthz`.
    pub async fn last_auth_error(&self) -> Option<String> {
        self.last_auth_error.lock().await.clone()
    }

    /// Live idempotency-ledger size (observability).
    pub fn tracked_tasks(&self) -> usize {
        self.tasks.len()
    }

    /// Poke the running read loop to re-send `local_catalog` immediately (a local catalog mutation).
    pub fn request_catalog_refresh(&self) {
        self.catalog_refresh.notify_one();
    }

    /// Main loop — connect + listen with auto-reconnect (full-jitter backoff). Mirrors
    /// `LinkedAgentBridge::run` / `SaaSBridge::run`.
    pub async fn run(&self) {
        self.running.store(true, std::sync::atomic::Ordering::Relaxed);

        // Clear `connected` on EVERY exit from this function, including a panic unwinding out of the
        // read loop — otherwise `/healthz` keeps answering 200 for a dead bridge.
        struct ConnectedGuard<'a>(&'a std::sync::atomic::AtomicBool);
        impl Drop for ConnectedGuard<'_> {
            fn drop(&mut self) {
                self.0.store(false, std::sync::atomic::Ordering::Relaxed);
            }
        }
        let _connected_guard = ConnectedGuard(&self.connected);

        // Prime the in-memory channel-key cache from the encrypted config kv (survives restarts).
        if let Ok(Some(ck)) = config_kv::get(&self.db, FLEET_CHANNEL_KEY_KEY).await {
            if !ck.is_empty() {
                *self.channel_key.lock().await = Some(ck);
            }
        }

        // Start the `BridgeOutgoing` → raw-`Message` forwarder ONCE for the life of the process.
        // Both channels are stable (they live on `self`), so this task never needs retiring and the
        // streaming relays / monitor loop keep a working sender across every reconnect. Spawned here
        // rather than in `listen` precisely because a per-connection forwarder was one of the places
        // an in-flight sender went dead on reconnect.
        if let Some(mut bridge_out_rx) = self.bridge_out_rx.lock().await.take() {
            let fwd = self.outgoing_tx.clone();
            tokio::spawn(async move {
                use crate::streaming::BridgeOutgoing;
                while let Some(bo) = bridge_out_rx.recv().await {
                    let msg = match bo {
                        BridgeOutgoing::Json(v) => Message::Text(v.to_string()),
                        BridgeOutgoing::Binary(b) => Message::Binary(b),
                    };
                    if fwd.send(msg).is_err() {
                        break; // only reachable if the bridge itself is gone
                    }
                }
            });
        }

        while self.running.load(std::sync::atomic::Ordering::Relaxed) {
            let started = tokio::time::Instant::now();
            let outcome = self.connect_and_listen().await;
            self.connected.store(false, std::sync::atomic::Ordering::Relaxed);
            let session = started.elapsed();

            if session >= Self::MIN_HEALTHY_SESSION {
                *self.reconnect_delay.lock().await = 1.0;
            }

            match outcome {
                // `listen` returns Ok on any clean close. Two very different things land here:
                //   * a DELIBERATE stop — the coordinator sent an explicit `disconnect` frame, or
                //     `shutdown()` was called; BOTH flip `self.running` to false before the read
                //     loop exits, so the `while`/`break` below terminates the bridge; or
                //   * the SERVER simply closed the stream (graceful coordinator restart/redeploy,
                //     idle LB reap, plain stream end) — `self.running` is still true, and an
                //     unattended worker must RECONNECT, not stop forever.
                // Only the deliberate stop is terminal. A clean close within MIN_HEALTHY_SESSION
                // still backs off (the reset above never ran), so an auth-reject loop that
                // accepts-then-closes cannot hot-loop.
                Ok(()) => {
                    if !self.running.load(std::sync::atomic::Ordering::Relaxed) {
                        break; // explicit `disconnect` frame or shutdown()
                    }
                    if session >= Self::MIN_HEALTHY_SESSION {
                        tracing::info!(
                            session_s = session.as_secs(),
                            "FleetBridge WS closed by server after a healthy session — reconnecting"
                        );
                    } else {
                        tracing::warn!(
                            session_ms = session.as_millis() as u64,
                            "FleetBridge WS closed cleanly within {:?} — treating as rejection + backing off",
                            Self::MIN_HEALTHY_SESSION,
                        );
                    }
                }
                Err(e) => {
                    if !self.running.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    tracing::warn!(error = %e, "FleetBridge connection lost, will back off");
                }
            }

            if !self.running.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }

            let delay = {
                let mut d = self.reconnect_delay.lock().await;
                let ceiling = *d;
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .subsec_nanos() as f64;
                let rand01 = nanos / 1_000_000_000.0;
                *d = (ceiling * 2.0).min(30.0);
                (ceiling * rand01).max(0.1)
            };
            // An auth rejection backs off HARDER than a transient failure. A revoked/rotated token
            // will not start working again in 30 seconds, and re-presenting a dead Bearer every 30s
            // forever both hides the problem and looks like credential stuffing to the coordinator.
            // Escalates 60s → 300s while the rejection persists; the very first attempt after a
            // successful connect is unaffected (the counter resets there).
            let delay = if self.is_auth_rejected() {
                let n = self.auth_failure_count().clamp(1, 5) as f64;
                (60.0 * n).min(300.0)
            } else {
                delay
            };
            tracing::warn!(
                delay_s = delay,
                auth_rejected = self.is_auth_rejected(),
                "FleetBridge sleeping before reconnect"
            );
            tokio::time::sleep(std::time::Duration::from_secs_f64(delay)).await;
        }

        // The bridge loop is over for good (a coordinator `disconnect`, or `shutdown()`). Nothing on
        // the fleet path used to close the warm browser: the desktop daemon calls
        // `BrowserManager::shutdown()` on its own teardown, but the fleet worker had no equivalent, so
        // Chromium — and every context still attached to it — was left to `Drop for Playwright`, which
        // SIGKILLs the node driver and orphans the browser + renderer children.
        //
        // A host binary that tears the browser down itself (the fleet main does, on every exit path)
        // makes this a no-op: `BrowserManager::shutdown` takes the browser out of its slot, so whoever
        // gets there first wins and the second call does nothing. Kept deliberately short so it fits
        // inside a supervisor's loop-stop grace rather than competing with it.
        self.shutdown_browser().await;
    }

    /// Close the warm browser (and stop the Playwright driver), bounded and idempotent.
    ///
    /// Best-effort by design: this runs on the way out, so a driver that does not answer must cost a
    /// few seconds and a log line, never the exit itself. Public so a host binary can order the
    /// teardown itself; calling it twice is harmless.
    pub async fn shutdown_browser(&self) {
        let Some(browser) = self.engine.browser() else { return };
        match tokio::time::timeout(Duration::from_secs(3), browser.shutdown()).await {
            Ok(Ok(())) => tracing::info!("warm browser closed on fleet shutdown"),
            Ok(Err(e)) => tracing::warn!(error = %e, "warm browser close failed on fleet shutdown"),
            Err(_) => tracing::warn!(
                "warm browser did not close within 3s on fleet shutdown — leaving it to process exit"
            ),
        }
    }

    async fn connect_and_listen(&self) -> Result<(), anyhow::Error> {
        // `connect` hands back any non-handshake frames it had to read past, so `listen` can serve
        // them instead of losing them (see the handshake buffering note in `connect`).
        let (ws, buffered) = self.connect().await?;
        self.listen(ws, buffered).await
    }

    /// Record a `/connect` auth rejection (401/403): a distinct, operator-visible state.
    async fn note_auth_rejected(&self, message: String) {
        self.auth_rejected.store(true, std::sync::atomic::Ordering::Relaxed);
        let n = self.auth_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        *self.last_auth_error.lock().await = Some(message.clone());
        tracing::error!(
            consecutive = n,
            "COORDINATOR REJECTED THIS WORKER'S FLEET TOKEN: {message}. The worker will keep \
             retrying (slowly) in case the token is re-minted, but it will receive NO work until \
             then. Fix: mint a fresh token in the coordinator (POST /api/fleet/tokens), export it \
             as WRIT_SERVICE_TOKEN, and restart this worker."
        );
    }

    /// Clear the auth-rejected state (any non-auth outcome from `/connect`).
    async fn clear_auth_rejected(&self) {
        if self.auth_rejected.swap(false, std::sync::atomic::Ordering::Relaxed) {
            tracing::info!("coordinator accepted the fleet token again");
        }
        self.auth_failures.store(0, std::sync::atomic::Ordering::Relaxed);
        *self.last_auth_error.lock().await = None;
    }

    /// Two-step connect: (1) POST `/api/recorder/connect` with the fleet Bearer, (2) WS to the
    /// returned gateway url with the gateway JWT in the Authorization header. Reads the `welcome`
    /// frame for the assigned agent_id and the `auth_ok` frame for the channel key. Mirrors
    /// `saas_bridge::connect` / `gateway::connect` but with NO cloud-token machinery.
    async fn connect(&self) -> Result<(WsStream, VecDeque<Message>), anyhow::Error> {
        require_secure_url(&self.base_url, self.allow_insecure, "coordinator")?;

        let stored_agent_id = config_kv::get(&self.db, FLEET_AGENT_ID_KEY)
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        {
            let mut aid = self.agent_id.lock().await;
            *aid = if stored_agent_id.is_empty() { None } else { Some(stored_agent_id.clone()) };
        }

        // Step 1: POST /api/recorder/connect with the fleet service token as Bearer. The body is a
        // non-secret routing/capability hint; identity is derived coordinator-side from the token.
        let client = reqwest::Client::new();
        // Isolation tier: an isolated-pool VM's cloud-init exports
        // WRIT_AGENT_TIER=isolated so sensitive (credential/persona) runs are
        // routed here and non-sensitive dispatch prefers shared boxes.
        let agent_tier = std::env::var("WRIT_AGENT_TIER")
            .ok()
            .filter(|t| t == "isolated")
            .unwrap_or_else(|| "shared".to_string());
        let connect_body = json!({
            // Governor-derived admissible capacity (see `advertised_capacity`), overridable via env +
            // coordinator set_capacity within that ceiling; never below what's already running.
            "max_sessions": (self.max_sessions() as u32).max(self.active_units() as u32).max(1),
            "captcha_trusted": false,
            "agent_id": stored_agent_id,
            "tier": agent_tier,
            // "streaming" advertises that this worker serves live streaming
            // sessions (it wires the shared streaming module), so the backend's
            // streaming-capable filter routes streaming here and the autoscaler's
            // streaming demand is actually drainable by scaling this pool.
            "capabilities": ["local_workflows", "streaming"],
            // Monitoring capability: advertise host capacity + check modes so the coordinator's
            // capacity-aware distributor can assign target time-slots to this worker (a fleet worker
            // is a shared monitoring-fleet node — it RUNS assigned checks). Parity with the cloud
            // recorder's connect body. A `monitor_register` frame re-advertises after the gateway
            // assigns our agent_id (see `listen`).
            "capacity": self.monitor.capacity.to_json(),
            "check_modes": ["content", "uptime", "playwright"],
            "platform": std::env::consts::OS,
            "device_name": device_name(),
            "version": env!("CARGO_PKG_VERSION"),
        });
        let resp = client
            .post(format!("{}/api/recorder/connect", self.base_url))
            .header("Authorization", format!("Bearer {}", self.token))
            .json(&connect_body)
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            let detail = truncate_str(&body, 200);
            // 401/403 is NOT the same failure as a 5xx and must not be reported as one: the token is
            // dead (revoked, rotated, or wrong coordinator) and no amount of retrying at the 30s
            // ceiling will fix it. Keep retrying — a re-mint is a legitimate recovery and an
            // unattended worker should heal itself — but say so at `error!`, expose the state to
            // `/healthz`, and back off much harder (see `run`).
            if matches!(status.as_u16(), 401 | 403) {
                self.note_auth_rejected(format!("/connect returned {status}: {detail}")).await;
                anyhow::bail!("coordinator rejected the fleet token ({status}): {detail}");
            }
            self.clear_auth_rejected().await;
            anyhow::bail!("coordinator /connect failed ({}): {}", status, detail);
        }
        self.clear_auth_rejected().await;
        let connect_data: Value = resp.json().await?;
        let gateway_ws_url = connect_data["gateway_ws_url"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing gateway_ws_url in /connect response"))?;
        let gateway_token = connect_data["gateway_token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing gateway_token in /connect response"))?;
        require_secure_url(gateway_ws_url, self.allow_insecure, "gateway")?;

        // Per-agent credential channel key returned by /connect for infra/service-
        // token agents (the ws-gateway path never sends `auth_ok` with a key). Cache
        // it so credentialed cloud-dispatch runs can Fernet-decrypt their
        // `credentials_encrypted` (which the backend re-encrypted under this key).
        // The `auth_ok` handler below still overrides it if the gateway ever does
        // send one.
        if let Some(ck) = connect_data["channel_key"].as_str() {
            if !ck.is_empty() {
                *self.channel_key.lock().await = Some(ck.to_string());
                if let Err(e) = config_kv::set(&self.db, FLEET_CHANNEL_KEY_KEY, ck).await {
                    tracing::warn!(error = %e, "failed to persist fleet channel key from /connect (continuing)");
                }
            }
        }

        // Build the WS url. The gateway JWT goes in the Authorization header (never the URL). The
        // `local_workflows=1` param opts this agent into hosting a coordinator-deployable catalog
        // (the coordinator gates `request_local_catalog` on it for trusted fleet-token agents); the
        // `ai_keys_configured` param advertises BYO-AI capability.
        let separator = if gateway_ws_url.contains('?') { "&" } else { "?" };
        let mut full_url = format!("{}{}role=recorder&local_workflows=1", gateway_ws_url, separator);
        if self.ai_keys_configured {
            full_url.push_str("&ai_keys_configured=1");
        }
        if !stored_agent_id.is_empty() {
            full_url.push_str(&format!("&agent_id={}", urlencoding(&stored_agent_id)));
        }

        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        use tokio_tungstenite::tungstenite::http::HeaderValue;
        let mut request = full_url
            .as_str()
            .into_client_request()
            .map_err(|e| anyhow::anyhow!("Failed to build gateway WS request: {}", e))?;
        let bearer = HeaderValue::from_str(&format!("Bearer {}", gateway_token))
            .map_err(|e| anyhow::anyhow!("Invalid gateway token header: {}", e))?;
        request.headers_mut().insert("Authorization", bearer);

        // Bounded WS config — see `WS_MAX_*`. `connect_async`'s defaults (64 MiB message / 16 MiB
        // frame / unbounded write buffer) are a remote OOM primitive.
        let ws_config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
            max_message_size: Some(WS_MAX_MESSAGE_SIZE),
            max_frame_size: Some(WS_MAX_FRAME_SIZE),
            max_write_buffer_size: WS_MAX_WRITE_BUFFER,
            ..Default::default()
        };
        let (ws_stream, _) =
            tokio_tungstenite::connect_async_with_config(request, Some(ws_config), false)
                .await
                .map_err(|e| anyhow::anyhow!("WebSocket connect failed: {}", e))?;

        // Read the post-auth frames: `welcome` (agent_id) then `auth_ok` (channel_key). The
        // coordinator sends `welcome` first, then `auth_ok`.
        //
        // Anything else that arrives in this window is BUFFERED and handed to `listen`, never
        // discarded. A coordinator that re-pushes state the instant the socket is up (on reconnect it
        // typically fires `assign_targets` / `assign_workflows` / `save_local_workflow` immediately,
        // and `send_and_await`s the acks) used to lose those frames here: the old `_ => continue`
        // arm CONSUMED them, so the coordinator's awaited future hung until its own timeout.
        let (write, mut read) = ws_stream.split();
        let mut assigned_agent_id = stored_agent_id.clone();
        let mut got_channel_key: Option<String> = None;
        let mut buffered: VecDeque<Message> = VecDeque::new();
        // Bound on how far we read ahead looking for `auth_ok`. Each non-handshake frame is buffered
        // rather than dropped, so a coordinator that talks first cannot starve the handshake.
        const HANDSHAKE_MAX_FRAMES: usize = 16;
        for _ in 0..HANDSHAKE_MAX_FRAMES {
            match tokio::time::timeout(std::time::Duration::from_secs(5), read.next()).await {
                Ok(Some(Ok(Message::Text(text)))) => {
                    let Ok(v) = serde_json::from_str::<Value>(&text) else {
                        // Not JSON: not ours to interpret, but not ours to swallow either.
                        buffered.push_back(Message::Text(text));
                        continue;
                    };
                    match v["type"].as_str() {
                        Some("welcome") => {
                            if let Some(id) = v["agent_id"].as_str() {
                                if !id.is_empty() {
                                    assigned_agent_id = id.to_string();
                                }
                            }
                        }
                        Some("auth_ok") => {
                            if let Some(id) = v["agent_id"].as_str() {
                                if !id.is_empty() {
                                    assigned_agent_id = id.to_string();
                                }
                            }
                            if let Some(ck) = v["channel_key"].as_str() {
                                if !ck.is_empty() {
                                    got_channel_key = Some(ck.to_string());
                                }
                            }
                            // auth_ok is the last handshake frame — stop reading ahead.
                            break;
                        }
                        Some("auth_error") => {
                            // A gateway-level auth rejection is the same operator problem as a 401
                            // from /connect — surface it identically instead of as a generic error.
                            let reason = v["reason"].as_str().unwrap_or("unknown");
                            let reason = truncate_str(reason, 200);
                            self.note_auth_rejected(format!("gateway auth_error: {reason}")).await;
                            anyhow::bail!("coordinator rejected auth: {}", reason);
                        }
                        // Real work that raced ahead of `auth_ok` — keep it for the read loop.
                        _ => buffered.push_back(Message::Text(v.to_string())),
                    }
                }
                // Control/data frames during the handshake: a Ping MUST be answered (buffer it so the
                // read loop replies with a proper Pong control frame), binary is screencast payload.
                Ok(Some(Ok(other))) => match other {
                    Message::Close(_) => anyhow::bail!("coordinator closed the WS during handshake"),
                    Message::Pong(_) => continue,
                    keep => buffered.push_back(keep),
                },
                Ok(None) => anyhow::bail!("coordinator closed the WS during handshake"),
                Ok(Some(Err(e))) => anyhow::bail!("WS read error during handshake: {}", e),
                Err(_) => break, // handshake read timed out — proceed with what we have
            }
        }
        if !buffered.is_empty() {
            tracing::info!(
                frames = buffered.len(),
                "buffered non-handshake frames that arrived during the coordinator handshake"
            );
        }

        let final_agent_id = if assigned_agent_id.is_empty() {
            format!("agent-{}", &uuid::Uuid::new_v4().to_string()[..8])
        } else {
            assigned_agent_id
        };
        {
            let mut aid = self.agent_id.lock().await;
            *aid = Some(final_agent_id.clone());
        }
        if final_agent_id != stored_agent_id {
            if let Err(e) = config_kv::set(&self.db, FLEET_AGENT_ID_KEY, &final_agent_id).await {
                tracing::warn!(error = %e, "failed to persist fleet agent_id (continuing)");
            }
        }
        if let Some(ck) = got_channel_key {
            *self.channel_key.lock().await = Some(ck.clone());
            // Persist to the encrypted config kv (Layer-A at rest) so a redeploy after a restart
            // that hasn't yet re-issued auth_ok can still open a sealed blob.
            if let Err(e) = config_kv::set(&self.db, FLEET_CHANNEL_KEY_KEY, &ck).await {
                tracing::warn!(error = %e, "failed to persist fleet channel key (continuing)");
            }
        }

        tracing::info!(agent_id = %final_agent_id, "FleetBridge connected to coordinator");
        self.connected.store(true, std::sync::atomic::Ordering::Relaxed);

        let ws_stream = read
            .reunite(write)
            .map_err(|e| anyhow::anyhow!("Reunite failed: {}", e))?;
        Ok((ws_stream, buffered))
    }

    /// The cached channel key (from `auth_ok`), if any. Read for every deploy decrypt.
    async fn current_channel_key(&self) -> Option<String> {
        self.channel_key.lock().await.clone()
    }

    /// Read loop: advertise the catalog on connect; answer `request_local_catalog`; service the
    /// fleet-local deploy frames + `run_local_workflow`; honor `disconnect`/`ping`. Long-running
    /// runs are spawned so frame I/O never blocks. Returns `Ok` on a clean close; `Err` to reconnect.
    async fn listen(
        &self,
        ws: WsStream,
        mut pending_in: VecDeque<Message>,
    ) -> Result<(), anyhow::Error> {
        let (mut write, mut read) = ws.split();

        // Take the STABLE outgoing receiver for this connection cycle (the sender lives on `self`
        // and is cloned into every spawned handler — see `outgoing_tx`). The writer task hands the
        // receiver BACK when the cycle ends, so senders held by in-flight work keep delivering
        // across a reconnect. Same shape as `saas_bridge` (CR-1).
        // NOT `?`: this is the one exit from `listen` that does not go through the post-loop cleanup
        // below, so the session registries would keep whatever the PREVIOUS cycle left behind. The
        // receiver never comes back once it is leaked, so every later attempt fails here too — i.e.
        // exactly the path on which "wait for the idle reaper" degenerates into "never".
        // Bind the `take()` first so the guard is released before the `await` below — the scrutinee's
        // temporaries would otherwise live for the whole `match`.
        let taken_rx = self.outgoing_rx.lock().await.take();
        let mut outgoing_rx = match taken_rx {
            Some(rx) => rx,
            None => {
                crate::local::browse::close_all().await;
                crate::local::record::bridge::close_all();
                return Err(anyhow::anyhow!(
                    "outgoing receiver already taken (writer task leaked)"
                ));
            }
        };

        // Stop signal so the writer can be retired WITHOUT dropping the receiver.
        let (writer_stop_tx, mut writer_stop_rx) = tokio::sync::oneshot::channel::<()>();
        let mut write_handle: JoinHandle<mpsc::UnboundedReceiver<Message>> = tokio::spawn(async move {
            // Control frames rescued by a shed pass; written before anything newer is pulled so the
            // surviving frames keep their relative order.
            let mut rescued: VecDeque<Message> = VecDeque::new();
            'writer: loop {
                while let Some(msg) = rescued.pop_front() {
                    if !write_frame(&mut write, msg).await {
                        break 'writer;
                    }
                }
                tokio::select! {
                    _ = &mut writer_stop_rx => break 'writer,
                    maybe = outgoing_rx.recv() => match maybe {
                        Some(msg) => {
                            // Bound the queue: an unbounded SENDER (required — ~20 call sites clone
                            // it) must not mean unbounded MEMORY when the peer stops reading.
                            if outgoing_rx.len() > OUTGOING_SOFT_CAP {
                                match shed_backlog(
                                    &mut outgoing_rx,
                                    |m| matches!(m, Message::Binary(_)),
                                    OUTGOING_HARD_CAP,
                                ) {
                                    ShedOutcome::Shed { keep, dropped } => {
                                        if dropped > 0 {
                                            tracing::warn!(
                                                dropped,
                                                kept = keep.len(),
                                                "outgoing WS backlog over cap — dropped stale screencast frames"
                                            );
                                        }
                                        rescued = keep;
                                    }
                                    ShedOutcome::Overflow { queued } => {
                                        tracing::error!(
                                            queued,
                                            cap = OUTGOING_HARD_CAP,
                                            "coordinator stopped reading — dropping this WS session instead of buffering without bound"
                                        );
                                        break 'writer;
                                    }
                                }
                            }
                            if !write_frame(&mut write, msg).await {
                                break 'writer;
                            }
                        }
                        None => break 'writer, // sender dropped (never: it lives on `self`)
                    },
                }
            }
            // Hand the receiver back for the next connect cycle.
            outgoing_rx
        });

        // Local aliases so the (large) frame-dispatch body below is unchanged: both senders are the
        // STABLE ones on `self`.
        let outgoing_tx = self.outgoing_tx.clone();
        let bridge_out_tx = self.bridge_out_tx.clone();

        // Advertise the catalog immediately (metadata only).
        self.send_catalog(&outgoing_tx).await;

        // Heartbeat — keep this agent in the coordinator's dispatchable registry.
        // Reports the LIVE advertised capacity each beat, so a runtime
        // set_capacity (or an env-detected value) reaches dispatch + autoscale.
        let heartbeat_handle: JoinHandle<()> = {
            let hb_tx = outgoing_tx.clone();
            let hb_engine = self.engine.clone();
            let hb_cap = self.max_sessions.clone();
            let hb_inflight = self.inflight.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(25)).await;
                    let msg = json!({
                        "type": "heartbeat",
                        // ALL in-flight dispatch, not just engine runs: crawl shards, raw
                        // `execute_workflow`, streaming, AI/browse sessions and monitor checks were
                        // invisible here, so a saturated worker reported itself idle and the
                        // coordinator kept pushing until the box OOMed.
                        "active_sessions": hb_inflight
                            .load(std::sync::atomic::Ordering::SeqCst)
                            .max(hb_engine.active_runs()),
                        "max_sessions": hb_cap.load(std::sync::atomic::Ordering::Relaxed).max(1),
                        "platform": std::env::consts::OS,
                        "version": env!("CARGO_PKG_VERSION"),
                        "role": "fleet",
                    });
                    if hb_tx.send(Message::Text(msg.to_string())).is_err() {
                        break;
                    }
                }
            })
        };

        // Per-session force-Stop registry: session_id -> cancel flag. The `ai_session_cancel` frame
        // sets a session's flag; the running session loop polls it and aborts mid-turn. Frames are
        // handled concurrently (each `ai_session_start` runs in its own spawned task), so a cancel
        // frame arrives + takes effect while the session is still running.
        let ai_cancels: Arc<tokio::sync::Mutex<std::collections::HashMap<String, Arc<std::sync::atomic::AtomicBool>>>> =
            Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

        // Shared recorder for coordinator-dispatched RECORDING sessions (`session_open{purpose:
        // record}`) — wraps the SAME warm `BrowserManager` the run engine drives (one Chromium, never
        // a second). Built once per connection. NOTE: the record registry no longer survives a
        // reconnect — the cleanup at the bottom of this function drops every session when the listen
        // loop exits, because a WS drop is the point at which nothing can address them again (see the
        // `close_all` note there). A coordinator that reconnects re-opens its sessions. `None` only on
        // a browserless/stub engine, in which case `record::open` fails closed with a clear ack
        // instead of hanging.
        let recorder: Option<Arc<crate::recorder::core::PlaywrightRecorder>> = self
            .engine
            .browser()
            .map(|bm| Arc::new(crate::recorder::core::PlaywrightRecorder::new(bm)));

        // Autonomous MONITORING loop (scheduled parallel target checks) — the SAME
        // `monitor::run_monitor_loop` the cloud recorder runs. A fleet worker is a shared
        // monitoring-fleet node, so it RUNS coordinator-assigned checks (parity with saas_bridge).
        // Spawned only when the engine exposes a browser (JS/visual checks need it); a browserless
        // stub simply skips monitoring. `monitor_register` re-advertises capacity now that the gateway
        // assigned our agent_id (the /connect POST couldn't carry it on first connect). The loop emits
        // `target_check_batch`/`precheck_complete` via the shared `BridgeOutgoing` channel.
        let mut monitor_handle: Option<JoinHandle<()>> = None;
        let monitor_running = Arc::new(std::sync::atomic::AtomicBool::new(false));
        if let Some(browser) = self.engine.browser() {
            let aid_now = self.agent_id.lock().await.clone();
            if let Some(aid) = aid_now.clone().filter(|a| !a.is_empty()) {
                let _ = outgoing_tx.send(Message::Text(
                    json!({
                        "type": "monitor_register",
                        "agent_id": aid,
                        "capacity": self.monitor.capacity.to_json(),
                        "check_modes": ["content", "uptime", "playwright"],
                    })
                    .to_string(),
                ));
            }
            monitor_running.store(true, std::sync::atomic::Ordering::Relaxed);
            let state = self.monitor.clone();
            let outgoing = bridge_out_tx.clone();
            let agent_id = Arc::new(tokio::sync::RwLock::new(aid_now));
            let running_loop = monitor_running.clone();
            let channel_key = self.current_channel_key().await;
            monitor_handle = Some(tokio::spawn(async move {
                crate::monitor::run_monitor_loop(
                    state, browser, outgoing, agent_id, running_loop, channel_key,
                )
                .await;
            }));
        }

        // Half-open-connection detector: probe with a client-initiated Ping after a silent stretch
        // and require a Pong. Without it a black-holed TCP flow parks this loop in `read.next()` for
        // ~15 minutes (Linux default) while `/healthz` stays green and the coordinator has already
        // reaped us. See `WsLiveness` for the full rationale.
        let mut liveness = WsLiveness::new(READ_IDLE_TIMEOUT, PONG_GRACE);
        // Set when the writer task is joined inside the loop, so the cleanup below does not poll a
        // finished JoinHandle.
        let mut reclaimed_rx: Option<mpsc::UnboundedReceiver<Message>> = None;

        let result: Result<(), anyhow::Error> = loop {
            // READ-LOOP LIVENESS STAMP — read by `/healthz`.
            //
            // Stamped at the TOP of the body, so it ticks once per COMPLETED iteration. That is the
            // property that makes it a wedge detector: if a handler hangs (a blocked await, a
            // non-advancing loop), control never returns here and the stamp goes stale, which is
            // invisible in every other signal — `is_connected` was set at handshake, `last_task_at`
            // only moves for task frames, and `WsLiveness` only catches a dead SOCKET, not a live
            // socket with a stuck reader.
            //
            // It must not false-positive on an idle-but-healthy link, and it doesn't: an idle
            // connection still comes back through here every `READ_IDLE_TIMEOUT` via the ping-probe
            // arm below (which `continue`s), so the stamp stays fresh with zero coordinator traffic.
            self.last_frame_at
                .store(chrono::Utc::now().timestamp(), std::sync::atomic::Ordering::Relaxed);

            if !self.running.load(std::sync::atomic::Ordering::Relaxed) {
                break Ok(());
            }

            // Frames buffered during the handshake are served BEFORE new reads (bug: they used to be
            // consumed and dropped, hanging the coordinator's `send_and_await`).
            let frame: Message = if let Some(buffered) = pending_in.pop_front() {
                buffered
            } else {
                let wait = liveness.timeout(Instant::now());
                tokio::select! {
                    _ = self.catalog_refresh.notified() => {
                        self.send_catalog_fresh(&outgoing_tx).await;
                        continue;
                    }
                    // The write half died (write error, or the peer's window shut for WRITE_TIMEOUT,
                    // or the backlog blew the hard cap). A dead writer used to leave the read loop
                    // parked forever, silently unable to answer anything.
                    joined = &mut write_handle => {
                        match joined {
                            Ok(rx) => reclaimed_rx = Some(rx),
                            Err(e) => tracing::error!(error = %e, "outgoing WS writer task failed"),
                        }
                        break Err(anyhow::anyhow!(
                            "outgoing WS writer stopped — tearing down the session to reconnect"
                        ));
                    }
                    res = tokio::time::timeout(wait, read.next()) => match res {
                        Err(_elapsed) => match liveness.on_idle(Instant::now()) {
                            ProbeAction::SendPing => {
                                tracing::debug!("no coordinator frame for {READ_IDLE_TIMEOUT:?} — probing with a WS ping");
                                let _ = outgoing_tx.send(Message::Ping(Vec::new()));
                                continue;
                            }
                            ProbeAction::PeerDead => break Err(anyhow::anyhow!(
                                "coordinator did not answer a WS ping within {PONG_GRACE:?} — \
                                 connection is half-open, reconnecting"
                            )),
                        },
                        Ok(Some(Ok(m))) => m,
                        Ok(Some(Err(e))) => break Err(anyhow::anyhow!("WS read error: {}", e)),
                        Ok(None) => break Ok(()),
                    }
                }
            };

            // ANY inbound frame proves the path is alive.
            liveness.on_frame();

            let raw = match frame {
                Message::Text(text) => text,
                Message::Ping(data) => {
                    // A real Pong CONTROL frame (not a data frame — see the saas_bridge fix).
                    let _ = outgoing_tx.send(Message::Pong(data));
                    continue;
                }
                Message::Binary(_) | Message::Pong(_) | Message::Frame(_) => continue,
                Message::Close(_) => break Ok(()),
            };

            let msg: Value = match serde_json::from_str(&raw) {
                Ok(v) => v,
                Err(_) => continue,
            };

            // Session-channel frame `{channel:"session", session_id, msg:{...}}`. The addressed
            // session_id may belong to (1) a live STREAMING session, (2) a live RECORDING session
            // (self-host coordinator "Record"), or (3) a backend-orchestrated CONCIERGE/browse
            // session. Route to whichever owns it — mirrors the cloud bridge + the desktop
            // LinkedAgent gateway.
            if msg["channel"].as_str() == Some("session") {
                if let Some(sid) = msg["session_id"].as_str() {
                    let inner = msg.get("msg").cloned().unwrap_or_else(|| msg.clone());
                    if let Some(relay) = self.active_relays.get(sid) {
                        relay.dispatch_incoming(inner);
                    } else if crate::local::record::bridge::dispatch_wrapped(sid, inner.clone()) {
                        // Routed to the live recording SessionDriver (nothing more to do here).
                    } else if let Some(browser) = self.engine.browser() {
                        // Backend-orchestrated CONCIERGE/browse session: the cloud sends `agent_action`
                        // wrapped here but correlates on the TOP-LEVEL request_id and expects
                        // `agent_action_result` TOP-LEVEL. Inject the addressed session_id (+ request_id)
                        // the wrapped inner frame omits, run the SHARED browse handler, and reply
                        // UNWRAPPED so `send_and_await` correlates.
                        let mut inner = inner;
                        if let Some(obj) = inner.as_object_mut() {
                            obj.entry("session_id").or_insert_with(|| json!(sid));
                            if let Some(rid) = msg.get("request_id") {
                                obj.entry("request_id").or_insert_with(|| rid.clone());
                            }
                        }
                        let out = outgoing_tx.clone();
                        tokio::spawn(async move {
                            if let Some(reply) =
                                crate::local::browse::handle(&inner, Some(&browser)).await
                            {
                                let _ = out.send(Message::Text(reply.to_string()));
                            }
                        });
                    }
                }
                continue;
            }

            let msg_type = msg["type"].as_str().unwrap_or("");

            // Best-effort `/healthz` observability: stamp the arrival of any task-ish frame.
            if matches!(msg_type, "run_local_workflow" | "execute_workflow" | "ai_session_start") {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                self.last_task_at.store(now, std::sync::atomic::Ordering::Relaxed);
            }

            match msg_type {
                "ping" => {
                    let _ = outgoing_tx.send(Message::Text(json!({"type": "pong"}).to_string()));
                }
                // A late/refreshed channel key (e.g. after a reconnect the coordinator re-issues
                // auth_ok). Cache it so subsequent deploys open.
                "auth_ok" => {
                    if let Some(ck) = msg["channel_key"].as_str() {
                        if !ck.is_empty() {
                            *self.channel_key.lock().await = Some(ck.to_string());
                            let _ = config_kv::set(&self.db, FLEET_CHANNEL_KEY_KEY, ck).await;
                        }
                    }
                }
                "request_local_catalog" => {
                    // A ~40-byte frame that used to buy a full sha256 + placeholder scan of the whole
                    // stored corpus, SYNCHRONOUSLY IN THIS LOOP. Now: rate-limited, served from the
                    // cache, and always built on a spawned task so frame I/O never stalls.
                    self.spawn_catalog_send(&outgoing_tx).await;
                }
                "save_local_workflow" => {
                    let out = outgoing_tx.clone();
                    let db = self.db.clone();
                    let vault = self.vault.clone();
                    let channel_key = self.current_channel_key().await;
                    let msg = msg.clone();
                    let cache = self.catalog_cache.clone();
                    tokio::spawn(async move {
                        let ack = handle_save_local_workflow(&db, &vault, channel_key.as_deref(), &msg).await;
                        let _ = out.send(Message::Text(ack.to_string()));
                        // Re-advertise the catalog so the coordinator refreshes its LocalWorkflow rows.
                        send_catalog_to(&db, &cache, &out).await;
                    });
                }
                "save_local_secret" => {
                    let out = outgoing_tx.clone();
                    let db = self.db.clone();
                    let vault = self.vault.clone();
                    let channel_key = self.current_channel_key().await;
                    let msg = msg.clone();
                    let cache = self.catalog_cache.clone();
                    tokio::spawn(async move {
                        let ack = handle_save_local_secret(&db, &vault, channel_key.as_deref(), &msg).await;
                        let _ = out.send(Message::Text(ack.to_string()));
                        send_catalog_to(&db, &cache, &out).await;
                    });
                }
                "save_local_persona" => {
                    let out = outgoing_tx.clone();
                    let db = self.db.clone();
                    let vault = self.vault.clone();
                    let channel_key = self.current_channel_key().await;
                    let msg = msg.clone();
                    let cache = self.catalog_cache.clone();
                    tokio::spawn(async move {
                        let ack = handle_save_local_persona(&db, &vault, channel_key.as_deref(), &msg).await;
                        let _ = out.send(Message::Text(ack.to_string()));
                        send_catalog_to(&db, &cache, &out).await;
                    });
                }
                "run_local_workflow" => {
                    let task_id = id_str(&msg["task_id"]);
                    // The frozen run contract keys the id as `local_id`; the existing
                    // `LinkedAgentBridge` keys it as `local_workflow_id`. Accept EITHER so this
                    // agent works against both the fleet coordinator and the legacy dispatcher.
                    let local_id = msg["local_id"]
                        .as_str()
                        .or_else(|| msg["local_workflow_id"].as_str())
                        .unwrap_or("")
                        .to_string();
                    let inputs = msg.get("inputs").cloned().unwrap_or_else(|| json!({}));
                    // At-least-once dispatch: a redispatch of the same task_id must be ANSWERED, not
                    // re-run. These workflows submit forms and place orders.
                    if !self.accept_task(&task_id, &outgoing_tx) {
                        continue;
                    }
                    tracing::info!(task_id, local_id, "FleetBridge received run_local_workflow");
                    let engine = self.engine.clone();
                    let db = self.db.clone();
                    let out = outgoing_tx.clone();
                    let claim = TaskClaim::new(self.tasks.clone(), task_id.clone());
                    let busy = InflightGuard::new(self.inflight.clone());
                    let dispatched = self.dispatched_runs.clone();
                    tokio::spawn(async move {
                        // Held for the whole run: `busy` so the heartbeat reports this worker as
                        // occupied, `claim` so a duplicate dispatch is answered not re-run.
                        let _busy = busy;
                        let frame =
                            run_local_workflow(&engine, &db, &task_id, &local_id, inputs, &dispatched)
                                .await;
                        claim.settle(&out, frame);
                    });
                }
                // `execute_workflow` serves TWO dispatch shapes:
                //   * DRAGNET distributed crawl — the coordinator dispatches each shard as an
                //     `execute_workflow` whose single step is `crawl_batch` and whose
                //     `trigger_context` carries the URL batch (`_crawl_shard`) + extraction spec
                //     (`_crawl_extract`). Served via the SHARED shard runner (HTTP-first + browser
                //     fallback, markdown/schema, link harvest), replying the reply-awaited
                //     `task_result` (payload under `result_data`, the fleet-crawl contract).
                //   * a RAW full-definition workflow push (coordinator UI "Run" of a plain
                //     coordinator-stored workflow) — steps/credentials/session_state ride in the
                //     message config; executed through the SHARED `wire_exec` executor (the exact
                //     code path the cloud `saas_bridge` runs), with the channel key opening
                //     `credentials_encrypted`. Shapes a fleet worker genuinely cannot run
                //     (streaming / AI-loop) are pre-flight rejected with a clear error so the
                //     coordinator's awaited future resolves instead of hanging.
                "execute_workflow" => {
                    let task_id = id_str(&msg["task_id"]);
                    // Idempotency guard (see `run_local_workflow`): a crawl shard re-run wastes
                    // bandwidth, but a re-run wire workflow repeats real side effects.
                    if !self.accept_task(&task_id, &outgoing_tx) {
                        continue;
                    }
                    let claim = TaskClaim::new(self.tasks.clone(), task_id.clone());
                    // ADMISSION. Neither of these paths ever touched the governor: they call
                    // `create_stealth_context_with_fingerprint_proxy` on the `BrowserManager`
                    // directly, so 16 shards × the shard concurrency constant of fetches plus browser
                    // fallbacks could run with no local ceiling at all. Admit them on the same
                    // background lane as a by-id run, and REFUSE with a resolved `task_result` when
                    // there is no room — the coordinator's awaited future must resolve, not hang.
                    let permit = match self.admit_dispatch().await {
                        Ok(p) => p,
                        Err(reason) => {
                            self.refuse_at_capacity(&task_id, reason, &outgoing_tx);
                            // The claim is dropped (releasing its ledger slot) and the refusal is
                            // deliberately NOT recorded as a terminal result: "at capacity" is
                            // transient, so a later redispatch of this task_id must be free to
                            // actually run rather than replay a cached failure for the result TTL.
                            drop(claim);
                            continue;
                        }
                    };
                    let busy = InflightGuard::new(self.inflight.clone());
                    if let Some(config) = crawl_shard_config(&msg) {
                        tracing::info!(task_id, "FleetBridge received crawl shard (execute_workflow/crawl_batch)");
                        let browser = self.engine.browser();
                        let out = outgoing_tx.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            let _busy = busy;
                            // Live page tally while the batch runs. A 25-URL browser-lane shard is a
                            // minute of work; without this the coordinator's crawl counters cannot
                            // move until it ends, and the run reads as frozen on its first page.
                            let progress = spawn_crawl_progress_forwarder(out.clone(), task_id.clone());
                            let frame = crate::crawl_shard::run_shard_from_message(
                                browser, &task_id, &config, Some(progress),
                            ).await;
                            claim.settle(&out, frame);
                        });
                    } else {
                        tracing::info!(task_id, "FleetBridge received raw execute_workflow");
                        let engine = self.engine.clone();
                        let out = outgoing_tx.clone();
                        let channel_key = self.current_channel_key().await;
                        let msg = msg.clone();
                        let ledger = self.tasks.clone();
                        tokio::spawn(async move {
                            // The shared executor emits its own frames, so the ledger is recorded by
                            // the sink wrapper inside `execute_wire_workflow`; the claim guard is
                            // held here so a panic releases the slot for a legitimate retry.
                            let _claim = claim;
                            let _permit = permit;
                            let _busy = busy;
                            execute_wire_workflow(&engine, channel_key.as_deref(), &task_id, &msg, &out, &ledger).await;
                        });
                    }
                }
                // Coordinator-side cancel of a dispatched task.
                //
                // This used to be a log line and NOTHING else ("in-flight run not torn down — cloud-
                // bridge parity"), with no ack: a user pressing Stop changed nothing while the worker
                // kept driving the browser and holding its concurrency slot. A working cooperative
                // cancel already existed (`LocalEngine::cancel` → `RunRegistry::cancel` → the
                // `CancelToken` the step loop polls between steps) — it just had no way to map the
                // coordinator's `task_id` onto a local `run_id`. It does now (`dispatched_runs`).
                "cancel_task" => {
                    let task_id = id_str(&msg["task_id"]);
                    self.handle_cancel_task(&task_id, &outgoing_tx);
                }
                // Coordinator-pushed MONITORING assignment → drive the SAME `MonitorState` the cloud
                // recorder uses (the fleet worker RUNS these checks — shared fleet node). The loop
                // task spawned above executes due batches + reports `target_check_batch` frames.
                //
                // All four are SPAWNED, never awaited inline: each takes the monitor's assignment
                // mutex and re-groups the whole target set, so a slow (or wedged) scheduler inside
                // one of them used to stop ALL frame I/O — no acks, no task results, no pongs.
                "assign_targets" => {
                    let monitor = self.monitor.clone();
                    let msg = msg.clone();
                    tokio::spawn(async move { monitor.assign_targets(&msg).await });
                }
                "target_sync" => {
                    let monitor = self.monitor.clone();
                    let msg = msg.clone();
                    tokio::spawn(async move { monitor.apply_sync(&msg).await });
                }
                "check_target_now" => {
                    if let Some(tid) = msg.get("target_id").and_then(|v| v.as_i64()) {
                        let monitor = self.monitor.clone();
                        tokio::spawn(async move { monitor.check_target_now(tid).await });
                    }
                }
                "assign_workflows" => {
                    let monitor = self.monitor.clone();
                    let msg = msg.clone();
                    tokio::spawn(async move { monitor.assign_workflows(&msg).await });
                }
                // The coordinator dispatches ONE autonomous AI session (browse a site, fill a form,
                // optionally record a workflow). Needs the local AI engine + browser, so it is
                // `local`-gated; run the whole loop in a spawned task and reply
                // `ai_session_complete`/`ai_session_failed` correlated by `session_id`. A record
                // re-advertises the catalog so the coordinator mirrors the new workflow.
                #[cfg(feature = "local")]
                "ai_session_start" => {
                    let out = outgoing_tx.clone();
                    let db = self.db.clone();
                    let vault = self.vault.clone();
                    let engine = self.engine.clone();
                    let channel_key = self.current_channel_key().await;
                    let msg = msg.clone();
                    // Register a cancel flag under this session id so an `ai_session_cancel` frame can
                    // force-Stop it mid-run; removed when the session finishes.
                    let sid = id_str(&msg["session_id"]);
                    let cancel_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
                    ai_cancels.lock().await.insert(sid.clone(), cancel_flag.clone());
                    let ai_cancels_cleanup = ai_cancels.clone();
                    let cache = self.catalog_cache.clone();
                    // An AI session drives a real browser context for minutes — it must count toward
                    // the advertised active-session number like any other unit of work.
                    let busy = InflightGuard::new(self.inflight.clone());
                    tokio::spawn(async move {
                        let _busy = busy;
                        // Isolate ALL failures from the WS loop: on any error reply
                        // `ai_session_failed` rather than panicking the task.
                        let (reply, recorded) =
                            handle_ai_session_start(&db, &vault, &engine, channel_key.as_deref(), &msg, Some(cancel_flag)).await;
                        ai_cancels_cleanup.lock().await.remove(&sid);
                        let _ = out.send(Message::Text(reply.to_string()));
                        // On a successful record, re-advertise the catalog so the coordinator mirrors
                        // the new workflow (same path save_local_workflow uses).
                        if recorded {
                            send_catalog_to(&db, &cache, &out).await;
                        }
                    });
                }
                // Coordinator force-Stop: set the running session's cancel flag so its loop aborts
                // mid-turn (the session then finalizes 'cancelled' and replies ai_session_complete).
                #[cfg(feature = "local")]
                "ai_session_cancel" => {
                    let sid = id_str(&msg["session_id"]);
                    let hit = {
                        let guard = ai_cancels.lock().await;
                        if let Some(flag) = guard.get(&sid) {
                            flag.store(true, std::sync::atomic::Ordering::Relaxed);
                            true
                        } else {
                            false
                        }
                    };
                    let _ = outgoing_tx.send(Message::Text(json!({
                        "type": "ai_session_cancelled",
                        "session_id": sid,
                        "found": hit,
                    }).to_string()));
                }
                // Fleet build WITHOUT the local AI engine: degrade gracefully so the coordinator's
                // `send_and_await` resolves (with a clear error) instead of hanging on an ignored frame.
                #[cfg(not(feature = "local"))]
                "ai_session_start" => {
                    let session_id = id_str(&msg["session_id"]);
                    let _ = outgoing_tx.send(Message::Text(
                        json!({
                            "type": "ai_session_failed",
                            "session_id": session_id,
                            "status": "error",
                            "error": "ai_unavailable",
                        })
                        .to_string(),
                    ));
                }
                // The coordinator asks THIS agent to live-optimize one of its own deployed workflows:
                // replay it in a real browser with network capture on, then propose + live-verify
                // DOM→api_call/login_post substitutions. Needs the local AI engine + browser, so it is
                // `local`-gated; the (30–120s) replay runs in a spawned task and replies
                // `optimize_workflow_live_result` correlated by `request_id`. The daemon owns the recipe
                // + secrets — only `{local_id, confirm_side_effects}` cross the wire, and the returned
                // diff carries `{{placeholders}}` (never plaintext).
                #[cfg(feature = "local")]
                "optimize_workflow_live" => {
                    let out = outgoing_tx.clone();
                    let db = self.db.clone();
                    let vault = self.vault.clone();
                    let engine = self.engine.clone();
                    let msg = msg.clone();
                    tokio::spawn(async move {
                        let reply = handle_optimize_workflow_live(&db, &vault, &engine, &msg).await;
                        let _ = out.send(Message::Text(reply.to_string()));
                    });
                }
                // Fleet build WITHOUT the local AI engine: degrade so the coordinator's `send_and_await`
                // resolves with a clear error instead of hanging on an ignored frame.
                #[cfg(not(feature = "local"))]
                "optimize_workflow_live" => {
                    let request_id = id_str(&msg["request_id"]);
                    let _ = outgoing_tx.send(Message::Text(
                        json!({
                            "type": "optimize_workflow_live_result",
                            "request_id": request_id,
                            "error": "ai_unavailable",
                        })
                        .to_string(),
                    ));
                }
                "set_capacity" => {
                    // Coordinator/admin adjusts this worker's advertised capacity
                    // at runtime; re-advertised on the next heartbeat + a catalog
                    // poke so dispatch/autoscale pick it up without a reconnect.
                    if let Some(n) = msg["max_sessions"].as_u64() {
                        self.set_max_sessions(n as usize);
                    }
                }
                "start_streaming_session" => {
                    // Serve a LIVE streaming session via the SHARED handler (same
                    // code the cloud bridge runs). We resolve credentials/proxy the
                    // fleet way (channel-key decrypt) and hand them in.
                    let task_id = id_str(&msg["task_id"]);
                    let session_key = msg["config"]["session_key"].as_str()
                        .or_else(|| msg["session_key"].as_str())
                        .unwrap_or("").to_string();
                    let Some(browser_mgr) = self.engine.browser() else {
                        tracing::warn!("start_streaming_session: no browser on this engine — cannot stream");
                        continue;
                    };
                    let channel_key = self.current_channel_key().await;
                    let config = msg["config"].clone();
                    let credentials = crate::bridge::wire_exec::resolve_credentials(
                        &config, channel_key.as_deref());
                    let proxy_override = crate::bridge::wire_exec::extract_proxy_override(
                        &config, channel_key.as_deref());
                    let msg_clone = msg.clone();
                    let out = bridge_out_tx.clone();
                    let relays = self.active_relays.clone();
                    // A live streaming session holds a browser context for as long as the user keeps
                    // it open; count it as an active session.
                    let busy = InflightGuard::new(self.inflight.clone());
                    tokio::spawn(async move {
                        let _busy = busy;
                        crate::bridge::streaming_session::handle_start_streaming_session(
                            &task_id, &session_key, &msg_clone,
                            &browser_mgr, &out, &relays,
                            credentials, proxy_override,
                        ).await;
                    });
                }
                "streaming_command" => {
                    // Interaction command from the frontend → route to the session
                    // relay (the session loop drains it via handle_command).
                    let session_key = msg["session_key"].as_str().unwrap_or("");
                    if let Some(relay) = self.active_relays.get(session_key) {
                        relay.dispatch_incoming(msg.clone());
                    }
                }
                "end_streaming_session" => {
                    let session_key = msg["session_key"].as_str().unwrap_or("");
                    if let Some((_, relay)) = self.active_relays.remove(session_key) {
                        relay.close();
                    }
                }
                // Coordinator-dispatched RECORDING session ("Record" on the self-host coordinator):
                // `session_open{purpose:record}` then frames multiplexed as `{channel:session,...}`
                // (routed above). Served by the SHARED record router over the SAME `SessionDriver`
                // the desktop `/ws/record` + cloud-link recording drive — no reimplementation.
                "session_open" if crate::local::record::bridge::is_record_open(&msg) => {
                    let recorder = recorder.clone();
                    let out = outgoing_tx.clone();
                    let msg = msg.clone();
                    tokio::spawn(async move {
                        let ack =
                            crate::local::record::bridge::open(&msg, recorder.as_ref(), &out).await;
                        let _ = out.send(Message::Text(ack.to_string()));
                    });
                }
                "session_close"
                    if crate::local::record::bridge::is_active(
                        crate::local::record::bridge::session_id_of(&msg).as_str(),
                    ) =>
                {
                    let sid = crate::local::record::bridge::session_id_of(&msg);
                    let ack = crate::local::record::bridge::close(&sid);
                    let _ = outgoing_tx.send(Message::Text(ack.to_string()));
                }
                // Backend-orchestrated interactive/AI browsing (the cloud CONCIERGE): open a live
                // session on the warm browser and drive it step-by-step via `agent_action`. REUSES the
                // SHARED `local::browse` handler (same `run_agent_actions` + auth-harvest the desktop
                // cloud-link runs). Serving these closes the `ai_session_open` HANG: the backend
                // dispatches `ai_session_open` to ANY role=recorder agent with a free slot (NO
                // capability gate — `_pick_ai_recorder_agent`), so a fleet-backed recorder that ignored
                // it wedged the backend's `send_and_await`, exactly like the streaming runaway. The
                // fleet worker trusts its coordinator (as for `execute_workflow`/streaming), so the
                // desktop's foreign-tenant supply-pool gate is intentionally not applied here.
                "session_open" | "session_close" | "ai_session_open" | "ai_session_close"
                | "agent_action" => {
                    let out = outgoing_tx.clone();
                    let msg = msg.clone();
                    let browser = self.engine.browser();
                    tokio::spawn(async move {
                        if let Some(reply) =
                            crate::local::browse::handle(&msg, browser.as_ref()).await
                        {
                            let _ = out.send(Message::Text(reply.to_string()));
                        }
                    });
                }
                // A backend spectator started/stopped watching a live concierge session → screencast
                // its page back as `spectate_frame`s (the coordinator relays them to the frontend).
                "spectate_start" => {
                    let sid = msg["session_id"].as_str().unwrap_or("").to_string();
                    crate::local::browse::start_spectate(&sid, outgoing_tx.clone());
                }
                "spectate_stop" => {
                    let sid = msg["session_id"].as_str().unwrap_or("").to_string();
                    crate::local::browse::stop_spectate(&sid);
                }
                "disconnect" => {
                    let reason = msg["reason"].as_str().unwrap_or("unknown");
                    tracing::warn!(reason, "FleetBridge: coordinator requested disconnect");
                    self.running.store(false, std::sync::atomic::Ordering::Relaxed);
                    break Ok(());
                }
                _ => {} // ignore unrelated frames (this bridge only handles its own contract)
            }
        };

        // COOPERATIVE monitor shutdown, not `abort()`.
        //
        // `monitor_running` is the flag the loop already polls, and it is cleared right here — so the
        // loop will finish its current check and return on its own. The old code cleared the flag and
        // then IMMEDIATELY aborted, which dropped the loop's future mid-check. Since `BrowserContext`
        // and `Page` have no `Drop` in the playwright crate, that stranded the check's context (plus
        // its renderer processes and memory) inside Chromium — on EVERY connection loss, not on some
        // rare path. Give it a bounded grace period to close what it opened, and abort only if it
        // overruns (a wedged loop must not stop us reconnecting).
        monitor_running.store(false, std::sync::atomic::Ordering::Relaxed);
        if let Some(mut h) = monitor_handle {
            // A RECONNECT keeps the warm browser, so a stranded context is permanent → full grace. A
            // deliberate stop closes the browser right after → short grace, so we don't sit on a
            // supervisor's stop deadline for cleanup that is about to happen anyway.
            let grace = if self.running.load(std::sync::atomic::Ordering::Relaxed) {
                MONITOR_SHUTDOWN_GRACE
            } else {
                MONITOR_STOP_GRACE
            };
            // `&mut h`: `JoinHandle` is `Unpin`, so the timeout borrows it instead of consuming it —
            // which is what leaves `abort()` available on the overrun path.
            match tokio::time::timeout(grace, &mut h).await {
                Ok(Ok(())) => tracing::debug!("monitor loop stopped cooperatively"),
                Ok(Err(e)) => tracing::warn!(error = %e, "monitor loop ended abnormally"),
                Err(_) => {
                    tracing::warn!(
                        grace_s = grace.as_secs(),
                        "monitor loop did not stop within its grace period — aborting it"
                    );
                    h.abort();
                }
            }
        }
        // The heartbeat task is a pure `sleep` + `send` loop with no browser or other resource to
        // release, so aborting it is safe.
        heartbeat_handle.abort();

        // Close the browse/record session registries.
        //
        // These are PROCESS-GLOBAL maps whose entries each own a live `BrowserContext` + `Page`. A
        // coordinator that drops the WS without sending `*_close` leaves an orphan, and on the record
        // side a stale entry additionally BLOCKS re-opening that `session_id` (the duplicate check
        // refuses it). Both modules run an idle reaper, so the leak was bounded — but bounded at an
        // hour, and every reconnect can add more. The connection going away is the moment we KNOW no
        // peer is coming back for them, so reclaim here rather than waiting for the reaper.
        crate::local::browse::close_all().await;
        crate::local::record::bridge::close_all();

        // Retire the writer WITHOUT dropping the receiver: signal stop, then await it to reclaim the
        // receiver for the next connect cycle. `write_handle.abort()` (the old code) dropped the
        // receiver, which is what silently killed every sender held by in-flight work.
        let reclaimed = match reclaimed_rx {
            Some(rx) => Some(rx),
            None => {
                let _ = writer_stop_tx.send(());
                match write_handle.await {
                    Ok(rx) => Some(rx),
                    Err(e) => {
                        // The writer body has no panic points, so this is a bug if it happens. The
                        // receiver is gone with it, and there is no sound way to keep serving: stop
                        // the bridge so the supervisor restarts the process with a clean channel
                        // (better than silently black-holing every outgoing frame forever).
                        tracing::error!(
                            error = %e,
                            "outgoing WS writer task panicked — stopping the bridge so the \
                             supervisor restarts this worker"
                        );
                        self.running.store(false, std::sync::atomic::Ordering::Relaxed);
                        None
                    }
                }
            }
        };
        *self.outgoing_rx.lock().await = reclaimed;
        result
    }

    /// Build + send the `local_catalog` frame from the `cloud_callable` workflows (METADATA ONLY),
    /// serving the cached frame when it is still fresh.
    async fn send_catalog(&self, outgoing_tx: &mpsc::UnboundedSender<Message>) {
        let frame = self.catalog_cache.frame(&self.db).await;
        *self.last_catalog_send.lock().await = Some(Instant::now());
        let _ = outgoing_tx.send(Message::Text(frame.to_string()));
    }

    /// Rebuild the catalog from the DB (a local mutation invalidated it) and send it.
    async fn send_catalog_fresh(&self, outgoing_tx: &mpsc::UnboundedSender<Message>) {
        self.catalog_cache.invalidate().await;
        self.send_catalog(outgoing_tx).await;
    }

    /// Rate-limited, OFF-the-read-loop catalog send for a coordinator `request_local_catalog`.
    async fn spawn_catalog_send(&self, outgoing_tx: &mpsc::UnboundedSender<Message>) {
        {
            let last = self.last_catalog_send.lock().await;
            if let Some(at) = *last {
                if at.elapsed() < CATALOG_MIN_INTERVAL {
                    tracing::debug!("request_local_catalog rate-limited (a catalog was just sent)");
                    return;
                }
            }
        }
        *self.last_catalog_send.lock().await = Some(Instant::now());
        let db = self.db.clone();
        let cache = self.catalog_cache.clone();
        let out = outgoing_tx.clone();
        tokio::spawn(async move {
            let frame = cache.frame(&db).await;
            let _ = out.send(Message::Text(frame.to_string()));
        });
    }

    /// Governor admission for a dispatched unit of work that does NOT flow through the engine's own
    /// run pipeline (a crawl shard, a raw wire `execute_workflow`).
    ///
    /// `Ok(Some(permit))` — admitted; hold the permit for the work's lifetime.
    /// `Ok(None)` — this engine has no governor (stub/test engines): admit unconditionally, which is
    ///              the pre-existing behavior for them.
    /// `Err(reason)` — no room. The caller MUST answer its dispatcher rather than queue or drop.
    ///
    /// Uses [`Lane::Background`] to share one ceiling with by-id runs: all three are coordinator-
    /// dispatched work competing for the same warm browser and the same RAM, so they must be counted
    /// together. The background lane also fails FAST instead of queueing, which is what lets us answer
    /// the coordinator immediately instead of parking a dispatch until its patience runs out.
    async fn admit_dispatch(&self) -> Result<Option<crate::local::governor::RunPermit>, &'static str> {
        let Some(gov) = self.engine.governor() else {
            return Ok(None);
        };
        match gov.admit(Lane::Background).await {
            Ok(permit) => Ok(Some(permit)),
            Err(reject) => Err(reject.as_str()),
        }
    }

    /// Answer a dispatch this worker cannot admit with a RESOLVED `task_result`.
    ///
    /// The coordinator dispatches with `send_and_await`; silently dropping a frame it cannot run parks
    /// that future until the coordinator's own patience expires, and then the same work is redispatched
    /// at a box that is still full. A prompt, explicit `success: false, error: "at capacity: …"` lets
    /// the coordinator re-place the task somewhere else immediately.
    fn refuse_at_capacity(
        &self,
        task_id: &str,
        reason: &str,
        out: &mpsc::UnboundedSender<Message>,
    ) {
        tracing::warn!(
            task_id,
            reason,
            advertised = self.max_sessions(),
            active = self.active_units(),
            "FleetBridge refused dispatch — at capacity"
        );
        let frame = task_result_frame(
            task_id,
            false,
            json!({}),
            Some(format!("at capacity: {reason}")),
            0,
        );
        send_task_result(out, task_id, &frame);
    }

    /// Route a coordinator `cancel_task` into the engine's cooperative cancel and ACK it.
    ///
    /// Looks the coordinator's `task_id` up in the dispatch map to find the local `run_id`, signals
    /// [`LocalEngine::cancel`] (which flips the `CancelToken` the step loop polls between steps), and
    /// always replies `task_cancelled{task_id, found}` — mirroring the `ai_session_cancel` →
    /// `ai_session_cancelled{found}` shape so the coordinator's awaited future resolves either way.
    ///
    /// `found` is false for an unknown/already-settled task, and also for dispatch shapes that own no
    /// engine run (a crawl shard, a raw wire `execute_workflow`): those run outside the run registry
    /// and have no cancel token to flip. Acking honestly beats pretending.
    fn handle_cancel_task(&self, task_id: &str, out: &mpsc::UnboundedSender<Message>) {
        let run_id = self.dispatched_runs.get(task_id).map(|e| *e.value());
        let found = match run_id {
            Some(rid) => {
                // `Some(true)` = this call flipped it, `Some(false)` = already cancelling, `None` = the
                // run settled between the map lookup and here.
                let signalled = self.engine.cancel(rid);
                tracing::info!(
                    task_id,
                    run_id = rid,
                    live = signalled.is_some(),
                    "FleetBridge: cancel_task routed to the engine's cooperative cancel"
                );
                signalled.is_some()
            }
            None => {
                tracing::info!(task_id, "FleetBridge: cancel_task for a task with no live local run");
                false
            }
        };
        let _ = out.send(Message::Text(
            json!({
                "type": "task_cancelled",
                "task_id": task_id,
                "found": found,
            })
            .to_string(),
        ));
    }

    /// Idempotency gate for a dispatched task. Returns `true` when the caller should EXECUTE.
    ///
    /// A duplicate is answered INLINE (cheap, no browser): a completed task replays its cached
    /// `task_result` so the coordinator's awaited future resolves with the ORIGINAL outcome, and a
    /// still-running task gets an `already_running` ack so the coordinator knows the work is live.
    fn accept_task(&self, task_id: &str, out: &mpsc::UnboundedSender<Message>) -> bool {
        if task_id.is_empty() {
            // No id to key on — cannot dedupe. Execute (the pre-existing behavior) but say so.
            tracing::warn!("dispatch arrived with no task_id — cannot apply idempotency");
            return true;
        }
        match self.tasks.claim(task_id) {
            Claim::Fresh => true,
            Claim::Replay(frame) => {
                tracing::warn!(
                    task_id,
                    "DUPLICATE dispatch of an already-completed task — replaying the cached result \
                     instead of running it again"
                );
                send_task_result(out, task_id, &frame);
                false
            }
            Claim::AlreadyRunning => {
                tracing::warn!(
                    task_id,
                    "DUPLICATE dispatch of a task that is still running — acking instead of \
                     starting a second run"
                );
                let _ = out.send(Message::Text(
                    json!({
                        "type": "task_ack",
                        "task_id": task_id,
                        "status": "already_running",
                    })
                    .to_string(),
                ));
                false
            }
        }
    }
}

/// The split write half of the coordinator WS.
type WsSink = futures_util::stream::SplitSink<WsStream, Message>;

/// Write one frame with a DEADLINE. Returns `false` when the write half is unusable and the session
/// must be torn down.
///
/// The timeout matters: a peer whose receive window is shut (zero-window, or a machine that vanished)
/// makes `send().await` park indefinitely, which stops the writer from ever draining — and therefore
/// from ever shedding — its queue. A parked writer is indistinguishable from a healthy idle one, so
/// bound it and let the read loop's `write_handle` arm reconnect.
async fn write_frame(write: &mut WsSink, msg: Message) -> bool {
    match tokio::time::timeout(WRITE_TIMEOUT, write.send(msg)).await {
        Ok(Ok(())) => true,
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "coordinator WS write failed");
            false
        }
        Err(_) => {
            tracing::warn!(
                timeout_s = WRITE_TIMEOUT.as_secs(),
                "coordinator WS write timed out (peer not reading) — dropping the session"
            );
            false
        }
    }
}

/// Free-function catalog send (used by the post-save spawned tasks, which don't hold `&self`).
/// Invalidates the cache first: the caller just MUTATED the corpus, so a cached frame would advertise
/// the pre-save state.
async fn send_catalog_to(
    db: &SqlitePool,
    cache: &CatalogCache,
    outgoing_tx: &mpsc::UnboundedSender<Message>,
) {
    cache.invalidate().await;
    let frame = cache.frame(db).await;
    let _ = outgoing_tx.send(Message::Text(frame.to_string()));
}

// ---------------------------------------------------------------------------
// Save handlers — decrypt channel-key ciphertext, re-seal under the LOCAL vault,
// persist via the store, and build the *_saved ack. Every handler scopes to THIS
// agent's own local data; it never trusts an id/tenant in the payload.
// ---------------------------------------------------------------------------

/// `save_local_workflow` — persist a deployed workflow. Because the workflow-credentials seal AAD is
/// bound to the (not-yet-known) row id via [`workflows::credentials_aad`], we INSERT first with
/// `credentials_encrypted = None` to get the id, then seal the decrypted creds under that AAD and
/// UPDATE the row (also flipping `cloud_callable = 1`, `execution_target = "local"`, and the persona
/// FK when a persona is bundled). Returns `local_workflow_saved{request_id, local_id, recipe_hash}`.
async fn handle_save_local_workflow(
    db: &SqlitePool,
    vault: &Vault,
    channel_key: Option<&str>,
    msg: &Value,
) -> Value {
    let request_id = id_str(&msg["request_id"]);

    let name = msg["name"].as_str().unwrap_or("").trim().to_string();
    if name.is_empty() {
        return json!({ "type": "local_workflow_saved", "request_id": request_id,
            "error": "save_local_workflow: missing name" });
    }
    let description = msg["description"].as_str().map(|s| s.to_string());
    // steps/form_data cross the wire as rich JSON; the store column is TEXT. Normalize to compact
    // JSON text (NewWorkflow's serde would do this, but we build it directly here).
    let steps_text = value_to_json_text(&msg["steps"]).unwrap_or_else(|| "[]".to_string());
    let form_data_text = value_to_json_text(&msg["form_data"]);

    // Bound what a deploy can PERSIST to this worker's disk. Without these, a buggy or hostile
    // coordinator can write unbounded `steps` text that then survives every restart (the frame is
    // accepted, the row is stored, the disk fills, and nothing here would ever reclaim it). Reject
    // with a clear error on the ack so the coordinator surfaces the refusal instead of retrying.
    if let Some(err) = deploy_size_error(&name, description.as_deref(), &steps_text, form_data_text.as_deref())
    {
        tracing::warn!(name = %truncate_str(&name, 64), %err, "rejecting oversized deployed workflow");
        return json!({ "type": "local_workflow_saved", "request_id": request_id, "error": err });
    }
    match stored_workflow_count(db).await {
        Ok(n) if n >= MAX_STORED_WORKFLOWS => {
            let err = format!(
                "this worker already stores {n} workflows (cap {MAX_STORED_WORKFLOWS}) — delete some \
                 before deploying more"
            );
            tracing::warn!(count = n, "rejecting deployed workflow: storage cap reached");
            return json!({ "type": "local_workflow_saved", "request_id": request_id, "error": err });
        }
        Ok(_) => {}
        // A count that cannot be read is not a reason to refuse a legitimate deploy; the per-field
        // caps above still bound the write.
        Err(e) => tracing::warn!(error = %e, "could not count stored workflows (continuing)"),
    }

    // 1) Insert with NO credentials yet (the seal AAD needs the row id).
    let new = workflows::NewWorkflow {
        name: name.clone(),
        description: description.clone(),
        workflow_type: None,
        steps: Some(steps_text),
        form_data: form_data_text,
        credentials_encrypted: None,
        ..Default::default()
    };
    let inserted = match workflows::insert(db, &new).await {
        Ok(wf) => wf,
        Err(e) => {
            return json!({ "type": "local_workflow_saved", "request_id": request_id,
                "error": format!("insert failed: {e}") });
        }
    };
    let wf_id = inserted.id;

    // 2) Seal the decrypted credentials under this row's AAD. When the frame carries
    //    credentials_encrypted we MUST fail CLOSED on a missing channel key or a
    //    decrypt/seal failure (mirroring handle_save_local_secret): saving a
    //    credential-less workflow would ack SUCCESS, and under mode=move the
    //    coordinator would then DELETE its copy + exclusive secrets — turning a
    //    transient channel-key gap into irreversible data loss with no fallback.
    //    Roll the just-inserted row back before returning the error so no orphan
    //    credential-less handle is left behind.
    let mut sealed_creds: Option<String> = None;
    if let Some(enc) = msg["credentials_encrypted"].as_str().filter(|s| !s.is_empty()) {
        let seal_err: Option<String> = match channel_key {
            Some(ck) => match channel_decrypt_map_text(ck, enc) {
                Some(json_text) => {
                    match vault.seal_field(json_text.as_bytes(), &workflows::credentials_aad(wf_id)) {
                        Ok(blob) => {
                            sealed_creds = Some(blob);
                            None
                        }
                        Err(e) => Some(format!("could not seal deployed workflow credentials: {e}")),
                    }
                }
                None => Some(
                    "could not open deployed workflow credentials with channel key".to_string(),
                ),
            },
            None => Some(
                "no channel key available to open deployed workflow credentials".to_string(),
            ),
        };
        if let Some(err) = seal_err {
            let _ = workflows::delete(db, wf_id).await;
            tracing::warn!(workflow_id = wf_id, error = %err,
                "rejecting deployed workflow save (credentials could not be sealed)");
            return json!({ "type": "local_workflow_saved", "request_id": request_id,
                "error": err });
        }
    }

    // 3) If a persona is bundled, persist it and capture its id for the FK.
    let mut persona_id: Option<i64> = None;
    if msg["persona"].is_object() {
        match persist_persona_blob(db, vault, channel_key, &msg["persona"]).await {
            Ok(id) => persona_id = Some(id),
            Err(e) => tracing::warn!(workflow_id = wf_id, error = %e,
                "could not persist bundled persona (workflow saved without it)"),
        }
    }

    // 4) UPDATE: seal creds + mark cloud_callable + local execution target + persona FK.
    let patch = workflows::WorkflowUpdate {
        credentials_encrypted: sealed_creds,
        cloud_callable: Some(1),
        execution_target: Some("local".to_string()),
        default_persona_id: persona_id,
        ..Default::default()
    };
    if let Err(e) = workflows::update(db, wf_id, &patch).await {
        return json!({ "type": "local_workflow_saved", "request_id": request_id,
            "error": format!("finalize failed: {e}") });
    }

    // Re-read for the recipe hash (the update refreshed the row).
    let recipe_hash = match workflows::get_by_id(db, wf_id).await {
        Ok(Some(wf)) => recipe_hash(&wf),
        _ => recipe_hash(&inserted),
    };

    tracing::info!(workflow_id = wf_id, name = %name, "FleetBridge saved deployed workflow");
    json!({
        "type": "local_workflow_saved",
        "request_id": request_id,
        // Integer PK rendered as a string — self-consistent with the catalog + run round-trip.
        "local_id": wf_id.to_string(),
        "recipe_hash": recipe_hash,
    })
}

/// Reject a deploy whose persisted fields exceed the storage caps. `None` = accepted.
///
/// Pure + separately testable: these ceilings are the only thing between a coordinator bug and an
/// unbounded write to the worker's disk.
fn deploy_size_error(
    name: &str,
    description: Option<&str>,
    steps_text: &str,
    form_data_text: Option<&str>,
) -> Option<String> {
    if name.chars().count() > MAX_NAME_CHARS {
        return Some(format!("workflow name exceeds {MAX_NAME_CHARS} characters"));
    }
    if description.map(|d| d.len()).unwrap_or(0) > MAX_DESCRIPTION_BYTES {
        return Some(format!("workflow description exceeds {MAX_DESCRIPTION_BYTES} bytes"));
    }
    if steps_text.len() > MAX_STEPS_BYTES {
        return Some(format!(
            "workflow steps exceed {MAX_STEPS_BYTES} bytes ({} received)",
            steps_text.len()
        ));
    }
    if form_data_text.map(|f| f.len()).unwrap_or(0) > MAX_FORM_DATA_BYTES {
        return Some(format!("workflow form_data exceeds {MAX_FORM_DATA_BYTES} bytes"));
    }
    None
}

/// Total stored workflow rows (the deploy cap counts ALL rows, not just cloud-callable ones).
async fn stored_workflow_count(db: &SqlitePool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM workflows").fetch_one(db).await
}

/// `save_local_secret` — decrypt the channel-key-sealed value, re-seal under the local vault (bound
/// to the secret key via [`secret_value_aad`], matching the run-time opener), upsert, ack.
async fn handle_save_local_secret(
    db: &SqlitePool,
    vault: &Vault,
    channel_key: Option<&str>,
    msg: &Value,
) -> Value {
    let request_id = id_str(&msg["request_id"]);
    let key = msg["key"].as_str().unwrap_or("").trim().to_string();
    if key.is_empty() {
        return json!({ "type": "local_secret_saved", "request_id": request_id,
            "error": "save_local_secret: missing key" });
    }
    let enc = match msg["value_encrypted"].as_str().filter(|s| !s.is_empty()) {
        Some(e) => e,
        None => {
            return json!({ "type": "local_secret_saved", "request_id": request_id,
                "error": "save_local_secret: missing value_encrypted" });
        }
    };
    let ck = match channel_key {
        Some(ck) => ck,
        None => {
            return json!({ "type": "local_secret_saved", "request_id": request_id,
                "error": "no channel key available to open the sealed secret" });
        }
    };
    // A standalone secret value crosses the wire as a Fernet-sealed PLAINTEXT string (not a JSON
    // map): the coordinator seals `SecretEncryption.decrypt_secret(...)` output. Open to raw bytes.
    let plaintext = match channel_decrypt_bytes(ck, enc) {
        Some(b) => b,
        None => {
            return json!({ "type": "local_secret_saved", "request_id": request_id,
                "error": "could not open the sealed secret with the channel key" });
        }
    };
    let value_encrypted = match vault.seal_field(&plaintext, &secret_value_aad(&key)) {
        Ok(blob) => blob,
        Err(e) => {
            return json!({ "type": "local_secret_saved", "request_id": request_id,
                "error": format!("local seal failed: {e}") });
        }
    };
    let new = vault_secrets::NewVaultSecret {
        key: key.clone(),
        value_encrypted,
        description: None,
        category: None,
    };
    if let Err(e) = vault_secrets::upsert(db, &new).await {
        return json!({ "type": "local_secret_saved", "request_id": request_id,
            "error": format!("upsert failed: {e}") });
    }
    tracing::info!(key = %key, "FleetBridge saved deployed secret");
    json!({ "type": "local_secret_saved", "request_id": request_id, "key": key })
}

/// `save_local_persona` — persist a standalone deployed persona, ack with its local id.
async fn handle_save_local_persona(
    db: &SqlitePool,
    vault: &Vault,
    channel_key: Option<&str>,
    msg: &Value,
) -> Value {
    let request_id = id_str(&msg["request_id"]);
    match persist_persona_blob(db, vault, channel_key, msg).await {
        Ok(id) => {
            tracing::info!(persona_id = id, "FleetBridge saved deployed persona");
            json!({ "type": "local_persona_saved", "request_id": request_id,
                "persona_local_id": id.to_string() })
        }
        Err(e) => json!({ "type": "local_persona_saved", "request_id": request_id,
            "error": format!("persona save failed: {e}") }),
    }
}

/// Persist a sealed persona blob (from a standalone `save_local_persona` OR the `persona` field of a
/// `save_local_workflow`). Insert-or-update by NAME (personas has no `upsert`), then seal every
/// deployed field under the NEW row's per-column AAD (`personas|<column>|<id>`) and UPDATE. Returns
/// the local persona id.
///
/// Field decrypt formats (as sealed by the coordinator `_build_persona_blob`):
///   * `creds_encrypted` — Fernet(channel_key) of a JSON `{name: value}` MAP → re-seal as JSON text.
///   * `proxy` — Fernet(channel_key) of a JSON OBJECT → re-seal the JSON text.
///   * `session_state_encrypted` / `totp_seed_encrypted` — Fernet(channel_key) of RAW inner bytes
///     (gzip / base32) → re-seal the SAME bytes so the inner framing survives.
///   * `fingerprint` — PLAINTEXT display JSON (not sealed).
async fn persist_persona_blob(
    db: &SqlitePool,
    vault: &Vault,
    channel_key: Option<&str>,
    blob: &Value,
) -> Result<i64, String> {
    let name = blob["name"].as_str().unwrap_or("").trim().to_string();
    if name.is_empty() {
        return Err("persona: missing name".to_string());
    }

    // Fingerprint is plaintext JSON — normalize to text for the store column.
    let fingerprint_text = value_to_json_text(&blob["fingerprint"]);

    // 1) Insert-or-find the row by name (no sealed fields yet — the seal AAD needs the id).
    let id = match personas::get_by_name(db, &name).await.map_err(|e| e.to_string())? {
        Some(existing) => {
            // Refresh the plaintext display fields on the existing row.
            let patch = personas::PersonaUpdate {
                fingerprint: fingerprint_text.clone(),
                ..Default::default()
            };
            personas::update(db, existing.id, &patch).await.map_err(|e| e.to_string())?;
            existing.id
        }
        None => {
            let new = personas::NewPersona {
                name: name.clone(),
                fingerprint: fingerprint_text.clone(),
                ..Default::default()
            };
            personas::insert(db, &new).await.map_err(|e| e.to_string())?.id
        }
    };

    // 2) Seal each deployed field under the new row's per-column AAD.
    let ck = channel_key; // may be None → sealed fields are skipped (logged)
    let creds_sealed = seal_channel_map(vault, ck, blob["creds_encrypted"].as_str(),
        &persona_aad("credentials_encrypted", id), id, "credentials");
    let proxy_sealed = seal_channel_json(vault, ck, blob["proxy"].as_str(),
        &persona_aad("proxy_config_encrypted", id), id, "proxy");
    let session_sealed = seal_channel_raw(vault, ck, blob["session_state_encrypted"].as_str(),
        &persona_aad("session_state_encrypted", id), id, "session_state");
    let totp_sealed = seal_channel_raw(vault, ck, blob["totp_seed_encrypted"].as_str(),
        &persona_aad("totp_seed_encrypted", id), id, "totp_seed");

    // 3) UPDATE the sealed fields (COALESCE — a None leaves the column untouched).
    let patch = personas::PersonaUpdate {
        credentials_encrypted: creds_sealed,
        proxy_config_encrypted: proxy_sealed,
        session_state_encrypted: session_sealed,
        totp_seed_encrypted: totp_sealed,
        ..Default::default()
    };
    personas::update(db, id, &patch).await.map_err(|e| e.to_string())?;
    Ok(id)
}

/// Seal a channel-key-sealed `{name: value}` MAP under the local vault as canonical JSON text.
/// `None` in (absent field / no channel key / decrypt fail) → `None` out (column untouched).
fn seal_channel_map(
    vault: &Vault,
    channel_key: Option<&str>,
    enc: Option<&str>,
    aad: &str,
    persona_id: i64,
    what: &str,
) -> Option<String> {
    let (ck, enc) = (channel_key?, enc.filter(|s| !s.is_empty())?);
    let Some(json_text) = channel_decrypt_map_text(ck, enc) else {
        tracing::warn!(persona_id, "could not open persona {what} with channel key");
        return None;
    };
    match vault.seal_field(json_text.as_bytes(), aad) {
        Ok(blob) => Some(blob),
        Err(e) => {
            tracing::warn!(persona_id, error = %e, "could not seal persona {what}");
            None
        }
    }
}

/// Seal a channel-key-sealed JSON OBJECT under the local vault, preserving the JSON text.
fn seal_channel_json(
    vault: &Vault,
    channel_key: Option<&str>,
    enc: Option<&str>,
    aad: &str,
    persona_id: i64,
    what: &str,
) -> Option<String> {
    let (ck, enc) = (channel_key?, enc.filter(|s| !s.is_empty())?);
    let Some(json_text) = channel_decrypt_json_text(ck, enc) else {
        tracing::warn!(persona_id, "could not open persona {what} with channel key");
        return None;
    };
    match vault.seal_field(json_text.as_bytes(), aad) {
        Ok(blob) => Some(blob),
        Err(e) => {
            tracing::warn!(persona_id, error = %e, "could not seal persona {what}");
            None
        }
    }
}

/// Seal a channel-key-sealed RAW-BYTES blob (gzip session state / base32 TOTP seed) under the local
/// vault, preserving the exact inner bytes.
fn seal_channel_raw(
    vault: &Vault,
    channel_key: Option<&str>,
    enc: Option<&str>,
    aad: &str,
    persona_id: i64,
    what: &str,
) -> Option<String> {
    let (ck, enc) = (channel_key?, enc.filter(|s| !s.is_empty())?);
    let Some(bytes) = channel_decrypt_bytes(ck, enc) else {
        tracing::warn!(persona_id, "could not open persona {what} with channel key");
        return None;
    };
    match vault.seal_field(&bytes, aad) {
        Ok(blob) => Some(blob),
        Err(e) => {
            tracing::warn!(persona_id, error = %e, "could not seal persona {what}");
            None
        }
    }
}

/// Normalize a JSON value into compact JSON TEXT for a TEXT store column. A JSON string passes
/// through untouched (assumed already-JSON text); `null`/absent → `None`.
fn value_to_json_text(v: &Value) -> Option<String> {
    match v {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// run_local_workflow — load by id, PRE-FLIGHT reject unsupported shapes, run
// headless via the engine, emit task_result. Mirrors the gateway run path.
// ---------------------------------------------------------------------------

/// Run a workflow by its local id and build the `task_result` frame.
///
/// SECURITY (TB-1): only a workflow the owner has explicitly exposed (`cloud_callable = 1`) may run
/// — the same flag the catalog filters on. Unknown/unparseable ids and non-exposed rows are refused
/// with a clear reason, never dispatched. Pre-flight rejects (no browser launch) a workflow that
/// needs streaming / an AI-loop or automation-block interpreter, or a persona with email/SMS 2FA —
/// capabilities a headless fleet worker does not service (per plan §3.4 / risk 7).
async fn run_local_workflow(
    engine: &Arc<dyn LocalEngine>,
    db: &SqlitePool,
    task_id: &str,
    local_id: &str,
    inputs: Value,
    // `task_id → run_id` map the `cancel_task` frame reads. Registered the moment the engine allocates
    // the run row and removed by the RAII guard below when this function returns.
    dispatched: &Arc<dashmap::DashMap<String, i64>>,
) -> Value {
    let start = Instant::now();

    let wf_id = match local_id.trim().parse::<i64>() {
        Ok(id) => id,
        Err(_) => {
            return task_result_frame(task_id, false, json!({}),
                Some(format!("invalid local_id: {}", truncate_str(local_id, 64))),
                start.elapsed().as_millis() as u64);
        }
    };

    // Load + gate on the owner's exposure flag; also drives the pre-flight shape checks.
    let wf = match workflows::get_by_id(db, wf_id).await {
        Ok(Some(wf)) if wf.cloud_callable == 1 => wf,
        Ok(Some(_)) => {
            return task_result_frame(task_id, false, json!({}),
                Some(format!("workflow {wf_id} is not exposed for fleet execution")),
                start.elapsed().as_millis() as u64);
        }
        Ok(None) => {
            return task_result_frame(task_id, false, json!({}),
                Some(format!("workflow {wf_id} not found")),
                start.elapsed().as_millis() as u64);
        }
        Err(e) => {
            return task_result_frame(task_id, false, json!({}),
                Some(format!("failed to load workflow {wf_id}: {e}")),
                start.elapsed().as_millis() as u64);
        }
    };

    // Pre-flight: reject shapes a headless fleet worker cannot service, with a clear error and NO
    // browser launch.
    if let Some(reason) = preflight_reject_reason(db, &wf).await {
        tracing::info!(workflow_id = wf_id, %reason, "FleetBridge pre-flight rejected run");
        return task_result_frame(task_id, false, json!({}), Some(reason),
            start.elapsed().as_millis() as u64);
    }

    let req = RunRequest {
        workflow_id: wf_id,
        inputs,
        // Provenance only — identity/billing stay coordinator-side. Reuses the CloudAgent tag (the
        // engine has no FleetAgent variant; both mean "dispatched to this machine over the WS").
        source: RunSource::CloudAgent,
        lane: Lane::Background,
        dry_run: false,
        persona_id: None,
        // The OWNER's own deployed workflow, run on the owner's own machine → resolves the local
        // vault (its secrets were deployed here at save-time and re-sealed under this vault).
        allow_local_secret_refs: true,
    };

    // CANCELLABILITY: publish the local `run_id` into the dispatch map as soon as the engine allocates
    // it, so a `cancel_task` frame arriving mid-run has something to cancel. The guard removes the
    // entry when this function returns (settled, or unwound), so the map only holds live runs and a
    // recycled task id can never cancel an unrelated run.
    let _tracked = DispatchedRunGuard { map: dispatched.clone(), task_id: task_id.to_string() };
    let sink: crate::local::engine::RunIdSink<'_> = {
        let map = dispatched.clone();
        let tid = task_id.to_string();
        Box::new(move |run_id| {
            map.insert(tid, run_id);
        })
    };

    match engine.run_tracked(req, sink).await {
        Ok(res) => task_result_frame(task_id, res.success, res.extracted_data, res.error, res.duration_ms),
        Err(e) => task_result_frame(task_id, false, json!({}), Some(e.to_string()),
            start.elapsed().as_millis() as u64),
    }
}

/// Classify an `execute_workflow` message: when it is a DRAGNET crawl shard, return its config
/// with the crawl keys folded under `config.trigger_context` (the crawl keys ride there, but a
/// top-level placement is tolerated so the shard runner always finds them); `None` means a RAW
/// full-definition workflow run to be served by [`execute_wire_workflow`].
fn crawl_shard_config(msg: &Value) -> Option<Value> {
    let mut config = msg.get("config").cloned().unwrap_or_else(|| json!({}));
    let tc = config
        .get("trigger_context")
        .cloned()
        .or_else(|| msg.get("trigger_context").cloned())
        .unwrap_or_else(|| json!({}));
    let is_crawl_shard = tc.get("_crawl_shard").is_some()
        || config
            .get("steps")
            .and_then(|s| s.as_array())
            .and_then(|a| a.first())
            .and_then(|s| s.get("type"))
            .and_then(|t| t.as_str())
            == Some("crawl_batch");
    if !is_crawl_shard {
        return None;
    }
    if config.get("trigger_context").is_none() {
        if let Some(obj) = config.as_object_mut() {
            obj.insert("trigger_context".into(), tc);
        }
    }
    Some(config)
}

/// Pre-flight reject reason for a RAW wire `execute_workflow` on a fleet worker. Mirrors
/// [`preflight_reject_reason`] but reads the WIRE config instead of a stored row: streaming
/// workflows and AI-loop/advanced-script workflows need machinery this build does not run.
/// (Persona 2FA is NOT pre-flight rejected here: the wire dialect carries an OTP-mint contract
/// — `config.persona.{persona_id, otp_token, coordinator_url}` — the shared executor serves at
/// the `twofa` step, and it fails there with a clear `TWOFA_NOT_AVAILABLE` when absent.)
fn wire_preflight_reject_reason(config: &Value) -> Option<String> {
    if config.get("workflow_type").and_then(Value::as_str) == Some("streaming") {
        return Some("streaming workflows are not supported on a fleet worker".to_string());
    }
    let has_script = config
        .get("streaming_config")
        .and_then(|sc| match sc {
            Value::String(s) => serde_json::from_str::<Value>(s).ok(),
            other => Some(other.clone()),
        })
        .and_then(|v| {
            v.get("advanced_script")
                .and_then(Value::as_str)
                .map(|s| !s.trim().is_empty())
        })
        .unwrap_or(false);
    if has_script {
        return Some(
            "AI-loop / advanced-script workflows are not supported on a fleet worker".to_string(),
        );
    }
    None
}

/// Run a RAW wire-dispatched `execute_workflow` (full definition in the message config) through
/// the SHARED executor ([`crate::bridge::wire_exec`]) — the exact code path the cloud agent
/// serves — and emit its frames over `out`. The channel key opens `credentials_encrypted`;
/// `session_state` (cookies/localStorage/fingerprint) and the BYO `__proxy__` override are
/// honored by the executor itself. Pre-flight rejects the shapes a fleet worker cannot run, and
/// degrades with a clear error when the engine exposes no browser manager (stub/test engines).
async fn execute_wire_workflow(
    engine: &Arc<dyn LocalEngine>,
    channel_key: Option<&str>,
    task_id: &str,
    msg: &Value,
    out: &mpsc::UnboundedSender<Message>,
    // Idempotency ledger: the terminal `task_result` this run emits is recorded here so a duplicate
    // dispatch of the same task_id replays it instead of re-executing the workflow.
    ledger: &Arc<TaskLedger>,
) {
    let start = Instant::now();
    let config = msg.get("config").cloned().unwrap_or_else(|| json!({}));

    if let Some(reason) = wire_preflight_reject_reason(&config) {
        tracing::info!(task_id, %reason, "FleetBridge pre-flight rejected raw execute_workflow");
        let frame =
            task_result_frame(task_id, false, json!({}), Some(reason), start.elapsed().as_millis() as u64);
        ledger.complete(task_id, frame.clone());
        send_task_result(out, task_id, &frame);
        return;
    }

    let Some(browser) = engine.browser() else {
        let frame = task_result_frame(
            task_id,
            false,
            json!({}),
            Some("no browser manager available on this fleet worker".to_string()),
            start.elapsed().as_millis() as u64,
        );
        ledger.complete(task_id, frame.clone());
        send_task_result(out, task_id, &frame);
        return;
    };

    // The shared executor emits several frames (progress, twofa parks, the terminal `task_result`).
    // Tee the terminal one into the ledger as it goes past, and surface a failed send for it — the
    // other frames are advisory, a lost `task_result` is not.
    let sink = out.clone();
    let ledger = ledger.clone();
    let task_id_owned = task_id.to_string();
    let send = move |v: Value| {
        if v["type"].as_str() == Some("task_result") {
            ledger.complete(&task_id_owned, v.clone());
            send_task_result(&sink, &task_id_owned, &v);
            return;
        }
        let _ = sink.send(Message::Text(v.to_string()));
    };
    crate::bridge::wire_exec::handle_execute_workflow(task_id, msg, &browser, &send, None, channel_key)
        .await;
}

/// Return `Some(reason)` when a workflow must be pre-flight rejected on a headless fleet worker:
///   * a STREAMING workflow (`workflow_type == "streaming"`) — needs the streaming session path the
///     fleet worker does not run,
///   * an AI-loop / automation-block workflow (a non-empty `streaming_config.advanced_script`) —
///     needs the interactive AI-driver loop, absent here,
///   * a default persona whose 2FA is email/SMS — its code can only be read in the cloud, so a run
///     would dead-end at the challenge; reject up front instead of launching a browser to fail.
/// Returns `None` when the workflow is a plain by-id run the fleet engine can execute.
async fn preflight_reject_reason(db: &SqlitePool, wf: &workflows::Workflow) -> Option<String> {
    if wf.workflow_type == "streaming" {
        return Some("streaming workflows are not supported on a fleet worker".to_string());
    }
    if let Some(sc) = wf.streaming_config.as_deref().filter(|s| !s.trim().is_empty()) {
        if let Ok(v) = serde_json::from_str::<Value>(sc) {
            let has_script = v
                .get("advanced_script")
                .and_then(Value::as_str)
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false);
            if has_script {
                return Some(
                    "AI-loop / advanced-script workflows are not supported on a fleet worker".to_string(),
                );
            }
        }
    }
    if let Some(pid) = wf.default_persona_id {
        if let Ok(Some(p)) = personas::get_by_id(db, pid).await {
            if matches!(p.twofa_method.as_str(), "email_otp" | "sms") {
                return Some(format!(
                    "workflow persona uses {} 2FA, which a fleet worker cannot complete (cloud-only)",
                    p.twofa_method
                ));
            }
        }
    }
    // A `twofa` step with no resolvable local persona dead-ends at the challenge. Cloud-persona
    // runs are pinned to cloud agents and never routed here, so nothing else can supply the code —
    // reject up front instead of launching a browser to fail. (A persona with method 'none' is NOT
    // rejected: its warm session may skip the challenge, and the engine arm is challenge-aware.)
    let has_twofa_step = serde_json::from_str::<Value>(&wf.steps)
        .ok()
        .and_then(|v| v.as_array().map(|steps| {
            steps.iter().any(|s| s.get("type").and_then(Value::as_str) == Some("twofa"))
        }))
        .unwrap_or(false);
    if has_twofa_step {
        let persona_resolves = match wf.default_persona_id {
            Some(pid) => matches!(personas::get_by_id(db, pid).await, Ok(Some(_))),
            None => false,
        };
        if !persona_resolves {
            return Some(
                "workflow enters a 2FA code but has no persona attached — attach a persona with a \
                 2FA method (or import its 2FA secret) so runs can enter codes automatically"
                    .to_string(),
            );
        }
    }
    None
}

// ---------------------------------------------------------------------------
// ai_session_start — run one autonomous AI session locally (reusing the daemon's
// shared run+record driver) and build the ai_session_complete/ai_session_failed reply.
// ---------------------------------------------------------------------------

/// Run a coordinator-dispatched autonomous AI session on THIS agent's local engine and build the
/// reply frame. Returns `(reply_frame, recorded)` where `recorded` is `true` iff a workflow was
/// recorded (the caller then re-advertises the catalog). All failures are turned into an
/// `ai_session_failed` reply — this never panics.
///
/// Secret handling mirrors `save_local_workflow`: `credentials_encrypted` (when present) is a
/// channel-key-sealed `{name: value}` MAP; it is decrypted with the cached channel key and merged
/// into `fill_data` (overriding the plaintext `available_data` hints on key collision). Non-secret
/// hints ride in `available_data` plaintext. Correlation is by `session_id`, echoed back on the reply.
#[cfg(feature = "local")]
async fn handle_ai_session_start(
    db: &SqlitePool,
    vault: &Arc<Vault>,
    engine: &Arc<dyn LocalEngine>,
    channel_key: Option<&str>,
    msg: &Value,
    // Cooperative force-Stop flag: the coordinator's `ai_session_cancel` frame sets it, and the
    // autonomous session loop (which polls it via await_or_cancel) aborts mid-turn. `None` = no
    // cancel wiring (the session runs to completion) — parity with the pre-cancel behavior.
    cancel: Option<Arc<std::sync::atomic::AtomicBool>>,
) -> (Value, bool) {
    use crate::local::ai::provider;
    use crate::local::ai::run::{run_ai_session_and_record, AiSessionParams};
    use crate::local::engine::persona;
    use std::collections::HashMap;

    // Correlation id (echoed on every reply). Also the coordinator's external handle for the session.
    let session_id = id_str(&msg["session_id"]);

    // Small helper: build the failure reply (isolates every early return below).
    let fail = |err: String| -> (Value, bool) {
        (
            json!({
                "type": "ai_session_failed",
                "session_id": session_id,
                "status": "error",
                "error": err,
            }),
            false,
        )
    };

    let goal = msg["goal"].as_str().unwrap_or("").trim().to_string();
    if goal.is_empty() {
        return fail("ai_session_start: missing goal".to_string());
    }

    // Resolve the AI provider up front — a session with no configured brain cannot run, UNLESS the
    // cloud AI gateway is on (which supplies the brain itself). Mirrors the /v1/ai-sessions/start gate.
    let ai_cfg = match provider::resolve_config(db, vault).await {
        Ok(Some(c)) if !c.provider.trim().is_empty() => c,
        Ok(_) if provider::cloud_gateway_enabled(db).await => provider::AiConfig {
            provider: String::new(),
            model: String::new(),
            base_url: None,
            api_key: None,
        },
        Ok(_) => return fail("ai_unavailable: no AI provider configured on this agent".to_string()),
        Err(e) => return fail(format!("ai provider resolve failed: {e}")),
    };

    // The engine must expose a warm browser (present in the real fleet engine).
    let browser = match engine.browser() {
        Some(b) => b,
        None => return fail("ai_unavailable: this engine cannot run AI sessions (no browser)".to_string()),
    };

    // Non-secret plaintext hints shown to the model.
    let available_data: HashMap<String, String> = msg["available_data"]
        .as_object()
        .map(|o| {
            o.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    // fill_data base = the plaintext hints; then the persona credentials, then the sealed
    // `credentials_encrypted` overrides win (caller-supplied secrets are authoritative).
    let mut fill_data: HashMap<String, String> = available_data.clone();

    // Optional persona already deployed to this agent: pin fingerprint/proxy, restore session-state,
    // merge its login credentials. A dangling id is non-fatal (runs without it).
    let persona_id = msg["persona_id"].as_i64();
    let resolved_persona = match persona_id {
        Some(pid) => match persona::resolve_persona(db, vault, pid).await {
            Ok(p) => p,
            Err(e) => return fail(format!("persona resolve failed: {e}")),
        },
        None => None,
    };
    if let Some(p) = resolved_persona.as_ref() {
        let mut creds: HashMap<String, String> = HashMap::new();
        p.merge_into_credentials(&mut creds);
        for (k, v) in creds {
            fill_data.entry(k).or_insert(v);
        }
    }

    // Decrypt the channel-key-sealed secret fill values (if any) and merge them LAST so they override
    // both the plaintext hints and the persona credentials. FAIL CLOSED when a sealed blob is present
    // but cannot be opened (a missing channel key or a decrypt failure) — running with silently-missing
    // secrets would produce a confusing dead-end rather than a clear error.
    if let Some(enc) = msg["credentials_encrypted"].as_str().filter(|s| !s.is_empty()) {
        let json_text = match channel_key {
            Some(ck) => match channel_decrypt_map_text(ck, enc) {
                Some(t) => t,
                None => return fail("could not open ai-session credentials with the channel key".to_string()),
            },
            None => return fail("no channel key available to open ai-session credentials".to_string()),
        };
        match serde_json::from_str::<HashMap<String, String>>(&json_text) {
            Ok(secrets) => {
                for (k, v) in secrets {
                    fill_data.insert(k, v);
                }
            }
            Err(e) => return fail(format!("ai-session credentials were not a string map: {e}")),
        }
    }

    let max_steps = msg["max_steps"].as_u64().unwrap_or(20).clamp(1, 100) as u32;
    // Default to recording (parity with the REST handler's `None ⇒ true`).
    let generate_workflow = msg["generate_workflow"].as_bool().unwrap_or(true);
    let name = msg["name"].as_str().map(|s| s.to_string());
    let entry_url = msg["entry_url"].as_str().map(|s| s.to_string());

    let params = AiSessionParams {
        name,
        goal,
        entry_url,
        available_data,
        fill_data,
        max_steps,
        // The fleet path never binds to an existing coordinator workflow id (the coordinator mirrors
        // whatever LOCAL workflow this records), so recording is governed solely by generate_workflow.
        workflow_id: None,
        resolved_persona,
        generate_workflow,
        explore: false,  // fleet AI session keeps the classic form-filler behavior
        record_templates: std::collections::HashMap::new(),
        ask_concierge_session_id: None,
        cancel,
    };

    match run_ai_session_and_record(db, engine, &browser, &ai_cfg, params).await {
        Ok(outcome) => {
            let recorded = outcome.workflow_id.is_some();
            (
                json!({
                    "type": "ai_session_complete",
                    "session_id": session_id,
                    "status": outcome.status,
                    "workflow_id": outcome.workflow_id,
                    "workflow_name": outcome.workflow_name,
                    "steps": outcome.steps,
                    "message": outcome.message,
                    "error": outcome.error,
                }),
                recorded,
            )
        }
        Err(e) => fail(format!("ai session run failed: {e}")),
    }
}

// ---------------------------------------------------------------------------
// optimize_workflow_live — live-optimize a deployed workflow by its local id.
// ---------------------------------------------------------------------------

/// Handle an `optimize_workflow_live` frame: parse `{local_id, confirm_side_effects}`, gate on the
/// owner's exposure flag (`cloud_callable`, same as `run_local_workflow`), drive the daemon's live
/// optimizer over the locally-held recipe + secrets, and build the reply frame. The optimizer already
/// scrubs plaintext and spells synthesized steps with `{{placeholders}}`, so the returned diff is
/// safe to ship back to the coordinator. Every failure replies an `error` (never panics the task) so
/// the coordinator's `send_and_await` resolves.
#[cfg(feature = "local")]
async fn handle_optimize_workflow_live(
    db: &SqlitePool,
    vault: &Arc<Vault>,
    engine: &Arc<dyn LocalEngine>,
    msg: &Value,
) -> Value {
    // Correlation id echoed on the reply; the coordinator defaults to `request_id`.
    let request_id = id_str(&msg["request_id"]);

    // Build the error reply (isolates the early returns below).
    let fail = |err: String| -> Value {
        json!({
            "type": "optimize_workflow_live_result",
            "request_id": request_id,
            "error": err,
        })
    };

    // `local_id` is the integer PK rendered as a string (self-consistent with the catalog + run
    // round-trip); accept a bare number too for wire-dialect tolerance.
    let local_id = msg["local_id"]
        .as_str()
        .map(|s| s.to_string())
        .or_else(|| msg["local_id"].as_i64().map(|n| n.to_string()))
        .unwrap_or_default();
    let wf_id = match local_id.trim().parse::<i64>() {
        Ok(id) => id,
        Err(_) => return fail(format!("invalid local_id: {}", truncate_str(&local_id, 64))),
    };
    let confirm_side_effects = msg["confirm_side_effects"].as_bool().unwrap_or(false);

    // Gate on the owner's exposure flag (parity with run_local_workflow): only a workflow the owner has
    // explicitly exposed for fleet execution may be optimized. Load once so a missing/non-exposed row
    // is refused with a clear reason before any browser launches.
    match workflows::get_by_id(db, wf_id).await {
        Ok(Some(wf)) if wf.cloud_callable == 1 => {}
        Ok(Some(_)) => return fail(format!("workflow {wf_id} is not exposed for fleet execution")),
        Ok(None) => return fail(format!("workflow {wf_id} not found")),
        Err(e) => return fail(format!("failed to load workflow {wf_id}: {e}")),
    }

    // Drive the daemon's live optimizer over this agent's own recipe + secrets. It returns the full
    // `{steps, changes, warnings, removed_count, requires_confirm, verified, credits_used}` envelope.
    match crate::local::ai::optimize_live::optimize_workflow_live_core(
        db,
        vault,
        engine,
        wf_id,
        confirm_side_effects,
    )
    .await
    {
        Ok(result) => {
            // Splat the envelope fields alongside the frame envelope so the coordinator reads the diff
            // directly (steps/changes/warnings/removed_count/requires_confirm/verified/credits_used).
            let mut frame = json!({
                "type": "optimize_workflow_live_result",
                "request_id": request_id,
            });
            if let (Some(obj), Some(diff)) = (frame.as_object_mut(), result.as_object()) {
                for (k, v) in diff {
                    obj.insert(k.clone(), v.clone());
                }
            }
            frame
        }
        Err(e) => fail(format!("live optimize failed: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tempfile::TempDir;

    /// A fresh encrypted DB + vault rooted in a temp dir (no keyring — headless test path).
    async fn fresh_db_vault() -> (SqlitePool, Arc<Vault>, TempDir) {
        let dir = TempDir::new().unwrap();
        let vault = Arc::new(Vault::load_or_create(dir.path(), false).unwrap());
        let db = crate::local::db::open(&dir.path().join("writ.db"), &vault.db_key_hex())
            .await
            .unwrap();
        (db, vault, dir)
    }

    /// A channel-key Fernet-seal of a `{name: value}` credential MAP, as the coordinator sends it.
    fn seal_map(channel_key: &str, map: &HashMap<String, String>) -> String {
        let fernet = fernet::Fernet::new(channel_key).unwrap();
        fernet.encrypt(serde_json::to_string(map).unwrap().as_bytes())
    }

    /// A channel-key Fernet-seal of a raw plaintext string, as the coordinator sends a standalone
    /// secret (`_seal_plaintext_for_agent`).
    fn seal_plain(channel_key: &str, plaintext: &str) -> String {
        let fernet = fernet::Fernet::new(channel_key).unwrap();
        fernet.encrypt(plaintext.as_bytes())
    }

    #[tokio::test]
    async fn save_local_workflow_round_trips_sealed_creds_and_is_runnable_by_id() {
        let (db, vault, _dir) = fresh_db_vault().await;
        let channel_key = fernet::Fernet::generate_key();

        let mut creds = HashMap::new();
        creds.insert("password".to_string(), "s3cret-pw".to_string());
        let frame = json!({
            "type": "save_local_workflow",
            "request_id": "req-1",
            "name": "Deployed WF",
            "description": "from coordinator",
            "steps": [{ "type": "navigate", "url": "https://example.com" }],
            "form_data": { "input.user": "alice" },
            "credentials_encrypted": seal_map(&channel_key, &creds),
            "persona": Value::Null,
            "execution_target": "local",
            "cloud_callable": true,
            "source_workflow_id": 42,
        });

        let ack = handle_save_local_workflow(&db, &vault, Some(&channel_key), &frame).await;
        assert_eq!(ack["type"], "local_workflow_saved");
        assert_eq!(ack["request_id"], "req-1");
        assert!(ack.get("error").is_none(), "unexpected error: {ack}");

        // local_id is the integer PK as a string, and the row is loadable by that id.
        let local_id = ack["local_id"].as_str().unwrap();
        let wf_id: i64 = local_id.parse().expect("local_id must be an integer-string");
        let wf = workflows::get_by_id(&db, wf_id).await.unwrap().unwrap();

        // Exposure + venue were stamped, and the creds sealed under the row AAD open back to plaintext.
        assert_eq!(wf.cloud_callable, 1);
        assert_eq!(wf.execution_target.as_deref(), Some("local"));
        let blob = wf.credentials_encrypted.as_deref().expect("creds sealed");
        let opened = vault
            .open_field(blob, &workflows::credentials_aad(wf_id))
            .expect("creds open under row AAD");
        let map: HashMap<String, String> = serde_json::from_slice(&opened).unwrap();
        assert_eq!(map.get("password").map(String::as_str), Some("s3cret-pw"));

        // recipe_hash echoed in the ack is stable for the stored row.
        assert_eq!(ack["recipe_hash"].as_str().unwrap(), recipe_hash(&wf));

        // The saved workflow appears in the cloud_callable catalog with the integer-string local_id.
        let entries = workflows::list_cloud_callable(&db).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(catalog_entry(&entries[0])["local_id"], json!(wf_id.to_string()));
    }

    #[tokio::test]
    async fn save_local_secret_round_trips_under_the_run_time_aad() {
        let (db, vault, _dir) = fresh_db_vault().await;
        let channel_key = fernet::Fernet::generate_key();

        let frame = json!({
            "type": "save_local_secret",
            "request_id": "req-secret",
            "key": "API_KEY",
            "value_encrypted": seal_plain(&channel_key, "tok_live_123"),
        });
        let ack = handle_save_local_secret(&db, &vault, Some(&channel_key), &frame).await;
        assert_eq!(ack["type"], "local_secret_saved");
        assert_eq!(ack["key"], "API_KEY");
        assert!(ack.get("error").is_none(), "unexpected error: {ack}");

        // Opens under the EXACT AAD the engine's resolve path uses at run time.
        let row = vault_secrets::get_by_key(&db, "API_KEY").await.unwrap().unwrap();
        let opened = vault
            .open_field(&row.value_encrypted, &secret_value_aad("API_KEY"))
            .expect("secret opens under run-time AAD");
        assert_eq!(String::from_utf8(opened).unwrap(), "tok_live_123");
    }

    #[tokio::test]
    async fn save_local_persona_seals_every_field_under_its_row_aad() {
        let (db, vault, _dir) = fresh_db_vault().await;
        let channel_key = fernet::Fernet::generate_key();

        let mut login = HashMap::new();
        login.insert("username".to_string(), "bob".to_string());
        login.insert("password".to_string(), "hunter2".to_string());
        // session_state / totp are raw bytes sealed under the channel key (inner framing preserved).
        let session_bytes = br#"{"cookies":[],"local_storage":[]}"#;
        let totp_seed = b"JBSWY3DPEHPK3PXP"; // base32
        let fernet = fernet::Fernet::new(&channel_key).unwrap();

        let frame = json!({
            "type": "save_local_persona",
            "request_id": "req-persona",
            "name": "Persona A",
            "creds_encrypted": seal_map(&channel_key, &login),
            "fingerprint": { "ua": "test" },
            "proxy": Value::Null,
            "session_state_encrypted": fernet.encrypt(session_bytes),
            "totp_seed_encrypted": fernet.encrypt(totp_seed),
        });
        let ack = handle_save_local_persona(&db, &vault, Some(&channel_key), &frame).await;
        assert_eq!(ack["type"], "local_persona_saved");
        assert!(ack.get("error").is_none(), "unexpected error: {ack}");
        let pid: i64 = ack["persona_local_id"].as_str().unwrap().parse().unwrap();

        let row = personas::get_by_id(&db, pid).await.unwrap().unwrap();
        // Credentials open under the persona credentials AAD as the JSON map.
        let creds_blob = row.credentials_encrypted.as_deref().unwrap();
        let opened = vault
            .open_field(creds_blob, &persona_aad("credentials_encrypted", pid))
            .unwrap();
        let map: HashMap<String, String> = serde_json::from_slice(&opened).unwrap();
        assert_eq!(map.get("password").map(String::as_str), Some("hunter2"));
        // session_state / totp open back to the EXACT inner bytes (framing preserved).
        let ss_blob = row.session_state_encrypted.as_deref().unwrap();
        let ss = vault
            .open_field(ss_blob, &persona_aad("session_state_encrypted", pid))
            .unwrap();
        assert_eq!(ss, session_bytes);
        let totp_blob = row.totp_seed_encrypted.as_deref().unwrap();
        let totp = vault
            .open_field(totp_blob, &persona_aad("totp_seed_encrypted", pid))
            .unwrap();
        assert_eq!(totp, totp_seed);
        // Fingerprint is stored as plaintext display JSON.
        assert!(row.fingerprint.as_deref().unwrap().contains("test"));
    }

    #[tokio::test]
    async fn run_local_workflow_refuses_non_exposed_and_unknown_ids_without_panic() {
        let (db, _vault, _dir) = fresh_db_vault().await;
        struct NeverEngine;
        impl LocalEngine for NeverEngine {
            fn run<'a>(
                &'a self,
                _req: RunRequest,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = crate::local::error::LocalResult<crate::local::engine::RunResult>> + Send + 'a>,
            > {
                Box::pin(async { panic!("engine.run must not be called for a rejected/unknown id") })
            }
            fn active_runs(&self) -> usize {
                0
            }
        }
        let engine: Arc<dyn LocalEngine> = Arc::new(NeverEngine);

        // Non-numeric id.
        let f = run_local_workflow(&engine, &db, "t1", "not-a-number", json!({}), &no_map()).await;
        assert_eq!(f["success"], json!(false));
        assert!(f["error"].as_str().unwrap().contains("invalid local_id"));

        // Unknown id.
        let f = run_local_workflow(&engine, &db, "t2", "9999", json!({}), &no_map()).await;
        assert_eq!(f["success"], json!(false));
        assert!(f["error"].as_str().unwrap().contains("not found"));

        // A NON-cloud_callable workflow is refused (insert one directly, leave cloud_callable=0).
        let new = workflows::NewWorkflow {
            name: "private".to_string(),
            steps: Some("[]".to_string()),
            ..Default::default()
        };
        let wf = workflows::insert(&db, &new).await.unwrap();
        let f = run_local_workflow(&engine, &db, "t3", &wf.id.to_string(), json!({}), &no_map()).await;
        assert_eq!(f["success"], json!(false));
        assert!(f["error"].as_str().unwrap().contains("not exposed"));
    }

    #[tokio::test]
    async fn run_local_workflow_preflight_rejects_streaming_without_launching() {
        let (db, _vault, _dir) = fresh_db_vault().await;
        struct NeverEngine;
        impl LocalEngine for NeverEngine {
            fn run<'a>(
                &'a self,
                _req: RunRequest,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = crate::local::error::LocalResult<crate::local::engine::RunResult>> + Send + 'a>,
            > {
                Box::pin(async { panic!("engine.run must not be called for a pre-flight-rejected run") })
            }
            fn active_runs(&self) -> usize {
                0
            }
        }
        let engine: Arc<dyn LocalEngine> = Arc::new(NeverEngine);

        // Insert a cloud_callable STREAMING workflow.
        let new = workflows::NewWorkflow {
            name: "stream wf".to_string(),
            workflow_type: Some("streaming".to_string()),
            steps: Some("[]".to_string()),
            ..Default::default()
        };
        let wf = workflows::insert(&db, &new).await.unwrap();
        workflows::update(
            &db,
            wf.id,
            &workflows::WorkflowUpdate { cloud_callable: Some(1), ..Default::default() },
        )
        .await
        .unwrap();

        let f = run_local_workflow(&engine, &db, "t", &wf.id.to_string(), json!({}), &no_map()).await;
        assert_eq!(f["success"], json!(false));
        assert!(f["error"].as_str().unwrap().contains("streaming"));
    }

    /// A stub engine with no warm browser (the trait default `browser() -> None`) — enough to reach
    /// the goal/provider/browser gates in `handle_ai_session_start` without launching anything.
    struct StubEngine;
    impl LocalEngine for StubEngine {
        fn run<'a>(
            &'a self,
            _req: RunRequest,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = crate::local::error::LocalResult<crate::local::engine::RunResult>> + Send + 'a>,
        > {
            Box::pin(async { panic!("engine.run must not be called before the pre-run gates") })
        }
        fn active_runs(&self) -> usize {
            0
        }
    }

    /// A throwaway `task_id → run_id` map for the pre-flight tests (nothing ever reaches the engine,
    /// so nothing is ever registered).
    fn no_map() -> Arc<dashmap::DashMap<String, i64>> {
        Arc::new(dashmap::DashMap::new())
    }

    /// Receive the single frame a degrade/pre-flight path emits and parse it as JSON.
    fn recv_frame(rx: &mut mpsc::UnboundedReceiver<Message>) -> Value {
        match rx.try_recv().expect("expected an emitted frame") {
            Message::Text(t) => serde_json::from_str::<Value>(&t).unwrap(),
            other => panic!("unexpected non-text frame: {other:?}"),
        }
    }

    /// A raw (non-crawl) `execute_workflow` is SERVED, not rejected: on a stub engine with no
    /// browser manager it still answers a well-formed `task_result` naming the missing browser —
    /// never the old "raw execute_workflow is not supported" copy.
    #[tokio::test]
    async fn raw_execute_workflow_is_dispatched_not_rejected() {
        let engine: Arc<dyn LocalEngine> = Arc::new(StubEngine);
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        let msg = json!({
            "type": "execute_workflow",
            "task_id": "t-raw",
            "config": {
                "entry_url": "https://example.com",
                "steps": [{ "type": "navigate", "url": "https://example.com" }],
            },
        });
        execute_wire_workflow(&engine, None, "t-raw", &msg, &tx, &Arc::new(TaskLedger::new())).await;
        let frame = recv_frame(&mut rx);
        assert_eq!(frame["type"], "task_result");
        assert_eq!(frame["task_id"], "t-raw");
        assert_eq!(frame["success"], json!(false), "StubEngine has no browser manager");
        let err = frame["error"].as_str().unwrap();
        assert!(
            !err.contains("not supported"),
            "raw execute_workflow must be served, got rejection: {err}"
        );
        assert!(err.contains("browser"), "degrade names the missing browser: {err}");
    }

    /// Wire pre-flight mirrors the by-id run path: streaming and AI-loop/advanced-script shapes
    /// are rejected with a clear `task_result` error and no browser/engine touch.
    #[tokio::test]
    async fn raw_execute_workflow_preflight_rejects_streaming_shapes() {
        let engine: Arc<dyn LocalEngine> = Arc::new(StubEngine);

        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        let msg = json!({
            "type": "execute_workflow",
            "task_id": "t-stream",
            "config": { "workflow_type": "streaming", "steps": [] },
        });
        execute_wire_workflow(&engine, None, "t-stream", &msg, &tx, &Arc::new(TaskLedger::new())).await;
        let frame = recv_frame(&mut rx);
        assert_eq!(frame["success"], json!(false));
        assert!(frame["error"].as_str().unwrap().contains("streaming"));

        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        let msg = json!({
            "type": "execute_workflow",
            "task_id": "t-script",
            "config": { "streaming_config": { "advanced_script": "loop {}" }, "steps": [] },
        });
        execute_wire_workflow(&engine, None, "t-script", &msg, &tx, &Arc::new(TaskLedger::new())).await;
        let frame = recv_frame(&mut rx);
        assert_eq!(frame["success"], json!(false));
        assert!(frame["error"].as_str().unwrap().contains("advanced-script"));
    }

    /// Crawl-shard classification: `crawl_batch` first steps and `_crawl_shard` trigger contexts
    /// route to the shard runner (with the trigger_context folded into the config); a plain
    /// workflow config routes to the raw wire executor.
    #[test]
    fn crawl_shard_classification_routes_shards_only() {
        // steps[0].type == crawl_batch, trigger_context riding top-level → folded in.
        let m = json!({
            "config": { "steps": [{ "type": "crawl_batch" }] },
            "trigger_context": { "_crawl_shard": { "urls": ["https://example.com"] } },
        });
        let cfg = crawl_shard_config(&m).expect("crawl_batch routes to the shard runner");
        assert!(cfg["trigger_context"]["_crawl_shard"].is_object(), "top-level tc folded into config");

        // `_crawl_shard` under config.trigger_context is also a shard.
        let m = json!({
            "config": {
                "trigger_context": { "_crawl_shard": {} },
                "steps": [{ "type": "navigate" }],
            },
        });
        assert!(crawl_shard_config(&m).is_some());

        // A plain full-definition workflow is NOT a shard → raw wire executor.
        let m = json!({ "config": { "steps": [{ "type": "navigate" }] } });
        assert!(crawl_shard_config(&m).is_none());
    }

    /// `ai_session_start` with a missing goal replies `ai_session_failed`, echoes `session_id`, and
    /// never panics (nor records a workflow).
    #[tokio::test]
    async fn ai_session_start_missing_goal_fails_gracefully() {
        let (db, vault, _dir) = fresh_db_vault().await;
        let engine: Arc<dyn LocalEngine> = Arc::new(StubEngine);
        let msg = json!({
            "type": "ai_session_start",
            "session_id": "sess-1",
            "goal": "   ",
            "entry_url": "https://example.com",
            "generate_workflow": true,
        });
        let (reply, recorded) = handle_ai_session_start(&db, &vault, &engine, None, &msg, None).await;
        assert!(!recorded, "a failed start records nothing");
        assert_eq!(reply["type"], "ai_session_failed");
        assert_eq!(reply["session_id"], "sess-1", "correlation id echoed back");
        assert!(reply["error"].as_str().unwrap().contains("goal"));
    }

    /// With a valid goal but NO AI provider configured (and no cloud gateway), the start replies
    /// `ai_session_failed` with an `ai_unavailable` reason (graceful degrade, echoes `session_id`).
    #[tokio::test]
    async fn ai_session_start_without_ai_provider_replies_ai_unavailable() {
        let (db, vault, _dir) = fresh_db_vault().await;
        let engine: Arc<dyn LocalEngine> = Arc::new(StubEngine);
        let msg = json!({
            "type": "ai_session_start",
            "session_id": "sess-2",
            "goal": "sign up for an account",
            "entry_url": "https://example.com",
        });
        let (reply, recorded) = handle_ai_session_start(&db, &vault, &engine, None, &msg, None).await;
        assert!(!recorded);
        assert_eq!(reply["type"], "ai_session_failed");
        assert_eq!(reply["session_id"], "sess-2");
        assert!(
            reply["error"].as_str().unwrap().contains("ai_unavailable"),
            "no provider ⇒ ai_unavailable, got {}",
            reply["error"]
        );
    }

    // -----------------------------------------------------------------------
    // Idempotency ledger
    // -----------------------------------------------------------------------

    /// The core invariant: a duplicate dispatch is ANSWERED, never re-executed. A completed task
    /// replays its exact recorded result; a still-running one reports `AlreadyRunning`.
    #[test]
    fn ledger_replays_completed_and_refuses_a_second_concurrent_run() {
        let ledger = TaskLedger::new();
        assert_eq!(ledger.claim("t1"), Claim::Fresh);
        // Redispatch while in flight → do NOT start a second run.
        assert_eq!(ledger.claim("t1"), Claim::AlreadyRunning);

        let result = task_result_frame("t1", true, json!({"order_id": 42}), None, 1234);
        ledger.complete("t1", result.clone());
        // Redispatch after completion → replay the ORIGINAL outcome.
        match ledger.claim("t1") {
            Claim::Replay(frame) => assert_eq!(frame, result),
            other => panic!("expected a replay, got {other:?}"),
        }
        // A different id is unaffected.
        assert_eq!(ledger.claim("t2"), Claim::Fresh);
    }

    /// A handler that dies without producing a result must RELEASE its claim (via the drop guard),
    /// so the coordinator's retry can legitimately run — while a settled task keeps its cached
    /// result even after the guard drops.
    #[test]
    fn task_claim_guard_releases_an_unfinished_run_but_keeps_a_settled_result() {
        let ledger = Arc::new(TaskLedger::new());
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

        assert_eq!(ledger.claim("t-panic"), Claim::Fresh);
        {
            let _claim = TaskClaim::new(ledger.clone(), "t-panic".to_string());
        } // dropped without settling — as on a panic/abort
        assert_eq!(
            ledger.claim("t-panic"),
            Claim::Fresh,
            "an abandoned run must not be answered `already_running` forever"
        );

        assert!(matches!(ledger.claim("t-ok"), Claim::AlreadyRunning | Claim::Fresh));
        {
            let claim = TaskClaim::new(ledger.clone(), "t-ok".to_string());
            claim.settle(&tx, task_result_frame("t-ok", true, json!({}), None, 7));
        }
        assert!(matches!(ledger.claim("t-ok"), Claim::Replay(_)), "settled results survive the guard");
        // …and settling actually emitted the frame.
        let frame = recv_frame(&mut rx);
        assert_eq!(frame["type"], "task_result");
        assert_eq!(frame["task_id"], "t-ok");
    }

    /// The ledger is a bounded cache, not a log: terminal results past the cap are evicted
    /// oldest-first, and in-flight claims are never evicted for size.
    #[test]
    fn ledger_is_bounded_and_never_evicts_an_in_flight_claim() {
        let ledger = TaskLedger::new();
        let in_flight = "t-live";
        assert_eq!(ledger.claim(in_flight), Claim::Fresh);
        for n in 0..(TASK_LEDGER_CAP * 2) {
            let id = format!("done-{n}");
            ledger.claim(&id);
            ledger.complete(&id, json!({"n": n}));
        }
        // The next claim runs an eviction pass.
        ledger.claim("trigger");
        assert!(
            ledger.len() <= TASK_LEDGER_CAP + 2,
            "ledger must stay bounded, got {}",
            ledger.len()
        );
        assert_eq!(
            ledger.claim(in_flight),
            Claim::AlreadyRunning,
            "an in-flight claim must survive size eviction (evicting it would allow a double run)"
        );
    }

    /// `accept_task` is the read-loop gate: a duplicate is answered inline and NOT executed.
    #[tokio::test]
    async fn accept_task_answers_duplicates_inline() {
        let (db, vault, _dir) = fresh_db_vault().await;
        let engine: Arc<dyn LocalEngine> = Arc::new(StubEngine);
        let bridge = FleetBridge::new(
            engine,
            db,
            vault,
            "https://coordinator.example.com".to_string(),
            "tok".to_string(),
            false,
            false,
        );
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

        assert!(bridge.accept_task("task-1", &tx), "first dispatch executes");
        assert!(!bridge.accept_task("task-1", &tx), "duplicate must not execute");
        let ack = recv_frame(&mut rx);
        assert_eq!(ack["type"], "task_ack");
        assert_eq!(ack["status"], "already_running");

        // Once terminal, a duplicate replays the cached task_result.
        bridge
            .tasks
            .complete("task-1", task_result_frame("task-1", true, json!({}), None, 5));
        assert!(!bridge.accept_task("task-1", &tx));
        let replay = recv_frame(&mut rx);
        assert_eq!(replay["type"], "task_result");
        assert_eq!(replay["task_id"], "task-1");

        // An id-less dispatch cannot be deduped and is still executed (unchanged behavior).
        assert!(bridge.accept_task("", &tx));
    }

    // -----------------------------------------------------------------------
    // Deploy input caps
    // -----------------------------------------------------------------------

    /// A deployed workflow persists to disk and survives restarts, so oversized fields are REFUSED
    /// (with a clear reason on the ack) instead of written.
    #[test]
    fn deploy_size_caps_reject_oversized_fields() {
        assert!(deploy_size_error("ok", Some("fine"), "[]", Some("{}")).is_none());
        assert!(deploy_size_error(&"x".repeat(MAX_NAME_CHARS + 1), None, "[]", None)
            .unwrap()
            .contains("name"));
        assert!(deploy_size_error("ok", Some(&"d".repeat(MAX_DESCRIPTION_BYTES + 1)), "[]", None)
            .unwrap()
            .contains("description"));
        assert!(deploy_size_error("ok", None, &"s".repeat(MAX_STEPS_BYTES + 1), None)
            .unwrap()
            .contains("steps"));
        assert!(deploy_size_error("ok", None, "[]", Some(&"f".repeat(MAX_FORM_DATA_BYTES + 1)))
            .unwrap()
            .contains("form_data"));
    }

    /// End-to-end through the save handler: an oversized `steps` blob is refused on the ack and
    /// NOTHING is written to the store.
    #[tokio::test]
    async fn save_local_workflow_refuses_an_oversized_steps_blob() {
        let (db, vault, _dir) = fresh_db_vault().await;
        // One step whose selector alone blows the cap.
        let huge = json!([{ "type": "click", "selector": "a".repeat(MAX_STEPS_BYTES + 1) }]);
        let frame = json!({
            "type": "save_local_workflow",
            "request_id": "req-big",
            "name": "Huge",
            "steps": huge,
        });
        let ack = handle_save_local_workflow(&db, &vault, None, &frame).await;
        assert_eq!(ack["request_id"], "req-big");
        assert!(
            ack["error"].as_str().unwrap_or_default().contains("steps"),
            "expected a steps-size refusal, got {ack}"
        );
        assert_eq!(stored_workflow_count(&db).await.unwrap(), 0, "nothing may be persisted");
    }

    // -----------------------------------------------------------------------
    // Capacity: advertise what can actually be admitted
    // -----------------------------------------------------------------------

    /// An engine that exposes a REAL resource governor (and records cancels), so the capacity +
    /// cancel plumbing can be exercised with no browser and no coordinator.
    struct GovernedEngine {
        governor: Arc<crate::local::governor::ResourceGovernor>,
        cancelled: Arc<std::sync::Mutex<Vec<i64>>>,
        /// Run ids `cancel` should report as LIVE (`Some(true)`); anything else reports `None`.
        live_runs: Vec<i64>,
    }

    impl GovernedEngine {
        fn new(global: usize, background: usize) -> Self {
            Self {
                governor: Arc::new(crate::local::governor::ResourceGovernor::new(
                    crate::local::governor::GovernorConfig {
                        max_concurrent_runs: global,
                        max_background_runs: background,
                        rss_soft_watermark_bytes: 0,
                    },
                )),
                cancelled: Arc::new(std::sync::Mutex::new(Vec::new())),
                live_runs: Vec::new(),
            }
        }
    }

    impl LocalEngine for GovernedEngine {
        fn run<'a>(
            &'a self,
            _req: RunRequest,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = crate::local::error::LocalResult<crate::local::engine::RunResult>> + Send + 'a>,
        > {
            Box::pin(async { panic!("engine.run must not be called by these tests") })
        }
        fn active_runs(&self) -> usize {
            0
        }
        fn cancel(&self, run_id: i64) -> Option<bool> {
            self.cancelled.lock().unwrap().push(run_id);
            self.live_runs.contains(&run_id).then_some(true)
        }
        fn governor(&self) -> Option<Arc<crate::local::governor::ResourceGovernor>> {
            Some(self.governor.clone())
        }
    }

    async fn bridge_with(engine: Arc<dyn LocalEngine>) -> (FleetBridge, TempDir) {
        let (db, vault, dir) = fresh_db_vault().await;
        let bridge = FleetBridge::new(
            engine,
            db,
            vault,
            "https://coordinator.example.com".to_string(),
            "tok".to_string(),
            false,
            false,
        );
        (bridge, dir)
    }

    /// The advertised capacity is what the GOVERNOR can admit (its background sub-ceiling), not a
    /// CPU/RAM guess. This is the whole bug: a 16-core box advertised 16, admitted 2, and failed 14
    /// dispatches instantly with a cryptic ceiling error.
    #[tokio::test]
    async fn advertised_capacity_matches_what_the_governor_admits() {
        // Background sub-ceiling 2 while the global ceiling is 8 — the coordinator must see 2.
        let (bridge, _dir) = bridge_with(Arc::new(GovernedEngine::new(8, 2))).await;
        assert_eq!(bridge.max_sessions(), 2, "advertise the admissible number, not the host's cores");

        // A tiny box is still bounded by the HOST hint, so we never advertise more than the machine
        // can host either: capacity = min(governor, host hint).
        let host_hint = detect_max_sessions();
        let (big, _dir2) = bridge_with(Arc::new(GovernedEngine::new(64, 64))).await;
        assert_eq!(big.max_sessions(), host_hint.max(1));
    }

    /// A governorless engine keeps the pre-existing host-derived capacity (no behavior change for the
    /// stub/test engines that have nothing to admit against).
    #[tokio::test]
    async fn governorless_engine_falls_back_to_the_host_hint() {
        let (bridge, _dir) = bridge_with(Arc::new(StubEngine)).await;
        assert_eq!(bridge.max_sessions(), detect_max_sessions());
    }

    /// `set_capacity` may LOWER capacity but never raise it past what the governor admits — otherwise
    /// a coordinator (or an admin UI) could re-create the over-advertising bug at runtime.
    #[tokio::test]
    async fn set_capacity_is_clamped_to_the_governor_ceiling() {
        let (bridge, _dir) = bridge_with(Arc::new(GovernedEngine::new(8, 3))).await;
        let ceiling = bridge.max_sessions();
        assert!(ceiling >= 1);

        bridge.set_max_sessions(50);
        assert_eq!(bridge.max_sessions(), ceiling, "cannot advertise beyond the admissible ceiling");

        bridge.set_max_sessions(1);
        assert_eq!(bridge.max_sessions(), 1, "lowering is always allowed");

        bridge.set_max_sessions(0);
        assert_eq!(bridge.max_sessions(), 1, "never zero");
    }

    /// Admission is shared with by-id runs on the background lane, and once it is saturated a further
    /// dispatch is REFUSED rather than queued — that fast refusal is what lets the worker answer the
    /// coordinator instead of parking its awaited future.
    #[tokio::test]
    async fn dispatch_admission_saturates_then_refuses() {
        let (bridge, _dir) = bridge_with(Arc::new(GovernedEngine::new(4, 2))).await;

        let p1 = bridge.admit_dispatch().await.expect("slot 1").expect("governed engine");
        let p2 = bridge.admit_dispatch().await.expect("slot 2").expect("governed engine");
        let reason = bridge.admit_dispatch().await.expect_err("third must be refused");
        assert!(reason.contains("ceiling"), "refusal names the reason: {reason}");

        drop(p1);
        bridge.admit_dispatch().await.expect("a freed slot admits again");
        drop(p2);
    }

    /// A governorless engine admits unconditionally (`Ok(None)`) so those builds keep working exactly
    /// as before.
    #[tokio::test]
    async fn dispatch_admission_is_a_noop_without_a_governor() {
        let (bridge, _dir) = bridge_with(Arc::new(StubEngine)).await;
        assert!(bridge.admit_dispatch().await.expect("admitted").is_none());
    }

    /// A capacity refusal must produce a RESOLVED `task_result{success:false}` naming the condition —
    /// the coordinator's awaited future has to resolve, not hang until its own timeout.
    #[tokio::test]
    async fn capacity_refusal_emits_a_resolved_task_result() {
        let (bridge, _dir) = bridge_with(Arc::new(GovernedEngine::new(1, 1))).await;
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

        bridge.refuse_at_capacity("t-full", "background concurrency ceiling reached", &tx);

        let frame = recv_frame(&mut rx);
        assert_eq!(frame["type"], "task_result", "must be the terminal frame the coordinator awaits");
        assert_eq!(frame["task_id"], "t-full");
        assert_eq!(frame["success"], json!(false));
        let err = frame["error"].as_str().unwrap();
        assert!(err.starts_with("at capacity"), "stable prefix for the coordinator: {err}");
    }

    /// The refusal is NOT recorded as a terminal result: capacity is transient, so a redispatch of the
    /// same task id must be free to actually run rather than replay the failure for the result TTL.
    #[tokio::test]
    async fn capacity_refusal_is_not_cached_in_the_ledger() {
        let (bridge, _dir) = bridge_with(Arc::new(GovernedEngine::new(1, 1))).await;
        let (tx, _rx) = mpsc::unbounded_channel::<Message>();

        assert!(bridge.accept_task("t-retry", &tx), "first dispatch claims the id");
        {
            let claim = TaskClaim::new(bridge.tasks.clone(), "t-retry".to_string());
            bridge.refuse_at_capacity("t-retry", "memory watermark exceeded", &tx);
            drop(claim); // the read loop drops the claim on refusal
        }
        assert_eq!(
            bridge.tasks.claim("t-retry"),
            Claim::Fresh,
            "a refused task must be retryable, not permanently answered"
        );
    }

    // -----------------------------------------------------------------------
    // cancel_task
    // -----------------------------------------------------------------------

    /// `cancel_task` for a LIVE dispatched run reaches the engine's cooperative cancel and acks
    /// `found: true`. Previously this arm logged a line, sent nothing, and tore nothing down.
    #[tokio::test]
    async fn cancel_task_cancels_the_mapped_run_and_acks() {
        let mut eng = GovernedEngine::new(4, 2);
        eng.live_runs = vec![4242];
        let cancelled = eng.cancelled.clone();
        let (bridge, _dir) = bridge_with(Arc::new(eng)).await;
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

        // As `run_local_workflow` does when the engine allocates the run row.
        bridge.dispatched_runs.insert("task-9".to_string(), 4242);

        bridge.handle_cancel_task("task-9", &tx);

        let ack = recv_frame(&mut rx);
        assert_eq!(ack["type"], "task_cancelled");
        assert_eq!(ack["task_id"], "task-9");
        assert_eq!(ack["found"], json!(true));
        assert_eq!(cancelled.lock().unwrap().as_slice(), &[4242], "the engine was actually asked");
    }

    /// An unknown / already-settled task still gets an ACK (`found: false`) and never touches the
    /// engine — a coordinator awaiting the reply must not hang, and no unrelated run may be cancelled.
    #[tokio::test]
    async fn cancel_task_acks_not_found_without_touching_the_engine() {
        let eng = GovernedEngine::new(4, 2);
        let cancelled = eng.cancelled.clone();
        let (bridge, _dir) = bridge_with(Arc::new(eng)).await;
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

        bridge.handle_cancel_task("never-dispatched", &tx);

        let ack = recv_frame(&mut rx);
        assert_eq!(ack["type"], "task_cancelled");
        assert_eq!(ack["found"], json!(false));
        assert!(cancelled.lock().unwrap().is_empty(), "no run id ⇒ no cancel attempt");
    }

    /// A run the engine reports as no-longer-live acks `found: false` — the map entry existed but the
    /// run settled in between, which the coordinator should be told plainly.
    #[tokio::test]
    async fn cancel_task_of_a_settled_run_reports_not_found() {
        // `live_runs` is empty → `cancel` returns None for every id.
        let (bridge, _dir) = bridge_with(Arc::new(GovernedEngine::new(4, 2))).await;
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        bridge.dispatched_runs.insert("task-done".to_string(), 7);

        bridge.handle_cancel_task("task-done", &tx);
        assert_eq!(recv_frame(&mut rx)["found"], json!(false));
    }

    /// The dispatch map is RAII: the entry is gone once the handler returns, so a recycled task id can
    /// never cancel an unrelated run.
    #[test]
    fn dispatched_run_guard_removes_its_entry_on_drop() {
        let map: Arc<dashmap::DashMap<String, i64>> = Arc::new(dashmap::DashMap::new());
        {
            let _g = DispatchedRunGuard { map: map.clone(), task_id: "t".to_string() };
            map.insert("t".to_string(), 11);
            assert_eq!(map.get("t").map(|e| *e.value()), Some(11));
        }
        assert!(map.get("t").is_none(), "a settled run must not stay cancellable");
    }

    // -----------------------------------------------------------------------
    // Active-unit accounting
    // -----------------------------------------------------------------------

    /// Every spawned dispatch unit counts toward the advertised active-session number, and the count
    /// is RAII so an aborted handler (a connection loss) cannot leak it.
    #[tokio::test]
    async fn inflight_guard_counts_all_work_and_releases_on_drop() {
        let (bridge, _dir) = bridge_with(Arc::new(StubEngine)).await;
        assert_eq!(bridge.active_units(), 0);

        let a = InflightGuard::new(bridge.inflight.clone());
        let b = InflightGuard::new(bridge.inflight.clone());
        assert_eq!(bridge.active_units(), 2, "shards/wire runs/sessions are no longer invisible");

        drop(a);
        assert_eq!(bridge.active_units(), 1);
        drop(b);
        assert_eq!(bridge.active_units(), 0);

        // A stray release saturates instead of wrapping — a wrapped usize gauge would advertise
        // ~1.8e19 active sessions and exclude this worker from dispatch forever.
        drop(InflightGuard { counter: bridge.inflight.clone() });
        assert_eq!(bridge.active_units(), 0);
    }
}
