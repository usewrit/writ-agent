//! Cloud REFLECTION — the desktop "dual view" surface (daemon side) for Workflows, Monitors and
//! Personas.
//!
//! When a cloud account is linked, the desktop Workflows / Monitors / Personas pages each show BOTH a
//! LIVE reflection of the user's cloud items (controlled IN THE CLOUD) and the LOCAL-DB items
//! (runnable on the local agent). This module backs the CLOUD half:
//!
//!   * **LIST**  — [`list_workflows`] is a thin authenticated passthrough to the cloud automation
//!     list (`GET /api/automation/workflows`). The summary array is passed through VERBATIM and is
//!     NEVER persisted locally (no import on view).
//!   * **RUN**   — [`run_workflow`] is a CLOUD-MEDIATED run: it POSTs the cloud run endpoint
//!     (`POST /api/automation/workflows/{id}/run`); the CLOUD executes + meters. We return a stable
//!     `{ run_id }` (the cloud's `task_id` stringified) so the UI can poll.
//!   * **RUN STATUS** — [`run_status`] polls the cloud task (`GET /api/automation/tasks/{task_id}`)
//!     and projects it to a stable webview shape `{ run_id, status, done, duration_ms, error, ... }`.
//!   * **COPY FOR OFFLINE** — [`copy_local`] fetches the cloud workflow DETAIL and inserts a LOCAL
//!     row via the EXISTING sync mapping (`sync::new_workflow_from_cloud` + `cloud_sync_map` upsert,
//!     `origin='cloud'`). It is IDEMPOTENT on the cloud id (a second copy returns the existing local
//!     id, `copied=false`) and NEVER imports a credential VALUE (`credentials_encrypted = None`).
//!     This is the ONLY path in this module that writes anything locally — it is per-item and
//!     user-initiated, for disconnected/offline use.
//!
//! MONITORS (the local `targets` table) mirror the workflow shape, minus the run/poll machinery (the
//! cloud has no "check now" endpoint — see the daemon scout). The CLOUD half exposes:
//!   * **LIST** — [`list_monitors`] passes through `GET /api/targets` (live state incl. `enabled`).
//!   * **PAUSE/RESUME** — [`set_monitor_enabled`] issues `PATCH /api/targets/{id} { enabled }` so the
//!     cloud pause/resume happens cloud-side (the local scheduler never touches a reflected monitor).
//!   * **RUN ON MY LOCAL AGENT** — [`copy_monitor_local`] fetches the cloud target DETAIL and inserts a
//!     LOCAL `targets` row via [`sync::new_target_from_cloud`], forcing `enabled = 1` and
//!     `next_run_at = None` so the LOCAL scheduler picks it up offline (the explicit intent of
//!     localizing a monitor). It is IDEMPOTENT on the cloud id and NEVER imports a session/secret value
//!     (`NewTarget` has no `auth_session_encrypted` field — the no-secret invariant is structural).
//!
//! PERSONAS mirror the same shape with NO run/control (personas aren't executable). The CLOUD half is:
//!   * **LIST** — [`list_personas`] passes through `GET /api/personas` (METADATA ONLY: the backend
//!     returns `has_password`/`has_totp_seed`/`has_warm_session` booleans, NEVER a secret value).
//!   * **COPY FOR OFFLINE** — [`copy_persona_local`] fetches the cloud persona DETAIL and inserts a
//!     LOCAL `personas` row via [`sync::new_persona_from_cloud`] (which hard-codes every `*_encrypted`
//!     column to `None` — a credential VALUE is NEVER imported; the user re-attaches creds locally).
//!     IDEMPOTENT on the cloud id.
//!
//! INVARIANTS (matching the dual-view LAW):
//!  - Cloud-reflected items are LIVE: the lists are passthroughs; nothing is written on view, so the
//!    local SCHEDULER (which runs only local `workflows`/`targets` rows) never touches them. A
//!    cloud-reflected monitor is NEVER run by the local scheduler — only an explicit `copy-local`
//!    creates a local (intentionally enabled) row.
//!  - `copy-local` reuses the sync mapping so a copied row is a normal cloud-origin local row, and a
//!    later `cloud_sync_pull` treats it as already mapped (no duplicate).
//!  - `copy-local` never pulls cred/session values — the shared mappers hard-code the secret columns
//!    to `None` (`new_workflow_from_cloud` / `new_persona_from_cloud`); `NewTarget` has no secret
//!    column at all.
//!  - `wto_` stays daemon-side: the webview hits the loopback `/v1/cloud/reflect/*` routes with the
//!    `wlt_` bearer only; this module attaches the `wto_` via [`CloudClient`].
//!
//! Net-new Rust in this crate, behind the `local` cargo feature.

use serde_json::{json, Value};
use sqlx::sqlite::SqlitePool;

use super::super::error::{LocalError, LocalResult};
use super::super::store::{cloud_sync_map, personas, targets, workflows};
use super::client::CloudClient;
use super::state::LinkState;
use super::sync;

// --------------------------------------------------------------------------------------------
// Cloud automation paths (backend `automation_router` is mounted under `/api`).
// CloudClient joins these onto the resolved cloud base url (no trailing slash).
// --------------------------------------------------------------------------------------------

/// The cloud automation workflows collection (list + `{id}` detail/run base).
const CLOUD_WORKFLOWS: &str = "/api/automation/workflows";

/// The cloud monitors collection (`GET` list + `{id}` detail/`PATCH`). Backend `targets_router` is
/// mounted under `/api`; the desktop `wto_`/`pso_` OAuth token reaches it (see the daemon scout).
const CLOUD_MONITORS: &str = "/api/targets";

/// The cloud personas collection (`GET` list + `{id}` detail). Backend `personas_router` is mounted
/// under `/api` and returns METADATA ONLY (`has_*` booleans, never secret values).
const CLOUD_PERSONAS: &str = "/api/personas";

/// The cloud streaming-session START endpoint (`POST`). Backend `streaming_router` is mounted under
/// `/api`; a STREAMING workflow has no one-shot run, so "run in cloud" for it starts a session here.
const CLOUD_STREAMING_START: &str = "/api/streaming/sessions/start";

/// The coordinator's management view of the tenant's cloud-callable LOCAL workflows (backend
/// `connected_apps` router, self-prefixed). Session-authed, METADATA ONLY — it is how this daemon
/// learns the CANONICAL coordinator id the cloud assigned to each workflow it advertised.
const CLOUD_CONNECTED_APPS: &str = "/api/connected-apps/workflows";

/// The linked ACCOUNT's API keys (`wt_…`) — backend `auth_router`, mounted under `/api`. These are
/// the credentials a caller off this machine needs, so the desktop must be able to mint and revoke
/// them without sending the user to the web app.
const CLOUD_API_KEYS: &str = "/api/api-keys";

/// Build the cloud run path for a workflow cloud id (`POST .../{id}/run`).
fn run_path(cloud_id: &str) -> String {
    format!("{CLOUD_WORKFLOWS}/{}/run", encode_segment(cloud_id))
}

/// Build the cloud workflow DETAIL path for a cloud id (`GET .../{id}`). Used by `copy-local` (the
/// list summary strips `steps`, so the copy must read the full recipe).
fn detail_path(cloud_id: &str) -> String {
    format!("{CLOUD_WORKFLOWS}/{}", encode_segment(cloud_id))
}

/// Build the cloud monitor DETAIL path for a cloud id (`GET`/`PATCH .../{id}`). Used by both the
/// pause/resume PATCH and `copy-local` (which reads the full check definition).
fn monitor_detail_path(cloud_id: &str) -> String {
    format!("{CLOUD_MONITORS}/{}", encode_segment(cloud_id))
}

/// Build the cloud persona DETAIL path for a cloud id (`GET .../{id}`). Used by `copy-local`.
fn persona_detail_path(cloud_id: &str) -> String {
    format!("{CLOUD_PERSONAS}/{}", encode_segment(cloud_id))
}

/// Build the cloud task-status path for a run/task id (`GET /api/automation/tasks/{task_id}`). The
/// run endpoint returns a `task_id`; the status endpoint is keyed on `tasks/{task_id}`.
fn task_status_path(run_id: &str) -> String {
    format!("/api/automation/tasks/{}", encode_segment(run_id))
}

/// Open an authenticated cloud client for the current link, or a clean `Unauthorized` when the
/// desktop is not linked. Mirrors `marketplace::client` so the `wto_` token loads once from the
/// keyring and never leaves the daemon.
async fn client(db: &SqlitePool) -> LocalResult<CloudClient> {
    let link = LinkState::load_or_default(db).await?;
    CloudClient::connect(Some(&link))
}

// --------------------------------------------------------------------------------------------
// LIST — live passthrough (NEVER stored)
// --------------------------------------------------------------------------------------------

/// `GET /api/automation/workflows` — the live cloud workflow list. The summary array is passed
/// through VERBATIM (the UI renders it). Nothing is persisted: reflected rows are never written to
/// the local DB, so they can never be picked up by the local scheduler.
pub async fn list_workflows(db: &SqlitePool) -> LocalResult<Value> {
    let list: Value = client(db).await?.get_json(CLOUD_WORKFLOWS).await?;
    let arr = match list.as_array() {
        Some(a) => a,
        None => return Ok(list),
    };

    // Enrich each cloud workflow with its LOCAL-install state so the UI can hide workflows the user
    // already copied locally (unless the cloud copy has since changed):
    //   * `installed_local`   — a `cloud_sync_map` entry maps this cloud id to a local row that still
    //                           exists AND is visible (is_active=1; a soft-deleted copy doesn't count,
    //                           so it re-appears in the cloud list to be re-installed).
    //   * `update_available`  — best-effort drift: the cloud `updated_at` is newer than when we copied
    //                           (`synced_at`). When the cloud omits `updated_at`, this stays false
    //                           (treated as "no update" → the installed row is hidden).
    let maps = cloud_sync_map::list_by_type(db, sync::ENTITY_WORKFLOW)
        .await
        .unwrap_or_default();

    let mut out = Vec::with_capacity(arr.len());
    for w in arr {
        let mut w = w.clone();
        let cloud_id = reflect_id_to_string(w.get("id").unwrap_or(&Value::Null));
        let mut installed_local = false;
        let mut update_available = false;
        if !cloud_id.is_empty() {
            if let Some(m) = maps.iter().find(|m| m.cloud_id == cloud_id) {
                installed_local = matches!(
                    workflows::get_by_id(db, m.local_id).await,
                    Ok(Some(ref r)) if r.is_active == 1
                );
                if installed_local {
                    if let Some(updated) = w.get("updated_at").and_then(Value::as_str) {
                        update_available = updated > m.synced_at.as_str();
                    }
                }
            }
        }
        if let Some(obj) = w.as_object_mut() {
            obj.insert("installed_local".into(), json!(installed_local));
            obj.insert("update_available".into(), json!(update_available));
        }
        out.push(w);
    }
    Ok(Value::Array(out))
}

/// `GET /api/automation/tasks` (+ names from `/api/automation/workflows`) — the linked account's LIVE
/// (non-terminal) cloud runs, projected to the activity-feed shape the desktop popover renders as
/// "Running in cloud". This is a REAL cloud call authenticated as the desktop's OAuth-logged user (the
/// `wto_` token stays in the daemon), so it returns the user's OWN in-flight cloud runs. Nothing is
/// stored. Shape: `{ "runs": [ { run_id, workflow_id, workflow_name, status, started_at, venue } ] }`.
/// Best-effort on names: a name-fetch failure falls back to a null name (the UI shows the id), never an
/// error that would blank the whole feed.
pub async fn list_running_runs(db: &SqlitePool) -> LocalResult<Value> {
    let mut c = client(db).await?;
    // Recent tasks; `summary` omits heavy result_data/screenshots. Keep only the non-terminal ("live")
    // ones — that IS "what's running in the cloud right now".
    let tasks_raw: Value = c
        .get_json("/api/automation/tasks?summary=true&limit=50")
        .await?;
    let live: Vec<Value> = tasks_raw
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter(|t| {
                    let s = t.get("status").and_then(Value::as_str).unwrap_or("");
                    !is_terminal_cloud_status(s)
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    if live.is_empty() {
        return Ok(json!({ "runs": [] }));
    }

    // Resolve workflow names (best-effort). A fetch failure → empty map → the UI shows the id.
    let names: std::collections::HashMap<i64, String> =
        match c.get_json::<Value>(CLOUD_WORKFLOWS).await {
            Ok(list) => list
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|w| {
                            let id = w.get("id").and_then(Value::as_i64)?;
                            let name = w.get("name").and_then(Value::as_str)?.to_string();
                            Some((id, name))
                        })
                        .collect()
                })
                .unwrap_or_default(),
            Err(_) => std::collections::HashMap::new(),
        };

    let runs: Vec<Value> = live
        .iter()
        .map(|t| {
            let wid = t.get("workflow_id").and_then(Value::as_i64);
            json!({
                "run_id": reflect_id_to_string(t.get("id").unwrap_or(&Value::Null)),
                "workflow_id": t.get("workflow_id").cloned().unwrap_or(Value::Null),
                "workflow_name": wid.and_then(|id| names.get(&id).cloned()),
                "status": t.get("status").cloned().unwrap_or(Value::Null),
                // Prefer the real start; fall back to created_at (queued runs have no start yet).
                "started_at": t
                    .get("started_at")
                    .cloned()
                    .filter(|v| !v.is_null())
                    .or_else(|| t.get("created_at").cloned())
                    .unwrap_or(Value::Null),
                "venue": "cloud",
                // Place-in-line + ETA for a CLOUD-queued run, passed straight
                // through from the cloud task summary (the backend fills these for
                // status == "queued" via queue_estimator). Absent/null otherwise —
                // the desktop UI just omits the "in line" label then.
                "queue_source": t.get("queue_source").cloned().unwrap_or(Value::Null),
                "queue_position": t.get("queue_position").cloned().unwrap_or(Value::Null),
                "queue_total": t.get("queue_total").cloned().unwrap_or(Value::Null),
                "estimated_wait_ms": t.get("estimated_wait_ms").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();
    Ok(json!({ "runs": runs }))
}

/// Coerce a cloud id (int or string) to a stable string the webview treats as opaque.
fn reflect_id_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

// --------------------------------------------------------------------------------------------
// RUN — cloud-mediated (the cloud executes + meters)
// --------------------------------------------------------------------------------------------

/// Result of [`run_workflow`] — the cloud run/task id, stringified for the webview.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReflectRunStarted {
    /// The cloud `task_id`, stringified (cloud ids may be ints; the UI treats it as opaque).
    pub run_id: String,
}

/// `POST /api/automation/workflows/{cloud_id}/run` — start a CLOUD-MEDIATED run of the user's own
/// cloud workflow. The cloud executes and meters it; we only relay the returned `task_id` (or
/// `run_id`) as a stable string the UI polls with [`run_status`].
///
/// We PIN `execution_target: "cloud"` in the body. This surface is explicitly "run in the cloud"
/// (the desktop's Run→Cloud choice / a cloud row's default venue). Without the pin the backend falls
/// back to the workflow's stored `execution_target`, whose default `"auto"` routes to the user-hosted
/// BYO agent FIRST — so a linked desktop (which auto-registers as a supply agent) would silently
/// execute "Run in cloud" on THIS very device. Forcing `"cloud"` sends it to the cloud pool, matching
/// the UI's promise ("executed and metered in the cloud"). The cloud still resolves the workflow's own
/// inputs/config server-side.
pub async fn run_workflow(
    db: &SqlitePool,
    cloud_id: &str,
    form_data: Option<Value>,
) -> LocalResult<ReflectRunStarted> {
    // Per-run inputs collected by the desktop Run modal (the `{{input.NAME}}` placeholder values).
    // The cloud run endpoint accepts a `form_data` override and otherwise falls back to the workflow's
    // stored form_data — so we forward it only when the modal actually collected values. Secrets are
    // NEVER included here: they stay resolved server-side (creator vault / stored credentials).
    let mut body = json!({ "execution_target": "cloud" });
    if let (Some(obj), Some(fd)) = (body.as_object_mut(), form_data) {
        if fd.as_object().is_some_and(|m| !m.is_empty()) {
            obj.insert("form_data".into(), fd);
        }
    }
    let resp: Value = client(db).await?.post_json(&run_path(cloud_id), &body).await?;
    // The run endpoint returns `{ task_id, ... }`; tolerate `run_id`/`id` as fallbacks.
    let run_id = resp
        .get("task_id")
        .and_then(value_id_string)
        .or_else(|| resp.get("run_id").and_then(value_id_string))
        .or_else(|| resp.get("id").and_then(value_id_string))
        .ok_or_else(|| {
            // Authorized run but no id is a cloud contract violation; surface a clean error rather
            // than a silent success the UI can't poll.
            LocalError::Internal("cloud run response missing a task_id/run_id".into())
        })?;
    Ok(ReflectRunStarted { run_id })
}

/// Result of [`start_streaming_session`] — the cloud streaming-session handle for the UI.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReflectStreamingStarted {
    /// The cloud streaming session key (opaque string; the UI can surface / poll it web-side).
    pub session_key: String,
    /// The session status the cloud reported at start (e.g. `"queued"` / `"running"`).
    pub status: String,
}

/// `POST /api/streaming/sessions/start` — start a CLOUD streaming session for the user's own cloud
/// STREAMING workflow (`workflow_type == "streaming"`).
///
/// A streaming workflow has NO one-shot dispatch — its recipe lives in `streaming_config`, not
/// `steps` — so the regular [`run_workflow`] `/run` path is wrong for it (it would try to execute an
/// empty step list). This starts a session instead, exactly like the web app's "start streaming
/// session". The backend requires a `target_url`; the list summary strips it, so we read the
/// workflow DETAIL's `entry_url` (same source `copy_local` uses). We PIN `execution_target: "cloud"`
/// for the same reason [`run_workflow`] does — never the user-hosted BYO agent. Returns
/// `{ session_key, status }`.
pub async fn start_streaming_session(
    db: &SqlitePool,
    cloud_id: &str,
) -> LocalResult<ReflectStreamingStarted> {
    let mut cli = client(db).await?;
    // The session start needs the workflow's entry URL as `target_url`; read it from the detail.
    let detail: Value = cli.get_json(&detail_path(cloud_id)).await?;
    let workflow_id = cloud_id
        .parse::<i64>()
        .map_err(|_| LocalError::Internal("cloud workflow id is not numeric".into()))?;
    let target_url = detail
        .get("entry_url")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let body = json!({
        "workflow_id": workflow_id,
        "target_url": target_url,
        // Pin the CLOUD venue (never the BYO agent) — see run_workflow.
        "execution_target": "cloud",
        "headless": true,
    });
    let resp: Value = cli.post_json(CLOUD_STREAMING_START, &body).await?;
    let session_key = resp
        .get("session_key")
        .and_then(value_id_string)
        .ok_or_else(|| {
            LocalError::Internal("cloud streaming start response missing a session_key".into())
        })?;
    let status = resp
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("queued")
        .to_string();
    Ok(ReflectStreamingStarted { session_key, status })
}

// --------------------------------------------------------------------------------------------
// RUN STATUS — poll the cloud task
// --------------------------------------------------------------------------------------------

/// Terminal cloud task statuses for a reflected (cloud-mediated) run. `done` keys on the CLOUD task
/// status set (not the local-runs lifecycle states), so the UI stops polling once the cloud task
/// reaches any terminal state. Anything not in this set (e.g. `running`/`pending`/`queued`/empty)
/// is treated as still in flight.
fn is_terminal_cloud_status(status: &str) -> bool {
    matches!(
        status.to_ascii_lowercase().as_str(),
        "success" | "failed" | "error" | "completed" | "cancelled" | "canceled"
    )
}

/// `GET /api/automation/tasks/{run_id}` — poll a cloud-mediated run's status, projected to the
/// stable webview shape `{ run_id, status, done, duration_ms?, started_at?, finished_at?, error? }`.
/// We deliberately do NOT pass the raw cloud row through: the UI keys on a `done` flag and an
/// end-user-safe `error`, and the cloud row uses different field names (`completed_at`,
/// `error_message`).
pub async fn run_status(db: &SqlitePool, run_id: &str) -> LocalResult<Value> {
    let task: Value = client(db).await?.get_json(&task_status_path(run_id)).await?;
    let status = task
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    // A cloud task may also carry a boolean `success` once terminal; fold it into a friendly status
    // when the textual status is ambiguous, but `done` is the authoritative stop signal for the UI.
    let done = is_terminal_cloud_status(&status);
    Ok(json!({
        "run_id": run_id,
        "status": status,
        "done": done,
        "duration_ms": task.get("duration_ms").and_then(Value::as_i64),
        "started_at": task.get("started_at").cloned().unwrap_or(Value::Null),
        "finished_at": task.get("completed_at").cloned().unwrap_or(Value::Null),
        // End-user-safe error detail only; the cloud already keeps this generic.
        "error": task.get("error_message").cloned().unwrap_or(Value::Null),
    }))
}

// --------------------------------------------------------------------------------------------
// CONTROL — cloud-authoritative pause/resume + rename + delete + cancel of the user's OWN cloud
// workflow (the desktop dual-view mirrors the website's controls, relayed to the cloud instantly).
// The cloud is the source of truth for a reflected workflow's state; we relay the mutation and
// return the cloud's response (or unit) for an authoritative UI refresh. NOTHING is written locally
// — a reflected workflow is never stored, so these never touch a local row or the local scheduler.
// --------------------------------------------------------------------------------------------

/// `PUT /api/automation/workflows/{cloud_id}` — relay a PARTIAL operational update. Only the explicit
/// whitelisted fields are forwarded — schedule pause/resume (`schedule_enabled`), interval
/// (`schedule_interval_ms`), rename (`name`) — never a logic-bearing field (steps/functions/entry),
/// so this control path can never rewrite the recipe. The cloud `WorkflowUpdate` schema is fully
/// optional, so a field left `None` is simply omitted. Returns the updated cloud workflow row for an
/// authoritative refresh. An all-`None` call is a harmless no-op update.
pub async fn update_workflow(
    db: &SqlitePool,
    cloud_id: &str,
    schedule_enabled: Option<bool>,
    schedule_interval_ms: Option<i64>,
    name: Option<&str>,
) -> LocalResult<Value> {
    let mut patch = serde_json::Map::new();
    if let Some(v) = schedule_enabled {
        patch.insert("schedule_enabled".into(), json!(v));
    }
    if let Some(v) = schedule_interval_ms {
        patch.insert("schedule_interval_ms".into(), json!(v));
    }
    if let Some(v) = name {
        patch.insert("name".into(), json!(v));
    }
    client(db)
        .await?
        .put_json::<_, Value>(&detail_path(cloud_id), &Value::Object(patch))
        .await
}

/// `DELETE /api/automation/workflows/{cloud_id}` — delete the user's OWN cloud workflow. The UI drops
/// the row + refetches; never touches a local row (a reflected workflow is never stored locally).
pub async fn delete_workflow(db: &SqlitePool, cloud_id: &str) -> LocalResult<()> {
    client(db).await?.delete(&detail_path(cloud_id)).await
}

/// `DELETE /api/automation/tasks/{run_id}` — cancel an in-flight cloud-mediated run (the cloud frees
/// the reserved hold immediately). `run_id` is the cloud task id returned by [`run_workflow`].
pub async fn cancel_run(db: &SqlitePool, run_id: &str) -> LocalResult<()> {
    client(db).await?.delete(&task_status_path(run_id)).await
}

// --------------------------------------------------------------------------------------------
// COPY FOR OFFLINE — insert a LOCAL row via the existing sync mapping (idempotent, no cred values)
// --------------------------------------------------------------------------------------------

/// Result of [`copy_local`] — the local row id and whether a NEW copy was created (`true`) or an
/// existing mapping was reused (`false`, the idempotent path).
#[derive(Debug, Clone, serde::Serialize)]
pub struct CopyLocalResult {
    pub local_id: i64,
    /// A NEW local row was created (`true`) vs an existing mapping was reused (`false`).
    pub copied: bool,
    /// The reused local row was refreshed from a CHANGED cloud recipe on this call (idempotent path
    /// only). Lets the UI say "updated the local copy" and clear the `update_available` badge.
    pub updated: bool,
}

/// "Copy for offline" — fetch the cloud workflow DETAIL and insert a LOCAL row so it can run on the
/// local agent while disconnected. IDEMPOTENT on the cloud id: if `cloud_sync_map` already maps this
/// cloud id to a still-present local row, return that local id with `copied=false` (no duplicate).
///
/// Reuses the EXISTING sync mapping exactly as `sync::pull_workflows` does:
///   * the row is built by [`sync::new_workflow_from_cloud`] (which hard-codes
///     `credentials_encrypted = None` — a cred VALUE is NEVER imported),
///   * the mapping is recorded with `origin='cloud'` and the normalized content hash, so a later
///     `cloud_sync_pull` treats this row as already-mapped (cloud wins, no re-import).
pub async fn copy_local(db: &SqlitePool, cloud_id: &str) -> LocalResult<CopyLocalResult> {
    // Idempotency + UPDATE: an existing mapping whose local row still exists is REUSED (no duplicate).
    // On that path we additionally
    //   (a) REACTIVATE a deactivated copy (`is_active=0` is hidden by the default list), and
    //   (b) PULL the latest cloud recipe when the local row hasn't been edited since the last sync —
    //       so "Copy for offline" on a workflow the cloud has since CHANGED refreshes the local copy
    //       and clears its `update_available` badge.
    // This mirrors `sync::pull_workflows`' cloud-wins rule: a LOCALLY-EDITED (diverged) row is never
    // clobbered — we only reactivate it. A mapping pointing at a vanished local row re-imports fresh.
    if let Some(map) = cloud_sync_map::get_by_cloud_id(db, sync::ENTITY_WORKFLOW, cloud_id).await? {
        if let Some(existing) = workflows::get_by_id(db, map.local_id).await? {
            let reactivate = existing.is_active == 0;
            let local_hash = sync::workflow_content_hash(&existing);
            let diverged = map.content_hash.as_deref() != Some(local_hash.as_str());
            let mut updated = false;

            if diverged {
                // The user edited this copy locally — don't overwrite their edits with the cloud recipe.
                // Still make a deactivated copy runnable again.
                if reactivate {
                    workflows::update(
                        db,
                        map.local_id,
                        &workflows::WorkflowUpdate { is_active: Some(1), ..Default::default() },
                    )
                    .await?;
                }
            } else {
                // Unchanged locally → cloud wins: pull the fresh recipe (+ reactivate) in one write.
                let detail: Value = client(db).await?.get_json(&detail_path(cloud_id)).await?;
                // Diagnostic: if the cloud response arrives with EMPTY `steps`, this
                // branch would clobber a good local recipe with `"[]"`. Log the
                // dimensions before we write. `steps_from_cloud=0` here + a run
                // that later reports `steps=0` = the copy-side overwrite is the
                // culprit; guard the write below if this is confirmed.
                let steps_from_cloud = detail.get("steps").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0);
                let entry_url_from_cloud = detail.get("entry_url").and_then(Value::as_str).unwrap_or("").to_string();
                let is_installed_from_cloud = detail.get("is_installed").and_then(Value::as_bool).unwrap_or(false);
                tracing::info!(
                    cloud_id,
                    local_id = map.local_id,
                    steps_from_cloud,
                    entry_url = %entry_url_from_cloud,
                    is_installed = is_installed_from_cloud,
                    prev_stored_steps_len = existing.steps.len(),
                    "cloud detail received for copy_local re-sync"
                );
                // DEFENSIVE: the cloud strips `steps` for install proxies (creator IP
                // protection) via `workflow_to_response`. If the cloud response has
                // NO steps but we already hold a real local recipe, refusing to
                // overwrite prevents "1-step re-sync silently wiped my copy". Only
                // reactivate if needed and re-hash so we stop replaying this branch.
                let cloud_recipe_looks_stripped = steps_from_cloud == 0 && !existing.steps.is_empty() && existing.steps != "[]";
                let mut patch = if cloud_recipe_looks_stripped {
                    tracing::warn!(
                        cloud_id,
                        local_id = map.local_id,
                        is_installed = is_installed_from_cloud,
                        "cloud response missing steps — keeping local recipe (re-sync would have wiped it)"
                    );
                    workflows::WorkflowUpdate::default()
                } else {
                    sync::workflow_update_from_cloud(&detail)
                };
                if reactivate {
                    patch.is_active = Some(1);
                }
                let new_row = workflows::update(db, map.local_id, &patch).await?;
                let new_hash = sync::workflow_content_hash(&new_row);
                updated = new_hash != local_hash;
                // Always refresh the mapping (`set_content_hash` also bumps `synced_at`): even when the
                // recipe is byte-identical, we just re-synced, so `synced_at` must advance past the
                // cloud `updated_at` — otherwise the time-based `update_available` flag (a no-op cloud
                // save can bump `updated_at` without changing content) would never clear.
                cloud_sync_map::set_content_hash(db, sync::ENTITY_WORKFLOW, map.local_id, &new_hash)
                    .await?;
            }

            if reactivate || updated {
                tracing::info!(
                    cloud_id,
                    local_id = map.local_id,
                    reactivated = reactivate,
                    updated,
                    "refreshed an existing cloud-copied workflow on re-copy"
                );
            }
            return Ok(CopyLocalResult { local_id: map.local_id, copied: false, updated });
        }
    }

    // Fetch the FULL recipe (the list summary strips `steps`), then map → insert via the shared
    // pull mapping (no cred values) and record the cloud-origin mapping.
    let detail: Value = client(db).await?.get_json(&detail_path(cloud_id)).await?;
    // Diagnostic: log the cloud-side recipe DIMENSIONS (never the values) so a
    // silently-empty copy is diagnosable without a repro. `steps=0` here means
    // the cloud response itself dropped them — that's the "installed proxy /
    // recipe-protected" branch on the server. `steps=N` here + `steps=0` at run
    // time means the loss is on OUR side (insert / re-read).
    let steps_from_cloud = detail.get("steps").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0);
    let entry_url_from_cloud = detail.get("entry_url").and_then(Value::as_str).unwrap_or("").to_string();
    let is_installed_from_cloud = detail.get("is_installed").and_then(Value::as_bool).unwrap_or(false);
    tracing::info!(
        cloud_id,
        steps_from_cloud,
        entry_url = %entry_url_from_cloud,
        is_installed = is_installed_from_cloud,
        "cloud detail received for copy_local"
    );
    let new = sync::new_workflow_from_cloud(&detail);
    let new_steps_len = new.steps.as_deref().map(str::len).unwrap_or(0);
    let inserted = workflows::insert(db, &new).await?;
    let hash = sync::workflow_content_hash(&inserted);
    cloud_sync_map::upsert(
        db,
        sync::ENTITY_WORKFLOW,
        inserted.id,
        cloud_id,
        Some(&hash),
        "cloud",
    )
    .await?;

    tracing::info!(
        cloud_id,
        local_id = inserted.id,
        stored_steps_len = inserted.steps.len(),
        mapped_steps_text_len = new_steps_len,
        entry_url_stored = ?inserted.entry_url,
        "cloud workflow copied for offline use"
    );
    Ok(CopyLocalResult { local_id: inserted.id, copied: true, updated: false })
}

// ============================================================================================
// MONITORS (the local `targets` table) — list + cloud pause/resume + "run on my local agent"
// ============================================================================================

/// `GET /api/targets` — the live cloud monitor list. The array is passed through VERBATIM (real
/// state incl. `enabled`). Nothing is persisted: reflected monitors are never written to the local
/// DB, so the local scheduler (which runs only local `targets` rows) can never pick them up.
pub async fn list_monitors(db: &SqlitePool) -> LocalResult<Value> {
    let list: Value = client(db).await?.get_json(CLOUD_MONITORS).await?;
    let arr = match list.as_array() {
        Some(a) => a,
        None => return Ok(list),
    };
    // Enrich with LOCAL-install state so the Cloud tab can hide monitors already copied to the local
    // agent (mirrors `list_workflows`): `installed_local` = a `cloud_sync_map` entry maps this cloud id
    // to a local `targets` row that still exists. A read error is treated as not-installed (never fails
    // the whole list over one row).
    let maps = cloud_sync_map::list_by_type(db, sync::ENTITY_MONITOR)
        .await
        .unwrap_or_default();
    let mut out = Vec::with_capacity(arr.len());
    for m in arr {
        let mut m = m.clone();
        let cloud_id = reflect_id_to_string(m.get("id").unwrap_or(&Value::Null));
        let mut installed_local = false;
        if !cloud_id.is_empty() {
            if let Some(map) = maps.iter().find(|x| x.cloud_id == cloud_id) {
                installed_local = matches!(targets::get_by_id(db, map.local_id).await, Ok(Some(_)));
            }
        }
        if let Some(obj) = m.as_object_mut() {
            obj.insert("installed_local".into(), json!(installed_local));
        }
        out.push(m);
    }
    Ok(Value::Array(out))
}

/// `PATCH /api/targets/{cloud_id} { enabled }` — CLOUD pause/resume of the user's own cloud monitor.
/// The cloud is authoritative for a reflected monitor's run state; we relay the cloud's response
/// (the updated target) back to the UI for an authoritative refresh. Never writes locally.
pub async fn set_monitor_enabled(
    db: &SqlitePool,
    cloud_id: &str,
    enabled: bool,
) -> LocalResult<Value> {
    client(db)
        .await?
        .patch_json::<_, Value>(&monitor_detail_path(cloud_id), &json!({ "enabled": enabled }))
        .await
}

/// "Run on my local agent" — fetch the cloud monitor DETAIL and insert a LOCAL `targets` row so the
/// local scheduler runs it OFFLINE. IDEMPOTENT on the cloud id: if `cloud_sync_map` already maps this
/// cloud id to a still-present local row, return that local id with `copied=false` (no duplicate).
///
/// The row is built by [`sync::new_target_from_cloud`] (the SAME mapper `sync::pull_monitors` uses)
/// and then FORCED to `enabled = 1` + `next_run_at = None`: localizing a monitor is the explicit
/// user intent to run it on the local agent, so it imports ENABLED and ready for the scheduler.
/// A session/secret value is NEVER imported — `NewTarget` has no `auth_session_encrypted` field, so
/// the no-secret invariant is structural, not just a guard.
pub async fn copy_monitor_local(db: &SqlitePool, cloud_id: &str) -> LocalResult<CopyLocalResult> {
    // Idempotency: an existing mapping whose local row still exists short-circuits (no cloud call,
    // no duplicate). A mapping pointing at a vanished local row falls through to re-copy.
    if let Some(map) = cloud_sync_map::get_by_cloud_id(db, sync::ENTITY_MONITOR, cloud_id).await? {
        if targets::get_by_id(db, map.local_id).await?.is_some() {
            return Ok(CopyLocalResult { local_id: map.local_id, copied: false, updated: false });
        }
    }

    // Fetch the full check definition, map → insert (no secret values), forcing the row ENABLED and
    // unscheduled so the local scheduler runs it immediately.
    let detail: Value = client(db).await?.get_json(&monitor_detail_path(cloud_id)).await?;
    let mut new = sync::new_target_from_cloud(&detail);
    new.enabled = Some(1);
    new.next_run_at = None;
    // `targets::insert` returns the new id (not the row), so re-read to compute the content hash.
    let local_id = targets::insert(db, &new).await?;
    let hash = match targets::get_by_id(db, local_id).await? {
        Some(t) => Some(sync::target_content_hash(&t)),
        None => None,
    };
    cloud_sync_map::upsert(
        db,
        sync::ENTITY_MONITOR,
        local_id,
        cloud_id,
        hash.as_deref(),
        "cloud",
    )
    .await?;

    tracing::info!(cloud_id, local_id, "cloud monitor copied to run on the local agent");
    Ok(CopyLocalResult { local_id, copied: true, updated: false })
}

/// `POST /api/targets` (+ `/api/targets/{id}/selectors`) — CREATE a monitor that lives + runs in the
/// CLOUD, from the desktop creation wizard's "run this check in the cloud" choice. Orchestrates the
/// SAME sequence the local `/v1/monitors` create does, but against the cloud target API:
///   1. create the target (the cloud re-enforces plan limits / blocklist / SSRF — a `PlanLimitDenied`
///      surfaces to the webview as the create error, exactly like a local capacity refusal),
///   2. create each selector on it, then
///   3. best-effort seed each selector's baseline so change detection has a reference on the first
///      check (a slow/failed baseline never aborts the create — the first cloud check re-derives it).
/// Nothing is written locally: a cloud monitor is a reflected row, controlled from the Cloud tab.
/// Returns `{ cloud_id, monitor }` (the created cloud target) for an authoritative UI refresh.
pub async fn create_monitor(
    db: &SqlitePool,
    target: Value,
    selectors: Vec<Value>,
) -> LocalResult<Value> {
    let mut c = client(db).await?;
    // (1) Create the target. A cloud refusal (plan limit / blocked domain / bad URL) propagates as the
    // create error — the wizard shows it and stays put, so nothing is half-created client-side.
    let created: Value = c.post_json(CLOUD_MONITORS, &target).await?;
    let cloud_id = reflect_id_to_string(created.get("id").unwrap_or(&Value::Null));

    if !cloud_id.is_empty() {
        for sel in &selectors {
            let sel_path = format!("{CLOUD_MONITORS}/{}/selectors", encode_segment(&cloud_id));
            // (2) Best-effort per selector: a duplicate/invalid selector must not orphan the target or
            // drop the other selectors — the target already exists and is usable with what lands.
            match c.post_json::<_, Value>(&sel_path, sel).await {
                Ok(created_sel) => {
                    let sid = reflect_id_to_string(created_sel.get("id").unwrap_or(&Value::Null));
                    if !sid.is_empty() {
                        // (3) Best-effort baseline — non-fatal (the first scheduled cloud check will
                        // establish one anyway). Never blocks or fails the create over a fetch hiccup.
                        let base_path = format!(
                            "{CLOUD_MONITORS}/{}/selectors/{}/set-baseline",
                            encode_segment(&cloud_id),
                            encode_segment(&sid),
                        );
                        if let Err(e) = c.post_json::<_, Value>(&base_path, &json!({})).await {
                            tracing::debug!(cloud_id, selector_id = sid, error = %e, "cloud monitor baseline seed failed (non-fatal)");
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(cloud_id, error = %e, "cloud monitor selector create failed (non-fatal)");
                }
            }
        }
    }

    tracing::info!(cloud_id, selectors = selectors.len(), "created a cloud monitor from the desktop wizard");
    Ok(json!({ "cloud_id": cloud_id, "monitor": created }))
}

/// `PATCH /api/targets/{cloud_id}` — relay a PARTIAL operational update of a reflected cloud monitor
/// (pause/resume, check cadence, Render-JS, region, structured recurrence) by its `cloud_id`. Only the
/// present, whitelisted fields are forwarded — never a selector/logic rewrite — so this control path
/// mirrors `update_workflow`: the desktop can retune a cloud check it created without opening the web
/// app. Returns the updated cloud target for an authoritative refresh; nothing is written locally.
#[allow(clippy::too_many_arguments)]
pub async fn update_monitor(
    db: &SqlitePool,
    cloud_id: &str,
    enabled: Option<bool>,
    check_period_ms: Option<i64>,
    requires_playwright: Option<bool>,
    preferred_region: Option<Value>,
    schedule_kind: Option<&str>,
    schedule_time: Option<Value>,
    schedule_days: Option<Vec<i64>>,
    schedule_tz: Option<Value>,
) -> LocalResult<Value> {
    let mut patch = serde_json::Map::new();
    if let Some(v) = enabled {
        patch.insert("enabled".into(), json!(v));
    }
    if let Some(v) = check_period_ms {
        patch.insert("check_period_ms".into(), json!(v));
    }
    if let Some(v) = requires_playwright {
        patch.insert("requires_playwright".into(), json!(v));
    }
    // `preferred_region`/`schedule_*` accept an explicit null (clear the region / reset to interval),
    // so they ride as `Value` — a present `Some(Null)` is forwarded, an absent `None` is omitted.
    if let Some(v) = preferred_region {
        patch.insert("preferred_region".into(), v);
    }
    if let Some(v) = schedule_kind {
        patch.insert("schedule_kind".into(), json!(v));
    }
    if let Some(v) = schedule_time {
        patch.insert("schedule_time".into(), v);
    }
    if let Some(v) = schedule_days {
        patch.insert("schedule_days".into(), json!(v));
    }
    if let Some(v) = schedule_tz {
        patch.insert("schedule_tz".into(), v);
    }
    client(db)
        .await?
        .patch_json::<_, Value>(&monitor_detail_path(cloud_id), &Value::Object(patch))
        .await
}

// ============================================================================================
// PERSONAS — list + "copy for offline" (NO run/control; personas aren't executable)
// ============================================================================================

/// `GET /api/personas` — the live cloud persona list. METADATA ONLY by construction: the backend
/// `PersonaResponse` exposes only `has_password`/`has_totp_seed`/`has_warm_session` booleans, never a
/// secret value. The array is passed through VERBATIM and never persisted on view.
pub async fn list_personas(db: &SqlitePool) -> LocalResult<Value> {
    let list: Value = client(db).await?.get_json(CLOUD_PERSONAS).await?;
    let arr = match list.as_array() {
        Some(a) => a,
        None => return Ok(list),
    };
    // Enrich with LOCAL-install state so the Cloud tab can hide personas already copied for offline
    // (mirrors `list_workflows`): `installed_local` = a `cloud_sync_map` entry maps this cloud id to a
    // local `personas` row that still exists. A read error is treated as not-installed.
    let maps = cloud_sync_map::list_by_type(db, sync::ENTITY_PERSONA)
        .await
        .unwrap_or_default();
    let mut out = Vec::with_capacity(arr.len());
    for p in arr {
        let mut p = p.clone();
        let cloud_id = reflect_id_to_string(p.get("id").unwrap_or(&Value::Null));
        let mut installed_local = false;
        if !cloud_id.is_empty() {
            if let Some(map) = maps.iter().find(|x| x.cloud_id == cloud_id) {
                installed_local = matches!(personas::get_by_id(db, map.local_id).await, Ok(Some(_)));
            }
        }
        if let Some(obj) = p.as_object_mut() {
            obj.insert("installed_local".into(), json!(installed_local));
        }
        out.push(p);
    }
    Ok(Value::Array(out))
}

/// "Copy for offline" — fetch the cloud persona DETAIL and insert a LOCAL `personas` row so it is
/// available while disconnected. IDEMPOTENT on the cloud id (a second copy returns the existing local
/// id, `copied=false`).
///
/// The row is built by [`sync::new_persona_from_cloud`], which hard-codes EVERY secret column
/// (`credentials_encrypted` / `totp_seed_encrypted` / `proxy_config_encrypted` /
/// `session_state_encrypted`) to `None` — a credential VALUE is NEVER imported. The user re-attaches
/// credentials locally (the same no-cred-import rule `sync::pull_personas` follows).
pub async fn copy_persona_local(db: &SqlitePool, cloud_id: &str) -> LocalResult<CopyLocalResult> {
    // Idempotency: a present mapping → reuse the local id with no cloud call, no duplicate.
    if let Some(map) = cloud_sync_map::get_by_cloud_id(db, sync::ENTITY_PERSONA, cloud_id).await? {
        if personas::get_by_id(db, map.local_id).await?.is_some() {
            return Ok(CopyLocalResult { local_id: map.local_id, copied: false, updated: false });
        }
    }

    // Fetch the persona metadata, map → insert (no cred VALUES by construction) + record the mapping.
    let detail: Value = client(db).await?.get_json(&persona_detail_path(cloud_id)).await?;
    let new = sync::new_persona_from_cloud(&detail);
    let inserted = personas::insert(db, &new).await?;
    let hash = sync::persona_content_hash(&inserted);
    cloud_sync_map::upsert(
        db,
        sync::ENTITY_PERSONA,
        inserted.id,
        cloud_id,
        Some(&hash),
        "cloud",
    )
    .await?;

    tracing::info!(cloud_id, local_id = inserted.id, "cloud persona copied for offline use");
    Ok(CopyLocalResult { local_id: inserted.id, copied: true, updated: false })
}

// ============================================================================================
// CLOUD-CALLABLE LOCAL WORKFLOWS — the coordinator's view of what THIS device advertises
// ============================================================================================

/// `GET /api/connected-apps/workflows` — the SESSION-authed management view of the tenant's
/// cloud-callable LOCAL workflows. Each row carries the CANONICAL coordinator `id` (the ref
/// `POST /api/v1/local-workflows/{id}/run` takes), the daemon-side `local_id` it mirrors, the
/// owning `agent_id`, and whether that daemon is online right now.
///
/// The desktop needs this because the catalog flows ONE WAY: the gateway pushes `local_catalog`
/// frames up (see `gateway::send_catalog`) and never learns the coordinator id the cloud assigned.
/// Without reading it back, a Connect surface could only advertise the LEGACY `local_id` ref —
/// which the cloud rejects as ambiguous (409) the moment a tenant links a second daemon. So we
/// read the real id rather than print a URL that breaks for multi-device users.
///
/// Passthrough only: METADATA (name/description/declared inputs/recipe hash) — never steps or
/// credentials — and nothing is persisted locally.
pub async fn list_cloud_callable(db: &SqlitePool) -> LocalResult<Value> {
    client(db).await?.get_json(CLOUD_CONNECTED_APPS).await
}

// ============================================================================================
// CLOUD ACCOUNT API KEYS — mint / list / revoke the `wt_` credentials from the desktop
// ============================================================================================
//
// The cloud-callable surfaces hand out a cloud URL, and that URL takes an ACCOUNT key (`wt_`), not
// the loopback `wlk_` one. Without these the only way to get that credential was the web app, which
// breaks the desktop-only promise the moment a user wants to call their own workflow from anywhere.
//
// These are passthroughs, NOT a local key store: the cloud owns issuance, hashing and revocation,
// and the SECRET is returned exactly once by the cloud's create response — we relay that response
// verbatim and never persist it. The `wto_` account token stays in the daemon as always; the
// webview only ever sees the created key it just asked for.

/// `GET /api/api-keys` — the account's API keys (metadata; the secret is never re-served).
pub async fn list_cloud_api_keys(db: &SqlitePool) -> LocalResult<Value> {
    client(db).await?.get_json(CLOUD_API_KEYS).await
}

/// `GET /api/api-keys/catalog` — the scope vocabulary (resources / actions / presets) the cloud
/// serves so every key screen offers the same grants instead of hardcoding its own subset.
pub async fn cloud_api_key_catalog(db: &SqlitePool) -> LocalResult<Value> {
    client(db)
        .await?
        .get_json(&format!("{CLOUD_API_KEYS}/catalog"))
        .await
}

/// `POST /api/ws-ticket` — mint a single-use recording-WS ticket on the linked account, for the
/// desktop's "record on Writ Cloud" venue. The cloud accepts the daemon's first-party `wto_` token
/// and binds the ticket to a short-lived session JWT it mints server-side; the reply
/// (`{ticket, expires_in, record_ws_url}`) carries everything the webview needs to dial the
/// ws-gateway directly (`record_ws_url?ticket=…`). The `wto_` token itself never reaches the
/// webview — only the one-shot ticket does.
pub async fn mint_record_ticket(db: &SqlitePool) -> LocalResult<Value> {
    client(db).await?.post_json("/api/ws-ticket", &json!({})).await
}

/// `POST /api/automation/workflows` — create a workflow ON the linked cloud account (the wizard's
/// cloud-venue save). Body is the cloud `WorkflowCreate` passed through verbatim; the cloud
/// re-enforces every plan limit, so a refusal surfaces as this call's error. The created row is a
/// CLOUD workflow — it appears in the Cloud list via [`cloud_workflows`], is never written locally.
pub async fn create_cloud_workflow(db: &SqlitePool, body: &Value) -> LocalResult<Value> {
    client(db).await?.post_json("/api/automation/workflows", body).await
}

/// `POST /api/api-keys` — mint an account key. `body` is the cloud `CreateAPIKeyRequest`
/// (`{label, preset|scopes, …}`) passed through verbatim; the reply carries the one-time secret.
pub async fn create_cloud_api_key(db: &SqlitePool, body: &Value) -> LocalResult<Value> {
    client(db).await?.post_json(CLOUD_API_KEYS, body).await
}

/// `DELETE /api/api-keys/{id}` — revoke an account key. The cloud answers 204; we return `{ok:true}`
/// so the webview has a uniform JSON shape to branch on.
pub async fn delete_cloud_api_key(db: &SqlitePool, key_id: &str) -> LocalResult<Value> {
    client(db)
        .await?
        .delete(&format!("{CLOUD_API_KEYS}/{}", encode_segment(key_id)))
        .await?;
    Ok(json!({ "ok": true }))
}

// --------------------------------------------------------------------------------------------
// Small helpers (path encoding + tolerant cloud-JSON id reads)
// --------------------------------------------------------------------------------------------

/// Percent-encode a single path SEGMENT (a cloud id) so a hostile value can't traverse the path or
/// inject a query. Cloud ids are normally numeric/`[a-z0-9_-]`, but we encode defensively.
fn encode_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Stringify a JSON `id`-like field (cloud ids may be ints or strings). Empty string → `None`.
fn value_id_string(v: &Value) -> Option<String> {
    match v {
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::db;

    async fn pool() -> SqlitePool {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        db::open(&dir.path().join("t.db"), "test-key-reflect").await.unwrap()
    }

    #[test]
    fn paths_encode_segments() {
        assert_eq!(run_path("42"), "/api/automation/workflows/42/run");
        assert_eq!(detail_path("42"), "/api/automation/workflows/42");
        assert_eq!(task_status_path("99"), "/api/automation/tasks/99");
        assert_eq!(monitor_detail_path("7"), "/api/targets/7");
        assert_eq!(persona_detail_path("p_3"), "/api/personas/p_3");
        // A hostile id can't escape the path segment (monitor/persona detail paths too).
        assert_eq!(run_path("../x"), "/api/automation/workflows/..%2Fx/run");
        assert_eq!(task_status_path("a/b?c=1"), "/api/automation/tasks/a%2Fb%3Fc%3D1");
        assert_eq!(monitor_detail_path("../x"), "/api/targets/..%2Fx");
        assert_eq!(persona_detail_path("a/b?c=1"), "/api/personas/a%2Fb%3Fc%3D1");
    }

    #[test]
    fn terminal_status_table() {
        for s in ["success", "failed", "error", "completed", "cancelled", "canceled", "SUCCESS"] {
            assert!(is_terminal_cloud_status(s), "{s} should be terminal");
        }
        for s in ["running", "pending", "queued", "", "in_progress"] {
            assert!(!is_terminal_cloud_status(s), "{s} should NOT be terminal");
        }
    }

    #[test]
    fn value_id_string_tolerates_shapes() {
        assert_eq!(value_id_string(&json!(42)).as_deref(), Some("42"));
        assert_eq!(value_id_string(&json!("wf_7")).as_deref(), Some("wf_7"));
        assert_eq!(value_id_string(&json!("")), None);
        assert_eq!(value_id_string(&json!(null)), None);
        assert_eq!(value_id_string(&json!(true)), None);
    }

    /// `copy-local` is idempotent on the cloud id: a pre-existing mapping to a present local row is
    /// reused (`copied=false`) WITHOUT any cloud call. We seed a local workflow + its cloud mapping
    /// directly, then assert copy_local short-circuits to the same id. (The insert path that hits the
    /// cloud detail fetch is covered by the live link; here we prove the idempotency guard + the
    /// no-cred-value invariant of the shared mapper.)
    #[tokio::test]
    async fn copy_local_is_idempotent_on_existing_mapping() {
        let pool = pool().await;

        // Seed: a local workflow row built via the SAME shared mapper copy-local uses (proves the
        // no-cred-value invariant — `credentials_encrypted` is None by construction).
        let new = sync::new_workflow_from_cloud(&json!({
            "name": "Reflected WF",
            "workflow_type": "recorded",
            "steps": [ { "type": "wait", "config": { "duration": 10 } } ],
            "entry_url": "https://example.com",
            // A cloud payload may carry creds; the mapper MUST drop the value.
            "credentials_encrypted": "should_never_be_imported",
        }));
        assert!(new.credentials_encrypted.is_none(), "copy-local must never import a cred value");
        let inserted = workflows::insert(&pool, &new).await.unwrap();

        // Map it as a cloud-origin row for cloud id "777" with a STALE content hash — i.e. the local
        // copy has been edited since the last sync (the "diverged" case). This is the branch that
        // reuses the mapping WITHOUT any cloud call: an unchanged (non-diverged) copy would instead
        // re-pull the fresh cloud recipe (cloud-wins), which needs a live link. Seeding a stale hash
        // keeps this a pure, offline idempotency assertion (no unlinked cloud fetch → no Unauthorized).
        cloud_sync_map::upsert(&pool, sync::ENTITY_WORKFLOW, inserted.id, "777", Some("stale-hash"), "cloud")
            .await
            .unwrap();

        // copy_local("777") must reuse the existing local id, NOT duplicate (and not call the cloud).
        let res = copy_local(&pool, "777").await.unwrap();
        assert_eq!(res.local_id, inserted.id, "idempotent: reuse the mapped local id");
        assert!(!res.copied, "an existing mapping is reused, not re-copied");

        // No duplicate mapping was created.
        let maps = cloud_sync_map::list_by_type(&pool, sync::ENTITY_WORKFLOW).await.unwrap();
        assert_eq!(maps.len(), 1, "no duplicate cloud_sync_map row");
    }

    /// Monitor `copy-local` is idempotent on the cloud id: a pre-existing mapping to a present local
    /// `targets` row is reused (`copied=false`) WITHOUT any cloud call. We seed a local target via the
    /// SAME shared mapper copy-local uses, then assert the guard short-circuits to the same id. (The
    /// insert path that hits the cloud detail fetch is covered by the live link.) This also proves the
    /// no-secret invariant is structural — `NewTarget` has no session/secret column to import.
    #[tokio::test]
    async fn copy_monitor_local_is_idempotent_on_existing_mapping() {
        let pool = pool().await;

        // Seed a local target built via the mapper, forced enabled exactly as copy_monitor_local does.
        let mut new = sync::new_target_from_cloud(&json!({
            "url": "https://example.com/watch",
            "check_type": "content",
            "enabled": false, // cloud value; copy-local forces enabled below
        }));
        new.enabled = Some(1);
        new.next_run_at = None;
        let local_id = targets::insert(&pool, &new).await.unwrap();
        let t = targets::get_by_id(&pool, local_id).await.unwrap().unwrap();
        assert_eq!(t.enabled, 1, "a localized monitor must import ENABLED for the local scheduler");

        // Map it as a cloud-origin monitor for cloud id "555".
        let hash = sync::target_content_hash(&t);
        cloud_sync_map::upsert(&pool, sync::ENTITY_MONITOR, local_id, "555", Some(&hash), "cloud")
            .await
            .unwrap();

        // copy_monitor_local("555") must reuse the existing local id, NOT duplicate (no cloud call).
        let res = copy_monitor_local(&pool, "555").await.unwrap();
        assert_eq!(res.local_id, local_id, "idempotent: reuse the mapped local id");
        assert!(!res.copied, "an existing mapping is reused, not re-copied");

        let maps = cloud_sync_map::list_by_type(&pool, sync::ENTITY_MONITOR).await.unwrap();
        assert_eq!(maps.len(), 1, "no duplicate cloud_sync_map row");
    }

    /// Persona `copy-local` is idempotent on the cloud id: a pre-existing mapping to a present local
    /// `personas` row is reused (`copied=false`) WITHOUT any cloud call. We seed a local persona via the
    /// SAME shared mapper copy-local uses (which hard-codes every `*_encrypted` column to `None` — a
    /// cred VALUE is NEVER imported), then assert the guard short-circuits to the same id.
    #[tokio::test]
    async fn copy_persona_local_is_idempotent_on_existing_mapping() {
        let pool = pool().await;

        // Seed a local persona via the mapper. A cloud payload may carry a cred value; the mapper MUST
        // drop it (the no-cred-import invariant).
        let new = sync::new_persona_from_cloud(&json!({
            "name": "Reflected Persona",
            "target_domain": "example.com",
            "login_username": "user@example.com",
            "credentials": { "password": "should_never_be_imported" },
        }));
        assert!(new.credentials_encrypted.is_none(), "copy-local must never import a cred value");
        assert!(new.totp_seed_encrypted.is_none(), "copy-local must never import a TOTP seed");
        assert!(new.session_state_encrypted.is_none(), "copy-local must never import a session blob");
        let inserted = personas::insert(&pool, &new).await.unwrap();

        // Map it as a cloud-origin persona for cloud id "888".
        let hash = sync::persona_content_hash(&inserted);
        cloud_sync_map::upsert(&pool, sync::ENTITY_PERSONA, inserted.id, "888", Some(&hash), "cloud")
            .await
            .unwrap();

        // copy_persona_local("888") must reuse the existing local id, NOT duplicate (no cloud call).
        let res = copy_persona_local(&pool, "888").await.unwrap();
        assert_eq!(res.local_id, inserted.id, "idempotent: reuse the mapped local id");
        assert!(!res.copied, "an existing mapping is reused, not re-copied");

        let maps = cloud_sync_map::list_by_type(&pool, sync::ENTITY_PERSONA).await.unwrap();
        assert_eq!(maps.len(), 1, "no duplicate cloud_sync_map row");
    }
}
