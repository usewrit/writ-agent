//! `/v1/cloud/agent/*` REST handlers — the desktop's full cloud-execution-agent surface for the Tauri
//! shell (`golden-stargazing-gadget` Workstream A, §6/§7).
//!
//! These thin axum handlers wrap [`crate::local::cloud::agent::manager`] (the supervised
//! [`LinkedAgentManager`]) + [`crate::local::cloud::agent::runs`] (the live cloud-run map) so the Tauri
//! `cloud_agent_*` IPC commands have a loopback REST target. They run UNDER the existing loopback
//! bearer + Origin/Host guard applied once by `server.rs` (`auth_mw`) — there is NO new auth here.
//!
//! Routes (FIXED CONTRACT — the React/Tauri client matches these exactly):
//!   GET  /v1/cloud/agent/status   → live agent status snapshot (never any secret; works unlinked)
//!   POST /v1/cloud/agent/enable   → clear the disable flag + `mgr.start()` → status  (requires link)
//!   POST /v1/cloud/agent/disable  → set the disable flag + `mgr.stop()` → status     (requires link)
//!   GET  /v1/cloud/agent/runs     → live cloud-initiated runs (task_id ↔ run_id joined w/ runs row)
//!
//! SECURITY (HARD INVARIANTS — will be audited, the never-trust-a-BYO-agent rule):
//! - GATING: `enable`/`disable` require a linked cloud account. Unlinked → [`LocalError::Unauthorized`].
//!   `status`/`runs` are read-only and work while unlinked (`status` reports `linked: false`).
//! - The agent is DEFAULT-ON when linked; `enable`/`disable` only flip the explicit config OFF-switch
//!   (persisted to `config.toml` so it survives a restart) and drive the process-global manager.
//! - SECRETS: no token / channel-key / credential material ever appears in any response here.
//!
//! House style: thin handlers, `LocalResult<Json<_>>` with `?` propagation, no auth layer here.
//! Net-new Rust (behind the `local` feature).

use crate::local::cloud::agent::manager;
use crate::local::cloud::gateway::LINKED_AGENT_ID_KEY;
use crate::local::cloud::state::LinkState;
use crate::local::config;
use crate::local::error::{LocalError, LocalResult};
use crate::local::server::AppState;
use crate::local::store::{config_kv, runs};
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};

/// Mount the `/v1/cloud/agent/*` routes onto the shared `AppState` router. Auth is applied by
/// `server.rs` (mirror `relay::router()`).
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/cloud/agent/status", get(status))
        .route("/v1/cloud/agent/enable", post(enable))
        .route("/v1/cloud/agent/disable", post(disable))
        .route("/v1/cloud/agent/runs", get(agent_runs))
}

/// Require a linked cloud account, else a clean `Unauthorized`. Every WRITE route calls this first so
/// the gating invariant ("the cloud execution agent is ONLY drivable when a cloud account is linked")
/// is enforced uniformly (mirror `relay::require_linked`).
async fn require_linked(st: &AppState) -> LocalResult<LinkState> {
    let link = LinkState::load_or_default(&st.db).await?;
    if !link.is_linked() {
        return Err(LocalError::Unauthorized);
    }
    Ok(link)
}

/// Build the non-secret status snapshot. Combines link reflection, the persisted (disable /
/// supply-pool) config toggles, the gateway-assigned `agent_id` (non-secret routing metadata), and the
/// live manager snapshot (desired/online/last_error). Zeros/defaults when no manager is installed
/// (e.g. in tests). NEVER includes token / channel-key / credential material.
async fn build_status(st: &AppState) -> LocalResult<Value> {
    let link = LinkState::load_or_default(&st.db).await?;
    let linked = link.is_linked();

    // The persisted OFF-switch + supply-pool opt-in (freshest values from config.toml, not the boot
    // snapshot — enable/disable rewrite the file).
    let (disabled, supply_pool) = match config::Paths::resolve() {
        Ok(paths) => {
            let cfg = config::load_config(&paths);
            (cfg.cloud_agent_disabled, cfg.supply_pool_opt_in)
        }
        Err(_) => (st.config.cloud_agent_disabled, st.config.supply_pool_opt_in),
    };
    // "enabled" is the derived intent surface the UI toggles on: linked AND not explicitly disabled.
    let enabled = linked && !disabled;

    // Non-secret gateway-assigned agent_id (routing metadata; absent until the agent has connected).
    let agent_id = config_kv::get(&st.db, LINKED_AGENT_ID_KEY)
        .await
        .ok()
        .flatten()
        .filter(|s| !s.is_empty());

    // Live manager snapshot (zeros if not installed, e.g. tests). The `.await` reads LinkState +
    // config to compute `blocking_reason` — a gate-read failure fails safe to `None` in there.
    let snap = match manager::global() {
        Some(m) => Some(m.snapshot().await),
        None => None,
    };
    let (desired_running, online, last_error, blocking_reason) = match snap {
        Some(s) => (s.desired_running, s.online, s.last_error, s.blocking_reason),
        None => (false, false, None, None),
    };

    // Capabilities the agent advertises. `supply_pool` widens this server-side; the agent-side list is
    // reflection only (identity/isolation/billing stay server-side).
    let mut capabilities = vec!["local_workflows", "execute_workflow", "execute_ai_task"];
    if supply_pool {
        capabilities.push("supply_pool");
    }

    Ok(json!({
        "linked": linked,
        "enabled": enabled,
        "disabled": disabled,
        "supply_pool": supply_pool,
        "desired_running": desired_running,
        "online": online,
        "agent_id": agent_id,
        "capabilities": capabilities,
        "last_error": last_error,
        // Stable token (unlinked / disabled / no_channel_key) naming the precondition currently
        // blocking the agent — surfaced so the UI can explain a "linked but Offline" state
        // instead of a silent Offline. Absent when all gates pass.
        "blocking_reason": blocking_reason,
    }))
}

/// `GET /v1/cloud/agent/status` — the live, NON-SECRET agent status. Works while unlinked (reports
/// `linked: false`). NEVER returns token/channel-key material.
async fn status(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    Ok(Json(build_status(&st).await?))
}

/// `POST /v1/cloud/agent/enable` — clear the persisted disable OFF-switch (so the agent is on when
/// linked), persist it to `config.toml`, and start the process-global manager. Requires a cloud link.
/// The supply-pool opt-in is preserved as-is (a separate toggle). Returns the status snapshot.
async fn enable(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    require_linked(&st).await?;

    // Persist enabled=true (disable flag off), preserving the current supply-pool opt-in.
    let paths = config::Paths::resolve()?;
    let supply_pool = config::load_config(&paths).supply_pool_opt_in;
    config::set_cloud_agent(&paths, true, supply_pool)?;

    if let Some(mgr) = manager::global() {
        let _ = mgr.start().await; // honors linked/keyed preconditions internally (no-op if unmet)
    }
    tracing::info!("cloud execution agent enabled");
    Ok(Json(build_status(&st).await?))
}

/// `POST /v1/cloud/agent/disable` — set the persisted disable OFF-switch, persist it to `config.toml`,
/// and stop the process-global manager (tears the live gateway WS down). Requires a cloud link (the
/// off-switch is meaningless without a link, and the manager gate is linked-only anyway).
async fn disable(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    require_linked(&st).await?;

    let paths = config::Paths::resolve()?;
    let supply_pool = config::load_config(&paths).supply_pool_opt_in;
    config::set_cloud_agent(&paths, false, supply_pool)?;

    if let Some(mgr) = manager::global() {
        mgr.stop();
    }
    tracing::info!("cloud execution agent disabled");
    Ok(Json(build_status(&st).await?))
}

/// `GET /v1/cloud/agent/runs` — the cloud-dispatched runs this device is serving RIGHT NOW.
///
/// Sourced from the `runs` table (`trigger_type='cloud'` and a live status), NOT from the
/// process-global `task_id → run_id` map. The map cannot answer this: its only production writer
/// (`cloud::agent::workflow`) calls `bind` on the line after `engine.run_recipe(..).await` returns —
/// i.e. once the run has already TERMINATED — and `unbind`s immediately after, so it is never
/// non-empty for any observable interval and this endpoint always returned `{ runs: [] }`. The `runs`
/// row is the real liveness record: inserted before the run starts, finalized when it ends, and
/// stamped `trigger_type='cloud'` for `RunSource::CloudAgent` (see `engine::real::trigger_type_for`).
///
/// The map remains the right structure for `cancel_task` (task_id → run_id routing) and is still
/// consulted here, best-effort, to attach a `task_id` when one happens to be bound. A null `task_id`
/// is expected and fine: the UI cancels by `run_id` via `POST /v1/runs/{run_id}/cancel`.
///
/// Returns `{ runs: [ { run_id, task_id, source, workflow_name, workflow_id, origin, status,
/// trigger_type, started_at, duration_ms } ] }`. Read-only; works while unlinked (nothing is live, so
/// `{ runs: [] }`). NEVER any credential/recipe/token content — `workflow_name` is the recipe's
/// display name, which the engine records in `trigger_context.recipe_name`.
async fn agent_runs(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    let live = runs::list_live_by_trigger_type(&st.db, "cloud", 100).await?;

    let out: Vec<Value> = live
        .iter()
        .map(|run| {
            // An ad-hoc cloud recipe has no `workflows` row (workflow_id is NULL), so its display
            // name can only come from the trigger_context the engine stamped at insert.
            let ctx: Option<Value> = run
                .trigger_context
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok());
            let workflow_name = ctx
                .as_ref()
                .and_then(|c| c.get("recipe_name"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or("Cloud workflow")
                .to_string();

            json!({
                "run_id": run.id,
                "task_id": task_id_for_run(run.id),
                "source": "cloud",
                "workflow_name": workflow_name,
                "workflow_id": run.workflow_id,
                // Who called it on the cloud side is the backend's to know; the dispatch frame
                // doesn't carry it, so report null rather than invent an attribution.
                "origin": Value::Null,
                "status": run.status,
                "trigger_type": run.trigger_type,
                "started_at": run.started_at,
                "duration_ms": run.duration_ms,
            })
        })
        .collect();

    Ok(Json(json!({ "runs": out })))
}

/// Reverse-lookup the cloud `task_id` currently bound to `run_id`, if any. Best-effort: the
/// correlation map is keyed task_id → run_id, so this scans the (tiny — live cloud runs only) live
/// set. Returns JSON null when unbound, which is the common case today.
fn task_id_for_run(run_id: i64) -> Value {
    let pairs = match manager::global() {
        Some(mgr) => mgr.live_runs(),
        None => crate::local::cloud::agent::runs::live_pairs(),
    };
    pairs
        .into_iter()
        .find(|(_, rid)| *rid == run_id)
        .map(|(task_id, _)| Value::String(task_id))
        .unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::server::build_router;
    use crate::local::{config::LocalConfig, db, engine, vault};
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use std::sync::Arc;
    use tower::ServiceExt;

    const TOKEN: &str = "wlt_test_cloud_agent";

    async fn test_state() -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::local::config::Paths::at(dir.path().join(".writ"));
        paths.ensure_dirs().unwrap();
        let v = vault::Vault::load_or_create(&paths.root, false).unwrap();
        let pool = db::open(&paths.db(), &v.db_key_hex()).await.unwrap();
        let st = AppState {
            db: pool,
            vault: Arc::new(v),
            engine: Arc::new(engine::StubEngine),
            config: LocalConfig::default(),
            token: Arc::new(TOKEN.to_string()),
            health: crate::local::app::health::DaemonHealth::shared(),
            recorder: None,
        };
        (dir, st)
    }

    async fn call(st: &AppState, method: &str, uri: &str) -> (u16, Value) {
        let resp = build_router(st.clone())
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("authorization", format!("Bearer {TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let body: Value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        (status, body)
    }

    #[tokio::test]
    async fn status_unlinked_reports_not_linked_never_500() {
        let (_dir, st) = test_state().await;
        let (code, body) = call(&st, "GET", "/v1/cloud/agent/status").await;
        assert_eq!(code, 200, "body={body}");
        assert_eq!(body["linked"], json!(false));
        assert_eq!(body["enabled"], json!(false), "unlinked ⇒ not enabled");
        assert_eq!(body["online"], json!(false));
        assert!(body["capabilities"].is_array());
        assert!(body["agent_id"].is_null());
        // No secret material may ever leak.
        let raw = body.to_string();
        assert!(
            !raw.contains("wto_") && !raw.contains("wtr_") && !raw.contains("channel_key"),
            "no secret leak: {raw}"
        );
    }

    #[tokio::test]
    async fn runs_returns_empty_shape_when_idle() {
        let (_dir, st) = test_state().await;
        let (code, body) = call(&st, "GET", "/v1/cloud/agent/runs").await;
        assert_eq!(code, 200, "body={body}");
        assert!(body["runs"].is_array(), "runs is always an array");
        // No live cloud runs bound in this test process for these ids → the shape is present.
        assert!(body.get("runs").is_some());
    }

    /// Insert a `runs` row directly, as the engine does at the start of a run.
    /// `runs::insert` stamps `status='running'`, so a fresh row is live by construction.
    async fn insert_run(st: &AppState, trigger_type: &str, recipe_name: Option<&str>) -> i64 {
        let trigger_context = recipe_name
            .map(|n| serde_json::json!({ "source": "cloud_agent", "recipe_name": n }).to_string());
        runs::insert(
            &st.db,
            &runs::NewRun {
                workflow_id: None,
                trigger_type: Some(trigger_type.to_string()),
                trigger_context,
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .id
    }

    /// The regression test for the bug this endpoint shipped with: it built its list from the
    /// process-global task_id → run_id map, whose only production writer binds AFTER the run has
    /// already terminated and unbinds on the next line — so the map was never non-empty and this
    /// route always returned `{ runs: [] }`, no matter how many cloud runs were in flight. The feed
    /// is now sourced from the `runs` row, which is live for the whole run.
    #[tokio::test]
    async fn runs_lists_live_cloud_runs_from_the_runs_table() {
        let (_dir, st) = test_state().await;
        let run_id = insert_run(&st, "cloud", Some("Nightly price sync")).await;

        let (code, body) = call(&st, "GET", "/v1/cloud/agent/runs").await;
        assert_eq!(code, 200, "body={body}");
        let listed = body["runs"].as_array().unwrap();
        assert_eq!(listed.len(), 1, "the live cloud run must be listed: {body}");

        let run = &listed[0];
        assert_eq!(run["run_id"].as_i64(), Some(run_id));
        assert_eq!(run["source"], "cloud");
        assert_eq!(run["status"], "running");
        assert_eq!(run["trigger_type"], "cloud");
        // The display name comes from trigger_context.recipe_name — an ad-hoc cloud recipe has no
        // workflows row to join a name from.
        assert_eq!(run["workflow_name"], "Nightly price sync");
        // Nothing bound this run in the correlation map, which is the normal case.
        assert!(run["task_id"].is_null(), "unbound task_id reports null: {run}");
    }

    /// Only CLOUD-dispatched runs belong in this feed, and only while they're live.
    #[tokio::test]
    async fn runs_excludes_non_cloud_and_finished_runs() {
        let (_dir, st) = test_state().await;
        // A live LOCAL run — right status, wrong trigger_type.
        insert_run(&st, "manual", Some("Local thing")).await;
        // A cloud run that has already finished — right trigger_type, no longer live.
        let done = insert_run(&st, "cloud", Some("Finished cloud run")).await;
        runs::set_status(&st.db, done, "success").await.unwrap();

        let (code, body) = call(&st, "GET", "/v1/cloud/agent/runs").await;
        assert_eq!(code, 200, "body={body}");
        assert!(
            body["runs"].as_array().unwrap().is_empty(),
            "neither a local run nor a finished cloud run is a live cloud run: {body}"
        );
    }

    /// A cloud run whose dispatch carried no name still gets a display label rather than an empty
    /// string (the engine defaults the recipe name, but the row may predate that).
    #[tokio::test]
    async fn runs_falls_back_to_a_label_when_no_recipe_name() {
        let (_dir, st) = test_state().await;
        insert_run(&st, "cloud", None).await;
        let (_code, body) = call(&st, "GET", "/v1/cloud/agent/runs").await;
        assert_eq!(body["runs"][0]["workflow_name"], "Cloud workflow");
    }

    #[tokio::test]
    async fn enable_disable_require_cloud_link() {
        // Both write routes are gated on a cloud link → 401 when unlinked.
        let (_dir, st) = test_state().await;
        for (method, uri) in [
            ("POST", "/v1/cloud/agent/enable"),
            ("POST", "/v1/cloud/agent/disable"),
        ] {
            let (code, _body) = call(&st, method, uri).await;
            assert_eq!(code, 401, "{method} {uri} must require a cloud link when unlinked");
        }
    }

    #[tokio::test]
    async fn read_routes_work_unlinked() {
        // status + runs are read-only and must NOT require a link.
        let (_dir, st) = test_state().await;
        let (code, _) = call(&st, "GET", "/v1/cloud/agent/status").await;
        assert_eq!(code, 200);
        let (code, _) = call(&st, "GET", "/v1/cloud/agent/runs").await;
        assert_eq!(code, 200);
    }

    #[tokio::test]
    async fn routes_require_the_loopback_bearer() {
        let (_dir, st) = test_state().await;
        for uri in ["/v1/cloud/agent/status", "/v1/cloud/agent/runs"] {
            let resp = build_router(st.clone())
                .oneshot(Request::builder().method("GET").uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status().as_u16(), 401, "{uri}: no bearer → 401 before the handler");
        }
    }
}
