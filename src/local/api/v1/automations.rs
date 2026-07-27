//! `/v1/automations` REST handlers — CRUD over the `automations` table (event→action rules) plus an
//! enable/disable toggle. House style: thin handlers over `store::automations`,
//! `LocalResult<Json<_>>` with `?` propagation, no auth layer here (server.rs applies the loopback
//! bearer middleware at the router level).

use crate::local::engine::{Lane, RunSource};
use crate::local::error::{LocalError, LocalResult};
use crate::local::flow;
use crate::local::server::AppState;
use crate::local::store::automations::{self, Automation, AutomationPatch, NewAutomation};
use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

/// Default page size for the list endpoint when `?limit=` is omitted.
const DEFAULT_LIMIT: i64 = 100;
/// Hard cap so a client cannot ask for an unbounded scan.
const MAX_LIMIT: i64 = 500;

#[derive(Debug, Default, Deserialize)]
struct ListQuery {
    limit: Option<i64>,
}

impl ListQuery {
    /// Clamp the requested limit into `1..=MAX_LIMIT`, defaulting when unset.
    fn limit(&self) -> i64 {
        self.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
    }
}

/// Body for `POST /v1/automations/:id/enable` — `{"enabled": true|false}`. Defaults to enabling.
#[derive(Debug, Deserialize)]
struct EnableBody {
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_true() -> bool {
    true
}

/// Body for `POST /v1/automations/:id/run` — optional `{"inputs": {...}}` handed to the flow's
/// workflow actions. Absent/empty ⇒ `{}`.
#[derive(Debug, Default, Deserialize)]
struct RunBody {
    #[serde(default)]
    inputs: Option<Value>,
}

/// Routes for this resource, mounted under the shared `/v1` namespace by the parent router.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/automations", get(list).post(create))
        .route(
            "/v1/automations/:id",
            get(get_one).patch(update).delete(delete),
        )
        .route("/v1/automations/:id/enable", post(enable))
        .route("/v1/automations/:id/run", post(run_now))
}

/// Serialize an [`Automation`] for the HTTP response with its JSON-TEXT columns PARSED — `blocks`
/// (→ array | null), `actions` (→ array), `conditions` (→ object) — so the API contract matches the
/// cloud (which returns parsed JSON). Without this the UI receives raw strings and call sites like
/// `blocks.find(...)` throw "not a function". Parse failures degrade to sensible empties.
fn automation_response(a: &Automation) -> Value {
    let mut v = serde_json::to_value(a).unwrap_or_else(|_| json!({}));
    if let Some(obj) = v.as_object_mut() {
        // Clone the string columns out first to avoid a borrow conflict with the inserts below.
        let conditions = obj.get("conditions").and_then(|x| x.as_str()).map(String::from);
        let actions = obj.get("actions").and_then(|x| x.as_str()).map(String::from);
        let blocks = obj.get("blocks").and_then(|x| x.as_str()).map(String::from);
        if let Some(s) = conditions {
            obj.insert("conditions".into(), serde_json::from_str(&s).unwrap_or_else(|_| json!({})));
        }
        if let Some(s) = actions {
            obj.insert("actions".into(), serde_json::from_str(&s).unwrap_or_else(|_| json!([])));
        }
        if let Some(s) = blocks {
            obj.insert("blocks".into(), serde_json::from_str(&s).unwrap_or(Value::Null));
        }
    }
    v
}

/// `GET /v1/automations` — newest-first list, capped by `?limit`.
async fn list(
    State(st): State<AppState>,
    Query(q): Query<ListQuery>,
) -> LocalResult<Json<Value>> {
    let rows = automations::list(&st.db, q.limit()).await?;
    Ok(Json(Value::Array(rows.iter().map(automation_response).collect())))
}

/// `POST /v1/automations` — create an automation. Requires a non-empty `name`; schema defaults fill
/// `event_type`/`enabled`/`conditions`/`actions`.
async fn create(
    State(st): State<AppState>,
    Json(body): Json<NewAutomation>,
) -> LocalResult<Json<Value>> {
    if body.name.trim().is_empty() {
        return Err(LocalError::BadRequest("name is required".into()));
    }
    let row = automations::insert(&st.db, &body).await?;
    Ok(Json(automation_response(&row)))
}

/// `GET /v1/automations/:id` — one automation or 404.
async fn get_one(State(st): State<AppState>, Path(id): Path<i64>) -> LocalResult<Json<Value>> {
    let row = automations::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("automation {id}")))?;
    Ok(Json(automation_response(&row)))
}

/// `PATCH /v1/automations/:id` — partial update (COALESCE); returns the refreshed row or 404.
async fn update(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<AutomationPatch>,
) -> LocalResult<Json<Value>> {
    let row = automations::update(&st.db, id, &body)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("automation {id}")))?;
    Ok(Json(automation_response(&row)))
}

/// `DELETE /v1/automations/:id` — hard-delete (executions cascade via FK). 404 if absent.
async fn delete(
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> LocalResult<Json<serde_json::Value>> {
    let removed = automations::delete(&st.db, id).await?;
    if !removed {
        return Err(LocalError::NotFound(format!("automation {id}")));
    }
    Ok(Json(json!({ "deleted": true, "id": id })))
}

/// `POST /v1/automations/:id/enable` — toggle the `enabled` flag (body `{"enabled": bool}`, defaults
/// to true). Returns the refreshed row or 404.
async fn enable(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    body: Option<Json<EnableBody>>,
) -> LocalResult<Json<Value>> {
    // Tolerate an absent/empty body: default to enabling.
    let enabled = body.map(|Json(b)| b.enabled).unwrap_or(true);
    let updated = automations::set_enabled(&st.db, id, enabled).await?;
    if !updated {
        return Err(LocalError::NotFound(format!("automation {id}")));
    }
    let row = automations::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("automation {id}")))?;
    Ok(Json(automation_response(&row)))
}

/// `POST /v1/automations/:id/run` — fire the automation now (manual trigger). Walks its block tree
/// (conditions / branches / actions) via the flow interpreter and returns the execution outcome,
/// including any `return_data`. 404 if the automation does not exist.
async fn run_now(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    body: Option<Json<RunBody>>,
) -> LocalResult<Json<Value>> {
    let auto = automations::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("automation {id}")))?;

    let inputs = body.and_then(|Json(b)| b.inputs).unwrap_or_else(|| json!({}));
    let exec = flow::run_automation(
        &st.db,
        &st.engine,
        &auto,
        flow::FlowTrigger {
            event: "manual".to_string(),
            change_id: None,
            base_inputs: inputs.clone(),
            context: json!({ "event": "manual", "input": inputs }),
            source: RunSource::Manual,
            lane: Lane::Interactive,
        },
    )
    .await?;

    match exec {
        Some(e) => Ok(Json(json!({
            "execution_id": e.id,
            "status": e.status,
            "results": serde_json::from_str::<Value>(&e.action_results).unwrap_or(Value::Null),
            "error": e.error_message,
        }))),
        // A status-gated event (e.g. "on workflow error") has no triggering context on a manual run.
        None => Ok(Json(json!({ "status": "skipped", "reason": "trigger gate not matched" }))),
    }
}
