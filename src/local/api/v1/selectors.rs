//! `/v1/monitors/:id/selectors` REST handlers — multi-selector content monitoring under a target.
//!
//! A content monitor is checked against its `target_selectors` rows (text / html / visual). Without
//! these routes a wizard-created monitor has ZERO selectors and is checked against nothing, so this is
//! what makes content monitoring actually work. House style mirrors `monitors.rs`: thin handlers over
//! `store::target_selectors`, `LocalResult<Json<_>>` with `?`, no auth layer here (server.rs applies
//! the loopback bearer at the router level). Every selector-scoped route verifies the selector belongs
//! to the path's target, so a valid id under the wrong monitor is a 404 (no cross-target probing).
//!
//! `test` / `set-baseline` / `set-all-baselines` perform a LIVE one-off fetch through the shared
//! checker (see `crate::local::monitor`) — they are explicit user actions and skip the scheduler's
//! anti-detection floor.

use crate::local::error::{LocalError, LocalResult};
use crate::local::monitor::{BaselineSummary, SelectorProbe};
use crate::local::server::AppState;
use crate::local::store::target_selectors::{
    self, NewTargetSelector, TargetSelector, TargetSelectorUpdate,
};
use crate::local::store::targets;
use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

/// Hard cap on a target's selector list (matches the resource list caps elsewhere).
const MAX_SELECTORS: i64 = 500;

/// Routes for this resource, mounted under the shared `/v1` namespace by the parent router.
///
/// NOTE: the target segment is `:id` to match `monitors.rs` (matchit rejects a differently-named
/// param at the same position once the routers are merged). matchit 0.7 also rejects a STATIC segment
/// as a sibling of a `:param` segment, so the wizard's `POST .../selectors/set-all-baselines` cannot be
/// its own static route next to `:selector_id` — instead the leaf `POST` handler ([`post_selector`])
/// dispatches the `set-all-baselines` sentinel. The deeper `/toggle` etc. routes are static children of
/// the `:selector_id` param (no sibling conflict).
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/monitors/:id/selectors", get(list).post(create))
        .route(
            "/v1/monitors/:id/selectors/:selector_id",
            get(get_one).patch(update).delete(delete).post(post_selector),
        )
        .route("/v1/monitors/:id/selectors/:selector_id/toggle", post(toggle))
        .route("/v1/monitors/:id/selectors/:selector_id/test", post(test))
        .route(
            "/v1/monitors/:id/selectors/:selector_id/set-baseline",
            post(set_baseline),
        )
        .route(
            "/v1/monitors/:id/selectors/:selector_id/clear-baseline",
            post(clear_baseline),
        )
}

/// `?enabled_only=true|false` — the recorder/edit surfaces ask for the full set; the check-loop wants
/// only enabled ones.
#[derive(Debug, Default, Deserialize)]
struct ListQuery {
    #[serde(default)]
    enabled_only: Option<bool>,
}

/// Create body. `target_id` comes from the PATH, not the body. `enabled` accepts the JSON-natural
/// bool the wizard sends; `visual_region` accepts an object (stored as JSON-TEXT).
#[derive(Debug, Deserialize)]
struct CreateSelectorBody {
    #[serde(default)]
    name: String,
    #[serde(default)]
    selector: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default, deserialize_with = "targets::de_opt_bool_int")]
    enabled: Option<i64>,
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default, deserialize_with = "targets::de_opt_json_text")]
    visual_region: Option<String>,
    #[serde(default)]
    ignore_regex: Option<String>,
    #[serde(default, deserialize_with = "targets::de_opt_int")]
    priority: Option<i64>,
}

/// Partial update; same flexible shapes as create, all optional.
#[derive(Debug, Default, Deserialize)]
struct UpdateSelectorBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    selector: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default, deserialize_with = "targets::de_opt_bool_int")]
    enabled: Option<i64>,
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default, deserialize_with = "targets::de_opt_json_text")]
    visual_region: Option<String>,
    #[serde(default)]
    ignore_regex: Option<String>,
    #[serde(default, deserialize_with = "targets::de_opt_int")]
    priority: Option<i64>,
}

/// 404 unless the target exists.
async fn ensure_target(st: &AppState, target_id: i64) -> LocalResult<()> {
    if targets::get_by_id(&st.db, target_id).await?.is_none() {
        return Err(LocalError::NotFound(format!("monitor {target_id}")));
    }
    Ok(())
}

/// Load a selector that MUST belong to `target_id`, else 404.
async fn ensure_owned(st: &AppState, target_id: i64, selector_id: i64) -> LocalResult<TargetSelector> {
    target_selectors::get_by_id(&st.db, selector_id)
        .await?
        .filter(|s| s.target_id == target_id)
        .ok_or_else(|| LocalError::NotFound(format!("selector {selector_id}")))
}

/// `GET /v1/monitors/:id/selectors` — a target's selectors (all, or enabled-only).
async fn list(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<ListQuery>,
) -> LocalResult<Json<Vec<TargetSelector>>> {
    ensure_target(&st, id).await?;
    let rows = if q.enabled_only.unwrap_or(false) {
        target_selectors::list_enabled_by_target(&st.db, id).await?
    } else {
        target_selectors::list_by_target(&st.db, id, MAX_SELECTORS).await?
    };
    Ok(Json(rows))
}

/// `POST /v1/monitors/:id/selectors` — add a selector to a target. Requires a non-empty `selector`;
/// `name` defaults to the selector string.
async fn create(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<CreateSelectorBody>,
) -> LocalResult<Json<TargetSelector>> {
    ensure_target(&st, id).await?;
    if body.selector.trim().is_empty() {
        return Err(LocalError::BadRequest("selector is required".into()));
    }
    // `UNIQUE(target_id, selector)` — pre-check so adding the same CSS selector twice gets a 409 that
    // says what happened, rather than the raw driver text behind a 500 (the personas and secrets
    // routes already pre-check; this one did not). The generic constraint mapping in `error.rs` is the
    // backstop for the check-then-insert race.
    if let Some(existing) =
        target_selectors::get_by_target_and_selector(&st.db, id, &body.selector).await?
    {
        return Err(LocalError::Conflict(format!(
            "this monitor already watches '{}' (selector {})",
            existing.selector, existing.id
        )));
    }
    let name = if body.name.trim().is_empty() {
        body.selector.clone()
    } else {
        body.name
    };
    let new = NewTargetSelector {
        target_id: id,
        name,
        selector: body.selector,
        description: body.description,
        enabled: body.enabled,
        content_type: body.content_type,
        visual_region: body.visual_region,
        ignore_regex: body.ignore_regex,
        priority: body.priority,
    };
    let sel_id = target_selectors::insert(&st.db, &new).await?;
    let row = target_selectors::get_by_id(&st.db, sel_id)
        .await?
        .ok_or_else(|| LocalError::Internal(format!("selector {sel_id} vanished after insert")))?;
    Ok(Json(row))
}

/// `GET /v1/monitors/:id/selectors/:selector_id` — one selector or 404.
async fn get_one(
    State(st): State<AppState>,
    Path((id, selector_id)): Path<(i64, i64)>,
) -> LocalResult<Json<TargetSelector>> {
    Ok(Json(ensure_owned(&st, id, selector_id).await?))
}

/// `PATCH /v1/monitors/:id/selectors/:selector_id` — partial update; returns the refreshed row.
async fn update(
    State(st): State<AppState>,
    Path((id, selector_id)): Path<(i64, i64)>,
    Json(body): Json<UpdateSelectorBody>,
) -> LocalResult<Json<TargetSelector>> {
    ensure_owned(&st, id, selector_id).await?;
    // A PATCH that RETARGETS the selector string can collide with a sibling on the same monitor
    // (`UNIQUE(target_id, selector)`) exactly like a create — same 409, same reason.
    if let Some(new_sel) = body.selector.as_deref() {
        if let Some(existing) =
            target_selectors::get_by_target_and_selector(&st.db, id, new_sel).await?
        {
            if existing.id != selector_id {
                return Err(LocalError::Conflict(format!(
                    "this monitor already watches '{new_sel}' (selector {})",
                    existing.id
                )));
            }
        }
    }
    let patch = TargetSelectorUpdate {
        name: body.name,
        selector: body.selector,
        description: body.description,
        enabled: body.enabled,
        content_type: body.content_type,
        visual_region: body.visual_region,
        ignore_regex: body.ignore_regex,
        priority: body.priority,
    };
    let row = target_selectors::update(&st.db, selector_id, &patch)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("selector {selector_id}")))?;
    Ok(Json(row))
}

/// `DELETE /v1/monitors/:id/selectors/:selector_id` — hard-delete (cascades to its extractors).
async fn delete(
    State(st): State<AppState>,
    Path((id, selector_id)): Path<(i64, i64)>,
) -> LocalResult<Json<Value>> {
    ensure_owned(&st, id, selector_id).await?;
    let n = target_selectors::delete(&st.db, selector_id).await?;
    Ok(Json(json!({ "deleted": n > 0, "selector_id": selector_id })))
}

/// `POST /v1/monitors/:id/selectors/:selector_id/toggle` — flip `enabled`.
async fn toggle(
    State(st): State<AppState>,
    Path((id, selector_id)): Path<(i64, i64)>,
) -> LocalResult<Json<Value>> {
    let sel = ensure_owned(&st, id, selector_id).await?;
    let enabled = sel.enabled == 0;
    target_selectors::set_enabled(&st.db, selector_id, enabled).await?;
    Ok(Json(json!({ "selector_id": selector_id, "enabled": enabled })))
}

/// `POST /v1/monitors/:id/selectors/:selector_id/test` — fetch the page NOW and report what this
/// selector resolves to, without persisting.
async fn test(
    State(st): State<AppState>,
    Path((id, selector_id)): Path<(i64, i64)>,
) -> LocalResult<Json<SelectorProbe>> {
    Ok(Json(crate::local::monitor::probe_selector(&st.db, id, selector_id).await?))
}

/// `POST /v1/monitors/:id/selectors/:selector_id/set-baseline` — capture this selector's baseline
/// from a fresh fetch.
async fn set_baseline(
    State(st): State<AppState>,
    Path((id, selector_id)): Path<(i64, i64)>,
) -> LocalResult<Json<SelectorProbe>> {
    Ok(Json(
        crate::local::monitor::capture_selector_baseline(&st.db, id, selector_id).await?,
    ))
}

/// `POST /v1/monitors/:id/selectors/:selector_id/clear-baseline` — drop the stored baseline so the
/// next check re-seeds it.
async fn clear_baseline(
    State(st): State<AppState>,
    Path((id, selector_id)): Path<(i64, i64)>,
) -> LocalResult<Json<Value>> {
    ensure_owned(&st, id, selector_id).await?;
    target_selectors::set_baseline(&st.db, selector_id, None, None, None).await?;
    Ok(Json(json!({ "selector_id": selector_id, "cleared": true })))
}

/// `POST /v1/monitors/:id/selectors/:selector_id` — dispatches the `set-all-baselines` sentinel (the
/// wizard's post-create step: capture baselines for ALL of a target's selectors in one fetch). Any
/// other value is a 404 — there is no plain `POST` on an individual selector.
async fn post_selector(
    State(st): State<AppState>,
    Path((id, selector_id)): Path<(i64, String)>,
) -> LocalResult<Json<BaselineSummary>> {
    if selector_id == "set-all-baselines" {
        return Ok(Json(crate::local::monitor::capture_all_baselines(&st.db, id).await?));
    }
    Err(LocalError::NotFound(format!("selector action {selector_id}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::store::targets::NewTarget;
    use crate::local::{db, engine, vault};
    use std::sync::Arc;

    /// A minimal AppState over a fresh encrypted DB (file-fallback vault, no keyring prompt).
    async fn state() -> AppState {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let v = vault::Vault::load_or_create(dir.path(), false).unwrap();
        let pool = db::open(&dir.path().join("t.db"), &v.db_key_hex()).await.unwrap();
        AppState {
            db: pool,
            vault: Arc::new(v),
            engine: Arc::new(engine::StubEngine),
            config: crate::local::config::LocalConfig::default(),
            token: Arc::new("wlt_test".into()),
            health: crate::local::app::health::DaemonHealth::shared(),
            recorder: None,
        }
    }

    async fn make_target(st: &AppState, url: &str) -> i64 {
        targets::insert(&st.db, &NewTarget { url: url.into(), ..Default::default() })
            .await
            .unwrap()
    }

    fn create_body(name: &str, selector: &str) -> CreateSelectorBody {
        // Round-trip through JSON so the flexible deserializers (bool `enabled`, object
        // `visual_region`) are exercised exactly as the wizard sends them.
        serde_json::from_value(json!({
            "name": name, "selector": selector, "content_type": "text", "enabled": true,
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn crud_round_trip() {
        let st = state().await;
        let tid = make_target(&st, "https://example.test").await;

        // Create.
        let Json(sel) = create(State(st.clone()), Path(tid), Json(create_body("Title", "h1")))
            .await
            .unwrap();
        assert_eq!(sel.target_id, tid);
        assert_eq!(sel.selector, "h1");
        assert_eq!(sel.enabled, 1);

        // List (all + enabled-only) sees it.
        let Json(all) = list(State(st.clone()), Path(tid), Query(ListQuery::default()))
            .await
            .unwrap();
        assert_eq!(all.len(), 1);
        let Json(en) = list(
            State(st.clone()),
            Path(tid),
            Query(ListQuery { enabled_only: Some(true) }),
        )
        .await
        .unwrap();
        assert_eq!(en.len(), 1);

        // Get.
        let Json(got) = get_one(State(st.clone()), Path((tid, sel.id))).await.unwrap();
        assert_eq!(got.id, sel.id);

        // Update the selector string.
        let body: UpdateSelectorBody =
            serde_json::from_value(json!({ "selector": "h2" })).unwrap();
        let Json(upd) = update(State(st.clone()), Path((tid, sel.id)), Json(body)).await.unwrap();
        assert_eq!(upd.selector, "h2");

        // Toggle off.
        let Json(tog) = toggle(State(st.clone()), Path((tid, sel.id))).await.unwrap();
        assert_eq!(tog["enabled"], json!(false));

        // Clear baseline is a no-op-safe store write.
        let _ = clear_baseline(State(st.clone()), Path((tid, sel.id))).await.unwrap();

        // Delete.
        let Json(del) = delete(State(st.clone()), Path((tid, sel.id))).await.unwrap();
        assert_eq!(del["deleted"], json!(true));
        let Json(after) = list(State(st), Path(tid), Query(ListQuery::default())).await.unwrap();
        assert!(after.is_empty());
    }

    #[tokio::test]
    async fn ownership_is_enforced() {
        let st = state().await;
        let a = make_target(&st, "https://a.test").await;
        let b = make_target(&st, "https://b.test").await;
        let Json(sel) = create(State(st.clone()), Path(a), Json(create_body("x", ".x")))
            .await
            .unwrap();

        // Reading selector `sel` under the WRONG target b → 404.
        let err = get_one(State(st.clone()), Path((b, sel.id))).await.unwrap_err();
        assert!(matches!(err, LocalError::NotFound(_)));
        // And updating it under b → 404 (no cross-target writes).
        let err = update(
            State(st.clone()),
            Path((b, sel.id)),
            Json(UpdateSelectorBody::default()),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, LocalError::NotFound(_)));
    }

    #[tokio::test]
    async fn create_requires_target_and_selector() {
        let st = state().await;
        // Missing target → 404.
        let err = create(State(st.clone()), Path(999_999), Json(create_body("x", ".x")))
            .await
            .unwrap_err();
        assert!(matches!(err, LocalError::NotFound(_)));
        // Empty selector → 400.
        let tid = make_target(&st, "https://example.test").await;
        let err = create(State(st), Path(tid), Json(create_body("x", "   ")))
            .await
            .unwrap_err();
        assert!(matches!(err, LocalError::BadRequest(_)));
    }

    #[tokio::test]
    async fn set_all_baselines_on_empty_target_is_noop() {
        let st = state().await;
        let tid = make_target(&st, "https://example.test").await;
        let Json(sum) =
            post_selector(State(st.clone()), Path((tid, "set-all-baselines".into()))).await.unwrap();
        assert_eq!(sum.selectors, 0);
        assert_eq!(sum.captured, 0);

        // A non-sentinel POST on the leaf is a 404.
        let err = post_selector(State(st), Path((tid, "99".into()))).await.unwrap_err();
        assert!(matches!(err, LocalError::NotFound(_)));
    }
}
