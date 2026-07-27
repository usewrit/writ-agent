//! `/v1/extractors` + `/v1/selectors/:selector_id/extractors` REST handlers — field extractors that
//! turn a selector's captured content into typed values (price / SKU / arrays) via one of five
//! `extract_type`s. House style mirrors `monitors.rs`: thin handlers over `store::selector_extractors`,
//! `LocalResult<Json<_>>` with `?`, no auth layer here (server.rs applies the loopback bearer).
//!
//! The `test` routes run the actual extraction engine ([`crate::monitor::extract`]) over caller-supplied
//! content, so the inline-extractor editor can preview a value before saving.

use crate::local::error::{LocalError, LocalResult};
use crate::local::server::AppState;
use crate::local::store::selector_extractors::{
    self, NewSelectorExtractor, SelectorExtractor, SelectorExtractorUpdate,
};
use crate::local::store::{target_selectors, targets};
use crate::monitor::extract::run_extractor;
use axum::extract::{Path, Query, State};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

/// Routes for this resource, mounted under the shared `/v1` namespace by the parent router.
///
/// matchit 0.7 rejects a STATIC segment as a sibling of a `:param` segment, so the ad-hoc
/// `POST /v1/extractors/test-content` cannot be its own static route next to `:extractor_id` — the
/// leaf `POST` handler ([`post_extractor`]) dispatches the `test-content` sentinel. `/extractors`
/// (exact) and `/extractors/:extractor_id` (param child) do NOT conflict.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/selectors/:selector_id/extractors", get(list))
        .route("/v1/extractors", post(create))
        .route(
            "/v1/extractors/:extractor_id",
            get(get_one).patch(update).delete(delete).post(post_extractor),
        )
        .route("/v1/extractors/:extractor_id/toggle", patch(toggle))
        .route("/v1/extractors/:extractor_id/test", post(test))
}

#[derive(Debug, Default, Deserialize)]
struct ListQuery {
    #[serde(default)]
    enabled_only: Option<bool>,
}

/// Create body. `enabled`/`is_array` accept JSON bools; `config` accepts an object (stored as JSON-TEXT).
#[derive(Debug, Deserialize)]
struct CreateExtractorBody {
    target_selector_id: i64,
    #[serde(default)]
    name: String,
    #[serde(default)]
    output_name: String,
    #[serde(default, deserialize_with = "targets::de_opt_bool_int")]
    enabled: Option<i64>,
    #[serde(default)]
    extract_type: Option<String>,
    #[serde(default, deserialize_with = "targets::de_opt_json_text")]
    config: Option<String>,
    #[serde(default, deserialize_with = "targets::de_opt_bool_int")]
    is_array: Option<i64>,
    #[serde(default)]
    default_value: Option<String>,
}

/// Partial update; same flexible shapes as create, all optional.
#[derive(Debug, Default, Deserialize)]
struct UpdateExtractorBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    output_name: Option<String>,
    #[serde(default, deserialize_with = "targets::de_opt_bool_int")]
    enabled: Option<i64>,
    #[serde(default)]
    extract_type: Option<String>,
    #[serde(default, deserialize_with = "targets::de_opt_json_text")]
    config: Option<String>,
    #[serde(default, deserialize_with = "targets::de_opt_bool_int")]
    is_array: Option<i64>,
    #[serde(default)]
    default_value: Option<String>,
}

/// `POST /v1/extractors/:id/test` body — content to run the SAVED extractor against.
#[derive(Debug, Default, Deserialize)]
struct TestBody {
    #[serde(default)]
    content: String,
    #[serde(default)]
    content_type: Option<String>,
}

/// `POST /v1/extractors/test-content` query — an AD-HOC extraction (no saved row). `config` is a JSON
/// string (e.g. `config={"selector":"h1"}`); a non-string/object value is treated as empty config.
/// Every field is optional so a non-sentinel `POST` on the leaf path falls through to a clean 404
/// rather than a query-decode 422.
#[derive(Debug, Default, Deserialize)]
struct TestContentQuery {
    #[serde(default)]
    content: String,
    #[serde(default)]
    #[allow(dead_code)]
    content_type: Option<String>,
    #[serde(default)]
    extract_type: Option<String>,
    #[serde(default)]
    config: Option<String>,
    #[serde(default)]
    is_array: Option<bool>,
}

/// Parse a stored/sent JSON-TEXT config into a `Value`, defaulting to `{}` on absence/parse error.
fn parse_config(raw: Option<&str>) -> Value {
    raw.and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_else(|| json!({}))
}

/// Load an extractor by id or 404.
async fn load_extractor(st: &AppState, id: i64) -> LocalResult<SelectorExtractor> {
    selector_extractors::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("extractor {id}")))
}

/// `GET /v1/selectors/:selector_id/extractors` — a selector's extractors (all, or enabled-only).
async fn list(
    State(st): State<AppState>,
    Path(selector_id): Path<i64>,
    Query(q): Query<ListQuery>,
) -> LocalResult<Json<Vec<SelectorExtractor>>> {
    if target_selectors::get_by_id(&st.db, selector_id).await?.is_none() {
        return Err(LocalError::NotFound(format!("selector {selector_id}")));
    }
    let rows = if q.enabled_only.unwrap_or(false) {
        selector_extractors::list_enabled_by_selector(&st.db, selector_id).await?
    } else {
        selector_extractors::list_by_selector(&st.db, selector_id).await?
    };
    Ok(Json(rows))
}

/// `POST /v1/extractors` — create an extractor under an existing selector. Requires a non-empty
/// `output_name` (the result key); `name` defaults to it.
async fn create(
    State(st): State<AppState>,
    Json(body): Json<CreateExtractorBody>,
) -> LocalResult<Json<SelectorExtractor>> {
    if target_selectors::get_by_id(&st.db, body.target_selector_id).await?.is_none() {
        return Err(LocalError::NotFound(format!("selector {}", body.target_selector_id)));
    }
    if body.output_name.trim().is_empty() {
        return Err(LocalError::BadRequest("output_name is required".into()));
    }
    let name = if body.name.trim().is_empty() {
        body.output_name.clone()
    } else {
        body.name
    };
    let new = NewSelectorExtractor {
        target_selector_id: body.target_selector_id,
        name,
        output_name: body.output_name,
        enabled: body.enabled,
        extract_type: body.extract_type,
        config: body.config,
        is_array: body.is_array,
        default_value: body.default_value,
    };
    let id = selector_extractors::insert(&st.db, &new).await?;
    let row = load_extractor(&st, id).await?;
    Ok(Json(row))
}

/// `GET /v1/extractors/:extractor_id` — one extractor or 404.
async fn get_one(
    State(st): State<AppState>,
    Path(extractor_id): Path<i64>,
) -> LocalResult<Json<SelectorExtractor>> {
    Ok(Json(load_extractor(&st, extractor_id).await?))
}

/// `PATCH /v1/extractors/:extractor_id` — partial update; returns the refreshed row.
async fn update(
    State(st): State<AppState>,
    Path(extractor_id): Path<i64>,
    Json(body): Json<UpdateExtractorBody>,
) -> LocalResult<Json<SelectorExtractor>> {
    let patch = SelectorExtractorUpdate {
        name: body.name,
        output_name: body.output_name,
        enabled: body.enabled,
        extract_type: body.extract_type,
        config: body.config,
        is_array: body.is_array,
        default_value: body.default_value,
    };
    let row = selector_extractors::update(&st.db, extractor_id, &patch)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("extractor {extractor_id}")))?;
    Ok(Json(row))
}

/// `DELETE /v1/extractors/:extractor_id` — hard-delete.
async fn delete(
    State(st): State<AppState>,
    Path(extractor_id): Path<i64>,
) -> LocalResult<Json<Value>> {
    let n = selector_extractors::delete(&st.db, extractor_id).await?;
    if n == 0 {
        return Err(LocalError::NotFound(format!("extractor {extractor_id}")));
    }
    Ok(Json(json!({ "deleted": true, "extractor_id": extractor_id })))
}

/// `PATCH /v1/extractors/:extractor_id/toggle` — flip `enabled`; returns the refreshed row.
async fn toggle(
    State(st): State<AppState>,
    Path(extractor_id): Path<i64>,
) -> LocalResult<Json<SelectorExtractor>> {
    let ex = load_extractor(&st, extractor_id).await?;
    selector_extractors::set_enabled(&st.db, extractor_id, ex.enabled == 0).await?;
    Ok(Json(load_extractor(&st, extractor_id).await?))
}

/// `POST /v1/extractors/:extractor_id/test` — run the SAVED extractor over caller-supplied content.
async fn test(
    State(st): State<AppState>,
    Path(extractor_id): Path<i64>,
    Json(body): Json<TestBody>,
) -> LocalResult<Json<Value>> {
    let ex = load_extractor(&st, extractor_id).await?;
    let config = parse_config(ex.config.as_deref());
    let value = run_extractor(
        &body.content,
        &ex.extract_type,
        &config,
        ex.is_array != 0,
        ex.default_value.as_deref(),
    );
    let _ = body.content_type; // accepted for API parity; the engine keys off extract_type.
    Ok(Json(json!({
        "extractor_id": ex.id,
        "output_name": ex.output_name,
        "value": value,
    })))
}

/// `POST /v1/extractors/:extractor_id` — dispatches the `test-content` sentinel: an ad-hoc extraction
/// with no saved row (inline preview). Any other value is a 404 — there is no plain `POST` on an
/// individual extractor.
async fn post_extractor(
    State(_st): State<AppState>,
    Path(extractor_id): Path<String>,
    Query(q): Query<TestContentQuery>,
) -> LocalResult<Json<Value>> {
    if extractor_id != "test-content" {
        return Err(LocalError::NotFound(format!("extractor action {extractor_id}")));
    }
    let extract_type = q
        .extract_type
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| LocalError::BadRequest("extract_type is required".into()))?;
    let config = parse_config(q.config.as_deref());
    let value = run_extractor(&q.content, extract_type, &config, q.is_array.unwrap_or(false), None);
    Ok(Json(json!({ "value": value })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::store::target_selectors::NewTargetSelector;
    use crate::local::store::targets::NewTarget;
    use crate::local::{db, engine, vault};
    use std::sync::Arc;

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

    /// Create a target + selector and return the selector id to hang extractors off.
    async fn make_selector(st: &AppState) -> i64 {
        let tid = targets::insert(&st.db, &NewTarget { url: "https://example.test".into(), ..Default::default() })
            .await
            .unwrap();
        target_selectors::insert(
            &st.db,
            &NewTargetSelector { target_id: tid, name: "price".into(), selector: ".price".into(), ..Default::default() },
        )
        .await
        .unwrap()
    }

    fn create_body(selector_id: i64) -> CreateExtractorBody {
        // Exercise the flexible deserializers (bool enabled/is_array, object config) as the UI sends them.
        serde_json::from_value(json!({
            "target_selector_id": selector_id,
            "name": "Price",
            "output_name": "price",
            "enabled": true,
            "extract_type": "regex",
            "config": { "pattern": r"\$([0-9.]+)" },
            "is_array": false,
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn crud_and_test_round_trip() {
        let st = state().await;
        let sid = make_selector(&st).await;

        // Create.
        let Json(ex) = create(State(st.clone()), Json(create_body(sid))).await.unwrap();
        assert_eq!(ex.target_selector_id, sid);
        assert_eq!(ex.extract_type, "regex");
        assert_eq!(ex.enabled, 1);

        // List under the selector.
        let Json(rows) = list(State(st.clone()), Path(sid), Query(ListQuery::default())).await.unwrap();
        assert_eq!(rows.len(), 1);

        // Get.
        let Json(got) = get_one(State(st.clone()), Path(ex.id)).await.unwrap();
        assert_eq!(got.output_name, "price");

        // Test the SAVED extractor's regex over content.
        let Json(res) = test(
            State(st.clone()),
            Path(ex.id),
            Json(TestBody { content: "Now only $12.50!".into(), content_type: None }),
        )
        .await
        .unwrap();
        assert_eq!(res["value"], json!("12.50"));
        assert_eq!(res["output_name"], json!("price"));

        // Toggle off.
        let Json(tog) = toggle(State(st.clone()), Path(ex.id)).await.unwrap();
        assert_eq!(tog.enabled, 0);

        // Delete.
        let Json(del) = delete(State(st.clone()), Path(ex.id)).await.unwrap();
        assert_eq!(del["deleted"], json!(true));
        let err = get_one(State(st), Path(ex.id)).await.unwrap_err();
        assert!(matches!(err, LocalError::NotFound(_)));
    }

    #[tokio::test]
    async fn create_requires_existing_selector_and_output_name() {
        let st = state().await;
        // Unknown selector → 404.
        let err = create(State(st.clone()), Json(create_body(999_999))).await.unwrap_err();
        assert!(matches!(err, LocalError::NotFound(_)));
        // Missing output_name → 400.
        let sid = make_selector(&st).await;
        let body: CreateExtractorBody = serde_json::from_value(json!({
            "target_selector_id": sid, "output_name": "  ", "extract_type": "text",
        }))
        .unwrap();
        let err = create(State(st), Json(body)).await.unwrap_err();
        assert!(matches!(err, LocalError::BadRequest(_)));
    }

    #[tokio::test]
    async fn ad_hoc_test_content_runs_engine() {
        let st = state().await;
        let Json(res) = post_extractor(
            State(st.clone()),
            Path("test-content".into()),
            Query(TestContentQuery {
                content: r#"<a data-id="99">x</a>"#.into(),
                content_type: None,
                extract_type: Some("css".into()),
                config: Some(r#"{"selector":"a","attribute":"data-id"}"#.into()),
                is_array: Some(false),
            }),
        )
        .await
        .unwrap();
        assert_eq!(res["value"], json!("99"));

        // A non-sentinel POST on the leaf is a 404.
        let err = post_extractor(State(st), Path("123".into()), Query(TestContentQuery::default()))
            .await
            .unwrap_err();
        assert!(matches!(err, LocalError::NotFound(_)));
    }
}
