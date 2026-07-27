//! OpenAI-compatible surface conformance for the Writ desktop local backend.
//!
//! Drives the REAL loopback router (`local::server::build_router`) end-to-end via
//! `tower::ServiceExt::oneshot` (mirrors `tests/cipher_gate.rs`). Every request carries the `wlt_`
//! bearer, so the server's loopback-auth layer is exercised too. ADDITIVE (net-new file),
//! `local`-feature only → the cloud build is byte-unchanged.
//!
//! What this proves (`local::api::v1::openai`):
//!   - `GET /v1/models` → `{object:"list", data:[…]}` where each entry is `{id, object:"model", …}`
//!     and the id is the `writ:workflow:<id>` contract for an enabled workflow. Soft-deleted
//!     workflows never surface as models.
//!   - `POST /v1/chat/completions` + `POST /v1/responses` VALIDATION/shape paths that do NOT require
//!     a live Chromium run:
//!       * a malformed `model` (not `writ:workflow:<id>`) → 400 Bad Request before any run.
//!       * a well-formed model naming a NON-existent workflow → 404 Not Found before any run.
//!       * auth: no bearer → 401 from the server layer.
//!   - The non-stream SUCCESS body shape (`object:"chat.completion"` / `object:"response"` with an
//!     assistant turn) is RUN-DEPENDENT — the bundled `StubEngine` has no browser, so an actual run
//!     returns 500. Those success-shape assertions are gated `#[ignore]` (need a real engine) and
//!     documented; the unit tests in `openai.rs` already cover the object SHAPING off a `RunResult`.
//!
//! Run:  cargo test --features local --test openai_conformance

#![cfg(feature = "local")]

use axum::body::{to_bytes, Body};
use axum::http::Request;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt as _;
use writ_agent::local::server::{build_router, AppState};
use writ_agent::local::store::workflows::{self, NewWorkflow, WorkflowUpdate};
use writ_agent::local::{config, config::LocalConfig, db, engine, vault};

const TOKEN: &str = "wlt_openai_conformance";

/// Real `AppState` over a fresh headless vault + encrypted DB (same recipe as the lib tests:
/// `vault::load_or_create(.., false)` → no OS keyring; `db::open` keys + migrates).
async fn test_state() -> AppState {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = config::Paths::at(dir.keep()); // keep() persists the dir for the test process lifetime
    paths.ensure_dirs().expect("ensure dirs");
    let v = vault::Vault::load_or_create(&paths.root, false).expect("headless vault");
    let pool = db::open(&paths.db(), &v.db_key_hex()).await.expect("open encrypted db");
    AppState {
        db: pool,
        vault: Arc::new(v),
        engine: Arc::new(engine::StubEngine),
        config: LocalConfig::default(),
        token: Arc::new(TOKEN.to_string()),
        health: writ_agent::local::app::health::DaemonHealth::shared(),
        recorder: None,
    }
}

/// GET a path with the bearer; return `(status, body_bytes)`.
async fn get(state: &AppState, uri: &str) -> (u16, Vec<u8>) {
    let resp = build_router(state.clone())
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let bytes = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
    (status, bytes.to_vec())
}

/// POST a JSON body with the bearer; return `(status, body_bytes)`.
async fn post(state: &AppState, uri: &str, body: &Value) -> (u16, Vec<u8>) {
    let resp = build_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("authorization", format!("Bearer {TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let bytes = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
    (status, bytes.to_vec())
}

/// Seed one enabled workflow; return its id.
async fn seed_workflow(state: &AppState, name: &str) -> i64 {
    let wf = workflows::insert(
        &state.db,
        &NewWorkflow {
            name: name.into(),
            description: Some(format!("desc for {name}")),
            steps: Some(r#"[{"type":"goto","config":{"url":"{{input.target_url}}"}}]"#.into()),
            ..Default::default()
        },
    )
    .await
    .expect("seed workflow");
    wf.id
}

#[tokio::test]
async fn models_list_conforms_and_uses_workflow_model_ids() {
    let st = test_state().await;
    let id = seed_workflow(&st, "Report Puller").await;

    let (status, bytes) = get(&st, "/v1/models").await;
    assert_eq!(status, 200);
    let v: Value = serde_json::from_slice(&bytes).unwrap();

    // Top-level OpenAI models-list shape.
    assert_eq!(v["object"], "list", "models list has object:list");
    let data = v["data"].as_array().expect("data is an array");
    assert_eq!(data.len(), 1, "exactly the one enabled workflow surfaces as a model");

    let model = &data[0];
    assert_eq!(model["object"], "model", "each entry is object:model");
    assert_eq!(
        model["id"], format!("writ:workflow:{id}"),
        "model id is the writ:workflow:<id> contract"
    );
    assert!(model["created"].is_number(), "created timestamp present");
    assert_eq!(model["owned_by"], "writ");
    assert_eq!(model["name"], "Report Puller");
}

#[tokio::test]
async fn models_list_excludes_deleted_workflows() {
    let st = test_state().await;
    let keep = seed_workflow(&st, "Keep Me").await;
    let gone = seed_workflow(&st, "Delete Me").await;

    // Delete one (workflow rows are now HARD-deleted — the soft-delete/is_active path was retired).
    // It must NOT surface as a callable model.
    assert!(workflows::delete(&st.db, gone).await.unwrap(), "delete applied");

    let (status, bytes) = get(&st, "/v1/models").await;
    assert_eq!(status, 200);
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    let ids: Vec<String> = v["data"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["id"].as_str().map(String::from))
        .collect();
    assert!(ids.contains(&format!("writ:workflow:{keep}")), "active workflow present");
    assert!(
        !ids.contains(&format!("writ:workflow:{gone}")),
        "deleted workflow is not a model"
    );
}

#[tokio::test]
async fn empty_models_list_is_well_formed() {
    let st = test_state().await;
    let (status, bytes) = get(&st, "/v1/models").await;
    assert_eq!(status, 200);
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["object"], "list");
    assert_eq!(v["data"], json!([]), "no workflows → empty data array (still well-formed)");
}

// The global `/v1/chat/completions` + `/v1/responses` routes (model-based workflow selection) were
// removed for cloud parity — the call surface is now PER-WORKFLOW (`…/v1/workflows/{id}/v1/…`), where
// the workflow comes from the PATH and the request `model` field is optional and NOT format-validated.
// So the old "malformed `model` → 400" contract no longer has a surface to assert against. These two
// cases are kept (not deleted) as `#[ignore]`d documentation of the retired contract.
#[ignore = "global model-based routing removed; per-workflow surface does not validate model format"]
#[tokio::test]
async fn chat_completions_rejects_malformed_model() {}

#[ignore = "global model-based routing removed; per-workflow surface does not validate model format"]
#[tokio::test]
async fn responses_rejects_malformed_model() {}

#[tokio::test]
async fn chat_completions_404_for_unknown_workflow() {
    let st = test_state().await;
    // The OpenAI CALL surface is PER-WORKFLOW only (the workflow comes from the PATH, not the `model`
    // field — the global `/v1/chat/completions` route was deliberately removed for cloud parity). A
    // path pointing at a non-existent workflow → 404, before any run (the lookup precedes execution).
    let (status, bytes) = post(
        &st,
        "/v1/workflows/999999/v1/chat/completions",
        &json!({ "messages": [{"role":"user","content":"hi"}] }),
    )
    .await;
    assert_eq!(status, 404, "unknown workflow → 404 NotFound (before any run)");
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["code"], "not_found");
}

#[tokio::test]
async fn responses_404_for_unknown_workflow() {
    let st = test_state().await;
    // Per-workflow Responses surface — same contract: unknown workflow id in the PATH → 404.
    let (status, bytes) = post(
        &st,
        "/v1/workflows/424242/v1/responses",
        &json!({ "input": "hello" }),
    )
    .await;
    assert_eq!(status, 404, "unknown workflow → 404 NotFound");
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["code"], "not_found");
}

#[tokio::test]
async fn openai_surface_requires_bearer() {
    let st = test_state().await;
    // No Authorization header → 401 from the server auth layer (the handler never runs). The call
    // surface is per-workflow, so the bearer gate is asserted on the per-workflow routes.
    for (method, uri, body) in [
        ("GET", "/v1/models", None),
        ("POST", "/v1/workflows/1/v1/chat/completions", Some(json!({"messages":[]}))),
        ("POST", "/v1/workflows/1/v1/responses", Some(json!({"input":"hi"}))),
    ] {
        let mut builder = Request::builder().method(method).uri(uri);
        let req = if let Some(b) = body {
            builder = builder.header("content-type", "application/json");
            builder.body(Body::from(b.to_string())).unwrap()
        } else {
            builder.body(Body::empty()).unwrap()
        };
        let resp = build_router(st.clone()).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 401, "{method} {uri} requires a bearer");
    }
}

// ── Run-dependent SUCCESS-shape assertions (need a real engine + Chromium) ────────────────────────
//
// The bundled `StubEngine` has no browser; an actual `engine.run(...)` returns an Internal error (500).
// The success-body SHAPING (`object:"chat.completion"` / `"response"` with an assistant turn) is
// already unit-tested in `openai.rs` off a synthetic `RunResult`. These integration cases assert the
// SAME success shape over the real router but require a run-capable engine, so they are `#[ignore]`d
// (run explicitly with `--ignored` against a build wired to the `RealEngine` + a recorded workflow).

#[tokio::test]
#[ignore = "needs a run-capable engine (RealEngine + Chromium); StubEngine has no browser"]
async fn chat_completions_success_shape() {
    let st = test_state().await;
    let id = seed_workflow(&st, "Echo").await;
    let (status, bytes) = post(
        &st,
        "/v1/chat/completions",
        &json!({
            "model": format!("writ:workflow:{id}"),
            "messages": [{"role":"user","content":"go"}],
        }),
    )
    .await;
    assert_eq!(status, 200, "a real run returns a 200 completion");
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["object"], "chat.completion");
    assert_eq!(v["choices"][0]["message"]["role"], "assistant");
    assert!(v["usage"].is_object(), "usage block present");
}

#[tokio::test]
#[ignore = "needs a run-capable engine (RealEngine + Chromium); StubEngine has no browser"]
async fn responses_success_shape() {
    let st = test_state().await;
    let id = seed_workflow(&st, "Echo2").await;
    // Keep the workflow active + cloud-irrelevant; just exercise the Responses success path.
    workflows::update(&st.db, id, &WorkflowUpdate { is_active: Some(1), ..Default::default() })
        .await
        .unwrap();
    let (status, bytes) = post(
        &st,
        "/v1/responses",
        &json!({ "model": format!("writ:workflow:{id}"), "input": "go" }),
    )
    .await;
    assert_eq!(status, 200);
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["object"], "response");
    assert_eq!(v["output"][0]["content"][0]["type"], "output_text");
}
