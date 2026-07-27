//! Delivery contract for `POST /v1/workflows/:id/run` — the local mirror of the cloud managed
//! gateway's wait/async split (`backend/routers/managed_api_proxy.py`).
//!
//! Drives the REAL loopback router via `tower::ServiceExt::oneshot`, same recipe as
//! `tests/openai_conformance.rs`, so the server's auth layer is exercised too.
//!
//! What this proves:
//!   - Default is UNCHANGED: `202 {run_id, status:"running"}`. Existing callers (the desktop UI,
//!     the SSE stream) must not be affected by adding `?wait=`.
//!   - `?wait=true` blocks and answers `200` with a terminal `{status, done:true}` document, and
//!     reports a FAILED run as 200-with-status rather than an HTTP error — a caller has to be able
//!     to tell "your run failed" from "your call was rejected".
//!   - `?wait=true&timeout=…` that expires answers `504` and still hands back the `run_id` plus
//!     where to observe it, so a slow run is collected rather than re-run.
//!
//! Uses the REAL engine (`RealEngine::with_env_browser`), not the `StubEngine`: the stub's `run` is
//! unimplemented, so it can never produce a terminal run for the wait path to observe. In a
//! browserless environment the real engine still terminalizes quickly — as `failed` on browser
//! launch — and a terminal run is a terminal run as far as this contract is concerned.
//!
//! Run:  cargo test --features local --test run_wait_contract

#![cfg(feature = "local")]

use axum::body::{to_bytes, Body};
use axum::http::Request;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt as _;
use writ_agent::local::server::{build_router, AppState};
use writ_agent::local::store::workflows::{self, NewWorkflow};
use writ_agent::local::{config, config::LocalConfig, db, vault};

const TOKEN: &str = "wlt_run_wait_contract";

async fn test_state() -> AppState {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = config::Paths::at(dir.keep());
    paths.ensure_dirs().expect("ensure dirs");
    let v = vault::Vault::load_or_create(&paths.root, false).expect("headless vault");
    let pool = db::open(&paths.db(), &v.db_key_hex()).await.expect("open encrypted db");
    let vault = Arc::new(v);
    let engine = writ_agent::local::engine::RealEngine::with_env_browser(pool.clone(), vault.clone());
    AppState {
        db: pool,
        vault,
        engine: Arc::new(engine),
        config: LocalConfig::default(),
        token: Arc::new(TOKEN.to_string()),
        health: writ_agent::local::app::health::DaemonHealth::shared(),
        recorder: None,
    }
}

async fn post(state: &AppState, uri: &str, body: &Value) -> (u16, Value) {
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
    let json = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
    (status, json)
}

async fn seed_workflow(state: &AppState, name: &str) -> i64 {
    let wf = workflows::insert(
        &state.db,
        &NewWorkflow { name: name.into(), steps: Some("[]".into()), ..Default::default() },
    )
    .await
    .expect("seed workflow");
    wf.id
}

/// REGRESSION GUARD: the default must stay async. Every existing caller (desktop Run modal, SSE
/// consumers) depends on getting the id back immediately rather than blocking.
#[tokio::test]
async fn run_defaults_to_async_202() {
    let st = test_state().await;
    let id = seed_workflow(&st, "async-default").await;

    let (status, body) = post(&st, &format!("/v1/workflows/{id}/run"), &json!({})).await;

    assert_eq!(status, 202, "default run is accepted, not awaited: {body}");
    assert_eq!(body["status"], "running");
    assert!(body["run_id"].is_i64(), "202 carries the run id: {body}");
    assert!(body.get("data").is_none(), "202 has no result yet");
}

/// `?wait=true` blocks and returns the run's own terminal document.
#[tokio::test]
async fn wait_true_blocks_and_returns_terminal_result() {
    let st = test_state().await;
    let id = seed_workflow(&st, "wait-blocks").await;

    let (status, body) = post(&st, &format!("/v1/workflows/{id}/run?wait=true&timeout=60"), &json!({})).await;

    assert_eq!(status, 200, "a terminal run answers 200: {body}");
    assert_eq!(body["done"], true, "terminal document: {body}");
    assert!(body["run_id"].is_i64(), "the id is still reported: {body}");
    let run_status = body["status"].as_str().unwrap_or_default();
    assert!(
        ["success", "failed", "timeout", "cancelled"].contains(&run_status),
        "status uses the shared terminal vocabulary, got {run_status:?}: {body}"
    );
}

/// A FAILED run is still a successful REPORT. Conflating the two would leave a caller unable to
/// distinguish a workflow that failed from a request that was rejected.
#[tokio::test]
async fn failed_run_is_reported_as_200_not_an_http_error() {
    let st = test_state().await;
    let id = seed_workflow(&st, "wait-failure").await;

    let (status, body) = post(&st, &format!("/v1/workflows/{id}/run?wait=true&timeout=60"), &json!({})).await;

    assert_eq!(status, 200, "the report succeeded even if the run did not: {body}");
    assert_eq!(body["done"], true);
    if body["status"] == "failed" {
        assert!(body.get("error").is_some(), "a failed run explains itself: {body}");
    }
}

/// An expired budget must not discard the run: 504 carries the id and where to observe it.
#[tokio::test]
async fn wait_timeout_returns_504_with_a_collectable_run_id() {
    let st = test_state().await;
    let id = seed_workflow(&st, "wait-timeout").await;

    // timeout=0 clamps to the 1s floor, so this either finishes (200) or expires (504) — both are
    // valid outcomes of the SAME contract, and in each case the run id must survive.
    let (status, body) = post(&st, &format!("/v1/workflows/{id}/run?wait=true&timeout=0"), &json!({})).await;

    assert!(status == 200 || status == 504, "expected 200 or 504, got {status}: {body}");
    assert!(body["run_id"].is_i64(), "the run id survives either way: {body}");
    if status == 504 {
        assert_eq!(body["done"], false);
        assert_eq!(body["status"], "running", "the run is still going: {body}");
        assert!(body["status_url"].is_string(), "504 says where to collect: {body}");
        assert!(body["events_url"].is_string(), "504 says where to stream: {body}");
    }
}

/// `wait=false` is explicit-async and must behave exactly like the default.
#[tokio::test]
async fn wait_false_is_explicit_async() {
    let st = test_state().await;
    let id = seed_workflow(&st, "wait-false").await;

    let (status, body) = post(&st, &format!("/v1/workflows/{id}/run?wait=false"), &json!({})).await;

    assert_eq!(status, 202, "explicit wait=false matches the default: {body}");
    assert_eq!(body["status"], "running");
}

/// The run id from a waited call addresses the same run as any other: it resolves through the
/// ordinary read path, so `wait` is a delivery choice and not a separate kind of run.
#[tokio::test]
async fn waited_run_is_readable_through_the_normal_run_endpoint() {
    let st = test_state().await;
    let id = seed_workflow(&st, "wait-readable").await;

    let (_, body) = post(&st, &format!("/v1/workflows/{id}/run?wait=true&timeout=60"), &json!({})).await;
    let run_id = body["run_id"].as_i64().expect("run id");

    // `/v1/runs/:id/results` reports the run's own id and status back — proving the waited call
    // did not mint some parallel notion of a run.
    let resp = build_router(st.clone())
        .oneshot(
            Request::builder()
                .uri(format!("/v1/runs/{run_id}/results"))
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "the waited run is an ordinary run");
    let bytes = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
    let run: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(run["run_id"].as_i64(), Some(run_id), "same run: {run}");
    assert_eq!(
        run["status"], body["status"],
        "the status the wait reported is the status the run store holds: {run}"
    );
}
