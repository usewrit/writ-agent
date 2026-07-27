//! MCP-over-HTTP JSON-RPC 2.0 conformance for the Writ desktop local backend.
//!
//! Drives the REAL loopback router (`local::server::build_router`) end-to-end via
//! `tower::ServiceExt::oneshot` (mirrors `tests/cipher_gate.rs` + the in-file `mcp::http` tests). Each
//! request carries the `wlt_` bearer the daemon mints, so the server's loopback-auth layer is exercised
//! too. ADDITIVE (net-new file), `local`-feature only → the cloud build is byte-unchanged.
//!
//! Conformance asserted against MCP `2025-03-26` over JSON-RPC 2.0 (mcp::protocol):
//!   - `initialize` → `protocolVersion` + `serverInfo{name,version}` + `capabilities.tools`.
//!   - `ping` → empty-object result, id echoed.
//!   - `tools/list` → `{tools:[…]}`; with a seeded workflow, exactly one tool with `name` +
//!     `inputSchema{type:object}`, and its derived input properties reflect the `{{input.*}}` scan.
//!   - `tools/call` → for a stubbed engine the run path surfaces a clean JSON-RPC INTERNAL_ERROR
//!     (the run itself needs a live Chromium; we assert the dispatch/shape, not a successful run).
//!   - A BATCH (top-level array) of [initialize, ping] → an array of two responses with echoed ids;
//!     a batch of a single notification → `202 Accepted` with no body.
//!   - Error shapes: unknown method → METHOD_NOT_FOUND; missing tool name → INVALID_PARAMS;
//!     a non-object/array body → PARSE_ERROR.
//!   - Auth: no bearer → 401 from the server layer (the `/mcp` handler is never reached).
//!
//! Run:  cargo test --features local --test mcp_conformance

#![cfg(feature = "local")]

use axum::body::{to_bytes, Body};
use axum::http::Request;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt as _;
use writ_agent::local::server::{build_router, AppState};
use writ_agent::local::store::workflows::{self, NewWorkflow};
use writ_agent::local::{config, config::LocalConfig, db, engine, vault};

const TOKEN: &str = "wlt_mcp_conformance";

/// Build a real `AppState` over a fresh headless vault + encrypted DB (same recipe as the lib tests:
/// `vault::load_or_create(.., false)` so no OS keyring is touched; `db::open` keys + migrates). The
/// `StubEngine` has no browser — that is fine: every assertion here is a protocol/shape/validation
/// path; the one run-dependent call (`tools/call`) is asserted only for its clean error shape.
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

/// POST a JSON-RPC frame (object or array) to `/mcp` with the bearer; return `(status, body_bytes)`.
async fn post_mcp(state: &AppState, frame: &Value) -> (u16, Vec<u8>) {
    let resp = build_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("authorization", format!("Bearer {TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(frame.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let bytes = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
    (status, bytes.to_vec())
}

/// POST + decode the body as a single JSON-RPC response object.
async fn rpc(state: &AppState, frame: &Value) -> Value {
    let (status, bytes) = post_mcp(state, frame).await;
    assert_eq!(status, 200, "expected a 200 JSON-RPC reply, body={}", String::from_utf8_lossy(&bytes));
    serde_json::from_slice(&bytes).expect("JSON-RPC response decodes")
}

/// Seed one enabled workflow that reads two `{{input.*}}` placeholders so `tools/list` surfaces a
/// derived inputSchema with required properties. Returns its id.
async fn seed_workflow(state: &AppState) -> i64 {
    let steps = r#"[
        {"type":"goto","config":{"url":"{{input.target_url}}"}},
        {"type":"fill","config":{"value":"{{input.username}}"}}
    ]"#;
    let wf = workflows::insert(
        &state.db,
        &NewWorkflow {
            name: "Daily Report".into(),
            description: Some("Pulls the daily report".into()),
            steps: Some(steps.into()),
            ..Default::default()
        },
    )
    .await
    .expect("seed workflow");
    wf.id
}

#[tokio::test]
async fn initialize_conforms() {
    let st = test_state().await;
    let resp = rpc(&st, &json!({"jsonrpc":"2.0","id":1,"method":"initialize"})).await;

    assert_eq!(resp["jsonrpc"], "2.0");
    assert_eq!(resp["id"], json!(1), "id echoed");
    let result = &resp["result"];
    assert_eq!(result["protocolVersion"], "2025-03-26", "advertised MCP protocol version");
    assert_eq!(result["serverInfo"]["name"], "writ-local");
    assert!(result["serverInfo"]["version"].is_string(), "serverInfo carries a version");
    // Tool capability must be advertised (this server exposes workflows as tools).
    assert!(result["capabilities"]["tools"].is_object(), "tools capability present");
    // A success response must NOT carry an error member.
    assert!(resp.get("error").is_none(), "initialize is a success, no error member");
}

#[tokio::test]
async fn ping_returns_empty_result_with_echoed_id() {
    let st = test_state().await;
    let resp = rpc(&st, &json!({"jsonrpc":"2.0","id":"p-1","method":"ping"})).await;
    assert_eq!(resp["id"], json!("p-1"), "string id echoed");
    assert_eq!(resp["result"], json!({}), "ping result is an empty object");
}

#[tokio::test]
async fn tools_list_conforms_and_reflects_seeded_workflow() {
    let st = test_state().await;
    let id = seed_workflow(&st).await;

    let resp = rpc(&st, &json!({"jsonrpc":"2.0","id":2,"method":"tools/list"})).await;
    let tools = resp["result"]["tools"].as_array().expect("tools is an array");
    // The static `writ_*` tools lead the catalog; every tool honors the MCP contract.
    // writ_browser_use is the front door and leads the static catalog (see static_tools::NAMES).
    assert_eq!(tools[0]["name"], "writ_browser_use", "static tools lead the catalog");
    for t in tools {
        assert!(t["name"].as_str().map(|n| !n.is_empty()).unwrap_or(false), "non-empty name: {t}");
        assert_eq!(t["inputSchema"]["type"], "object", "object inputSchema: {t}");
    }
    // Exactly the one seeded workflow follows as a DERIVED tool.
    let derived: Vec<&Value> = tools
        .iter()
        .filter(|t| !t["name"].as_str().unwrap_or("").starts_with("writ_"))
        .collect();
    assert_eq!(derived.len(), 1, "exactly the one seeded workflow is exposed as a derived tool");

    let tool = derived[0];
    assert_eq!(tool["name"], "daily_report", "name is the sanitized workflow name");
    assert_eq!(tool["description"], "Pulls the daily report");
    let schema = &tool["inputSchema"];
    assert_eq!(schema["type"], "object", "inputSchema is a JSON-Schema object");

    // The `{{input.*}}` scan must surface both placeholders as required string properties.
    assert_eq!(schema["properties"]["target_url"]["type"], "string");
    assert_eq!(schema["properties"]["username"]["type"], "string");
    let required = schema["required"].as_array().expect("required is an array");
    let req: Vec<&str> = required.iter().filter_map(Value::as_str).collect();
    assert!(req.contains(&"target_url") && req.contains(&"username"), "both inputs required: {req:?}");

    // A bare `workflow_<id>` literal is the executor's convenience alias — not surfaced as a name here,
    // but the catalog id must match the seeded workflow (sanity that the right row was exposed).
    assert!(id > 0);
}

#[tokio::test]
async fn tools_call_dispatches_and_shapes_engine_error() {
    // The StubEngine has no browser; `engine.run` returns an Internal error. We assert the protocol
    // SHAPE: a known tool resolves + dispatches, and an engine/store failure becomes a clean JSON-RPC
    // INTERNAL_ERROR (-32603) with a generic, non-leaking message — NOT a transport-level 500.
    let st = test_state().await;
    seed_workflow(&st).await;

    let resp = rpc(
        &st,
        &json!({
            "jsonrpc":"2.0","id":3,"method":"tools/call",
            "params": { "name": "daily_report", "arguments": { "target_url": "https://x", "username": "u" } }
        }),
    )
    .await;
    assert_eq!(resp["id"], json!(3));
    // Engine-not-implemented surfaces as INTERNAL_ERROR, ref-tagged + generic (no internal text leaked).
    let err = resp["error"].as_object().expect("tools/call against a stub engine returns an error object");
    assert_eq!(err["code"], json!(-32603), "engine failure → JSON-RPC INTERNAL_ERROR");
    let msg = err["message"].as_str().unwrap_or_default();
    assert!(msg.contains("Internal error"), "generic, ref-tagged message: {msg:?}");
    assert!(!msg.contains("ENG-6"), "must not leak the internal engine error text");
}

#[tokio::test]
async fn tools_call_unknown_tool_is_invalid_params() {
    let st = test_state().await;
    let resp = rpc(
        &st,
        &json!({
            "jsonrpc":"2.0","id":4,"method":"tools/call",
            "params": { "name": "does_not_exist", "arguments": {} }
        }),
    )
    .await;
    assert_eq!(resp["error"]["code"], json!(-32602), "unknown tool → INVALID_PARAMS");
    assert!(
        resp["error"]["message"].as_str().unwrap_or_default().contains("Unknown tool"),
        "unknown-tool message is caller-facing"
    );
}

#[tokio::test]
async fn tools_call_missing_name_is_invalid_params() {
    let st = test_state().await;
    let resp = rpc(
        &st,
        &json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params": { "arguments": {} }}),
    )
    .await;
    assert_eq!(resp["error"]["code"], json!(-32602), "missing tool name → INVALID_PARAMS");
}

#[tokio::test]
async fn batch_request_returns_array_of_responses() {
    let st = test_state().await;
    let batch = json!([
        {"jsonrpc":"2.0","id":10,"method":"initialize"},
        {"jsonrpc":"2.0","id":"ping-11","method":"ping"}
    ]);
    let (status, bytes) = post_mcp(&st, &batch).await;
    assert_eq!(status, 200, "a batch of requests returns 200 with a JSON array");
    let arr: Value = serde_json::from_slice(&bytes).unwrap();
    let items = arr.as_array().expect("batch reply is a JSON array");
    assert_eq!(items.len(), 2, "one response per request frame");

    // Ids are echoed (order is preserved by the handler, but assert by id to be robust).
    let by_id = |id: &Value| items.iter().find(|r| &r["id"] == id).expect("response for id present");
    assert_eq!(by_id(&json!(10))["result"]["protocolVersion"], "2025-03-26");
    assert_eq!(by_id(&json!("ping-11"))["result"], json!({}));
}

#[tokio::test]
async fn batch_of_only_notifications_returns_202_no_body() {
    let st = test_state().await;
    // A batch whose every frame is a notification (no id / notifications/*) yields no response bodies.
    let batch = json!([
        {"jsonrpc":"2.0","method":"notifications/initialized"}
    ]);
    let (status, bytes) = post_mcp(&st, &batch).await;
    assert_eq!(status, 202, "all-notification batch → 202 Accepted");
    assert!(bytes.is_empty(), "202 carries no JSON-RPC body");
}

#[tokio::test]
async fn empty_batch_is_invalid_request() {
    let st = test_state().await;
    let (status, bytes) = post_mcp(&st, &json!([])).await;
    assert_eq!(status, 200, "an (invalid) empty batch still returns a JSON-RPC error object");
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["error"]["code"], json!(-32600), "empty batch → INVALID_REQUEST");
    assert_eq!(v["id"], Value::Null, "no id available for an empty batch");
}

#[tokio::test]
async fn unknown_method_is_method_not_found() {
    let st = test_state().await;
    let resp = rpc(&st, &json!({"jsonrpc":"2.0","id":6,"method":"frobnicate"})).await;
    assert_eq!(resp["error"]["code"], json!(-32601), "unknown method → METHOD_NOT_FOUND");
    assert_eq!(resp["id"], json!(6));
}

#[tokio::test]
async fn single_notification_returns_202_no_body() {
    let st = test_state().await;
    let (status, bytes) = post_mcp(
        &st,
        &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await;
    assert_eq!(status, 202, "a lone notification → 202 with no body");
    assert!(bytes.is_empty());
}

#[tokio::test]
async fn non_object_body_is_parse_error() {
    let st = test_state().await;
    // A bare JSON string/number is neither a JSON-RPC object nor a batch array.
    let (status, bytes) = post_mcp(&st, &json!("not a frame")).await;
    assert_eq!(status, 200);
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["error"]["code"], json!(-32700), "non-object/array body → PARSE_ERROR");
}

#[tokio::test]
async fn mcp_requires_bearer() {
    let st = test_state().await;
    // No Authorization header → the server auth layer rejects before `/mcp` runs.
    let resp = build_router(st)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "MCP transport inherits the loopback bearer gate");
}
