//! MCP-over-HTTP transport — a single `POST /mcp` JSON-RPC endpoint on the loopback router.
//!
//! Mounts alongside the `/v1` REST surface; `server.rs` applies the loopback bearer + Origin/Host
//! guard at the top-level router, so there is no auth LAYER here (same contract as every `/v1`
//! resource). The handler decodes one JSON-RPC frame, dispatches it through `mcp::protocol`, and
//! returns the response as JSON. Notifications (no `id`) produce no JSON-RPC body, so we answer
//! `202 Accepted` with an empty payload per the JSON-RPC-over-HTTP convention.
//!
//! AUTHORIZATION: the route-level gate can only classify `POST /mcp` once (`Run`), which is too coarse
//! for a surface that multiplexes read/run/admin tools. So this handler forwards the capability
//! `server::auth_mw` resolved for the request ([`Caller`], from request extensions) into `protocol`,
//! where `tool_executor` enforces a per-tool minimum scope. A MISSING extension means the request never
//! passed the auth middleware, and [`auth::caller_or_deny`] then grants nothing — fail closed.
//!
//! Batch requests (a top-level JSON array) are supported: each element is dispatched independently
//! and the non-empty responses are returned as a JSON array (notifications drop out). House style:
//! `async fn(State, Json) -> impl IntoResponse`; `tracing` only; no `async-trait`.

use super::protocol::{self, JsonRpcResponse, PARSE_ERROR};
use crate::local::auth::{self, Caller};
use crate::local::server::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Json, Router};
use serde_json::Value;

/// Mount the MCP HTTP transport. Auth is applied by `server.rs` at the router level.
pub fn router() -> Router<AppState> {
    Router::new().route("/mcp", post(handle))
}

/// `POST /mcp` — single or batched JSON-RPC 2.0. Returns the JSON-RPC response object (single) or
/// array (batch), or `202` with no body when every frame was a notification.
async fn handle(
    State(st): State<AppState>,
    caller: Option<Extension<Caller>>,
    Json(body): Json<Value>,
) -> Response {
    let caller = auth::caller_or_deny(caller.as_ref().map(|Extension(c)| c));
    match body {
        // Batch: dispatch each frame; collect only the frames that produce a reply.
        Value::Array(frames) => {
            if frames.is_empty() {
                // An empty batch is an invalid request per JSON-RPC 2.0.
                return Json(JsonRpcResponse::err(
                    Value::Null,
                    protocol::INVALID_REQUEST,
                    "Empty batch",
                ))
                .into_response();
            }
            let mut responses: Vec<JsonRpcResponse> = Vec::with_capacity(frames.len());
            for frame in frames {
                if let Some(resp) = protocol::handle_value(&st, &caller, frame).await {
                    responses.push(resp);
                }
            }
            if responses.is_empty() {
                // All notifications → no body.
                return StatusCode::ACCEPTED.into_response();
            }
            Json(responses).into_response()
        }

        // Single request object.
        Value::Object(_) => match protocol::handle_value(&st, &caller, body).await {
            Some(resp) => Json(resp).into_response(),
            None => StatusCode::ACCEPTED.into_response(),
        },

        // Anything else is not a valid JSON-RPC message.
        _ => Json(JsonRpcResponse::err(
            Value::Null,
            PARSE_ERROR,
            "Request body must be a JSON-RPC object or array",
        ))
        .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::server::build_router;
    use crate::local::{config::LocalConfig, db, engine, vault};
    use axum::body::Body;
    use axum::http::Request;
    use std::sync::Arc;
    use tower::ServiceExt;

    async fn state(token: &str) -> AppState {
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::local::config::Paths::at(dir.keep());
        paths.ensure_dirs().unwrap();
        let v = vault::Vault::load_or_create(&paths.root, false).unwrap();
        let pool = db::open(&paths.db(), &v.db_key_hex()).await.unwrap();
        AppState {
            db: pool,
            vault: Arc::new(v),
            engine: Arc::new(engine::StubEngine),
            config: LocalConfig::default(),
            token: Arc::new(token.into()),
            health: crate::local::app::health::DaemonHealth::shared(),
            recorder: None,
        }
    }

    #[tokio::test]
    async fn initialize_over_http_requires_bearer() {
        let st = state("wlt_x").await;

        // No bearer → 401 (server.rs auth layer).
        let resp = build_router(st.clone())
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
        assert_eq!(resp.status(), 401);

        // With bearer → 200 + protocol version.
        let resp = build_router(st)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("authorization", "Bearer wlt_x")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["result"]["protocolVersion"], protocol::MCP_PROTOCOL_VERSION);
    }

    /// Mint a scoped `wlk_` key straight into the store; returns the raw bearer.
    async fn mint_key(st: &AppState, scopes: &str) -> String {
        use crate::local::store::local_api_keys::{insert, NewLocalApiKey};
        let raw = format!("wlk_mcp_{}", scopes.replace(',', "_"));
        let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
        sha2::Digest::update(&mut hasher, raw.as_bytes());
        let key_hash: String =
            sha2::Digest::finalize(hasher).iter().map(|b| format!("{b:02x}")).collect();
        insert(
            &st.db,
            &NewLocalApiKey {
                name: "k".into(),
                prefix: "wlk_mcp".into(),
                key_hash,
                scopes: Some(scopes.into()),
            },
        )
        .await
        .unwrap();
        raw
    }

    async fn tools_call(st: &AppState, bearer: &str, tool: &str, args: Value) -> Value {
        let frame = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": tool, "arguments": args },
        });
        let resp = build_router(st.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("authorization", format!("Bearer {bearer}"))
                    .header("content-type", "application/json")
                    .body(Body::from(frame.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "JSON-RPC always answers 200 at the HTTP layer");
        let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// END-TO-END for the `POST /mcp` scope collapse: the route is classified `Run` once, so without a
    /// per-tool gate a `run`-scoped key reached `Admin` tools (`writ_create_automation`,
    /// `writ_set_schedule`, …). Through the real router + real auth middleware: the admin tool is
    /// refused, the run/read tools still work.
    #[tokio::test]
    async fn run_scoped_key_is_refused_admin_tools_over_http() {
        let st = state("wlt_mcp_scopes").await;
        let run_key = mint_key(&st, "run").await;

        for tool in ["writ_create_automation", "writ_set_schedule", "writ_expose_workflow_api"] {
            let v = tools_call(&st, &run_key, tool, serde_json::json!({})).await;
            let msg = v["error"]["message"].as_str().unwrap_or_default();
            assert!(
                msg.contains("Not authorized"),
                "{tool} must be refused to a run key, got {v}"
            );
            assert!(msg.contains("admin"), "{tool}: refusal names the needed scope: {msg}");
            assert!(v.get("result").is_none(), "{tool} must not have executed");
        }

        // The capability it WAS granted still works (a read tool through the run chain).
        let v = tools_call(&st, &run_key, "writ_list_workflows", serde_json::json!({})).await;
        assert!(v.get("error").is_none(), "run key may list workflows: {v}");
        assert!(v["result"]["content"].is_array());

        // An admin key gets through to the tool body (it fails on ARGUMENTS, not authorization).
        let admin_key = mint_key(&st, "admin").await;
        let v = tools_call(&st, &admin_key, "writ_set_schedule", serde_json::json!({})).await;
        let msg = v["error"]["message"].as_str().unwrap_or_default();
        assert!(
            !msg.contains("Not authorized"),
            "an admin key must pass the scope gate (any error is about args): {v}"
        );

        // And the full-access `wlt_` UI token is unaffected — same as before the gate existed.
        let v = tools_call(&st, "wlt_mcp_scopes", "writ_list_workflows", serde_json::json!({})).await;
        assert!(v.get("error").is_none(), "wlt_ token unaffected: {v}");
    }

    #[tokio::test]
    async fn notification_returns_202_no_body() {
        let st = state("wlt_n").await;
        let resp = build_router(st)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("authorization", "Bearer wlt_n")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 202);
    }
}
