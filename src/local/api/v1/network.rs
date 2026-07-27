//! `/v1/network/*` REST handlers — the LAN-exposure opt-in surface for the Tauri shell.
//!
//! The Writ daemon is LOOPBACK-ONLY BY DEFAULT (binds `127.0.0.1`, never network-reachable). The
//! user may OPT IN — via a UI button that proxies onto these routes — to expose the local
//! API/MCP/OpenAI surface on the LAN (bind `0.0.0.0`) so other devices on the same network can call
//! it. The `wlt_`/`wlk_` bearer token stays MANDATORY in both modes, and the DNS-rebind Origin/Host
//! guard still rejects foreign browser origins (see `server::auth_mw` + `auth::origin_allowed_for`).
//!
//! Routes (FIXED CONTRACT — the Tauri shell proxies to these):
//!   GET  /v1/network/status  → { exposed, bind_host, port, lan_url|null, needs_restart:false }
//!   POST /v1/network/expose  → { enabled } persists `[server].network_exposed` to config.toml and
//!                              returns { needs_restart:true } (the bind only changes on RESTART).
//!
//! The bind is fixed for the running listener's lifetime, so `POST /expose` only PERSISTS the flag —
//! the Tauri shell applies it by restarting the sidecar (stop_engine + start_engine). `status`
//! therefore reports the CURRENTLY-RUNNING bind (from `AppState.config`), which can differ from the
//! just-persisted on-disk flag until that restart happens.
//!
//! House style: thin handlers over `config` + `server` helpers, `LocalResult<Json<_>>` with `?`
//! propagation, no auth layer here (server.rs applies the loopback/LAN bearer + Origin/Host guard).
//! `tracing` only, NEVER any secret value (this surface carries none).
//!
//! Net-new Rust in this crate (behind the `local` feature).

use crate::local::config::{self, Paths};
use crate::local::error::LocalResult;
use crate::local::server::{self, AppState};
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

/// Mount the `/v1/network/*` routes onto the shared `AppState` router. Auth is applied by `server.rs`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/network/status", get(status))
        .route("/v1/network/expose", post(expose))
}

/// Body for `POST /v1/network/expose`. The single toggle the UI flips.
#[derive(Debug, Deserialize)]
struct ExposeBody {
    enabled: bool,
}

/// `GET /v1/network/status` — reflect the CURRENTLY-RUNNING network posture.
///
/// `exposed`/`bind_host`/`port` come from the live `AppState.config` (the listener that is actually
/// bound right now), NOT from the on-disk flag — so immediately after a `POST /expose` this still
/// reports the old bind until the daemon restarts. `lan_url` is a best-effort `http://<lan-ip>:<port>`
/// hint when exposed (null when loopback-only or when no LAN IP can be resolved). `needs_restart` is
/// always false here — a pending restart is signalled by the `expose` response, not reflected here.
async fn status(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    let exposed = st.config.network_exposed;
    let port = st.config.port;
    let bind = server::bind_host(exposed);
    let lan_url = if exposed {
        server::primary_lan_ip().map(|ip| format!("http://{ip}:{port}"))
    } else {
        None
    };
    Ok(Json(json!({
        "exposed": exposed,
        "bind_host": bind,
        "port": port,
        "lan_url": lan_url,
        "needs_restart": false,
    })))
}

/// `POST /v1/network/expose` — persist the LAN-exposure opt-in to `~/.writ/config.toml`.
///
/// This ONLY writes `[server].network_exposed` (read-modify-write that preserves every other on-disk
/// field). The running listener's bind is fixed for its lifetime, so the change takes effect only on
/// the next daemon start — hence `needs_restart: true`. The Tauri shell applies it by restarting the
/// sidecar (stop_engine + start_engine). Idempotent: writing the same value is a no-op flip.
///
/// NEVER logs a secret (the config file carries none). The exposure decision IS logged (a security-
/// relevant operator action) but only as the boolean + the fact a restart is pending.
async fn expose(State(_st): State<AppState>, Json(body): Json<ExposeBody>) -> LocalResult<Json<Value>> {
    // Resolve the on-disk home the same way the daemon does at boot (`$WRIT_HOME` or `~/.writ`), so
    // the persisted flag lands in the file the next start reads. No `AppState` field is threaded.
    let paths = Paths::resolve()?;
    config::set_network_exposed(&paths, body.enabled)?;
    tracing::warn!(
        enabled = body.enabled,
        "network exposure flag persisted (restart required to apply the new bind)"
    );
    Ok(Json(json!({ "needs_restart": true })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::config::LocalConfig;
    use crate::local::server::build_router;
    use crate::local::{config::Paths, db, engine, vault};
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use std::sync::Arc;
    use tower::ServiceExt;

    const TOKEN: &str = "wlt_net_secret";

    /// A loopback `AppState` over a throwaway encrypted DB, with `WRIT_HOME` pointed at the temp dir
    /// so the `expose` handler's `Paths::resolve()` writes into the test sandbox (not the real home).
    /// Returns the dir guard (kept alive) + the state, with the given `network_exposed` posture. The
    /// caller MUST already hold the shared [`crate::local::config::test_env_guard`] for the duration
    /// of the test (see each `#[tokio::test]`).
    async fn test_state(network_exposed: bool) -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().unwrap();
        // Point the daemon's home resolver at the sandbox for the duration of the test.
        std::env::set_var("WRIT_HOME", dir.path().join(".writ"));
        std::env::remove_var("WRIT_NETWORK_EXPOSE");
        let paths = Paths::resolve().unwrap();
        paths.ensure_dirs().unwrap();
        let v = vault::Vault::load_or_create(&paths.root, false).unwrap();
        let pool = db::open(&paths.db(), &v.db_key_hex()).await.unwrap();
        let config = LocalConfig { network_exposed, ..LocalConfig::default() };
        let st = AppState {
            db: pool,
            vault: Arc::new(v),
            engine: Arc::new(engine::StubEngine),
            config,
            token: Arc::new(TOKEN.to_string()),
            health: crate::local::app::health::DaemonHealth::shared(),
            recorder: None,
        };
        (dir, st)
    }

    /// Issue an authenticated loopback request (optional JSON body) → `(status, json_body)`.
    async fn call(st: &AppState, method: &str, uri: &str, body: Option<&str>) -> (u16, Value) {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {TOKEN}"))
            .header("content-type", "application/json")
            .body(body.map(|b| Body::from(b.to_string())).unwrap_or_else(Body::empty))
            .unwrap();
        let resp = build_router(st.clone()).oneshot(req).await.unwrap();
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
    async fn status_loopback_default() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state(false).await;
        let (code, body) = call(&st, "GET", "/v1/network/status", None).await;
        assert_eq!(code, 200, "body={body}");
        assert_eq!(body["exposed"], json!(false));
        assert_eq!(body["bind_host"], json!("127.0.0.1"));
        assert!(body["port"].is_number());
        assert_eq!(body["lan_url"], Value::Null, "no LAN url when loopback-only");
        assert_eq!(body["needs_restart"], json!(false));
        std::env::remove_var("WRIT_HOME");
    }

    #[tokio::test]
    async fn status_reflects_exposed_running_bind() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state(true).await;
        let (code, body) = call(&st, "GET", "/v1/network/status", None).await;
        assert_eq!(code, 200, "body={body}");
        assert_eq!(body["exposed"], json!(true));
        assert_eq!(body["bind_host"], json!("0.0.0.0"));
        // lan_url is best-effort: a string `http://<ip>:<port>` if a LAN IP resolved, else null.
        assert!(body["lan_url"].is_string() || body["lan_url"].is_null(), "lan_url shape: {body}");
        std::env::remove_var("WRIT_HOME");
    }

    #[tokio::test]
    async fn expose_persists_flag_and_signals_restart() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state(false).await;
        let paths = Paths::resolve().unwrap();

        // Enable → persisted to config.toml + needs_restart true.
        let (code, body) = call(&st, "POST", "/v1/network/expose", Some(r#"{"enabled":true}"#)).await;
        assert_eq!(code, 200, "body={body}");
        assert_eq!(body["needs_restart"], json!(true));
        assert!(config::load_config(&paths).network_exposed, "flag landed on disk");

        // Disable → persisted off, still needs a restart to apply.
        let (code, body) = call(&st, "POST", "/v1/network/expose", Some(r#"{"enabled":false}"#)).await;
        assert_eq!(code, 200, "body={body}");
        assert_eq!(body["needs_restart"], json!(true));
        assert!(!config::load_config(&paths).network_exposed, "flag cleared on disk");

        // The RUNNING bind is unchanged by the persist (status still reflects the boot snapshot).
        let (_code, status) = call(&st, "GET", "/v1/network/status", None).await;
        assert_eq!(status["exposed"], json!(false), "running posture unchanged until restart");
        std::env::remove_var("WRIT_HOME");
    }

    #[tokio::test]
    async fn routes_require_the_loopback_bearer() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state(false).await;
        let resp = build_router(st.clone())
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/network/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 401);
        std::env::remove_var("WRIT_HOME");
    }
}
