//! `/v1/diagnostics` — the "Export diagnostics" surface for the Settings UI (PROD-13).
//!
//! Builds a REDACTED diagnostics bundle (a dependency-free `.tar` of the scrubbed logs + crash
//! records + the non-secret `config.toml`) under `~/.writ/artifacts/` and returns its on-disk path so
//! the Tauri shell can reveal/save it. NEVER includes the DB, the vault key, the local token, or any
//! secret material — only redacted text artifacts (see [`crate::local::crash::build_diagnostics_bundle`]).
//!
//! Route (loopback + bearer gated by `server.rs`, like every other `/v1` route):
//!   GET /v1/diagnostics  → { "bundle_path": "<abs path to the .tar>" }
//!
//! The path is the daemon-local filesystem path (the UI runs on the same machine). It is NOT a
//! `~/.writ` path that would be scrubbed by the log sink — it is the legitimate return value of an
//! operator-initiated export, surfaced to a same-host UI, not a log line. House style: thin handler
//! over the `crash` helper + `Paths::resolve`, `LocalResult<Json<_>>` with `?`, no auth layer here.
//!
//! Net-new Rust in this crate (behind the `local` feature).

use crate::local::config::Paths;
use crate::local::crash;
use crate::local::error::{LocalError, LocalResult};
use crate::local::server::AppState;
use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};

/// Mount `/v1/diagnostics`. Auth is applied by `server.rs` at the router level.
pub fn router() -> Router<AppState> {
    Router::new().route("/v1/diagnostics", get(export))
}

/// `GET /v1/diagnostics` — build a redacted diagnostics bundle and return its path.
///
/// Resolves the home the same way the daemon does at boot (`$WRIT_HOME` or `~/.writ`), writes the
/// `.tar` into `~/.writ/artifacts/`, and returns the absolute path. A build failure maps to a 500
/// (the bundler is best-effort per file, so this only fails on an outright IO error creating the
/// archive). NEVER logs a secret — the bundle's contents are scrubbed before they land.
async fn export(State(_st): State<AppState>) -> LocalResult<Json<Value>> {
    let paths = Paths::resolve()?;
    let bundle = crash::build_diagnostics_bundle(&paths)
        .map_err(|e| LocalError::Internal(format!("build diagnostics bundle: {e}")))?;
    tracing::info!("diagnostics bundle exported");
    Ok(Json(json!({ "bundle_path": bundle.to_string_lossy() })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::config::LocalConfig;
    use crate::local::server::build_router;
    use crate::local::{db, engine, vault};
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use std::sync::Arc;
    use tower::ServiceExt;

    const TOKEN: &str = "wlt_diag_secret";

    async fn test_state() -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("WRIT_HOME", dir.path().join(".writ"));
        let paths = Paths::resolve().unwrap();
        paths.ensure_dirs().unwrap();
        // Seed a log line carrying a token + username path so we can prove the bundle is scrubbed.
        std::fs::write(
            paths.logs_dir().join("agentd.log"),
            "boot token wlt_LEAK12_abc at /Users/jane/.writ/writ.db\n",
        )
        .unwrap();
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

    #[tokio::test]
    async fn export_returns_a_scrubbed_bundle_path() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state().await;
        let req = Request::builder()
            .method("GET")
            .uri("/v1/diagnostics")
            .header("authorization", format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .unwrap();
        let resp = build_router(st.clone()).oneshot(req).await.unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        let path = body["bundle_path"].as_str().expect("bundle_path string");
        assert!(path.ends_with(".tar"), "got {path}");

        // The produced archive must not carry the seeded token / username.
        let blob = std::fs::read(path).unwrap();
        let text = String::from_utf8_lossy(&blob);
        assert!(!text.contains("wlt_LEAK12"), "token leaked into bundle");
        assert!(!text.contains("jane"), "username leaked into bundle");
        assert!(text.contains("logs/agentd.log"), "log entry present");

        std::env::remove_var("WRIT_HOME");
    }

    #[tokio::test]
    async fn export_requires_the_loopback_bearer() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state().await;
        let resp = build_router(st.clone())
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/diagnostics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 401);
        std::env::remove_var("WRIT_HOME");
    }
}
