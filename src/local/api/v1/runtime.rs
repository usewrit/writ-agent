//! `/v1/runtime/*` REST handlers — the first-run RUNTIME readiness surface for the Tauri shell's
//! setup wizard. Reports whether a usable Chromium + the patchright driver are present, and (when
//! Chromium is missing) drives a best-effort install with pollable progress.
//!
//! Routes (FIXED CONTRACT — the wizard proxies onto these; all loopback + bearer gated by `server.rs`):
//!   GET  /v1/runtime/status                     → { chromium:{available,source,path},
//!                                                    driver:{bundled,path} }
//!   POST /v1/runtime/install-chromium           → { started:bool }
//!   GET  /v1/runtime/install-chromium/progress  → { state, percent, message }
//!
//! Onboarding-state companions (the wizard's first/last steps; persisted to `[app]` in config.toml):
//!   GET  /v1/runtime/onboarding                 → { completed:bool, language:string }
//!   POST /v1/runtime/onboarding/language        { language } → { language }
//!   POST /v1/runtime/onboarding/complete        → { completed:true }  (wizard "Finish")
//!
//! Detection + the install orchestration live in [`crate::local::runtime_setup`] (the testable core);
//! these handlers are thin shells over it, mirroring `network.rs` over `config`/`server`. No auth
//! layer is added here (server.rs applies the loopback bearer + Origin/Host guard once). `tracing`
//! only, NEVER a secret — this surface carries none (only public filesystem paths + install state).
//!
//! Net-new Rust in this crate (behind the `local` feature).

use crate::local::config::{self, Paths};
use crate::local::error::LocalResult;
use crate::local::runtime_setup;
use crate::local::server::AppState;
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

/// Mount the `/v1/runtime/*` routes onto the shared `AppState` router. Auth is applied by `server.rs`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/runtime/status", get(status))
        .route("/v1/runtime/install-chromium", post(install_chromium))
        .route("/v1/runtime/install-chromium/progress", get(install_progress))
        .route("/v1/runtime/onboarding", get(onboarding_get))
        .route("/v1/runtime/onboarding/language", post(onboarding_language))
        .route("/v1/runtime/onboarding/complete", post(onboarding_complete))
}

/// `GET /v1/runtime/status` — Chromium + driver readiness for the setup wizard.
///
/// `chromium.source` is `bundled` (app-bundled, `WRIT_BUNDLED_CHROMIUM`), `system` (a
/// playwright/patchright/system Chromium on disk), or `none`. `driver.bundled` reflects
/// `WRIT_BUNDLED_DRIVER` — the driver is always shipped, so it is reported but never installable.
/// Serialized straight from the detection structs (their serde shape IS the contract).
async fn status(/* no state needed: detection is env+fs only */) -> LocalResult<Json<Value>> {
    let st = runtime_setup::detect_runtime();
    Ok(Json(json!({
        "chromium": st.chromium,
        "driver": st.driver,
    })))
}

/// `POST /v1/runtime/install-chromium` — begin a best-effort Chromium install (idempotent).
///
/// Spawns the bundled driver's "install chromium" command on a background task and returns
/// immediately. `started=true` when this call kicked off a fresh install; `started=false` when an
/// install is already running OR a Chromium is already present (nothing to do). The wizard polls
/// `…/progress` for completion either way.
async fn install_chromium() -> LocalResult<Json<Value>> {
    let started = runtime_setup::start_install_chromium();
    tracing::info!(started, "runtime: install-chromium requested");
    Ok(Json(json!({ "started": started })))
}

/// `GET /v1/runtime/install-chromium/progress` — poll the current install state.
///
/// Returns `{ state: "idle"|"running"|"done"|"error", percent: int|null, message: string|null }`.
/// `percent` is a best-effort parse of the driver output (null = indeterminate). This is a pollable
/// GET (the contract permits SSE OR polling; polling matches the rest of the `/v1` surface).
async fn install_progress() -> LocalResult<Json<Value>> {
    let p = runtime_setup::install_progress();
    Ok(Json(json!({
        "state": p.state,
        "percent": p.percent,
        "message": p.message,
    })))
}

/// `GET /v1/runtime/onboarding` — reflect the CURRENTLY-RUNNING onboarding state so the shell can
/// decide whether to show the setup wizard. Reads the live `AppState.config` snapshot (the booted
/// values); a value persisted this session via the POSTs below takes effect on the next daemon start,
/// so this can lag the on-disk flag until restart — same lifecycle contract as `/v1/network/status`.
async fn onboarding_get(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    Ok(Json(json!({
        "completed": st.config.onboarding_completed,
        "language": st.config.language,
    })))
}

/// Body for `POST /v1/runtime/onboarding/language` — the wizard's language step.
#[derive(Debug, Deserialize)]
struct LanguageBody {
    language: String,
}

/// `POST /v1/runtime/onboarding/language` — persist the chosen UI language to `[app].language`.
/// Read-modify-write that preserves every other on-disk field. Rejects an empty tag (400). The shell
/// re-seeds react-i18next from the returned value immediately; the daemon snapshot updates on restart.
async fn onboarding_language(Json(body): Json<LanguageBody>) -> LocalResult<Json<Value>> {
    let paths = Paths::resolve()?;
    let lang = body.language.trim().to_string();
    config::set_language(&paths, &lang)?;
    tracing::info!(language = %lang, "onboarding: language persisted");
    Ok(Json(json!({ "language": lang })))
}

/// `POST /v1/runtime/onboarding/complete` — the wizard's "Finish". Persists
/// `[app].onboarding_completed = true` so the shell stops showing setup on the next launch.
/// Idempotent. NEVER logs a secret (the config carries none).
async fn onboarding_complete() -> LocalResult<Json<Value>> {
    let paths = Paths::resolve()?;
    config::set_onboarding_completed(&paths, true)?;
    tracing::info!("onboarding: marked complete");
    Ok(Json(json!({ "completed": true })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::config::{LocalConfig, Paths};
    use crate::local::runtime_setup::{ENV_BUNDLED_CHROMIUM, ENV_BUNDLED_DRIVER};
    use crate::local::server::build_router;
    use crate::local::{db, engine, vault};
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use std::sync::Arc;
    use tower::ServiceExt;

    const TOKEN: &str = "wlt_runtime_secret";

    /// A loopback `AppState` over a throwaway encrypted DB. The runtime routes need no special state —
    /// detection reads env + filesystem only — but `build_router` requires a full `AppState`.
    async fn test_state() -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("WRIT_HOME", dir.path().join(".writ"));
        let paths = Paths::resolve().unwrap();
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
        call_body(st, method, uri, None).await
    }

    /// Authenticated loopback request with an optional JSON body → `(status, json)`.
    async fn call_body(st: &AppState, method: &str, uri: &str, body: Option<&str>) -> (u16, Value) {
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

    /// `status` reports the contract shape, and a bundled-Chromium env is surfaced as
    /// `source = "bundled"`.
    #[tokio::test]
    async fn status_reports_bundled_chromium_and_driver_shape() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state().await;

        // Point both bundled-resource envs at existing sandbox paths.
        let res = tempfile::tempdir().unwrap();
        let exe = res.path().join("Chromium");
        std::fs::write(&exe, b"#!/bin/sh\n").unwrap();
        let driver = res.path().join("driver");
        std::fs::create_dir_all(&driver).unwrap();
        std::env::set_var(ENV_BUNDLED_CHROMIUM, &exe);
        std::env::set_var(ENV_BUNDLED_DRIVER, &driver);

        let (code, body) = call(&st, "GET", "/v1/runtime/status").await;
        assert_eq!(code, 200, "body={body}");
        assert_eq!(body["chromium"]["available"], json!(true));
        assert_eq!(body["chromium"]["source"], json!("bundled"));
        assert!(body["chromium"]["path"].is_string());
        assert_eq!(body["driver"]["bundled"], json!(true));
        assert!(body["driver"]["path"].is_string());

        std::env::remove_var(ENV_BUNDLED_CHROMIUM);
        std::env::remove_var(ENV_BUNDLED_DRIVER);
        std::env::remove_var("WRIT_HOME");
    }

    /// `install-chromium` short-circuits to `started=false` + `done` progress when a Chromium is
    /// already available (the bundled env path exists). Exercises the full POST→GET progress flow
    /// WITHOUT a real download.
    #[tokio::test]
    async fn install_short_circuits_and_progress_reports_done() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state().await;
        crate::local::runtime_setup::reset_install_progress_for_test();

        let res = tempfile::tempdir().unwrap();
        let exe = res.path().join("Chromium");
        std::fs::write(&exe, b"#!/bin/sh\n").unwrap();
        std::env::set_var(ENV_BUNDLED_CHROMIUM, &exe);

        let (code, body) = call(&st, "POST", "/v1/runtime/install-chromium").await;
        assert_eq!(code, 200, "body={body}");
        assert_eq!(body["started"], json!(false), "already-available ⇒ nothing started");

        let (code, prog) = call(&st, "GET", "/v1/runtime/install-chromium/progress").await;
        assert_eq!(code, 200, "prog={prog}");
        assert_eq!(prog["state"], json!("done"));
        assert_eq!(prog["percent"], json!(100));

        std::env::remove_var(ENV_BUNDLED_CHROMIUM);
        crate::local::runtime_setup::reset_install_progress_for_test();
        std::env::remove_var("WRIT_HOME");
    }

    /// The onboarding companions: GET reflects the booted defaults, the language POST persists +
    /// preserves, and `complete` flips the on-disk flag. The GET reflects the BOOT snapshot (so it
    /// still reads the pre-persist values), matching the network-status lifecycle contract.
    #[tokio::test]
    async fn onboarding_get_persist_and_complete() {
        let _g = crate::local::config::test_env_guard();
        for k in ["WRIT_ONBOARDING_COMPLETED", "WRIT_LANGUAGE"] {
            std::env::remove_var(k);
        }
        let (_dir, st) = test_state().await;
        let paths = Paths::resolve().unwrap();

        // Fresh install: not completed, default language.
        let (code, body) = call(&st, "GET", "/v1/runtime/onboarding").await;
        assert_eq!(code, 200, "body={body}");
        assert_eq!(body["completed"], json!(false));
        assert_eq!(body["language"], json!("en"));

        // Persist a language → lands on disk, preserves the (still-false) completion flag.
        let (code, body) =
            call_body(&st, "POST", "/v1/runtime/onboarding/language", Some(r#"{"language":"fr"}"#))
                .await;
        assert_eq!(code, 200, "body={body}");
        assert_eq!(body["language"], json!("fr"));
        let on_disk = config::load_config(&paths);
        assert_eq!(on_disk.language, "fr", "language persisted");
        assert!(!on_disk.onboarding_completed, "completion untouched by the language write");

        // An empty language is a 400 (keep a valid tag on disk).
        let (code, _b) =
            call_body(&st, "POST", "/v1/runtime/onboarding/language", Some(r#"{"language":"  "}"#))
                .await;
        assert_eq!(code, 400, "empty language rejected");
        assert_eq!(config::load_config(&paths).language, "fr", "rejected write left disk intact");

        // Finish the wizard → completion flag flips on disk, language preserved.
        let (code, body) = call(&st, "POST", "/v1/runtime/onboarding/complete").await;
        assert_eq!(code, 200, "body={body}");
        assert_eq!(body["completed"], json!(true));
        let on_disk = config::load_config(&paths);
        assert!(on_disk.onboarding_completed, "completion persisted");
        assert_eq!(on_disk.language, "fr", "language preserved through the complete write");

        std::env::remove_var("WRIT_HOME");
    }

    /// Every runtime route requires the loopback bearer.
    #[tokio::test]
    async fn routes_require_the_loopback_bearer() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state().await;
        for (method, uri) in [
            ("GET", "/v1/runtime/status"),
            ("POST", "/v1/runtime/install-chromium"),
            ("GET", "/v1/runtime/install-chromium/progress"),
            ("GET", "/v1/runtime/onboarding"),
            ("POST", "/v1/runtime/onboarding/language"),
            ("POST", "/v1/runtime/onboarding/complete"),
        ] {
            let resp = build_router(st.clone())
                .oneshot(
                    Request::builder().method(method).uri(uri).body(Body::empty()).unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status().as_u16(), 401, "{method} {uri} must be 401 without a bearer");
        }
        std::env::remove_var("WRIT_HOME");
    }
}
