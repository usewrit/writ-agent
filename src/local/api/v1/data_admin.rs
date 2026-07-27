//! `/v1/data/*` REST handlers — retention purge, factory reset, and the retention-window setting
//! (PROD-18). These run UNDER the loopback bearer + Origin/Host guard `server.rs` applies once (no
//! new auth). The Tauri shell proxies the "Privacy & Data" UI onto them.
//!
//! Routes (FIXED CONTRACT):
//!   GET  /v1/data/retention     → { retention_days }                 (the live setting)
//!   POST /v1/data/retention     { days }    → { retention_days, needs_restart:false }  (persist)
//!   POST /v1/data/purge         { days? }   → PurgeReport             (run the purge now)
//!   POST /v1/data/reset         { confirm, rotate_vault? } → ResetReport (delete-all / factory)
//!
//! SAFETY:
//! - `purge` only removes regenerable HISTORY (runs/changes/uptime + captured workflow-output files)
//!   older than the cutoff — never user-authored definitions (see `retention::purge_older_than`).
//! - `reset` is a HARD wipe of the DB + file/artifact stores; it requires `{"confirm":"DELETE"}` so a
//!   stray click can't nuke the home, and returns `needs_restart=true` (the shell restarts the daemon
//!   onto a fresh DB). `rotate_vault=true` additionally rotates the local vault root (old backups
//!   become unreadable). NEVER logs secrets.
//!
//! Net-new Rust in this crate (behind the `local` feature).

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::local::config::{self, Paths};
use crate::local::error::{LocalError, LocalResult};
use crate::local::server::AppState;
use crate::local::{backup, retention};

/// The literal a `reset` body must carry in `confirm` to proceed (guards against accidental wipes).
const RESET_CONFIRM: &str = "DELETE";

/// Mount the `/v1/data/*` routes onto the shared `AppState` router. Auth is applied by `server.rs`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/data/retention", get(get_retention).post(set_retention))
        .route("/v1/data/purge", post(purge))
        .route("/v1/data/reset", post(reset))
}

fn paths() -> LocalResult<Paths> {
    Paths::resolve()
}

/// Read the retention window straight from the on-disk config so a value just saved via
/// `set_retention` is reflected immediately (the running `AppState.config` snapshot is fixed for the
/// process lifetime).
fn live_retention_days(paths: &Paths) -> u32 {
    config::load_config(paths).retention_days
}

#[derive(Debug, Deserialize)]
struct RetentionBody {
    /// New retention window in days (`0` = keep everything).
    days: u32,
}

#[derive(Debug, Deserialize, Default)]
struct PurgeBody {
    /// Optional override window for THIS purge only (does not persist). When omitted the saved
    /// retention setting is used.
    #[serde(default)]
    days: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct ResetBody {
    /// Must equal [`RESET_CONFIRM`] (`"DELETE"`) or the request is rejected.
    confirm: String,
    /// Also rotate the local vault root (old backups become unreadable). Default false.
    #[serde(default)]
    rotate_vault: bool,
}

/// `GET /v1/data/retention` — the live retention setting.
async fn get_retention(State(_st): State<AppState>) -> LocalResult<Json<Value>> {
    let paths = paths()?;
    Ok(Json(json!({ "retention_days": live_retention_days(&paths) })))
}

/// `POST /v1/data/retention` — persist the retention window to `~/.writ/config.toml` (`[app]`).
/// Takes effect on the next scheduler tick (and immediately for a manual `POST /v1/data/purge`),
/// so `needs_restart` is false.
async fn set_retention(
    State(_st): State<AppState>,
    Json(body): Json<RetentionBody>,
) -> LocalResult<Json<Value>> {
    let paths = paths()?;
    config::set_retention_days(&paths, body.days)?;
    tracing::info!(retention_days = body.days, "retention window persisted");
    Ok(Json(json!({ "retention_days": body.days, "needs_restart": false })))
}

/// `POST /v1/data/purge` — run the retention purge now. Uses `body.days` when supplied (one-off),
/// otherwise the saved setting. `0` (or a saved `0`) is a no-op.
async fn purge(State(st): State<AppState>, body: Option<Json<PurgeBody>>) -> LocalResult<Json<Value>> {
    let paths = paths()?;
    let days = body
        .and_then(|Json(b)| b.days)
        .unwrap_or_else(|| live_retention_days(&paths));
    let report = retention::purge_with_config(&st.db, &paths, days).await?;
    Ok(Json(serde_json::to_value(report).unwrap_or(Value::Null)))
}

/// `POST /v1/data/reset` — delete-all / factory reset. Requires `{"confirm":"DELETE"}`. Wipes the DB
/// + file/artifact stores (and optionally the vault root); the shell restarts the daemon afterward.
async fn reset(State(_st): State<AppState>, Json(body): Json<ResetBody>) -> LocalResult<Json<Value>> {
    if body.confirm != RESET_CONFIRM {
        return Err(LocalError::BadRequest(format!(
            "reset requires confirm = \"{RESET_CONFIRM}\""
        )));
    }
    let paths = paths()?;
    let report = backup::reset(&paths, body.rotate_vault)?;
    Ok(Json(json!({
        "db_removed": report.db_removed,
        "files_removed": report.files_removed,
        "artifacts_removed": report.artifacts_removed,
        "vault_rotated": report.vault_rotated,
        "needs_restart": report.needs_restart,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::config::LocalConfig;
    use crate::local::server::build_router;
    use crate::local::store::runs::{self, NewRun};
    use crate::local::{db, engine, vault};
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use std::sync::Arc;
    use tower::ServiceExt;

    const TOKEN: &str = "wlt_data_test";

    async fn test_state() -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("WRIT_HOME", dir.path().join(".writ"));
        std::env::remove_var("WRIT_RETENTION_DAYS");
        let paths = Paths::resolve().unwrap();
        paths.ensure_dirs().unwrap();
        let v = vault::Vault::load_or_create(&paths.root, false).unwrap();
        let pool = db::open(&paths.db(), &v.db_key_hex()).await.unwrap();
        crate::local::config::write_config(&paths, &LocalConfig::default()).unwrap();
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

    async fn call(st: &AppState, method: &str, uri: &str, body: Option<&str>) -> (u16, Value) {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {TOKEN}"))
            .header("content-type", "application/json")
            .body(body.map(|b| Body::from(b.to_string())).unwrap_or_else(Body::empty))
            .unwrap();
        let resp = build_router(st.clone()).oneshot(req).await.unwrap();
        let code = resp.status().as_u16();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let v: Value = if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap_or(Value::Null) };
        (code, v)
    }

    #[tokio::test]
    async fn retention_get_set_roundtrips() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state().await;

        // Default is the build default.
        let (code, body) = call(&st, "GET", "/v1/data/retention", None).await;
        assert_eq!(code, 200, "body={body}");
        assert_eq!(body["retention_days"], json!(config::DEFAULT_RETENTION_DAYS));

        // Persist a new value, then read it back.
        let (code, body) = call(&st, "POST", "/v1/data/retention", Some(r#"{"days":7}"#)).await;
        assert_eq!(code, 200, "body={body}");
        assert_eq!(body["days"].as_u64().or(body["retention_days"].as_u64()), Some(7));
        let (_c, body) = call(&st, "GET", "/v1/data/retention", None).await;
        assert_eq!(body["retention_days"], json!(7));

        std::env::remove_var("WRIT_HOME");
    }

    #[tokio::test]
    async fn purge_with_explicit_window_removes_old_runs() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state().await;

        let old = runs::insert(&st.db, &NewRun::default()).await.unwrap();
        sqlx::query("UPDATE runs SET created_at = '2000-01-01T00:00:00.000Z' WHERE id = ?1")
            .bind(old.id)
            .execute(&st.db)
            .await
            .unwrap();
        let recent = runs::insert(&st.db, &NewRun::default()).await.unwrap();

        let (code, body) = call(&st, "POST", "/v1/data/purge", Some(r#"{"days":30}"#)).await;
        assert_eq!(code, 200, "body={body}");
        assert_eq!(body["runs_deleted"], json!(1));
        assert!(runs::get_by_id(&st.db, old.id).await.unwrap().is_none());
        assert!(runs::get_by_id(&st.db, recent.id).await.unwrap().is_some());

        std::env::remove_var("WRIT_HOME");
    }

    #[tokio::test]
    async fn reset_requires_confirm_literal() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state().await;

        // Wrong confirm → 400, nothing wiped.
        let (code, _b) = call(&st, "POST", "/v1/data/reset", Some(r#"{"confirm":"nope"}"#)).await;
        assert_eq!(code, 400);
        assert!(Paths::resolve().unwrap().db().exists(), "db untouched on bad confirm");

        // Correct confirm → wipes the db + signals restart.
        let (code, body) = call(&st, "POST", "/v1/data/reset", Some(r#"{"confirm":"DELETE"}"#)).await;
        assert_eq!(code, 200, "body={body}");
        assert_eq!(body["needs_restart"], json!(true));
        assert!(!Paths::resolve().unwrap().db().exists(), "db wiped on confirm");
        assert_eq!(body["vault_rotated"], json!(false), "vault kept by default");

        std::env::remove_var("WRIT_HOME");
    }

    #[tokio::test]
    async fn routes_require_the_loopback_bearer() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state().await;
        let resp = build_router(st.clone())
            .oneshot(Request::builder().method("GET").uri("/v1/data/retention").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 401);
        std::env::remove_var("WRIT_HOME");
    }
}
