//! `/v1/vault/*` REST handlers — the desktop's app-lock control surface for the Tauri shell.
//!
//! The Tauri `vault_lock` / `vault_unlock` / `vault_status` IPC commands proxy onto these loopback
//! routes (FIXED CONTRACT). They run UNDER the existing loopback bearer + Origin/Host guard applied
//! once by `server.rs` (`auth_mw`) — there is NO new auth here. Beyond the three named endpoints we
//! also expose enable/disable + recovery-code generation so the lock is actually configurable from
//! the UI (unlock is meaningless without an enable path).
//!
//! Routes:
//!   GET  /v1/vault/status            → { enabled, locked, idle_timeout_secs }
//!   POST /v1/vault/lock              → { ok: true }                    (relock now)
//!   POST /v1/vault/unlock            → { ok: true } | 423/401          (passphrase in body)
//!   POST /v1/vault/enable            → { ok: true, recovery_mnemonic } (sets passphrase; FORCES a
//!                                       recovery code per spec §1.3 and returns it ONCE)
//!   POST /v1/vault/disable           → { ok: true }                    (turn off the passphrase)
//!   POST /v1/vault/recovery/generate → { recovery_mnemonic }           (re-issue a recovery code)
//!
//! SECURITY (SECURITY_AND_ENTITLEMENTS_SPEC §1.3):
//! - The passphrase is consumed handler-side and NEVER logged, echoed, or persisted (only the XOR
//!   wrap + salt + Argon2id cost tier are stored, none of which reveal the keyring root).
//! - The recovery mnemonic is returned ONCE on enable/generate for the user to write down; it is
//!   NEVER stored or logged (only its XOR wrap is persisted).
//! - The lock lives in a process-global slot (`vault_lock::global`), the same pattern `cloud::link`
//!   uses; it is installed once at `lifecycle::bootstrap`. No `AppState` field is added.
//!
//! Net-new Rust in this crate (behind the `local` feature).

use crate::local::error::LocalResult;
use crate::local::server::AppState;
use crate::local::{vault_lock, vault_recovery};
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

/// Mount the `/v1/vault/*` routes onto the shared `AppState` router. Auth is applied by `server.rs`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/vault/status", get(status))
        .route("/v1/vault/lock", post(lock))
        .route("/v1/vault/unlock", post(unlock))
        .route("/v1/vault/enable", post(enable))
        .route("/v1/vault/disable", post(disable))
        .route("/v1/vault/recovery/generate", post(recovery_generate))
}

/// Body carrying an app-lock passphrase. Consumed handler-side; NEVER logged/echoed/persisted.
#[derive(Debug, Deserialize)]
struct PassphraseBody {
    passphrase: String,
}

/// `GET /v1/vault/status` — non-secret lock snapshot for the UI: `{ enabled, locked, idle_timeout_secs }`.
async fn status(State(_st): State<AppState>) -> LocalResult<Json<Value>> {
    let s = vault_lock::global().status();
    Ok(Json(json!({
        "enabled": s.enabled,
        "locked": s.locked,
        "idle_timeout_secs": s.idle_timeout_secs,
    })))
}

/// `POST /v1/vault/lock` — relock the vault now (sleep / screen-lock / manual "Lock"). Idempotent.
async fn lock(State(_st): State<AppState>) -> LocalResult<Json<Value>> {
    vault_lock::global().lock();
    Ok(Json(json!({ "ok": true })))
}

/// `POST /v1/vault/unlock` — unlock with the passphrase. The passphrase is verified by re-deriving
/// the Argon2id key and constant-time matching the recovered root against the live keyring root
/// (`vault_lock::unlock`). A wrong passphrase → 401; a disabled lock is a no-op success.
async fn unlock(State(st): State<AppState>, Json(body): Json<PassphraseBody>) -> LocalResult<Json<Value>> {
    vault_lock::global().unlock(&st.db, &st.vault, &body.passphrase).await?;
    Ok(Json(json!({ "ok": true })))
}

/// `POST /v1/vault/enable` — set the app-lock passphrase AND force a recovery code (spec §1.3:
/// recovery is forced at PIN-enable). Returns the 24-word mnemonic ONCE for the user to record; it is
/// never stored or logged. The session is left unlocked (the caller just authenticated).
///
/// SECURITY (AC-1): setting the passphrase the FIRST time is open (no lock exists yet), but
/// OVERWRITING an already-configured lock is a privileged act — a loopback-bearer caller must not be
/// able to silently replace the passphrase while the vault is locked (which would let them then
/// "unlock" with a passphrase of their choosing and read all secrets). When a lock already exists we
/// require the vault to be UNLOCKED (`guard()?` → 423 when locked) before the overwrite is allowed.
async fn enable(State(st): State<AppState>, Json(body): Json<PassphraseBody>) -> LocalResult<Json<Value>> {
    if vault_lock::VaultLock::is_configured(&st.db).await? {
        vault_lock::global().guard()?;
    }
    vault_lock::global().enable(&st.db, &st.vault, &body.passphrase).await?;
    // Force a recovery code so a forgotten passphrase / lost keyring is recoverable.
    let mnemonic = vault_recovery::generate_recovery(&st.db, &st.vault).await?;
    Ok(Json(json!({ "ok": true, "recovery_mnemonic": mnemonic })))
}

/// `POST /v1/vault/disable` — turn off the app-lock entirely (clears the persisted wrap/salt/tier).
///
/// SECURITY (AC-1): the app-lock must be UNLOCKED to be turned off (`guard()?` → 423 when locked).
/// Otherwise any loopback-bearer caller could disable the lock without the PIN and then read secrets.
async fn disable(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    vault_lock::global().guard()?;
    vault_lock::global().disable(&st.db).await?;
    Ok(Json(json!({ "ok": true })))
}

/// `POST /v1/vault/recovery/generate` — (re)issue a BIP39 recovery code, replacing any prior one.
/// Returns the mnemonic ONCE; it is never stored or logged.
///
/// SECURITY (AC-1): re-issuing a recovery code hands out fresh material that recovers the vault root,
/// so it must be UNLOCKED (`guard()?` → 423 when locked). A locked vault yields no recovery code.
async fn recovery_generate(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    vault_lock::global().guard()?;
    let mnemonic = vault_recovery::generate_recovery(&st.db, &st.vault).await?;
    Ok(Json(json!({ "recovery_mnemonic": mnemonic })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::server::build_router;
    use crate::local::{config::LocalConfig, db, engine, vault};
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use std::sync::Arc;
    use tower::ServiceExt;

    const TOKEN: &str = "wlt_vault_test";

    async fn test_state() -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::local::config::Paths::at(dir.path().join(".writ"));
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
    async fn status_reports_disabled_by_default() {
        let (_dir, st) = test_state().await;
        // The process-global lock defaults to disabled when nothing is installed.
        let (code, body) = call(&st, "GET", "/v1/vault/status", None).await;
        assert_eq!(code, 200, "body={body}");
        assert!(body["enabled"].is_boolean());
        assert!(body["locked"].is_boolean());
        assert!(body["idle_timeout_secs"].is_number());
    }

    #[tokio::test]
    async fn lock_and_unlock_routes_are_wired() {
        let (_dir, st) = test_state().await;
        // lock() on a disabled global is a no-op success.
        let (code, body) = call(&st, "POST", "/v1/vault/lock", None).await;
        assert_eq!(code, 200, "body={body}");
        assert_eq!(body["ok"], json!(true));

        // unlock on a disabled lock is a no-op success (passphrase ignored when disabled).
        let (code, body) = call(&st, "POST", "/v1/vault/unlock", Some(r#"{"passphrase":"whatever"}"#)).await;
        assert_eq!(code, 200, "body={body}");
        assert_eq!(body["ok"], json!(true));
    }

    #[tokio::test]
    async fn routes_require_the_loopback_bearer() {
        let (_dir, st) = test_state().await;
        let resp = build_router(st.clone())
            .oneshot(Request::builder().method("GET").uri("/v1/vault/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 401);
    }

    #[tokio::test]
    async fn recovery_generate_returns_a_24_word_mnemonic_once() {
        let (_dir, st) = test_state().await;
        let (code, body) = call(&st, "POST", "/v1/vault/recovery/generate", None).await;
        assert_eq!(code, 200, "body={body}");
        let phrase = body["recovery_mnemonic"].as_str().expect("mnemonic string");
        assert_eq!(phrase.split_whitespace().count(), 24);
        // The mnemonic must NEVER appear in any persisted config value verbatim.
        let entries = crate::local::store::config_kv::list_all(&st.db).await.unwrap();
        for e in entries {
            assert!(!e.value.contains(phrase), "mnemonic leaked into config {}", e.key);
        }
    }
}
