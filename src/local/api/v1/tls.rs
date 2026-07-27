//! `/v1/tls/*` — the local-HTTPS lane surface for the Tauri shell.
//!
//! The daemon serves its ENTIRE API (REST `/v1`, OpenAI-compat, `/mcp`, WebSockets) over a second
//! TLS listener (see `local::tls` + `server::spawn_tls_listener`) because some MCP / OpenAI-compat
//! clients refuse a plain `http://` base URL. The certificate chains to a per-install,
//! name-constrained local CA — these routes let the UI report that lane and get the CA trusted:
//!
//!   GET  /v1/tls/status → { enabled, https_base, endpoints{rest,openai_hint,mcp}, ca_path,
//!                           ca_fingerprint_sha256, ca_expires_at, leaf_expires_at,
//!                           trusted (best-effort bool|null), platform, manual_instructions,
//!                           node_hint }
//!   POST /v1/tls/trust  → install the CA into the OS *user* trust store (macOS login keychain via
//!                          `security`, Windows user Root via `certutil`; Linux returns manual
//!                          instructions). Returns { ok, method, detail }.
//!
//! NO key material ever appears here — the CA cert is public by definition (it's the anchor the
//! user installs); the CA key stays 0600 on disk and the leaf key never leaves process memory.
//! House style: thin handlers, `LocalResult<Json<_>>`, auth applied by `server.rs` at the top.

use crate::local::config::Paths;
use crate::local::error::{LocalError, LocalResult};
use crate::local::server::AppState;
use crate::local::tls;
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::time::Duration;

/// Mount the `/v1/tls/*` routes. Auth is applied by `server.rs` at the router level.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/tls/status", get(status))
        .route("/v1/tls/trust", post(trust))
}

/// How long an OS trust-store helper (`security` / `certutil`) may run before we give up. These
/// can block on a native auth prompt the user has to answer, so be generous.
const TRUST_CMD_TIMEOUT: Duration = Duration::from_secs(120);
/// The trust CHECK must never hang the status endpoint — it runs on every UI poll.
const CHECK_CMD_TIMEOUT: Duration = Duration::from_secs(5);

fn platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    }
}

/// Manual trust instructions per platform — always included so the UI can offer a fallback when
/// the one-click install is declined or unavailable.
fn manual_instructions(ca_path: &str) -> String {
    match platform() {
        "macos" => format!(
            "Import '{ca_path}' into Keychain Access (login keychain) and set 'Always Trust' for SSL, \
             or run: security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db '{ca_path}'"
        ),
        "windows" => format!("Run: certutil -user -addstore Root \"{ca_path}\""),
        _ => format!(
            "System store: sudo cp '{ca_path}' /usr/local/share/ca-certificates/writ-local-ca.crt && \
             sudo update-ca-certificates. Firefox/Chromium (NSS): certutil -d sql:$HOME/.pki/nssdb -A \
             -t 'C,,' -n 'Writ Local CA' -i '{ca_path}'"
        ),
    }
}

/// `GET /v1/tls/status` — the HTTPS lane's public facts + a best-effort trusted probe.
///
/// `enabled` reflects whether the TLS listener actually came up this boot (`tls::runtime_status`),
/// not just the config knob. Endpoint fields cover EVERY surface the lane serves (the TLS listener
/// mounts the same router as the plain one): the REST base, the per-workflow OpenAI-compat base
/// hint, and the MCP endpoint. `trusted` is null when the platform gives no cheap signal.
async fn status(State(_st): State<AppState>) -> LocalResult<Json<Value>> {
    let runtime = tls::runtime_status();
    let paths = Paths::resolve()?;
    let ca_path = paths.tls_dir().join("ca.pem");
    let ca_path_str = ca_path.to_string_lossy().into_owned();

    let (enabled, https_base, leaf_expires, ca_expires, fingerprint) = match runtime {
        Some(s) => (
            true,
            Some(format!("https://127.0.0.1:{}", s.port)),
            Some(s.leaf_expires_at.clone()),
            Some(s.ca_expires_at.clone()),
            Some(s.ca_fingerprint_sha256.clone()),
        ),
        // Lane not up (disabled or failed): still report the anchor facts if material exists so
        // the UI can render something useful.
        None => (
            false,
            None,
            None,
            None,
            tls::ca_fingerprint_from_disk(&paths).ok(),
        ),
    };

    let trusted = if ca_path.exists() { check_trusted(&ca_path_str).await } else { None };

    let endpoints = https_base.as_ref().map(|base| {
        json!({
            // Full REST surface (same routes as the plain lane).
            "rest": format!("{base}/v1"),
            // Per-workflow OpenAI-compat base derives from REST (cloud parity — no global base).
            "openai_hint": format!("{base}/v1/workflows/{{id}}/v1"),
            "mcp": format!("{base}/mcp"),
        })
    });

    Ok(Json(json!({
        "enabled": enabled,
        "https_base": https_base,
        "endpoints": endpoints,
        "ca_path": ca_path_str,
        "ca_fingerprint_sha256": fingerprint,
        "ca_expires_at": ca_expires,
        "leaf_expires_at": leaf_expires,
        "trusted": trusted,
        "platform": platform(),
        "manual_instructions": manual_instructions(&ca_path_str),
        // Node-based clients (Electron/CLI MCP hosts) don't read the OS store — they need this env.
        "node_hint": format!("NODE_EXTRA_CA_CERTS={ca_path_str}"),
    })))
}

/// `POST /v1/tls/trust` — one-click install of the local CA into the OS USER trust store. The OS
/// shows its own native confirmation (keychain prompt / certutil dialog); we surface the outcome.
async fn trust(State(_st): State<AppState>) -> LocalResult<Json<Value>> {
    let paths = Paths::resolve()?;
    let ca_path = paths.tls_dir().join("ca.pem");
    if !ca_path.exists() {
        return Err(LocalError::Internal(
            "tls: no local CA on disk yet (start the daemon with the HTTPS lane enabled first)".into(),
        ));
    }
    let ca = ca_path.to_string_lossy().into_owned();

    let (method, result) = match platform() {
        "macos" => {
            // Login keychain → per-user trust, native auth prompt, NO sudo. `-r trustRoot` marks the
            // cert as a trusted anchor for this user.
            let keychain = format!(
                "{}/Library/Keychains/login.keychain-db",
                std::env::var("HOME").unwrap_or_else(|_| "~".into())
            );
            (
                "security add-trusted-cert (login keychain)",
                run_checked(
                    "security",
                    &["add-trusted-cert", "-r", "trustRoot", "-k", &keychain, &ca],
                    TRUST_CMD_TIMEOUT,
                )
                .await,
            )
        }
        "windows" => (
            "certutil -user -addstore Root",
            run_checked("certutil", &["-user", "-addstore", "Root", &ca], TRUST_CMD_TIMEOUT).await,
        ),
        _ => {
            // Linux: no universal user store. Try NSS (covers Chromium/Firefox) when certutil
            // exists; the system store needs sudo, which we never invoke — manual instructions.
            let nssdb = format!("sql:{}/.pki/nssdb", std::env::var("HOME").unwrap_or_default());
            (
                "nss certutil (~/.pki/nssdb)",
                run_checked(
                    "certutil",
                    &["-d", &nssdb, "-A", "-t", "C,,", "-n", tls::CA_COMMON_NAME, "-i", &ca],
                    TRUST_CMD_TIMEOUT,
                )
                .await,
            )
        }
    };

    match result {
        Ok(()) => {
            tracing::info!(method, "local HTTPS CA installed into the OS user trust store");
            Ok(Json(json!({ "ok": true, "method": method, "detail": Value::Null })))
        }
        Err(detail) => {
            // Declined prompt / missing helper — NOT an HTTP error: the UI shows the manual path.
            tracing::warn!(method, %detail, "local CA trust install did not complete");
            Ok(Json(json!({
                "ok": false,
                "method": method,
                "detail": detail,
                "manual_instructions": manual_instructions(&ca),
            })))
        }
    }
}

/// Best-effort "is our CA already trusted?" probe. `None` = no cheap signal on this platform.
async fn check_trusted(ca_path: &str) -> Option<bool> {
    match platform() {
        // `security verify-cert` succeeds only when the cert chains to a trusted anchor — for a
        // self-signed CA that means ITS OWN trust-settings entry exists (user or admin domain).
        "macos" => run_checked("security", &["verify-cert", "-c", ca_path], CHECK_CMD_TIMEOUT)
            .await
            .map(|_| true)
            .ok()
            .or(Some(false)),
        // Present in the user Root store? (exit 0 when the named cert is found and verifies).
        "windows" => run_checked(
            "certutil",
            &["-user", "-verifystore", "Root", tls::CA_COMMON_NAME],
            CHECK_CMD_TIMEOUT,
        )
        .await
        .map(|_| true)
        .ok()
        .or(Some(false)),
        _ => None,
    }
}

/// Run a helper binary with a timeout; Ok(()) on exit 0, Err(detail) otherwise. Output is captured
/// (never streamed to the log wholesale — these helpers can echo file paths, which are fine, but we
/// keep the surface tight and only attach trimmed stderr on failure).
async fn run_checked(bin: &str, args: &[&str], timeout: Duration) -> Result<(), String> {
    let fut = tokio::process::Command::new(bin)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output();
    match tokio::time::timeout(timeout, fut).await {
        Err(_) => Err(format!("{bin} timed out after {}s", timeout.as_secs())),
        Ok(Err(e)) => Err(format!("{bin} failed to launch: {e}")),
        Ok(Ok(out)) if out.status.success() => Ok(()),
        Ok(Ok(out)) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            let detail = if stderr.trim().is_empty() { stdout } else { stderr };
            Err(format!("{bin} exited {}: {}", out.status, detail.trim()))
        }
    }
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

    const TOKEN: &str = "wlt_tls_secret";

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

    #[tokio::test]
    async fn status_reports_shape_and_no_key_material() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state().await;

        // Materialize the CA in the sandbox home so status has an anchor to describe.
        let paths = Paths::resolve().unwrap();
        crate::local::tls::load_or_create(&paths, &[]).unwrap();

        let resp = build_router(st)
            .oneshot(
                Request::builder()
                    .uri("/v1/tls/status")
                    .header("authorization", format!("Bearer {TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        // Shape: fields exist; enabled may be true if ANOTHER test in this process installed the
        // process-global runtime status (OnceLock) — accept both, but the anchor facts must be there.
        assert!(v["enabled"].is_boolean());
        assert!(v["ca_path"].as_str().unwrap().ends_with("ca.pem"));
        assert_eq!(v["ca_fingerprint_sha256"].as_str().unwrap().len(), 64, "hex sha256");
        assert!(v["manual_instructions"].is_string());
        assert!(v["node_hint"].as_str().unwrap().starts_with("NODE_EXTRA_CA_CERTS="));

        // NO private key material, ever.
        let raw = String::from_utf8_lossy(&bytes);
        assert!(!raw.contains("PRIVATE KEY"), "no key material in /v1/tls/status");
        std::env::remove_var("WRIT_HOME");
    }

    /// AC-2: installing the local CA into the OS user trust store is a DEVICE-wide trust decision, so
    /// it needs the explicitly-granted `manage` capability — `admin` (an ordinary "create a workflow"
    /// key) must not be able to plant a trust anchor. Reading the lane's public status stays a `read`.
    ///
    /// The refusal happens in `server::auth_mw`, i.e. BEFORE the handler, so this test never invokes
    /// the OS keychain/certutil helper.
    #[tokio::test]
    async fn trust_requires_manage_not_admin() {
        use crate::local::store::local_api_keys::{insert, NewLocalApiKey};
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state().await;

        let mint = |scopes: &'static str| {
            let db = st.db.clone();
            async move {
                let raw = format!("wlk_tls_{scopes}");
                let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
                sha2::Digest::update(&mut hasher, raw.as_bytes());
                let key_hash: String =
                    sha2::Digest::finalize(hasher).iter().map(|b| format!("{b:02x}")).collect();
                insert(
                    &db,
                    &NewLocalApiKey {
                        name: "k".into(),
                        prefix: "wlk_tls".into(),
                        key_hash,
                        scopes: Some(scopes.into()),
                    },
                )
                .await
                .unwrap();
                raw
            }
        };

        for scopes in ["read", "run", "admin"] {
            let key = mint(scopes).await;
            let resp = build_router(st.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/tls/trust")
                        .header("authorization", format!("Bearer {key}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), 403, "'{scopes}' must NOT install a trust anchor");
        }

        // A read key can still read the lane's status (unchanged).
        let read_key = mint("read").await;
        let resp = build_router(st.clone())
            .oneshot(
                Request::builder()
                    .uri("/v1/tls/status")
                    .header("authorization", format!("Bearer {read_key}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "status stays a plain read");
        std::env::remove_var("WRIT_HOME");
    }

    #[tokio::test]
    async fn tls_routes_require_bearer() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state().await;
        for (method, uri) in [("GET", "/v1/tls/status"), ("POST", "/v1/tls/trust")] {
            let resp = build_router(st.clone())
                .oneshot(Request::builder().method(method).uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), 401, "{method} {uri} must be bearer-gated");
        }
        std::env::remove_var("WRIT_HOME");
    }
}
