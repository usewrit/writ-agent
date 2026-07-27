//! `/v1/backup/*` REST handlers — encrypted backup export / inspect / restore (PROD-16).
//!
//! These run UNDER the loopback bearer + Origin/Host guard `server.rs` applies once (no new auth).
//! The Tauri shell proxies a "Back up / Restore" UI onto them.
//!
//! Routes (FIXED CONTRACT):
//!   POST /v1/backup/export   { passphrase, dest? }      → { path, bytes, schema_version, created_at,
//!                                                           download_url, download_id }
//!   GET  /v1/backup/download ?id=<opaque>               → streams the encrypted archive bytes
//!                            ?path=<abs>                  (legacy, hardened — see below)
//!   POST /v1/backup/inspect  { path, passphrase }       → manifest (app/schema versions + entries)
//!   POST /v1/backup/restore  { path, passphrase }       → { needs_restart, previous_db_backup, … }
//!
//! SECURITY:
//! - The passphrase is consumed handler-side and NEVER logged/echoed/persisted. The encrypted archive
//!   is age-sealed under it; the daemon's live SQLCipher key (vault-rooted) is what makes the restored
//!   DB readable on THIS device (a foreign-key archive fails restore validation, see `backup::restore`).
//! - `restore` only SWAPS the DB file; the running pool still holds the old handle, so the handler
//!   returns `needs_restart=true` and the Tauri shell restarts the sidecar to pick up the restored DB.
//! - `download` hands over an encrypted copy of the WHOLE device state, so it requires the `manage`
//!   capability (`auth::is_privileged_read_path`) — `admin`, and the `run` grant every OAuth consent
//!   issues, cannot reach it. On top of that scope gate it applies THREE independent content gates
//!   (see [`resolve_download`]): an opaque, TTL'd, few-use export id minted by `export` (preferred, no
//!   caller-supplied path at all); home-root containment; and a passphrase-free age-header sniff plus a
//!   sensitive-basename denylist. Containment alone was NOT sufficient here: `~/.writ` is exactly where
//!   `vault.key`, `runtime.json` (the master `wlt_` bearer), `writ.db` and `tls/ca.key` live, so a
//!   contained-but-unfiltered read of "any file under the home" WAS a vault-root + full-access-token
//!   disclosure.
//!
//! Net-new Rust in this crate (behind the `local` feature).

use std::path::{Path as FsPath, PathBuf};
use std::sync::Mutex;

use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use rand::RngCore as _;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::local::backup;
use crate::local::config::Paths;
use crate::local::error::{LocalError, LocalResult};
use crate::local::server::AppState;

/// Mount the `/v1/backup/*` routes onto the shared `AppState` router. Auth is applied by `server.rs`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/backup/export", post(export))
        .route("/v1/backup/download", get(download))
        .route("/v1/backup/inspect", post(inspect))
        .route("/v1/backup/restore", post(restore))
}

/// Resolve the canonical `~/.writ/` (or `$WRIT_HOME`) layout — the same root the daemon booted from.
fn paths() -> LocalResult<Paths> {
    Paths::resolve()
}

#[derive(Debug, Deserialize)]
struct ExportBody {
    /// User passphrase the archive is age-sealed under. Required (non-empty).
    passphrase: String,
    /// Optional destination path. When omitted, the archive lands at `~/.writ/writ-backup.age`. A
    /// supplied dest MUST resolve under the home root (no writing arbitrary files off-tree).
    #[serde(default)]
    dest: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ArchiveBody {
    /// Absolute path of the encrypted archive to inspect/restore.
    path: String,
    passphrase: String,
}

/// `GET /v1/backup/download` accepts EITHER an opaque export id (preferred: minted by `export`, no
/// filesystem path in the request at all) or — for the existing desktop "save the archive" call, which
/// re-downloads an archive it already knows the path of — a `path`, which is then put through the full
/// containment + content guard. Neither is trusted on its own; see [`resolve_download`].
#[derive(Debug, Deserialize)]
struct DownloadQuery {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    path: Option<String>,
}

// ── download grants (opaque export ids) ──────────────────────────────────────────────────────────

/// How long a minted download id stays valid. Long enough for the shell to stream the bytes (and for
/// the user to retry once), short enough that a leaked URL is worthless minutes later.
const DOWNLOAD_TTL_SECS: i64 = 600;
/// How many times one id may be redeemed. NOT one: a browser/axios retry, or a shell that streams the
/// URL twice (e.g. HEAD-then-GET), would otherwise fail the user's export outright. Small enough that
/// the id is not a durable capability.
const DOWNLOAD_MAX_USES: u32 = 3;

/// One minted download capability: the REAL path, plus its expiry and remaining redemptions.
#[derive(Debug, Clone)]
struct DownloadGrant {
    path: PathBuf,
    created_unix: i64,
    uses_left: u32,
}

/// In-process grant table. In-memory ON PURPOSE — a daemon restart should invalidate every outstanding
/// download URL (nothing here is worth persisting, and persisting it would create a second, durable
/// pointer at an archive). Same shape/lifecycle as the OAuth consent-transaction table.
static DOWNLOADS: Mutex<Option<std::collections::HashMap<String, DownloadGrant>>> = Mutex::new(None);

fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Mint an opaque, non-guessable download id for `path` (32 bytes of OS entropy, base64url). The id
/// is the ONLY thing that crosses the API boundary; the path stays process-side.
fn mint_download_grant(path: &FsPath) -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    let id = format!("bkd_{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b));
    let mut guard = DOWNLOADS.lock().unwrap();
    let map = guard.get_or_insert_with(std::collections::HashMap::new);
    // Opportunistic expiry sweep — the table only ever holds in-flight downloads.
    let now = now_unix();
    map.retain(|_, g| now - g.created_unix < DOWNLOAD_TTL_SECS);
    map.insert(
        id.clone(),
        DownloadGrant { path: path.to_path_buf(), created_unix: now, uses_left: DOWNLOAD_MAX_USES },
    );
    id
}

/// Redeem a download id: returns the recorded path and consumes one use (removing the entry when its
/// budget or TTL is exhausted). An unknown/expired/spent id yields `None`.
fn redeem_download_grant(id: &str) -> Option<PathBuf> {
    let mut guard = DOWNLOADS.lock().unwrap();
    let map = guard.get_or_insert_with(std::collections::HashMap::new);
    let now = now_unix();
    let g = map.get_mut(id)?;
    if now - g.created_unix >= DOWNLOAD_TTL_SECS {
        map.remove(id);
        return None;
    }
    let path = g.path.clone();
    g.uses_left = g.uses_left.saturating_sub(1);
    if g.uses_left == 0 {
        map.remove(id);
    }
    Some(path)
}

/// `POST /v1/backup/export` — write an encrypted backup archive and return its path + a download URL.
/// NEVER logs the passphrase.
async fn export(State(st): State<AppState>, Json(body): Json<ExportBody>) -> LocalResult<Json<Value>> {
    let paths = paths()?;
    let dest = match body.dest.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(d) => Some(resolve_dest_under_home(&paths, d)?),
        None => None,
    };
    let db_key = st.vault.db_key_hex();
    let report = backup::export(&paths, &body.passphrase, &db_key, dest.as_deref()).await?;
    // Mint an OPAQUE download id rather than putting the archive's path in the URL: the download route
    // then needs no caller-supplied filesystem path at all (the strongest form of the guard).
    let download_id = mint_download_grant(FsPath::new(&report.path));
    Ok(Json(json!({
        "path": report.path,
        "bytes": report.bytes,
        "schema_version": report.schema_version,
        "created_at": report.created_at,
        // A bearer-gated stream URL so the shell/browser can save the bytes without a second IPC hop.
        "download_url": format!("/v1/backup/download?id={}", urlencode(&download_id)),
        "download_id": download_id,
    })))
}

/// `GET /v1/backup/download?id=` (or the legacy `?path=`) — stream an encrypted archive's bytes.
///
/// Requires the `manage` capability (see the module header): this response IS the device's state.
async fn download(State(_st): State<AppState>, Query(q): Query<DownloadQuery>) -> LocalResult<Response> {
    let paths = paths()?;
    let path = resolve_download(&paths, &q)?;
    let bytes = std::fs::read(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            LocalError::NotFound(format!("backup {}", path.display()))
        } else {
            LocalError::Io(e)
        }
    })?;
    let filename = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(backup::DEFAULT_BACKUP_NAME);
    let disposition = format!("attachment; filename=\"{filename}\"");
    let resp = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, bytes.len())
        .header(header::CONTENT_DISPOSITION, disposition)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(bytes))
        .map_err(|e| LocalError::Internal(format!("building backup response: {e}")))?;
    Ok(resp.into_response())
}

/// `POST /v1/backup/inspect` — decrypt + validate an archive (no live file touched) and return its
/// manifest so the UI can preview a restore (versions, entries) and confirm the passphrase is right.
async fn inspect(State(_st): State<AppState>, Json(body): Json<ArchiveBody>) -> LocalResult<Json<Value>> {
    let path = validate_archive_path(&body.path)?;
    let manifest = backup::inspect(&path, &body.passphrase).map_err(map_archive_error)?;
    Ok(Json(serde_json::to_value(manifest).unwrap_or(Value::Null)))
}

/// `POST /v1/backup/restore` — atomically restore an archive over the live home (write-temp →
/// validate under the live vault key → swap, keeping a rollback copy). Returns `needs_restart=true`;
/// the shell restarts the daemon to load the restored DB. NEVER logs the passphrase or the db key.
async fn restore(State(st): State<AppState>, Json(body): Json<ArchiveBody>) -> LocalResult<Json<Value>> {
    let paths = paths()?;
    let archive = validate_archive_path(&body.path)?;
    let db_key = st.vault.db_key_hex();
    let report = backup::restore(&paths, &archive, &body.passphrase, &db_key)
        .await
        .map_err(map_archive_error)?;
    Ok(Json(json!({
        "needs_restart": report.needs_restart,
        "previous_db_backup": report.previous_db_backup,
        "schema_version": report.schema_version,
    })))
}

// ── path safety ──────────────────────────────────────────────────────────────────────────────────

/// Resolve a caller-supplied EXPORT dest, asserting it lands under the home root (the parent is
/// canonicalized; the file itself need not exist yet). Rejects traversal off the tree.
fn resolve_dest_under_home(paths: &Paths, dest: &str) -> LocalResult<PathBuf> {
    let candidate = PathBuf::from(dest);
    // Make relative dests relative to the home root.
    let candidate = if candidate.is_absolute() { candidate } else { paths.root.join(candidate) };
    let parent = candidate
        .parent()
        .ok_or_else(|| LocalError::BadRequest("dest has no parent directory".into()))?;
    std::fs::create_dir_all(parent)?;
    let canon_parent = parent
        .canonicalize()
        .map_err(|e| LocalError::BadRequest(format!("dest parent not resolvable: {e}")))?;
    let canon_home = paths
        .root
        .canonicalize()
        .map_err(|e| LocalError::Internal(format!("home not resolvable: {e}")))?;
    if !canon_parent.starts_with(&canon_home) {
        return Err(LocalError::BadRequest("backup dest must be under the Writ home".into()));
    }
    let name = candidate
        .file_name()
        .ok_or_else(|| LocalError::BadRequest("dest has no filename".into()))?;
    Ok(canon_parent.join(name))
}

/// Basenames that must NEVER be served by `download`, whatever else says otherwise.
///
/// Belt-and-braces next to the age-header sniff: these are the exact files whose disclosure IS the
/// compromise — the vault root, the discovery descriptor carrying the master `wlt_` bearer, the token
/// file, the live database (+ its sidecars) and the local CA's private key. Should a future change ever
/// weaken the format check, these still cannot leave. Matched on the file name so a copy of one of them
/// anywhere under the home is covered too.
const NEVER_DOWNLOAD: &[&str] = &[
    "vault.key",
    "runtime.json",
    "local_token",
    "writ.db",
    "writ.db-wal",
    "writ.db-shm",
    "ca.key",
    "leaf.key",
];

/// Resolve what `GET /v1/backup/download` is allowed to stream.
///
/// Preference order:
///   1. `id` — an opaque grant minted by `export` ([`mint_download_grant`]). No path in the request, so
///      there is nothing for a caller to steer; the recorded path still goes through the content gates
///      below (defense in depth — the grant table is not the only check).
///   2. `path` — the legacy shape the desktop's "save the archive" call still uses. Accepted only after
///      containment + content gates.
///
/// Gates applied to the resolved path in BOTH cases:
///   * canonicalized containment under the Writ home (blocks `..`/symlink escape),
///   * the [`NEVER_DOWNLOAD`] basename denylist,
///   * a passphrase-free age-header sniff ([`backup::looks_like_archive`]).
///
/// The last two are what close the real hole: containment alone still allowed `vault.key`,
/// `runtime.json` (master bearer) and `writ.db` — all of which live UNDER the home root — to be read
/// out through a route that only ever needs to serve encrypted archives. Failures are `Forbidden`
/// rather than a distinguishing error so the endpoint is not also a file-probing oracle.
fn resolve_download(paths: &Paths, q: &DownloadQuery) -> LocalResult<PathBuf> {
    let candidate = match q.id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(id) => match redeem_download_grant(id) {
            Some(p) => p,
            None => {
                // Unknown, expired, or already-spent id. Never says which.
                tracing::warn!("backup download rejected: unknown or expired download id");
                return Err(LocalError::Forbidden);
            }
        },
        None => match q.path.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(p) => PathBuf::from(p),
            None => {
                return Err(LocalError::BadRequest(
                    "backup download needs an `id` (from POST /v1/backup/export) or a `path`".into(),
                ))
            }
        },
    };

    let canon = resolve_existing_under_home(paths, &candidate.to_string_lossy())?;
    let name = canon.file_name().and_then(|s| s.to_str()).unwrap_or_default();
    if NEVER_DOWNLOAD.contains(&name) {
        tracing::warn!(file = %name, "backup download refused: sensitive device file, never downloadable");
        return Err(LocalError::Forbidden);
    }
    if !backup::looks_like_archive(&canon) {
        tracing::warn!(
            file = %name,
            "backup download refused: not an encrypted Writ archive (this route serves archives only)"
        );
        return Err(LocalError::Forbidden);
    }
    Ok(canon)
}

/// Resolve an EXISTING archive path, asserting (via canonicalization) it sits under the home root so
/// the bearer-gated download can't be steered at an arbitrary file. Canonicalization resolves symlinks
/// FIRST, so a symlink planted inside the home that points outside it is rejected too.
fn resolve_existing_under_home(paths: &Paths, p: &str) -> LocalResult<PathBuf> {
    let canon = PathBuf::from(p.trim())
        .canonicalize()
        // Uniform `Forbidden` (not `NotFound`): a distinguishable "missing" answer would make this
        // route a file-existence oracle for anything on the filesystem.
        .map_err(|_| LocalError::Forbidden)?;
    let canon_home = paths
        .root
        .canonicalize()
        .map_err(|e| LocalError::Internal(format!("home not resolvable: {e}")))?;
    if !canon.starts_with(&canon_home) {
        return Err(LocalError::Forbidden);
    }
    Ok(canon)
}

/// Validate a caller-supplied archive path for `inspect`/`restore`.
///
/// NOT containment-checked, deliberately: the desktop restore flow is a native FILE PICKER, so the
/// archive the user chose legitimately lives wherever they saved it (`~/Downloads`, an external drive,
/// …). Requiring it under `~/.writ` would break restore outright for the normal case.
///
/// What it DOES enforce is enough to close the oracle these two routes formed. Previously any path was
/// passed straight to the decryptor, and the error variants (`NotFound` vs `Decrypt` vs `BadMagic`)
/// distinguished "this file exists and is readable" from "it does not" for arbitrary filesystem paths.
/// Now: the sensitive-basename denylist and the age-header sniff must both pass, and EVERY rejection —
/// missing file, unreadable file, not-an-archive, denylisted name — collapses into the SAME message the
/// wrong-passphrase case produces. An `admin` key therefore learns nothing about the filesystem it
/// could not already learn by guessing a passphrase.
fn validate_archive_path(p: &str) -> LocalResult<PathBuf> {
    let path = PathBuf::from(p.trim());
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or_default();
    if !NEVER_DOWNLOAD.contains(&name) && backup::looks_like_archive(&path) {
        return Ok(path);
    }
    Err(archive_rejected())
}

/// The SINGLE failure `inspect`/`restore` report for any archive they cannot use — bad path, missing
/// file, unreadable file, not-an-archive, denylisted name, OR wrong passphrase.
///
/// One message for all of them is the whole point: distinguishable errors are what made these routes a
/// file oracle. It stays actionable for the user who genuinely mistyped a passphrase or picked the
/// wrong file, since those are by far the likeliest causes.
fn archive_rejected() -> LocalError {
    LocalError::BadRequest(
        "not a readable Writ backup archive (wrong file, wrong passphrase, or damaged archive)".into(),
    )
}

/// Collapse the archive-OPENING failures into [`archive_rejected`], leaving genuinely internal
/// failures alone. `Decrypt`/`BadMagic`/`BadManifest`/`NotFound`/`Io` all describe "this file is not a
/// usable archive (or you gave the wrong passphrase)" and must be indistinguishable; everything else
/// (e.g. `RestoreValidation` — the archive DID open, but its database failed the live-key check) is a
/// real, non-oracle diagnostic the user needs.
fn map_archive_error(e: backup::BackupError) -> LocalError {
    match e {
        backup::BackupError::Decrypt
        | backup::BackupError::BadMagic
        | backup::BackupError::BadManifest(_)
        | backup::BackupError::NotFound(_)
        | backup::BackupError::Io(_) => archive_rejected(),
        other => LocalError::from(other),
    }
}

/// Minimal percent-encoding for the `path` query value in the returned download URL (spaces + a few
/// reserved chars). The path is the daemon's own home path; this just keeps the URL well-formed.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
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

    const TOKEN: &str = "wlt_backup_test";

    async fn test_state() -> (tempfile::TempDir, AppState, String) {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("WRIT_HOME", dir.path().join(".writ"));
        let paths = Paths::resolve().unwrap();
        paths.ensure_dirs().unwrap();
        let v = vault::Vault::load_or_create(&paths.root, false).unwrap();
        let key = v.db_key_hex();
        let pool = db::open(&paths.db(), &key).await.unwrap();
        sqlx::query("INSERT INTO config (key, value) VALUES ('marker', 'present')")
            .execute(&pool)
            .await
            .unwrap();
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
        (dir, st, key)
    }

    async fn call(st: &AppState, method: &str, uri: &str, body: Option<&str>) -> (u16, Value) {
        call_as(st, TOKEN, method, uri, body).await
    }

    async fn call_as(
        st: &AppState,
        bearer: &str,
        method: &str,
        uri: &str,
        body: Option<&str>,
    ) -> (u16, Value) {
        let (code, bytes) = call_raw(st, bearer, method, uri, body).await;
        let v: Value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        (code, v)
    }

    /// Like [`call_as`] but returns the raw body — the download route streams octets, not JSON.
    async fn call_raw(
        st: &AppState,
        bearer: &str,
        method: &str,
        uri: &str,
        body: Option<&str>,
    ) -> (u16, Vec<u8>) {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {bearer}"))
            .header("content-type", "application/json")
            .body(body.map(|b| Body::from(b.to_string())).unwrap_or_else(Body::empty))
            .unwrap();
        let resp = build_router(st.clone()).oneshot(req).await.unwrap();
        let code = resp.status().as_u16();
        let bytes = to_bytes(resp.into_body(), 8 << 20).await.unwrap().to_vec();
        (code, bytes)
    }

    /// Mint a scoped `wlk_` key directly in the store; returns the raw bearer.
    async fn mint_key(st: &AppState, scopes: &str) -> String {
        use crate::local::store::local_api_keys::{insert, NewLocalApiKey};
        let raw = format!("wlk_backup_{}", scopes.replace(',', "_"));
        let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
        sha2::Digest::update(&mut hasher, raw.as_bytes());
        let key_hash: String =
            sha2::Digest::finalize(hasher).iter().map(|b| format!("{b:02x}")).collect();
        insert(
            &st.db,
            &NewLocalApiKey {
                name: "k".into(),
                prefix: "wlk_backup".into(),
                key_hash,
                scopes: Some(scopes.into()),
            },
        )
        .await
        .unwrap();
        raw
    }

    #[tokio::test]
    async fn export_inspect_restore_roundtrip() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st, _key) = test_state().await;

        // Export.
        let (code, body) = call(&st, "POST", "/v1/backup/export", Some(r#"{"passphrase":"pw-123"}"#)).await;
        assert_eq!(code, 200, "body={body}");
        let path = body["path"].as_str().unwrap().to_string();
        assert!(std::path::Path::new(&path).exists());

        // Inspect with the right passphrase reflects the manifest.
        let inspect_body = format!(r#"{{"path":"{path}","passphrase":"pw-123"}}"#);
        let (code, body) = call(&st, "POST", "/v1/backup/inspect", Some(&inspect_body)).await;
        assert_eq!(code, 200, "body={body}");
        assert!(body["entries"].as_array().unwrap().iter().any(|e| e["name"] == "writ.db"));

        // Restore signals a needed restart + keeps a rollback copy.
        let restore_body = format!(r#"{{"path":"{path}","passphrase":"pw-123"}}"#);
        let (code, body) = call(&st, "POST", "/v1/backup/restore", Some(&restore_body)).await;
        assert_eq!(code, 200, "body={body}");
        assert_eq!(body["needs_restart"], json!(true));

        std::env::remove_var("WRIT_HOME");
    }

    #[tokio::test]
    async fn export_rejects_empty_passphrase() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st, _key) = test_state().await;
        let (code, _body) = call(&st, "POST", "/v1/backup/export", Some(r#"{"passphrase":"  "}"#)).await;
        assert_eq!(code, 400, "empty passphrase is a 400");
        std::env::remove_var("WRIT_HOME");
    }

    #[tokio::test]
    async fn inspect_wrong_passphrase_is_400() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st, _key) = test_state().await;
        let (_c, body) = call(&st, "POST", "/v1/backup/export", Some(r#"{"passphrase":"right"}"#)).await;
        let path = body["path"].as_str().unwrap().to_string();
        let wrong = format!(r#"{{"path":"{path}","passphrase":"wrong"}}"#);
        let (code, _b) = call(&st, "POST", "/v1/backup/inspect", Some(&wrong)).await;
        assert_eq!(code, 400, "wrong passphrase decrypt failure maps to 400");
        std::env::remove_var("WRIT_HOME");
    }

    /// THE FIX for the vault-root / master-bearer disclosure: `download` may only ever emit an
    /// encrypted archive. Containment under `~/.writ` was already enforced and was NOT enough — the
    /// home root is precisely where `vault.key`, `runtime.json` (the `wlt_` master bearer) and
    /// `writ.db` live.
    #[tokio::test]
    async fn download_refuses_every_sensitive_home_file() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st, _key) = test_state().await;
        let paths = Paths::resolve().unwrap();

        // A real archive downloads fine (via its minted id AND via its path).
        let (_c, body) = call(&st, "POST", "/v1/backup/export", Some(r#"{"passphrase":"pw"}"#)).await;
        let archive_path = body["path"].as_str().unwrap().to_string();
        let dl_url = body["download_url"].as_str().unwrap().to_string();
        assert!(dl_url.starts_with("/v1/backup/download?id=bkd_"), "opaque id URL, got {dl_url}");
        assert!(!dl_url.contains(".writ"), "no filesystem path in the download URL");

        let (code, bytes) = call_raw(&st, TOKEN, "GET", &dl_url, None).await;
        assert_eq!(code, 200, "the just-exported archive streams by id");
        assert_eq!(&bytes[..backup::AGE_STREAM_MAGIC.len()], backup::AGE_STREAM_MAGIC);

        let by_path =
            format!("/v1/backup/download?path={}", urlencode(&archive_path));
        let (code, _b) = call_raw(&st, TOKEN, "GET", &by_path, None).await;
        assert_eq!(code, 200, "the legacy ?path= shape still works for a real archive");

        // Every crown jewel in the SAME directory is refused — this is the disclosure that existed.
        std::fs::write(paths.root.join("runtime.json"), br#"{"token":"wlt_master_bearer"}"#).unwrap();
        std::fs::write(paths.root.join("local_token"), b"wlt_master_bearer").unwrap();
        for name in ["vault.key", "runtime.json", "local_token", "writ.db", "config.toml"] {
            let p = paths.root.join(name);
            assert!(p.exists(), "{name} must exist for this test to mean anything");
            let uri = format!("/v1/backup/download?path={}", urlencode(&p.to_string_lossy()));
            let (code, bytes) = call_raw(&st, TOKEN, "GET", &uri, None).await;
            assert_eq!(code, 403, "downloading {name} must be forbidden");
            let raw = String::from_utf8_lossy(&bytes);
            assert!(!raw.contains("wlt_master_bearer"), "{name}: no secret bytes may leak");
        }

        // Traversal off the tree, and a nonexistent path, are the SAME uniform refusal (no oracle).
        for uri in [
            "/v1/backup/download?path=%2Fetc%2Fpasswd",
            "/v1/backup/download?path=%2Fetc%2Fdefinitely-not-here-9f3a",
            "/v1/backup/download?id=bkd_forged",
        ] {
            let (code, _b) = call_raw(&st, TOKEN, "GET", uri, None).await;
            assert_eq!(code, 403, "{uri} must be a uniform 403");
        }
        // Neither parameter → a plain 400 (a shape error, not an authorization signal).
        let (code, _b) = call_raw(&st, TOKEN, "GET", "/v1/backup/download", None).await;
        assert_eq!(code, 400);

        std::env::remove_var("WRIT_HOME");
    }

    /// A minted download id is short-lived and few-use: it stops working once its budget is spent, so
    /// a leaked URL is not a durable capability.
    #[tokio::test]
    async fn download_id_is_few_use() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st, _key) = test_state().await;
        let (_c, body) = call(&st, "POST", "/v1/backup/export", Some(r#"{"passphrase":"pw"}"#)).await;
        let dl_url = body["download_url"].as_str().unwrap().to_string();

        for i in 1..=DOWNLOAD_MAX_USES {
            let (code, _b) = call_raw(&st, TOKEN, "GET", &dl_url, None).await;
            assert_eq!(code, 200, "redemption {i} of {DOWNLOAD_MAX_USES} must succeed");
        }
        let (code, _b) = call_raw(&st, TOKEN, "GET", &dl_url, None).await;
        assert_eq!(code, 403, "the id is spent after {DOWNLOAD_MAX_USES} redemptions");
        std::env::remove_var("WRIT_HOME");
    }

    /// AC-2 scope gate: `download` hands over the whole device, so it needs `manage`. A `run`-scoped
    /// credential — exactly what every OAuth consent grants, under a page promising the client "cannot
    /// manage keys, secrets, or device settings" — must not reach it, and neither must plain `admin`.
    #[tokio::test]
    async fn download_requires_manage_not_read_or_admin() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st, _key) = test_state().await;
        let (_c, body) = call(&st, "POST", "/v1/backup/export", Some(r#"{"passphrase":"pw"}"#)).await;
        let dl_url = body["download_url"].as_str().unwrap().to_string();

        for scopes in ["read", "run", "admin", "read,run,admin"] {
            let key = mint_key(&st, scopes).await;
            let (code, _b) = call_raw(&st, &key, "GET", &dl_url, None).await;
            assert_eq!(code, 403, "'{scopes}' must NOT be able to download the device backup");
        }
        // An explicitly-issued `manage` key may (that is what the capability is for).
        let manage = mint_key(&st, "manage").await;
        let (code, _b) = call_raw(&st, &manage, "GET", &dl_url, None).await;
        assert_eq!(code, 200, "a manage key may download");
        std::env::remove_var("WRIT_HOME");
    }

    /// `inspect`/`restore` no longer form a file-existence oracle: a non-archive path, a missing path
    /// and a wrong passphrase are ALL the same 400 with the same message.
    #[tokio::test]
    async fn inspect_is_not_a_file_existence_oracle() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st, _key) = test_state().await;
        let paths = Paths::resolve().unwrap();
        let (_c, body) = call(&st, "POST", "/v1/backup/export", Some(r#"{"passphrase":"right"}"#)).await;
        let archive = body["path"].as_str().unwrap().to_string();

        let vault_key = paths.root.join("vault.key").to_string_lossy().into_owned();
        let mut messages = Vec::new();
        for (label, path) in [
            ("existing sensitive file", vault_key.as_str()),
            ("existing non-archive", "/etc/hosts"),
            ("missing file", "/etc/definitely-not-here-9f3a"),
            ("real archive, wrong passphrase", archive.as_str()),
        ] {
            let body = format!(r#"{{"path":"{path}","passphrase":"wrong"}}"#);
            let (code, v) = call_as(&st, TOKEN, "POST", "/v1/backup/inspect", Some(&body)).await;
            assert_eq!(code, 400, "{label} must be a 400");
            messages.push(v.to_string());
        }
        assert!(
            messages.windows(2).all(|w| w[0] == w[1]),
            "every rejection must be indistinguishable, got {messages:?}"
        );

        // Restore is gated the same way (and never touches the live DB on a rejected path).
        let body = format!(r#"{{"path":"{vault_key}","passphrase":"right"}}"#);
        let (code, _v) = call_as(&st, TOKEN, "POST", "/v1/backup/restore", Some(&body)).await;
        assert_eq!(code, 400, "restore refuses a non-archive path");
        std::env::remove_var("WRIT_HOME");
    }

    #[tokio::test]
    async fn routes_require_the_loopback_bearer() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st, _key) = test_state().await;
        let resp = build_router(st.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/backup/export")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"passphrase":"x"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 401);
        std::env::remove_var("WRIT_HOME");
    }
}
