//! `/v1/update/*` — the daemon's authenticated auto-update trust authority.
//!
//! Three routes, one owner: the daemon holds every piece of update state that must not live in the
//! shell (the pinned keys, the monotonic version record, the channel), so the shell asks rather than
//! keeps its own copy.
//!   * `POST /v1/update/verify`  — run the full §3 chain over a candidate manifest (the gate below).
//!   * `GET  /v1/update/state`   — channel + version record + any durable rollback demand.
//!   * `PUT  /v1/update/channel` — switch the channel the §3 chain enforces.
//!
//! The Tauri shell must NOT install a desktop update on its own authority. Before staging anything it
//! asks THIS endpoint to run the full AUTO_UPDATE.md §3 verification chain against the candidate
//! manifest. The daemon is the trust authority because it holds (a) the compiled-in pinned Ed25519
//! keys and (b) the monotonic installed-version record in the encrypted DB — the downgrade anchor the
//! shell cannot see.
//!
//! The endpoint runs [`crate::local::update::policy::evaluate`], which checks, IN ORDER: schema →
//! pinned kid → Ed25519 signature → channel → expiry/staleness → downgrade → min-supported →
//! rollout-bucket → platform/arch artifact select (and surfaces the expected sha256 digest). It
//! returns an EXPLICIT verdict; the shell installs ONLY on `approved: true`.
//!
//! FAIL-CLOSED: a malformed manifest, an unknown/unpinned kid (the shipped default, until real keys
//! are provisioned), a bad signature, a version mismatch vs. what the shell is about to install, or
//! ANY internal error all yield `approved: false`. There is no path that returns `approved: true`
//! without a positive [`policy::evaluate`] decision.
//!
//! House style: thin handler, no auth layer here (server.rs applies the loopback bearer + Origin/Host
//! guard, so this endpoint requires the `wlt_`/scoped bearer); NEVER logs a secret.

use crate::local::error::{LocalError, LocalResult};
use crate::local::server::AppState;
use crate::local::store::config_kv;
use crate::local::update::{self, policy};
use axum::extract::State;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::Engine as _;
use rand::RngCore as _;
use serde::Deserialize;
use serde_json::{json, Value};

/// config-kv keys for the (offline-derived) rollout install-id and the update channel.
const INSTALL_ID_KEY: &str = "update.install_id";
const CHANNEL_KEY: &str = "update.channel";

/// Durable rollback demand written by the boot-time post-update gate
/// (`app::lifecycle::reconcile_update_state`). Present ⇒ the RUNNING build failed its self-check
/// enough consecutive boots to demand a restore; the value is the retained prior version, or an
/// empty string when none was retained (unhealthy, but nothing to roll back to).
const ROLLBACK_TO_KEY: &str = "update.rollback_to";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/update/verify", post(verify))
        .route("/v1/update/state", get(state))
        .route("/v1/update/channel", put(set_channel))
}

/// `GET /v1/update/state` — everything the shell needs to drive the updater, from the ONE authority
/// that owns it (the encrypted DB).
///
/// The shell deliberately keeps NO copy of the channel: duplicating it would let the two halves
/// disagree, and a shell that checked `beta` while the daemon only approves `stable` manifests would
/// download bytes it can never install. So the channel travels shell←daemon on every check, and the
/// shell builds its endpoint URL from THIS value.
///
/// Also reports the version record (the downgrade anchor + the retained rollback target) and any
/// durable rollback demand, so the UI can surface an unhealthy build instead of limping silently.
async fn state(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    let channel = config_kv::get_or(&st.db, CHANNEL_KEY, "stable").await?;
    let record = update::VersionRecord::load(&st.db).await?;
    // `Some("")` ⇒ a demand with no retained target; distinguish it from "no demand" (`None`).
    let rollback_to = config_kv::get(&st.db, ROLLBACK_TO_KEY).await?;
    Ok(Json(json!({
        "channel": channel,
        "installed_version": record.installed_version,
        "prior_version": record.prior_version,
        "health_fail_count": record.health_fail_count,
        "rollback_pending": rollback_to.is_some(),
        "rollback_to": rollback_to.filter(|v| !v.trim().is_empty()),
        // The version this daemon binary was compiled as. A mismatch with `installed_version` means
        // the boot reconciliation has not run yet (or failed) — useful for diagnosing a stuck anchor.
        "running_version": env!("CARGO_PKG_VERSION"),
    })))
}

/// Request body for `PUT /v1/update/channel`.
#[derive(Debug, Deserialize)]
struct ChannelBody {
    channel: String,
}

/// `PUT /v1/update/channel` — switch the update channel the §3 policy chain enforces.
///
/// Validated against [`policy::Channel::parse`] so only a channel the verifier actually understands
/// can be persisted; an unknown value is a 400 rather than a silently-stored string that would make
/// every later manifest fail closed as `unknown_channel`.
async fn set_channel(State(st): State<AppState>, Json(body): Json<ChannelBody>) -> LocalResult<Json<Value>> {
    let Some(channel) = policy::Channel::parse(&body.channel) else {
        return Err(LocalError::BadRequest(format!(
            "unknown update channel {:?} (expected stable, beta or managed)",
            body.channel
        )));
    };
    config_kv::set(&st.db, CHANNEL_KEY, channel.as_str()).await?;
    tracing::info!(channel = channel.as_str(), "update channel changed");
    Ok(Json(json!({ "channel": channel.as_str() })))
}

/// Request body: the candidate manifest (raw AUTO_UPDATE.md JSON object) plus the version the shell's
/// updater is about to install. `expected_version` is cross-checked against the manifest's signed
/// version so the daemon can never approve a manifest for a DIFFERENT release than the one being
/// staged (a swap between "check" and "install").
#[derive(Debug, Deserialize)]
struct VerifyBody {
    manifest: Value,
    #[serde(default)]
    expected_version: Option<String>,
}

/// `POST /v1/update/verify` → `{ approved, code, reason, version? }`. HTTP is always 200 when the
/// request was well-formed; the trust decision is the `approved` bool inside (a `false` is a normal
/// "do not install", not an HTTP error). A missing `manifest` field is a 400.
async fn verify(State(st): State<AppState>, Json(body): Json<VerifyBody>) -> LocalResult<Json<Value>> {
    if body.manifest.is_null() {
        return Err(LocalError::BadRequest("missing manifest".into()));
    }

    // Serialize the manifest object back to bytes for the signature check. The §3 verifier
    // re-canonicalizes the `signed` sub-object with RFC 8785 JCS, so field ordering / whitespace of
    // this round-trip is irrelevant — the signature still verifies iff the signed bytes are intact.
    let bytes = serde_json::to_vec(&body.manifest).map_err(|_| {
        LocalError::BadRequest("manifest is not serializable JSON".into())
    })?;

    // FAIL-CLOSED parse: a manifest that doesn't even parse is rejected as a verdict (not a 5xx).
    let manifest = match update::Manifest::parse(&bytes) {
        Ok(m) => m,
        Err(e) => return Ok(Json(reject_verdict("malformed_manifest", &e.to_string(), None))),
    };

    // The channel this client applies (default stable). An unknown configured channel matches nothing
    // → fail closed.
    let channel_str = config_kv::get_or(&st.db, CHANNEL_KEY, "stable").await?;
    let channel = match policy::Channel::parse(&channel_str) {
        Some(c) => c,
        None => return Ok(Json(reject_verdict("unknown_channel", "configured channel is unknown", None))),
    };

    // The monotonic installed version (downgrade anchor) from the encrypted DB. If never seeded, fall
    // back to the running build's version so a fresh install still gates correctly.
    let record = update::VersionRecord::load(&st.db).await?;
    let installed_version = record
        .installed_version
        .clone()
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());

    // A stable per-install id for offline rollout bucketing (minted once, persisted).
    let install_id = load_or_mint_install_id(&st.db).await?;

    let input = policy::PolicyInput {
        channel,
        installed_version: &installed_version,
        installed_build_released_at: record.installed_build_released_at.as_deref(),
        install_id: &install_id,
        platform_key: policy::current_platform_key(),
        now: chrono::Utc::now(),
    };

    match policy::evaluate(&manifest, &bytes, &input) {
        Ok(decision) => {
            // Defense: the daemon must approve the SAME version the shell is about to install.
            if let Some(exp) = body.expected_version.as_deref() {
                if exp.trim() != decision.version {
                    tracing::warn!(
                        expected = exp,
                        approved = %decision.version,
                        "update verify: version mismatch between shell and manifest — rejecting"
                    );
                    return Ok(Json(reject_verdict(
                        "version_mismatch",
                        "manifest version does not match the version being installed",
                        Some(&decision.version),
                    )));
                }
            }
            tracing::info!(version = %decision.version, "update verify: APPROVED");
            Ok(Json(json!({
                "approved": true,
                "code": "approved",
                "reason": "manifest passed all §3 gates",
                "version": decision.version,
                "expected_sha256": decision.expected_sha256(),
            })))
        }
        Err(reject) => {
            let code = reject.code();
            // A SKIP (channel/downgrade/rollout/no-artifact) is a normal "stay put"; a REJECT
            // (signature/expiry/replay) is an integrity failure. Both mean approved:false.
            if reject.is_skip() {
                tracing::info!(code, "update verify: not applicable (skip)");
            } else {
                tracing::warn!(code, "update verify: REJECTED (integrity/trust)");
            }
            Ok(Json(reject_verdict(code, &reject.to_string(), None)))
        }
    }
}

/// Build a `approved:false` verdict body with a stable machine code + a coarse (non-secret) reason.
fn reject_verdict(code: &str, reason: &str, version: Option<&str>) -> Value {
    json!({
        "approved": false,
        "code": code,
        "reason": reason,
        "version": version,
    })
}

/// Read the persisted rollout install-id, minting + storing one on first use. 16 CSPRNG bytes, hex.
async fn load_or_mint_install_id(pool: &sqlx::SqlitePool) -> LocalResult<String> {
    if let Some(id) = config_kv::get(pool, INSTALL_ID_KEY).await? {
        if !id.trim().is_empty() {
            return Ok(id);
        }
    }
    let mut raw = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    config_kv::set(pool, INSTALL_ID_KEY, &id).await?;
    Ok(id)
}
