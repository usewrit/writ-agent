//! `/v1/cloud/*` REST handlers — the desktop's cloud-account link surface for the Tauri shell.
//!
//! These thin axum handlers wrap [`crate::local::cloud`] (`link` / `state` / `entitlements` /
//! `token`) so the Tauri `cloud_*` IPC commands have a loopback REST target to proxy onto. They run
//! UNDER the existing loopback bearer + Origin/Host guard applied once by `server.rs` (`auth_mw`) —
//! there is NO new auth here.
//!
//! Routes (FIXED CONTRACT — Tauri proxies to these, the React `cloud_*` commands match exactly):
//!   GET  /v1/cloud/status        → { linked, account?, base_url? }
//!   POST /v1/cloud/link/start    → { user_code, verification_uri, verification_uri_complete?,
//!                                     expires_in, interval, device_code }
//!   POST /v1/cloud/link/poll     → { status, account? }
//!   POST /v1/cloud/unlink        → { ok: true }
//!   GET  /v1/cloud/entitlements  → { plan, features, limits, can_monetize, nav, web_url, failed_closed }
//!   POST /v1/cloud/sync/pull     → { ok, counts, diverged, errors }  (authoritative cloud→app import)
//!   GET  /v1/cloud/sync/status   → { in_progress, last_pull_at, counts, diverged_count }
//!   GET  /v1/cloud/sync/items    → { items:[{entity_type,local_id,cloud_id,origin,name,status}] }
//!   POST /v1/cloud/sync/push     → { ok, pushed, skipped }            (granular, user-initiated app→cloud)
//!
//! SECURITY (SECURITY_AND_ENTITLEMENTS_SPEC + the never-trust-a-BYO-agent rule):
//! - The cloud ACCOUNT token (`wto_`/`wtr_`) lives ONLY in the OS keyring; it is NEVER returned by any
//!   of these routes and NEVER logged. The link/start `device_code` is a bearer-equivalent polling
//!   secret: it is held in-process by [`crate::local::cloud::link`] and surfaced to the local UI in
//!   the start response (the loopback caller already holds the `wlt_` bearer), but it is never logged.
//! - Entitlements are REFLECTION-ONLY (UI/upsell + offline grace). Nothing here is an authorization
//!   gate; every paid/metered capability is re-enforced SERVER-SIDE per call.
//!
//! House style: thin handlers over the cloud module, `LocalResult<Json<_>>` with `?` propagation, no
//! auth layer here (server.rs owns it). `tracing` only, NEVER token/secret values.
//!
//! Net-new Rust in this crate (behind the `local` feature).

use crate::local::cloud::client::CloudClient;
use crate::local::cloud::entitlements::Entitlements;
use crate::local::cloud::link::{self, LinkPollStatus};
use crate::local::cloud::marketplace;
use crate::local::cloud::reflect;
use crate::local::cloud::state::LinkState;
use crate::local::cloud::sync;
use crate::local::error::{LocalError, LocalResult};
use crate::local::server::AppState;
use axum::extract::{Path, RawQuery, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

/// Mount the `/v1/cloud/*` routes onto the shared `AppState` router. Auth is applied by `server.rs`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/cloud/status", get(status))
        .route("/v1/cloud/local-only", post(set_local_only))
        .route("/v1/cloud/link/start", post(link_start))
        .route("/v1/cloud/link/poll", post(link_poll))
        .route("/v1/cloud/unlink", post(unlink))
        .route("/v1/cloud/entitlements", get(entitlements))
        .route("/v1/cloud/sync/pull", post(sync_pull))
        .route("/v1/cloud/sync/status", get(sync_status))
        .route("/v1/cloud/sync/items", get(sync_items))
        .route("/v1/cloud/sync/push", post(sync_push))
        // --- Native marketplace (daemon stage 2): browse / install / protected local executor ---
        .route("/v1/cloud/marketplace/listings", get(mp_listings))
        .route("/v1/cloud/marketplace/listings/:slug", get(mp_listing))
        .route("/v1/cloud/marketplace/listings/:slug/reviews", get(mp_reviews))
        .route("/v1/cloud/marketplace/categories", get(mp_categories))
        .route("/v1/cloud/marketplace/collections", get(mp_collections))
        .route("/v1/cloud/marketplace/creators", get(mp_creators))
        .route("/v1/cloud/marketplace/install", post(mp_install))
        .route("/v1/cloud/marketplace/uninstall", post(mp_uninstall))
        .route("/v1/cloud/marketplace/installs", get(mp_installs))
        .route("/v1/cloud/marketplace/installs/:slug/attach", get(mp_attach_state))
        .route("/v1/cloud/marketplace/installs/:slug/bindings", post(mp_apply_bindings))
        .route("/v1/cloud/marketplace/run", post(mp_run))
        .route("/v1/cloud/marketplace/run/:run_id", get(mp_run_status))
        // --- Cloud workflow REFLECTION (dual-view Workflows surface): live list + cloud-mediated
        //     run/poll + per-item "copy for offline" ---
        .route("/v1/cloud/reflect/workflows", get(reflect_workflows))
        .route("/v1/cloud/reflect/runs", get(reflect_running_runs))
        .route("/v1/cloud/reflect/workflows/:cloud_id/run", post(reflect_workflow_run))
        .route("/v1/cloud/reflect/workflows/:cloud_id/start-session", post(reflect_workflow_start_session))
        .route("/v1/cloud/reflect/workflows/run/:run_id", get(reflect_workflow_run_status))
        .route("/v1/cloud/reflect/workflows/run/:run_id/cancel", post(reflect_workflow_run_cancel))
        .route("/v1/cloud/reflect/workflows/:cloud_id/update", post(reflect_workflow_update))
        .route("/v1/cloud/reflect/workflows/:cloud_id/delete", post(reflect_workflow_delete))
        .route("/v1/cloud/reflect/workflows/:cloud_id/copy-local", post(reflect_workflow_copy_local))
        // --- Cloud MONITOR reflection: create-in-cloud + live list + cloud pause/resume/retune +
        //     "run on my local agent" ---
        .route("/v1/cloud/reflect/monitors", get(reflect_monitors))
        .route("/v1/cloud/reflect/monitors/create", post(reflect_monitor_create))
        .route("/v1/cloud/reflect/monitors/:cloud_id/enable", post(reflect_monitor_set_enabled))
        .route("/v1/cloud/reflect/monitors/:cloud_id/update", post(reflect_monitor_update))
        .route("/v1/cloud/reflect/monitors/:cloud_id/copy-local", post(reflect_monitor_copy_local))
        // --- Cloud PERSONA reflection: live (metadata-only) list + "copy for offline" (no control) ---
        .route("/v1/cloud/reflect/personas", get(reflect_personas))
        .route("/v1/cloud/reflect/personas/:cloud_id/copy-local", post(reflect_persona_copy_local))
        // --- Cloud-callable LOCAL workflows: the coordinator ids for what THIS device advertises,
        //     so the Connect surfaces can print the real cloud run URL ---
        .route("/v1/cloud/reflect/local-workflows", get(reflect_local_workflows))
        // --- Cloud ACCOUNT api keys (`wt_`): mint / list / revoke without leaving the desktop ---
        .route("/v1/cloud/reflect/api-keys", get(reflect_api_keys).post(reflect_api_key_create))
        .route("/v1/cloud/reflect/api-keys/catalog", get(reflect_api_key_catalog))
        .route("/v1/cloud/reflect/api-keys/:key_id/delete", post(reflect_api_key_delete))
}

/// Build the non-secret `account` reflection object from a linked [`LinkState`], or `null` when the
/// desktop is not linked. NEVER includes token material.
fn account_json(link: &LinkState) -> Value {
    if !link.is_linked() {
        return Value::Null;
    }
    json!({
        "account_id": link.account_id,
        "email": link.email,
        "scopes": link.scopes,
        "linked_at": link.linked_at,
        // Reflected preferred UI language (`en`/`fr`/`es`) or null — the desktop adopts it on first
        // link when the user hasn't chosen a language locally.
        "language": link.language,
    })
}

/// Build the authoritative auth-status object. Unlike the old metadata-only view, this PROBES the
/// keyring token so `linked` reflects whether a USABLE session actually exists — closing the
/// "linked-but-broken" gap where a failed refresh cleared the token yet status still said linked.
///
/// `state` is the single field the login gate switches on:
///   - `linked`      — account metadata AND a keyring token are present (a working session).
///   - `logged_out`  — account metadata exists but the token is gone (refresh failed / revoked) →
///                     the UI offers a one-tap re-link to `account.email`.
///   - `local_only`  — the user chose to run with no cloud account (side user); the app runs, cloud
///                     surfaces stay hidden.
///   - `unlinked`    — never linked and no local-only choice yet → the login screen's first run.
///
/// `account` carries the non-secret email/metadata whenever it exists (even when logged out, so the
/// re-link prompt can name the account). NEVER includes token material.
async fn build_status(st: &AppState) -> LocalResult<Value> {
    let link = LinkState::load_or_default(&st.db).await?;
    let base_url = CloudClient::resolve_base_url(Some(&link));
    let has_account = link.is_linked();
    // Keyring probe (sync). A present token is necessary for a working session.
    //
    // An `Err` here is NOT proof of a missing token: on macOS the login keychain can be
    // momentarily locked (post-sleep/unlock), and a re-signed build can hit an ACL prompt or
    // transient denial. Folding that into "no token" flips a perfectly good session to
    // `logged_out`, and since the gate re-polls this endpoint every 60s AND on window focus,
    // ONE blip ejects the user to the sign-in screen. So mirror the boot reconciliation's rule
    // (see `lifecycle::reconcile_profile_link_state_for`): only a definitive `Ok(None)` counts
    // as "the token is gone". On `Err` we keep the session and let the real authority decide —
    // a cloud call that 401s drives the refresh path, which clears the token on a genuine
    // `invalid_grant`, after which this probe returns `Ok(None)` and the gate logs out for real.
    let (token_present, keyring_unavailable) = match crate::local::cloud::token::get() {
        Ok(t) => (t.is_some(), false),
        Err(e) => {
            tracing::warn!(error = %e, "cloud status: keyring read failed — keeping the session (transient, not a logout)");
            (false, true)
        }
    };
    let token_usable = token_present || keyring_unavailable;
    let local_only = crate::local::cloud::state::local_only(&st.db).await?;
    let linked = has_account && token_usable;
    let state = derive_auth_state(has_account, token_usable, local_only);
    Ok(json!({
        "linked": linked,
        "state": state,
        "account": account_json(&link),
        "base_url": base_url,
        "token_present": token_present,
        // True when the keyring could not be read at all — `token_present: false` then means
        // "unknown", not "absent", and `state` deliberately keeps the prior session.
        "keyring_unavailable": keyring_unavailable,
        "local_only": local_only,
    }))
}

/// Pure auth-state decision (no IO) — the single source of truth the login gate switches on.
/// Precedence: a usable session (`linked`) wins; else prior account metadata means `logged_out`
/// (token gone → offer re-link); else an explicit no-account choice means `local_only`; else
/// `unlinked` (first run).
///
/// `token_usable` is "the token is present, or we could not tell" — an unreadable keyring must
/// never read as a logout (see [`build_status`]).
fn derive_auth_state(has_account: bool, token_usable: bool, local_only: bool) -> &'static str {
    if has_account && token_usable {
        "linked"
    } else if has_account {
        "logged_out"
    } else if local_only {
        "local_only"
    } else {
        "unlinked"
    }
}

/// `GET /v1/cloud/status` — the authoritative auth state (see [`build_status`]).
async fn status(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    Ok(Json(build_status(&st).await?))
}

/// Body for `POST /v1/cloud/local-only` — `{"enabled": true|false}` (defaults to enabling). Records
/// the "use the app without a cloud account" choice so the login gate stops prompting.
#[derive(serde::Deserialize)]
struct LocalOnlyBody {
    #[serde(default = "default_true_local_only")]
    enabled: bool,
}
fn default_true_local_only() -> bool {
    true
}

/// `POST /v1/cloud/local-only` — set/clear the local-only (no cloud account) choice; returns the
/// refreshed status so the caller can transition immediately.
async fn set_local_only(
    State(st): State<AppState>,
    body: Option<Json<LocalOnlyBody>>,
) -> LocalResult<Json<Value>> {
    let enabled = body.map(|Json(b)| b.enabled).unwrap_or(true);
    crate::local::cloud::state::set_local_only(&st.db, enabled).await?;
    Ok(Json(build_status(&st).await?))
}

/// `POST /v1/cloud/link/start` — begin the OAuth device-authorization flow.
///
/// Requests a device + user code from the cloud and stashes the in-flight handshake in-process (see
/// [`link::start_link`]). Returns the user-facing fields the UI renders plus the opaque `device_code`
/// (server-held-ok per the contract: the loopback caller already holds the `wlt_` bearer). The UI
/// then opens `verification_uri_complete` (or `verification_uri`) and polls `link/poll`.
async fn link_start(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    // Resolve the base url from any prior link / env / default (a re-link reuses the same endpoint).
    let link = LinkState::load_or_default(&st.db).await?;
    let base_url = CloudClient::resolve_base_url(Some(&link));

    // mode = None → standard user-hosted link (the server applies its default).
    let auth = link::start_link(&base_url, None).await?;
    Ok(Json(json!({
        "user_code": auth.user_code,
        "verification_uri": auth.verification_uri,
        "verification_uri_complete": auth.verification_uri_complete,
        "expires_in": auth.expires_in,
        "interval": auth.interval,
        "device_code": auth.device_code,
    })))
}

/// `POST /v1/cloud/link/poll` — advance the in-flight device flow by one poll.
///
/// Maps [`LinkPollStatus`] onto the contract `{ status, account? }`:
/// `"pending"` | `"linked"` (carries `account`) | `"denied"` | `"expired"`. On `"linked"` the
/// `wto_`/`wtr_` pair is already persisted to the keyring and `LinkState` to the DB.
async fn link_poll(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    let outcome = link::poll_link(&st.db).await?;
    let body = match outcome {
        LinkPollStatus::Pending => json!({ "status": "pending" }),
        LinkPollStatus::Linked(state) => {
            // A successful link is a definitive "I want a cloud account" — drop any prior local-only
            // choice so the gate treats this as fully linked (best-effort; never fails the link).
            let _ = crate::local::cloud::state::set_local_only(&st.db, false).await;
            // Auto-on the cloud execution agent (default-on-when-linked): start the process-global
            // manager, which re-checks its own preconditions (channel key sealed + not disabled).
            // Best-effort — a start failure never fails the link.
            if let Some(mgr) = crate::local::cloud::agent::manager::global() {
                let _ = mgr.start().await;
            }
            json!({ "status": "linked", "account": account_json(&state) })
        }
        LinkPollStatus::Denied => json!({ "status": "denied" }),
        LinkPollStatus::Expired => json!({ "status": "expired" }),
    };
    Ok(Json(body))
}

/// `POST /v1/cloud/unlink` — clear the keyring account token AND the persisted `LinkState` (and any
/// in-flight device flow). Idempotent; always reports `{ ok: true }` on success.
async fn unlink(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    link::unlink(&st.db).await?;
    // Tear down the cloud execution agent: unlinking removes the token + channel key, so the agent
    // must stop advertising/serving immediately (its `can_run` gate would refuse a restart anyway).
    if let Some(mgr) = crate::local::cloud::agent::manager::global() {
        mgr.stop();
    }
    Ok(Json(json!({ "ok": true })))
}

/// `GET /v1/cloud/entitlements` — the REFLECTION-ONLY entitlements reflection
/// `{ plan, features, limits, can_monetize, nav, web_url, failed_closed }`.
///
/// Tries a fresh, signature-verified fetch from the cloud; on any fetch/auth/network error (including
/// "not linked") it falls back to the signature-verified on-disk cache with its offline grace window,
/// and finally to a fully fail-closed reflection. This NEVER errors the route — a missing/stale/
/// unverifiable document degrades the UI to the free presentation rather than 500-ing.
///
/// All fields are reflection-only: they drive UI gating / upsell affordances / deep-link targets in
/// the desktop shell. NONE of them authorize anything — the cloud re-resolves and re-enforces every
/// paid/metered/monetized action server-side, per call (see the [`entitlements`] module docs and
/// the never-trust-a-BYO-agent rule).
///
/// [`entitlements`]: crate::local::cloud::entitlements
async fn entitlements(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    let link = LinkState::load_or_default(&st.db).await?;

    // Prefer a fresh verified fetch; fall back to the cached (grace-aware) reflection on any error.
    // `offline` distinguishes "couldn't reach the cloud" (retryable — keep showing the last-known
    // plan) from "not linked / free", so the UI can say "offline, last-known" instead of implying a
    // downgrade. This route NEVER errors: an offline cloud must never block the local app.
    let mut offline = false;
    let ent = match CloudClient::connect(Some(&link)) {
        Ok(mut client) => match Entitlements::refresh(&mut client).await {
            Ok(e) => e,
            Err(e) => {
                offline = matches!(e, LocalError::CloudUnreachable(_));
                tracing::debug!(error = %e, offline, "entitlements refresh failed — using cached reflection");
                Entitlements::load_cached()
            }
        },
        // Not linked / no token → reflect the cached document (typically empty/fail-closed).
        Err(e) => {
            tracing::debug!(error = %e, "no cloud client for entitlements — using cached reflection");
            Entitlements::load_cached()
        }
    };

    Ok(Json(json!({
        "plan": ent.plan(),
        "features": ent.features(),
        "limits": ent.limits(),
        "can_monetize": ent.can_monetize(),
        "nav": ent.nav(),
        "web_url": ent.web_url(),
        "failed_closed": ent.is_failed_closed(),
        "offline": offline,
    })))
}

/// `POST /v1/cloud/sync/pull` — run a full AUTHORITATIVE cloud → app import.
///
/// Pulls the linked account's OWN workflows / personas / monitors, upserting cloud-origin rows
/// (cloud wins) while NEVER touching locally-authored rows and REPORTING — not overwriting — any
/// cloud-origin row whose local content diverged. Resilient: a per-entity failure is collected into
/// `errors`; the route never 500s on a partial failure (it returns `ok=false`).
///
/// Auto-pull on link is driven by the DESKTOP shell; this endpoint just exposes the import. Returns
/// `{ ok, counts:{workflows,personas,monitors}, diverged:[{entity_type,local_id,name}], errors:[..] }`.
async fn sync_pull(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    let link = LinkState::load_or_default(&st.db).await?;
    let result = sync::pull_all(&st.db, &st.vault, &link).await;
    Ok(Json(serde_json::to_value(result)?))
}

/// `GET /v1/cloud/sync/status` — non-secret sync status reflection.
///
/// Returns `{ in_progress, last_pull_at, counts, diverged_count }`. `in_progress` reflects whether a
/// pull is currently running; `last_pull_at` + `counts` are persisted from the last completed pull;
/// `diverged_count` is a live scan over the sync items.
async fn sync_status(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    let status = sync::status(&st.db).await?;
    Ok(Json(serde_json::to_value(status)?))
}

/// `GET /v1/cloud/sync/items` — the granular per-item sync list.
///
/// Lists every local workflow / persona / monitor joined with its cloud mapping, each carrying
/// `origin` (`cloud`|`local`) and `status` (`cloud`|`local`|`diverged`). Drives the desktop "Cloud
/// Sync" page's per-item PUSH checkboxes + divergence display. Returns `{ items: [...] }`.
async fn sync_items(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    let items = sync::items(&st.db).await?;
    Ok(Json(json!({ "items": items })))
}

/// Body for `POST /v1/cloud/sync/push`: which local rows of one entity type to push up.
#[derive(Debug, Deserialize)]
struct SyncPushBody {
    /// `"workflow" | "persona" | "monitor"`.
    entity_type: String,
    /// The local row ids the USER explicitly selected to push (granular, never bulk-by-default).
    #[serde(default)]
    local_ids: Vec<i64>,
}

/// `POST /v1/cloud/sync/push` — GRANULAR, USER-INITIATED app → cloud push.
///
/// Creates/updates the user's PRIVATE cloud records for the selected local rows, shipping the recipe
/// + references ONLY (every secret/credential VALUE is stripped). NEVER automatic/bulk/silent — the
/// desktop calls this per user action. Per-item failures land in `skipped` with a reason; the route
/// never 500s. Returns `{ ok, pushed:[{local_id,cloud_id}], skipped:[{local_id,reason}] }`.
async fn sync_push(
    State(st): State<AppState>,
    Json(body): Json<SyncPushBody>,
) -> LocalResult<Json<Value>> {
    let link = LinkState::load_or_default(&st.db).await?;
    let result = sync::push(&st.db, &link, &body.entity_type, &body.local_ids).await;
    Ok(Json(serde_json::to_value(result)?))
}

// ============================================================================================
// Native marketplace handlers (daemon stage 2)
//
// SECURITY: these run UNDER the loopback `wlt_` bearer (server.rs `auth_mw`). The marketplace
// module attaches the cloud `wto_` account token via `CloudClient` and unseals installed recipes
// with the keyring channel key — NEITHER ever crosses back to the webview. Browse/install responses
// are passed through verbatim; the install/run summaries deliberately omit the recipe/sealed blob.
// ============================================================================================

/// Body for `POST /v1/cloud/marketplace/install` and `POST /v1/cloud/marketplace/run` — both key on
/// a listing `slug`. `inputs` is OPTIONAL (run only): the consumer's own values for the recipe's
/// `{{input.*}}` placeholders. The desktop UI sends `{slug}` alone — absent inputs stay `{}` so the
/// pre-existing behavior is unchanged.
#[derive(Debug, Deserialize)]
struct SlugBody {
    slug: String,
    #[serde(default)]
    inputs: Option<Value>,
}

/// `GET /v1/cloud/marketplace/listings` — browse grid (forwards the raw query string to the cloud).
async fn mp_listings(
    State(st): State<AppState>,
    RawQuery(query): RawQuery,
) -> LocalResult<Json<Value>> {
    let q = query.unwrap_or_default();
    Ok(Json(marketplace::list_listings(&st.db, &q).await?))
}

/// `GET /v1/cloud/marketplace/listings/{slug}` — listing detail.
async fn mp_listing(
    State(st): State<AppState>,
    Path(slug): Path<String>,
) -> LocalResult<Json<Value>> {
    Ok(Json(marketplace::get_listing(&st.db, &slug).await?))
}

/// `GET /v1/cloud/marketplace/listings/{slug}/reviews` — read-only reviews (forwards the query).
async fn mp_reviews(
    State(st): State<AppState>,
    Path(slug): Path<String>,
    RawQuery(query): RawQuery,
) -> LocalResult<Json<Value>> {
    let q = query.unwrap_or_default();
    Ok(Json(marketplace::get_reviews(&st.db, &slug, &q).await?))
}

/// `GET /v1/cloud/marketplace/categories`.
async fn mp_categories(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    Ok(Json(marketplace::list_categories(&st.db).await?))
}

/// `GET /v1/cloud/marketplace/collections`.
async fn mp_collections(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    Ok(Json(marketplace::list_collections(&st.db).await?))
}

/// `GET /v1/cloud/marketplace/creators`.
async fn mp_creators(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    Ok(Json(marketplace::list_creators(&st.db).await?))
}

/// `POST /v1/cloud/marketplace/install` — install a listing natively. Calls the cloud install
/// endpoint, fetches + stores the SEALED recipe locally, and returns the install SUMMARY (never the
/// recipe). Body: `{ slug }`.
async fn mp_install(
    State(st): State<AppState>,
    Json(body): Json<SlugBody>,
) -> LocalResult<Json<Value>> {
    let summary = marketplace::install(&st.db, &st.vault, &body.slug).await?;
    Ok(Json(serde_json::to_value(summary)?))
}

/// `POST /v1/cloud/marketplace/uninstall` — uninstall a listing: best-effort cloud grant release,
/// then removes BOTH local rows (the `installed_workflows` row and the PROXY `workflows` row), so
/// a leftover proxy can never hit the engine's "reinstall the listing" error. Body: `{ slug }`.
async fn mp_uninstall(
    State(st): State<AppState>,
    Json(body): Json<SlugBody>,
) -> LocalResult<Json<Value>> {
    let summary = marketplace::uninstall(&st.db, &body.slug).await?;
    Ok(Json(serde_json::to_value(summary)?))
}

/// `GET /v1/cloud/marketplace/installs/{slug}/attach` — the NAMES-ONLY attach projection (manifest
/// slots + current bindings) the desktop Run modal renders for a proxy workflow. 404 when the
/// install row is gone (orphaned proxy — reinstall).
async fn mp_attach_state(
    State(st): State<AppState>,
    Path(slug): Path<String>,
) -> LocalResult<Json<Value>> {
    marketplace::attach_state(&st.db, &slug)
        .await?
        .map(Json)
        .ok_or_else(|| LocalError::NotFound(format!("installed workflow {slug}")))
}

/// `POST /v1/cloud/marketplace/installs/{slug}/bindings` — persist attach PICKS from the desktop
/// Run modal (secrets = vault KEY NAMES per slot, persona id/"none", non-secret input defaults) —
/// the loopback twin of the MCP elicitation. Returns the refreshed attach projection.
async fn mp_apply_bindings(
    State(st): State<AppState>,
    Path(slug): Path<String>,
    Json(picks): Json<Value>,
) -> LocalResult<Json<Value>> {
    marketplace::apply_bindings(&st.db, &slug, &picks).await?;
    marketplace::attach_state(&st.db, &slug)
        .await?
        .map(Json)
        .ok_or_else(|| LocalError::NotFound(format!("installed workflow {slug}")))
}

/// `GET /v1/cloud/marketplace/installs` — list locally installed workflows (METADATA ONLY; the
/// sealed blob / steps are never included).
async fn mp_installs(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    let installs = marketplace::list_installed(&st.db).await?;
    // `{ installs: [...] }` — the desktop `MarketplaceInstalledItem[]` contract (the UI reads
    // `res.installs`). METADATA ONLY: `InstalledMeta` has no `sealed_recipe` field, so the sealed
    // blob / steps cannot surface here. Each row is enriched with its local PROXY workflow id
    // (0017) so the Installed page can route "Run" through the regular workflow detail → Run
    // modal input collection instead of a blind slug dispatch (`null` for a pre-0017 install
    // whose proxy hasn't been lazily minted yet — the slug run path heals it).
    let mut items = Vec::with_capacity(installs.len());
    for meta in installs {
        let proxy_id = crate::local::store::workflows::get_by_marketplace_slug(&st.db, &meta.slug)
            .await?
            .map(|w| w.id);
        let mut v = serde_json::to_value(meta)?;
        if let Some(obj) = v.as_object_mut() {
            obj.insert("local_workflow_id".into(), json!(proxy_id));
        }
        items.push(v);
    }
    Ok(Json(json!({ "installs": items })))
}

/// `POST /v1/cloud/marketplace/run` — the PROTECTED EXECUTOR. For a PAID listing this authorizes a
/// metered run cloud-side BEFORE executing and finalizes the charge after; FREE listings run with no
/// charge. Decrypts the recipe IN MEMORY, runs it on the local engine with the consumer's own data,
/// and returns `{ run_id }` (the run surfaces in `/v1/runs`). Body: `{ slug }`.
async fn mp_run(
    State(st): State<AppState>,
    Json(body): Json<SlugBody>,
) -> LocalResult<Json<Value>> {
    let inputs = body.inputs.unwrap_or_else(|| json!({}));
    let outcome = marketplace::run(&st.db, &st.engine, &body.slug, inputs).await?;
    // Keep the historical `{ run_id }` wire contract for the desktop UI (it polls
    // `/v1/cloud/marketplace/run/{run_id}` for status/result); the richer RunOutcome fields are
    // consumed in-daemon by the MCP `writ_install_api` tool only.
    Ok(Json(json!({ "run_id": outcome.run_id })))
}

/// `GET /v1/cloud/marketplace/run/{run_id}` — status/result of a marketplace run (reads the runs
/// store; the recipe is never part of it).
async fn mp_run_status(
    State(st): State<AppState>,
    Path(run_id): Path<i64>,
) -> LocalResult<Json<Value>> {
    Ok(Json(marketplace::run_status(&st.db, run_id).await?))
}

// ============================================================================================
// Cloud workflow REFLECTION handlers (dual-view Workflows surface)
//
// The desktop Workflows page shows BOTH a LIVE reflection of the user's cloud workflows (runnable
// IN THE CLOUD) and the LOCAL-DB workflows (runnable on the local agent). These routes back the
// CLOUD half. SECURITY: they run UNDER the loopback `wlt_` bearer (server.rs `auth_mw`); the
// reflect module attaches the cloud `wto_` token via `CloudClient` — it never crosses to the
// webview. The list/run/status routes NEVER persist anything; only `copy-local` writes (a single
// cloud-origin local row via the existing sync mapping, with no credential values).
// ============================================================================================

/// `GET /v1/cloud/reflect/workflows` — the LIVE cloud workflow list (passthrough summary array;
/// never stored locally, so it can never be picked up by the local scheduler).
async fn reflect_workflows(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    // Cloud GET returns a BARE array; wrap as { workflows: [...] } to match the desktop ipc contract
    // (CloudWorkflowList reads `res.workflows`). Without the wrap the live list renders empty.
    Ok(Json(json!({ "workflows": reflect::list_workflows(&st.db).await? })))
}

/// `GET /v1/cloud/reflect/runs` — the linked account's LIVE (in-flight) cloud runs, for the desktop
/// activity popover's "Running in cloud" section. A REAL cloud call authenticated as the OAuth-logged
/// user (the `wto_` token stays in the daemon). Returns `{ runs: [...] }` (empty when nothing is
/// running or when unlinked/offline — the UI simply shows no cloud section).
async fn reflect_running_runs(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    Ok(Json(reflect::list_running_runs(&st.db).await?))
}

/// `POST /v1/cloud/reflect/workflows/{cloud_id}/run` — start a CLOUD-MEDIATED run of the user's own
/// cloud workflow (the cloud executes + meters). Returns `{ run_id }` (the cloud task id as a
/// string) for polling. Bodyless.
async fn reflect_workflow_run(
    State(st): State<AppState>,
    Path(cloud_id): Path<String>,
    // Optional body `{ form_data?: {...} }` — the desktop Run modal's per-run input values. A bodyless
    // POST (the plain "Run" with nothing to collect) still works: `Option<Json<..>>` yields `None`.
    body: Option<Json<Value>>,
) -> LocalResult<Json<Value>> {
    let form_data = body.and_then(|Json(v)| v.get("form_data").cloned());
    let started = reflect::run_workflow(&st.db, &cloud_id, form_data).await?;
    Ok(Json(serde_json::to_value(started)?))
}

/// `POST /v1/cloud/reflect/workflows/{cloud_id}/start-session` — start a CLOUD streaming session for
/// the user's own cloud STREAMING workflow (`workflow_type == "streaming"`), which has no one-shot
/// run. Pins the CLOUD venue (never the BYO agent). Returns `{ session_key, status }` for the UI.
async fn reflect_workflow_start_session(
    State(st): State<AppState>,
    Path(cloud_id): Path<String>,
) -> LocalResult<Json<Value>> {
    let started = reflect::start_streaming_session(&st.db, &cloud_id).await?;
    Ok(Json(serde_json::to_value(started)?))
}

/// `GET /v1/cloud/reflect/workflows/run/{run_id}` — poll a cloud-mediated run's status, projected to
/// the stable `{ run_id, status, done, duration_ms?, started_at?, finished_at?, error? }` shape.
async fn reflect_workflow_run_status(
    State(st): State<AppState>,
    Path(run_id): Path<String>,
) -> LocalResult<Json<Value>> {
    Ok(Json(reflect::run_status(&st.db, &run_id).await?))
}

/// `POST /v1/cloud/reflect/workflows/{cloud_id}/copy-local` — "copy for offline": fetch the cloud
/// workflow detail and insert a LOCAL row via the existing sync mapping. IDEMPOTENT on the cloud id
/// (a second copy returns the existing local id, `copied=false`); NEVER imports a credential value.
/// Returns `{ local_id, copied }`.
async fn reflect_workflow_copy_local(
    State(st): State<AppState>,
    Path(cloud_id): Path<String>,
) -> LocalResult<Json<Value>> {
    let result = reflect::copy_local(&st.db, &cloud_id).await?;
    Ok(Json(serde_json::to_value(result)?))
}

/// Body for `POST /v1/cloud/reflect/workflows/{cloud_id}/update` — a PARTIAL operational update
/// (schedule pause/resume, interval, rename). Every field is optional; only the present ones reach
/// the cloud `PUT`. Logic-bearing fields (steps/functions/entry/…) are intentionally NOT accepted
/// here, so the webview can never rewrite the recipe through the control surface.
#[derive(Debug, Deserialize)]
struct WorkflowUpdateBody {
    #[serde(default)]
    schedule_enabled: Option<bool>,
    #[serde(default)]
    schedule_interval_ms: Option<i64>,
    #[serde(default)]
    name: Option<String>,
}

/// `POST /v1/cloud/reflect/workflows/{cloud_id}/update` — relay a partial workflow update to the
/// cloud (`PUT /api/automation/workflows/{cloud_id}`) and return the updated cloud row. This backs
/// the dual-view "Pause/Resume schedule + rename + change interval" controls. The shell proxy speaks
/// only GET/POST, so the desktop POSTs here and the daemon issues the cloud PUT. Never writes locally.
async fn reflect_workflow_update(
    State(st): State<AppState>,
    Path(cloud_id): Path<String>,
    Json(body): Json<WorkflowUpdateBody>,
) -> LocalResult<Json<Value>> {
    Ok(Json(
        reflect::update_workflow(
            &st.db,
            &cloud_id,
            body.schedule_enabled,
            body.schedule_interval_ms,
            body.name.as_deref(),
        )
        .await?,
    ))
}

/// `POST /v1/cloud/reflect/workflows/{cloud_id}/delete` — delete the user's OWN cloud workflow
/// (`DELETE /api/automation/workflows/{cloud_id}`). The shell proxy speaks only GET/POST, so the
/// desktop POSTs here and the daemon issues the cloud DELETE. Returns `{ ok: true }`.
async fn reflect_workflow_delete(
    State(st): State<AppState>,
    Path(cloud_id): Path<String>,
) -> LocalResult<Json<Value>> {
    reflect::delete_workflow(&st.db, &cloud_id).await?;
    Ok(Json(json!({ "ok": true })))
}

/// `POST /v1/cloud/reflect/workflows/run/{run_id}/cancel` — cancel an in-flight cloud-mediated run
/// (`DELETE /api/automation/tasks/{run_id}`). Returns `{ ok: true }`.
async fn reflect_workflow_run_cancel(
    State(st): State<AppState>,
    Path(run_id): Path<String>,
) -> LocalResult<Json<Value>> {
    reflect::cancel_run(&st.db, &run_id).await?;
    Ok(Json(json!({ "ok": true })))
}

// ============================================================================================
// Cloud MONITOR reflection handlers (dual-view Monitors surface)
//
// Mirror the workflow reflection routes, minus run/poll (the cloud has no "check now" endpoint).
// SECURITY: same loopback `wlt_` guard; the reflect module attaches the cloud `wto_` via CloudClient.
// The list/enable routes NEVER persist; only `copy-local` writes (a single cloud-origin local target
// row via the existing sync mapping, no session/secret values, FORCED enabled for the local scheduler).
// ============================================================================================

/// `GET /v1/cloud/reflect/monitors` — the LIVE cloud monitor list (passthrough array, real state
/// incl. `enabled`; never stored locally, so the local scheduler can never pick it up).
async fn reflect_monitors(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    // Wrap the bare cloud array as { monitors: [...] } to match the desktop (CloudMonitorList reads `res.monitors`).
    Ok(Json(json!({ "monitors": reflect::list_monitors(&st.db).await? })))
}

/// Body for `POST /v1/cloud/reflect/monitors/{cloud_id}/enable` — `{ enabled: bool }`. The shell
/// proxy speaks only GET/POST, so the desktop POSTs here and the daemon issues the cloud `PATCH`.
#[derive(Debug, Deserialize)]
struct MonitorEnableBody {
    enabled: bool,
}

/// `POST /v1/cloud/reflect/monitors/{cloud_id}/enable` — CLOUD pause/resume. Relays
/// `PATCH /api/targets/{cloud_id} { enabled }` and returns the cloud's updated target for an
/// authoritative UI refresh. Never writes locally.
async fn reflect_monitor_set_enabled(
    State(st): State<AppState>,
    Path(cloud_id): Path<String>,
    Json(body): Json<MonitorEnableBody>,
) -> LocalResult<Json<Value>> {
    Ok(Json(reflect::set_monitor_enabled(&st.db, &cloud_id, body.enabled).await?))
}

/// Body for `POST /v1/cloud/reflect/monitors/create` — the desktop wizard's "create this check in the
/// cloud" payload: the `target` (cloud `CreateTargetRequest` shape, snake_case) plus the list of
/// `selectors` (cloud `SelectorCreate` shape) to attach. The daemon orchestrates the multi-step cloud
/// create (target → selectors → baselines) so the webview makes ONE call.
#[derive(Debug, Deserialize)]
struct MonitorCreateBody {
    target: Value,
    #[serde(default)]
    selectors: Vec<Value>,
}

/// `POST /v1/cloud/reflect/monitors/create` — CREATE a monitor that lives + runs in the cloud
/// (`POST /api/targets` + per-selector `POST /api/targets/{id}/selectors`). Backs the wizard's
/// Local/Cloud venue choice for content monitors. The cloud re-enforces plan limits (a refusal
/// surfaces here as the create error); nothing is written locally. Returns `{ cloud_id, monitor }`.
async fn reflect_monitor_create(
    State(st): State<AppState>,
    Json(body): Json<MonitorCreateBody>,
) -> LocalResult<Json<Value>> {
    Ok(Json(
        reflect::create_monitor(&st.db, body.target, body.selectors).await?,
    ))
}

/// Body for `POST /v1/cloud/reflect/monitors/{cloud_id}/update` — a PARTIAL operational retune
/// (pause/resume, cadence, Render-JS, region, structured recurrence). Every field is optional; only
/// the present ones reach the cloud `PATCH`. Selector/logic edits are intentionally NOT accepted here.
#[derive(Debug, Deserialize)]
struct MonitorUpdateBody {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    check_period_ms: Option<i64>,
    #[serde(default)]
    requires_playwright: Option<bool>,
    // `preferred_region`/`schedule_*` ride as `serde_json::Value` so a concrete value forwards
    // verbatim. To CLEAR the region, the webview sends `""` (empty string = "any region" on the
    // cloud), never JSON `null` — serde collapses a present `null` to `None` (omitted) for `Option`.
    #[serde(default)]
    preferred_region: Option<Value>,
    #[serde(default)]
    schedule_kind: Option<String>,
    #[serde(default)]
    schedule_time: Option<Value>,
    #[serde(default)]
    schedule_days: Option<Vec<i64>>,
    #[serde(default)]
    schedule_tz: Option<Value>,
}

/// `POST /v1/cloud/reflect/monitors/{cloud_id}/update` — relay a partial monitor retune to the cloud
/// (`PATCH /api/targets/{cloud_id}`) and return the updated cloud target. The shell proxy speaks only
/// GET/POST, so the desktop POSTs here and the daemon issues the cloud PATCH. Never writes locally.
async fn reflect_monitor_update(
    State(st): State<AppState>,
    Path(cloud_id): Path<String>,
    Json(body): Json<MonitorUpdateBody>,
) -> LocalResult<Json<Value>> {
    Ok(Json(
        reflect::update_monitor(
            &st.db,
            &cloud_id,
            body.enabled,
            body.check_period_ms,
            body.requires_playwright,
            body.preferred_region,
            body.schedule_kind.as_deref(),
            body.schedule_time,
            body.schedule_days,
            body.schedule_tz,
        )
        .await?,
    ))
}

/// `POST /v1/cloud/reflect/monitors/{cloud_id}/copy-local` — "run on my local agent": fetch the cloud
/// monitor detail and insert a LOCAL target via the existing sync mapping, FORCED enabled so the local
/// scheduler runs it offline. IDEMPOTENT on the cloud id; NEVER imports a session/secret value.
/// Returns `{ local_id, copied }`.
async fn reflect_monitor_copy_local(
    State(st): State<AppState>,
    Path(cloud_id): Path<String>,
) -> LocalResult<Json<Value>> {
    let result = reflect::copy_monitor_local(&st.db, &cloud_id).await?;
    Ok(Json(serde_json::to_value(result)?))
}

// ============================================================================================
// Cloud PERSONA reflection handlers (dual-view Personas surface)
//
// Mirror the workflow reflection routes, minus run/poll/control (personas aren't executable). The
// list is METADATA ONLY by backend construction (`has_*` booleans). Only `copy-local` writes (a
// single cloud-origin local persona row via the existing sync mapping, NEVER a credential value).
// ============================================================================================

/// `GET /v1/cloud/reflect/personas` — the LIVE cloud persona list (passthrough; metadata only —
/// the backend returns only `has_*` booleans, never secret values; never stored on view).
async fn reflect_personas(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    // Wrap the bare cloud array as { personas: [...] } to match the desktop (CloudPersonaList reads `res.personas`).
    Ok(Json(json!({ "personas": reflect::list_personas(&st.db).await? })))
}

/// `POST /v1/cloud/reflect/personas/{cloud_id}/copy-local` — "copy for offline": fetch the cloud
/// persona detail and insert a LOCAL row via the existing sync mapping. IDEMPOTENT on the cloud id;
/// NEVER imports a credential value (the user re-attaches creds locally). Returns `{ local_id, copied }`.
async fn reflect_persona_copy_local(
    State(st): State<AppState>,
    Path(cloud_id): Path<String>,
) -> LocalResult<Json<Value>> {
    let result = reflect::copy_persona_local(&st.db, &cloud_id).await?;
    Ok(Json(serde_json::to_value(result)?))
}

/// `GET /v1/cloud/reflect/local-workflows` — the coordinator's view of the workflows THIS account's
/// daemons advertise as cloud-callable, wrapped as `{ workflows: [...], base_url }`.
///
/// The Connect surfaces use it to print the REAL cloud run URL for a local workflow: the catalog
/// only flows upward, so the daemon never learns the canonical coordinator id it must be called by.
/// `base_url` is the resolved cloud API origin (the same one `/v1/cloud/status` reports) so the
/// webview can compose an absolute URL without a second round-trip.
async fn reflect_local_workflows(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    let link = LinkState::load_or_default(&st.db).await?;
    let base_url = CloudClient::resolve_base_url(Some(&link));
    Ok(Json(json!({
        "workflows": reflect::list_cloud_callable(&st.db).await?,
        "base_url": base_url,
    })))
}

// ── Cloud ACCOUNT api keys ───────────────────────────────────────────────────
// The desktop's Connect surfaces advertise a cloud URL, and that URL takes an ACCOUNT key (`wt_`).
// Minting one used to mean opening the web app, which defeats using the desktop app on its own.
// These four thin passthroughs put the whole lifecycle in the app. The cloud remains the sole
// issuer/revoker; the `wto_` token never leaves the daemon, and the one-time secret in the create
// reply is relayed to the caller and never stored.

/// `GET /v1/cloud/reflect/api-keys` — the linked account's keys, wrapped as `{ keys: [...] }`
/// (the cloud returns a bare array; the wrap matches the other reflect list routes).
async fn reflect_api_keys(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    Ok(Json(json!({ "keys": reflect::list_cloud_api_keys(&st.db).await? })))
}

/// `GET /v1/cloud/reflect/api-keys/catalog` — the cloud's scope vocabulary (resources/actions/
/// presets), served rather than hardcoded so the desktop key screen can't drift from the web one.
async fn reflect_api_key_catalog(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    Ok(Json(reflect::cloud_api_key_catalog(&st.db).await?))
}

/// `POST /v1/cloud/reflect/api-keys` — mint an account key. The body is the cloud's
/// `CreateAPIKeyRequest` passed through verbatim, and the reply carries the ONE-TIME secret.
async fn reflect_api_key_create(
    State(st): State<AppState>,
    Json(body): Json<Value>,
) -> LocalResult<Json<Value>> {
    Ok(Json(reflect::create_cloud_api_key(&st.db, &body).await?))
}

/// `POST /v1/cloud/reflect/api-keys/{key_id}/delete` — revoke an account key. POST rather than
/// DELETE to match the other reflect mutations. Returns `{ok:true}`.
async fn reflect_api_key_delete(
    State(st): State<AppState>,
    Path(key_id): Path<String>,
) -> LocalResult<Json<Value>> {
    Ok(Json(reflect::delete_cloud_api_key(&st.db, &key_id).await?))
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

    const TOKEN: &str = "wlt_test_secret";

    #[test]
    fn auth_state_decision_table() {
        // (has_account, token_present, local_only) → state
        assert_eq!(derive_auth_state(true, true, false), "linked");
        assert_eq!(derive_auth_state(true, true, true), "linked", "a session wins over a stale local-only flag");
        // metadata but no token = the refresh-failure case → must surface as logged_out, not linked.
        assert_eq!(derive_auth_state(true, false, false), "logged_out");
        assert_eq!(derive_auth_state(true, false, true), "logged_out", "re-link prompt wins over local-only");
        // no account: explicit local-only choice, else first-run unlinked.
        assert_eq!(derive_auth_state(false, false, true), "local_only");
        assert_eq!(derive_auth_state(false, false, false), "unlinked");
        // a stray token with no account metadata is not a session.
        assert_eq!(derive_auth_state(false, true, false), "unlinked");
        // An UNREADABLE keyring (locked/ACL-prompt) reaches here as token_usable=true — a blip must
        // never eject a linked user, since the gate re-polls this on a 60s timer and on focus.
        assert_eq!(
            derive_auth_state(true, true, false),
            "linked",
            "keyring read error must keep the session, not log out"
        );
    }

    /// A loopback `AppState` over a fresh throwaway encrypted DB (no keyring/cloud token).
    async fn test_state() -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().unwrap();
        let paths = config_paths(&dir);
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

    fn config_paths(dir: &tempfile::TempDir) -> crate::local::config::Paths {
        crate::local::config::Paths::at(dir.path().join(".writ"))
    }

    /// Issue an authenticated loopback request and return `(status, json_body)`.
    async fn call(st: &AppState, method: &str, uri: &str) -> (u16, Value) {
        let resp = build_router(st.clone())
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("authorization", format!("Bearer {TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
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
    async fn status_unlinked_reports_not_linked() {
        let (_dir, st) = test_state().await;
        let (code, body) = call(&st, "GET", "/v1/cloud/status").await;
        assert_eq!(code, 200, "body={body}");
        assert_eq!(body["linked"], json!(false));
        assert_eq!(body["account"], Value::Null);
        // base_url is always present (resolved from env/link/default).
        assert!(body["base_url"].is_string(), "base_url should be a string: {body}");
    }

    #[tokio::test]
    async fn status_reflects_persisted_link_state() {
        let (_dir, st) = test_state().await;
        // Persist a LinkState directly (account metadata).
        let state = LinkState {
            account_id: "acct_77".into(),
            email: "u@example.com".into(),
            cloud_base_url: "https://cloud.example.com/".into(),
            scopes: vec!["workflows:execute".into()],
            linked_at: Some(chrono::Utc::now()),
            language: None,
        };
        state.save(&st.db).await.unwrap();

        let (code, body) = call(&st, "GET", "/v1/cloud/status").await;
        assert_eq!(code, 200, "body={body}");
        // The account reflection surfaces regardless of token state (so a logged-out re-link prompt
        // can still name the account).
        assert_eq!(body["account"]["account_id"], json!("acct_77"));
        assert_eq!(body["account"]["email"], json!("u@example.com"));
        // With account metadata present, `state` is either `linked` (a keyring token exists) or
        // `logged_out` (token cleared) — NEVER `local_only`/`unlinked`. The exact split depends on the
        // OS keyring (covered deterministically by `auth_state_decision_table`); we must not touch the
        // real keyring here. `linked` mirrors the `linked` state.
        let state_str = body["state"].as_str().unwrap_or_default();
        assert!(
            state_str == "linked" || state_str == "logged_out",
            "state with metadata must be linked|logged_out, got {state_str}"
        );
        assert_eq!(body["linked"], json!(state_str == "linked"));
        // No local-only flag was set.
        assert_eq!(body["local_only"], json!(false));
        // (base_url resolution is covered by the dedicated env-override tests below; it is NOT asserted
        // here because those tests mutate the process-global WRIT_CLOUD_URL in parallel.)
        // The account block must NEVER carry token material.
        let raw = body.to_string();
        assert!(!raw.contains("wto_") && !raw.contains("wtr_"), "no token material may leak: {raw}");
    }

    #[tokio::test]
    async fn status_local_only_choice_surfaces() {
        let (_dir, st) = test_state().await;
        // No account metadata; set the local-only choice → state must be `local_only`.
        crate::local::cloud::state::set_local_only(&st.db, true).await.unwrap();
        let (code, body) = call(&st, "GET", "/v1/cloud/status").await;
        assert_eq!(code, 200, "body={body}");
        assert_eq!(body["state"], json!("local_only"));
        assert_eq!(body["linked"], json!(false));
        assert_eq!(body["local_only"], json!(true));
        assert_eq!(body["account"], json!(null));

        // The POST setter returns the refreshed status. An empty body defaults to ENABLING, so the
        // choice stays on (and the response is the live status, not a bare ack).
        let (code, body) = call(&st, "POST", "/v1/cloud/local-only").await;
        assert_eq!(code, 200, "body={body}");
        assert_eq!(body["state"], json!("local_only"), "default-enable keeps it on");
    }

    #[tokio::test]
    async fn poll_without_start_is_expired() {
        // With no in-flight flow, poll reports the terminal `expired` state (never 500s).
        let (_dir, st) = test_state().await;
        // Defensively clear any cross-test pending flow (the slot is process-global).
        link::clear_pending().await;
        let (code, body) = call(&st, "POST", "/v1/cloud/link/poll").await;
        assert_eq!(code, 200, "body={body}");
        assert_eq!(body["status"], json!("expired"));
    }

    #[tokio::test]
    async fn unlink_is_ok_and_idempotent() {
        let (_dir, st) = test_state().await;
        // Unlink with nothing linked still succeeds.
        let (code, body) = call(&st, "POST", "/v1/cloud/unlink").await;
        assert_eq!(code, 200, "body={body}");
        assert_eq!(body["ok"], json!(true));
        // And again (idempotent).
        let (code, body) = call(&st, "POST", "/v1/cloud/unlink").await;
        assert_eq!(code, 200, "body={body}");
        assert_eq!(body["ok"], json!(true));
    }

    #[tokio::test]
    async fn entitlements_unlinked_fails_closed_to_free() {
        // Hold the shared env guard: this test mutates the process-global WRIT_HOME, which would
        // otherwise race any concurrent test that resolves `Paths` from the env (e.g. the backup
        // snapshot opening a keyed DB at the resolved path).
        let _g = crate::local::config::test_env_guard();
        // Not linked + no cache → fail-closed reflection: plan "free", empty maps, never errors.
        let (_dir, st) = test_state().await;
        // Pin WRIT_HOME at the throwaway tempdir so the grace-aware `load_cached()` fallback reads
        // an EMPTY cloud dir, not the developer's real `~/.writ/cloud/entitlements.json` (which, on
        // a linked dev box, would otherwise reflect a live plan and flake this assertion). No other
        // test in this file consults `WRIT_HOME` (they all use `config::Paths::at`), so this is safe.
        std::env::set_var("WRIT_HOME", _dir.path().join(".writ"));
        let (code, body) = call(&st, "GET", "/v1/cloud/entitlements").await;
        std::env::remove_var("WRIT_HOME");
        assert_eq!(code, 200, "body={body}");
        assert_eq!(body["plan"], json!("free"));
        assert!(body["features"].is_object(), "features must be an object: {body}");
        assert!(body["limits"].is_object(), "limits must be an object: {body}");
        // The widened contract surfaces these fields (fail-closed values when unlinked).
        assert_eq!(body["can_monetize"], json!(false), "body={body}");
        assert!(body["nav"].is_object(), "nav must be an object: {body}");
        assert!(body["web_url"].is_string(), "web_url must be a string: {body}");
        assert_eq!(body["failed_closed"], json!(true), "body={body}");
    }

    #[tokio::test]
    async fn routes_require_the_loopback_bearer() {
        // No bearer → the server.rs auth middleware rejects with 401 before reaching the handler.
        let (_dir, st) = test_state().await;
        let resp = build_router(st.clone())
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/cloud/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 401);
    }

    /// Issue an authenticated loopback request with a JSON body (for the push route).
    async fn call_json(st: &AppState, method: &str, uri: &str, body: Value) -> (u16, Value) {
        let resp = build_router(st.clone())
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("authorization", format!("Bearer {TOKEN}"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, body)
    }

    #[tokio::test]
    async fn sync_pull_returns_contract_shape_never_500() {
        // The pull handler must ALWAYS return the contract shape and never 500, regardless of link
        // state. We point the cloud at an unroutable loopback port so that even on a linked dev box
        // (where the keyring may hold a real token) the fetch fails fast and the pull degrades to
        // ok=false rather than hitting a live backend. The shape contract is the invariant under test.
        let prev = std::env::var(crate::local::cloud::client::ENV_CLOUD_URL).ok();
        std::env::set_var(crate::local::cloud::client::ENV_CLOUD_URL, "http://127.0.0.1:1");
        let (_dir, st) = test_state().await;
        let (code, body) = call(&st, "POST", "/v1/cloud/sync/pull").await;
        match prev {
            Some(v) => std::env::set_var(crate::local::cloud::client::ENV_CLOUD_URL, v),
            None => std::env::remove_var(crate::local::cloud::client::ENV_CLOUD_URL),
        }
        assert_eq!(code, 200, "body={body}");
        assert!(body["ok"].is_boolean(), "ok present: {body}");
        assert!(body["counts"].is_object(), "counts present: {body}");
        assert!(body["counts"]["workflows"].is_number(), "counts.workflows present: {body}");
        assert!(body["diverged"].is_array(), "diverged is an array: {body}");
        assert!(body["errors"].is_array(), "errors is an array: {body}");
    }

    #[tokio::test]
    async fn sync_status_and_items_shapes() {
        let (_dir, st) = test_state().await;
        let (code, body) = call(&st, "GET", "/v1/cloud/sync/status").await;
        assert_eq!(code, 200, "body={body}");
        assert_eq!(body["in_progress"], json!(false));
        assert!(body["counts"].is_object());
        assert_eq!(body["diverged_count"], json!(0));

        let (code, body) = call(&st, "GET", "/v1/cloud/sync/items").await;
        assert_eq!(code, 200, "body={body}");
        assert!(body["items"].is_array(), "items is an array: {body}");
    }

    #[tokio::test]
    async fn sync_push_skips_unpushable_ids_never_500() {
        // Push references ids that don't exist locally → each is skipped with a reason; never 500.
        // Point the cloud at an unroutable port so a linked dev box can't reach a real backend; the
        // ids (1,2) don't exist in this throwaway DB, so they're skipped as "not found" before any
        // network call anyway. The shape contract (ok + pushed[] + skipped[]) is the invariant.
        let prev = std::env::var(crate::local::cloud::client::ENV_CLOUD_URL).ok();
        std::env::set_var(crate::local::cloud::client::ENV_CLOUD_URL, "http://127.0.0.1:1");
        let (_dir, st) = test_state().await;
        let (code, body) = call_json(
            &st,
            "POST",
            "/v1/cloud/sync/push",
            json!({ "entity_type": "workflow", "local_ids": [1, 2] }),
        )
        .await;
        match prev {
            Some(v) => std::env::set_var(crate::local::cloud::client::ENV_CLOUD_URL, v),
            None => std::env::remove_var(crate::local::cloud::client::ENV_CLOUD_URL),
        }
        assert_eq!(code, 200, "body={body}");
        assert!(body["ok"].is_boolean(), "ok present: {body}");
        assert!(body["pushed"].as_array().unwrap().is_empty(), "nothing pushed: {body}");
        assert_eq!(body["skipped"].as_array().unwrap().len(), 2, "both ids skipped: {body}");
    }

    // ---- Native marketplace routes (daemon stage 2) -------------------------------------------

    #[tokio::test]
    async fn marketplace_routes_require_the_loopback_bearer() {
        // No bearer → 401 from server.rs auth_mw before reaching any handler (proves the routes are
        // mounted under the same guard as the rest of /v1/cloud).
        let (_dir, st) = test_state().await;
        for (method, uri) in [
            ("GET", "/v1/cloud/marketplace/listings"),
            ("GET", "/v1/cloud/marketplace/installs"),
            ("POST", "/v1/cloud/marketplace/install"),
            ("POST", "/v1/cloud/marketplace/run"),
        ] {
            let resp = build_router(st.clone())
                .oneshot(
                    Request::builder().method(method).uri(uri).body(Body::empty()).unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status().as_u16(), 401, "{method} {uri} must require the bearer");
        }
    }

    #[tokio::test]
    async fn marketplace_installs_lists_local_metadata_unlinked() {
        // The installs LIST reads only the local DB (no cloud call), so it works while unlinked and
        // returns the contract shape. We seed one install row directly and assert the metadata-only
        // projection comes back WITHOUT the sealed blob (invariant 1 at the API boundary).
        let (_dir, st) = test_state().await;
        crate::local::store::installed_workflows::upsert(
            &st.db,
            &crate::local::store::installed_workflows::NewInstall {
                slug: "cool-wf".into(),
                listing_title: Some("Cool WF".into()),
                creator: Some("acme".into()),
                is_free: false,
                price_micros: Some(50_000),
                proxy_cloud_id: Some("wf_proxy".into()),
                sealed_recipe: "WF1:opaque_blob_must_not_leak".into(),
                input_schema: None,
            },
        )
        .await
        .unwrap();

        let (code, body) = call(&st, "GET", "/v1/cloud/marketplace/installs").await;
        assert_eq!(code, 200, "body={body}");
        // Contract: `{ installs: [...] }` (the desktop MarketplaceInstalledItem[] shape).
        assert_eq!(body["installs"].as_array().map(|a| a.len()), Some(1), "body={body}");
        assert_eq!(body["installs"][0]["slug"], json!("cool-wf"));
        assert_eq!(body["installs"][0]["is_free"], json!(false));
        // The sealed blob must NEVER appear in the API surface.
        let raw = body.to_string();
        assert!(!raw.contains("sealed"), "installs JSON must not leak the sealed recipe: {raw}");
        assert!(!raw.contains("opaque_blob_must_not_leak"), "no sealed value may leak: {raw}");
    }

    #[tokio::test]
    async fn reflect_routes_require_the_loopback_bearer() {
        // No bearer → 401 from server.rs auth_mw before reaching any handler (proves the reflection
        // routes are mounted under the same guard as the rest of /v1/cloud).
        let (_dir, st) = test_state().await;
        for (method, uri) in [
            ("GET", "/v1/cloud/reflect/workflows"),
            ("POST", "/v1/cloud/reflect/workflows/42/run"),
            ("GET", "/v1/cloud/reflect/workflows/run/99"),
            ("POST", "/v1/cloud/reflect/workflows/42/copy-local"),
            ("GET", "/v1/cloud/reflect/monitors"),
            ("POST", "/v1/cloud/reflect/monitors/create"),
            ("POST", "/v1/cloud/reflect/monitors/42/enable"),
            ("POST", "/v1/cloud/reflect/monitors/42/update"),
            ("POST", "/v1/cloud/reflect/monitors/42/copy-local"),
            ("GET", "/v1/cloud/reflect/personas"),
            ("POST", "/v1/cloud/reflect/personas/42/copy-local"),
        ] {
            let resp = build_router(st.clone())
                .oneshot(
                    Request::builder().method(method).uri(uri).body(Body::empty()).unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status().as_u16(), 401, "{method} {uri} must require the bearer");
        }
    }

    #[tokio::test]
    async fn reflect_workflows_unlinked_is_unauthorized_not_404() {
        // The live list passthrough requires a cloud client; unlinked (no keyring token) degrades to
        // a clean 401 — NOT a 404/hang. Point the cloud at an unroutable port so a linked dev box
        // can't reach a real backend and instead fails fast on connect/refresh.
        let prev = std::env::var(crate::local::cloud::client::ENV_CLOUD_URL).ok();
        std::env::set_var(crate::local::cloud::client::ENV_CLOUD_URL, "http://127.0.0.1:1");
        let (_dir, st) = test_state().await;
        let (code, _body) = call(&st, "GET", "/v1/cloud/reflect/workflows").await;
        match prev {
            Some(v) => std::env::set_var(crate::local::cloud::client::ENV_CLOUD_URL, v),
            None => std::env::remove_var(crate::local::cloud::client::ENV_CLOUD_URL),
        }
        // Unlinked → 401; a linked dev box pointed at the dead port → 500 (network). Either is a
        // clean non-404 error, never a hang or a silent success.
        assert!(code == 401 || code == 500, "expected 401 (unlinked) or 500 (unreachable), got {code}");
    }

    #[tokio::test]
    async fn reflect_monitors_and_personas_unlinked_are_unauthorized_not_404() {
        // The monitor + persona live-list passthroughs each require a cloud client; unlinked (no
        // keyring token) degrades to a clean 401 — NOT a 404/hang. Point the cloud at an unroutable
        // port so a linked dev box fails fast on connect/refresh instead of hitting a live backend.
        let prev = std::env::var(crate::local::cloud::client::ENV_CLOUD_URL).ok();
        std::env::set_var(crate::local::cloud::client::ENV_CLOUD_URL, "http://127.0.0.1:1");
        let (_dir, st) = test_state().await;
        let (mcode, _m) = call(&st, "GET", "/v1/cloud/reflect/monitors").await;
        let (pcode, _p) = call(&st, "GET", "/v1/cloud/reflect/personas").await;
        match prev {
            Some(v) => std::env::set_var(crate::local::cloud::client::ENV_CLOUD_URL, v),
            None => std::env::remove_var(crate::local::cloud::client::ENV_CLOUD_URL),
        }
        // Unlinked → 401; a linked dev box pointed at the dead port → 500 (network). Either is a
        // clean non-404 error, never a hang or a silent success.
        assert!(mcode == 401 || mcode == 500, "monitors: expected 401|500, got {mcode}");
        assert!(pcode == 401 || pcode == 500, "personas: expected 401|500, got {pcode}");
    }

    #[tokio::test]
    async fn reflect_local_workflows_unlinked_is_unauthorized_not_404() {
        // The cloud-callable catalog read-back is a cloud passthrough like its siblings: unlinked
        // (no keyring token) must degrade to a clean 401, NOT a 404 the webview would mistake for
        // "this daemon is too old" and NOT a hang. The Connect surfaces treat any failure as "no
        // cloud address to advertise", so the only thing that matters is that it fails fast.
        let prev = std::env::var(crate::local::cloud::client::ENV_CLOUD_URL).ok();
        std::env::set_var(crate::local::cloud::client::ENV_CLOUD_URL, "http://127.0.0.1:1");
        let (_dir, st) = test_state().await;
        let (code, _body) = call(&st, "GET", "/v1/cloud/reflect/local-workflows").await;
        match prev {
            Some(v) => std::env::set_var(crate::local::cloud::client::ENV_CLOUD_URL, v),
            None => std::env::remove_var(crate::local::cloud::client::ENV_CLOUD_URL),
        }
        assert!(code == 401 || code == 500, "expected 401 (unlinked) or 500 (unreachable), got {code}");
    }

    #[tokio::test]
    async fn reflect_api_keys_routes_exist_and_are_unauthorized_when_unlinked() {
        // Cloud ACCOUNT keys are minted through the daemon so the desktop never needs the web app.
        // All three routes must be MOUNTED — a 404 here would read to the key screen as "this
        // daemon is too old" and silently hide cloud keys — and must fail closed when unlinked.
        let prev = std::env::var(crate::local::cloud::client::ENV_CLOUD_URL).ok();
        std::env::set_var(crate::local::cloud::client::ENV_CLOUD_URL, "http://127.0.0.1:1");
        let (_dir, st) = test_state().await;
        let (list, _) = call(&st, "GET", "/v1/cloud/reflect/api-keys").await;
        let (catalog, _) = call(&st, "GET", "/v1/cloud/reflect/api-keys/catalog").await;
        let (revoke, _) = call(&st, "POST", "/v1/cloud/reflect/api-keys/1/delete").await;
        match prev {
            Some(v) => std::env::set_var(crate::local::cloud::client::ENV_CLOUD_URL, v),
            None => std::env::remove_var(crate::local::cloud::client::ENV_CLOUD_URL),
        }
        for (name, code) in [("list", list), ("catalog", catalog), ("revoke", revoke)] {
            assert!(code == 401 || code == 500, "{name}: expected 401|500, got {code}");
        }
    }

    #[tokio::test]
    async fn marketplace_run_absent_install_is_404() {
        // The protected executor loads the install row FIRST; an uninstalled slug is a clean 404
        // (no cloud authorize-run, no execution) regardless of link state.
        let (_dir, st) = test_state().await;
        let (code, body) =
            call_json(&st, "POST", "/v1/cloud/marketplace/run", json!({ "slug": "nope" })).await;
        assert_eq!(code, 404, "body={body}");
        assert_eq!(body["code"], json!("not_found"));
    }

    #[tokio::test]
    async fn marketplace_browse_unlinked_is_unauthorized_not_404() {
        // Browse passthrough requires a cloud client; unlinked (no keyring token) degrades to a clean
        // 401 Unauthorized — NOT a 404/hang. We point the cloud at an unroutable port so a linked dev
        // box can't reach a real backend and instead fails fast on connect/refresh.
        let prev = std::env::var(crate::local::cloud::client::ENV_CLOUD_URL).ok();
        std::env::set_var(crate::local::cloud::client::ENV_CLOUD_URL, "http://127.0.0.1:1");
        let (_dir, st) = test_state().await;
        let (code, _body) = call(&st, "GET", "/v1/cloud/marketplace/listings").await;
        match prev {
            Some(v) => std::env::set_var(crate::local::cloud::client::ENV_CLOUD_URL, v),
            None => std::env::remove_var(crate::local::cloud::client::ENV_CLOUD_URL),
        }
        // Unlinked → 401; a linked dev box pointed at the dead port → 500 (network). Either is a clean
        // non-404 error, never a hang or a silent success.
        assert!(code == 401 || code == 500, "expected 401 (unlinked) or 500 (unreachable), got {code}");
    }
}
