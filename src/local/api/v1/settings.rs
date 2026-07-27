//! `/v1/settings/runtime` REST handlers — the desktop "Daemon / Browser" runtime-settings surface.
//!
//! One tab in Settings lets the user set (and ENFORCE) the daemon's resource + browser runtime knobs:
//!   * the resource-governor ceilings — `max_concurrent_runs`, `max_background_runs`, and the soft
//!     RSS/"max RAM" watermark (`rss_soft_watermark_mb`, `0` = disabled),
//!   * the global browser `headless` default,
//!   * the monitor cadence floors — the minimum content-check + browser-check intervals
//!     (`html_floor_ms`/`js_floor_ms`), clamped up to the hard anti-detection constants.
//!
//! Routes (loopback + bearer gated by `server.rs`; the Tauri shell proxies onto these):
//!   GET /v1/settings/runtime  → { settings, running, pending_restart, bounds, live }
//!   PUT /v1/settings/runtime  { <any subset of the settings fields> }
//!                             → the same shape, reflecting the just-persisted (clamped) values.
//!
//! LIFECYCLE (mixed):
//!   * The governor ceilings + the browser headless default are read at BOOT — the running governor's
//!     semaphore and the warm browser's launch mode are FIXED for the session — so a change takes
//!     effect only on the next daemon start. `pending_restart` is `true` while those on-disk values
//!     differ from what is running; the Tauri shell applies them by restarting the sidecar.
//!   * The monitor floors apply IMMEDIATELY (no restart): the PUT re-installs them into the
//!     scheduler's process-global clamp ([`clamp::install_monitor_floors`]), so the next tick honors
//!     the new cadence. They are therefore NOT part of `pending_restart`.
//!
//! House style: thin handlers over `config` helpers + the live `AppState` (governor/engine/health),
//! `LocalResult<Json<_>>` with `?` propagation, no auth layer here. `tracing` only, NEVER a secret —
//! this surface carries none (only non-secret resource ceilings + observability counters).
//!
//! Net-new Rust in this crate (behind the `local` feature).

use crate::local::auth::{self, Caller, Scope};
use crate::local::config::{
    self, Paths, RuntimeSettings, HTML_FLOOR_MS, JS_FLOOR_MS, MAX_CONCURRENT_RUNS_CEILING,
    MIN_RSS_SOFT_WATERMARK_MB,
};
use crate::local::scheduler::clamp;
use crate::local::error::{LocalError, LocalResult};
use crate::local::server::AppState;
use axum::extract::State;
use axum::routing::get;
use axum::{Extension, Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

const BYTES_PER_MB: u64 = 1024 * 1024;

/// Mount the `/v1/settings/*` routes onto the shared `AppState` router. Auth is applied by `server.rs`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/settings/runtime", get(get_runtime).put(put_runtime))
        .route("/v1/settings/telemetry", get(get_telemetry).put(put_telemetry))
        .route("/v1/settings/telemetry/report", axum::routing::post(post_telemetry_report))
}

/// Partial update body for `PUT /v1/settings/runtime`. Every field is optional so the UI can PATCH a
/// single knob; omitted fields keep their current on-disk value. Values are clamped on persist (see
/// [`RuntimeSettings::clamp`]), so an out-of-range input is corrected rather than rejected.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RuntimeUpdate {
    max_concurrent_runs: Option<usize>,
    max_background_runs: Option<usize>,
    rss_soft_watermark_mb: Option<u64>,
    browser_headless: Option<bool>,
    browser_disable_sandbox: Option<bool>,
    browser_ignore_certificate_errors: Option<bool>,
    browser_disable_web_security: Option<bool>,
    browser_use_local_chrome: Option<bool>,
    html_floor_ms: Option<u64>,
    js_floor_ms: Option<u64>,
}

impl RuntimeUpdate {
    /// Apply the provided (Some) fields over a base [`RuntimeSettings`]; omitted fields are unchanged.
    fn merge_over(&self, base: RuntimeSettings) -> RuntimeSettings {
        RuntimeSettings {
            max_concurrent_runs: self.max_concurrent_runs.unwrap_or(base.max_concurrent_runs),
            max_background_runs: self.max_background_runs.unwrap_or(base.max_background_runs),
            rss_soft_watermark_mb: self.rss_soft_watermark_mb.unwrap_or(base.rss_soft_watermark_mb),
            browser_headless: self.browser_headless.unwrap_or(base.browser_headless),
            browser_disable_sandbox: self
                .browser_disable_sandbox
                .unwrap_or(base.browser_disable_sandbox),
            browser_ignore_certificate_errors: self
                .browser_ignore_certificate_errors
                .unwrap_or(base.browser_ignore_certificate_errors),
            browser_disable_web_security: self
                .browser_disable_web_security
                .unwrap_or(base.browser_disable_web_security),
            browser_use_local_chrome: self
                .browser_use_local_chrome
                .unwrap_or(base.browser_use_local_chrome),
            html_floor_ms: self.html_floor_ms.unwrap_or(base.html_floor_ms),
            js_floor_ms: self.js_floor_ms.unwrap_or(base.js_floor_ms),
        }
    }
}

/// The four browser knobs `config::env` itself labels "DANGEROUS, opt-in" — each one strips a browser
/// security boundary for EVERY subsequent run on this device:
///   * `browser_disable_sandbox` — no renderer sandbox, so a hostile page's renderer exploit lands
///     directly in the daemon's own process context,
///   * `browser_ignore_certificate_errors` — TLS is no longer authenticated (MITM),
///   * `browser_disable_web_security` — no same-origin policy, so one visited page can read any other,
///   * `browser_use_local_chrome` — seeds the profile from the user's REAL Chrome, importing their
///     live cookie jar / logged-in sessions into automated browsing.
///
/// Flipping these is device control, not resource tuning: it decides what a later `run`-scoped call
/// gets to do to the user. Ordered/named so the before-after comparison in [`put_runtime`] can never
/// silently drop a flag — add a new dangerous knob HERE and the gate covers it.
fn dangerous_flags(s: &RuntimeSettings) -> [(&'static str, bool); 4] {
    [
        ("browser_disable_sandbox", s.browser_disable_sandbox),
        ("browser_ignore_certificate_errors", s.browser_ignore_certificate_errors),
        ("browser_disable_web_security", s.browser_disable_web_security),
        ("browser_use_local_chrome", s.browser_use_local_chrome),
    ]
}

/// `GET /v1/settings/runtime` — the current on-disk settings + what's actually running + live counters.
async fn get_runtime(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    Ok(Json(snapshot(&st)?))
}

/// `PUT /v1/settings/runtime` — merge the provided fields over the current on-disk settings, clamp to
/// a safe shape, and persist to `~/.writ/config.toml` (read-modify-write preserving every other
/// field). Returns the refreshed snapshot so the UI re-renders the clamped values + the new
/// `pending_restart`. Idempotent: re-persisting the same values is a harmless no-op flip.
///
/// SECURITY (AC-2) — this is a MIXED-PRIVILEGE route. Most of what it carries is benign resource
/// tuning that an `admin` key should be able to set, but the same body can flip the four
/// [`dangerous_flags`], which is device control. `auth::required_scope` sees only method+path and so
/// leaves the route at `Admin`; the DANGEROUS subset is gated HERE, against the capability
/// `server::auth_mw` resolved for this request, requiring the separate `Manage` grant that `admin`
/// deliberately does not imply.
///
/// The comparison is on EFFECTIVE VALUES (post-clamp, on-disk base vs merged result), not on key
/// presence: a caller re-sending `browser_disable_sandbox: false` when it is already false changes
/// nothing and stays `Admin`, while a caller who omits the key cannot sneak a change through either.
/// The full-access `wlt_` UI token is `Caller::FullAccess`, so the desktop Settings tab is unaffected.
async fn put_runtime(
    State(st): State<AppState>,
    caller: Option<Extension<Caller>>,
    Json(update): Json<RuntimeUpdate>,
) -> LocalResult<Json<Value>> {
    let paths = Paths::resolve()?;
    // Base = the current ON-DISK settings (not the boot snapshot) so a partial PATCH composes with any
    // value saved earlier this session but not yet applied via a restart.
    let base = RuntimeSettings::from_local(&config::load_config(&paths));
    let merged = update.merge_over(base);

    // Device-control gate: only when a dangerous flag's effective value actually MOVES. Fails closed
    // if the auth middleware never ran (`caller_or_deny`), and refuses BEFORE anything is persisted.
    let before = dangerous_flags(&base.clamp());
    let after = dangerous_flags(&merged.clamp());
    if before != after {
        let caller = auth::caller_or_deny(caller.as_ref().map(|Extension(c)| c));
        if !caller.grants(Scope::Manage) {
            let changed: Vec<&str> = before
                .iter()
                .zip(after.iter())
                .filter(|((_, b), (_, a))| b != a)
                .map(|((name, _), _)| *name)
                .collect();
            tracing::warn!(
                caller = caller.describe(),
                changed = ?changed,
                "refusing runtime-settings update: flipping a DANGEROUS browser flag needs the `manage` \
                 capability (device control), which `admin` does not grant"
            );
            return Err(LocalError::Forbidden);
        }
    }

    config::set_runtime_settings(&paths, &merged)?;
    let saved = merged.clamp();
    // The monitor floors apply LIVE — re-install them into the scheduler's process-global clamp so the
    // next tick honors the new cadence WITHOUT a restart. (The governor + headless knobs are
    // boot-fixed; the caller restarts the engine to apply those — see `pending_restart`.)
    clamp::install_monitor_floors(saved.html_floor_ms, saved.js_floor_ms);
    tracing::info!(
        max_concurrent_runs = saved.max_concurrent_runs,
        max_background_runs = saved.max_background_runs,
        rss_soft_watermark_mb = saved.rss_soft_watermark_mb,
        browser_headless = saved.browser_headless,
        browser_disable_sandbox = saved.browser_disable_sandbox,
        browser_ignore_certificate_errors = saved.browser_ignore_certificate_errors,
        browser_disable_web_security = saved.browser_disable_web_security,
        browser_use_local_chrome = saved.browser_use_local_chrome,
        html_floor_ms = saved.html_floor_ms,
        js_floor_ms = saved.js_floor_ms,
        "runtime settings persisted (governor + browser knobs apply on the next daemon restart; monitor floors applied live)"
    );
    Ok(Json(snapshot(&st)?))
}

/// Body for `PUT /v1/settings/telemetry`.
#[derive(Debug, Deserialize)]
struct TelemetryUpdate {
    enabled: bool,
}

/// `GET /v1/settings/telemetry` — the anonymized-usage-metrics opt-in, plus enough reporting state for
/// the Settings tab to be HONEST about what has actually happened: the random install id that is the
/// only identifier in a report, and the last whole UTC day the cloud accepted.
///
/// Both reporting fields are `null` when telemetry is off (opting out deletes them) and in builds
/// without the `cloud` feature (the OSS self-host daemon has no ingest at all, so the toggle is inert
/// there and the UI can say so).
async fn get_telemetry(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    let paths = Paths::resolve()?;
    let enabled = config::load_config(&paths).telemetry_opt_in;
    Ok(Json(telemetry_snapshot(&st, enabled).await))
}

/// `PUT /v1/settings/telemetry` — persist the opt-in to `~/.writ/config.toml`.
///
/// This route exists because the Tauri shell CANNOT write this key: `[app].telemetry_opt_in` is
/// daemon-authoritative and the shell's `config_set` allowlist rejects it (an XSS'd webview must not
/// be able to retune the daemon). So the toggle goes through the authenticated loopback API instead.
///
/// Takes effect within one reporter tick — no restart. Turning it OFF is a full stop: the reporter
/// drops the install id and the last-reported cursor on its next tick, so re-enabling later starts a
/// fresh identity that cannot be correlated with anything sent before.
async fn put_telemetry(
    State(st): State<AppState>,
    Json(update): Json<TelemetryUpdate>,
) -> LocalResult<Json<Value>> {
    let paths = Paths::resolve()?;
    config::set_telemetry_opt_in(&paths, update.enabled)?;
    tracing::info!(
        enabled = update.enabled,
        "anonymized usage telemetry opt-in persisted (applies on the next reporter tick)"
    );
    Ok(Json(telemetry_snapshot(&st, update.enabled).await))
}

/// Body for `POST /v1/settings/telemetry/report`. Both fields are optional; the defaults (dry run,
/// yesterday) are the safe ones, so a bare `{}` shows you what would be sent without sending it.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct TelemetryReportRequest {
    /// `true` (default) builds the report and returns it WITHOUT sending. `false` sends it.
    dry_run: Option<bool>,
    /// `YYYY-MM-DD`; defaults to yesterday, the most recent complete day.
    day: Option<String>,
}

/// `POST /v1/settings/telemetry/report` — build (and optionally send) a usage report right now.
///
/// The reporter loop runs on a daily cadence, which left the feature unverifiable: there was no way
/// to answer "what exactly would this send?" or "is the pipeline actually working?" without waiting
/// a day. The DEFAULT is a dry run, which is the honest-disclosure affordance — the user can read
/// the exact payload before trusting the copy that describes it.
///
/// `manage`-gated like the opt-in itself (`is_device_management_path`): sending is egress, and a dry
/// run still summarizes this device's activity into a response.
async fn post_telemetry_report(
    State(st): State<AppState>,
    body: Option<Json<TelemetryReportRequest>>,
) -> LocalResult<Json<Value>> {
    let req = body.map(|Json(b)| b).unwrap_or_default();
    // Annotate the parse target explicitly. `report_now` (the only consumer) is behind
    // `#[cfg(feature = "cloud")]`, so in a cloud-free build — the OSS `local,fleet,openai` worker and
    // the desktop `local,openai` daemon — nothing downstream constrains this type and inference falls
    // back to `()`, which is a hard `(): FromStr` compile error rather than a warning.
    let day: Option<chrono::NaiveDate> =
        match req.day.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(s) => Some(s.parse().map_err(|_| {
                LocalError::BadRequest("day must be YYYY-MM-DD".into())
            })?),
            None => None,
        };
    let dry_run = req.dry_run.unwrap_or(true);

    #[cfg(feature = "cloud")]
    {
        let outcome = crate::local::cloud::usage_metrics::report_now(&st.db, day, dry_run).await?;
        tracing::info!(
            sent = outcome.sent,
            skipped = outcome.skipped_reason.as_deref().unwrap_or("-"),
            "on-demand usage report"
        );
        Ok(Json(serde_json::to_value(outcome).unwrap_or(Value::Null)))
    }
    #[cfg(not(feature = "cloud"))]
    {
        let _ = (st, day, dry_run);
        Err(LocalError::BadRequest(
            "this build has no cloud ingest, so there is nothing to report".into(),
        ))
    }
}

/// Shared body for both telemetry handlers. Never carries a secret — an install id is a random UUID
/// with no relationship to the account, the hardware, or any user data.
async fn telemetry_snapshot(st: &AppState, enabled: bool) -> Value {
    #[cfg(feature = "cloud")]
    let (install_id, last_reported_day, supported) = {
        use crate::local::cloud::usage_metrics::{INSTALL_ID_KEY, LAST_PERIOD_KEY};
        use crate::local::store::config_kv;
        let get = |k: &'static str| async move { config_kv::get(&st.db, k).await.ok().flatten() };
        (get(INSTALL_ID_KEY).await, get(LAST_PERIOD_KEY).await, true)
    };
    #[cfg(not(feature = "cloud"))]
    let (install_id, last_reported_day, supported) = {
        let _ = st;
        (None::<String>, None::<String>, false)
    };

    json!({
        "enabled": enabled,
        // False in the OSS/self-host build: there is no cloud ingest, so the toggle collects nothing.
        "supported": supported,
        "install_id": install_id,
        "last_reported_day": last_reported_day,
    })
}

/// Build the response body: the ON-DISK settings (what the form edits), the RUNNING values (what is
/// actually in effect right now — the live governor config + the boot-time headless), a
/// `pending_restart` flag (the boot-fixed knobs differ from disk ⇒ a restart is needed to apply), the
/// hard bounds the UI validates against, and live observability (RSS, run slots, warm browser).
fn snapshot(st: &AppState) -> LocalResult<Value> {
    let paths = Paths::resolve()?;
    let on_disk = RuntimeSettings::from_local(&config::load_config(&paths));

    // What is actually RUNNING now. The governor is the source of truth for the run ceilings (its
    // semaphore was sized at boot from the then-current config); the warm browser launched with the
    // boot-time headless (`AppState.config`). Fall back to the boot config snapshot if there is no
    // governor (the test-only `StubEngine`).
    let gov = st.engine.governor();
    let (running_concurrent, running_background, running_rss_mb) = match gov.as_ref() {
        Some(g) => {
            let c = g.config();
            (c.max_concurrent_runs, c.max_background_runs, c.rss_soft_watermark_bytes / BYTES_PER_MB)
        }
        None => (
            st.config.max_concurrent_runs,
            st.config.max_background_runs,
            st.config.rss_soft_watermark_mb,
        ),
    };
    let running_headless = st.config.browser_headless;
    // The DANGEROUS browser-security toggles are boot-fixed too (the warm browser's argv is set at
    // launch from `AppState.config`), so they participate in `pending_restart` exactly like headless.
    let running_disable_sandbox = st.config.browser_disable_sandbox;
    let running_ignore_cert = st.config.browser_ignore_certificate_errors;
    let running_disable_web_security = st.config.browser_disable_web_security;
    let running_use_local_chrome = st.config.browser_use_local_chrome;

    // A restart is pending when a BOOT-FIXED knob on disk no longer matches what's running. The monitor
    // floors are re-read every tick, so they are deliberately NOT part of this comparison.
    let pending_restart = on_disk.max_concurrent_runs != running_concurrent
        || on_disk.max_background_runs != running_background
        || on_disk.rss_soft_watermark_mb != running_rss_mb
        || on_disk.browser_headless != running_headless
        || on_disk.browser_disable_sandbox != running_disable_sandbox
        || on_disk.browser_ignore_certificate_errors != running_ignore_cert
        || on_disk.browser_disable_web_security != running_disable_web_security
        || on_disk.browser_use_local_chrome != running_use_local_chrome;

    // Live observability (never a secret): current footprint + run-slot occupancy + warm-browser hint.
    let active_runs = st.engine.active_runs();
    let live = match gov.as_ref() {
        Some(g) => json!({
            "governor_present": true,
            "rss_mb": g.rss_sample_bytes() / BYTES_PER_MB,
            "active_runs": active_runs,
            "available_slots": g.available_slots(),
            "background_inflight": g.background_inflight(),
            "background_ceiling": running_background,
            "warm_browser": st.health.warm_browser() || active_runs > 0,
        }),
        None => json!({
            "governor_present": false,
            "rss_mb": Value::Null,
            "active_runs": active_runs,
            "available_slots": Value::Null,
            "background_inflight": Value::Null,
            "background_ceiling": running_background,
            "warm_browser": st.health.warm_browser() || active_runs > 0,
        }),
    };

    Ok(json!({
        "settings": settings_json(&on_disk),
        "running": {
            "max_concurrent_runs": running_concurrent,
            "max_background_runs": running_background,
            "rss_soft_watermark_mb": running_rss_mb,
            "browser_headless": running_headless,
            "browser_disable_sandbox": running_disable_sandbox,
            "browser_ignore_certificate_errors": running_ignore_cert,
            "browser_disable_web_security": running_disable_web_security,
            "browser_use_local_chrome": running_use_local_chrome,
        },
        "pending_restart": pending_restart,
        "bounds": {
            "max_concurrent_runs_ceiling": MAX_CONCURRENT_RUNS_CEILING,
            "min_rss_soft_watermark_mb": MIN_RSS_SOFT_WATERMARK_MB,
            "html_floor_ms_min": HTML_FLOOR_MS,
            "js_floor_ms_min": JS_FLOOR_MS,
        },
        "live": live,
    }))
}

/// Serialize the editable settings subset (the shape the PUT accepts and the form renders).
fn settings_json(s: &RuntimeSettings) -> Value {
    json!({
        "max_concurrent_runs": s.max_concurrent_runs,
        "max_background_runs": s.max_background_runs,
        "rss_soft_watermark_mb": s.rss_soft_watermark_mb,
        "browser_headless": s.browser_headless,
        "browser_disable_sandbox": s.browser_disable_sandbox,
        "browser_ignore_certificate_errors": s.browser_ignore_certificate_errors,
        "browser_disable_web_security": s.browser_disable_web_security,
        "browser_use_local_chrome": s.browser_use_local_chrome,
        "html_floor_ms": s.html_floor_ms,
        "js_floor_ms": s.js_floor_ms,
    })
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

    const TOKEN: &str = "wlt_settings_secret";

    /// A loopback `AppState` over a throwaway encrypted DB, with `WRIT_HOME` pointed at the sandbox so
    /// the handlers' `Paths::resolve()` reads/writes the test config.toml (not the real home). The
    /// engine is the `StubEngine` (no governor) — the handler's no-governor branch is exercised; the
    /// running values then echo the boot config snapshot. Caller holds the shared env guard.
    async fn test_state(config: LocalConfig) -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("WRIT_HOME", dir.path().join(".writ"));
        for k in [
            "WRIT_MAX_CONCURRENT_RUNS",
            "WRIT_MAX_BACKGROUND_RUNS",
            "WRIT_RSS_SOFT_WATERMARK_MB",
            "WRIT_HEADLESS",
            "WRIT_HTML_FLOOR_MS",
            "WRIT_JS_FLOOR_MS",
        ] {
            std::env::remove_var(k);
        }
        let paths = Paths::resolve().unwrap();
        paths.ensure_dirs().unwrap();
        let v = vault::Vault::load_or_create(&paths.root, false).unwrap();
        let pool = db::open(&paths.db(), &v.db_key_hex()).await.unwrap();
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

    async fn call(st: &AppState, method: &str, uri: &str, body: Option<&str>) -> (u16, Value) {
        call_as(st, TOKEN, method, uri, body).await
    }

    /// Same as [`call`] but with an arbitrary bearer, so a scoped `wlk_` key can be exercised through
    /// the real `server::auth_mw` (the only place `Caller` is resolved).
    async fn call_as(
        st: &AppState,
        bearer: &str,
        method: &str,
        uri: &str,
        body: Option<&str>,
    ) -> (u16, Value) {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {bearer}"))
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

    /// Mint a scoped `wlk_` key straight into the store and return the raw bearer.
    async fn mint_key(st: &AppState, scopes: &str) -> String {
        use crate::local::store::local_api_keys::{insert, NewLocalApiKey};
        let raw = format!("wlk_settings_{}", scopes.replace(',', "_"));
        let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
        sha2::Digest::update(&mut hasher, raw.as_bytes());
        let key_hash: String =
            sha2::Digest::finalize(hasher).iter().map(|b| format!("{b:02x}")).collect();
        insert(
            &st.db,
            &NewLocalApiKey {
                name: "k".into(),
                prefix: "wlk_settings".into(),
                key_hash,
                scopes: Some(scopes.into()),
            },
        )
        .await
        .unwrap();
        raw
    }

    /// GET reflects the boot config; the running values echo it (no governor ⇒ from boot snapshot) so
    /// `pending_restart` is false on a fresh, unchanged install. Bounds are surfaced.
    #[tokio::test]
    async fn get_reflects_defaults_no_pending_restart() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state(LocalConfig::default()).await;
        let (code, body) = call(&st, "GET", "/v1/settings/runtime", None).await;
        assert_eq!(code, 200, "body={body}");
        assert_eq!(body["settings"]["max_concurrent_runs"], json!(4));
        assert_eq!(body["settings"]["max_background_runs"], json!(2));
        assert_eq!(body["settings"]["rss_soft_watermark_mb"], json!(1536));
        assert_eq!(body["settings"]["browser_headless"], json!(true));
        assert_eq!(body["pending_restart"], json!(false), "unchanged install is not pending");
        assert_eq!(body["bounds"]["max_concurrent_runs_ceiling"], json!(MAX_CONCURRENT_RUNS_CEILING));
        assert_eq!(body["live"]["governor_present"], json!(false));
        assert_eq!(body["live"]["active_runs"], json!(0));
        std::env::remove_var("WRIT_HOME");
    }

    /// PUT persists a partial change; the value lands on disk and — because the governor ceiling is
    /// boot-fixed — `pending_restart` flips true (disk differs from the running/boot snapshot).
    #[tokio::test]
    async fn put_persists_and_signals_restart() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state(LocalConfig::default()).await;
        let paths = Paths::resolve().unwrap();

        let (code, body) = call(
            &st,
            "PUT",
            "/v1/settings/runtime",
            Some(r#"{"max_concurrent_runs":8,"browser_headless":false}"#),
        )
        .await;
        assert_eq!(code, 200, "body={body}");
        // Persisted on disk.
        let on_disk = config::load_config(&paths);
        assert_eq!(on_disk.max_concurrent_runs, 8, "ceiling persisted");
        assert!(!on_disk.browser_headless, "headless persisted");
        // The response reflects the new on-disk value + a pending restart (running still = boot=4/true).
        assert_eq!(body["settings"]["max_concurrent_runs"], json!(8));
        assert_eq!(body["settings"]["browser_headless"], json!(false));
        assert_eq!(body["running"]["max_concurrent_runs"], json!(4), "running unchanged until restart");
        assert_eq!(body["pending_restart"], json!(true));
        std::env::remove_var("WRIT_HOME");
    }

    /// Out-of-range values are CLAMPED on persist (not rejected): an absurd ceiling is capped, the
    /// background sub-ceiling is clamped to the (capped) global, a non-zero sub-floor watermark is
    /// raised, and sub-floor monitor intervals are raised to their hard anti-detection floors.
    #[tokio::test]
    async fn put_clamps_out_of_range_values() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state(LocalConfig::default()).await;

        let (code, body) = call(
            &st,
            "PUT",
            "/v1/settings/runtime",
            Some(r#"{"max_concurrent_runs":100000,"max_background_runs":100000,"rss_soft_watermark_mb":10,"html_floor_ms":1,"js_floor_ms":1}"#),
        )
        .await;
        assert_eq!(code, 200, "body={body}");
        assert_eq!(
            body["settings"]["max_concurrent_runs"],
            json!(MAX_CONCURRENT_RUNS_CEILING),
            "ceiling capped"
        );
        assert_eq!(
            body["settings"]["max_background_runs"],
            json!(MAX_CONCURRENT_RUNS_CEILING),
            "background clamped to the (capped) global ceiling"
        );
        assert_eq!(
            body["settings"]["rss_soft_watermark_mb"],
            json!(MIN_RSS_SOFT_WATERMARK_MB),
            "tiny non-zero watermark raised to the floor"
        );
        assert_eq!(body["settings"]["html_floor_ms"], json!(HTML_FLOOR_MS), "content floor enforced");
        assert_eq!(body["settings"]["js_floor_ms"], json!(JS_FLOOR_MS), "browser floor enforced");
        // The clamped (default) floors were installed live into the scheduler global.
        assert_eq!(clamp::configured_monitor_floors(), (HTML_FLOOR_MS, JS_FLOOR_MS));

        // A `0` watermark (memory shedding disabled) is a legal value and is preserved.
        let (code, body) =
            call(&st, "PUT", "/v1/settings/runtime", Some(r#"{"rss_soft_watermark_mb":0}"#)).await;
        assert_eq!(code, 200, "body={body}");
        assert_eq!(body["settings"]["rss_soft_watermark_mb"], json!(0), "0 disables shedding");
        std::env::remove_var("WRIT_HOME");
    }

    /// AC-2: an `admin`-scoped key may tune the harmless resource knobs but must NOT be able to strip
    /// a browser security boundary — those four flags are device control and need `manage`.
    #[tokio::test]
    async fn admin_key_cannot_flip_dangerous_browser_flags() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state(LocalConfig::default()).await;
        let admin = mint_key(&st, "admin").await;
        let paths = Paths::resolve().unwrap();

        // Benign tuning with an admin key: allowed.
        let (code, body) = call_as(
            &st,
            &admin,
            "PUT",
            "/v1/settings/runtime",
            Some(r#"{"max_concurrent_runs":6,"browser_headless":false}"#),
        )
        .await;
        assert_eq!(code, 200, "admin may tune resource ceilings: body={body}");
        assert_eq!(config::load_config(&paths).max_concurrent_runs, 6);

        // Each dangerous flag, one at a time: 403 and NOTHING persisted.
        for field in [
            "browser_disable_sandbox",
            "browser_ignore_certificate_errors",
            "browser_disable_web_security",
            "browser_use_local_chrome",
        ] {
            let (code, _b) = call_as(
                &st,
                &admin,
                "PUT",
                "/v1/settings/runtime",
                Some(&format!(r#"{{"{field}":true}}"#)),
            )
            .await;
            assert_eq!(code, 403, "admin must NOT flip {field}");
            let on_disk = RuntimeSettings::from_local(&config::load_config(&paths));
            assert!(
                dangerous_flags(&on_disk).iter().all(|(_, v)| !*v),
                "{field} must not have been persisted by the refused request"
            );
        }

        // A dangerous flag smuggled in alongside benign knobs is still refused, and the benign part
        // does NOT land either (the gate runs before anything is written).
        let (code, _b) = call_as(
            &st,
            &admin,
            "PUT",
            "/v1/settings/runtime",
            Some(r#"{"max_concurrent_runs":9,"browser_disable_web_security":true}"#),
        )
        .await;
        assert_eq!(code, 403, "mixed body is refused as a whole");
        assert_eq!(
            config::load_config(&paths).max_concurrent_runs,
            6,
            "refused request must not persist its benign fields either"
        );

        // Re-asserting a dangerous flag at its CURRENT value is not a change → still allowed. This is
        // why the gate compares effective values instead of looking for key presence.
        let (code, body) = call_as(
            &st,
            &admin,
            "PUT",
            "/v1/settings/runtime",
            Some(r#"{"browser_disable_sandbox":false,"max_background_runs":2}"#),
        )
        .await;
        assert_eq!(code, 200, "no-op on a dangerous flag stays admin-allowed: body={body}");

        std::env::remove_var("WRIT_HOME");
    }

    /// A `manage` key may flip them, and so may the full-access `wlt_` UI token — the desktop
    /// Settings tab keeps working exactly as before.
    #[tokio::test]
    async fn manage_key_and_ui_token_may_flip_dangerous_flags() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state(LocalConfig::default()).await;
        let paths = Paths::resolve().unwrap();

        // `admin,manage` — the realistic shape of a device-management key. `manage` is ORTHOGONAL to
        // the read⊆run⊆admin chain (it backfills nothing), and the route itself is classified `Admin`,
        // so a manage-ONLY key is correctly rejected at the middleware before the handler is reached
        // (asserted below).
        let manage = mint_key(&st, "admin,manage").await;
        let (code, body) = call_as(
            &st,
            &manage,
            "PUT",
            "/v1/settings/runtime",
            Some(r#"{"browser_disable_sandbox":true}"#),
        )
        .await;
        assert_eq!(code, 200, "manage may flip a dangerous flag: body={body}");
        assert!(config::load_config(&paths).browser_disable_sandbox, "persisted");

        // The in-app `wlt_` token bypasses the scope model entirely (it IS the device owner).
        let (code, body) = call(
            &st,
            "PUT",
            "/v1/settings/runtime",
            Some(r#"{"browser_ignore_certificate_errors":true,"browser_disable_sandbox":false}"#),
        )
        .await;
        assert_eq!(code, 200, "wlt_ UI token unaffected: body={body}");
        let on_disk = config::load_config(&paths);
        assert!(on_disk.browser_ignore_certificate_errors);
        assert!(!on_disk.browser_disable_sandbox, "wlt_ can turn one back off too");

        // A manage-ONLY key still cannot use the route at all: `manage` grants no `admin`, and the
        // route's baseline classification IS `admin`. Rejected by the middleware, never the handler.
        let manage_only = mint_key(&st, "manage").await;
        let (code, _b) = call_as(
            &st,
            &manage_only,
            "PUT",
            "/v1/settings/runtime",
            Some(r#"{"max_concurrent_runs":3}"#),
        )
        .await;
        assert_eq!(code, 403, "manage alone does not backfill admin");

        std::env::remove_var("WRIT_HOME");
    }

    /// The telemetry opt-in round-trips to DISK, which is the whole point of this route: the
    /// desktop toggle used to write a shell-owned `telemetry` key the daemon never read, so the
    /// switch showed a preference that changed nothing. Assert the value reaches
    /// `[app].telemetry_opt_in`, where the reporter loop actually looks.
    #[tokio::test]
    async fn telemetry_opt_in_persists_where_the_reporter_reads_it() {
        let _g = crate::local::config::test_env_guard();
        std::env::remove_var("WRIT_TELEMETRY");
        let (_dir, st) = test_state(LocalConfig::default()).await;

        let (code, body) = call(&st, "GET", "/v1/settings/telemetry", None).await;
        assert_eq!(code, 200);
        assert_eq!(body["enabled"], false, "OFF by default");
        assert!(body["last_reported_day"].is_null(), "nothing reported yet");

        let (code, body) = call(&st, "PUT", "/v1/settings/telemetry", Some(r#"{"enabled":true}"#)).await;
        assert_eq!(code, 200);
        assert_eq!(body["enabled"], true);

        // The on-disk config the daemon loads — not just the response echo.
        let paths = Paths::resolve().unwrap();
        assert!(config::load_config(&paths).telemetry_opt_in, "must land in [app].telemetry_opt_in");

        let (_, body) = call(&st, "PUT", "/v1/settings/telemetry", Some(r#"{"enabled":false}"#)).await;
        assert_eq!(body["enabled"], false);
        assert!(!config::load_config(&paths).telemetry_opt_in);

        std::env::remove_var("WRIT_HOME");
    }

    /// Opting a device into (or out of) sending data is the OWNER's call, so the route needs the
    /// `manage` capability — the same class as `/v1/network/expose`. An `admin`-scoped external key
    /// must not be able to flip a privacy setting in either direction.
    #[tokio::test]
    async fn flipping_telemetry_needs_manage_not_admin() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state(LocalConfig::default()).await;
        let admin_key = mint_key(&st, "admin").await;
        let manage_key = mint_key(&st, "manage").await;

        let (code, _) = call_as(&st, &admin_key, "PUT", "/v1/settings/telemetry", Some(r#"{"enabled":true}"#)).await;
        assert_eq!(code, 403, "an admin key must not be able to turn telemetry on");
        let paths = Paths::resolve().unwrap();
        assert!(!config::load_config(&paths).telemetry_opt_in, "and nothing was persisted");

        let (code, _) = call_as(&st, &manage_key, "PUT", "/v1/settings/telemetry", Some(r#"{"enabled":true}"#)).await;
        assert_eq!(code, 200, "manage is the capability that owns device-level decisions");

        std::env::remove_var("WRIT_HOME");
    }

    /// Both routes require the loopback bearer.
    #[tokio::test]
    async fn routes_require_the_loopback_bearer() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state(LocalConfig::default()).await;
        for method in ["GET", "PUT"] {
            let resp = build_router(st.clone())
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri("/v1/settings/runtime")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status().as_u16(), 401, "{method} must be 401 without a bearer");
        }
        std::env::remove_var("WRIT_HOME");
    }
}
