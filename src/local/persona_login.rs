//! Persona sign-in — run a persona's login workflow to establish its warm session.
//!
//! THE GAP THIS CLOSES. Locally a persona's warm session could not be established at
//! all: a successful run harvested its session into `workflow_sessions` (workflow-keyed,
//! for the HTTP lane) and NEVER onto the persona, and nothing could make a persona sign
//! IN. A persona created from credentials alone therefore never had a session, and every
//! authenticated local crawl using it was refused pre-seed ("no saved login session")
//! with no route out of the error.
//!
//! HOW IT WORKS. `personas.login_workflow_id` (0025) names the workflow that performs
//! the login. Running it with `RunRequest.persona_id` set folds the persona's
//! credentials + 2FA into the run, and the engine's post-run write-back (real.rs)
//! seals the harvested session onto the persona. This module owns no capture code;
//! it runs the workflow to completion and re-reads the row.
//!
//! STAMPEDE CONTROL. The daemon is a single process, so an in-process mutex set is a
//! complete lock: when N callers (crawl seeder retries, a user mashing "Sign in now")
//! want the same persona signed in, ONE runs the login and the rest wait for its result
//! — never N concurrent logins against one account, which is exactly the pattern that
//! trips a site's abuse defenses and gets the account locked.

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use super::engine::{Lane, RunRequest, RunSource, RunStatus};
use super::server::AppState;
use super::store::personas;

/// How long a sign-in run may take before we give up on waiting for a CONCURRENT one.
/// The run itself is bounded by the engine's own run budget; this only bounds the
/// losing waiters. Login flows with an email-OTP hop are genuinely slow, so this is
/// well above a normal run's duration.
const LOGIN_WAIT_BUDGET: Duration = Duration::from_secs(240);
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// The set of persona ids currently mid-sign-in. Single-process daemon ⇒ this IS the
/// whole lock domain (no Redis needed, unlike the cloud coordinator).
fn in_flight() -> &'static Mutex<HashSet<i64>> {
    static IN_FLIGHT: OnceLock<Mutex<HashSet<i64>>> = OnceLock::new();
    IN_FLIGHT.get_or_init(|| Mutex::new(HashSet::new()))
}

/// RAII guard releasing the in-flight marker even on early return / panic.
struct FlightGuard(i64);
impl Drop for FlightGuard {
    fn drop(&mut self) {
        if let Ok(mut set) = in_flight().lock() {
            set.remove(&self.0);
        }
    }
}

/// Does the persona row carry a usable, unexpired warm session?
///
/// Presence + expiry only — the sealed blob's SHAPE is validated where it is opened
/// (`engine::persona::resolve_from_row`), and re-validating it here would mean opening
/// secret material on every freshness probe.
fn session_is_fresh(p: &personas::Persona) -> bool {
    let has_blob = p
        .session_state_encrypted
        .as_deref()
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    if !has_blob {
        return false;
    }
    match p.expires_at.as_deref().filter(|s| !s.is_empty()) {
        // Stored as RFC3339 UTC TEXT; an unparseable value counts as expired rather
        // than granting a broken row eternal freshness.
        Some(raw) => chrono::DateTime::parse_from_rfc3339(raw)
            .map(|t| t > chrono::Utc::now())
            .unwrap_or(false),
        None => true,
    }
}

/// The outcome of [`ensure_fresh_session`], shaped for both the API handler and the
/// crawl gate: `Ok` means "a usable session exists on the row now".
pub struct SignInOutcome {
    pub ok: bool,
    /// Human-actionable reason when `ok == false`.
    pub error: Option<String>,
}

impl SignInOutcome {
    fn ok() -> Self {
        Self { ok: true, error: None }
    }
    fn fail(msg: impl Into<String>) -> Self {
        Self { ok: false, error: Some(msg.into()) }
    }
}

/// Guarantee the persona has a usable warm session, signing it in if needed.
///
/// `force` re-runs the login even when the current session still looks usable (the
/// "Sign in now" button: a session that merely LOOKS live but the site has already
/// invalidated is the exact case the button exists for).
///
/// Safe to call concurrently for one persona: only one caller runs the login, the
/// rest wait for that result and reuse it.
pub async fn ensure_fresh_session(st: &AppState, persona_id: i64, force: bool) -> SignInOutcome {
    let Some(p) = load(st, persona_id).await else {
        return SignInOutcome::fail(
            "The login identity is missing. Re-link a persona for the site, then try again.",
        );
    };
    if p.is_active == 0 {
        return SignInOutcome::fail(
            "That persona is inactive. Re-activate it (or pick another) to sign in.",
        );
    }
    if !force && session_is_fresh(&p) {
        return SignInOutcome::ok();
    }
    let Some(login_wf) = p.login_workflow_id else {
        return SignInOutcome::fail(
            "This persona has no login workflow, so it can't sign itself in. Record or \
             attach a login workflow for it, then try again.",
        );
    };

    // ---- stampede lock: first caller runs, the rest wait for its write-back ----
    let acquired = in_flight()
        .lock()
        .map(|mut set| set.insert(persona_id))
        .unwrap_or(true);
    if !acquired {
        return wait_for_other_signin(st, persona_id).await;
    }
    let _guard = FlightGuard(persona_id);

    tracing::info!(persona_id, workflow_id = login_wf, "persona sign-in: running login workflow");
    let req = RunRequest {
        workflow_id: login_wf,
        inputs: serde_json::Value::Null,
        source: RunSource::Api,
        lane: Lane::Interactive,
        dry_run: false,
        // THE tag that makes this a persona login: the engine resolves the persona
        // (credentials + 2FA + fingerprint folded in) and its post-run write-back
        // seals the harvested session back onto this persona row.
        persona_id: Some(persona_id),
        allow_local_secret_refs: true,
    };
    let run = match st.engine.run(req).await {
        Ok(r) => r,
        Err(e) => {
            let msg = format!("Could not start the login run: {e}");
            let _ = personas::record_login_result(&st.db, persona_id, Some(&msg)).await;
            return SignInOutcome::fail(msg);
        }
    };
    if !matches!(run.status, RunStatus::Success) {
        let msg = format!(
            "The login workflow for this persona failed: {}",
            run.error.as_deref().unwrap_or("the run did not succeed")
        );
        let _ = personas::record_login_result(&st.db, persona_id, Some(&msg)).await;
        return SignInOutcome::fail(msg);
    }

    // The run succeeded — but success only means the STEPS ran. If the workflow never
    // actually authenticated (or captured nothing), there is still no session, and
    // reporting ok here is exactly the silent logged-out crawl this path exists to
    // prevent.
    match load(st, persona_id).await {
        Some(fresh) if session_is_fresh(&fresh) => {
            let _ = personas::record_login_result(&st.db, persona_id, None).await;
            tracing::info!(persona_id, "persona sign-in: session captured");
            SignInOutcome::ok()
        }
        _ => {
            let msg = "The login workflow ran but captured no session. Check that it \
                       actually signs in and ends on a logged-in page, then try again.";
            let _ = personas::record_login_result(&st.db, persona_id, Some(msg)).await;
            SignInOutcome::fail(msg)
        }
    }
}

/// Another caller holds the sign-in: poll for the session IT establishes rather than
/// hammering the site with a second concurrent login.
async fn wait_for_other_signin(st: &AppState, persona_id: i64) -> SignInOutcome {
    let deadline = std::time::Instant::now() + LOGIN_WAIT_BUDGET;
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(POLL_INTERVAL).await;
        if let Some(p) = load(st, persona_id).await {
            if session_is_fresh(&p) {
                tracing::info!(persona_id, "persona sign-in: reusing a concurrent sign-in's session");
                return SignInOutcome::ok();
            }
            // The other sign-in finished and FAILED — its recorded error is the answer;
            // waiting the full budget would just delay the same news.
            let done = in_flight()
                .lock()
                .map(|set| !set.contains(&persona_id))
                .unwrap_or(false);
            if done {
                return SignInOutcome::fail(p.last_login_error.unwrap_or_else(|| {
                    "The concurrent sign-in for this persona did not produce a session.".into()
                }));
            }
        }
    }
    SignInOutcome::fail(
        "Another sign-in for this persona is already running and didn't finish in time. \
         Try again in a moment.",
    )
}

async fn load(st: &AppState, persona_id: i64) -> Option<personas::Persona> {
    match personas::get_by_id(&st.db, persona_id).await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(persona_id, error = %e, "persona sign-in: could not load persona");
            None
        }
    }
}
