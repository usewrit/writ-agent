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

// ---------------------------------------------------------------------------
// AUTH-MATERIAL verification — the STRICT sign-in test
// ---------------------------------------------------------------------------
//
// `session_is_fresh` above stays PERMISSIVE (a sealed blob that hasn't expired) because the
// crawl gate shares it and must never block a WORKING persona over a heuristic. This is the
// STRICTER check the "Sign in now" TEST reports: the daemon's post-run write-back seals
// WHATEVER the run harvested onto the persona (engine/real.rs), so a login that ran and landed
// back on the sign-in page still banks the site's anonymous cookies (consent/analytics) — which
// `session_is_fresh` accepts and would read as "signed in". This check confirms the login
// actually TOOK: real auth material, not merely SOME state.
//
// Ported verbatim from `backend/services/persona_login.py::session_has_auth_material` so cloud
// and desktop can never disagree about what counts as a real login. It runs on the UNTYPED
// session JSON (see `engine::persona::open_session_value`) so it recognizes EVERY auth shape,
// including a Playwright `origins[]` the typed `SessionState` cannot carry.

/// Cookie NAME fragments that mark a real authentication/session cookie across the common stacks.
/// Deliberately BROAD — the goal is to recognize EVERY auth shape (server sessions, framework
/// cookies, OAuth/JWT, "remember me", SSO) so a real login is never misread as anonymous. Matched
/// case-insensitively as substrings.
const AUTH_COOKIE_HINTS: &[&str] = &[
    "session", "sess", "sid", "auth", "token", "jwt", "login", "logged", "loggedin",
    "account", "identity", "credential", "access", "refresh", "remember", "rememberme",
    "oauth", "openid", "saml", "sso", "bearer", "apikey", "api_key", "passport",
    "phpsessid", "jsessionid", "asp.net", "aspxauth", "connect.sid", "csrftoken",
    "_session", "user_session", "auth_token", "id_token", "access_token", "ss-id",
    "ss-pid", "laravel_session", "django", "rails", "_forum_session", "wordpress_logged_in",
];

/// Cookie names that are NEVER, on their own, evidence of a login — analytics, consent banners,
/// CDN/anti-bot, A/B tests. A session made of ONLY these is the anonymous logged-OUT state a
/// failed login leaves behind.
const ANON_COOKIE_HINTS: &[&str] = &[
    "consent", "cookieconsent", "cookie_consent", "gdpr", "optanon", "onetrust",
    "_ga", "_gid", "_gat", "_gcl", "_fbp", "_fbc", "fr", "_hj", "hotjar", "amplitude",
    "mixpanel", "segment", "intercom", "_pk_", "matomo", "analytics", "utm",
    "__cf", "cf_", "cf-", "_cfuvid", "__cflb", "ak_bmsc", "bm_", "_abck", "datadome",
    "incap_", "visid_incap", "nr_", "newrelic", "ab_test", "experiment", "gtm",
];

/// Python-`bool(x)` truthiness for a JSON value: `null`/absent, `false`, `0`, and empty
/// string/array/object are falsy; everything else is truthy. Mirrors the `or`/`if val` tests in
/// the source detector so ports of its edge cases (e.g. `httpOnly: false`) agree.
fn json_truthy(v: Option<&serde_json::Value>) -> bool {
    match v {
        None | Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Some(serde_json::Value::String(s)) => !s.is_empty(),
        Some(serde_json::Value::Array(a)) => !a.is_empty(),
        Some(serde_json::Value::Object(m)) => !m.is_empty(),
    }
}

/// Does ONE cookie look like it carries a login? True when it is HttpOnly (a server-set
/// session/auth cookie the page's JS can't read — analytics/consent cookies are readable, so never
/// HttpOnly), OR its name matches an auth hint and is not a known-anonymous name. Broad by design
/// (see the hint lists).
fn cookie_is_auth_like(cookie: &serde_json::Value) -> bool {
    let Some(obj) = cookie.as_object() else { return false };
    let name = obj.get("name").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
    if name.is_empty() {
        return false;
    }
    // A known analytics/consent/anti-bot cookie is not auth on its own — but an HttpOnly one still
    // is (some anti-bot names collide; HttpOnly wins as the stronger signal). Check the anonymous
    // list only for the name-based branch. `httpOnly` is Playwright's spelling; `http_only` covers
    // a snake_case blob.
    if json_truthy(obj.get("httpOnly")) || json_truthy(obj.get("http_only")) {
        return true;
    }
    if ANON_COOKIE_HINTS.iter().any(|h| name.contains(h)) {
        return false;
    }
    AUTH_COOKIE_HINTS.iter().any(|h| name.contains(h))
}

/// STRICTER than [`session_is_fresh`]: does the captured session carry material that actually
/// proves a LOGIN, rather than merely SOME state? Recognizes EVERY auth shape so a real login is
/// never misread as anonymous:
///   * a token store — `localStorage` / `sessionStorage` / captured auth `headers` / the HTTP-lane
///     `tokens` map (a token-auth SPA keeps its WHOLE session here, never in a cookie);
///   * a Playwright `origins[]` entry carrying localStorage/sessionStorage (storage_state shape);
///   * at least one auth-like COOKIE (HttpOnly, or an auth-named non-anonymous one).
///
/// Takes the UNTYPED session JSON (`engine::persona::open_session_value`) — not a typed
/// `SessionState` — so `origins[]` is visible. `session` that is not a JSON object is not auth.
pub fn session_has_auth_material(session: &serde_json::Value) -> bool {
    let Some(obj) = session.as_object() else { return false };

    // 1. Any token store is auth material — a logged-out page rarely writes one, and token-auth
    //    SPAs keep their whole session here with no auth cookie. Non-empty object OR array only
    //    (a bare string here is not a token store).
    for key in ["localStorage", "sessionStorage", "headers", "tokens"] {
        match obj.get(key) {
            Some(serde_json::Value::Object(m)) if !m.is_empty() => return true,
            Some(serde_json::Value::Array(a)) if !a.is_empty() => return true,
            _ => {}
        }
    }

    // 2. Playwright storage_state origins[] with localStorage/sessionStorage entries.
    if let Some(serde_json::Value::Array(origins)) = obj.get("origins") {
        for o in origins {
            if let Some(om) = o.as_object() {
                if json_truthy(om.get("localStorage")) || json_truthy(om.get("sessionStorage")) {
                    return true;
                }
            }
        }
    }

    // 3. An auth-like cookie among the jar (HttpOnly or auth-named, not anonymous).
    if let Some(serde_json::Value::Array(cookies)) = obj.get("cookies") {
        if cookies.iter().any(cookie_is_auth_like) {
            return true;
        }
    }

    false
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

#[cfg(test)]
mod tests {
    //! Auth-material verification parity with `backend/tests/test_persona_session_auth_material.py`.
    //! The "Sign in now" test must confirm the login actually TOOK, not merely that a session blob
    //! was captured: a login that landed back on the sign-in page still banks anonymous cookies,
    //! which `session_is_fresh` (the permissive crawl gate) accepts. `session_has_auth_material` is
    //! the stricter check that keys the reported outcome — every auth shape passes, a purely
    //! anonymous session is rejected.
    use super::session_has_auth_material as has_auth;
    use serde_json::json;

    // --- real auth shapes must all pass (broad by design) ------------------- //

    #[test]
    fn httponly_session_cookie_is_auth() {
        assert!(has_auth(&json!({ "cookies": [{ "name": "whatever_sess", "value": "x", "httpOnly": true }] })));
    }

    #[test]
    fn auth_named_cookie_even_without_httponly() {
        for name in [
            "sessionid", "auth_token", "jwt", "PHPSESSID", "connect.sid",
            "laravel_session", "remember_me", "access_token", ".AspNetAuth",
        ] {
            assert!(has_auth(&json!({ "cookies": [{ "name": name, "value": "x" }] })), "{name}");
        }
    }

    #[test]
    fn spa_localstorage_token_is_auth() {
        // Token-auth SPA: the whole session is a localStorage JWT, no auth cookie.
        assert!(has_auth(&json!({ "localStorage": { "access_token": "ey..." } })));
        assert!(has_auth(&json!({ "sessionStorage": { "id_token": "ey..." } })));
    }

    #[test]
    fn captured_headers_and_tokens_store_are_auth() {
        assert!(has_auth(&json!({ "headers": { "Authorization": "Bearer x" } })));
        assert!(has_auth(&json!({ "tokens": { "ACCESS": { "value": "x" } } })));
    }

    #[test]
    fn playwright_origins_localstorage_is_auth() {
        let s = json!({ "origins": [{ "origin": "https://a.test", "localStorage": [{ "name": "tok", "value": "x" }] }] });
        assert!(has_auth(&s));
    }

    #[test]
    fn http_only_wins_over_anonymous_name() {
        // A name that also looks anti-bot-ish, but HttpOnly → still a real cookie.
        assert!(has_auth(&json!({ "cookies": [{ "name": "cf_session", "value": "x", "httpOnly": true }] })));
    }

    // --- the anonymous logged-out state must be rejected -------------------- //

    #[test]
    fn consent_and_analytics_only_is_not_auth() {
        let s = json!({ "cookies": [
            { "name": "cookie_consent", "value": "yes" },
            { "name": "_ga", "value": "GA1.2.3" },
            { "name": "_gid", "value": "GA1.2.3" },
            { "name": "OptanonConsent", "value": "..." },
        ] });
        assert!(!has_auth(&s));
    }

    #[test]
    fn anti_bot_cookies_only_is_not_auth() {
        let s = json!({ "cookies": [
            { "name": "__cf_bm", "value": "x" },
            { "name": "datadome", "value": "x" },
            { "name": "visid_incap_123", "value": "x" },
        ] });
        assert!(!has_auth(&s));
    }

    #[test]
    fn empty_and_malformed_are_not_auth() {
        assert!(!has_auth(&serde_json::Value::Null));
        assert!(!has_auth(&json!({})));
        assert!(!has_auth(&json!({ "cookies": [] })));
        assert!(!has_auth(&json!({ "localStorage": {}, "cookies": [] })));
        assert!(!has_auth(&json!("nope")));
        // A present-but-EMPTY token store / headers map is not auth (matches the source's
        // `isinstance(val, dict) and val` truthiness — an empty dict is falsy).
        assert!(!has_auth(&json!({ "headers": {}, "tokens": {}, "sessionStorage": {} })));
        // An origins[] whose only entry has an EMPTY localStorage list is not auth.
        assert!(!has_auth(&json!({ "origins": [{ "origin": "https://a.test", "localStorage": [] }] })));
    }

    #[test]
    fn empty_string_cookie_name_ignored() {
        assert!(!has_auth(&json!({ "cookies": [{ "name": "", "value": "x" }] })));
    }

    #[test]
    fn http_only_false_falls_through_to_name_check() {
        // `httpOnly: false` must NOT be read as truthy (the source's `bool(... or ...)` splits on
        // it): an anonymous name with httpOnly:false stays anonymous; an auth name still passes.
        assert!(!has_auth(&json!({ "cookies": [{ "name": "_ga", "httpOnly": false }] })));
        assert!(has_auth(&json!({ "cookies": [{ "name": "sessionid", "httpOnly": false }] })));
    }

    // --- relationship to the permissive gate ------------------------------- //

    #[test]
    fn usable_but_not_authenticated_is_the_whole_point() {
        // The exact failure the verification exists to catch: a session that carries cookies (so the
        // permissive `session_is_fresh` blob would look alive) but no real login.
        let anon = json!({ "cookies": [{ "name": "_ga", "value": "x" }, { "name": "consent", "value": "1" }] });
        assert!(!has_auth(&anon));
    }
}
