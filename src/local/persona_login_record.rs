//! Persona login RECORDING by AI — "let AI sign in and record it", locally.
//!
//! Cloud parity: `backend/services/persona_login_record.py`. A persona could only
//! ever get a login workflow by the user recording one BY HAND or attaching one
//! they already had. This drives the daemon's own autonomous AI session to sign
//! in with the persona's stored credentials, records the flow as a local
//! workflow, and wires it onto `personas.login_workflow_id` — which
//! [`crate::local::persona_login::ensure_fresh_session`] then replays on every
//! session expiry.
//!
//! ## Why the model never sees a credential
//! The loop is handed `fill_data` (real values) and `record_templates` (how a
//! filled key must be SPELLED in the recorded step). The brain only ever emits
//! `{{key}}` placeholders — [`crate::local::ai::session`] substitutes the real
//! value at the wire and writes the TEMPLATE into the recording. Everything is
//! on-device: the AI runs through the user's own provider key (or the cloud
//! gateway toggle), and nothing but the prompt leaves the machine.
//!
//! ## The replay-spelling rule (load-bearing)
//! At replay a persona's credentials are merged into the CREDENTIALS channel
//! ([`crate::local::engine::persona::ResolvedPersona::merge_into_credentials`],
//! applied in `engine/real.rs`), which the engine resolves as `{{secret:KEY}}`.
//! A recorded step left with a bare `{{password}}` would resolve against run
//! INPUTS instead, find nothing, and type an empty string — a silent logged-out
//! re-login. So every persona credential key is registered in `record_templates`
//! as `{{secret:<key>}}`. Same defect the cloud port had to fix at wire time;
//! here the spelling is correct at the source.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use crate::local::error::{LocalError, LocalResult};
use crate::local::server::AppState;
use crate::local::store::personas::{self, Persona};

/// A login is a SHORT browse: find the form, fill, maybe one OTP hop, verify, stop.
/// Well under the default session budget so a lost run can't wander an account area.
pub const LOGIN_RECORD_MAX_STEPS: u32 = 30;

/// The canned goal for a login-recording browse.
///
/// Scope discipline matters more here than anywhere else: this recording is
/// REPLAYED on every session expiry, so a browse that wanders past the login
/// bakes that detour into every future re-login.
pub fn build_login_record_goal(target_domain: Option<&str>, entry_url: &str) -> String {
    let where_ = target_domain
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| entry_url.to_string());
    format!(
        "Sign in to {where_} as the saved account, then stop.\n\
         This browse exists ONLY to record a reusable sign-in workflow:\n\
         1. From the entry page, find and open the sign-in form (follow a 'Sign in' / \
         'Log in' link if the form is not already visible).\n\
         2. Fill the form using the provided secure fields — always reference the \
         placeholders, never type a literal credential value.\n\
         3. If a one-time code is requested, complete it with the twofa action.\n\
         4. Verify you actually ARE signed in: an account menu / avatar / dashboard is \
         visible and no login form remains.\n\
         5. Then finish immediately. Do not browse further, do not extract data, and do \
         not change any account setting."
    )
}

/// `{credential key → recorded spelling}` for every key this persona supplies.
///
/// See the module docs: the recorded step must name the CREDENTIALS channel
/// (`{{secret:key}}`), which is where `merge_into_credentials` puts these at
/// replay. `totp` is included so a 2FA fill is spelled the same way.
pub fn login_record_templates(credential_keys: &HashSet<String>) -> HashMap<String, String> {
    credential_keys
        .iter()
        .map(|k| (k.clone(), format!("{{{{secret:{k}}}}}")))
        .collect()
}

/// The entry URL a login recording should start from: the caller's explicit URL,
/// else the persona's domain root (the AI finds the sign-in form from there).
pub fn login_entry_url(target_domain: Option<&str>, login_url: Option<&str>) -> LocalResult<String> {
    if let Some(u) = login_url.map(str::trim).filter(|u| !u.is_empty()) {
        let full = if u.starts_with("http://") || u.starts_with("https://") {
            u.to_string()
        } else {
            format!("https://{u}")
        };
        return Ok(full);
    }
    match target_domain.map(str::trim) {
        Some(d) if !d.is_empty() => Ok(format!("https://{d}")),
        _ => Err(LocalError::BadRequest(
            "This persona has no site domain. Set its domain (or pass a login URL) so \
             the AI knows where to sign in."
                .into(),
        )),
    }
}

/// Single-flight guard: which personas currently have a login recording running.
///
/// The daemon is ONE process, so an in-process set is a COMPLETE lock (unlike the
/// cloud, which needs Redis across workers). Two clicks must not launch two AI
/// logins against the same account — concurrent logins are how a site locks one.
static IN_FLIGHT: std::sync::OnceLock<std::sync::Mutex<HashSet<i64>>> = std::sync::OnceLock::new();

fn in_flight() -> &'static std::sync::Mutex<HashSet<i64>> {
    IN_FLIGHT.get_or_init(|| std::sync::Mutex::new(HashSet::new()))
}

/// RAII claim on a persona's recording slot — released however the run ends
/// (success, failure, panic), so a crashed recording can't wedge the persona.
pub struct RecordGuard(i64);

impl RecordGuard {
    /// Claim the slot, or `None` when a recording for this persona is already running.
    pub fn claim(persona_id: i64) -> Option<Self> {
        let mut set = in_flight().lock().unwrap_or_else(|e| e.into_inner());
        if set.insert(persona_id) {
            Some(Self(persona_id))
        } else {
            None
        }
    }
}

impl Drop for RecordGuard {
    fn drop(&mut self) {
        let mut set = in_flight().lock().unwrap_or_else(|e| e.into_inner());
        set.remove(&self.0);
    }
}

/// Wire the recorded workflow onto the persona — honestly.
///
/// Cloud parity with `wire_login_record_result`: link the workflow, then report
/// what actually happened. A run "succeeding" only means the STEPS ran; if the
/// harvested session carries no real auth material the workflow is still wired
/// (so the user can fix and retry it) but the persona is FLAGGED rather than
/// shown as signed in.
pub async fn wire_login_record_result(
    st: &AppState,
    persona_id: i64,
    workflow_id: Option<i64>,
    status: &str,
    error: Option<&str>,
) -> LocalResult<()> {
    let recorded = workflow_id.filter(|_| status == "complete");
    let Some(wf_id) = recorded else {
        let msg = match error {
            Some(e) if !e.trim().is_empty() => {
                format!("The AI could not record the sign-in: {}", truncate(e, 300))
            }
            _ => format!(
                "The AI finished without recording any sign-in steps ({status}). Try \
                 again, or record the login manually."
            ),
        };
        let _ = personas::record_login_result(&st.db, persona_id, Some(&msg)).await;
        return Ok(());
    };

    personas::set_login_workflow(&st.db, persona_id, Some(wf_id)).await?;

    // Did the login actually TAKE? The write-back seals whatever the run
    // harvested, so a run that landed back on the sign-in page still banks the
    // site's anonymous cookies. Only real auth material counts as signed in.
    let persona = personas::get_by_id(&st.db, persona_id).await?;
    let authenticated = persona
        .as_ref()
        .and_then(|p| crate::local::engine::persona::open_session_value(&st.vault, p))
        .as_ref()
        .map(crate::local::persona_login::session_has_auth_material)
        .unwrap_or(false);

    if authenticated {
        let _ = personas::record_login_result(&st.db, persona_id, None).await;
    } else {
        let _ = personas::record_login_result(
            &st.db,
            persona_id,
            Some(
                "The AI recorded a sign-in workflow, but no logged-in session was \
                 captured — it may not have actually signed in. Use 'Sign in now' to \
                 run it and verify.",
            ),
        )
        .await;
    }
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    s.chars().take(max).collect()
}

/// Everything the detached recording task needs, resolved on the request path so
/// a bad persona/URL fails the HTTP call instead of a background task.
pub struct LoginRecordPlan {
    pub persona_id: i64,
    pub entry_url: String,
    pub goal: String,
    pub name: String,
    /// Real values to fill (persona credentials + minted TOTP). SECRET.
    pub fill_data: HashMap<String, String>,
    /// How each filled key is SPELLED in the recording (`{{secret:key}}`).
    pub record_templates: HashMap<String, String>,
    pub resolved_persona: crate::local::engine::persona::ResolvedPersona,
    pub cancel: Arc<AtomicBool>,
}

/// Build the plan for a login recording, validating everything the run needs.
pub async fn plan_login_record(
    st: &AppState,
    persona: &Persona,
    login_url: Option<&str>,
) -> LocalResult<LoginRecordPlan> {
    if persona.login_username.is_none() && !has_value(&persona.credentials_encrypted) {
        return Err(LocalError::BadRequest(
            "This persona has no login credentials, so the AI has nothing to sign in \
             with. Add a username and password first."
                .into(),
        ));
    }
    let entry_url = login_entry_url(persona.target_domain.as_deref(), login_url)?;

    let resolved = crate::local::engine::persona::resolve_persona(&st.db, &st.vault, persona.id)
        .await?
        .ok_or_else(|| {
            LocalError::BadRequest(
                "This persona's credentials could not be opened — unlock the vault and \
                 try again."
                    .into(),
            )
        })?;

    let mut fill_data: HashMap<String, String> = HashMap::new();
    resolved.merge_into_credentials(&mut fill_data);
    if fill_data.is_empty() {
        return Err(LocalError::BadRequest(
            "This persona has no login credentials, so the AI has nothing to sign in \
             with. Add a username and password first."
                .into(),
        ));
    }
    let keys: HashSet<String> = fill_data.keys().cloned().collect();

    Ok(LoginRecordPlan {
        persona_id: persona.id,
        goal: build_login_record_goal(persona.target_domain.as_deref(), &entry_url),
        name: format!("{} login", persona.name),
        entry_url,
        record_templates: login_record_templates(&keys),
        fill_data,
        resolved_persona: resolved,
        cancel: Arc::new(AtomicBool::new(false)),
    })
}

fn has_value(opt: &Option<String>) -> bool {
    opt.as_deref().map(|s| !s.trim().is_empty()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn goal_scopes_the_browse_to_signing_in_only() {
        // Replayed on every expiry — a wandering recording is a permanent tax.
        let g = build_login_record_goal(Some("acme.test"), "https://acme.test");
        assert!(g.contains("acme.test"));
        assert!(g.contains("then stop"));
        assert!(g.contains("Do not browse further"));
        assert!(g.contains("never type a literal credential"));
    }

    #[test]
    fn credentials_are_spelled_for_the_secret_channel() {
        // The whole point: a bare {{password}} resolves against run INPUTS at
        // replay and types an empty string — a silent logged-out re-login.
        let keys: HashSet<String> =
            ["username", "password", "account_id"].iter().map(|s| s.to_string()).collect();
        let t = login_record_templates(&keys);
        assert_eq!(t.get("username").unwrap(), "{{secret:username}}");
        assert_eq!(t.get("password").unwrap(), "{{secret:password}}");
        assert_eq!(t.get("account_id").unwrap(), "{{secret:account_id}}");
    }

    #[test]
    fn entry_url_prefers_the_explicit_login_url_and_schemes_it() {
        let d = Some("acme.test");
        assert_eq!(login_entry_url(d, Some("acme.test/login")).unwrap(), "https://acme.test/login");
        assert_eq!(
            login_entry_url(d, Some("https://acme.test/signin")).unwrap(),
            "https://acme.test/signin"
        );
        assert_eq!(login_entry_url(d, None).unwrap(), "https://acme.test");
        assert_eq!(login_entry_url(d, Some("   ")).unwrap(), "https://acme.test");
    }

    #[test]
    fn a_persona_with_no_domain_and_no_url_is_refused() {
        let err = login_entry_url(None, None).unwrap_err();
        assert!(matches!(err, LocalError::BadRequest(_)));
        assert!(login_entry_url(Some("  "), None).is_err());
    }

    #[test]
    fn single_flight_admits_one_recording_per_persona() {
        let first = RecordGuard::claim(4242).expect("first claim wins");
        assert!(RecordGuard::claim(4242).is_none(), "second claim must be refused");
        // A different persona is unaffected.
        let other = RecordGuard::claim(4343).expect("other persona claims freely");
        drop(other);
        drop(first);
        // Released on drop — a crashed recording must not wedge the persona.
        assert!(RecordGuard::claim(4242).is_some());
    }
}
