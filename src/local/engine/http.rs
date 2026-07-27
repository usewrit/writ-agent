//! Local-engine glue for the browserless HTTP lane.
//!
//! Owns the vault/DB access the lane itself must not touch: loading + persisting the per-workflow
//! session, mapping the persona fingerprint/proxy into the lane, and translating lane outcomes into
//! the engine's `RunFailure` / extracted-map contract. The lane's own logic (jar, request driver,
//! ladder) lives under `crate::automation::http_lane` and stays free of engine/vault deps.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::Value;
use sqlx::sqlite::SqlitePool;

use crate::automation::http_lane::ladder::{run_workflow_http, LadderConfig, StepObserver, StepPhase};
use crate::automation::http_lane::recipe::{AuthRecipe, ChallengeResolver, RecipeRunner};
use crate::automation::http_lane::{HttpLaneError, HttpLaneExecutor, HttpLaneOptions, HttpProxyConfig, ParkKind};
use crate::local::store::{workflow_sessions, workflows};
use crate::local::vault::Vault;
use crate::models::session::SessionState;

use super::events::{RunEvent, StepStatus};
use super::persona::ResolvedPersona;
use super::registry::{CancelToken, StepEmitter};
use super::RunFailure;

/// The result of attempting a run on the HTTP lane.
pub(super) enum HttpRunOutcome {
    /// Ran to completion over HTTP; the extracted map (carries the `_engine` sentinel).
    Done(HashMap<String, Value>),
    /// The lane declined — the caller should run the workflow in the browser this same run.
    Fallback { reason: &'static str },
    /// Terminal failure (a park or a fatal error); the caller finalizes with this.
    Failed(RunFailure),
}

fn aad(workflow_id: i64) -> String {
    format!("workflow_sessions|session_state_encrypted|{workflow_id}")
}

/// The `browser.step_range` of a `kind:"browser"` AuthRecipe (the DOM login prefix), if this workflow
/// is a hybrid. `None` for a plain HTTP recipe or no recipe.
pub(super) fn hybrid_browser_range(wf: &workflows::Workflow) -> Option<[usize; 2]> {
    let raw = wf.auth_config.as_deref()?.trim();
    if raw.is_empty() || raw == "null" {
        return None;
    }
    let recipe: AuthRecipe = serde_json::from_str(raw).ok()?;
    if recipe.kind != "browser" {
        return None;
    }
    recipe.browser.map(|b| b.step_range)
}

/// The DATA steps of a hybrid workflow = the steps OUTSIDE the browser-login range. These run over the
/// HTTP lane once the browser sign-in has harvested a session.
pub(super) fn hybrid_data_steps(raw_steps: &[Value], range: [usize; 2]) -> Vec<Value> {
    let [s, e] = range;
    raw_steps
        .iter()
        .enumerate()
        .filter(|(i, _)| *i < s || *i >= e)
        .map(|(_, v)| v.clone())
        .collect()
}

/// Whether a fresh (session_persistence on, not TTL-expired) workflow session exists to reuse.
pub(super) async fn has_fresh_workflow_session(db: &SqlitePool, wf: &workflows::Workflow) -> bool {
    if wf.session_persistence == 0 {
        return false;
    }
    match workflow_sessions::get(db, wf.id).await {
        Ok(Some(row)) => {
            row.session_state_encrypted.as_deref().map(|s| !s.is_empty()).unwrap_or(false)
                && !session_expired(row.extracted_at.as_deref(), wf.session_ttl_seconds)
        }
        _ => false,
    }
}

/// Load the session to seed the lane: the persisted per-workflow session (if session_persistence is on
/// and it hasn't aged past `session_ttl_seconds`), else the persona's session_state, else none.
async fn load_session(
    db: &SqlitePool,
    vault: &Vault,
    wf: &workflows::Workflow,
    persona: Option<&ResolvedPersona>,
) -> Option<SessionState> {
    if wf.session_persistence != 0 {
        if let Ok(Some(row)) = workflow_sessions::get(db, wf.id).await {
            if !session_expired(row.extracted_at.as_deref(), wf.session_ttl_seconds) {
                if let Some(blob) = row.session_state_encrypted.as_deref().filter(|s| !s.is_empty()) {
                    match vault.open_field(blob, &aad(wf.id)) {
                        Ok(plain) => match serde_json::from_slice::<SessionState>(&plain) {
                            Ok(state) => return Some(state),
                            Err(e) => tracing::warn!(workflow_id = wf.id, error = %e, "workflow session unparseable — ignoring"),
                        },
                        Err(e) => tracing::warn!(workflow_id = wf.id, error = %e, "workflow session decrypt failed — ignoring"),
                    }
                }
            } else {
                // Aged out — clear it so we don't keep decrypting a dead session.
                let _ = workflow_sessions::clear(db, wf.id).await;
            }
        }
    }
    persona.and_then(|p| p.session_state.clone())
}

/// True when `extracted_at` (RFC3339) is older than `ttl_seconds`. A missing timestamp or ttl → never
/// expires by age (cookie expiry still governs at request time inside the jar).
fn session_expired(extracted_at: Option<&str>, ttl_seconds: Option<i64>) -> bool {
    let (Some(ts), Some(ttl)) = (extracted_at, ttl_seconds) else {
        return false;
    };
    if ttl <= 0 {
        return false;
    }
    match chrono::DateTime::parse_from_rfc3339(ts) {
        Ok(dt) => {
            let age = chrono::Utc::now().signed_duration_since(dt.with_timezone(&chrono::Utc));
            age.num_seconds() > ttl
        }
        Err(_) => false,
    }
}

/// Seal + upsert a SessionState for reuse next run, tagged with which lane captured it.
async fn seal_and_upsert(db: &SqlitePool, vault: &Vault, workflow_id: i64, state: &SessionState, engine: &str) {
    let extracted_at = state.extracted_at.clone().unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
    let bytes = match serde_json::to_vec(state) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(workflow_id, error = %e, "could not serialize workflow session — not persisting");
            return;
        }
    };
    match vault.seal_field(&bytes, &aad(workflow_id)) {
        Ok(sealed) => {
            if let Err(e) = workflow_sessions::upsert(db, workflow_id, &sealed, &extracted_at, engine).await {
                tracing::warn!(workflow_id, error = %e, "could not persist workflow session");
            }
        }
        Err(e) => tracing::warn!(workflow_id, error = %e, "could not seal workflow session"),
    }
}

/// Seal + upsert the HTTP lane's current session for reuse next run.
async fn persist_session(db: &SqlitePool, vault: &Vault, workflow_id: i64, exec: &HttpLaneExecutor) {
    let state = exec.export_session_state();
    seal_and_upsert(db, vault, workflow_id, &state, "http").await;
}

/// Persist a session harvested from a BROWSER run (hybrid: a DOM sign-in whose session the HTTP lane
/// reuses on the next run). Called by the local engine's browser path.
pub(super) async fn persist_browser_session(db: &SqlitePool, vault: &Vault, workflow_id: i64, state: &SessionState) {
    seal_and_upsert(db, vault, workflow_id, state, "browser").await;
}

/// Emits per-step lifecycle events + a progress heartbeat, and forwards cancellation into the ladder.
struct EngineObserver<'a> {
    emitter: &'a StepEmitter,
    cancel: &'a CancelToken,
    run_id: i64,
    total: usize,
    completed: AtomicUsize,
}

impl StepObserver for EngineObserver<'_> {
    fn on_step(&self, index: usize, step_type: &str, phase: StepPhase) {
        let status = match phase {
            StepPhase::Running => StepStatus::Running,
            StepPhase::Succeeded => StepStatus::Succeeded,
            StepPhase::Skipped => StepStatus::Skipped,
            StepPhase::Failed => StepStatus::Failed,
        };
        self.emitter.emit(RunEvent::Step {
            run_id: self.run_id,
            index,
            step_type: step_type.to_string(),
            status,
        });
        if matches!(phase, StepPhase::Succeeded | StepPhase::Skipped) {
            let c = self.completed.fetch_add(1, Ordering::SeqCst) + 1;
            self.emitter.emit(RunEvent::Progress { run_id: self.run_id, completed: c, total: self.total });
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }
}

/// Attempt to run `raw_steps` on the browserless HTTP lane. Never launches a browser.
#[allow(clippy::too_many_arguments)]
pub(super) async fn try_http_run(
    db: &SqlitePool,
    vault: &Vault,
    wf: &workflows::Workflow,
    raw_steps: &[Value],
    credentials: &HashMap<String, String>,
    form_data: &HashMap<String, String>,
    resolved_persona: Option<&ResolvedPersona>,
    run_id: i64,
    cancel: &CancelToken,
    emitter: &StepEmitter,
    timeout_ms: u64,
) -> HttpRunOutcome {
    let seeded = load_session(db, vault, wf, resolved_persona).await;

    // Fingerprint: prefer the persona's captured one; else the seeded session's.
    let fingerprint = resolved_persona
        .and_then(|p| p.fingerprint.as_ref())
        .and_then(|f| serde_json::to_value(f).ok())
        .or_else(|| seeded.as_ref().and_then(|s| s.fingerprint.clone()));

    let proxy = resolved_persona.and_then(|p| p.proxy.as_ref()).map(|ps| HttpProxyConfig {
        server: ps.server.clone(),
        username: ps.username.clone(),
        password: ps.password.clone(),
        bypass: ps.bypass.clone(),
    });

    let entry_url = wf.entry_url.as_deref().filter(|s| !s.is_empty());

    let mut exec = match HttpLaneExecutor::new(HttpLaneOptions {
        fingerprint,
        proxy,
        session: seeded.as_ref(),
        entry_url,
        timeout: std::time::Duration::from_millis(timeout_ms),
    }) {
        Ok(e) => e,
        Err(HttpLaneError::Fatal(m)) => return HttpRunOutcome::Failed(RunFailure::step(m, "infra")),
        Err(_) => return HttpRunOutcome::Fallback { reason: "unsupported" },
    };

    let login_url_patterns: Vec<String> = wf
        .login_url_patterns
        .as_deref()
        .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
        .unwrap_or_default();
    let cfg = LadderConfig {
        login_url_patterns,
        relogin_max_retries: wf.relogin_max_retries.max(0) as u32,
    };

    let total = raw_steps
        .iter()
        .filter(|s| s.get("enabled").and_then(Value::as_bool).unwrap_or(true))
        .filter(|s| s.get("type").and_then(Value::as_str).map(|t| !t.is_empty()).unwrap_or(false))
        .count();
    let observer = EngineObserver { emitter, cancel, run_id, total, completed: AtomicUsize::new(0) };

    // Parse a declarative AuthRecipe (phase 2). When present it owns authentication; when absent the
    // ladder falls back to running the recorded login_post steps directly (phase-1 behavior).
    let recipe: Option<AuthRecipe> = wf
        .auth_config
        .as_deref()
        .filter(|s| !s.trim().is_empty() && s.trim() != "null")
        .and_then(|s| serde_json::from_str::<AuthRecipe>(s).ok());
    let seeded_tokens = seeded.as_ref().and_then(|s| s.tokens.clone());
    let mut runner = recipe.as_ref().map(|r| {
        RecipeRunner::new(
            r,
            credentials,
            form_data,
            seeded_tokens.as_ref(),
            ChallengeResolver::LocalPersona {
                totp_code: resolved_persona.and_then(|p| p.totp_code.clone()),
            },
            wf.relogin_max_retries.max(0) as u32,
        )
    });

    let run_result = run_workflow_http(
        &mut exec,
        raw_steps,
        credentials,
        form_data,
        &cfg,
        &observer,
        runner.as_mut(),
    )
    .await;

    match run_result {
        Ok(outcome) => {
            // Fold any recipe token store into the executor's session so it persists for reuse.
            if let Some(tokens) = runner.as_ref().and_then(|r| r.export_tokens()) {
                exec.merge_tokens(tokens);
            }
            if wf.session_persistence != 0 {
                persist_session(db, vault, wf.id, &exec).await;
            }
            let _ = workflows::set_http_capable(db, wf.id, 1).await;
            let mut extracted = outcome.extracted;
            extracted.insert("_engine".to_string(), Value::String("http".into()));
            HttpRunOutcome::Done(extracted)
        }
        Err(HttpLaneError::Fallback(reason)) => HttpRunOutcome::Fallback { reason: reason.as_str() },
        Err(HttpLaneError::Fatal(_)) if cancel.is_cancelled() => HttpRunOutcome::Failed(RunFailure::Cancelled),
        Err(HttpLaneError::Fatal(m)) => HttpRunOutcome::Failed(RunFailure::step(m, "infra")),
        Err(HttpLaneError::Parked(kind)) => HttpRunOutcome::Failed(park_to_failure(kind, entry_url)),
    }
}

/// Map a park (unattended 2FA / user-supplied code) to the engine's terminal `twofa_required` state —
/// the existing typed "needs a one-time code" terminal the FE/backend already render. No durable
/// pause/resume (per product decision): the user supplies the code out-of-band and re-runs.
fn park_to_failure(kind: ParkKind, entry_url: Option<&str>) -> RunFailure {
    let url = entry_url.unwrap_or("about:blank").to_string();
    match kind {
        ParkKind::Twofa(message) => RunFailure::Twofa { method: "email_otp".into(), message, url },
        ParkKind::Attention(message) => RunFailure::Twofa { method: "user_prompt".into(), message, url },
    }
}
