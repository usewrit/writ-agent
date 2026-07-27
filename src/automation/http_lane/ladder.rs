//! The probe ladder: run a pure-HTTP workflow with lazy login, session reuse, stale detection and
//! bounded re-login, falling back to the browser when the site can't be faithfully driven over HTTP.
//!
//! Engine-agnostic: per-step lifecycle is reported through a [`StepObserver`] the caller implements
//! (the local engine wraps its event emitter; the saas bridge can no-op), so this module never depends
//! on engine types.

use std::collections::HashMap;

use serde_json::Value;

use crate::models::workflow::WorkflowStepConfig;

use super::recipe::RecipeRunner;
use super::steps::{build_request, extractions_from_response, run_request};
use super::{FallbackReason, HttpLaneError, HttpLaneExecutor, HttpResponse};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StepPhase {
    Running,
    Succeeded,
    Skipped,
    Failed,
}

/// Observes per-step lifecycle + supplies cancellation. All methods are cheap/non-blocking.
///
/// `Send + Sync` so the ladder future stays `Send` when run inside the engine's panic-isolation task.
pub trait StepObserver: Send + Sync {
    fn on_step(&self, index: usize, step_type: &str, phase: StepPhase);
    fn is_cancelled(&self) -> bool {
        false
    }
}

/// A no-op observer (for callers that don't stream per-step events).
pub struct NullObserver;
impl StepObserver for NullObserver {
    fn on_step(&self, _: usize, _: &str, _: StepPhase) {}
}

pub struct LadderConfig {
    /// Case-insensitive substrings; a final post-redirect URL containing any of them = session expired.
    pub login_url_patterns: Vec<String>,
    /// Max re-login replays per run (0 = a stale response falls back immediately).
    pub relogin_max_retries: u32,
}

#[derive(Debug)]
pub struct LadderOutcome {
    pub extracted: HashMap<String, Value>,
    pub steps_completed: usize,
}

struct ParsedStep {
    index: usize,
    step_type: String,
    config: WorkflowStepConfig,
}

/// Run the workflow's steps over the HTTP lane.
///
/// When `recipe` is `Some`, it owns authentication: its ladder runs first (probe → refresh → login),
/// its extracted vars feed later `{{extracted:}}` placeholders, and every recorded `login_post` step
/// is skipped (the recipe replaces them). When `None`, the phase-1 degenerate behavior applies (lazy
/// login from the recorded login_post steps).
pub async fn run_workflow_http(
    exec: &mut HttpLaneExecutor,
    raw_steps: &[Value],
    credentials: &HashMap<String, String>,
    form_data: &HashMap<String, String>,
    cfg: &LadderConfig,
    observer: &dyn StepObserver,
    mut recipe: Option<&mut RecipeRunner<'_>>,
) -> Result<LadderOutcome, HttpLaneError> {
    let steps = parse_steps(raw_steps);
    let login_indices: Vec<usize> = steps
        .iter()
        .enumerate()
        .filter(|(_, s)| s.step_type == "login_post")
        .map(|(i, _)| i)
        .collect();

    let mut extracted: HashMap<String, Value> = HashMap::new();
    let mut steps_completed = 0usize;
    let mut relogin_attempts = 0u32;

    // Recipe-owned auth: run the recipe ladder up front, then merge its vars so data steps can
    // reference `{{extracted:name}}` values the login produced.
    if let Some(runner) = recipe.as_deref_mut() {
        runner.ensure_session(exec).await?;
        for (k, v) in runner.vars.clone() {
            extracted.insert(k, v);
        }
    }

    // Skip logic: a recipe replaces recorded login_post steps entirely. Otherwise lazy-login — with a
    // warm session, skip the recorded login and let the first data call probe it.
    let skip_login = recipe.is_some() || exec.has_session();

    for step in steps.iter() {
        if observer.is_cancelled() {
            return Err(HttpLaneError::Fatal("run cancelled".into()));
        }
        match step.step_type.as_str() {
            "login_post" => {
                if skip_login {
                    observer.on_step(step.index, &step.step_type, StepPhase::Skipped);
                    continue;
                }
                observer.on_step(step.index, &step.step_type, StepPhase::Running);
                run_login_step(exec, step, credentials, form_data, &extracted).await?;
                observer.on_step(step.index, &step.step_type, StepPhase::Succeeded);
                steps_completed += 1;
            }
            "api_call" => {
                observer.on_step(step.index, &step.step_type, StepPhase::Running);
                let req = build_request(&step.config, credentials, form_data, &extracted)?;
                let mut resp = run_request(exec, &req).await?;

                if looks_like_challenge(&resp) {
                    observer.on_step(step.index, &step.step_type, StepPhase::Failed);
                    return Err(HttpLaneError::Fallback(FallbackReason::ChallengePage));
                }

                if is_stale(&resp, &step.config, cfg) {
                    // Session expired mid-run. Re-authenticate (bounded) then retry this call once.
                    if relogin_attempts >= cfg.relogin_max_retries {
                        observer.on_step(step.index, &step.step_type, StepPhase::Failed);
                        return Err(HttpLaneError::Fallback(FallbackReason::AuthFailed));
                    }
                    if let Some(runner) = recipe.as_deref_mut() {
                        // Recipe owns auth: run its refresh→login ladder, then merge fresh vars.
                        runner.reauthenticate(exec).await?;
                        for (k, v) in runner.vars.clone() {
                            extracted.insert(k, v);
                        }
                    } else if !login_indices.is_empty() {
                        relogin(exec, &steps, &login_indices, credentials, form_data, &extracted).await?;
                    } else {
                        observer.on_step(step.index, &step.step_type, StepPhase::Failed);
                        return Err(HttpLaneError::Fallback(FallbackReason::AuthFailed));
                    }
                    relogin_attempts += 1;
                    let req2 = build_request(&step.config, credentials, form_data, &extracted)?;
                    resp = run_request(exec, &req2).await?;
                    if is_stale(&resp, &step.config, cfg) {
                        observer.on_step(step.index, &step.step_type, StepPhase::Failed);
                        return Err(HttpLaneError::Fallback(FallbackReason::LoginLoop));
                    }
                }

                for (k, v) in extractions_from_response(&step.config, &resp) {
                    extracted.insert(k, v);
                }
                observer.on_step(step.index, &step.step_type, StepPhase::Succeeded);
                steps_completed += 1;
            }
            "wait" => {
                observer.on_step(step.index, &step.step_type, StepPhase::Running);
                wait_step(&step.config).await;
                observer.on_step(step.index, &step.step_type, StepPhase::Succeeded);
                steps_completed += 1;
            }
            "return" => {
                observer.on_step(step.index, &step.step_type, StepPhase::Succeeded);
                steps_completed += 1;
                break;
            }
            _ => {
                // Eligibility already excluded other step types; be defensive and fall back.
                return Err(HttpLaneError::Fallback(FallbackReason::Unsupported));
            }
        }
    }

    Ok(LadderOutcome { extracted, steps_completed })
}

/// Execute the recorded login_post steps in order (a fresh sign-in). Clears the jar first so a stale
/// session cookie can't shadow the new one.
async fn relogin(
    exec: &mut HttpLaneExecutor,
    steps: &[ParsedStep],
    login_indices: &[usize],
    credentials: &HashMap<String, String>,
    form_data: &HashMap<String, String>,
    extracted: &HashMap<String, Value>,
) -> Result<(), HttpLaneError> {
    exec.jar_mut().clear();
    for &pos in login_indices {
        run_login_step(exec, &steps[pos], credentials, form_data, extracted).await?;
    }
    Ok(())
}

/// Run one login_post: any status < 400 is success (the point is the Set-Cookie / token side effect).
async fn run_login_step(
    exec: &mut HttpLaneExecutor,
    step: &ParsedStep,
    credentials: &HashMap<String, String>,
    form_data: &HashMap<String, String>,
    extracted: &HashMap<String, Value>,
) -> Result<(), HttpLaneError> {
    let req = build_request(&step.config, credentials, form_data, extracted)?;
    let resp = run_request(exec, &req).await?;
    if looks_like_challenge(&resp) {
        return Err(HttpLaneError::Fallback(FallbackReason::ChallengePage));
    }
    if resp.status >= 400 {
        return Err(HttpLaneError::Fallback(FallbackReason::AuthFailed));
    }
    Ok(())
}

async fn wait_step(config: &WorkflowStepConfig) {
    let ms = config
        .duration
        .map(|d| d as u64)
        .or_else(|| config.extra.get("duration").and_then(Value::as_u64))
        .unwrap_or(0)
        .min(30_000);
    if ms > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }
}

/// A response is "stale" (session expired) when: status is 401/403, OR the final URL matches a
/// login_url_pattern, OR a step that expected JSON got an HTML document.
fn is_stale(resp: &HttpResponse, config: &WorkflowStepConfig, cfg: &LadderConfig) -> bool {
    if resp.status == 401 || resp.status == 403 {
        return true;
    }
    let final_url = resp.final_url.as_str().to_ascii_lowercase();
    if cfg
        .login_url_patterns
        .iter()
        .any(|p| !p.is_empty() && final_url.contains(&p.to_ascii_lowercase()))
    {
        return true;
    }
    // HTML-when-JSON-expected: only treat as stale when this step actually wanted JSON (declares a
    // variable/response_extractions), else an HTML-returning endpoint is legitimate.
    let expects_json = config.extra.contains_key("response_extractions")
        || config.extra.contains_key("variable");
    if expects_json && resp.json.is_none() && resp.body.trim_start().starts_with('<') {
        return true;
    }
    false
}

/// Heuristic anti-bot / challenge interstitial detection — a page the browser might clear but the HTTP
/// lane can't.
fn looks_like_challenge(resp: &HttpResponse) -> bool {
    let body = &resp.body;
    let low = body.to_ascii_lowercase();
    if low.contains("cf-chl") || low.contains("cf-turnstile") || low.contains("just a moment")
        || low.contains("challenge-platform") || low.contains("/cdn-cgi/challenge")
    {
        return true;
    }
    if resp.status == 403 {
        let server = resp
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("server"))
            .map(|(_, v)| v.to_ascii_lowercase())
            .unwrap_or_default();
        if server.contains("cloudflare") || server.contains("akamai") {
            return true;
        }
    }
    false
}

fn parse_steps(raw_steps: &[Value]) -> Vec<ParsedStep> {
    let mut out = Vec::new();
    for (i, raw) in raw_steps.iter().enumerate() {
        if !raw.get("enabled").and_then(Value::as_bool).unwrap_or(true) {
            continue;
        }
        let step_type = raw.get("type").and_then(Value::as_str).unwrap_or("").to_string();
        if step_type.is_empty() {
            continue;
        }
        let cfg_val = raw.get("config").cloned().unwrap_or_else(|| raw.clone());
        let config: WorkflowStepConfig = serde_json::from_value(cfg_val).unwrap_or_default();
        out.push(ParsedStep { index: i, step_type, config });
    }
    out
}
