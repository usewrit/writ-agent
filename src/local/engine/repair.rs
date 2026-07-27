//! AI auto-repair for LOCAL runs — cloud-linked only.
//!
//! When a step fails on THIS device and the workflow opted into auto-repair (`ai_repair_enabled`),
//! we ask the MANAGED cloud AI gateway (never a BYO key — repair is a metered cloud capability) to
//! re-derive the broken CSS selector from the live page, validate the candidate against the DOM, and
//! hand it back to the engine to retry in place. The run stays on-device; only this repair call
//! crosses to the cloud (billed/enforced server-side). An out-of-credit account surfaces the
//! gateway's 402 upgrade message so the UI can prompt an upgrade.
//!
//! Whole module is `#[cfg(feature = "cloud")]`: the OSS build has no gateway to reach.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use sqlx::SqlitePool;

use crate::automation::step_eval;
use crate::browser::{navigation, page_query};
use crate::local::ai::explorer::run_explorer;
use crate::local::ai::provider::{self, AiConfig};
use crate::local::ai::session::{SessionConfig, SessionStatus};
use crate::local::cloud::state::LinkState;
use crate::local::error::LocalError;
use crate::local::store::{repair_history, workflows};
use crate::local::vault::Vault;
use crate::models::ai::{AiMessage, AiMessageContent};
use crate::models::workflow::WorkflowStepConfig;

use super::registry::CancelToken;

/// Cap the rendered-DOM snippet we ship to the model (token cost + gateway limits). The collapsed
/// `outerHTML` of a typical page fits well under this; larger pages are head-truncated.
const MAX_DOM_CHARS: usize = 12_000;
/// A re-derived selector is a short string — cap the model's output tokens tightly.
const MAX_REPAIR_TOKENS: u32 = 400;
/// A whole-recipe repair returns a full steps array — give it a generous output budget.
const MAX_RECIPE_TOKENS: u32 = 4_000;

const REPAIR_SYSTEM: &str = "You repair broken web-automation selectors. A recorded step's CSS \
selector no longer matches the page (the site changed). Given the failing step, its old selector, \
the runtime error, and the current page HTML, find the CSS selector that now targets the SAME \
element the step intended to act on. Prefer a stable, specific selector (ids, data-* attributes, \
aria labels, or a short tag+class path) over brittle nth-child chains. Reply with ONLY a JSON \
object of the form {\"selector\": \"<css>\"} and nothing else. If you cannot confidently identify \
the element, reply {\"selector\": null}.";

/// Outcome of a repair attempt.
pub enum RepairOutcome {
    /// A new selector was produced AND validated to match ≥1 element on the live page. Retry with it.
    Repaired { selector: String },
    /// The linked account is out of AI credit / over a plan limit. Carries the gateway's user-facing
    /// upgrade message; the engine should FAIL the run with it (no retry, no thrash).
    CreditRequired(String),
    /// No repair available (not linked, offline, unparseable reply, no matching candidate, non-selector
    /// step). The engine falls back to the ordinary step failure.
    Unavailable,
}

/// Try to re-derive `step_config`'s selector via the managed cloud AI gateway. Never mutates the page
/// or the workflow — it only returns a validated candidate for the caller to apply and persist.
pub async fn repair_step_selector(
    pool: &SqlitePool,
    page: &playwright_rs::Page,
    step_type: &str,
    step_config: &WorkflowStepConfig,
    error: &str,
) -> RepairOutcome {
    // Only selector-driven steps have something to re-derive. A navigation / script / wait step that
    // fails is not a moved-selector problem, so repair can't help — bail to the normal failure.
    let old_selector = match step_config.selector.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => s.to_string(),
        None => return RepairOutcome::Unavailable,
    };

    // Cloud-linked gate (defensive — the engine also checks before calling). Repair needs the gateway.
    match LinkState::load_or_default(pool).await {
        Ok(link) if link.is_linked() => {}
        _ => return RepairOutcome::Unavailable,
    }

    let dom = capture_dom(page).await;
    let user = build_user_prompt(step_type, &old_selector, error, &dom);
    let messages = vec![AiMessage { role: "user".into(), content: AiMessageContent::Text(user) }];

    let completion = match provider::repair_complete(pool, &messages, Some(REPAIR_SYSTEM), MAX_REPAIR_TOKENS).await {
        Ok(c) => c,
        // Out of credit → propagate the upgrade message so the engine can surface it.
        Err(LocalError::PaymentRequired(msg)) => return RepairOutcome::CreditRequired(msg),
        Err(e) => {
            tracing::warn!(error = %e, "AI repair: cloud gateway call failed");
            return RepairOutcome::Unavailable;
        }
    };

    let Some(candidate) = extract_selector(&completion.text) else {
        tracing::warn!(reply = %truncate(&completion.text, 200), "AI repair: no usable selector in reply");
        return RepairOutcome::Unavailable;
    };

    // NEVER apply an unvalidated selector: it must actually match on the live page, and differ from
    // the one that just failed (mirrors the concierge selector-finder's `selector_matches` guard).
    if candidate == old_selector {
        tracing::info!("AI repair: model returned the same (broken) selector — rejecting");
        return RepairOutcome::Unavailable;
    }
    if !selector_matches(page, &candidate).await {
        tracing::info!(candidate = %candidate, "AI repair: candidate selector matches nothing on page — rejecting");
        return RepairOutcome::Unavailable;
    }

    tracing::info!(old = %old_selector, new = %candidate, "AI repair: re-derived a matching selector");
    RepairOutcome::Repaired { selector: candidate }
}

/// Collapsed rendered-DOM snapshot for the model, head-truncated to [`MAX_DOM_CHARS`]. On any evaluate
/// failure we return an empty string — the model then works from the step + error alone.
async fn capture_dom(page: &playwright_rs::Page) -> String {
    let js = "document.documentElement ? document.documentElement.outerHTML : ''";
    let html = page_query::evaluate::<String>(page, js).await.unwrap_or_default();
    truncate(&html, MAX_DOM_CHARS)
}

fn build_user_prompt(step_type: &str, old_selector: &str, error: &str, dom: &str) -> String {
    format!(
        "Failing step type: {step_type}\nOld selector (no longer matches): {old_selector}\nRuntime error: {error}\n\nCurrent page HTML (possibly truncated):\n{dom}\n\nReturn ONLY {{\"selector\": \"<css>\"}}."
    )
}

/// Pull a `selector` string out of the model's reply. Tolerates code fences and surrounding prose by
/// scanning for the first `{ … }` object; a `null`/empty selector yields `None`.
fn extract_selector(text: &str) -> Option<String> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end < start {
        return None;
    }
    let obj: serde_json::Value = serde_json::from_str(&text[start..=end]).ok()?;
    obj.get("selector")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// `document.querySelectorAll(<sel>).length > 0` on the live page. Any evaluate failure = no match.
async fn selector_matches(page: &playwright_rs::Page, selector: &str) -> bool {
    let sel_json = serde_json::to_string(selector).unwrap_or_else(|_| "\"\"".into());
    let js = format!("() => {{ try {{ return document.querySelectorAll({sel_json}).length; }} catch (e) {{ return 0; }} }}");
    matches!(page.evaluate::<(), i64>(&js, None::<&()>).await, Ok(n) if n > 0)
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    s.chars().take(max).collect()
}

// ── Tier A: whole-workflow recipe repair ─────────────────────────────────────

const RECIPE_SYSTEM: &str = "You repair broken browser-automation workflows. A recorded workflow \
(an ordered list of steps) stopped working because the target site's UI changed. You see the WHOLE \
workflow, the names of the data/secret placeholders it may reference, the entry URL, the runtime \
error, and the current page HTML. Return a CORRECTED steps array that accomplishes the SAME thing \
on the new UI. You may fix CSS selectors (`config.selector`), JavaScript in `config.script` steps \
(`evaluate`/`codegen`/computed `extract`), navigation targets (`config.url`), and reorder/insert/ \
remove steps as needed. Keep every step's `type` valid and preserve `{{placeholder}}` references \
(e.g. `{{secret:KEY}}`, `{{input.NAME}}`, `{{NAME}}`) verbatim — never inline a secret value. Do \
NOT invent credentials. Reply with ONLY a JSON object {\"steps\": [ <step objects> ]} and nothing \
else. If you cannot confidently repair the whole workflow, reply {\"steps\": null} so the caller can \
fall back to re-recording it from scratch.";

/// Outcome of a whole-recipe repair (Tier A) or an autonomous re-record (Tier B).
pub enum RecipeOutcome {
    /// A replacement steps array (validated as a non-empty array of typed step objects). Persist it
    /// and restart the run with it.
    Recipe(Vec<serde_json::Value>),
    /// The linked account is out of AI credit / over a plan limit. Fail the run with this message.
    CreditRequired(String),
    /// No usable recipe produced — the caller falls through (to the next tier, or the ordinary failure).
    Unavailable,
}

/// Ship the WHOLE workflow + context to the managed gateway and get back a repaired steps array.
/// Fixes selectors, script steps, and navigation across the entire recipe in one shot (Tier A).
pub async fn repair_workflow_recipe(
    pool: &SqlitePool,
    page: &playwright_rs::Page,
    raw_steps: &[serde_json::Value],
    form_keys: &[String],
    secret_keys: &[String],
    entry_url: Option<&str>,
    error: &str,
) -> RecipeOutcome {
    match LinkState::load_or_default(pool).await {
        Ok(link) if link.is_linked() => {}
        _ => return RecipeOutcome::Unavailable,
    }

    let steps_json = serde_json::to_string_pretty(raw_steps).unwrap_or_else(|_| "[]".into());
    let dom = capture_dom(page).await;
    let user = format!(
        "Entry URL: {entry}\nAvailable data placeholders (values omitted): {form:?}\nAvailable secret placeholders (names only): {secret:?}\nRuntime error: {error}\n\nCurrent workflow steps (JSON):\n{steps}\n\nCurrent page HTML (possibly truncated):\n{dom}\n\nReturn ONLY {{\"steps\": [ ... ]}}.",
        entry = entry_url.unwrap_or(""),
        form = form_keys,
        secret = secret_keys,
        steps = truncate(&steps_json, MAX_DOM_CHARS),
    );
    let messages = vec![AiMessage { role: "user".into(), content: AiMessageContent::Text(user) }];

    let completion = match provider::repair_complete(pool, &messages, Some(RECIPE_SYSTEM), MAX_RECIPE_TOKENS).await {
        Ok(c) => c,
        Err(LocalError::PaymentRequired(msg)) => return RecipeOutcome::CreditRequired(msg),
        Err(e) => {
            tracing::warn!(error = %e, "AI repair: whole-recipe gateway call failed");
            return RecipeOutcome::Unavailable;
        }
    };

    match extract_steps(&completion.text) {
        Some(steps) if !steps.is_empty() => {
            tracing::info!(steps = steps.len(), "AI repair: model returned a repaired recipe");
            RecipeOutcome::Recipe(steps)
        }
        _ => {
            tracing::info!("AI repair: whole-recipe repair produced no usable steps");
            RecipeOutcome::Unavailable
        }
    }
}

/// Persist a whole-recipe repair: snapshot the OLD steps into repair history, then overwrite the
/// workflow's `steps` (and `entry_url` when the new recipe starts by navigating). Best-effort — a
/// failure is logged, never propagated (the fix was already applied to the in-flight restart).
/// `kind` = `"recipe"` (Tier A rewrite) | `"re_record"` (Tier B autonomous).
pub async fn persist_repaired_recipe(
    pool: &SqlitePool,
    workflow_id: i64,
    old_steps: &[serde_json::Value],
    new_steps: &[serde_json::Value],
    kind: &str,
    note: &str,
) {
    let old_json = serde_json::to_string(old_steps).unwrap_or_else(|_| "[]".into());
    let new_json = match serde_json::to_string(new_steps) {
        Ok(j) => j,
        Err(e) => {
            tracing::warn!(error = %e, "AI repair: could not serialize repaired recipe — not persisting");
            return;
        }
    };
    if let Err(e) = repair_history::record(pool, workflow_id, kind, &old_json, Some(&new_json), Some(note)).await {
        tracing::warn!(workflow_id, error = %e, "AI repair: failed to record repair history");
    }
    // A recipe that begins by navigating updates the workflow's entry_url too; None leaves it as-is.
    let entry_url = new_steps.iter().find_map(|s| {
        if s.get("type").and_then(|t| t.as_str()) != Some("navigate") {
            return None;
        }
        s.get("config")
            .and_then(|c| c.get("url"))
            .or_else(|| s.get("url"))
            .and_then(|u| u.as_str())
            .map(str::to_string)
    });
    let patch = workflows::WorkflowUpdate { steps: Some(new_json), entry_url, ..Default::default() };
    if let Err(e) = workflows::update(pool, workflow_id, &patch).await {
        tracing::warn!(workflow_id, error = %e, "AI repair: failed to persist repaired recipe");
    } else {
        // Stamp the workflow as repaired ONLY once the new recipe actually reached the DB — this is
        // what retires this workflow's older failures from Home's "Needs attention" (0023), so a
        // repair that failed to persist must not claim it.
        if let Err(e) = workflows::mark_repaired(pool, workflow_id).await {
            tracing::warn!(workflow_id, error = %e, "AI repair: failed to stamp last_repaired_at");
        }
        tracing::info!(workflow_id, kind, "AI repair: persisted repaired recipe");
    }
}

// ── Escalation: Tier A → Tier B ──────────────────────────────────────────────

/// Everything the smart-repair escalation needs about the failed workflow. Refs (no ownership) so the
/// engine can hand slices straight out of the run loop.
pub struct SmartRepairInputs<'a> {
    /// The full ordered steps array (raw JSON), pre-repair.
    pub raw_steps: &'a [serde_json::Value],
    /// Names of the available data placeholders (`{{NAME}}`/`{{input.NAME}}`) — values omitted.
    pub form_keys: &'a [String],
    /// Names of the referenced secret placeholders (`{{secret:KEY}}`) — names only, never values.
    pub secret_keys: &'a [String],
    /// The workflow's entry URL (where a re-record starts).
    pub entry_url: Option<&'a str>,
    /// A natural-language objective for a re-record (usually the workflow description).
    pub goal: Option<&'a str>,
    /// The runtime error that stopped the run.
    pub error: &'a str,
    /// Whether the expensive autonomous re-record (Tier B) is allowed — only true when a self-heal
    /// restart is still available to actually apply the result this run.
    pub allow_rerecord: bool,
    /// SECRET channel `KEY -> value` (decrypted). Handed to the re-record agent as fill values so a
    /// credentialed flow (login, etc.) can be reproduced autonomously; recorded back as
    /// `{{secret:KEY}}`, never a baked value.
    pub credentials: &'a HashMap<String, String>,
    /// NON-secret input values (`{{input.NAME}}`). Model-visible fill values for the re-record.
    pub form_data: &'a HashMap<String, String>,
}

/// Smart-repair escalation. The PRIMARY path is a grounded live re-record (Tier B): drive the real
/// browser from the entry point, SEEDED with the old (broken) recipe as intent, so every selector is
/// re-derived against the DOM the agent actually sees — this converges in one restart instead of the
/// one-shot rewrite's plausible-but-unvalidated guesses. The one-shot whole-workflow LLM rewrite
/// (Tier A) is the FALLBACK, used only when a live re-record can't run (no self-heal restart budget,
/// or no real entry URL) so we can still offer a (deferred) repair. Returns a replacement steps array
/// to persist + retry, a credit error, or `Unavailable` (nothing worked → ordinary failure).
pub async fn repair_or_rerecord(
    db: &SqlitePool,
    vault: &Arc<Vault>,
    page: &playwright_rs::Page,
    cancel: &CancelToken,
    inputs: SmartRepairInputs<'_>,
) -> RecipeOutcome {
    // Tier B (PRIMARY) — grounded autonomous re-record seeded with the old recipe. Needs a self-heal
    // restart to apply its result this run, and a real entry URL to start from.
    let entry = inputs.entry_url.filter(|u| !u.is_empty() && *u != "about:blank");
    if inputs.allow_rerecord {
        if let Some(entry) = entry {
            match rerecord_workflow(
                db, vault, page, cancel,
                inputs.goal, entry, inputs.raw_steps, inputs.error,
                inputs.credentials, inputs.form_data,
            )
            .await
            {
                RecipeOutcome::Recipe(steps) => return RecipeOutcome::Recipe(steps),
                RecipeOutcome::CreditRequired(m) => return RecipeOutcome::CreditRequired(m),
                RecipeOutcome::Unavailable => {
                    tracing::info!("AI smart repair: live re-record didn't converge — falling back to one-shot recipe rewrite");
                }
            }
        }
    }

    // Tier A (FALLBACK) — whole-workflow one-shot LLM rewrite. Selectors it can't ground get cleaned
    // up by per-step repair on the next run; used when the grounded re-record above wasn't possible.
    match repair_workflow_recipe(
        db,
        page,
        inputs.raw_steps,
        inputs.form_keys,
        inputs.secret_keys,
        inputs.entry_url,
        inputs.error,
    )
    .await
    {
        RecipeOutcome::Recipe(steps) => RecipeOutcome::Recipe(steps),
        RecipeOutcome::CreditRequired(m) => RecipeOutcome::CreditRequired(m),
        RecipeOutcome::Unavailable => RecipeOutcome::Unavailable,
    }
}

/// Tier B: drive the autonomous agent (`run_explorer`) from the entry point on the ALREADY-open
/// (and, via persona/session, already-authenticated) context to reproduce the workflow's goal on the
/// new UI, and return its freshly recorded steps. Metered on the linked account (forced gateway).
#[allow(clippy::too_many_arguments)]
async fn rerecord_workflow(
    db: &SqlitePool,
    vault: &Arc<Vault>,
    page: &playwright_rs::Page,
    cancel: &CancelToken,
    goal: Option<&str>,
    entry_url: &str,
    old_steps: &[serde_json::Value],
    error: &str,
    credentials: &HashMap<String, String>,
    form_data: &HashMap<String, String>,
) -> RecipeOutcome {
    // Vet + navigate the existing context back to the entry point (same guard the run path uses).
    if !crate::security::url_guard::is_navigation_url_safe_async(entry_url).await {
        tracing::warn!(entry_url, "AI re-record: unsafe entry URL — skipping");
        return RecipeOutcome::Unavailable;
    }
    if let Err(e) = navigation::goto(page, entry_url, "domcontentloaded", std::time::Duration::from_secs(30)).await {
        tracing::warn!(error = %e, "AI re-record: navigation to entry URL failed");
        return RecipeOutcome::Unavailable;
    }

    // Hand the workflow's data so a credentialed flow (login, etc.) can actually be reproduced.
    // `fill_data` carries the real values (incl. decrypted secrets); `available_data` masks secrets;
    // `record_templates` maps each key to the placeholder the RECORDED step must carry so replay
    // re-resolves it (secret → `{{secret:KEY}}`, input → `{{input.KEY}}`) instead of baking a value.
    let mut fill_data: HashMap<String, String> = form_data.clone();
    let mut available_data: HashMap<String, String> = form_data.clone();
    let mut record_templates: HashMap<String, String> = HashMap::new();
    for (k, v) in credentials {
        let placeholder = format!("{{{{secret:{k}}}}}");
        fill_data.insert(k.clone(), v.clone());
        available_data.insert(k.clone(), placeholder.clone()); // never expose the secret VALUE
        record_templates.insert(k.clone(), placeholder);
    }
    for k in form_data.keys() {
        record_templates.insert(k.clone(), format!("{{{{input.{k}}}}}"));
    }

    // SAFETY + SECRET HYGIENE: a recipe recorded with LITERAL fill values (rather than
    // `{{placeholders}}`) would otherwise embed raw values — including passwords — straight into the
    // seed PROMPT. That both leaks them to the gateway AND trips model safety classifiers (a prompt
    // full of credentials + "log in" reads as a credential-handling request, and some models answer
    // with a safety verdict instead of the completion — which stalls the whole re-record). Redact each
    // baked literal OUT of the seed copy and hand the real value to the agent via `fill_data` instead:
    // it still logs in, but the raw value never appears in the prompt. The re-recorded step keeps the
    // literal (via `record_templates`) so replay still resolves it. `old_steps` itself is untouched
    // (the graft below needs the real extraction steps).
    let mut seed_steps: Vec<serde_json::Value> = old_steps.to_vec();
    for (idx, step) in seed_steps.iter_mut().enumerate() {
        let ty = step.get("type").and_then(|t| t.as_str()).unwrap_or("").to_string();
        if !matches!(ty.as_str(), "fill" | "type") {
            continue;
        }
        let in_config = step.get("config").is_some();
        let raw_value = if in_config {
            step.get("config").and_then(|c| c.get("value")).and_then(|v| v.as_str())
        } else {
            step.get("value").and_then(|v| v.as_str())
        };
        let Some(value) = raw_value.map(str::to_string) else { continue };
        // Leave already-templated (`{{…}}`) or empty values alone — nothing sensitive to redact.
        if value.trim().is_empty() || value.contains("{{") {
            continue;
        }
        let key = format!("recorded_value_{idx}");
        // The advertised placeholder MUST spell the fill_data key EXACTLY — `resolve_placeholders`
        // substitutes `{{k}}` only for an exact fill_data key `k`. (A mismatch types the literal
        // `{{…}}` into the field → a broken login.) Register an `input.`-prefixed ALIAS too, so the
        // agent resolves whichever spelling it picks (the [SECURE] `{{key}}` or the `{{input.key}}`
        // user-data convention).
        let placeholder = format!("{{{{{key}}}}}");
        fill_data.insert(key.clone(), value.clone());
        fill_data.insert(format!("input.{key}"), value.clone());
        available_data.insert(key.clone(), placeholder.clone()); // model sees the placeholder, not the value
        record_templates.insert(key.clone(), value.clone()); // recorded step keeps the literal → replay resolves
        let redacted = serde_json::Value::String(placeholder);
        if in_config {
            if let Some(obj) = step.get_mut("config").and_then(|c| c.as_object_mut()) {
                obj.insert("value".to_string(), redacted);
            }
        } else if let Some(obj) = step.as_object_mut() {
            obj.insert("value".to_string(), redacted);
        }
    }

    // SEED the agent with the (credential-redacted) OLD recipe as intent + the specific break, so it
    // extrapolates old → new while grounding every selector in the live DOM it drives.
    let mut cfg = SessionConfig::new(build_rerecord_goal(goal, entry_url, &seed_steps, error));
    // Bound the autonomous run (the explorer's own stall breakers stop it sooner on a dead site).
    cfg.max_steps = 30;
    cfg.fill_data = fill_data;
    cfg.available_data = available_data;
    cfg.record_templates = record_templates;

    // The forced-gateway path ignores `ai_cfg`, but resolve one anyway (fall back to an empty config
    // when no BYO provider is configured — the gateway doesn't need it).
    let ai_cfg = provider::resolve_config(db, vault.as_ref())
        .await
        .ok()
        .flatten()
        .unwrap_or(AiConfig { provider: String::new(), model: String::new(), base_url: None, api_key: None });

    // Bridge the run's watch-based CancelToken to an AtomicBool the explorer polls, so a mid-repair
    // Stop aborts the autonomous run too.
    let flag = Arc::new(AtomicBool::new(cancel.is_cancelled()));
    {
        let flag2 = flag.clone();
        let ct = cancel.clone();
        tokio::spawn(async move {
            ct.cancelled().await;
            flag2.store(true, Ordering::SeqCst);
        });
    }

    match run_explorer(page, &cfg, &ai_cfg, db, Some(flag.as_ref()), None, None, /* force_gateway */ true).await {
        // Only auto-apply a recipe the agent believes ACCOMPLISHES the goal (status Complete). A
        // max-steps/stuck run didn't converge — fall through to the ordinary failure.
        Ok(res) if res.status == SessionStatus::Complete && !res.recorded_steps.is_empty() => {
            // The agent grounded the INTERACTION path against the live DOM, but it may have re-derived
            // its OWN extraction with a different output shape. The break is usually in navigation, not
            // extraction — so where the re-record left off (the data page), LIVE-TEST the ORIGINAL
            // extraction step(s) and graft them back when they still return real data, preserving the
            // workflow's output SCHEMA. If an original extraction is broken too, keep the agent's.
            let steps = graft_original_extractions(page, res.recorded_steps, old_steps).await;
            tracing::info!(steps = steps.len(), "AI re-record: agent reproduced the workflow on the new UI");
            RecipeOutcome::Recipe(steps)
        }
        Ok(res) => {
            tracing::info!(status = res.status.as_str(), "AI re-record: did not converge on a usable recipe");
            RecipeOutcome::Unavailable
        }
        Err(LocalError::PaymentRequired(msg)) => RecipeOutcome::CreditRequired(msg),
        Err(e) => {
            tracing::warn!(error = %e, "AI re-record: explorer run failed");
            RecipeOutcome::Unavailable
        }
    }
}

/// Build the re-record objective: the workflow's intent PLUS the old (now-broken) recipe as
/// reference and the specific break. The agent reproduces the SAME outcome on the CURRENT UI, using
/// the old steps only to know WHAT to do (order, which data goes in which field, what to extract) —
/// and re-derives every selector from the live DOM it drives, never reusing a broken one.
fn build_rerecord_goal(
    goal: Option<&str>,
    entry_url: &str,
    old_steps: &[serde_json::Value],
    error: &str,
) -> String {
    let intent = derive_goal(goal, entry_url);
    let steps_json = truncate(
        &serde_json::to_string_pretty(old_steps).unwrap_or_else(|_| "[]".into()),
        MAX_DOM_CHARS,
    );
    format!(
        "{intent}\n\nThe site's UI changed and the previously-recorded steps broke here: {error}\n\n\
Use the OLD recipe below ONLY as intent — the order of actions, which data placeholder fills which \
field, and what to extract. Do NOT reuse its CSS selectors or coordinates; they no longer match. \
Find each element on the CURRENT page you are driving and record fresh, working steps that achieve \
the same result. Keep every {{placeholder}} reference (e.g. {{secret:KEY}}, {{input.NAME}}) verbatim.\n\n\
Reproduce the SAME STYLE of interaction the old recipe used: where it filled a form or clicked in the \
browser, drive the live UI the same way — click through any NEW intermediate screens the redesign added \
(a consent/\"continue\"/verify step, a revealed panel, an extra page) to reach the real control. Do NOT \
substitute a direct HTTP/api_call login for a form the user filled in the browser — a gated flow will \
just bounce it. Only reach for an api_call when the OLD recipe itself used one.\n\n\
OLD (broken) recipe:\n{steps_json}"
    )
}

/// Turn the stored workflow description into an agent objective. AI-recorded workflows store their
/// original goal as `"Recorded from an autonomous AI session (goal: X)"`; unwrap the inner goal when
/// present, else use the description verbatim, else a generic reproduce-what-ran objective.
fn derive_goal(goal: Option<&str>, entry_url: &str) -> String {
    if let Some(d) = goal.map(str::trim).filter(|s| !s.is_empty()) {
        if let Some(idx) = d.find("(goal:") {
            let inner = d[idx + "(goal:".len()..].trim_end_matches(')').trim();
            if !inner.is_empty() {
                return format!("Reproduce this task on the current site and record the steps: {inner}");
            }
        }
        return format!("Reproduce this task on the current site and record the steps: {d}");
    }
    format!(
        "Reproduce the workflow that previously ran at {entry_url}: perform the same actions and extract the same data on the current UI, and record the steps."
    )
}

/// Pull a `steps` array out of the model reply and validate it is a non-empty array of step objects
/// that each carry a non-empty `type`. A `null`/malformed/typeless reply yields `None`.
fn extract_steps(text: &str) -> Option<Vec<serde_json::Value>> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end < start {
        return None;
    }
    let obj: serde_json::Value = serde_json::from_str(&text[start..=end]).ok()?;
    let arr = obj.get("steps")?.as_array()?;
    if arr.is_empty() {
        return None;
    }
    // Every step must be an object with a non-empty string `type` — otherwise the engine would just
    // skip it, and a recipe full of skips is worse than the original failure.
    let all_typed = arr.iter().all(|s| {
        s.get("type").and_then(|t| t.as_str()).map(|t| !t.trim().is_empty()).unwrap_or(false)
    });
    if !all_typed {
        return None;
    }
    Some(arr.clone())
}

// ── Preserve the output schema: graft the original extraction back after a re-record ──────────────

/// The step's config object — either the nested `config` or (for a flat recorded step) the step
/// itself. Mirrors how the run loop resolves a step's config.
fn step_config_value(step: &serde_json::Value) -> serde_json::Value {
    step.get("config").cloned().unwrap_or_else(|| step.clone())
}

/// A data DELIVERABLE step: a DOM read (`evaluate`/`extract`) or backend call (`api_call`) that names
/// an output `variable`. These carry the workflow's output SHAPE — a side-effect `evaluate` with no
/// `variable` is not a deliverable.
fn is_extraction_step(step: &serde_json::Value) -> bool {
    let ty = step.get("type").and_then(|t| t.as_str()).unwrap_or("");
    if !matches!(ty, "extract" | "evaluate" | "api_call") {
        return false;
    }
    let cfg = step_config_value(step);
    cfg.get("variable")
        .or_else(|| step.get("variable"))
        .and_then(|v| v.as_str())
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
}

/// A JSON value counts as real extracted data if it isn't null / empty string / empty collection.
fn json_value_nonempty(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Null => false,
        serde_json::Value::String(s) => !s.trim().is_empty(),
        serde_json::Value::Array(a) => !a.is_empty(),
        serde_json::Value::Object(o) => !o.is_empty(),
        _ => true, // numbers / bools are meaningful
    }
}

/// Live-run a single original extraction step on the CURRENT page and report whether it still returns
/// real data. `api_call` is a backend endpoint unaffected by a DOM/UI change, so it's treated as still
/// valid without a live hit (its auth is re-verified at replay). Only `evaluate`/`extract` — the DOM
/// reads that actually break on a redesign — are executed here (both are read-only, ctx-free).
async fn live_extraction_ok(page: &playwright_rs::Page, step: &serde_json::Value) -> bool {
    let ty = step.get("type").and_then(|t| t.as_str()).unwrap_or("");
    if ty == "api_call" {
        return true;
    }
    let cfg: WorkflowStepConfig = match serde_json::from_value(step_config_value(step)) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let result = match ty {
        "evaluate" => step_eval::execute_evaluate(page, &cfg).await,
        "extract" => step_eval::execute_extract(page, &cfg).await,
        _ => return false,
    };
    matches!(&result, Ok(Some(map)) if map.values().any(json_value_nonempty))
}

/// After a grounded re-record, keep the workflow's OUTPUT SCHEMA stable: if the original extraction
/// step(s) STILL return real data on the re-derived page, splice them back onto the agent's freshly
/// grounded INTERACTION steps (dropping the agent's own re-derived extraction). If any original
/// extraction is broken too — or the old recipe had none — keep the agent's steps unchanged.
async fn graft_original_extractions(
    page: &playwright_rs::Page,
    agent_steps: Vec<serde_json::Value>,
    old_steps: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    let old_deliverables: Vec<serde_json::Value> =
        old_steps.iter().filter(|s| is_extraction_step(s)).cloned().collect();
    if old_deliverables.is_empty() {
        return agent_steps;
    }
    for step in &old_deliverables {
        if !live_extraction_ok(page, step).await {
            tracing::info!(
                "AI re-record: an original extraction no longer returns data on the new UI — keeping the agent's re-derived extraction"
            );
            return agent_steps;
        }
    }
    // Every original extraction still works: rebuild as [agent interaction steps] + [old extractions].
    let mut out: Vec<serde_json::Value> =
        agent_steps.into_iter().filter(|s| !is_extraction_step(s)).collect();
    let grafted = old_deliverables.len();
    out.extend(old_deliverables);
    tracing::info!(grafted, "AI re-record: original extraction still returns data — grafted it back to preserve the output schema");
    out
}
