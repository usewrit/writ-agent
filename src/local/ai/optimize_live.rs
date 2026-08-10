//! Live workflow optimizer — replay a recorded workflow with network capture ON, then propose (and
//! LIVE-VERIFY) replacing fragile DOM steps with direct `api_call` / `login_post` steps.
//!
//! Unlike the blind static `optimize_workflow` (which guesses from whatever network the caller passed),
//! this actually REPLAYS the workflow in a real browser: that triggers + captures every backend API
//! call the DOM steps make and leaves an authenticated page open. An AI then emits STRUCTURED proposals
//! (`substitutions` / `removals`); the backend verifies each proposed request step against that
//! still-open authed page (`run_api_call` / `run_login_post`) and DETERMINISTICALLY assembles the final
//! steps, applying only the substitutions that actually returned data. The result is returned as a
//! diff for the user to confirm (the FE Applies via `PATCH /workflows/:id`) — nothing is written here.
//!
//! Replaying re-runs the workflow's real actions, so a side-effect gate (`risky_side_effect`) fails
//! closed with `requires_confirm` before launching a browser unless the caller opts in.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use sqlx::SqlitePool;
use tokio::sync::Mutex;

use crate::automation::files::RunFiles;
use crate::automation::network_capture::NetworkCapture;
use crate::automation::step_executor::execute_step;
use crate::local::ai::{brain, explorer, prompts, provider};
use crate::local::engine::{persona, resolve, twofa, LocalEngine};
use crate::local::error::{LocalError, LocalResult};
use crate::local::server::AppState;
use crate::local::store::workflows;
use crate::local::vault::Vault;
use crate::models::ai::{AiMessage, AiMessageContent};
use crate::models::workflow::WorkflowStepConfig;

/// Terms in a click/submit label or navigate URL that mark a mutating, hard-to-undo action. Replaying
/// a workflow re-runs these for real, so we gate on them (see [`risky_side_effect`]).
const RISKY_TERMS: &[&str] = &[
    "buy", "order", "checkout", "pay", "purchase", "submit", "delete", "remove", "send", "transfer",
    "confirm", "cart",
];
/// URL fragments that appear in an auth endpoint — a mutating POST to one of these is a benign
/// re-login, not a risky side effect.
const AUTH_URL_HINTS: &[&str] = &["login", "auth", "token", "session", "signin", "sign-in"];

/// Scan the workflow's steps for likely side effects. Returns `Some(reason)` naming what matched when
/// the workflow looks mutating (so the caller must explicitly confirm before we replay it), else `None`.
fn risky_side_effect(steps: &[Value]) -> Option<String> {
    let mut hits: Vec<String> = Vec::new();
    let note = |h: String, hits: &mut Vec<String>| {
        if !hits.contains(&h) {
            hits.push(h);
        }
    };
    for s in steps {
        let ty = s.get("type").and_then(|t| t.as_str()).unwrap_or("");
        match ty {
            "click" | "submit" | "check" => {
                let hay = format!(
                    "{} {}",
                    s.pointer("/config/selector").and_then(|v| v.as_str()).unwrap_or(""),
                    s.pointer("/config/text").and_then(|v| v.as_str()).unwrap_or(""),
                )
                .to_lowercase();
                for t in RISKY_TERMS {
                    if hay.contains(t) {
                        note((*t).to_string(), &mut hits);
                    }
                }
            }
            "navigate" => {
                let url = s.pointer("/config/url").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
                for t in ["checkout", "cart", "payment", "order"] {
                    if url.contains(t) {
                        note(t.to_string(), &mut hits);
                    }
                }
            }
            "api_call" => {
                let method = s.pointer("/config/method").and_then(|v| v.as_str()).unwrap_or("GET").to_uppercase();
                let url = s.pointer("/config/url").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
                let is_auth = AUTH_URL_HINTS.iter().any(|a| url.contains(a));
                if matches!(method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") && !is_auth {
                    note("a data-changing API call".to_string(), &mut hits);
                }
            }
            _ => {}
        }
    }
    if hits.is_empty() {
        None
    } else {
        Some(hits.join(", "))
    }
}

/// A `{steps, changes, warnings, removed_count, requires_confirm, verified}` envelope — the exact shape
/// the FE optimize confirm UI already renders (plus the two add-only fields).
fn envelope(steps: &[Value], changes: Vec<Value>, warnings: Vec<Value>, removed: i64, requires_confirm: bool, verified: bool) -> Value {
    json!({
        "steps": steps,
        "changes": changes,
        "warnings": warnings,
        "removed_count": removed,
        "requires_confirm": requires_confirm,
        "verified": verified,
        "credits_used": 0,
    })
}

/// Close-on-drop guard so a panic anywhere across the (long) replay + AI round-trip never leaks a
/// Chromium context. The normal exit calls `disarm()` after an awaited `close()`.
struct CtxGuard(Option<playwright_rs::BrowserContext>);
impl CtxGuard {
    fn disarm(&mut self) {
        self.0 = None;
    }
}
impl Drop for CtxGuard {
    fn drop(&mut self) {
        if let Some(ctx) = self.0.take() {
            tokio::spawn(async move {
                let _ = ctx.close().await;
            });
        }
    }
}

/// Live-optimize an existing workflow (daemon REST entry). Thin wrapper over [`optimize_workflow_live_core`]
/// that unpacks the three fields the optimizer needs off `AppState`. The fleet bridge calls the core
/// directly (it holds `db`/`vault`/`engine` but not a full `AppState`).
pub(crate) async fn optimize_workflow_live(
    st: &AppState,
    workflow_id: i64,
    confirm_side_effects: bool,
) -> LocalResult<Value> {
    optimize_workflow_live_core(&st.db, &st.vault, &st.engine, workflow_id, confirm_side_effects).await
}

/// Live-optimize an existing workflow. See the module docs. Returns the diff envelope; never writes.
///
/// Takes the three collaborators the optimizer actually reads — the encrypted pool, the vault, and the
/// browser engine — rather than a full [`AppState`], so callers that hold only these (the fleet bridge)
/// can drive it without fabricating the daemon's server state (`config`/`token`/`health`/`recorder`).
pub(crate) async fn optimize_workflow_live_core(
    db: &SqlitePool,
    vault: &Arc<Vault>,
    engine: &Arc<dyn LocalEngine>,
    workflow_id: i64,
    confirm_side_effects: bool,
) -> LocalResult<Value> {
    // 1) Load + parse the workflow's steps (the ORIGINAL, before optimization).
    let wf = workflows::get_by_id(db, workflow_id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("workflow {workflow_id}")))?;
    let original: Vec<Value> = serde_json::from_str(wf.steps.trim())
        .ok()
        .filter(|v: &Value| v.is_array())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    if original.len() < 2 {
        return Ok(envelope(&original, vec![], vec![json!("This workflow has too few steps to optimize.")], 0, false, false));
    }
    if wf.workflow_type == "streaming" {
        return Ok(envelope(&original, vec![], vec![json!("Streaming workflows can't be live-optimized.")], 0, false, false));
    }

    // 2) Side-effect gate — before launching any browser.
    if !confirm_side_effects {
        if let Some(reason) = risky_side_effect(&original) {
            return Ok(envelope(
                &original,
                vec![],
                vec![json!(format!(
                    "This workflow may have side effects ({reason}). Optimizing replays it in a real browser, which re-runs those actions."
                ))],
                0,
                true,
                false,
            ));
        }
    }

    // 3) Resolve credentials / form data / persona exactly like the run engine (real.rs::execute).
    let refs = resolve::resolve_run_refs(db, vault, &wf, &json!({}), true)
        .await
        .map_err(|e| LocalError::Internal(format!("run resolution failed: {e}")))?;
    let mut credentials = refs.credentials;
    let form_data = refs.form_data;
    let resolved_persona = match wf.default_persona_id {
        Some(pid) => persona::resolve_persona(db, vault, pid).await.ok().flatten(),
        None => None,
    };
    if let Some(p) = &resolved_persona {
        p.merge_into_credentials(&mut credentials);
    }
    let proxy = resolved_persona.as_ref().and_then(|p| p.proxy.clone());

    // Every credential key K resolves to its vault ref `{{secret:K}}` at record time, so a synthesized
    // api_call/login_post carries the replay-safe placeholder (never the plaintext). Form-data keys stay
    // `{{K}}` (resolved from form_data at replay) — record_value leaves unmapped keys untouched.
    let record_templates: HashMap<String, String> =
        credentials.keys().map(|k| (k.clone(), format!("{{{{secret:{k}}}}}"))).collect();
    // The map used to REVEAL held values as {{placeholders}} in the trace AND to resolve them when we
    // verify a proposed request live: form data (so `{{search_term}}` resolves) overlaid by credentials
    // (secrets win). `run_api_call` feeds this as BOTH the `{{secret:…}}` and `{{…}}` sources.
    let mut resolve_map = form_data.clone();
    resolve_map.extend(credentials.clone());

    let timeout_ms = if wf.timeout_ms > 0 { wf.timeout_ms as u64 } else { 60_000 };
    let fast_mode = wf.fast_mode != 0;
    let entry_url = wf.entry_url.as_deref().filter(|s| !s.is_empty()).unwrap_or("about:blank");

    // 4) Warm browser → own stealth context (persona fingerprint + proxy) → attach network capture.
    let browser = engine
        .browser()
        .ok_or_else(|| LocalError::Internal("browser engine unavailable".into()))?;
    browser
        .ensure_warm_browser_with(true)
        .await
        .map_err(|e| LocalError::Internal(format!("browser launch failed: {e}")))?;
    // The persona's banked fingerprint, or a deterministic one seeded on its id, so a
    // persona without saved warmth still presents ONE stable machine across runs. Built
    // after launch so the UA carries the real Chrome major; headless here → synthesize
    // the device rather than leak the container's hardware.
    let fingerprint = match resolved_persona.as_ref() {
        Some(p) => Some(p.identity(&browser.chrome_major().await, None, true)),
        None => None,
    };
    let (context, page, _fp) = browser
        .create_stealth_context_with_fingerprint_proxy(fingerprint, proxy)
        .await
        .map_err(|e| LocalError::Internal(format!("browser context failed: {e}")))?;
    let mut guard = CtxGuard(Some(context.clone()));
    let net = Arc::new(Mutex::new(NetworkCapture::new()));
    crate::ai::api_discovery_mode::attach_network_capture(&context, net.clone()).await;

    // 5) Establish the session: restore persona cookies if present, else navigate to the entry URL.
    let nav = match resolved_persona.as_ref().and_then(|p| p.session_state.as_ref()) {
        Some(state) => {
            crate::automation::session_state::inject_session_state(&page, &context, state, Some(entry_url), 30_000).await
        }
        None => crate::browser::navigation::goto(&page, entry_url, "domcontentloaded", Duration::from_secs(30))
            .await
            .map_err(|e| anyhow::anyhow!("{e}")),
    };
    let mut replay_warnings: Vec<Value> = Vec::new();
    if let Err(e) = nav {
        tracing::warn!(workflow_id, error = %e, "optimize replay: entry navigation failed (continuing best-effort)");
    }

    // 6) Replay the steps best-effort — the goal is to TRIGGER + CAPTURE the backend calls, not a perfect
    //    run. A failing step is logged and skipped so partial traffic is still captured.
    let run_files = RunFiles::from_config(&json!({}), None);
    for (i, raw) in original.iter().enumerate() {
        let ty = raw.get("type").and_then(|t| t.as_str()).unwrap_or("");
        if ty.is_empty() || !raw.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true) {
            continue;
        }
        net.lock().await.mark_step(ty);
        // Downloads aren't needed to capture API traffic; skip (the run engine handles them specially).
        if ty == "wait_for_download" {
            continue;
        }
        // 2FA: mint + enter a TOTP on-device (same path as the run engine); email/SMS can't be read
        // locally, so warn and move on (an authed step past it may capture nothing — that's fine).
        if ty == "twofa" {
            match resolved_persona.as_ref().map(|p| p.twofa_method.as_str()).unwrap_or("none") {
                "totp" => {
                    let pid = resolved_persona.as_ref().map(|p| p.persona_id).unwrap_or(0);
                    if let Ok(Some(code)) = persona::mint_current_totp(db, vault, pid).await {
                        let _ = twofa::enter_code(&page, raw, &code).await;
                    }
                }
                "email_otp" | "sms" => replay_warnings.push(json!(
                    "This workflow signs in with an email/SMS 2FA code, which can't be replayed locally — some authenticated calls may not have been captured."
                )),
                _ => {}
            }
            continue;
        }
        let cfg: WorkflowStepConfig =
            match serde_json::from_value(raw.get("config").cloned().unwrap_or_else(|| raw.clone())) {
                Ok(c) => c,
                Err(_) => continue,
            };
        if let Err(e) = execute_step(&page, ty, &cfg, &credentials, &form_data, &run_files, timeout_ms, fast_mode).await {
            tracing::warn!(workflow_id, step = i, ty, error = %e, "optimize replay step failed (continuing)");
        }
    }
    // Let late XHRs settle so the trace is complete.
    let _ = crate::browser::navigation::wait_for_page_quiet(&page, Duration::from_secs(6)).await;

    // 7) One optimize pass over the REAL captured trace.
    let trace = {
        let cap = net.lock().await;
        let calls: Vec<&crate::models::network::NetworkCall> = cap.get_all_calls().iter().collect();
        cap.format_for_prompt(&calls, &resolve_map)
    };
    let cred_keys: Vec<String> = credentials.keys().cloned().collect();
    let form_keys: Vec<String> = form_data.keys().cloned().collect();
    let user_text = format!(
        "WORKFLOW STEPS (0-indexed):\n{}\n\nCAPTURED BACKEND CALLS (real — from replaying this workflow just now):\n{}\n\nFORM DATA KEYS: {}\nCREDENTIAL KEYS: {}\nFINAL URL: {}",
        bounded(&json!(original), 30_000),
        trace,
        bounded(&json!(form_keys), 1_000),
        bounded(&json!(cred_keys), 1_000),
        page.url(),
    );
    let messages = vec![AiMessage { role: "user".into(), content: AiMessageContent::Text(user_text) }];
    let max_tokens = provider::resolve_max_tokens(db, "optimize", 6_000).await;
    let completion = provider::complete_routed(db, vault, &messages, Some(prompts::OPTIMIZE_LIVE_SYSTEM), max_tokens, "optimize").await;

    // 8) Verify each proposal live + assemble the final steps deterministically.
    let (mut final_steps, changes, mut warnings, removed) = match completion.ok().and_then(|c| brain::parse_decision(&c.text)) {
        Some(proposal) => assemble_optimized(&page, &original, &proposal, &resolve_map, &record_templates).await,
        None => (
            original.clone(),
            vec![],
            vec![json!("AI optimization could not be parsed; the workflow is unchanged.")],
            0,
        ),
    };
    warnings.extend(replay_warnings);

    // 9) Close the context, then scrub any credential plaintext out of the returned steps (defense in
    //    depth — synthesized steps already use {{secret:…}}, but a passed-through DOM step value can't leak).
    guard.disarm();
    let _ = context.close().await;
    let available: HashMap<String, String> = credentials.keys().map(|k| (k.clone(), format!("[SECURE:{k}]"))).collect();
    final_steps = final_steps.into_iter().map(|s| explorer::scrub_value(s, &credentials, &available)).collect();

    Ok(envelope(&final_steps, changes, warnings, removed, false, true))
}

/// Bounded JSON string for the prompt (mirrors ai_assist::json_bounded, kept local to this module).
/// CHAR-BOUNDARY-SAFE: workflow steps carry arbitrary text (accented/CJK/emoji in selectors, extracted
/// values, form data), so a raw byte slice `&s[..n]` can panic ("byte index N is not a char boundary")
/// when the cut lands mid-codepoint. That panic aborts the fleet's per-request task → no reply frame →
/// the coordinator's send_and_await stalls the full timeout. Walk back to the nearest boundary instead.
pub(crate) fn bounded(v: &Value, n: usize) -> String {
    let s = serde_json::to_string(v).unwrap_or_default();
    if s.len() <= n {
        return s;
    }
    let mut end = n;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…[truncated]", &s[..end])
}

/// Per-slot decision when assembling the optimized step list from the original.
enum Slot {
    Keep,
    Drop,
    Insert(Value),
}

/// Verify each proposed substitution LIVE on the still-open authed page, then build the final steps by
/// applying only the verified substitutions + the safe removals. Returns
/// `(final_steps, changes, warnings, removed_count)`.
pub(crate) async fn assemble_optimized(
    page: &playwright_rs::Page,
    original: &[Value],
    proposal: &Value,
    resolve_map: &HashMap<String, String>,
    record_templates: &HashMap<String, String>,
) -> (Vec<Value>, Vec<Value>, Vec<Value>, i64) {
    let n = original.len();
    let mut slots: Vec<Slot> = (0..n).map(|_| Slot::Keep).collect();
    let mut assigned = vec![false; n];
    let mut changes: Vec<Value> = Vec::new();
    let mut warnings: Vec<Value> = Vec::new();

    // ── Substitutions (apply in index order; each verified live before it's kept) ──
    if let Some(subs) = proposal.get("substitutions").and_then(|v| v.as_array()) {
        let mut ordered: Vec<&Value> = subs.iter().collect();
        ordered.sort_by_key(|s| first_index(s, "replace_indices"));
        for sub in ordered {
            let idxs = indices(sub, "replace_indices");
            // Valid iff non-empty, in range, contiguous, and no index already claimed.
            if idxs.is_empty() || idxs.iter().any(|&i| i >= n || assigned[i]) {
                continue;
            }
            if !idxs.windows(2).all(|w| w[1] == w[0] + 1) {
                continue;
            }
            let with = match sub.get("with") {
                Some(w) => w,
                None => continue,
            };
            let ty = with.get("type").and_then(|t| t.as_str()).unwrap_or("");
            let cfg = with.get("config").cloned().unwrap_or_else(|| json!({}));
            let desc = sub.get("description").cloned().unwrap_or(json!(""));
            match verify_and_build(page, ty, &cfg, resolve_map, record_templates).await {
                Some(step) => {
                    slots[idxs[0]] = Slot::Insert(step);
                    for &i in &idxs[1..] {
                        slots[i] = Slot::Drop;
                    }
                    for &i in &idxs {
                        assigned[i] = true;
                    }
                    changes.push(json!({
                        "action": "replaced",
                        "step_indices": idxs,
                        "description": desc,
                        "reason": sub.get("reason").cloned().unwrap_or(json!("")),
                        "risk": sub.get("risk").cloned().unwrap_or(json!("caution")),
                    }));
                }
                None => warnings.push(json!(format!(
                    "Kept the original steps for \"{}\" — the API substitution did not verify against the live site.",
                    desc.as_str().unwrap_or("this step")
                ))),
            }
        }
    }

    // ── Removals (never drop a load-bearing type, even if proposed) ──
    if let Some(rems) = proposal.get("removals").and_then(|v| v.as_array()) {
        const PROTECTED: &[&str] = &["navigate", "extract", "evaluate", "return", "api_call", "login_post", "fill", "select"];
        for rem in rems {
            let mut dropped: Vec<usize> = Vec::new();
            for i in indices(rem, "indices") {
                if i >= n || assigned[i] {
                    continue;
                }
                let ty = original[i].get("type").and_then(|t| t.as_str()).unwrap_or("");
                if PROTECTED.contains(&ty) {
                    continue;
                }
                slots[i] = Slot::Drop;
                assigned[i] = true;
                dropped.push(i);
            }
            if !dropped.is_empty() {
                changes.push(json!({
                    "action": "removed",
                    "step_indices": dropped,
                    "description": rem.get("reason").cloned().unwrap_or(json!("Removed a redundant step")),
                    "reason": rem.get("reason").cloned().unwrap_or(json!("")),
                    "risk": rem.get("risk").cloned().unwrap_or(json!("safe")),
                }));
            }
        }
    }

    // ── Assemble ──
    let mut out: Vec<Value> = Vec::with_capacity(n);
    for (i, slot) in slots.into_iter().enumerate() {
        match slot {
            Slot::Keep => out.push(original[i].clone()),
            Slot::Drop => {}
            Slot::Insert(step) => out.push(step),
        }
    }
    // A navigate that now only precedes api_call/login_post steps is dead weight (they fetch directly);
    // drop it — but never the entry navigate.
    explorer::prune_navigates_before_api_only(&mut out);

    if let Some(ws) = proposal.get("warnings").and_then(|v| v.as_array()) {
        warnings.extend(ws.iter().cloned());
    }

    let removed = (n as i64 - out.len() as i64).max(0);
    (out, changes, warnings, removed)
}

/// Run a proposed request step live; on success return the REPLAY-spelled step to record, else `None`.
async fn verify_and_build(
    page: &playwright_rs::Page,
    ty: &str,
    cfg: &Value,
    resolve_map: &HashMap<String, String>,
    record_templates: &HashMap<String, String>,
) -> Option<Value> {
    // The explorer helpers take an `action` with url/method/headers/body at the TOP level.
    let action = json!({
        "url": cfg.get("url").cloned().unwrap_or(json!("")),
        "method": cfg.get("method").cloned().unwrap_or(json!("GET")),
        "headers": cfg.get("headers").cloned().unwrap_or(json!({})),
        "body": cfg.get("body").cloned().unwrap_or(Value::Null),
    });
    match ty {
        "login_post" => match explorer::run_login_post(page, &action, resolve_map).await {
            Ok(_) => Some(explorer::build_login_post_step(&action, record_templates)),
            Err(_) => None,
        },
        _ => {
            let var = cfg
                .get("variable")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("data")
                .to_string();
            match explorer::run_api_call(page, &action, resolve_map, &var).await {
                Ok(_) => Some(explorer::build_api_call_step(&action, &var, record_templates)),
                Err(_) => None,
            }
        }
    }
}

/// First `replace_indices`/`indices` entry (for sorting); `u64::MAX` when absent.
fn first_index(v: &Value, key: &str) -> u64 {
    v.get(key)
        .and_then(|a| a.as_array())
        .and_then(|a| a.first())
        .and_then(|x| x.as_u64())
        .unwrap_or(u64::MAX)
}

/// Parse a `[usize]` index array from a proposal field (silently drops non-numbers).
fn indices(v: &Value, key: &str) -> Vec<usize> {
    v.get(key)
        .and_then(|a| a.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_u64().map(|n| n as usize)).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wf_steps() -> Vec<Value> {
        vec![
            json!({ "type": "navigate", "enabled": true, "config": { "url": "https://x.com/login" } }),
            json!({ "type": "fill", "enabled": true, "config": { "selector": "#u", "value": "{{login_username}}" } }),
            json!({ "type": "fill", "enabled": true, "config": { "selector": "#p", "value": "{{secret:login_password}}" } }),
            json!({ "type": "click", "enabled": true, "config": { "selector": "#go" } }),
            json!({ "type": "extract", "enabled": true, "config": { "selector": ".row", "variable": "rows" } }),
        ]
    }

    #[test]
    fn bounded_truncates_on_char_boundary_without_panicking() {
        // Multibyte text near the cut must NOT panic (byte-slice would). Cap chosen to land mid-codepoint.
        let v = json!({ "s": "é".repeat(5000) });
        let out = bounded(&v, 4001); // 4001 is inside a 2-byte 'é' sequence
        assert!(out.ends_with("…[truncated]"));
        assert!(out.len() <= 4001 + "…[truncated]".len());
        // Emoji (4-byte) too.
        let v2 = json!({ "s": "🚀".repeat(3000) });
        let _ = bounded(&v2, 5003); // must not panic
        // Short input returned unchanged.
        assert_eq!(bounded(&json!("hi"), 30000), "\"hi\"");
    }

    #[test]
    fn risky_gate_flags_purchase_and_passes_read_only() {
        let mut risky = wf_steps();
        risky.push(json!({ "type": "click", "enabled": true, "config": { "selector": "button", "text": "Buy now" } }));
        assert!(risky_side_effect(&risky).is_some(), "a Buy click must be flagged");
        // A plain login + scrape is not risky.
        assert!(risky_side_effect(&wf_steps()).is_none(), "read-only login+scrape must pass");
        // A mutating POST api_call is risky; an auth POST is not.
        let post = vec![json!({ "type": "api_call", "enabled": true, "config": { "method": "POST", "url": "https://x.com/api/orders" } })];
        assert!(risky_side_effect(&post).is_some());
        let auth = vec![json!({ "type": "api_call", "enabled": true, "config": { "method": "POST", "url": "https://x.com/api/login" } })];
        assert!(risky_side_effect(&auth).is_none());
    }

    // The deterministic assemble is tested without a browser by driving the slot logic directly through
    // a proposal where the "verify" outcome is simulated: we build the same slot/splice the real code
    // uses. (The live-verify itself needs a page and is covered by the manual e2e in the plan.)
    fn apply_slots(original: &[Value], subs_verified: &[(Vec<usize>, Value)], removals: &[Vec<usize>]) -> Vec<Value> {
        let n = original.len();
        let mut slots: Vec<Slot> = (0..n).map(|_| Slot::Keep).collect();
        let mut assigned = vec![false; n];
        for (idxs, step) in subs_verified {
            if idxs.is_empty() || idxs.iter().any(|&i| i >= n || assigned[i]) {
                continue;
            }
            if !idxs.windows(2).all(|w| w[1] == w[0] + 1) {
                continue;
            }
            slots[idxs[0]] = Slot::Insert(step.clone());
            for &i in &idxs[1..] {
                slots[i] = Slot::Drop;
            }
            for &i in idxs {
                assigned[i] = true;
            }
        }
        for idxs in removals {
            for &i in idxs {
                if i < n && !assigned[i] {
                    slots[i] = Slot::Drop;
                    assigned[i] = true;
                }
            }
        }
        let mut out = Vec::new();
        for (i, slot) in slots.into_iter().enumerate() {
            match slot {
                Slot::Keep => out.push(original[i].clone()),
                Slot::Drop => {}
                Slot::Insert(s) => out.push(s),
            }
        }
        explorer::prune_navigates_before_api_only(&mut out);
        out
    }

    #[test]
    fn assemble_folds_login_and_prunes_but_keeps_entry_nav() {
        // Verified login_post replaces fill+fill+click (indices 1..=3); extract kept.
        let original = wf_steps();
        let login = json!({ "type": "login_post", "enabled": true, "config": { "url": "https://x.com/api/login", "method": "POST" } });
        let out = apply_slots(&original, &[(vec![1, 2, 3], login.clone())], &[]);
        let types: Vec<&str> = out.iter().map(|s| s.get("type").and_then(|t| t.as_str()).unwrap()).collect();
        assert_eq!(types, vec!["navigate", "login_post", "extract"], "fold login block, keep entry nav + extract");
    }

    #[test]
    fn assemble_skips_overlapping_and_out_of_range_substitutions() {
        let original = wf_steps();
        let step = json!({ "type": "api_call", "enabled": true, "config": { "url": "https://x/api" } });
        // Second sub overlaps index 3 with the first → dropped; third is out of range → dropped.
        let out = apply_slots(
            &original,
            &[(vec![3], step.clone()), (vec![3, 4], step.clone()), (vec![99], step.clone())],
            &[],
        );
        // Only the first (index 3) applied: navigate, fill, fill, api_call, extract.
        let types: Vec<&str> = out.iter().map(|s| s.get("type").and_then(|t| t.as_str()).unwrap()).collect();
        assert_eq!(types, vec!["navigate", "fill", "fill", "api_call", "extract"]);
    }
}
