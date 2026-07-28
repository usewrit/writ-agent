//! Transport-neutral ephemeral agent-action executor.
//!
//! Executes AI-driven action(s) on a live page WITHOUT recording workflow steps, then builds a
//! compact next-decision observation. Extracted verbatim out of the cloud `bridge/saas_bridge.rs`
//! so both the cloud recorder AND the local AI-assist recording session drive the SAME executor —
//! the page-execution + observation contract must match exactly. Its dependencies are all neutral
//! (`crate::ai::action_executor`, `crate::browser::*`, `crate::security::url_guard`,
//! `crate::bridge::otp_entry`, `crate::dom::analyzer`), so this module carries NO cloud coupling
//! and stays in the KEEP set (compiles under `local,fleet`).

use std::collections::HashMap;

/// PageEvaluator adapter so the DOM analyzer can run against a live page.
/// Mirrors the private adapter in ai/intelligent_mode.rs.
struct AgentPageEvaluator<'a>(&'a playwright_rs::Page);

impl<'a> crate::dom::analyzer::PageEvaluator for AgentPageEvaluator<'a> {
    fn evaluate_json(
        &self,
        js: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<serde_json::Value>> + Send + '_>> {
        let js = js.to_string();
        Box::pin(async move {
            let result: serde_json::Value = self.0.evaluate(&js, None::<&()>).await
                .map_err(|e| anyhow::anyhow!("evaluate_json failed: {}", e))?;
            Ok(result)
        })
    }

    fn evaluate_json_with_args(
        &self,
        js: &str,
        args: &[serde_json::Value],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<serde_json::Value>> + Send + '_>> {
        let js = js.to_string();
        let args = serde_json::Value::Array(args.to_vec());
        Box::pin(async move {
            let result: serde_json::Value = self.0.evaluate(&js, Some(&args)).await
                .map_err(|e| anyhow::anyhow!("evaluate_json_with_args failed: {}", e))?;
            Ok(result)
        })
    }
}

/// Execute AI-driven action(s) on the live page WITHOUT recording workflow steps.
/// Accepts a batch via `actions: [...]`, a nested `action: {...}`, or a flat
/// `action: "click"` with sibling params. Returns (results, observation).
/// The page is already cloned out of the session — this fn never touches the
/// DashMap, so it holds no lock across its `.await`s.
// `pub` (re-exported at `crate::automation::run_agent_actions`) so BOTH the cloud recorder and the
// local daemon's recording session drive the SAME ephemeral agent-action executor — the local
// AI-assist brain runs the decision loop on the user's own provider, but the page-execution +
// observation contract must match exactly.
pub async fn run_agent_actions(
    page: &playwright_rs::Page,
    msg: &serde_json::Value,
    read_only: bool,
) -> (Vec<serde_json::Value>, serde_json::Value) {
    // Normalize incoming shapes into a list of action objects.
    let mut actions: Vec<serde_json::Value> = Vec::new();
    if let Some(arr) = msg.get("actions").and_then(|v| v.as_array()) {
        actions = arr.iter().filter(|a| a.is_object()).cloned().collect();
    } else {
        match msg.get("action") {
            Some(a @ serde_json::Value::Object(_)) => actions.push(a.clone()),
            Some(serde_json::Value::String(a)) => {
                // Flat form: lift sibling params into a single action object.
                let mut flat = serde_json::Map::new();
                if let Some(obj) = msg.as_object() {
                    for (k, v) in obj {
                        if k != "type" && k != "request_id" && k != "actions" {
                            flat.insert(k.clone(), v.clone());
                        }
                    }
                }
                flat.insert("action".to_string(), serde_json::Value::String(a.clone()));
                actions.push(serde_json::Value::Object(flat));
            }
            _ => {}
        }
    }

    // Pure observation request (model just wants fresh page context).
    if actions.is_empty() {
        return (Vec::new(), safe_observation(page, None).await);
    }

    // Initial DOM state (fields/buttons with coordinates) for index/coord actions.
    let mut dom_state: serde_json::Value = safe_dom_state(page).await;

    // RELIABILITY (mirrors the Python recorder): the runner waits
    // _AGENT_ACTION_TIMEOUT (120s) for agent_action_result, so we MUST return a
    // (possibly partial) batch BEFORE then — a runner-side timeout yields NO result
    // at all. Bound the whole batch and every individual action.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs_f64(BATCH_BUDGET);

    let mut results: Vec<serde_json::Value> = Vec::new();
    for act in actions.iter().take(25) {
        let atype = act.get("action").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
        let label = if atype.is_empty() { "(missing)".to_string() } else { atype.clone() };

        // Out of overall budget → report remaining actions as skipped.
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            results.push(serde_json::json!(
                {"action": label, "success": false, "error": "skipped: batch time budget exhausted"}));
            continue;
        }

        // Per-action hard budget, clamped to the time left so one action can't eat
        // the rest. A single hang (navigation that never settles, detached context,
        // missing selector) can NEVER wedge the batch — it becomes a timeout result.
        let budget = action_budget(act)
            .min(remaining)
            .max(std::time::Duration::from_secs(1));
        let res = match tokio::time::timeout(budget, run_one_agent_action(page, act, &dom_state, read_only)).await {
            Ok(v) => v,
            Err(_) => serde_json::json!({
                "action": label, "success": false,
                "error": format!("action timed out after {:.0}s", budget.as_secs_f64()),
            }),
        };
        results.push(res);

        // After a potentially page-changing action, settle deterministically then
        // refresh the DOM snapshot for the NEXT action's selectors.
        if matches!(
            atype.as_str(),
            "click" | "check" | "submit" | "navigate" | "press_key"
                | "scroll" | "back" | "evaluate_js" | "select" | "fill" | "type_text" | "type"
        ) {
            let navigated = matches!(
                atype.as_str(),
                "click" | "submit" | "navigate" | "press_key" | "back"
            );
            settle_page(page, navigated).await;
            dom_state = safe_dom_state(page).await;
        }
    }

    let observation = safe_observation(page, Some(&dom_state)).await;
    (results, observation)
}

/// Wall-clock ceiling for one agent_action batch. Kept comfortably under the
/// runner's _AGENT_ACTION_TIMEOUT (120s) with room for the final observation.
const BATCH_BUDGET: f64 = 95.0;

lazy_static::lazy_static! {
    /// Side-effecting JS patterns blocked by the read-only evaluate_js guard for
    /// autonomous AI sessions. Mirrors the Python recorder `_JS_WRITE_PATTERNS`.
    /// NOTE: the `regex` crate has no look-around, so assignment guards use
    /// `=(?:[^=]|$)` (an `=` NOT followed by another `=`) to skip ==/===/!=.
    static ref JS_WRITE_RE: Vec<(regex::Regex, &'static str)> = {
        let pats: &[(&str, &str)] = &[
            (r"\.click\s*\(", "DOM click()"),
            (r"\.submit\s*\(", "form submit()"),
            (r"\.dispatchEvent\s*\(", "dispatchEvent()"),
            (r"\.value\s*=(?:[^=]|$)", "writing .value"),
            (r"\.checked\s*=(?:[^=]|$)", "writing .checked"),
            (r"\.selected\s*=(?:[^=]|$)", "writing .selected"),
            (r"\.innerHTML\s*=(?:[^=]|$)", "writing .innerHTML"),
            (r"\.outerHTML\s*=(?:[^=]|$)", "writing .outerHTML"),
            (r"\.innerText\s*=(?:[^=]|$)", "writing .innerText"),
            (r"\.textContent\s*=(?:[^=]|$)", "writing .textContent"),
            (r"\.setAttribute\s*\(", "setAttribute()"),
            (r"\.removeAttribute\s*\(", "removeAttribute()"),
            (r"\.(?:append|prepend|before|after|replaceChildren|replaceWith|remove)\s*\(", "DOM tree mutation"),
            (r"\.(?:appendChild|removeChild|insertBefore|replaceChild)\s*\(", "DOM tree mutation"),
            (r"\bWebSocket\b", "WebSocket"),
            (r"\bEventSource\b", "EventSource"),
            (r"\bwindow\.open\s*\(", "window.open()"),
            (r"\blocation\s*=(?:[^=]|$)", "location assignment"),
            (r"\blocation\.(?:href|assign|replace|reload)\b", "navigation via location"),
            (r"\bhistory\.(?:pushState|replaceState|go|back|forward)\b", "history navigation"),
            (r"\b(?:localStorage|sessionStorage)\.(?:setItem|removeItem|clear)\b", "storage write"),
            (r"document\.cookie\s*=(?:[^=]|$)", "cookie write"),
            (r"\beval\s*\(", "eval()"),
            (r"\bnew\s+Function\b", "Function constructor"),
            (r"\bimport\s*\(", "dynamic import()"),
        ];
        pats.iter().map(|(p, w)| (regex::Regex::new(p).unwrap(), *w)).collect()
    };
}

/// Return a reason if `script` would mutate the page, navigate, hit the network, or
/// write storage — i.e. is NOT read-only. None for read-only scripts. Heuristic by
/// design; a false-positive just nudges the brain to use the structured action.
fn js_write_violation(script: &str) -> Option<&'static str> {
    if script.is_empty() {
        return None;
    }
    for (rx, why) in JS_WRITE_RE.iter() {
        if rx.is_match(script) {
            return Some(why);
        }
    }
    None
}

/// Per-action hard timeout. Generous for real page work, tight enough that a stuck
/// action can't outlive the runner. `wait` is bounded by its own requested duration.
fn action_budget(act: &serde_json::Value) -> std::time::Duration {
    use std::time::Duration;
    let atype = act.get("action").and_then(|v| v.as_str()).unwrap_or("").trim();
    match atype {
        "wait" => {
            let s = act.get("seconds").and_then(|v| v.as_f64()).unwrap_or(1.0).clamp(0.0, 10.0);
            Duration::from_secs_f64(s + 5.0)
        }
        "navigate" | "back" => Duration::from_secs(35), // full document load
        "click" | "submit" | "press_key" => Duration::from_secs(20),
        "get_screenshot" => Duration::from_secs(20),
        _ => Duration::from_secs(15), // fill/type/select/check/read/evaluate/etc.
    }
}

/// Deterministically let the page settle after a mutating action, fully bounded so
/// it can never hang. Navigating actions wait for the new document; all allow a
/// brief network-quiet window so SPA/XHR re-renders land before the next selector.
async fn settle_page(page: &playwright_rs::Page, navigated: bool) {
    use std::time::Duration;
    if navigated {
        let _ = tokio::time::timeout(
            Duration::from_secs(8),
            crate::browser::navigation::wait_for_load_state(page, "domcontentloaded", Duration::from_secs(8)),
        )
        .await;
    }
    // networkidle can stall on long-poll/streaming pages, so keep it short and
    // treat a timeout as "settled enough".
    let _ = tokio::time::timeout(
        Duration::from_millis(2500),
        crate::browser::navigation::wait_for_load_state(page, "networkidle", Duration::from_millis(2500)),
    )
    .await;
}

/// DOM field/button snapshot, bounded — never hangs on a navigating page.
async fn safe_dom_state(page: &playwright_rs::Page) -> serde_json::Value {
    match tokio::time::timeout(
        std::time::Duration::from_secs(8),
        crate::browser::page_query::evaluate(page, crate::ai::action_executor::DOM_FIELDS_WITH_COORDS_JS),
    )
    .await
    {
        Ok(Ok(v)) => v,
        _ => serde_json::json!({"fields": [], "buttons": []}),
    }
}

/// Build the next-decision observation under a hard cap. Every page.evaluate inside
/// auto-waits for navigation and could otherwise hang; on timeout return a minimal
/// observation so the agent still gets a reply and can re-observe.
async fn safe_observation(
    page: &playwright_rs::Page,
    dom_state: Option<&serde_json::Value>,
) -> serde_json::Value {
    match tokio::time::timeout(
        std::time::Duration::from_secs(12),
        build_agent_observation(page, dom_state),
    )
    .await
    {
        Ok(v) => v,
        Err(_) => serde_json::json!({
            "current_url": page.url(),
            "fields": [], "buttons": [], "page_text": "", "errors": [],
            "a11y": {"viewport": {}, "elements": []},
        }),
    }
}

/// Execute one ephemeral action. Prefers selector / JS / navigation for full
/// browser control; falls back to the intelligent-mode executor for
/// field_index / coordinate based actions. Never records a workflow step.
async fn run_one_agent_action(
    page: &playwright_rs::Page,
    act: &serde_json::Value,
    dom_state: &serde_json::Value,
    read_only: bool,
) -> serde_json::Value {
    use crate::browser::{navigation, page_actions, page_query};
    use std::time::Duration;

    let atype = act
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let selector = act.get("selector").and_then(|v| v.as_str());

    let result: anyhow::Result<serde_json::Value> = async {
        match atype.as_str() {
            "navigate" => {
                let url = act.get("url").and_then(|v| v.as_str())
                    .or_else(|| act.get("value").and_then(|v| v.as_str()));
                let url = match url {
                    Some(u) => u,
                    None => return Ok(serde_json::json!(
                        {"action": atype, "success": false, "error": "navigate requires url"})),
                };
                // SSRF guard (fail-CLOSED): the cloud drives this navigation, so vet the target before
                // `goto` — a malicious/compromised dispatcher must not reach loopback/metadata/LAN.
                if !crate::security::url_guard::is_navigation_url_safe_async(url).await {
                    return Ok(serde_json::json!(
                        {"action": atype, "success": false, "error": "navigate blocked: unsafe URL"}));
                }
                navigation::goto(page, url, "domcontentloaded", Duration::from_secs(30)).await?;
                Ok(serde_json::json!({"action": atype, "success": true, "url": page.url()}))
            }
            "back" => {
                // `false` = no history entry. Report it so the AI sees a refused
                // action and picks another move instead of looping on a no-op it
                // was told succeeded.
                let moved = navigation::go_back(page, Duration::from_secs(30)).await?;
                Ok(serde_json::json!({
                    "action": atype,
                    "success": moved,
                    "url": page.url(),
                    "error": if moved { serde_json::Value::Null } else { serde_json::json!("no history entry to go back to") },
                }))
            }
            "twofa_enter" => {
                // Runner-internal: the 2FA code was minted SERVER-SIDE and handed to
                // us here. Enter it via the shared robust OTP JS (single/segmented/
                // contenteditable/paste). NEVER echo the code — only {ok, kind, filled}.
                // Its own action arm, so the evaluate_js read-only guard never applies.
                let code = act.get("code").and_then(|v| v.as_str()).unwrap_or("");
                let kind = act.get("kind").and_then(|v| v.as_str()).unwrap_or("code");
                let mut sel = act.get("selector").and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty()).map(|s| s.to_string());
                let submit = act.get("submit_selector").and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty()).map(|s| s.to_string());
                if kind == "magic_link" {
                    // Fail-CLOSED: a magic link is a navigation target driven by the cloud.
                    if !crate::security::url_guard::is_navigation_url_safe_async(code).await {
                        return Ok(serde_json::json!({"action": atype, "success": false,
                            "error": "magic-link blocked: unsafe URL"}));
                    }
                    navigation::goto(page, code, "domcontentloaded", Duration::from_secs(30)).await?;
                    return Ok(serde_json::json!({"action": atype, "success": true, "ok": true, "kind": "magic_link"}));
                }
                let mut detected_submit: Option<String> = None;
                if sel.is_none() {
                    if let Ok(det) = page_query::evaluate::<serde_json::Value>(
                        page, &crate::bridge::otp_entry::detect_invocation()).await
                    {
                        sel = det.get("selector").and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty()).map(|s| s.to_string());
                        detected_submit = det.get("submit_selector").and_then(|v| v.as_str()).map(|s| s.to_string());
                    }
                }
                let entry_js = crate::bridge::otp_entry::entry_invocation(code, sel.as_deref());
                let res: serde_json::Value = page_query::evaluate(page, &entry_js).await
                    .unwrap_or_else(|_| serde_json::json!({"ok": false}));
                let ok = res.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
                let res_kind = res.get("kind").and_then(|v| v.as_str()).unwrap_or(kind).to_string();
                let filled = res.get("filled").and_then(|v| v.as_i64()).unwrap_or(0);
                if let Some(submit) = submit.or(detected_submit) {
                    let _ = page_actions::click_selector(page, &submit, false).await;
                }
                Ok(serde_json::json!({"action": atype, "success": ok, "ok": ok, "kind": res_kind, "filled": filled}))
            }
            "evaluate_js" => {
                let script = act.get("script").and_then(|v| v.as_str())
                    .or_else(|| act.get("value").and_then(|v| v.as_str()))
                    .unwrap_or("");
                // READ-ONLY guard for autonomous AI sessions: inspect the DOM freely
                // but reject any script that mutates the page, clicks, navigates,
                // hits the network, or writes storage. Interaction must use the
                // structured fill/click/... actions (which substitute {{secret:}} and
                // get recorded). Interactive scraper-builder (read_only=false) keeps
                // full raw JS. Mirrors the Python recorder _js_write_violation gate.
                if read_only {
                    if let Some(why) = js_write_violation(script) {
                        return Ok(serde_json::json!({
                            "action": atype, "success": false,
                            "error": format!(
                                "evaluate_js is READ-ONLY in AI sessions: {}. Use the structured \
                                 actions (fill/click/select/press_key/...) to interact with the page.",
                                why),
                        }));
                    }
                }
                // page.evaluate accepts an expression. Function bodies (with `return`)
                // are wrapped in an IIFE; expression/IIFE forms run as-is.
                let s = script.trim();
                let expr = if s.starts_with('(') {
                    script.to_string()
                } else if script.contains("return") {
                    format!("(() => {{ {} }})()", script)
                } else {
                    script.to_string()
                };
                let eval_result: serde_json::Value = page_query::evaluate(page, &expr).await?;
                Ok(serde_json::json!({"action": atype, "success": true, "eval_result": eval_result}))
            }
            "click" | "check" if selector.is_some() => {
                page_actions::click_selector(page, selector.unwrap(), false).await?;
                Ok(serde_json::json!({"action": atype, "success": true, "selector": selector}))
            }
            "fill" | "type_text" if selector.is_some() => {
                let value = act.get("value").and_then(|v| v.as_str()).unwrap_or("");
                page_actions::fill(page, selector.unwrap(), value).await?;
                Ok(serde_json::json!({"action": atype, "success": true, "selector": selector}))
            }
            "select" if selector.is_some() => {
                let value = act.get("value").and_then(|v| v.as_str()).unwrap_or("");
                page_actions::select_option(page, selector.unwrap(), value).await?;
                Ok(serde_json::json!({"action": atype, "success": true, "selector": selector}))
            }
            "press_key" => {
                let key = act.get("key").and_then(|v| v.as_str()).unwrap_or("Enter");
                page_actions::keyboard_press(page, key).await?;
                Ok(serde_json::json!({"action": atype, "success": true}))
            }
            "scroll" => {
                let direction = act.get("direction").and_then(|v| v.as_str()).unwrap_or("down");
                let amount = act.get("amount").and_then(|v| v.as_f64()).unwrap_or(600.0);
                let delta_y = if direction == "up" { -amount } else { amount };
                page_actions::mouse_wheel(page, 0.0, delta_y).await?;
                Ok(serde_json::json!({"action": atype, "success": true}))
            }
            "wait" => {
                let seconds = act.get("seconds").and_then(|v| v.as_f64()).unwrap_or(1.0).min(10.0);
                tokio::time::sleep(Duration::from_secs_f64(seconds.max(0.0))).await;
                Ok(serde_json::json!({"action": atype, "success": true}))
            }
            "read_text" | "get_text" => {
                let txt = if let Some(sel) = selector {
                    page_query::locator_text_content(page, sel).await.ok().flatten().unwrap_or_default()
                } else {
                    page_query::evaluate::<serde_json::Value>(
                        page,
                        "() => document.body ? document.body.innerText : ''",
                    )
                    .await
                    .ok()
                    .and_then(|v| v.as_str().map(|s| s.to_string()))
                    .unwrap_or_default()
                };
                let txt: String = txt.chars().take(4000).collect();
                Ok(serde_json::json!({"action": atype, "success": true, "text": txt}))
            }
            // Fall back to the intelligent-mode executor (field_index / coordinates /
            // inspect_field / hover / submit / etc.). It returns a result without
            // recording a step.
            _ => {
                let fill_data: HashMap<String, String> = act
                    .get("fill_data")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();
                let r = crate::ai::action_executor::execute_and_verify_action(
                    page, act, &fill_data, dom_state,
                )
                .await;
                let mut obj = serde_json::Map::new();
                obj.insert("action".to_string(), serde_json::Value::String(atype.clone()));
                obj.insert("success".to_string(), serde_json::Value::Bool(r.success));
                if let Some(err) = &r.error {
                    obj.insert("error".to_string(), serde_json::Value::String(err.clone()));
                }
                if let Some(ep) = &r.endpoint {
                    obj.insert("endpoint".to_string(), ep.clone());
                }
                if let Some(actual) = &r.verification.actual {
                    obj.insert("result".to_string(), serde_json::Value::String(actual.clone()));
                }
                Ok(serde_json::Value::Object(obj))
            }
        }
    }
    .await;

    match result {
        Ok(v) => v,
        Err(e) => {
            let msg: String = e.to_string().chars().take(300).collect();
            serde_json::json!({"action": atype, "success": false, "error": msg})
        }
    }
}

/// Compact page context for the AI's next scraper-building decision.
/// Mirrors Python _build_agent_observation.
async fn build_agent_observation(
    page: &playwright_rs::Page,
    dom_state: Option<&serde_json::Value>,
) -> serde_json::Value {
    // Reuse provided DOM state or fetch fresh.
    let owned;
    let dom_state: &serde_json::Value = match dom_state {
        Some(d) => d,
        None => {
            owned = crate::browser::page_query::evaluate(
                page,
                crate::ai::action_executor::DOM_FIELDS_WITH_COORDS_JS,
            )
            .await
            .unwrap_or_else(|_| serde_json::json!({"fields": [], "buttons": []}));
            &owned
        }
    };

    // Page text + validation errors via the DOM analyzer.
    let mut page_text = String::new();
    let mut errors: Vec<serde_json::Value> = Vec::new();
    {
        let evaluator = AgentPageEvaluator(page);
        if let Ok(ctx) = crate::dom::analyzer::extract_page_context(&evaluator).await {
            if let Ok(val) = serde_json::to_value(&ctx) {
                if let Some(pt) = val.get("pageText").and_then(|v| v.as_array()) {
                    let joined: Vec<String> = pt
                        .iter()
                        .map(|t| {
                            if let Some(s) = t.as_str() {
                                s.to_string()
                            } else if let Some(s) = t.get("text").and_then(|v| v.as_str()) {
                                s.to_string()
                            } else {
                                t.to_string()
                            }
                        })
                        .collect();
                    page_text = joined.join("\n").chars().take(3000).collect();
                }
                if let Some(errs) = val.get("errors").and_then(|v| v.as_array()) {
                    errors = errs.iter().take(10).cloned().collect();
                }
            }
        }
    }

    let fields: Vec<serde_json::Value> = dom_state
        .get("fields")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .take(40)
                .map(|f| {
                    serde_json::json!({
                        "index": f.get("index"),
                        "type": f.get("type"),
                        "label": f.get("label"),
                        "selector": f.get("selector"),
                        "value": f.get("value"),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let buttons: Vec<serde_json::Value> = dom_state
        .get("buttons")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .take(40)
                .enumerate()
                .map(|(i, b)| {
                    serde_json::json!({
                        "index": i,
                        "text": b.get("text"),
                        "selector": b.get("selector"),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    // Accessibility tree + viewport (coordinates) — the brain reads obs["a11y"]
    // for viewport + a11y_elements. Keep in lockstep with Python _build_a11y_tree.
    let a11y = crate::browser::page_query::evaluate(
        page,
        crate::ai::action_executor::A11Y_TREE_JS,
    )
    .await
    .unwrap_or_else(|_| serde_json::json!({"viewport": {}, "elements": []}));

    serde_json::json!({
        "current_url": page.url(),
        "fields": fields,
        "buttons": buttons,
        "page_text": page_text,
        "errors": errors,
        "a11y": a11y,
    })
}
