//! General web-agent loop for the concierge build — the desktop port of the cloud
//! `agent_brain` + `AISessionRunner` pattern. Where [`super::session::run_session`] is a
//! single-page FORM-FILLER (stateless per turn, fill/click/submit only), this loop is a real
//! AGENT: it carries a conversation thread across turns, sees the page's LINKS (so navigation
//! is grounded in what actually exists), navigates between pages, fills forms (secrets as
//! `{{key}}` placeholders resolved only at execution), probes with read-only JS, and finishes
//! by proposing data DELIVERABLES that are VERIFIED against the live page before acceptance —
//! an empty extraction is fed back as an error to adapt from, never accepted on faith, and
//! exhausted retries end in an HONEST failure (`stuck`), never a fake `complete`.
//!
//! Every executed structured interaction (navigate/fill/click/select/press/scroll/wait) is
//! recorded as a replayable workflow step; probes (read_text/evaluate_js) are not. Recorded
//! fill values keep their `{{key}}` template so credentials never bake into the workflow
//! (`value_resolver` re-resolves at replay — the recorder convention).

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use playwright_rs::Page;
use serde_json::{json, Value};
use sqlx::sqlite::SqlitePool;
use tokio::sync::Mutex;

use crate::automation::network_capture::NetworkCapture;
use crate::browser::{navigation, page_actions, page_query};
use crate::dom::analyzer::PageEvaluator;
use crate::local::ai::observation::build_ai_observation;
use crate::local::ai::provider::{self, AiConfig};
use crate::local::ai::session::{
    report_step, SessionConfig, SessionResult, SessionStatus, StepSink,
};
use crate::local::error::LocalResult;

/// How many `done` submissions with unverified deliverables we bounce back with feedback
/// before settling honestly (partial acceptance if anything verified, else `stuck`).
const MAX_VERIFY_REJECTS: u32 = 2;
/// Consecutive unparseable model replies tolerated before the run errors out.
const MAX_PARSE_RETRIES: u32 = 2;
/// Consecutive all-actions-failed turns tolerated before the run is declared stuck.
const MAX_ACTION_FAILURE_STREAK: u32 = 5;
/// Identical (url, decision) turns before the loop is declared stuck.
const STALL_LIMIT: u32 = 4;
/// Cap on actions executed from one `do` batch. Raised to 8 so the model can fold a whole
/// known-selector sequence (fill several fields + submit, or a click→wait→click flow) into ONE turn
/// instead of a turn each — every turn saved avoids re-sending the system prompt + the full DOM. A
/// probe (inspect/list_candidates/…) in a batch still defers any later define/extract/api_call in the
/// same batch, since the probe's result isn't available until the next observation.
const MAX_BATCH_ACTIONS: usize = 8;
/// Cap on the cleaned DOM (chars) sent each turn. Large enough to carry a real list page's structure
/// (rows + classes), bounded so a giant dashboard can't blow the model's context window.
const MAX_DOM_CHARS: usize = 24000;

/// In-page DOM collapse: run on a CLONE of the live, rendered DOM (post-hydration — so it works on any
/// framework: React/Vue/Angular/web-components/server-rendered alike, seeing the REAL structure), fold
/// each run of ≥`MIN` consecutive siblings that share the same tag+class into the first `KEEP` REAL
/// elements + a visible marker. The model still sees the real repeating element (its real tags/classes)
/// to write `querySelectorAll` against — just not hundreds of identical copies. It NEVER mutates the
/// live page (works on a clone), so replay is unaffected: the recorded selector matches the FULL DOM at
/// run time. Returns the collapsed `documentElement.outerHTML`, or the uncollapsed HTML on any error.
const COLLAPSE_DOM_JS: &str = r#"(() => {
  try {
    const KEEP = 4, MIN = 8;
    const sig = (el) => el.tagName + '|' + ((el.getAttribute && el.getAttribute('class')) || '');
    const walk = (node) => {
      const kids = [];
      for (let c = node.firstElementChild; c; c = c.nextElementSibling) kids.push(c);
      let i = 0;
      while (i < kids.length) {
        const s = sig(kids[i]);
        let j = i + 1;
        while (j < kids.length && sig(kids[j]) === s) j++;
        const count = j - i;
        if (count >= MIN) {
          for (let k = i + KEEP; k < j; k++) { try { kids[k].remove(); } catch (e) {} }
          const tag = kids[i].tagName.toLowerCase();
          const marker = document.createElement('span');
          marker.setAttribute('data-collapsed', String(count - KEEP));
          marker.textContent = '…+' + (count - KEEP) + ' more <' + tag + '> siblings, same structure…';
          const anchor = kids[i + KEEP - 1];
          if (anchor && anchor.parentNode) anchor.after(marker);
          for (let k = i; k < i + KEEP && k < j; k++) walk(kids[k]);
        } else {
          for (let k = i; k < j; k++) walk(kids[k]);
        }
        i = j;
      }
    };
    const clone = document.documentElement.cloneNode(true);
    walk(clone);
    return clone.outerHTML;
  } catch (e) {
    return document.documentElement.outerHTML;
  }
})()"#;
/// Failed attempts on the SAME function name before we stop letting the agent re-emit it — re-trying
/// selector variants for one capability forever is the classic thrash (the /workflows redefine loop).
const MAX_DEFINE_FAILS: u32 = 4;
// The stall/convergence floors below are deliberately GENEROUS: the agent now has a real inspection
// toolkit (list_candidates, inspect, find_text, get_attributes, page_outline, list_frames,
// list_requests, get_request, wait_for), so a correct extraction legitimately takes several PROBE
// turns that produce no deliverable yet. These count barren turns PER PAGE (a new page resets them),
// so raising them lets the agent explore a page thoroughly without a premature stop, while a genuine
// no-progress loop on ONE page still ends.
/// Barren turns (no NEW deliverable, same page) before we START nudging the agent to finish.
const STAGNANT_NUDGE_AT: u32 = 6;
/// Barren turns on the same page, WITH data already built, before we FORCE-finish (converge).
const STAGNANT_FORCE_AT: u32 = 10;
/// Turns with NO new deliverable at all before we stop — the absolute backstop against running to
/// max_steps. Per-page (a new page resets it), so it only fires on a real dead loop.
const BARREN_STUCK_AT: u32 = 18;

/// System prompt — the agent's contract. One JSON per turn; grounded actions only; deliverables
/// verified live; truth over claims.
const EXPLORER_SYSTEM: &str = r##"You are an autonomous WEB AGENT driving a real browser to accomplish a GOAL end to end, while RECORDING a reusable workflow of what you actually do. You work in a loop: each turn you receive the current page — the CLEANED LIVE DOM (real HTML: tags, classes, ids, attributes — scripts/styles/svg/base64 stripped), the form fields, buttons, LINKS, and captured backend API calls — plus the running history of your prior decisions and their REAL results. You do NOT get a screenshot every turn: the cleaned DOM is the source of truth for selectors. When you genuinely need to SEE the rendered page (a visual layout, a chart, which control is highlighted), emit a `screenshot` action and the image rides along with your NEXT observation. Reply with EXACTLY ONE JSON object per turn — no prose, no markdown fences.

YOU HAVE REAL INSPECTION TOOLS — USE THEM. You are NOT limited to what's summarized: you can inspect any part of the page, search it, and read backend responses. To extract data you have not seen before, DON'T GUESS a selector — probe first. The reliable loop for any list/table is: list_candidates (find the repeating row) → inspect that row (see its inner fields) → define_function fn_type:"list" (row_selector + field map; we generate + live-test the JS). Probing before you extract is DILIGENCE, not oscillation — the anti-repeat rules only forbid re-doing something that ALREADY returned real data. A blind define that fails, then another blind define, is the failure mode; one probe then one correct define is the target.
ONE BATCH = probe OR define, never both: a probe's result reaches you NEXT turn, so a define_function/extract/api_call placed after a probe in the same "do" batch is written blind — it is DEFERRED, not run. Probe this turn, read the result, define next turn.

Decide ONE of:
{"action":"act","thought":"<why, short>","do":[ ...1-8 browser actions, run in order... ]}
   BATCH aggressively: when you already know the selectors, put the whole sequence in ONE "do" — e.g. fill every login field + click submit, or fill a filter + click apply. Fewer turns is cheaper and faster. (One caveat: if a step in the batch DEPENDS on seeing the result of a probe/inspect earlier in the SAME batch, split it — the probe's result only arrives next turn.)
{"action":"ask","thought":"...","message":"<ONE-sentence question for the user>","credential_fields":[{"field":"login_key","label":"API key","secret":true}]}
{"action":"done","thought":"...","summary":"<one line>","deliverables":[ ...extract/evaluate specs... ]}

Browser actions for "do" (selector-based; they EXECUTE now and are RECORDED as replayable workflow steps):
- {"type":"navigate","url":"https://... or /path"}        (go to a page; use the LINKS list or a path you can see)
- {"type":"fill","selector":"css","value":"text or {{key}}"}
- {"type":"click","selector":"css","text":"<visible label>"}   (text is the FALLBACK: if the selector misses, the click retries by visible text — always include it when the element has one)
- {"type":"select","selector":"css","value":"option"}
- {"type":"press","key":"Enter"}
- {"type":"scroll","direction":"down","amount":800}
- {"type":"hover","selector":"css"}   (reveal a hover-only menu/tooltip)
- {"type":"upload","selector":"input[type=file]","mode":"input","file_slot":"resume"}   (declare a file upload: records a step with a per-run slot the user fills with a vault file at run time. mode "input" = selector IS the file input; "chooser" = selector is a button that opens the file dialog. Use this when the goal needs uploading a file.)
- {"type":"wait_for_download","trigger_selector":"css","output_key":"report"}   (capture a file the page downloads INTO the vault — records a step that clicks the trigger, waits for the download, and stores it as {{output_key}}. Omit trigger_selector if the previous step already starts the download.)
- {"type":"switch_tab","tab_index":N}   (make one of YOUR tabs active — index from list_tabs, or omit to jump to the NEWEST; records the switch so replay follows. A click that opens a new tab switches you automatically — use this only to go BACK to a previous tab.)
- {"type":"wait","seconds":1.5}   (or {"type":"wait","ms":1500} — same thing)
- {"type":"wait_for","selector":"css"}   (wait until an element appears — for a list/table that loads late; RECORDS a wait step so the replay also waits for it before extracting. Use this before an extraction when the data renders after the page settles.)
DATA EXTRACTION in "do" (runs on the CURRENT page NOW, is verified immediately — recorded at THIS position in the workflow ONLY if it returned real data; you see the actual result next turn):
- {"type":"extract","selector":"css","variable":"name"}                        (one element's text)
- {"type":"extract","selector":"<row selector>","fields":{"title":".name","price":".price"},"variable":"name"}   (a list WITHOUT writing JS: one row per element matching selector, each field read from a sub-selector scoped to that row. Use "." for the row element itself. Optional "limit" (default 100). Replays with the same shape.)
- {"type":"evaluate","script":"<JS returning a NON-EMPTY array/object>","variable":"name"}   (a list/table needing logic the fields form can't express)
Read-only PROBES (execute now, NOT recorded — results appear in your next turn; use them to check data exists before extracting):
- {"type":"list_candidates"}   (AUTO-DETECT the repeating rows on the page — same-tag+class elements appearing 3+ times, ranked, with a text sample. START HERE for any list/table extraction to get the row selector.)
- {"type":"inspect","selector":"css"}   (how many elements match + the cleaned outerHTML of the first few — confirm a row selector and see a row's inner fields before you define an extraction)
- {"type":"find_text","text":"a value you can see"}   (find which elements' own text contains a value — returns each element's suggested selector; locate a row/cell when you know a value but not its selector)
- {"type":"get_attributes","selector":"css"}   (href / data-* / id / aria-* of the first few matches — pull per-row links or ids the visible text doesn't show)
- {"type":"read_text","selector":"css"}   (the text content of ONE element)
- {"type":"page_outline"}   (a structural map — headings + the main/list/table containers with their selectors + child counts; orient here on an unfamiliar page)
- {"type":"list_frames"}   (the page's iframes — data inside one needs the iframe, a plain selector won't reach it)
- {"type":"list_tabs"}   (YOUR open tabs in this session — index, url, title, which is ACTIVE; only your own tabs, never other windows)
- {"type":"list_files"}   (the user's file VAULT — what can be uploaded; an upload declares a slot the user fills at run time, so you don't need a specific file to build the step)
- {"type":"screenshot"}   (ON-DEMAND VISION — capture a JPEG of the current page; it arrives with your NEXT observation. You do NOT get a screenshot automatically, so use this when the cleaned DOM can't answer a VISUAL question — a rendered chart/layout, which control looks active. For finding selectors, prefer list_candidates/inspect over a screenshot.)
- {"type":"evaluate_js","script":"<read-only JS expression returning JSON>"}
- {"type":"capture_network"}   (reload the page and return its BACKEND API calls — method/url/status/JSON payloads; use this to DISCOVER the JSON endpoint behind a list/table)
- {"type":"list_requests","url":"<optional substring>","method":"<optional>"}   (search the captured calls to FIND the endpoint that returns the data you want)
- {"type":"get_request","url":"<substring of the endpoint>"}   (the FULL detail of one captured call — method, status, request headers/body, and the WHOLE response body — read this to learn the exact JSON shape before building an api_call)
CALL THE BACKEND API (preferred over DOM scraping when the data comes from a JSON endpoint — more robust, returns everything, immune to layout changes). Runs in-page so it reuses the logged-in session's cookies/auth; recorded as a replayable step:
- {"type":"api_call","url":"https://…/api/…","method":"GET","headers":{"Authorization":"Bearer {{login_key}}"},"body":"…","variable":"name"}   (headers/body optional; a cookie-authed site usually needs no auth header). An api_call fetches its URL directly — you do NOT need to be on any particular page to run it, so don't navigate back and forth to "define it on the right page". Use a standalone api_call only for a ONE-OFF grab; for a NAMED capability the API should expose, use define_function fn_type:"api" (below) instead — never both for the same data.

LOG IN WITHOUT CLICKING (make the workflow authenticate with a request instead of the DOM form — the leanest API build):
- {"type":"login_post","url":"https://…/api/login","method":"POST","headers":{"Content-Type":"application/json"},"body":"{\"username\":\"{{login_username}}\",\"password\":\"{{login_password}}\"}"}   — replays the sign-in as a single request. Tested live the moment you emit it; on success it REPLACES the recorded fill/click login steps, so the workflow becomes navigate → login_post → (api_call data). The POST sets the session cookie, so every api_call after it is authenticated with no header.
  WHEN: after you've signed in via the form during discovery, look at the CAPTURED BACKEND API CALLS for the sign-in POST — the one whose BODY shows your held credentials as {{placeholders}} (the trace flags it). Copy its url, method, the Content-Type header shown, and the {{placeholder}} body EXACTLY (form-encoded `user={{login_username}}&pass={{login_password}}` or JSON — match what the trace shows). Emit ONE login_post.
  WHEN NOT TO: if the sign-in body ALSO carries a token you do NOT hold — csrf / authenticity_token / nonce / __RequestVerificationToken / a captcha — a bare POST can't reproduce it. Keep the recorded DOM login (do nothing). Same if the login is SSO/OAuth (a redirect flow), or login_post returns 401/403 twice. The DOM login always works as the fallback; login_post is the optimization when the sign-in is a clean credentials-only POST.

DEFINE API FUNCTIONS in "do" (for a goal that exposes the workflow as a callable API): emit while ON the page whose data the function returns — it is TESTED live (a REAL request / DOM read) THE MOMENT you emit it; only one that returns REAL data is defined. Defining a function ALSO records it as a workflow step (so the workflow run returns this dataset too) — so for each dataset use define_function ONCE and do NOT ALSO inline-extract or standalone-api_call the same data. ONE function per capability, ONE backing — never a variant of the same thing.
  PICK THE BACKING per capability: if the site loads that data from a JSON endpoint (you see it in CAPTURED BACKEND API CALLS or via capture_network) → fn_type:"api" (most robust — the workflow just does the fetch). Otherwise → fn_type:"script" (a DOM list) or fn_type:"extraction" (one field). Re-emitting the SAME name with a different backing REPLACES it in place (so fixing a DOM function by switching it to the API is ONE clean correction, not a duplicate) — but a function that already returned real data is DONE; do not switch a WORKING one back and forth.
  API AUTH — READ THE TRACE (works for ANY auth scheme): the CAPTURED BACKEND API CALLS print each request's auth header(s) with any credential you HOLD shown as its {{placeholder}} — e.g. "Authorization: Bearer {{login_apikey}}", or "X-API-Key: {{login_token}}", or a custom header. Whatever header(s) the trace shows for an endpoint, set your api_call / define_function-api "headers" to EXACTLY those (same names, same {{placeholders}}) — it then authenticates at both test and replay (the {{key}} resolves from the vault). If the trace shows NO auth header, the endpoint is cookie-authed — call it with no header. Only when the trace flags a secret you do NOT hold (a session token minted at sign-in) is the endpoint un-replayable — then define that capability from the DOM (fn_type:"list") instead. An unresolved/empty header is dropped automatically and the call falls back to cookies.
  For a multi-dataset API: navigate to page A → define its function; navigate to page B → define its function; then done. Do not go back and forth. A goal like "expose workflows and targets as an API" on an api-authed site is exactly TWO fn_type:"api" functions → done.
- {"type":"define_function","name":"get_workflows_list","fn_type":"list","row_selector":"<the repeating row from list_candidates/inspect>","fields":{"name":".title","status":".badge","link":{"selector":"a","attr":"href"}},"description":"...","output_fields":["name","status","link"]}   ← PREFER THIS for any list/table. You give the ROW selector + a field→sub-selector map (a bare string reads the sub-element's text; {"selector","attr"} reads an attribute; an empty selector reads the row's own text). We GENERATE the JS for you — you do NOT hand-write a script, so it can't break on quoting. Tested live immediately.
- {"type":"define_function","name":"get_workflows_list","fn_type":"api","url":"https://…/api/workflows","method":"GET","headers":{"Authorization":"Bearer {{login_key}}"},"description":"...","output_fields":["name","status"]}   (the auth header's {{login_key}} resolves from the vault at replay; a cookie-authed endpoint needs no header)
- {"type":"define_function","name":"get_monitor_list","fn_type":"script","code":"<evaluate-style IIFE, see WRITING EXTRACTION SCRIPTS>","description":"...","output_fields":["name","status"]}   (only when fn_type:list can't express it — a computed/derived value)
- {"type":"define_function","name":"get_status","fn_type":"extraction","selector":"css","description":"...","output_fields":["status"]}

WRITING EXTRACTION SCRIPTS (the crux — get this right and you finish fast):
- STRUCTURED data (a list, a table, multiple fields, per-row objects) → an "evaluate"/script IIFE that DISCOVERS the rows from the DOM and returns JSON: (() => Array.from(document.querySelectorAll('<stable row/card selector>')).map(el => ({ name: el.querySelector('<field sel>')?.innerText.trim(), status: el.querySelector('<sel>')?.innerText.trim() })).filter(r => r.name))(). The script does its OWN querying — it is selector-agnostic and returns whatever is on the page at call time.
- ONE element's text only → an "extract" with a CSS selector (no script).
- A list whose rows are plain field reads → an "extract" with "fields" (no script needed). Reach for "evaluate" only when the rows need logic the fields form can't express.
- NEVER hardcode the values you see (e.g. a literal ['korben.info', ...]) — that is REJECTED and breaks when the data changes. NEVER use a bare "extract" (no fields) for a list.
- To call the site's BACKEND API, use the api_call ACTION (or define_function fn_type:"api") — NEVER write fetch()/XMLHttpRequest inside a script (a script that fetches is REJECTED). Why: those are first-class replayable steps whose auth header resolves the credential from the vault ({{login_key}} → {{secret:…}}), whereas a script's fetch has no such auth at replay.
- NEVER read auth or data from sessionStorage/localStorage in a script (e.g. sessionStorage.getItem('apiKey')) — that store is EMPTY in a fresh replay session, so it returns nothing/unauthorized. It is REJECTED. Put the credential in the api_call header as {{login_key}}.
- THE RELIABLE LIST FLOW (use this — it is why you rarely need to write a script): (1) {"type":"list_candidates"} to get the repeating ROW selector, (2) {"type":"inspect","selector":"<row>"} to see a row's inner elements/classes and pick the field sub-selectors, (3) define_function fn_type:"list" with that row_selector + fields map. We generate the JS, test it live, and you correct by re-emitting the same name with a fixed selector. Only fall back to fn_type:"script" (hand-written JS) for a computed/derived value fn_type:list can't express.
- If you DO hand-write a script: FIND the row selector from the PAGE DOM below (the element that REPEATS once per row) and confirm with inspect first — never write a selector you did not see. If a row has no usable class, go up to the nearest repeating ancestor (tr, li, [role=row], a card div).

Optional "setup" array alongside "do" (noted now, created for real when the session ends; emit each AT MOST ONCE, only if the GOAL asks for it, while ON the page where the element lives):
- {"type":"create_monitor","selector":"css","watch":"price"|"content","threshold":123,"name":"..."}
- {"type":"wire_automation"}
- {"type":"expose_api","rest":true,"openai":false,"mcp":false}

RULES:
1. SECRETS: AVAILABLE DATA values shown as [SECURE] are credentials you HOLD but never see. To type one, use its placeholder: {"type":"fill","selector":"#key","value":"{{login_key}}"}. The runtime substitutes the real value at execution; the recorded step keeps the placeholder. NEVER type a literal credential and NEVER guess one.
2. TRUTH: never claim an action you did not perform. The recorded workflow is exactly what actually executed. If an action fails you see the error next turn — adapt (different selector, different route); do not repeat the same failing action.
3. NAVIGATION: signing in is a STEP, not the goal. Use the LINKS list (or a /path you can see) to reach EVERY page the goal names, one page at a time. After a navigate or a click that changes the page, END the batch — observe the new page before acting on it.
4. DELIVERABLES — API FIRST, then DOM: when the CAPTURED BACKEND API CALLS (or a capture_network probe) show a JSON endpoint returning the data, extract via api_call — it returns the full, live data and survives layout changes. Fall back to extract/evaluate on the DOM only when there is no usable endpoint. Either way, capture data AS YOU GO: when you are ON a page holding data the goal asks for, get it THERE with an api_call or extract/evaluate action in "do" (probe first with evaluate_js to see the data, then extract what you have SEEN work). Each successful extraction is recorded at that exact position, so a multi-page goal becomes navigate → extract → navigate → extract and replays in the same order. "done" may also carry final "deliverables":[extract/evaluate specs] — they run on the page you are on WHEN you submit done (and replay LAST in the workflow), so only use them for the final page's data. A done that fails its deliverables is REJECTED with the real results; a done with nothing extracted anywhere is questioned once — never claim data you did not capture.
5. ASK: if you cannot proceed without a decision or data only the user has (which account, an unexpected login field, a CAPTCHA) — "ask" with a one-sentence question. For a login credential, name EXACTLY the field(s) the real form shows in credential_fields (a single API key is common; do NOT assume username+password). Mark secrets "secret":true and name fields login_<something>. TWO-FACTOR / ONE-TIME CODE: if the page asks for a one-time verification code (authenticator, email, or SMS) and no persona is attached, do NOT re-type the username/password or navigate back to the login form (that just loops) — "ask" the user to paste the code so discovery can finish, and mention that to run this automatically on a schedule they should create a persona for this site (with its 2FA) and attach it, since a typed code is single-use.
6. JSON-SAFE scripts (your script rides inside a JSON string — escapes corrupt it): write NO backslash escape sequences in string/regex literals. Split lines with String.fromCharCode(10); use plain classes [0-9] and [a-zA-Z] (not backslash-d/-w); use .includes()/.startsWith()/.trim()/indexOf instead of escape-heavy regexes. Avoid a quoted CSS attribute selector inside the script (the inner quotes break the JSON) — instead query the tag and filter in JS: NOT querySelector('a[data-x="1"]') but Array.from(document.querySelectorAll('a')).find(a => a.dataset.x === '1'). Keep script string/regex literals single-quoted.
7. VERIFY before you commit: probe the page with evaluate_js and SEE real data before you extract/define. Never propose a script "on faith".
8. Keep "do" batches small (1-4). One page at a time. Do not re-fill keys listed as already filled.
9. SELECTORS: prefer STABLE anchors — #id, [name="..."], [aria-label="..."], or the exact selector shown in FORM FIELDS / BUTTONS / LINKS. NEVER invent a bare positional selector like button:nth-of-type(29) — it is unstable and usually matches the wrong element (or nothing). For clicks on labeled controls, always include "text" so the click can fall back to the visible label.
10. CORRECTIONS (never duplicate): the WHAT YOU'VE BUILT inventory lists your recorded extractions (by variable) and defined functions (by name). To FIX one, re-emit it with the SAME variable (extract/evaluate) or SAME name (define_function) — it REPLACES the existing one in place and is re-tested. A different variable/name makes a SECOND copy. To fix a broken "monitors" extraction, re-emit variable "monitors" — do NOT invent "monitors2".
11. COMMIT — don't oscillate: pick ONE backing per capability (fn_type:"api", or ONE evaluate script, or one extraction) and stick with it. A deliverable/function in WHAT YOU'VE BUILT that already returned REAL DATA is DONE — do NOT re-do it, do NOT switch it from DOM to API or back, do NOT give the same data a second name (get_workflows_list AND workflows is ONE capability — pick one name). When every capability the goal names has a working deliverable, call "done" immediately. Endlessly re-fixing working items is failure, not thoroughness — the no-progress guard will force-finish you if you keep re-touching the same items.
"##;

pub(crate) fn connected_explorer_instructions() -> &'static str { EXPLORER_SYSTEM }

/// Give an MCP-connected model the same discovery inputs used by the desktop explorer. The model
/// transport differs, but DOM cleanup, link collection, and network formatting must not.
pub(crate) async fn connected_discovery_context(
    page: &Page,
    network: Option<Arc<Mutex<NetworkCapture>>>,
    _fill_data: &HashMap<String, String>,
    recorded_steps: &[Value],
    defined_functions: &[Value],
) -> Value {
    let evaluator = ExplorerEval(page.clone());
    let mut observation = build_ai_observation(page, &evaluator).await;
    // The desktop loop can send a screenshot as a separate vision part. An MCP JSON result cannot:
    // embedding base64 here easily exceeds client tool-result limits and hides the useful DOM.
    if let Some(obj) = observation.as_object_mut() {
        obj.remove("screenshot");
    }
    let raw = match page_query::evaluate::<String>(page, COLLAPSE_DOM_JS).await {
        Ok(html) => html,
        Err(_) => page.content().await.unwrap_or_default(),
    };
    let cleaned = crate::local::ai::context_clean::clean_dom_for_ai(&raw);
    let dom: String = cleaned.chars().take(12_000).collect();
    let links = collect_links(page).await;
    let network_count = match network {
        Some(net) => {
            let cap = net.lock().await;
            cap.get_all_calls().len()
        }
        None => 0,
    };
    json!({
        "explorer_instructions": "Drive Writ's real local browser and record a reusable workflow. Treat cleaned_live_dom as selector truth. Network capture runs passively but its data is omitted here: call writ_browser_network(operation=list), then operation=get only when backend inspection is useful. Probe before guessing; read a probe before defining an extraction. Prefer a replayable API call when its auth can replay, otherwise define a DOM list/extraction. Every define_function is live-tested and must return real non-empty data. Use data_key / {{input.name}} for user-supplied values; ask missing clarifications, login, CAPTCHA/2FA guidance and choices in the connected AI chat. Never hardcode samples. Record the complete route, avoid duplicates, and save only after deliverables work.",
        "observation": observation,
        "cleaned_live_dom": dom,
        "links": links,
        "network_capture": {
            "request_count": network_count,
            "detail_included": false,
            "inspect_with": "writ_browser_network",
        },
        "recorded_steps": recorded_steps,
        "defined_functions": defined_functions,
    })
}

/// A completed turn in the thread: the model's raw decision JSON + what actually happened.
struct Turn {
    decision: String,
    result: String,
}

/// Evaluator over the live page for [`build_ai_observation`] parity.
struct ExplorerEval(Page);
impl PageEvaluator for ExplorerEval {
    fn evaluate_json(
        &self,
        js: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Value>> + Send + '_>>
    {
        let js = js.to_string();
        Box::pin(async move {
            self.0
                .evaluate(&js, None::<&()>)
                .await
                .map_err(|e| anyhow::anyhow!("evaluate_json failed: {}", e))
        })
    }
    fn evaluate_json_with_args(
        &self,
        js: &str,
        args: &[Value],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Value>> + Send + '_>>
    {
        let js = js.to_string();
        let args = Value::Array(args.to_vec());
        Box::pin(async move {
            self.0
                .evaluate(&js, Some(&args))
                .await
                .map_err(|e| anyhow::anyhow!("evaluate_json_with_args failed: {}", e))
        })
    }
}

/// Await `fut`, but abandon it and return `None` if the cooperative-cancel flag flips while we wait.
/// Polls the flag every 200ms; on cancel the future is DROPPED (aborting an in-flight model/HTTP call),
/// so Stop takes effect within a fraction of a second instead of blocking on the round-trip.
async fn await_or_cancel<F: std::future::Future>(
    cancel: Option<&AtomicBool>,
    fut: F,
) -> Option<F::Output> {
    use std::sync::atomic::Ordering;
    if cancel.map(|c| c.load(Ordering::Relaxed)).unwrap_or(false) {
        return None;
    }
    tokio::pin!(fut);
    loop {
        tokio::select! {
            biased;
            out = &mut fut => return Some(out),
            _ = tokio::time::sleep(Duration::from_millis(200)) => {
                if cancel.map(|c| c.load(Ordering::Relaxed)).unwrap_or(false) {
                    return None;
                }
            }
        }
    }
}

/// Path of the human-readable debug transcript for an explorer session: the full prompt, the model's
/// decision, and the real result of every turn. Lives under `~/.writ/explorer-debug/` (discoverable),
/// falling back to the OS temp dir.
fn debug_transcript_path(session_id: i64) -> std::path::PathBuf {
    let base = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .map(|h| h.join(".writ").join("explorer-debug"))
        .unwrap_or_else(std::env::temp_dir);
    base.join(format!("session-{session_id}.md"))
}

/// Append a section to the session's debug transcript. Best-effort — a debug aid never affects the run.
async fn debug_append(path: &std::path::Path, content: &str) {
    use tokio::io::AsyncWriteExt;
    if let Ok(mut f) = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
    {
        let _ = f.write_all(content.as_bytes()).await;
    }
}

/// Run the explorer agent over an already-navigated page. Same return contract as
/// [`super::session::run_session`], so the caller's recording/finalize path is unchanged.
#[allow(clippy::too_many_arguments)]
pub async fn run_explorer(
    page: &Page,
    cfg: &SessionConfig,
    ai_cfg: &AiConfig,
    pool: &SqlitePool,
    cancel: Option<&AtomicBool>,
    sink: Option<&StepSink<'_>>,
    network: Option<Arc<Mutex<NetworkCapture>>>,
    // Pin every turn's completion to the MANAGED cloud gateway (metered), ignoring the BYO toggle.
    // Set by AI auto-repair's autonomous re-record; `false` for the normal AI-session path.
    force_gateway: bool,
) -> LocalResult<SessionResult> {
    let evaluator = ExplorerEval(page.clone());
    let max_steps = cfg.max_steps.max(1);
    // Human-readable debug transcript (full prompt → decision → real result, per turn) for diagnosing
    // why a build did / didn't extract — especially the raw api_call responses. Fresh file per session;
    // its path is logged so it's easy to open. Best-effort; never affects the run.
    let debug_id = sink.map(|s| s.ref_id).unwrap_or(0);
    let debug_path = debug_transcript_path(debug_id);
    if let Some(dir) = debug_path.parent() {
        let _ = tokio::fs::create_dir_all(dir).await;
    }
    let _ = tokio::fs::remove_file(&debug_path).await;
    debug_append(
        &debug_path,
        &format!("# Explorer session {debug_id}\n\n**Goal:** {}\n", cfg.goal),
    )
    .await;
    tracing::warn!(target: "ai_api_debug", path = %debug_path.display(), "explorer debug transcript file");
    // Mutable copies: an in-flight ask-answer (park_for_answer) GROWS these — a newly provided
    // credential becomes fillable/recordable mid-session without restarting the browser.
    let mut fill_data: HashMap<String, String> = cfg.fill_data.clone();
    let mut available_data: HashMap<String, String> = cfg.available_data.clone();
    let mut record_templates: HashMap<String, String> = cfg.record_templates.clone();

    let mut turns: Vec<Turn> = Vec::new();
    // Seed the entry navigation (mirrors the form-filler): a replayed workflow must reach the page
    // the session started on, or it replays from about:blank and every later step fails.
    let entry = page.url();
    let mut recorded_steps: Vec<Value> = if entry.is_empty() || entry == "about:blank" {
        Vec::new()
    } else {
        vec![json!({ "type": "navigate", "enabled": true, "config": { "url": entry } })]
    };
    let mut orchestration_intents: Vec<Value> = Vec::new();
    let mut extracted_data: serde_json::Map<String, Value> = serde_json::Map::new();
    let mut filled_keys: Vec<String> = Vec::new();
    let mut setup_kinds_seen: Vec<String> = Vec::new();
    // Functions defined (and live-tested) in-session — deduped by name here, materialized after.
    let mut defined_functions: Vec<Value> = Vec::new();
    // Per-name count of FAILED api-backed define_function attempts. After a couple of failures the
    // endpoint plainly won't authenticate for replay (needs a dynamic token, not a static secret/
    // cookie) — we escalate the feedback to pivot the agent to a DOM backing instead of it retrying
    // the same dead endpoint forever (the "gets stuck" loop).
    let mut api_fail_counts: HashMap<String, u32> = HashMap::new();
    // Failed define_function attempts per name (any backing). Caps the "re-emit a new selector variant
    // for the same capability over and over" thrash.
    let mut def_fail_counts: HashMap<String, u32> = HashMap::new();

    let mut verify_rejects: u32 = 0;
    // Nudges for a `done` with no deliverables AND nothing extracted — kept SEPARATE from
    // verify_rejects so a real verification failure always gets its full feedback budget.
    let mut empty_done_nudges: u32 = 0;
    // Deliverables that ALREADY verified on an earlier (rejected) `done`, keyed by variable —
    // their steps must land in the workflow even if the model's next `done` omits them (it is
    // told "verified so far: X", so it may legitimately resubmit only the fixed ones). Inline
    // `do`-extractions are NOT cached here — their steps are already recorded in place.
    let mut done_verified_cache: HashMap<String, Value> = HashMap::new();
    let mut parse_retries: u32 = 0;
    let mut action_failure_streak: u32 = 0;
    let mut stall: u32 = 0;
    let mut last_fingerprint = String::new();
    let mut last_kf_hash: u64 = 0;
    // NO-NEW-PROGRESS breaker (kills the /workflows↔/targets ping-pong): the set of distinct
    // deliverables (recorded extraction/api_call variables + defined function names) either GROWS or
    // it doesn't. Endless re-corrections don't grow it — after a few barren turns we push to finish,
    // then force-finish with whatever real data exists (a 2-cycle evades the identical-decision stall
    // check because the url + decision differ each turn).
    let mut seen_deliverables: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut stagnant: u32 = 0;
    // Pages (URL path, query/fragment stripped) the agent has already worked on. Reaching a NEW page is
    // real forward progress on a multi-page build (login → /workflows → /targets), so it resets the
    // stall counters — otherwise the navigate+probe turns spent starting a second page wrongly read as
    // "stuck". Re-visiting an ALREADY-seen page does NOT reset, so the genuine ping-pong is still caught.
    let mut visited_pages: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Backstop against a no-data bounce running all the way to max_steps: turns since the deliverable
    // set last GREW, counted regardless of whether any data exists yet. Reset on real growth. A long
    // barren streak means the agent can neither extract nor converge — end honestly as Stuck.
    let mut barren_turns: u32 = 0;
    // Once the site's API REPEATEDLY rejects authentication (two real 401/403s — not a 404, not an
    // empty body, not a network error), stop the agent re-trying fn_type:"api" on every page — steer
    // it to DOM backings for the rest of the session. Anything short of that keeps the API available:
    // one bad header is fixable, and a wrong endpoint is a targeting problem, not an auth one.
    let mut api_auth_failed = false;
    let mut api_auth_fail_count: u32 = 0;

    // login_post (replay the sign-in as a request, dropping the DOM login steps): after two rejected
    // attempts (401/403 or a body needing an unheld token), turn it OFF for the session so the agent
    // keeps the DOM login it already recorded instead of thrashing on a POST that can't reproduce auth.
    let mut login_post_off = false;
    let mut login_post_fail_count: u32 = 0;

    // ── MULTI-TAB: the agent works on an ACTIVE tab that it can switch. A click that opens a new tab
    // (target=_blank / window.open) is detected after each batch and the agent is offered the new tab;
    // `list_tabs` / `switch_tab` let it move between tabs. Scoped to THIS session's own browser context
    // (`page.context()`), so it only ever sees its own tabs, never other windows or the user's browser.
    let context = page.context().ok();
    let mut active_page: Page = page.clone();

    // Vision is ON-DEMAND: the model's turn is TEXT + cleaned-DOM only, so it works on any provider
    // (a non-vision model can't take an image every turn). The model asks for a frame with the
    // `screenshot` action; this one-shot flag then attaches the just-captured JPEG to the NEXT turn.
    let mut send_screenshot = false;
    // The cleaned DOM we last showed the model — lets us skip re-sending a byte-identical DOM (Design A).
    let mut last_dom_sig: Option<String> = None;

    let mut step_count: u32 = 0;
    while step_count < max_steps {
        // Bind `page` to a CLONE of the active tab for this turn, so a switch_tab mid-batch can rebind
        // `active_page` (its effect lands next turn, like a navigation ends the batch). All the loop's
        // existing `page` uses now target whichever tab is active.
        let page_owned = active_page.clone();
        let page: &Page = &page_owned;
        if cancel
            .map(|c| c.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(false)
        {
            return Ok(finish(
                SessionStatus::Cancelled,
                step_count,
                "Session aborted by caller".into(),
                None,
                page,
                &filled_keys,
                &extracted_data,
                &mut recorded_steps,
                &mut orchestration_intents,
            ));
        }

        // ── NO-NEW-PROGRESS breaker: has the set of distinct deliverables GROWN since last turn? ──
        let mut progress_note = String::new();
        {
            let current: std::collections::HashSet<String> = recorded_steps
                .iter()
                .filter(|s| {
                    matches!(
                        s.get("type").and_then(|t| t.as_str()),
                        Some("extract") | Some("evaluate") | Some("api_call")
                    )
                })
                .filter_map(|s| {
                    s.pointer("/config/variable")
                        .and_then(|v| v.as_str())
                        .map(|v| format!("x:{v}"))
                })
                .chain(defined_functions.iter().filter_map(|f| {
                    f.get("name")
                        .and_then(|n| n.as_str())
                        .map(|n| format!("f:{n}"))
                }))
                .collect();
            let grew = current.iter().any(|k| !seen_deliverables.contains(k));
            seen_deliverables.extend(current.iter().cloned());
            let have_data = !current.is_empty();
            // Reaching a NEW page counts as progress (the agent is legitimately working through the
            // build's pages) — reset the stall counters so probing a fresh page is never "stuck".
            let url_now = page.url();
            let page_key = url_now
                .split(['?', '#'])
                .next()
                .unwrap_or(&url_now)
                .to_string();
            let reached_new_page = visited_pages.insert(page_key);
            let progressed = grew || reached_new_page;
            stagnant = if progressed || !have_data {
                0
            } else {
                stagnant + 1
            };
            barren_turns = if progressed { 0 } else { barren_turns + 1 };
            // BACKSTOP: many turns with NO new deliverable at all (data or not) — the agent is bouncing
            // between pages/backings and getting nowhere. Finish: complete if some data exists, else an
            // honest Stuck (never run all the way to max_steps re-trying a dead endpoint).
            if barren_turns >= BARREN_STUCK_AT {
                prune_dead_navigations(&mut recorded_steps);
                let status = if have_data {
                    SessionStatus::Complete
                } else {
                    SessionStatus::Stuck
                };
                let (label, phase, msg) = if have_data {
                    (
                        "Converged — finishing with the deliverables already built.",
                        "Finishing",
                        "Built the deliverables; stopped bouncing.",
                    )
                } else {
                    (
                        "No progress after many turns — stopping.",
                        "Stuck",
                        "Could not extract the requested data.",
                    )
                };
                report_step(
                    sink,
                    pool,
                    &mut last_kf_hash,
                    step_count as i64,
                    label,
                    phase,
                    &page.url(),
                    if have_data { "complete" } else { "stuck" },
                    "",
                )
                .await;
                return Ok(SessionResult {
                    status,
                    steps: step_count,
                    message: msg.into(),
                    error: if have_data {
                        None
                    } else {
                        Some("no new deliverable across many turns".into())
                    },
                    result: json!({ "current_url": page.url(), "filled_fields": filled_keys, "extracted": extracted_data }),
                    recorded_steps: std::mem::take(&mut recorded_steps),
                    orchestration_intents: std::mem::take(&mut orchestration_intents),
                });
            }
            // FORCE convergence: repeatedly re-touching the same items without adding new ones, while
            // real deliverables exist — stop and finish with what's built (the ping-pong ends here).
            if stagnant >= STAGNANT_FORCE_AT && have_data {
                prune_dead_navigations(&mut recorded_steps);
                report_step(sink, pool, &mut last_kf_hash, step_count as i64, "Converged — finishing with the deliverables already built (stopped re-fixing).", "Finishing", &page.url(), "complete", "").await;
                return Ok(SessionResult {
                    status: SessionStatus::Complete,
                    steps: step_count,
                    message: "Built the deliverables; stopped repeated revisions.".into(),
                    error: None,
                    result: json!({ "current_url": page.url(), "filled_fields": filled_keys, "extracted": extracted_data }),
                    recorded_steps: std::mem::take(&mut recorded_steps),
                    orchestration_intents: std::mem::take(&mut orchestration_intents),
                });
            }
            if stagnant >= STAGNANT_NUDGE_AT && have_data {
                progress_note = format!(
                    "\n\nSTOP RE-FIXING: you've added NO new deliverable in {stagnant} turns and keep revising items that already work. What you've built already returns real data. If every capability the goal asks for is covered, call \"done\" NOW. Do not switch a working extraction between DOM and API."
                );
            }
            // Once the API proved unauthenticatable for replay, forbid re-trying it — the biggest source
            // of wasted turns on an api-authed SPA is re-attempting fn_type:"api" on every page.
            if api_auth_failed {
                progress_note.push_str(
                    "\n\nAPI IS OFF for this site: its endpoints rejected authentication (HTTP 401/403) repeatedly — they need a token minted at sign-in, which a recorded request cannot carry. Do NOT emit fn_type:\"api\" or api_call again this session. Define EVERY remaining capability from the DOM: list_candidates → inspect → fn_type:\"list\". Do not return to a page whose function is already built."
                );
            }
        }

        // ── Observe ── (quiet guard first — never analyze a document that is still loading/mutating)
        navigation::wait_for_page_quiet(page, Duration::from_secs(2)).await;
        let obs = build_ai_observation(page, &evaluator).await;
        let current_url = page.url();
        let screenshot = obs
            .get("screenshot")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let links = collect_links(page).await;
        // The REAL DOM (cleaned: scripts/styles/svg/head/base64/inline-handlers stripped, every
        // element + class kept). This is what the API-builder reasons over to write extraction
        // selectors — a truncated visible-text "observation" hides the list STRUCTURE (the repeating
        // rows + their classes) the agent needs. Same lean HTML the AI-assist selector brain uses.
        // Bounded so a huge dashboard can't blow the context; the head/nav noise is already gone.
        let dom_html = {
            // Fetch the REAL rendered DOM with repeated sibling groups collapsed in-page (works on any
            // framework). Falls back to the raw content on any eval error so we never lose the DOM.
            let eval_res: Result<serde_json::Value, _> =
                page.evaluate(COLLAPSE_DOM_JS, None::<&()>).await;
            let raw = match eval_res {
                Ok(v) => v.as_str().map(str::to_string).filter(|s| !s.is_empty()),
                Err(e) => {
                    tracing::debug!(error = %e, "explorer: DOM-collapse eval failed — using raw content");
                    None
                }
            };
            let raw = match raw {
                Some(r) => r,
                None => page.content().await.unwrap_or_default(),
            };
            let cleaned = crate::local::ai::context_clean::clean_dom_for_ai(&raw);
            if cleaned.chars().count() > MAX_DOM_CHARS {
                let head: String = cleaned.chars().take(MAX_DOM_CHARS).collect();
                format!("{head}\n…[DOM truncated — probe deeper regions with evaluate_js if the data you need isn't shown]")
            } else {
                cleaned
            }
        };
        // Design A (conservative): when the cleaned DOM is BYTE-IDENTICAL to what we sent last turn
        // (the page truly didn't change — no navigation, no re-render, no filled value), skip re-sending
        // the whole block and send a short marker instead. Only ever omits on an exact match, so the
        // model never loses real structure; anything that changed re-sends the full DOM. `last_dom_sig`
        // holds the DOM we last showed the model.
        let dom_unchanged = last_dom_sig.as_deref() == Some(dom_html.as_str());
        let dom_for_prompt = if dom_unchanged {
            "(unchanged since your last turn — the page DOM is exactly as shown above; use inspect / list_candidates / evaluate_js if you need to re-examine a region)".to_string()
        } else {
            last_dom_sig = Some(dom_html.clone());
            dom_html.clone()
        };
        // Snapshot the backend API calls captured so far (auth values already redacted by the
        // capture layer) so the agent always SEES the site's real API and can prefer it over the DOM.
        let network_block = match &network {
            Some(net) => {
                let cap = net.lock().await;
                let calls: Vec<&crate::models::network::NetworkCall> =
                    cap.get_all_calls().iter().rev().take(20).collect();
                let calls: Vec<&crate::models::network::NetworkCall> =
                    calls.into_iter().rev().collect();
                if calls.is_empty() {
                    "  (none captured yet — use capture_network to reload the page and record its backend calls)".to_string()
                } else {
                    scrub_credentials(
                        &cap.format_for_prompt(&calls, &fill_data),
                        &fill_data,
                        &available_data,
                    )
                }
            }
            None => "  (network capture unavailable)".to_string(),
        };
        // Scrub the whole turn text: a page that renders the just-typed credential (an API-key
        // settings page, an echoing form) must not leak it into the model thread via page_text.
        let user_text = scrub_credentials(
            &format!(
                "{}{progress_note}",
                build_turn_text(
                    cfg,
                    &available_data,
                    &fill_data,
                    &obs,
                    &links,
                    &network_block,
                    &dom_for_prompt,
                    &turns,
                    &extracted_data,
                    &recorded_steps,
                    &setup_kinds_seen,
                    &defined_functions,
                    step_count,
                    max_steps,
                    &filled_keys
                )
            ),
            &fill_data,
            &available_data,
        );
        debug_append(
            &debug_path,
            &format!(
                "\n\n---\n\n## Turn {} — {}\n\n### PROMPT SENT TO MODEL\n\n````\n{}\n````\n",
                step_count + 1,
                current_url,
                user_text
            ),
        )
        .await;
        // Attach the screenshot ONLY when the model asked for it last turn (send_screenshot). Default
        // turns are text-only — no image is sent, so any model works and no vision tokens are spent.
        let sent_shot = send_screenshot && !screenshot.is_empty();
        let shot_for_model = if sent_shot { screenshot.as_str() } else { "" };
        send_screenshot = false;
        let messages = build_thread(cfg, &turns, &user_text, shot_for_model);

        // ── Decide ── (cancel-aware: the model call is the longest blocking op — if the user hits Stop
        // mid-call we abort the request and finish Cancelled promptly, rather than waiting it out.)
        let mut completion_res = await_or_cancel(
            cancel,
            provider::complete_with_gateway_pref(
                pool,
                ai_cfg,
                &messages,
                Some(EXPLORER_SYSTEM),
                2000,
                "agent",
                force_gateway,
            ),
        )
        .await;
        // Vision fallback: if THIS turn attached a screenshot and the provider rejected the image (a
        // non-vision model → HTTP 404 "no endpoints that support image input", or similar), retry the
        // SAME turn text-only so a screenshot request never kills the run.
        if sent_shot {
            if let Some(Err(e)) = &completion_res {
                tracing::warn!(error = %e, "explorer: model rejected the screenshot — retrying text-only");
                debug_append(
                    &debug_path,
                    &format!(
                        "\n### VISION FALLBACK (model rejected image, retrying text-only)\n\n{e}\n"
                    ),
                )
                .await;
                let text_only = build_thread(cfg, &turns, &user_text, "");
                completion_res = await_or_cancel(
                    cancel,
                    provider::complete_with_gateway_pref(
                        pool,
                        ai_cfg,
                        &text_only,
                        Some(EXPLORER_SYSTEM),
                        2000,
                        "agent",
                        force_gateway,
                    ),
                )
                .await;
            }
        }
        let completion = match completion_res {
            None => {
                return Ok(finish(
                    SessionStatus::Cancelled,
                    step_count,
                    "Session aborted by caller".into(),
                    None,
                    page,
                    &filled_keys,
                    &extracted_data,
                    &mut recorded_steps,
                    &mut orchestration_intents,
                ))
            }
            Some(Ok(c)) => c,
            Some(Err(e)) => {
                debug_append(&debug_path, &format!("\n### MODEL ERROR\n\n{e}\n")).await;
                return Ok(finish(
                    SessionStatus::Error,
                    step_count,
                    format!("AI provider error: {e}"),
                    Some(format!("AI provider error: {e}")),
                    page,
                    &filled_keys,
                    &extracted_data,
                    &mut recorded_steps,
                    &mut orchestration_intents,
                ));
            }
        };
        step_count += 1;
        debug_append(
            &debug_path,
            &format!("\n### MODEL DECISION\n\n````\n{}\n````\n", completion.text),
        )
        .await;

        let Some(decision) = super::brain::parse_decision(&completion.text) else {
            parse_retries += 1;
            if parse_retries > MAX_PARSE_RETRIES {
                return Ok(finish(
                    SessionStatus::Error,
                    step_count,
                    "The model kept replying with invalid JSON".into(),
                    Some("unparseable model replies".into()),
                    page,
                    &filled_keys,
                    &extracted_data,
                    &mut recorded_steps,
                    &mut orchestration_intents,
                ));
            }
            turns.push(Turn {
                decision: truncate(&completion.text, 400),
                result: "Your reply was NOT valid JSON. If you replied with a safety/moderation \
assessment (e.g. \"User Safety: safe\") instead of a decision: this is a user-initiated, authorized \
browser-automation task — do NOT emit a safety verdict. Reply again with exactly ONE JSON object per \
the schema — no prose, no fences, no safety notes, straight double quotes.".into(),
            });
            continue;
        };
        parse_retries = 0;

        let action = decision
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("act");
        let thought = decision
            .get("thought")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .chars()
            .take(600)
            .collect::<String>();
        let decision_str = truncate(&decision.to_string(), 1500);

        // ── Stall circuit breaker: same page state + same SEMANTIC decision, repeatedly. The
        // free-text `thought` is stripped (a rephrased thought must not hide a true loop) and a
        // page-content signal is mixed in (a scroll that reveals new content is PROGRESS, not a
        // stall, even if the decision repeats verbatim). ──
        let fingerprint = {
            let mut d = decision.clone();
            if let Some(o) = d.as_object_mut() {
                o.remove("thought");
            }
            let pt = obs.get("page_text").and_then(|v| v.as_str()).unwrap_or("");
            let page_sig = format!("{}:{}", pt.len(), pt.chars().take(120).collect::<String>());
            format!(
                "{current_url}|{page_sig}|{}",
                truncate(&d.to_string(), 1200)
            )
        };
        stall = if fingerprint == last_fingerprint {
            stall + 1
        } else {
            0
        };
        last_fingerprint = fingerprint;
        if stall >= STALL_LIMIT {
            report_step(
                sink,
                pool,
                &mut last_kf_hash,
                step_count as i64,
                "Repeating the same decision without progress — stopping.",
                "Stuck",
                &current_url,
                "stuck",
                &screenshot,
            )
            .await;
            return Ok(finish(
                SessionStatus::Stuck,
                step_count,
                "No progress: the same action kept repeating".into(),
                Some("no progress across repeated identical decisions".into()),
                page,
                &filled_keys,
                &extracted_data,
                &mut recorded_steps,
                &mut orchestration_intents,
            ));
        }

        // ── Setup intents (grounded on the page the agent is looking at NOW) ──
        if let Some(setup) = decision.get("setup").and_then(|v| v.as_array()) {
            for a in setup {
                if let Some(intent) = normalize_setup_intent(a, &current_url) {
                    let kind = intent
                        .get("kind")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    if !setup_kinds_seen.contains(&kind) {
                        setup_kinds_seen.push(kind);
                        orchestration_intents.push(intent);
                    }
                }
            }
        }

        match action {
            // ── Pause: the agent needs the user (decision/credential/CAPTCHA) ──
            "ask" => {
                let question = decision
                    .get("message")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .unwrap_or("I need a decision from you to continue — what should I do?")
                    .to_string();
                let credential_fields = decision
                    .get("credential_fields")
                    .cloned()
                    .unwrap_or(Value::Null);
                // PARK IN PLACE when this build belongs to a concierge mission: the browser stays
                // OPEN on the live page (the user can keep watching), `/respond` hands the answer
                // straight to this loop via ask_gate, and the session continues exactly where it
                // stopped — no re-login, no re-navigation. Timeout/cancel falls back to the classic
                // blocked-return below (browser closes; the planner re-runs discover with context).
                if let Some(cid) = cfg.ask_session_id {
                    report_step(
                        sink,
                        pool,
                        &mut last_kf_hash,
                        step_count as i64,
                        &question,
                        "Waiting for your answer — browser stays open",
                        &current_url,
                        "blocked",
                        &screenshot,
                    )
                    .await;
                    match park_for_answer(pool, cid, &question, &credential_fields, cancel).await {
                        Park::Answered(ans) => {
                            for (k, v) in ans.fill {
                                let masked = ans
                                    .record
                                    .get(&k)
                                    .map(|r| r.starts_with("{{secret:"))
                                    .unwrap_or(false);
                                available_data.insert(
                                    k.clone(),
                                    if masked {
                                        "[a secret credential you hold]".into()
                                    } else {
                                        v.clone()
                                    },
                                );
                                fill_data.insert(k, v);
                            }
                            record_templates.extend(ans.record);
                            let answered = ans
                                .text
                                .iter()
                                .map(|(k, v)| format!("- {k}: {v}"))
                                .collect::<Vec<_>>()
                                .join("\n");
                            turns.push(Turn {
                                decision: decision_str,
                                result: format!("THE USER ANSWERED:\n{answered}\nContinue from the current page with this — the browser never closed."),
                            });
                            report_step(
                                sink,
                                pool,
                                &mut last_kf_hash,
                                step_count as i64,
                                "Answer received — continuing on the same page.",
                                "Resuming",
                                &current_url,
                                "running",
                                &screenshot,
                            )
                            .await;
                            continue;
                        }
                        Park::Cancelled => {
                            return Ok(finish(
                                SessionStatus::Cancelled,
                                step_count,
                                "Session aborted by caller".into(),
                                None,
                                page,
                                &filled_keys,
                                &extracted_data,
                                &mut recorded_steps,
                                &mut orchestration_intents,
                            ));
                        }
                        Park::TimedOut => { /* fall through to the classic blocked return */ }
                    }
                }
                report_step(
                    sink,
                    pool,
                    &mut last_kf_hash,
                    step_count as i64,
                    &question,
                    "Asked the user",
                    &current_url,
                    "blocked",
                    &screenshot,
                )
                .await;
                return Ok(SessionResult {
                    status: SessionStatus::Blocked,
                    steps: step_count,
                    message: format!("Blocked: {question}"),
                    error: Some(question),
                    result: json!({
                        "current_url": current_url,
                        "filled_fields": filled_keys,
                        "extracted": extracted_data,
                        "credential_fields": credential_fields,
                    }),
                    recorded_steps: std::mem::take(&mut recorded_steps),
                    orchestration_intents: std::mem::take(&mut orchestration_intents),
                });
            }

            // ── Finish: verify the deliverables against the LIVE page before accepting ──
            "done" => {
                let deliverables = decision
                    .get("deliverables")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let summary = decision
                    .get("summary")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Goal accomplished")
                    .to_string();

                // "Nothing built" means NO data anywhere — not just an empty `extracted_data`. A
                // define_function (fn_type list/script/extraction/api) records its step + registers the
                // function WITHOUT touching `extracted_data`, so a build that defined both list functions
                // has genuinely captured its data. Counting only `extracted_data` here is what bounced a
                // finished agent back to re-extract — the "it doesn't see the first script works" loop.
                // Only deliverables that actually RETURNED DATA count. A recorded extract/evaluate/
                // api_call step is only recorded AFTER verify_deliverable passed (real data), and a
                // function carries a non-empty `test_sample` only when its live test returned data — so
                // both are proof of a working result, not a mere attempt.
                let has_recorded_deliverable = recorded_steps.iter().any(|s| {
                    matches!(
                        s.get("type").and_then(|t| t.as_str()),
                        Some("extract") | Some("evaluate") | Some("api_call")
                    )
                });
                let has_working_function = defined_functions.iter().any(|f| {
                    f.get("test_sample")
                        .and_then(|v| v.as_str())
                        .map(|s| !s.trim().is_empty())
                        .unwrap_or(false)
                });
                let nothing_built = deliverables.is_empty()
                    && extracted_data.is_empty()
                    && !has_working_function
                    && !has_recorded_deliverable;
                if nothing_built {
                    // A goal that names data to return MUST return data; a pure-interaction goal
                    // ("just log in") legitimately has none — the model decides, but we make the
                    // omission explicit once so it is a choice, not a slip.
                    if empty_done_nudges < 1 {
                        empty_done_nudges += 1;
                        turns.push(Turn {
                            decision: decision_str,
                            result: "You submitted done with NO deliverables and nothing extracted. If the goal asks for data (a list, a value, a state), extract it first (an extract/evaluate action in \"do\", on the page holding the data) or attach deliverables. Only finish empty if the goal genuinely returns no data.".into(),
                        });
                        continue;
                    }
                }

                // Verify this round's deliverables live; track which VARIABLES verified this round.
                let mut verified_steps: Vec<Value> = Vec::new();
                let mut verified_vars: Vec<String> = Vec::new();
                let mut failures: Vec<(String, String)> = Vec::new(); // (variable, report line)
                for d in &deliverables {
                    let var_of = d
                        .get("variable")
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .unwrap_or("data")
                        .to_string();
                    match verify_deliverable(page, d).await {
                        Ok((step, var, value)) => {
                            done_verified_cache.insert(var.clone(), step.clone());
                            verified_vars.push(var.clone());
                            verified_steps.push(step);
                            extracted_data
                                .insert(var, scrub_value(value, &fill_data, &available_data));
                        }
                        Err(line) => failures.push((var_of, line)),
                    }
                }
                // A failure whose variable ALREADY verified on an earlier done (its value is real and
                // its step is cached) is COVERED — the cached step replays; don't reject over it.
                let uncovered: Vec<String> = failures
                    .iter()
                    .filter(|(var, _)| !done_verified_cache.contains_key(var))
                    .map(|(_, line)| line.clone())
                    .collect();
                // Merge cached steps for variables NOT verified this round (omitted from the
                // resubmission, or resubmitted-and-failed but previously verified) — a step that
                // verified live must never silently vanish from the workflow.
                for (var, step) in &done_verified_cache {
                    if !verified_vars.contains(var) {
                        verified_steps.push(step.clone());
                    }
                }

                if !uncovered.is_empty() && verify_rejects < MAX_VERIFY_REJECTS {
                    verify_rejects += 1;
                    // Keep what verified (values already in extracted_data) but do NOT record any
                    // done-step yet — the model gets the real results and resubmits a consistent done.
                    turns.push(Turn {
                        decision: decision_str,
                        result: format!(
                            "done REJECTED — these deliverables returned NOTHING on the live page:\n{}\nFix the selector/script (probe with evaluate_js first) and submit done again. Verified so far: {}.",
                            uncovered.join("\n"),
                            if extracted_data.is_empty() { "none".into() } else { extracted_data.keys().cloned().collect::<Vec<_>>().join(", ") },
                        ),
                    });
                    continue;
                }

                if !uncovered.is_empty() && verified_steps.is_empty() && extracted_data.is_empty() {
                    // Retries exhausted and nothing real to show: HONEST failure, never a fake pass.
                    report_step(
                        sink,
                        pool,
                        &mut last_kf_hash,
                        step_count as i64,
                        "Could not extract the requested data.",
                        "Stopped",
                        &current_url,
                        "stuck",
                        &screenshot,
                    )
                    .await;
                    return Ok(finish(
                        SessionStatus::Stuck,
                        step_count,
                        "Could not extract the requested data from the site".into(),
                        Some(format!("extraction failed: {}", uncovered.join("; "))),
                        page,
                        &filled_keys,
                        &extracted_data,
                        &mut recorded_steps,
                        &mut orchestration_intents,
                    ));
                }

                recorded_steps.extend(verified_steps);
                prune_dead_navigations(&mut recorded_steps); // deterministic: drop bounced navs
                                                             // FINAL SELF-REVIEW: the agent inspects the workflow it just built and cleans it —
                                                             // remove redundant/duplicate steps, rename cryptic variables — before it is saved.
                                                             // Safe (remove/rename only, guarded), best-effort, once.
                report_step(
                    sink,
                    pool,
                    &mut last_kf_hash,
                    step_count as i64,
                    "Reviewing and cleaning the recorded workflow…",
                    "Reviewing",
                    &current_url,
                    "running",
                    &screenshot,
                )
                .await;
                review_and_clean(
                    &mut recorded_steps,
                    &mut extracted_data,
                    &defined_functions,
                    &cfg.goal,
                    ai_cfg,
                    pool,
                    force_gateway,
                )
                .await;
                prune_dead_navigations(&mut recorded_steps); // re-prune: a removal may leave adjacent navs
                                                             // Drop a navigate that only preceded api_call/login_post steps — those fetch their URL
                                                             // directly, so no positioning navigate is needed (typically after a login: login_post
                                                             // → api_call needs no navigate between). The ENTRY navigate is always kept.
                prune_navigates_before_api_only(&mut recorded_steps);
                prune_dead_navigations(&mut recorded_steps); // a removal above may leave adjacent navs
                report_step(
                    sink,
                    pool,
                    &mut last_kf_hash,
                    step_count as i64,
                    if thought.is_empty() {
                        &summary
                    } else {
                        &thought
                    },
                    "Marked complete",
                    &current_url,
                    "complete",
                    &screenshot,
                )
                .await;
                return Ok(SessionResult {
                    status: SessionStatus::Complete,
                    steps: step_count,
                    message: summary,
                    error: None,
                    result: json!({
                        "current_url": current_url,
                        "filled_fields": filled_keys,
                        "extracted": extracted_data,
                    }),
                    recorded_steps: std::mem::take(&mut recorded_steps),
                    orchestration_intents: std::mem::take(&mut orchestration_intents),
                });
            }

            // ── Act: execute the batch, record replayable steps, feed real results back ──
            _ => {
                let actions = decision
                    .get("do")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                if actions.is_empty() {
                    turns.push(Turn {
                        decision: decision_str,
                        result: "Your act decision had an empty \"do\" array — decide concrete actions, ask, or done.".into(),
                    });
                    continue;
                }

                report_step(
                    sink,
                    pool,
                    &mut last_kf_hash,
                    step_count as i64,
                    &thought,
                    &batch_summary(&actions),
                    &current_url,
                    "running",
                    &screenshot,
                )
                .await;

                let mut lines: Vec<String> = Vec::new();
                let mut any_ok = false;
                let url_before_batch = page.url();
                // Tab count before the batch — a click that opens a new tab is detected by comparing after.
                let tabs_before = context.as_ref().map(|c| c.pages().len()).unwrap_or(0);
                // PROBE→DEFINE ordering: a probe's result only reaches the model NEXT turn, so a
                // define/extract emitted in the SAME batch after a probe was written BLIND — the probe
                // informs nothing (the observed thrash: evaluate_js + define together, define fails,
                // repeat). Defer any deliverable that follows a probe in-batch; the model re-emits it
                // next turn actually informed.
                let mut probed_this_batch = false;
                for action in actions.iter().take(MAX_BATCH_ACTIONS) {
                    let ty = action.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    const PROBES: &[&str] = &[
                        "read_text",
                        "evaluate_js",
                        "inspect",
                        "query_dom",
                        "get_dom",
                        "find_text",
                        "find",
                        "search_dom",
                        "list_candidates",
                        "outline",
                        "repeating",
                        "list_rows",
                        "get_attributes",
                        "attrs",
                        "attributes",
                        "page_outline",
                        "page_map",
                        "outline_page",
                        "list_frames",
                        "frames",
                        "list_iframes",
                        "capture_network",
                        "list_requests",
                        "find_request",
                        "get_request",
                        "inspect_request",
                        "list_tabs",
                        "tabs",
                        "list_files",
                        "list_vault_files",
                        "screenshot",
                        "take_screenshot",
                    ];
                    if PROBES.contains(&ty) {
                        probed_this_batch = true;
                    } else if probed_this_batch
                        && matches!(
                            ty,
                            "define_function" | "extract" | "evaluate" | "api_call" | "login_post"
                        )
                    {
                        lines.push(format!(
                            "{ty} → DEFERRED (not run): you probed earlier in this same batch, so this {ty} was written BLIND — its result could not be informed by the probe. Read the probe results above and emit the {ty} NEXT turn, built from what they actually show."
                        ));
                        continue;
                    }
                    // SCREENSHOT: on-demand vision. The turn text + cleaned DOM are always provided, so a
                    // screenshot is only needed to disambiguate something the DOM can't convey (a visual
                    // layout, a rendered chart, which control is highlighted). This flags the just-captured
                    // JPEG to ride along with the NEXT turn's observation. Read-only; not a workflow step.
                    if ty == "screenshot" || ty == "take_screenshot" {
                        if screenshot.is_empty() {
                            lines.push(
                                "screenshot → could not capture a frame of this page.".into(),
                            );
                        } else {
                            send_screenshot = true;
                            any_ok = true;
                            lines.push("screenshot → captured; the image is attached to your NEXT observation. Use it to read what the DOM couldn't tell you, then continue.".into());
                        }
                        continue;
                    }
                    // LIST_TABS: the agent's OWN open tabs (this session's context only) — index, url,
                    // title, and which is active. How it "sees its own tab context". Read-only.
                    if ty == "list_tabs" || ty == "tabs" {
                        if let Some(ctx) = &context {
                            let pages = ctx.pages();
                            let active_url = active_page.url();
                            let mut tab_lines = Vec::new();
                            for (i, p) in pages.iter().enumerate() {
                                let url = p.url();
                                let title = p.title().await.unwrap_or_default();
                                let mark = if url == active_url { " (ACTIVE)" } else { "" };
                                tab_lines.push(format!(
                                    "  [{i}]{mark} {} — {}",
                                    truncate(&title, 40),
                                    truncate(&url, 90)
                                ));
                            }
                            any_ok = true;
                            lines.push(format!(
                                "list_tabs → {} open:\n{}",
                                pages.len(),
                                tab_lines.join("\n")
                            ));
                        } else {
                            lines.push("list_tabs → no browser context available".into());
                        }
                        continue;
                    }
                    // SWITCH_TAB: make another of the agent's tabs active (by index from list_tabs, or the
                    // NEWEST). Rebinds `active_page` (effect lands next turn) and RECORDS a switch_tab step
                    // so replay switches too. This is how the agent moves into a tab a click opened.
                    if ty == "switch_tab" {
                        if let Some(ctx) = &context {
                            let pages = ctx.pages();
                            let idx = action
                                .get("tab_index")
                                .or_else(|| action.get("index"))
                                .and_then(|v| v.as_u64())
                                .map(|n| n as usize)
                                .unwrap_or_else(|| pages.len().saturating_sub(1));
                            if let Some(target) = pages.get(idx) {
                                let _ = target.bring_to_front().await;
                                navigation::wait_for_page_quiet(target, Duration::from_secs(8))
                                    .await;
                                active_page = target.clone();
                                recorded_steps.push(json!({ "type": "switch_tab", "enabled": true, "config": { "tab_index": idx } }));
                                any_ok = true;
                                lines.push(format!("switch_tab → now on tab [{idx}]: {} (recorded). Observe it next turn.", truncate(&target.url(), 90)));
                            } else {
                                lines.push(format!("switch_tab → no tab at index {idx} (there are {} tabs; use list_tabs)", pages.len()));
                            }
                        } else {
                            lines.push("switch_tab → no browser context available".into());
                        }
                        continue;
                    }
                    // LIST_FILES: the user's file vault — so the agent knows what CAN be uploaded and can
                    // reference a file / propose a slot. Read-only.
                    if ty == "list_files" || ty == "list_vault_files" {
                        match crate::local::store::stored_files::list(pool, Some(30)).await {
                            Ok(files) if !files.is_empty() => {
                                let flines: Vec<String> = files
                                    .iter()
                                    .map(|f| format!("  {} — {} ({} bytes, {})", f.id, truncate(&f.filename, 50), f.size_bytes, f.content_type))
                                    .collect();
                                any_ok = true;
                                lines.push(format!("list_files → {} in the vault:\n{}", files.len(), flines.join("\n")));
                            }
                            Ok(_) => lines.push("list_files → the vault is empty. An upload step declares a file_slot the user fills at run time; you don't need a file now.".into()),
                            Err(e) => lines.push(format!("list_files → error: {e}")),
                        }
                        continue;
                    }
                    // DEFINE_FUNCTION: the candidate script/selector is tested on the CURRENT live
                    // page RIGHT NOW — before anything is appended anywhere. Real data ⇒ noted as a
                    // function intent (materialized after the run, no re-run needed: it was tested
                    // here); no data ⇒ the real result comes back as feedback, nothing is defined.
                    if ty == "define_function" {
                        let fn_name = action
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .trim()
                            .to_string();
                        let fn_type = action
                            .get("fn_type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("script")
                            .to_string();
                        if fn_name.is_empty()
                            || !fn_name
                                .chars()
                                .all(|c| c.is_ascii_alphanumeric() || c == '_')
                        {
                            lines.push(
                                "define_function → ERROR: name must be alphanumeric+underscore"
                                    .into(),
                            );
                            continue;
                        }
                        // An EXISTING function of this name: identical substance ⇒ true no-op (skip,
                        // no re-test); different code/selector ⇒ this is a CORRECTION — retest below
                        // and REPLACE the prior definition in place (never a second variant).
                        let prior = defined_functions.iter().find(|f| {
                            f.get("name").and_then(|n| n.as_str()) == Some(fn_name.as_str())
                        });
                        if let Some(p) = prior {
                            // "Identical" is backing-aware: an api function is the same only when its
                            // endpoint/method/headers/body match; a DOM function only when its code/
                            // selector match. A DIFFERENT backing (script↔api) is never "identical", so
                            // it falls through to re-test and REPLACE the prior definition in place.
                            let same = if fn_type == "api" {
                                p.get("url") == action.get("url")
                                    && p.get("method") == action.get("method")
                                    && p.get("headers") == action.get("headers")
                                    && p.get("body") == action.get("body")
                            } else {
                                p.get("code") == action.get("code")
                                    && p.get("selector") == action.get("selector")
                            };
                            if same {
                                lines.push(format!("define_function {fn_name} → already defined (identical); move on"));
                                continue;
                            }
                        }
                        // Per-name failure cap: stop the "re-emit a new selector variant forever" thrash.
                        if def_fail_counts.get(&fn_name).copied().unwrap_or(0) >= MAX_DEFINE_FAILS {
                            if prior.is_some() {
                                lines.push(format!("define_function {fn_name} → it already returned real data earlier and further edits keep failing — KEEP the working version, stop re-emitting {fn_name}, move on."));
                            } else {
                                lines.push(format!("define_function {fn_name} → STOP: {MAX_DEFINE_FAILS} attempts all failed to return data. Do NOT re-emit {fn_name} again — move on to the other capabilities, or if it was the last one, finish and report that {fn_name} could not be extracted."));
                            }
                            continue;
                        }
                        let is_correction = prior.is_some();
                        // API-BACKED function: the canonical unit for a capability whose data comes from
                        // the site's JSON endpoint. Tested with a REAL request live (reusing the session's
                        // cookies/auth), recorded as a replayable api_call step keyed by the function name
                        // — so the workflow itself does the fetch, and switching a DOM function to this
                        // (same name) REPLACES it in place (no duplicate, no oscillation). The auth header's
                        // {{login_key}} resolves from the vault at replay.
                        if fn_type == "api" {
                            match run_api_call(page, action, &fill_data, &fn_name).await {
                                Ok(value) => {
                                    any_ok = true;
                                    def_fail_counts.remove(&fn_name);
                                    let scrubbed = scrub_value(value, &fill_data, &available_data);
                                    // Record the data this function returned into the session's extracted
                                    // set — this is what the mission's got_data / test_result reads. Without
                                    // it a build that defined WORKING api functions looked like "no data",
                                    // so the planner re-ran discovery and OVERWROTE the good api_call
                                    // workflow with a broken DOM one. A working define IS a deliverable.
                                    extracted_data.insert(fn_name.clone(), scrubbed.clone());
                                    let sample = truncate(&scrubbed.to_string(), 300);
                                    let mut intent = serde_json::Map::new();
                                    intent.insert("kind".into(), json!("function"));
                                    intent.insert("name".into(), json!(fn_name));
                                    intent.insert("fn_type".into(), json!("api"));
                                    for k in [
                                        "url",
                                        "method",
                                        "headers",
                                        "body",
                                        "description",
                                        "input_variables",
                                        "output_fields",
                                    ] {
                                        if let Some(v) = action.get(k) {
                                            intent.insert(k.to_string(), v.clone());
                                        }
                                    }
                                    intent.insert("test_sample".into(), json!(sample));
                                    let intent = Value::Object(intent);
                                    upsert_by_name(
                                        &mut defined_functions,
                                        &fn_name,
                                        intent.clone(),
                                    );
                                    upsert_fn_intent(&mut orchestration_intents, &fn_name, intent);
                                    // Record the replayable api_call step with REPLAY spelling ({{secret:…}})
                                    // in url/headers/body, keyed by the function name (upsert replaces any
                                    // prior DOM step for this capability).
                                    let step =
                                        build_api_call_step(action, &fn_name, &record_templates);
                                    upsert_extract_step(&mut recorded_steps, step, &fn_name);
                                    lines.push(format!(
                                        "define_function {fn_name} (api) → {} live (recorded as an api_call step), returned {sample}",
                                        if is_correction { "CORRECTED (replaced), tested" } else { "TESTED" }
                                    ));
                                }
                                Err((auth, msg)) => {
                                    *def_fail_counts.entry(fn_name.clone()).or_insert(0) += 1;
                                    let n = api_fail_counts.entry(fn_name.clone()).or_insert(0);
                                    *n += 1;
                                    if auth {
                                        // Only a REAL 401/403 counts toward disabling the API — and only
                                        // after two of them (the first may just be a bad/unresolvable
                                        // header the agent then fixes by dropping it).
                                        api_auth_fail_count += 1;
                                        if api_auth_fail_count >= 2 {
                                            api_auth_failed = true;
                                        }
                                        if *n >= 2 {
                                            lines.push(format!("define_function {fn_name} (api) → REJECTED again ({msg}). This endpoint will NOT authenticate at replay (it needs a token minted at sign-in, not a static secret). STOP retrying the API for {fn_name} — define it from the DOM instead: fn_type:\"list\" over the rendered rows on this page (that data IS on screen now)."));
                                        } else {
                                            lines.push(format!("define_function {fn_name} (api) → NOT defined: {msg}. Try once WITHOUT an Authorization header (the in-page fetch reuses the session cookies from your sign-in). If it still gets 401/403, define {fn_name} from the DOM instead (fn_type:\"list\")."));
                                        }
                                    } else {
                                        // NOT an auth problem — wrong endpoint/params or empty data. The
                                        // API stays available; steer to finding the right request.
                                        lines.push(format!("define_function {fn_name} (api) → NOT defined: {msg}. This is NOT an auth problem — the endpoint responded but not with the data. Use list_requests / get_request to find the RIGHT endpoint and its exact URL+params (the API itself still works)."));
                                    }
                                }
                            }
                            continue;
                        }
                        // fn_type "list": GENERATE the extraction JS from the structured {row_selector,
                        // fields} spec so the model never hand-writes escape-prone JS. From here it flows
                        // through the SAME test-and-record path as a script (tested live, corrected in
                        // place). This is the reliable "create the good one directly" route for lists.
                        let generated;
                        let (action, fn_type): (&Value, String) = if fn_type == "list" {
                            let row = action
                                .get("row_selector")
                                .or_else(|| action.get("selector"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .trim()
                                .to_string();
                            if row.is_empty() {
                                lines.push(format!("define_function {fn_name} → ERROR: fn_type \"list\" needs \"row_selector\" (the repeating row) plus \"fields\" (name → sub-selector). Run list_candidates / inspect to get the row selector."));
                                continue;
                            }
                            let code = build_list_extract_script(
                                &row,
                                action.get("fields").unwrap_or(&Value::Null),
                            );
                            let mut a = action.clone();
                            if let Some(o) = a.as_object_mut() {
                                o.insert("code".into(), json!(code));
                                o.insert("fn_type".into(), json!("script"));
                            }
                            generated = a;
                            (&generated, "script".to_string())
                        } else {
                            (action, fn_type)
                        };
                        // Reject a fetch/storage script BEFORE testing — it passes live (storage is
                        // populated now) but is unauthorized/empty at replay. Steer to api_call.
                        if fn_type == "script" {
                            if let Some(hazard) = script_replay_hazard(
                                action.get("code").and_then(|v| v.as_str()).unwrap_or(""),
                            ) {
                                lines.push(format!(
                                    "define_function {fn_name} → NOT defined: {hazard}"
                                ));
                                continue;
                            }
                        }
                        // Reuse the deliverable verifier: script→evaluate / extraction→extract shape.
                        let probe = if fn_type == "extraction" {
                            json!({ "type": "extract", "selector": action.get("selector").cloned().unwrap_or(Value::Null), "variable": fn_name })
                        } else {
                            json!({ "type": "evaluate", "script": action.get("code").cloned().unwrap_or(Value::Null), "variable": fn_name })
                        };
                        match verify_deliverable(page, &probe).await {
                            Ok((_step, _var, value))
                                if fn_type == "script"
                                    && code_hardcodes_returned_data(
                                        action.get("code").and_then(|v| v.as_str()).unwrap_or(""),
                                        &value,
                                    ) =>
                            {
                                // Returned real data, but the script has the specific items BAKED IN
                                // — it would break when the data changes. Reject with the fix.
                                let sample = truncate(
                                    &scrub_value(value, &fill_data, &available_data).to_string(),
                                    200,
                                );
                                *def_fail_counts.entry(fn_name.clone()).or_insert(0) += 1;
                                lines.push(format!("define_function {fn_name} → NOT defined: the script HARDCODES the items it returns ({sample}) instead of discovering them from the page. Query the repeating rows with document.querySelectorAll (a stable row/card selector) and read each element's fields — never embed the names/values you see. Re-emit a structural version."));
                            }
                            Ok((_step, _var, value)) => {
                                any_ok = true;
                                def_fail_counts.remove(&fn_name);
                                let scrubbed = scrub_value(value, &fill_data, &available_data);
                                // The function's data IS a deliverable — record it into the session's
                                // extracted set so the mission sees the build succeeded (else it re-runs
                                // discovery and overwrites this working workflow). See the api arm above.
                                extracted_data.insert(fn_name.clone(), scrubbed.clone());
                                let sample = truncate(&scrubbed.to_string(), 300);
                                let mut intent = serde_json::Map::new();
                                intent.insert("kind".into(), json!("function"));
                                intent.insert("name".into(), json!(fn_name));
                                intent.insert(
                                    "fn_type".into(),
                                    json!(if fn_type == "extraction" {
                                        "extraction"
                                    } else {
                                        "script"
                                    }),
                                );
                                if let Some(c) = action.get("code").and_then(|v| v.as_str()) {
                                    intent.insert(
                                        "code".into(),
                                        json!(super::brain::sanitize_js_script(c)),
                                    );
                                }
                                if let Some(sel) = action.get("selector").and_then(|v| v.as_str()) {
                                    intent.insert("selector".into(), json!(sel));
                                }
                                for k in ["description", "input_variables", "output_fields"] {
                                    if let Some(v) = action.get(k) {
                                        intent.insert(k.to_string(), v.clone());
                                    }
                                }
                                intent.insert("test_sample".into(), json!(sample));
                                intent.insert("url".into(), json!(page.url()));
                                let intent = Value::Object(intent);
                                // Upsert by NAME in BOTH lists — a correction replaces the prior
                                // definition (the materializer skips same-name intents, so appending
                                // a corrected duplicate would let the WRONG first one win).
                                upsert_by_name(&mut defined_functions, &fn_name, intent.clone());
                                upsert_fn_intent(&mut orchestration_intents, &fn_name, intent);
                                // ALSO record the extraction as a WORKFLOW STEP (keyed by the function
                                // name) at THIS position — so the workflow itself returns this dataset
                                // when run (symmetry: every defined function leaves a step, exactly
                                // like an inline extract does), replaying after the navigate that got
                                // us here. Upsert so a correction updates it in place.
                                let step = if fn_type == "extraction" {
                                    json!({ "type": "extract", "enabled": true, "config": { "selector": action.get("selector").cloned().unwrap_or(Value::Null), "variable": fn_name } })
                                } else {
                                    json!({ "type": "evaluate", "enabled": true, "config": { "script": super::brain::sanitize_js_script(action.get("code").and_then(|v| v.as_str()).unwrap_or("")), "variable": fn_name } })
                                };
                                upsert_extract_step(&mut recorded_steps, step, &fn_name);
                                lines.push(format!(
                                    "define_function {fn_name} → {} on the live page (also recorded as a workflow step), returned {sample}",
                                    if is_correction { "CORRECTED (replaced), tested" } else { "TESTED" }
                                ));
                            }
                            Err(err_line) => {
                                *def_fail_counts.entry(fn_name.clone()).or_insert(0) += 1;
                                lines.push(format!("define_function {fn_name} → NOT defined: {err_line}. Do NOT guess another selector — run {{\"type\":\"list_candidates\"}} to get the repeating row selector, then {{\"type\":\"inspect\",\"selector\":\"<that>\"}} to see a row's inner fields, THEN re-emit the script mapping over that exact selector."));
                            }
                        }
                        continue;
                    }
                    // CAPTURE_NETWORK probe: reload the page so its data-loading XHR/fetch calls fire,
                    // then surface the freshly captured backend calls. NOT recorded (a probe) — the
                    // agent uses what it learns to build an api_call. Discovering the JSON endpoint is
                    // how it extracts robustly instead of scraping the DOM.
                    if ty == "capture_network" {
                        if let Some(net) = &network {
                            let before = net.lock().await.get_all_calls().len();
                            let _ = navigation::reload(page, Duration::from_secs(25)).await;
                            navigation::wait_for_page_quiet(page, Duration::from_secs(8)).await;
                            let cap = net.lock().await;
                            let all = cap.get_all_calls();
                            let fresh: Vec<&crate::models::network::NetworkCall> =
                                all.iter().skip(before.min(all.len())).collect();
                            let shown: Vec<&crate::models::network::NetworkCall> =
                                if fresh.is_empty() {
                                    all.iter()
                                        .rev()
                                        .take(20)
                                        .collect::<Vec<_>>()
                                        .into_iter()
                                        .rev()
                                        .collect()
                                } else {
                                    fresh
                                };
                            let block = scrub_credentials(
                                &cap.format_for_prompt(&shown, &fill_data),
                                &fill_data,
                                &available_data,
                            );
                            any_ok = true;
                            lines.push(format!(
                                "capture_network → reloaded; backend calls:\n{block}"
                            ));
                        } else {
                            lines.push(
                                "capture_network → network capture is unavailable this run".into(),
                            );
                        }
                        continue;
                    }
                    // LIST_REQUESTS: search the captured backend calls (filter by url substring / method)
                    // — the agent finds WHICH endpoint returns the data it wants. Read-only.
                    if ty == "list_requests" || ty == "find_request" {
                        if let Some(net) = &network {
                            let filter = action
                                .get("url")
                                .and_then(|v| v.as_str())
                                .or_else(|| action.get("filter").and_then(|v| v.as_str()))
                                .unwrap_or("")
                                .trim()
                                .to_lowercase();
                            let method_filter = action
                                .get("method")
                                .and_then(|v| v.as_str())
                                .map(|m| m.to_uppercase());
                            let cap = net.lock().await;
                            let matches: Vec<&crate::models::network::NetworkCall> = cap
                                .get_all_calls()
                                .iter()
                                .filter(|c| {
                                    (filter.is_empty() || c.url.to_lowercase().contains(&filter))
                                        && method_filter
                                            .as_ref()
                                            .map(|m| &c.method == m)
                                            .unwrap_or(true)
                                })
                                .collect();
                            if matches.is_empty() {
                                lines.push(format!("list_requests → no captured request matches (url~{filter:?}). Run capture_network first to record the page's calls."));
                            } else {
                                let n = matches.len();
                                let shown: Vec<&crate::models::network::NetworkCall> = matches
                                    .iter()
                                    .rev()
                                    .take(30)
                                    .cloned()
                                    .collect::<Vec<_>>()
                                    .into_iter()
                                    .rev()
                                    .collect();
                                let block = scrub_credentials(
                                    &cap.format_for_prompt(&shown, &fill_data),
                                    &fill_data,
                                    &available_data,
                                );
                                any_ok = true;
                                lines.push(format!("list_requests → {n} match(es):\n{block}\n(use get_request with a url substring to see one endpoint's FULL response body)"));
                            }
                        } else {
                            lines.push(
                                "list_requests → network capture unavailable this run".into(),
                            );
                        }
                        continue;
                    }
                    // GET_REQUEST: the FULL detail of one captured call (method, status, request header
                    // NAMES, request body, and the WHOLE response body) — this is how the agent reads the
                    // exact JSON shape to build a correct api_call / output_fields. Read-only.
                    if ty == "get_request" || ty == "inspect_request" {
                        if let Some(net) = &network {
                            let want = action
                                .get("url")
                                .and_then(|v| v.as_str())
                                .or_else(|| action.get("match").and_then(|v| v.as_str()))
                                .unwrap_or("")
                                .trim();
                            if want.is_empty() {
                                lines.push("get_request → ERROR: provide \"url\" (a substring of the endpoint to inspect)".into());
                                continue;
                            }
                            let cap = net.lock().await;
                            let hit = cap
                                .get_all_calls()
                                .iter()
                                .rev()
                                .find(|c| c.url.contains(want));
                            match hit {
                                Some(c) => {
                                    let req_hdrs: Vec<String> = c.request_headers.as_ref()
                                        .map(|h| h.keys().cloned().collect()).unwrap_or_default();
                                    let detail = format!(
                                        "get_request {url}\n  method: {method}\n  status: {status}\n  request headers: {hdrs}\n  request body: {reqbody}\n  RESPONSE body:\n{resp}",
                                        url = c.url,
                                        method = c.method,
                                        status = c.response_status.map(|s| s.to_string()).unwrap_or_else(|| "?".into()),
                                        hdrs = if req_hdrs.is_empty() { "(none)".into() } else { req_hdrs.join(", ") },
                                        reqbody = c.request_body.as_deref().map(|b| truncate(b, 500)).unwrap_or_else(|| "(none)".into()),
                                        resp = c.response_body.as_deref().map(|b| truncate(b, 3000)).unwrap_or_else(|| "(no body captured)".into()),
                                    );
                                    any_ok = true;
                                    lines.push(scrub_credentials(&detail, &fill_data, &available_data));
                                }
                                None => lines.push(format!("get_request → no captured request URL contains {want:?} (run capture_network, or widen the match / check list_requests)")),
                            }
                        } else {
                            lines.push("get_request → network capture unavailable this run".into());
                        }
                        continue;
                    }
                    // API_CALL deliverable: call the site's backend directly (in-page fetch, reuses the
                    // live session's cookies/auth), extract the JSON, and record a replayable api_call
                    // step. Upserts by variable like extract. Far more robust than DOM scraping.
                    if ty == "api_call" {
                        let var = action
                            .get("variable")
                            .and_then(|v| v.as_str())
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .unwrap_or("data")
                            .to_string();
                        match run_api_call(page, action, &fill_data, &var).await {
                            Ok(value) => {
                                any_ok = true;
                                let shown = truncate(
                                    &scrub_value(value.clone(), &fill_data, &available_data)
                                        .to_string(),
                                    300,
                                );
                                extracted_data.insert(
                                    var.clone(),
                                    scrub_value(value, &fill_data, &available_data),
                                );
                                // Record the step with REPLAY spelling ({{secret:...}}) in url/headers/body.
                                let step = build_api_call_step(action, &var, &record_templates);
                                let replaced = upsert_extract_step(&mut recorded_steps, step, &var);
                                lines.push(format!(
                                    "api_call {var} → {}, returned {shown}",
                                    if replaced {
                                        "corrected in place"
                                    } else {
                                        "recorded"
                                    }
                                ));
                            }
                            Err((auth, msg)) => {
                                if auth {
                                    api_auth_fail_count += 1;
                                    if api_auth_fail_count >= 2 {
                                        api_auth_failed = true;
                                    }
                                    lines.push(format!("api_call {var} → REJECTED ({msg}) — try WITHOUT an Authorization header (cookies from your sign-in are sent automatically), or read this data from the DOM"));
                                } else {
                                    lines.push(format!("api_call {var} → FAILED: {msg} — not an auth problem; use list_requests / get_request to find the right endpoint+params"));
                                }
                            }
                        }
                        continue;
                    }
                    // LOGIN_POST: replay the sign-in as a single request instead of the DOM form. Tested
                    // live now; on success it REPLACES the recorded fill/click login steps with this one
                    // POST (navigate → login_post → data). The in-page fetch sets the session cookie, so
                    // the api_calls after it authenticate with no header — the leanest API build.
                    if matches!(
                        ty,
                        "login_post" | "login_via_post" | "post_login" | "replay_login"
                    ) {
                        if login_post_off {
                            lines.push("login_post → OFF for this site (it was rejected twice — the sign-in needs a token you don't hold, or the credentials failed). Keep the DOM login you already recorded; do not emit login_post again.".into());
                            continue;
                        }
                        match run_login_post(page, action, &fill_data).await {
                            Ok(status) => {
                                any_ok = true;
                                let step = build_login_post_step(action, &record_templates);
                                let removed = strip_dom_login_and_insert(&mut recorded_steps, step);
                                login_post_off = true; // sign-in is replayed once; no second login step
                                lines.push(format!(
                                    "login_post → OK (HTTP {status}); replaced {removed} recorded DOM login step(s) with one sign-in request. The workflow now authenticates without the form, and api_calls after it reuse the session cookie. Do NOT log in via the form again — continue to the data."
                                ));
                            }
                            Err((auth, msg)) => {
                                login_post_fail_count += 1;
                                if login_post_fail_count >= 2 {
                                    login_post_off = true;
                                }
                                let tail = if login_post_off {
                                    "Stop trying login_post — keep the DOM login you already recorded and continue to the data."
                                } else if auth {
                                    "Re-check the body + Content-Type against get_request (exact field names, exact encoding). If the body needs a csrf/nonce/authenticity_token you don't hold, keep the DOM login instead."
                                } else {
                                    "Verify the url/method/body/Content-Type via get_request, or keep the DOM login."
                                };
                                lines.push(format!(
                                    "login_post → {} ({msg}). {tail}",
                                    if auth { "REJECTED" } else { "FAILED" }
                                ));
                            }
                        }
                        continue;
                    }
                    // INLINE extraction: runs on the CURRENT page, verified immediately, recorded AT
                    // THIS POSITION in the workflow — so navigate→extract→navigate→extract replays in
                    // order (multi-page goals). Only a deliverable that returned REAL data records.
                    if ty == "extract" || ty == "evaluate" {
                        // A fetch/storage script passes the LIVE test but breaks at replay — reject
                        // before it can green-light (static check, not test-based).
                        if ty == "evaluate" {
                            if let Some(hazard) = script_replay_hazard(
                                action.get("script").and_then(|v| v.as_str()).unwrap_or(""),
                            ) {
                                lines.push(format!("evaluate → NOT recorded: {hazard}"));
                                continue;
                            }
                        }
                        match verify_deliverable(page, action).await {
                            Ok((step, var, value)) => {
                                any_ok = true;
                                let shown = truncate(
                                    &scrub_value(value.clone(), &fill_data, &available_data)
                                        .to_string(),
                                    300,
                                );
                                extracted_data.insert(
                                    var.clone(),
                                    scrub_value(value, &fill_data, &available_data),
                                );
                                // UPSERT by variable: re-emitting an extraction is a CORRECTION, not a
                                // new deliverable — replace the existing step for this variable IN
                                // PLACE (same position) instead of appending a duplicate. Only a
                                // brand-new variable appends.
                                let replaced = upsert_extract_step(&mut recorded_steps, step, &var);
                                lines.push(format!(
                                    "{ty} {var} → {}, returned {shown}",
                                    if replaced {
                                        "corrected in place"
                                    } else {
                                        "recorded"
                                    }
                                ));
                            }
                            Err(line) => {
                                lines.push(format!(
                                    "{line} — NOT recorded; fix and retry (probe with evaluate_js)"
                                ));
                            }
                        }
                        continue;
                    }
                    let (line, ok, recorded) =
                        execute_explorer_action(page, action, &fill_data, &record_templates).await;
                    if ok {
                        any_ok = true;
                        if let Some(mut step) = recorded {
                            // Track filled placeholder keys so the prompt can mark them done.
                            if let Some(v) = action.get("value").and_then(|v| v.as_str()) {
                                for k in fill_data.keys() {
                                    if v.contains(&format!("{{{{{k}}}}}"))
                                        && !filled_keys.contains(k)
                                    {
                                        filled_keys.push(k.clone());
                                    }
                                }
                                // Tag a credential fill so a later login_post can locate + replace the DOM
                                // login block. Marker is stripped from every persisted path (prune).
                                let stype = step.get("type").and_then(|t| t.as_str()).unwrap_or("");
                                if matches!(stype, "fill" | "select")
                                    && value_references_credential(v, &available_data, &fill_data)
                                {
                                    if let Some(obj) = step.as_object_mut() {
                                        obj.insert("_auth_fill".into(), json!(true));
                                    }
                                }
                            }
                            recorded_steps.push(step);
                        }
                    }
                    // Scrub any credential value that echoed into the result (a probe reading a
                    // just-filled input, an error message quoting a value) BEFORE it can reach the
                    // model thread or the persisted history.
                    lines.push(scrub_credentials(&line, &fill_data, &available_data));
                    // The page changed under us (navigate or a page-changing click): stop the
                    // batch so the next turn decides on a FRESH observation.
                    if page.url() != url_before_batch {
                        lines.push("(page changed — remaining batch actions skipped; observe the new page)".into());
                        break;
                    }
                }
                // NEW TAB opened during the batch (a click with target=_blank / window.open). Switch to
                // it automatically, record a wait_for_tab step so replay follows it too, and tell the
                // agent — so a "click a button that opens a tab" flow just works. Scoped to this session's
                // own context, so only the agent's own tabs are ever considered.
                if let Some(ctx) = &context {
                    let pages = ctx.pages();
                    if pages.len() > tabs_before {
                        if let Some(newest) = pages.last() {
                            let _ = newest.bring_to_front().await;
                            navigation::wait_for_page_quiet(newest, Duration::from_secs(8)).await;
                            let new_url = newest.url();
                            active_page = newest.clone();
                            recorded_steps.push(
                                json!({ "type": "wait_for_tab", "enabled": true, "config": {} }),
                            );
                            lines.push(format!(
                                "A NEW TAB opened and is now ACTIVE: {} (recorded wait_for_tab so replay follows it). Observe it next turn; use switch_tab to go back to a previous tab.",
                                truncate(&new_url, 90)
                            ));
                        }
                    }
                }
                // Surface the batch OUTCOME to the live preview in real time —
                // SAME step number, so the panel merges it into the step it
                // just showed as "running": the step turns red with the first
                // failure line, or green when the whole batch landed. WS-only
                // (send_thought, not report_step): outcomes must not double
                // the persisted replay's step list.
                if let Some(s) = sink {
                    let failures: Vec<&String> = lines
                        .iter()
                        .filter(|l| {
                            l.contains("ERROR") || l.contains("FAILED") || l.contains("REJECTED")
                        })
                        .collect();
                    if !failures.is_empty() {
                        let th = truncate(failures[0], 180);
                        let act = format!("{} action(s) failed — adjusting", failures.len());
                        s.sender
                            .send_thought(step_count as i64, &th, &act, &page.url(), "error");
                        if let Some(m) = &s.mirror {
                            m.send_thought(step_count as i64, &th, &act, &page.url(), "error");
                        }
                    } else if any_ok {
                        s.sender
                            .send_thought(step_count as i64, "", "ok", &page.url(), "success");
                        if let Some(m) = &s.mirror {
                            m.send_thought(step_count as i64, "", "ok", &page.url(), "success");
                        }
                    }
                }
                action_failure_streak = if any_ok { 0 } else { action_failure_streak + 1 };
                if action_failure_streak >= MAX_ACTION_FAILURE_STREAK {
                    return Ok(finish(
                        SessionStatus::Stuck,
                        step_count,
                        "Every action kept failing".into(),
                        Some(format!("repeated action failures: {}", lines.join("; "))),
                        page,
                        &filled_keys,
                        &extracted_data,
                        &mut recorded_steps,
                        &mut orchestration_intents,
                    ));
                }
                debug_append(
                    &debug_path,
                    &format!("\n### RESULTS\n\n{}\n", lines.join("\n")),
                )
                .await;
                turns.push(Turn {
                    decision: decision_str,
                    result: format!("RESULTS:\n{}", lines.join("\n")),
                });
                // Let the page settle after interaction before the next observation. A click that
                // CHANGED the page (SPA route, submit) gets a real network-idle wait so the next
                // observation isn't a half-loaded page; same-page interactions just settle briefly.
                if page.url() != url_before_batch {
                    navigation::wait_for_page_quiet(page, Duration::from_secs(8)).await;
                }
                tokio::time::sleep(Duration::from_millis(400)).await;
            }
        }
    }

    Ok(finish(
        SessionStatus::MaxSteps,
        step_count,
        format!("Reached max steps ({max_steps})"),
        None,
        &active_page,
        &filled_keys,
        &extracted_data,
        &mut recorded_steps,
        &mut orchestration_intents,
    ))
}

/// Assemble a terminal [`SessionResult`] with the standard result payload.
#[allow(clippy::too_many_arguments)]
fn finish(
    status: SessionStatus,
    steps: u32,
    message: String,
    error: Option<String>,
    page: &Page,
    filled_keys: &[String],
    extracted: &serde_json::Map<String, Value>,
    recorded_steps: &mut Vec<Value>,
    orchestration_intents: &mut Vec<Value>,
) -> SessionResult {
    prune_dead_navigations(recorded_steps);
    SessionResult {
        status,
        steps,
        message,
        error,
        result: json!({
            "current_url": page.url(),
            "filled_fields": filled_keys,
            "extracted": extracted,
        }),
        recorded_steps: std::mem::take(recorded_steps),
        orchestration_intents: std::mem::take(orchestration_intents),
    }
}

/// System prompt for the final self-review: constrained to a remove/rename CLEAN spec (no arbitrary
/// rewrites — those would risk breaking replay).
const REVIEW_SYSTEM: &str = r##"You just finished building a browser workflow. REVIEW the recorded steps and return a small CLEAN spec so the saved workflow is tidy and correct. Reply with EXACTLY ONE JSON object — no prose:
{"remove":[<step indices to DELETE>], "rename":{"<old variable>":"<new clean variable>"}, "reason":"<short>"}

What to clean:
- REMOVE a navigation that is redundant (the same page navigated to again, or a page that is navigated away from without anything using it).
- REMOVE a DUPLICATE extraction: if two steps extract the SAME data (e.g. one variable "targets" and another "get_targets_list" returning the same list), keep ONE and remove the other — prefer the one with the cleaner variable name.
- RENAME cryptic extraction variables to clean, caller-friendly names: get_targets_list → targets, get_workflows_list → workflows, fn_test → drop it. A workflow's data columns come from these names, so make them clean nouns.

Rules:
- NEVER remove a login step (fill / click / select / check / press) or the very first navigate — the workflow must still log in and reach its pages.
- Keep exactly ONE extraction per dataset and the navigations needed to reach each.
- If it is already clean, return {"remove":[],"rename":{}}.
- Indices are the [i] shown. Reply with ONLY the JSON object."##;

/// Final self-review: the agent inspects the workflow it just recorded and returns a small CLEAN
/// spec — step indices to REMOVE (dead/duplicate) and variable RENAMES (cryptic → clean). Applied
/// with guards: never removes an interaction/login step or the entry navigate; renames only touch
/// extraction variables + the extracted-data keys. Best-effort — an AI/parse failure leaves the
/// workflow as the deterministic prune left it.
async fn review_and_clean(
    recorded_steps: &mut Vec<Value>,
    extracted_data: &mut serde_json::Map<String, Value>,
    defined_functions: &[Value],
    goal: &str,
    ai_cfg: &AiConfig,
    pool: &SqlitePool,
    force_gateway: bool,
) {
    use crate::models::ai::{AiMessage, AiMessageContent};
    if recorded_steps.len() < 3 {
        return; // nothing to clean in a login-only workflow
    }
    let listing = recorded_steps
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let ty = s.get("type").and_then(|t| t.as_str()).unwrap_or("step");
            let detail = s
                .pointer("/config/url")
                .and_then(|v| v.as_str())
                .or_else(|| s.pointer("/config/variable").and_then(|v| v.as_str()))
                .or_else(|| s.pointer("/config/selector").and_then(|v| v.as_str()))
                .unwrap_or("");
            format!("  {i}. {ty} {}", truncate(detail, 90))
        })
        .collect::<Vec<_>>()
        .join("\n");
    let fns = defined_functions
        .iter()
        .filter_map(|f| f.get("name").and_then(|n| n.as_str()))
        .collect::<Vec<_>>()
        .join(", ");
    let user = format!(
        "GOAL: {goal}\n\nRECORDED WORKFLOW STEPS:\n{listing}\n\nDEFINED FUNCTIONS: {}\n\nReturn the CLEAN spec now.",
        if fns.is_empty() { "(none)".to_string() } else { fns }
    );
    let messages = vec![AiMessage {
        role: "user".into(),
        content: AiMessageContent::Text(user),
    }];
    let completion =
        match provider::complete_with_gateway_pref(pool, ai_cfg, &messages, Some(REVIEW_SYSTEM), 800, "agent", force_gateway)
            .await
        {
            Ok(c) => c,
            Err(_) => return,
        };
    let Some(decision) = super::brain::parse_decision(&completion.text) else {
        return;
    };
    apply_clean_spec(recorded_steps, extracted_data, &decision);
}

/// Apply a review CLEAN spec (`{remove:[i…], rename:{old:new}}`) to the recorded steps + extracted
/// data, WITH GUARDS: never removes an interaction/login step (fill/click/select/check/press/type)
/// or the entry navigate (index 0); renames only alphanumeric+underscore names, on extraction step
/// variables and the extracted-data keys. Pure + deterministic (unit-tested).
fn apply_clean_spec(
    recorded_steps: &mut Vec<Value>,
    extracted_data: &mut serde_json::Map<String, Value>,
    decision: &Value,
) {
    const PROTECTED: &[&str] = &["fill", "click", "select", "check", "press", "type"];
    let mut remove: Vec<usize> = decision
        .get("remove")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_u64().map(|n| n as usize))
                .collect()
        })
        .unwrap_or_default();
    remove.sort_unstable();
    remove.dedup();
    for &i in remove.iter().rev() {
        if i == 0 || i >= recorded_steps.len() {
            continue; // never the entry navigate; ignore out-of-range
        }
        let ty = recorded_steps[i]
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("");
        if PROTECTED.contains(&ty) {
            continue; // never delete a login/interaction step
        }
        recorded_steps.remove(i);
    }
    if let Some(renames) = decision.get("rename").and_then(|v| v.as_object()) {
        for (old, newv) in renames {
            let Some(new_name) = newv.as_str().map(str::trim).filter(|s| {
                !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            }) else {
                continue;
            };
            for s in recorded_steps.iter_mut() {
                if s.pointer("/config/variable").and_then(|v| v.as_str()) == Some(old.as_str()) {
                    if let Some(cfg) = s.get_mut("config").and_then(|c| c.as_object_mut()) {
                        cfg.insert("variable".into(), json!(new_name));
                    }
                }
            }
            if let Some(v) = extracted_data.remove(old) {
                extracted_data.insert(new_name.to_string(), v);
            }
        }
    }
}

/// Remove NAVIGATE steps that were immediately superseded by another navigate — the page was never
/// acted on (a leftover of a back-and-forth path like /workflows → /targets → /workflows). Keeps a
/// navigate only when something (fill/click/extract/api_call/…) actually used its page.
pub(crate) fn prune_dead_navigations(steps: &mut Vec<Value>) {
    let is_nav = |s: &Value| s.get("type").and_then(|t| t.as_str()) == Some("navigate");
    let mut i = 0;
    while i + 1 < steps.len() {
        if is_nav(&steps[i]) && is_nav(&steps[i + 1]) {
            steps.remove(i); // dead: its page was navigated away from before use
        } else {
            i += 1;
        }
    }
    // Strip the internal `_auth_fill` marker (used only to locate the DOM login block for a possible
    // login_post swap) so it never leaks into the persisted workflow. This runs on every terminal path
    // (convergence / done / finish all prune) but NOT on a mid-session park, so a resumed session still
    // sees its login block. Marker-free steps are unaffected.
    for s in steps.iter_mut() {
        if let Some(obj) = s.as_object_mut() {
            obj.remove("_auth_fill");
        }
    }
}

/// Parse a URL's origin (`scheme://host[:port]`) for the same-origin check below. A relative or
/// unparseable URL returns `None` — treated as "unknown origin", which takes the conservative KEEP path.
fn url_origin(u: &str) -> Option<String> {
    url::Url::parse(u)
        .ok()
        .map(|p| p.origin().ascii_serialization())
}

/// Drop a NAVIGATE that existed only to POSITION the page for request steps. An `api_call` /
/// `login_post` fetches its URL DIRECTLY (an in-page fetch that reuses the session cookies), so a
/// navigate placed right before a run of only-request steps is dead weight — after a login, the data
/// calls don't need the page to be anywhere. This is the "no navigate before an api_call" cleanup.
///
/// NEVER removes the ENTRY navigate (the FIRST navigate): it establishes the site origin + cookie
/// context the in-page fetches rely on, so it always stays. Also keeps any navigate whose segment
/// contains a DOM step (fill/click/extract/evaluate/…), and is ORIGIN-SAFE — an intermediate navigate
/// is removed only when every request in its segment is same-origin as the entry navigate, so the
/// fetches still run same-origin (no CORS regression) from the retained entry page.
pub(crate) fn prune_navigates_before_api_only(steps: &mut Vec<Value>) {
    fn ty(s: &Value) -> &str {
        s.get("type").and_then(|t| t.as_str()).unwrap_or("")
    }
    // The entry navigate = the FIRST navigate. It is never removed and its origin anchors the check.
    let Some(entry_idx) = steps.iter().position(|s| ty(s) == "navigate") else {
        return;
    };
    let Some(entry_origin) = steps[entry_idx]
        .pointer("/config/url")
        .and_then(|u| u.as_str())
        .and_then(url_origin)
    else {
        return; // entry origin unknown → don't reason about removing anything
    };
    let is_request = |s: &Value| matches!(ty(s), "api_call" | "login_post");
    let same_origin_as_entry = |s: &Value| {
        s.pointer("/config/url")
            .and_then(|u| u.as_str())
            .and_then(url_origin)
            .map(|o| o == entry_origin)
            .unwrap_or(false)
    };

    let mut i = 0;
    while i < steps.len() {
        // The entry navigate is sacrosanct — skip it (never a removal candidate).
        if ty(&steps[i]) != "navigate" || i == entry_idx {
            i += 1;
            continue;
        }
        // Segment = the steps this navigate introduces, up to the next navigate (or the end).
        let mut j = i + 1;
        while j < steps.len() && ty(&steps[j]) != "navigate" {
            j += 1;
        }
        let segment = &steps[i + 1..j];
        let removable = !segment.is_empty()
            && segment.iter().all(is_request)
            && segment.iter().all(same_origin_as_entry);
        if removable {
            steps.remove(i); // drop the redundant navigate; its request segment stays and runs directly
        } else {
            i += 1;
        }
    }
}

/// Types that make up the DOM sign-in block (credential fills + the submit control). Used by
/// [`strip_dom_login_and_insert`] to replace them with a single `login_post` step.
const LOGIN_FORM_TYPES: &[&str] = &["fill", "select", "press", "click", "check"];

/// Whether a fill/select `value` references a credential the agent HOLDS (a `{{key}}` whose key is a
/// held secret, or a conventional `login_*`/`persona_*` credential). Used to tag DOM login fills.
fn value_references_credential(
    value: &str,
    available_data: &HashMap<String, String>,
    fill_data: &HashMap<String, String>,
) -> bool {
    for k in fill_data.keys() {
        if !value.contains(&format!("{{{{{k}}}}}")) {
            continue;
        }
        // A credential is a fill_data key whose real value differs from what AVAILABLE DATA shows (the
        // [SECURE] masking) — same test the scrubber uses — or a conventional login_/persona_ key.
        let masked = available_data
            .get(k)
            .map(|shown| shown != fill_data.get(k).unwrap())
            .unwrap_or(true);
        if masked || k.starts_with("login") || k.starts_with("persona") {
            return true;
        }
    }
    false
}

/// Replace the recorded DOM sign-in steps with a single `login_post` step. Locates the contiguous run
/// of form interactions (the tagged credential fills plus the surrounding username fill / submit click)
/// and splices `login_step` in at that position, so the workflow becomes navigate → login_post → data.
/// Returns how many DOM steps were removed. With no tagged login fill (nothing to replace) it inserts
/// `login_step` after any leading navigates so it still runs before the data calls.
pub(crate) fn strip_dom_login_and_insert(steps: &mut Vec<Value>, login_step: Value) -> usize {
    let is_form = |s: &Value| {
        s.get("type")
            .and_then(|t| t.as_str())
            .map(|t| LOGIN_FORM_TYPES.contains(&t))
            .unwrap_or(false)
    };
    let first = steps.iter().position(|s| {
        s.get("_auth_fill")
            .and_then(|b| b.as_bool())
            .unwrap_or(false)
    });
    let Some(start) = first else {
        let insert_at = steps
            .iter()
            .position(|s| s.get("type").and_then(|t| t.as_str()) != Some("navigate"))
            .unwrap_or(steps.len());
        steps.insert(insert_at, login_step);
        return 0;
    };
    // Extend backward over any form steps right before the tagged fill (a username field filled first),
    // but never across a navigate; then forward over the remaining fills + the submit click/press.
    let mut lo = start;
    while lo > 0 && is_form(&steps[lo - 1]) {
        lo -= 1;
    }
    let mut hi = start + 1;
    while hi < steps.len() && is_form(&steps[hi]) {
        hi += 1;
    }
    let removed = hi - lo;
    steps.splice(lo..hi, std::iter::once(login_step));
    removed
}

/// Execute one `do` action. Returns (result line for the model, success, replayable step to record).
pub(crate) async fn execute_explorer_action(
    page: &Page,
    action: &Value,
    fill_data: &HashMap<String, String>,
    record_templates: &HashMap<String, String>,
) -> (String, bool, Option<Value>) {
    let ty = action.get("type").and_then(|v| v.as_str()).unwrap_or("");
    match ty {
        "navigate" => {
            let target = action
                .get("url")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let Some(url) = to_absolute_url(&page.url(), target) else {
                return (
                    format!("navigate {target:?} → ERROR: not a resolvable URL"),
                    false,
                    None,
                );
            };
            if !crate::security::url_guard::is_navigation_url_safe_async(&url).await {
                return (
                    format!("navigate {url} → ERROR: refused unsafe URL"),
                    false,
                    None,
                );
            }
            match navigation::goto(page, &url, "domcontentloaded", Duration::from_secs(25)).await {
                Ok(()) => {
                    // Let the page actually FINISH (XHR-rendered lists, SPAs) before the next
                    // observation — otherwise the model decides on a half-loaded page. Real
                    // quiescence poll (the vendored "networkidle" is readyState-only), capped 8s.
                    navigation::wait_for_page_quiet(page, Duration::from_secs(8)).await;
                    (
                        format!("navigate {url} → ok"),
                        true,
                        Some(
                            json!({ "type": "navigate", "enabled": true, "config": { "url": url } }),
                        ),
                    )
                }
                Err(e) => (format!("navigate {url} → ERROR: {e}"), false, None),
            }
        }
        "fill" => {
            let selector = action
                .get("selector")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let template = action.get("value").and_then(|v| v.as_str()).unwrap_or("");
            if selector.is_empty() {
                return ("fill → ERROR: missing selector".into(), false, None);
            }
            let resolved = resolve_placeholders(template, fill_data);
            match page_actions::fill(page, selector, &resolved).await {
                Ok(()) => (
                    format!("fill {selector} → ok"),
                    true,
                    // Record the REPLAY-RESOLVABLE spelling: a vault credential's {{key}} becomes its
                    // {{secret:VAULT_KEY}} ref (the engine resolves it from the vault at run time), a
                    // plaintext answer its literal; unknown keys keep the placeholder. NEVER the
                    // resolved secret.
                    Some(
                        json!({ "type": "fill", "enabled": true, "config": { "selector": selector, "value": record_value(template, record_templates) } }),
                    ),
                ),
                Err(e) => (format!("fill {selector} → ERROR: {e}"), false, None),
            }
        }
        "click" => {
            let selector = action
                .get("selector")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let text = action
                .get("text")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty());
            if selector.is_empty() && text.is_none() {
                return ("click → ERROR: missing selector/text".into(), false, None);
            }
            // Selector first; on a miss, fall back to the VISIBLE TEXT (Playwright's text engine) —
            // fragile positional selectors (button:nth-of-type(29)) miss constantly, the label rarely
            // does. Record whichever anchor actually worked so the replay uses it too.
            let mut last_err = String::new();
            if !selector.is_empty() {
                match page_actions::click_selector(page, selector, false).await {
                    Ok(()) => {
                        return (
                            format!("click {selector} → ok"),
                            true,
                            Some(
                                json!({ "type": "click", "enabled": true, "config": { "selector": selector } }),
                            ),
                        )
                    }
                    Err(e) => last_err = e.to_string(),
                }
            }
            if let Some(label) = text {
                // Quoted text engine form: JSON-escaping handles quotes and stops '>>' / regex-ish
                // labels from being parsed as selector syntax. Exact-match on the visible label.
                let clean: String = label
                    .chars()
                    .filter(|c| *c != '\n' && *c != '\r')
                    .take(80)
                    .collect();
                let text_selector = format!(
                    "text={}",
                    serde_json::to_string(&clean).unwrap_or_else(|_| format!("{:?}", clean))
                );
                match page_actions::click_selector(page, &text_selector, false).await {
                    Ok(()) => {
                        let via = if selector.is_empty() {
                            String::new()
                        } else {
                            format!(" (selector {selector} missed; used the visible text)")
                        };
                        return (
                            format!("click {text_selector} → ok{via}"),
                            true,
                            Some(
                                json!({ "type": "click", "enabled": true, "config": { "selector": text_selector } }),
                            ),
                        );
                    }
                    Err(e) => last_err = format!("{last_err}; text fallback: {e}"),
                }
            }
            (format!("click {selector} → ERROR: {last_err}"), false, None)
        }
        "select" => {
            let selector = action
                .get("selector")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let value = action.get("value").and_then(|v| v.as_str()).unwrap_or("");
            if selector.is_empty() {
                return ("select → ERROR: missing selector".into(), false, None);
            }
            let resolved = resolve_placeholders(value, fill_data);
            match page_actions::select_option(page, selector, &resolved).await {
                Ok(()) => (
                    format!("select {selector} → ok"),
                    true,
                    Some(
                        json!({ "type": "select", "enabled": true, "config": { "selector": selector, "value": record_value(value, record_templates) } }),
                    ),
                ),
                Err(e) => (format!("select {selector} → ERROR: {e}"), false, None),
            }
        }
        "press" => {
            let key = action
                .get("key")
                .and_then(|v| v.as_str())
                .unwrap_or("Enter");
            match page_actions::keyboard_press(page, key).await {
                Ok(()) => (
                    format!("press {key} → ok"),
                    true,
                    Some(json!({ "type": "press", "enabled": true, "config": { "key": key } })),
                ),
                Err(e) => (format!("press {key} → ERROR: {e}"), false, None),
            }
        }
        "scroll" => {
            let direction = action
                .get("direction")
                .and_then(|v| v.as_str())
                .unwrap_or("down");
            let amount = action
                .get("amount")
                .and_then(|v| v.as_f64())
                .unwrap_or(600.0)
                .clamp(50.0, 4000.0);
            let dy = if direction == "up" { -amount } else { amount };
            match page_actions::mouse_wheel(page, 0.0, dy).await {
                Ok(()) => (
                    format!("scroll {direction} {amount} → ok"),
                    true,
                    // Executor-native shape: execute_scroll reads config.options.deltaX/deltaY —
                    // a {direction, amount} config would silently replay as the down-300 default.
                    Some(
                        json!({ "type": "scroll", "enabled": true, "config": { "options": { "deltaX": 0.0, "deltaY": dy } } }),
                    ),
                ),
                Err(e) => (format!("scroll → ERROR: {e}"), false, None),
            }
        }
        "wait" => {
            // `ms` is accepted as an alias for `seconds`; a caller that reached for
            // milliseconds used to get the silent 1s default instead of its pause.
            let secs = action
                .get("seconds")
                .and_then(|v| v.as_f64())
                .or_else(|| action.get("ms").and_then(|v| v.as_f64()).map(|ms| ms / 1000.0))
                .unwrap_or(1.0)
                .clamp(0.1, 10.0);
            tokio::time::sleep(Duration::from_millis((secs * 1000.0) as u64)).await;
            let ms = (secs * 1000.0) as u64;
            (
                format!("wait {secs}s → ok"),
                true,
                // Executor-native shape: the wait step reads config.duration (ms; mirrored into
                // value) — a {seconds} config would silently replay as the 1s default.
                Some(
                    json!({ "type": "wait", "enabled": true, "config": { "condition": "duration", "duration": ms, "value": ms.to_string() } }),
                ),
            )
        }
        "read_text" => {
            let selector = action
                .get("selector")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if selector.is_empty() {
                return ("read_text → ERROR: missing selector".into(), false, None);
            }
            match page_query::locator_text_content(page, selector).await {
                Ok(Some(text)) => (
                    format!("read_text {selector} → {:?}", truncate(text.trim(), 500)),
                    true,
                    None,
                ),
                Ok(None) => (
                    format!("read_text {selector} → (element has no text)"),
                    true,
                    None,
                ),
                Err(e) => (format!("read_text {selector} → ERROR: {e}"), false, None),
            }
        }
        "evaluate_js" => {
            let script = action.get("script").and_then(|v| v.as_str()).unwrap_or("");
            if script.trim().is_empty() {
                return ("evaluate_js → ERROR: empty script".into(), false, None);
            }
            let script = super::brain::sanitize_js_script(script);
            match page_query::evaluate::<Value>(page, &script).await {
                Ok(v) => (
                    format!("evaluate_js → {}", truncate(&v.to_string(), 800)),
                    true,
                    None,
                ),
                Err(e) => (format!("evaluate_js → ERROR: {e}"), false, None),
            }
        }
        // INSPECT a selector: how many match + the cleaned outerHTML of the first few. This is how the
        // agent CONFIRMS a candidate row selector and sees a row's inner structure (the fields to read)
        // without dumping the whole DOM. Read-only, not recorded.
        "inspect" | "query_dom" | "get_dom" => {
            let selector = action
                .get("selector")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if selector.trim().is_empty() {
                return ("inspect → ERROR: missing selector".into(), false, None);
            }
            let js = "(sel) => { try { const els = document.querySelectorAll(sel); const out = { count: els.length, samples: [] }; for (let i = 0; i < Math.min(els.length, 3); i++) { out.samples.push((els[i].outerHTML || '').slice(0, 2500)); } return out; } catch (e) { return { error: String(e) }; } }";
            match page_query::evaluate_with_args::<Value>(page, js, json!(selector)).await {
                Ok(v) => {
                    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
                        return (format!("inspect {selector} → ERROR: {err}"), false, None);
                    }
                    let count = v.get("count").and_then(|c| c.as_u64()).unwrap_or(0);
                    let samples: Vec<String> = v
                        .get("samples")
                        .and_then(|s| s.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str())
                                .map(|h| {
                                    truncate(
                                        &crate::local::ai::context_clean::clean_dom_for_ai(h),
                                        800,
                                    )
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    let body = if samples.is_empty() {
                        "(no matching element)".to_string()
                    } else {
                        samples.join("\n---\n")
                    };
                    (
                        format!("inspect {selector} → {count} match(es):\n{body}"),
                        true,
                        None,
                    )
                }
                Err(e) => (format!("inspect {selector} → ERROR: {e}"), false, None),
            }
        }
        // FIND where a known value lives: elements whose OWN text contains the query, each with a
        // suggested selector. Lets the agent locate a row/cell it can see on screen and get a selector
        // to build the extraction from. Read-only, not recorded.
        "find_text" | "find" | "search_dom" => {
            let q = action
                .get("text")
                .and_then(|v| v.as_str())
                .or_else(|| action.get("query").and_then(|v| v.as_str()))
                .unwrap_or("");
            if q.trim().is_empty() {
                return ("find_text → ERROR: missing text".into(), false, None);
            }
            let js = "(q) => { try { const needle = String(q).toLowerCase(); const out = []; const els = document.body ? document.body.querySelectorAll('*') : []; for (let i = 0; i < els.length && out.length < 10; i++) { const el = els[i]; let own = ''; const kids = el.childNodes; for (let j = 0; j < kids.length; j++) { if (kids[j].nodeType === 3) own += kids[j].textContent; } own = own.trim(); if (own && own.toLowerCase().indexOf(needle) !== -1) { const tag = el.tagName.toLowerCase(); let cls = ''; if (typeof el.className === 'string' && el.className.trim()) { cls = '.' + el.className.trim().split(/\\s+/).slice(0,4).join('.'); } out.push({ selector: tag + cls, text: own.slice(0, 90) }); } } return out; } catch (e) { return { error: String(e) }; } }";
            match page_query::evaluate_with_args::<Value>(page, js, json!(q)).await {
                Ok(Value::Array(hits)) if !hits.is_empty() => {
                    let lines: Vec<String> = hits
                        .iter()
                        .take(10)
                        .map(|h| {
                            format!(
                                "  {} → {:?}",
                                h.get("selector").and_then(|s| s.as_str()).unwrap_or("?"),
                                h.get("text").and_then(|t| t.as_str()).unwrap_or("")
                            )
                        })
                        .collect();
                    (format!("find_text {q:?} → matches:\n{}", lines.join("\n")), true, None)
                }
                Ok(_) => (format!("find_text {q:?} → no element's OWN text contains it (the text may be split across child elements — inspect a container instead)"), true, None),
                Err(e) => (format!("find_text → ERROR: {e}"), false, None),
            }
        }
        // AUTO-DETECT the repeating rows on the page: groups of same-tag+class siblings that appear ≥3×,
        // ranked by count, with a text sample. The fastest way to find a list's row selector. Read-only.
        "list_candidates" | "outline" | "repeating" | "list_rows" => {
            let js = "(() => { try { const groups = new Map(); const els = document.body ? document.body.querySelectorAll('*') : []; for (let i = 0; i < els.length; i++) { const el = els[i]; if (el.offsetParent === null && el.tagName !== 'BODY') continue; const tag = el.tagName.toLowerCase(); if (tag==='script'||tag==='style'||tag==='svg'||tag==='path'||tag==='br'||tag==='option') continue; let cls=''; if (typeof el.className==='string' && el.className.trim()) cls = el.className.trim().split(/\\s+/).filter(Boolean).slice(0,4).join('.'); const p = el.parentElement; const psig = p ? (p.tagName.toLowerCase() + '>' + (typeof p.className==='string'&&p.className.trim()? (p.className.trim().split(/\\s+/)[0]||'') : '')) : ''; const key = psig+'|'+tag+'|'+cls; let g = groups.get(key); if(!g){g={count:0,tag:tag,cls:cls,samples:[]};groups.set(key,g);} g.count++; if(g.samples.length<2){const t=(el.innerText||'').trim().replace(/\\s+/g,' '); if(t&&t.length>1)g.samples.push(t.slice(0,80));} } const out=[]; for(const g of groups.values()){ if(g.count>=3 && g.samples.length>0) out.push({count:g.count, selector:g.tag+(g.cls?'.'+g.cls:''), sample:g.samples.join(' | ')}); } out.sort((a,b)=>b.count-a.count); return out.slice(0,10); } catch(e){ return {error:String(e)}; } })()";
            match page_query::evaluate::<Value>(page, js).await {
                Ok(Value::Array(cands)) if !cands.is_empty() => {
                    let lines: Vec<String> = cands
                        .iter()
                        .take(10)
                        .map(|c| {
                            format!(
                                "  {}× {} → {:?}",
                                c.get("count").and_then(|v| v.as_u64()).unwrap_or(0),
                                c.get("selector").and_then(|v| v.as_str()).unwrap_or("?"),
                                c.get("sample").and_then(|v| v.as_str()).unwrap_or("")
                            )
                        })
                        .collect();
                    (format!("list_candidates → repeating elements (likely rows; inspect one, then extract by mapping over it):\n{}", lines.join("\n")), true, None)
                }
                Ok(_) => ("list_candidates → no clearly-repeating element found (the list may be virtualized, in a shadow DOM, or not loaded yet — scroll, or wait_for a row selector, then retry)".into(), true, None),
                Err(e) => (format!("list_candidates → ERROR: {e}"), false, None),
            }
        }
        // The ATTRIBUTES (href, data-*, id, aria-*) of the first few matches — for pulling per-row links
        // / ids the visible text doesn't show. Read-only.
        "get_attributes" | "attrs" | "attributes" => {
            let selector = action
                .get("selector")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if selector.trim().is_empty() {
                return (
                    "get_attributes → ERROR: missing selector".into(),
                    false,
                    None,
                );
            }
            let js = "(sel) => { try { const els = document.querySelectorAll(sel); const out=[]; for(let i=0;i<Math.min(els.length,5);i++){ const el=els[i]; const a={}; const ats=el.attributes; for(let j=0;j<ats.length;j++){ let v=ats[j].value||''; if(v.length>120)v=v.slice(0,120)+'…'; a[ats[j].name]=v; } out.push({tag:el.tagName.toLowerCase(), text:(el.innerText||'').trim().slice(0,60), attrs:a}); } return {count:els.length, items:out}; } catch(e){ return {error:String(e)}; } }";
            match page_query::evaluate_with_args::<Value>(page, js, json!(selector)).await {
                Ok(v) => {
                    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
                        return (
                            format!("get_attributes {selector} → ERROR: {err}"),
                            false,
                            None,
                        );
                    }
                    (
                        format!(
                            "get_attributes {selector} → {}",
                            truncate(&v.to_string(), 1200)
                        ),
                        true,
                        None,
                    )
                }
                Err(e) => (
                    format!("get_attributes {selector} → ERROR: {e}"),
                    false,
                    None,
                ),
            }
        }
        // WAIT for a selector to appear (SPA data that loads late) — and RECORD a wait-for-element step
        // so the replay waits for it too, before the extraction runs. This is the robust fix for a list
        // that isn't in the DOM yet at extract time.
        "wait_for" | "wait_for_selector" | "wait_for_element" => {
            let selector = action
                .get("selector")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if selector.trim().is_empty() {
                return ("wait_for → ERROR: missing selector".into(), false, None);
            }
            match page_query::wait_for_selector(page, selector, Duration::from_secs(15)).await {
                Ok(_) => (
                    format!("wait_for {selector} → appeared (recorded a wait step so replay waits for it before extracting)"),
                    true,
                    Some(json!({ "type": "wait", "enabled": true, "config": { "condition": "element", "selector": selector, "value": selector } })),
                ),
                Err(e) => (format!("wait_for {selector} → NOT found within 15s: {e} — the selector may be wrong, or the data never renders (try list_candidates / capture_network)"), false, None),
            }
        }
        // STRUCTURAL MAP of the page: headings + landmark/list/table containers with their selectors and
        // child counts. Orients the agent on an unfamiliar page ("where is the main content / the list").
        "page_outline" | "page_map" | "outline_page" => {
            let js = "(() => { try { const pick = (sel,n) => Array.from(document.querySelectorAll(sel)).slice(0,n).map(e => (e.innerText||'').trim().replace(/\\s+/g,' ').slice(0,60)).filter(Boolean); const landmarks = Array.from(document.querySelectorAll('main,[role=main],nav,[role=navigation],header,footer,aside,section,[role=list],[role=table],table,ul,ol')).filter(e => e.offsetParent!==null).slice(0,20).map(e => { let cls=''; if(typeof e.className==='string'&&e.className.trim())cls='.'+e.className.trim().split(/\\s+/).slice(0,3).join('.'); const role=e.getAttribute('role')||''; return { selector: e.tagName.toLowerCase()+cls+(role?'[role='+role+']':''), children: e.children.length }; }); return { headings: pick('h1,h2,h3',12), containers: landmarks }; } catch(e){ return {error:String(e)}; } })()";
            match page_query::evaluate::<Value>(page, js).await {
                Ok(v) => (
                    format!("page_outline → {}", truncate(&v.to_string(), 1500)),
                    true,
                    None,
                ),
                Err(e) => (format!("page_outline → ERROR: {e}"), false, None),
            }
        }
        // IFRAMES on the page — data can live inside one, and a plain querySelector won't reach it.
        "list_frames" | "frames" | "list_iframes" => {
            let js = "(() => { try { return Array.from(document.querySelectorAll('iframe')).slice(0,15).map((f,i)=>({ index:i, name:(f.name||f.id||''), src:((f.getAttribute('src')||'').slice(0,140)) })); } catch(e){ return {error:String(e)}; } })()";
            match page_query::evaluate::<Value>(page, js).await {
                Ok(Value::Array(a)) if !a.is_empty() => (
                    format!(
                        "list_frames → {}",
                        truncate(&Value::Array(a).to_string(), 900)
                    ),
                    true,
                    None,
                ),
                Ok(_) => ("list_frames → no iframes on this page".into(), true, None),
                Err(e) => (format!("list_frames → ERROR: {e}"), false, None),
            }
        }
        // UPLOAD a file to a file input — records a replayable `upload` step with a PER-RUN file_slot.
        // The build session doesn't need a file: it declares the slot; the user picks a vault file for
        // that slot when the workflow runs (the engine materializes it and fills the input). `mode`:
        // "input" (selector IS the <input type=file>) or "chooser" (selector is a button that opens the
        // native file dialog).
        "upload" | "upload_file" => {
            let selector = action
                .get("selector")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if selector.trim().is_empty() {
                return ("upload → ERROR: missing selector (the file input, or a trigger with mode:\"chooser\")".into(), false, None);
            }
            let mode = action
                .get("mode")
                .and_then(|v| v.as_str())
                .unwrap_or("input");
            // Slot name: given, else derived from the selector/label, else "file".
            let slot = action
                .get("file_slot")
                .or_else(|| action.get("slot"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("file")
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect::<String>();
            let slot = if slot.is_empty() {
                "file".to_string()
            } else {
                slot
            };
            (
                format!("upload → recorded a file-upload step (slot \"{slot}\"): the user picks a vault file for this slot when the workflow runs."),
                true,
                Some(json!({ "type": "upload", "enabled": true, "config": { "selector": selector, "mode": mode, "file_slot": slot } })),
            )
        }
        // WAIT_FOR_DOWNLOAD: capture a file the page downloads into the user's vault. Records a step
        // that (at replay) clicks the trigger, waits for the download, and saves it to the vault under
        // {{output_key}} for later steps. `trigger_selector` is the button/link that starts the
        // download (omit if the PREVIOUS step already triggers it).
        "wait_for_download" | "download" | "capture_download" => {
            let trigger = action
                .get("trigger_selector")
                .or_else(|| action.get("selector"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let output_key = action
                .get("output_key")
                .or_else(|| action.get("variable"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("downloaded_file")
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect::<String>();
            let output_key = if output_key.is_empty() {
                "downloaded_file".to_string()
            } else {
                output_key
            };
            let mut cfg = serde_json::Map::new();
            cfg.insert("output_key".into(), json!(output_key));
            if let Some(t) = trigger {
                cfg.insert("trigger_selector".into(), json!(t));
            }
            (
                format!("wait_for_download → recorded a download-capture step (saved to the vault as \"{output_key}\"){}", if trigger.is_some() { "" } else { " — relies on the previous step to trigger the download" }),
                true,
                Some(json!({ "type": "wait_for_download", "enabled": true, "config": Value::Object(cfg) })),
            )
        }
        // HOVER to reveal hover-only menus/tooltips (recorded so replay reproduces it).
        "hover" => {
            let selector = action
                .get("selector")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if selector.trim().is_empty() {
                return ("hover → ERROR: missing selector".into(), false, None);
            }
            match page_actions::hover(page, selector).await {
                Ok(_) => (
                    format!("hover {selector} → done"),
                    true,
                    Some(
                        json!({ "type": "hover", "enabled": true, "config": { "selector": selector } }),
                    ),
                ),
                Err(e) => (format!("hover {selector} → ERROR: {e}"), false, None),
            }
        }
        other => (format!("{other} → ERROR: unknown action type"), false, None),
    }
}

/// Execute an `api_call` action LIVE on the current page (in-page fetch → inherits the session's
/// cookies/auth), returning the JSON it produced. Placeholders resolve from `fill_data` for this
/// live call; the recorded step (built separately) keeps the `{{secret:...}}` replay spelling.
///
/// Errors carry `(is_auth_rejection, message)`: only an HTTP 401/403 is an AUTH problem (and may
/// justify steering the session off the API); a 404, an empty body, or a network error is NOT —
/// treating those as auth is what wrongly declared "API replay disabled" over a working API.
pub(crate) async fn run_api_call(
    page: &Page,
    action: &Value,
    fill_data: &HashMap<String, String>,
    var: &str,
) -> Result<Value, (bool, String)> {
    use crate::models::workflow::WorkflowStepConfig;
    let url = action
        .get("url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if url.is_empty() {
        return Err((false, "missing url".into()));
    }
    let cfg_json = json!({
        "url": url,
        "method": action.get("method").and_then(|v| v.as_str()).unwrap_or("GET"),
        "headers": action.get("headers").cloned().unwrap_or_else(|| json!({})),
        "body": action.get("body").cloned().unwrap_or(Value::Null),
        "variable": var,
    });
    let config: WorkflowStepConfig = serde_json::from_value(cfg_json)
        .map_err(|e| (false, format!("bad api_call config: {e}")))?;
    // fill_data serves as BOTH credentials ({{secret:KEY}}) and form_data ({{KEY}}) so the agent's
    // login_* keys resolve either spelling at this live call.
    match crate::automation::step_eval::api_call_raw(
        page,
        &config,
        fill_data,
        fill_data,
        &std::collections::HashMap::new(),
    )
    .await
    {
        Ok((status, v)) => {
            if status == 401 || status == 403 {
                Err((
                    true,
                    format!("HTTP {status} — the endpoint rejected the request's authentication"),
                ))
            } else if status >= 400 {
                Err((
                    false,
                    format!("HTTP {status}: {}", truncate(&v.to_string(), 160)),
                ))
            } else if value_has_data(&v) {
                Ok(v)
            } else {
                Err((
                    false,
                    format!(
                        "HTTP {status} but returned no data ({})",
                        truncate(&v.to_string(), 120)
                    ),
                ))
            }
        }
        Err(e) => Err((false, format!("{e}"))),
    }
}

/// Generate a robust list-extraction script from a STRUCTURED spec — a repeating `row_selector` plus a
/// `fields` map (fieldName → sub-selector string, or `{selector, attr}` for an attribute). The model
/// fills this in from what it SEES in the DOM instead of hand-writing escape-prone JS, which is the
/// single biggest reason its scripts fail. All selectors are JSON-encoded so quotes/specials can't
/// corrupt the code. The script discovers rows live (never bakes values) and drops all-empty rows.
pub(crate) fn build_list_extract_script(row_selector: &str, fields: &Value) -> String {
    let row_js = serde_json::to_string(row_selector).unwrap_or_else(|_| "\"\"".into());
    let mut parts: Vec<String> = Vec::new();
    if let Some(obj) = fields.as_object() {
        for (name, spec) in obj {
            let name_js = serde_json::to_string(name).unwrap_or_else(|_| "\"field\"".into());
            let (sel, attr) = match spec {
                Value::String(s) => (s.clone(), None),
                Value::Object(o) => (
                    o.get("selector")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    o.get("attr").and_then(|v| v.as_str()).map(str::to_string),
                ),
                _ => (String::new(), None),
            };
            let sel_js = serde_json::to_string(&sel).unwrap_or_else(|_| "\"\"".into());
            let getter = if let Some(a) = attr {
                let a_js = serde_json::to_string(&a).unwrap_or_else(|_| "\"\"".into());
                // element (row itself when selector empty) → attribute value
                format!("(function(){{var e={sel_js}?el.querySelector({sel_js}):el;return e?e.getAttribute({a_js}):null;}})()")
            } else if sel.trim().is_empty() {
                "((el.innerText||'').trim()||null)".to_string()
            } else {
                format!("(function(){{var e=el.querySelector({sel_js});return e?(e.innerText||'').trim():null;}})()")
            };
            parts.push(format!("{name_js}:{getter}"));
        }
    }
    // No fields → return each row's own text.
    let body = if parts.is_empty() {
        "(el.innerText||'').trim()".to_string()
    } else {
        format!("{{{}}}", parts.join(","))
    };
    format!(
        "Array.from(document.querySelectorAll({row_js})).map(function(el){{return {body};}}).filter(function(r){{return r&&(typeof r==='string'?r.length>0:Object.keys(r).some(function(k){{return r[k];}}));}})"
    )
}

/// Build the replayable `api_call` step, rewriting `{{key}}` placeholders in url/headers/body to
/// their REPLAY spelling (`{{secret:VAULT_KEY}}` for a vault credential) so it resolves at run time.
pub(crate) fn build_api_call_step(
    action: &Value,
    var: &str,
    record_templates: &HashMap<String, String>,
) -> Value {
    let url = record_value(
        action.get("url").and_then(|v| v.as_str()).unwrap_or(""),
        record_templates,
    );
    let method = action
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("GET")
        .to_string();
    let headers = match action.get("headers") {
        Some(Value::Object(o)) => {
            let mapped: serde_json::Map<String, Value> = o
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        json!(record_value(v.as_str().unwrap_or(""), record_templates)),
                    )
                })
                .collect();
            Value::Object(mapped)
        }
        _ => json!({}),
    };
    let mut config = serde_json::Map::new();
    config.insert("url".into(), json!(url));
    config.insert("method".into(), json!(method));
    config.insert("variable".into(), json!(var));
    config.insert("headers".into(), headers);
    if let Some(b) = action.get("body").and_then(|v| v.as_str()) {
        config.insert("body".into(), json!(record_value(b, record_templates)));
    }
    json!({ "type": "api_call", "enabled": true, "config": Value::Object(config) })
}

/// Test a `login_post` action LIVE: POST the sign-in body (with the agent's held credentials) to the
/// auth endpoint. Unlike an `api_call` deliverable, success is NOT "data came back" — a sign-in often
/// returns 204 / a bare token / a redirect. Success = any non-error status; the point is the Set-Cookie
/// side effect (the in-page fetch stores the session cookie so later api_calls inherit it). A 401/403
/// (`auth=true`) means the credentials/body were rejected; a ≥400 is another failure the agent can fix.
pub(crate) async fn run_login_post(
    page: &Page,
    action: &Value,
    fill_data: &HashMap<String, String>,
) -> Result<u16, (bool, String)> {
    use crate::models::workflow::WorkflowStepConfig;
    let url = action
        .get("url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if url.is_empty() {
        return Err((false, "missing url".into()));
    }
    let cfg_json = json!({
        "url": url,
        "method": action.get("method").and_then(|v| v.as_str()).unwrap_or("POST"),
        "headers": action.get("headers").cloned().unwrap_or_else(|| json!({})),
        "body": action.get("body").cloned().unwrap_or(Value::Null),
        "variable": "_login",
    });
    let config: WorkflowStepConfig = serde_json::from_value(cfg_json)
        .map_err(|e| (false, format!("bad login_post config: {e}")))?;
    match crate::automation::step_eval::api_call_raw(
        page,
        &config,
        fill_data,
        fill_data,
        &std::collections::HashMap::new(),
    )
    .await
    {
        Ok((status, v)) => {
            if status == 401 || status == 403 {
                Err((
                    true,
                    format!("HTTP {status} — the endpoint rejected these credentials"),
                ))
            } else if status >= 400 {
                Err((
                    false,
                    format!("HTTP {status}: {}", truncate(&v.to_string(), 160)),
                ))
            } else {
                Ok(status)
            }
        }
        Err(e) => Err((false, format!("{e}"))),
    }
}

/// Build the replayable `login_post` step, rewriting `{{key}}` placeholders in url/headers/body to their
/// REPLAY spelling. The body is taken verbatim from the action (a string — the trace's exact sign-in
/// body — or an object serialized to JSON). Stored under variable `_login` (internal; not a deliverable).
pub(crate) fn build_login_post_step(
    action: &Value,
    record_templates: &HashMap<String, String>,
) -> Value {
    let url = record_value(
        action.get("url").and_then(|v| v.as_str()).unwrap_or(""),
        record_templates,
    );
    let method = action
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("POST")
        .to_string();
    let headers = match action.get("headers") {
        Some(Value::Object(o)) => {
            let mapped: serde_json::Map<String, Value> = o
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        json!(record_value(v.as_str().unwrap_or(""), record_templates)),
                    )
                })
                .collect();
            Value::Object(mapped)
        }
        _ => json!({}),
    };
    // Body accepts a string (the exact serialized body the trace showed) or a JSON object/array.
    let body_str = match action.get("body") {
        Some(Value::String(s)) => Some(s.clone()),
        Some(b @ (Value::Object(_) | Value::Array(_))) => Some(b.to_string()),
        _ => None,
    };
    let mut config = serde_json::Map::new();
    config.insert("url".into(), json!(url));
    config.insert("method".into(), json!(method));
    config.insert("variable".into(), json!("_login"));
    config.insert("headers".into(), headers);
    if let Some(b) = body_str {
        config.insert("body".into(), json!(record_value(&b, record_templates)));
    }
    json!({ "type": "login_post", "enabled": true, "config": Value::Object(config) })
}

/// Run one `done` deliverable on the live page. Ok((replayable step, variable, value)) when it
/// returned REAL data; Err(report line) when it returned nothing (the honest rejection signal).
pub(crate) async fn verify_deliverable(
    page: &Page,
    d: &Value,
) -> Result<(Value, String, Value), String> {
    let ty = d.get("type").and_then(|v| v.as_str()).unwrap_or("");
    let variable = d
        .get("variable")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("data")
        .to_string();
    match ty {
        "extract" => {
            let selector = d
                .get("selector")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            if selector.is_empty() {
                return Err(format!("- extract {variable}: missing selector"));
            }
            // STRUCTURED extract: with `fields` this returns one row per element
            // matching `selector`, which is what a repeated list needs — previously
            // the only way to capture a list was a hand-written `evaluate` script.
            // The saved step carries `fields`, and automation::step_eval::execute_extract
            // reads it on replay, so the recorded and replayed shapes match.
            if let Some(fields) = d.get("fields").and_then(|v| v.as_object()) {
                let field_map: serde_json::Map<String, Value> = fields
                    .iter()
                    .filter(|(_, v)| v.is_string())
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                if field_map.is_empty() {
                    return Err(format!(
                        "- extract {variable}: `fields` must map names to CSS selector strings"
                    ));
                }
                let limit = d.get("limit").and_then(|v| v.as_u64()).unwrap_or(100).clamp(1, 1000);
                let js = crate::automation::step_eval::row_extraction_js(
                    &selector, &field_map, limit,
                );
                return match page_query::evaluate::<Value>(page, &js).await {
                    Ok(value) => {
                        let count =
                            value.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
                        if count == 0 {
                            Err(format!(
                                "- extract {variable} ({selector}): matched 0 rows — check the selector"
                            ))
                        } else {
                            Ok((
                                json!({ "type": "extract", "enabled": true, "config": {
                                    "selector": selector,
                                    "variable": variable,
                                    "fields": Value::Object(field_map),
                                    "limit": limit,
                                }}),
                                variable,
                                value,
                            ))
                        }
                    }
                    Err(e) => Err(format!("- extract {variable} ({selector}): {e}")),
                };
            }
            match page_query::locator_text_content(page, &selector).await {
                Ok(Some(text)) if !text.trim().is_empty() => Ok((
                    json!({ "type": "extract", "enabled": true, "config": { "selector": selector, "variable": variable } }),
                    variable,
                    json!(text.trim()),
                )),
                Ok(_) => Err(format!(
                    "- extract {variable} ({selector}): element found but EMPTY text"
                )),
                Err(e) => Err(format!("- extract {variable} ({selector}): {e}")),
            }
        }
        "evaluate" => {
            let script = d
                .get("script")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            if script.is_empty() {
                return Err(format!("- evaluate {variable}: missing script"));
            }
            let script = super::brain::sanitize_js_script(&script);
            match page_query::evaluate::<Value>(page, &script).await {
                Ok(v) if value_has_data(&v) => Ok((
                    json!({ "type": "evaluate", "enabled": true, "config": { "script": script, "variable": variable } }),
                    variable,
                    v,
                )),
                Ok(v) => Err(format!(
                    "- evaluate {variable}: script ran but returned NO data ({})",
                    truncate(&v.to_string(), 120)
                )),
                Err(e) => Err(format!("- evaluate {variable}: {e}")),
            }
        }
        other => Err(format!(
            "- {variable}: unknown deliverable type {other:?} (use extract or evaluate)"
        )),
    }
}

/// Reject an extraction script that would pass the LIVE test but BREAK at replay: one that fetches
/// the network itself (must be an api_call step, whose auth resolves from the vault) or reads auth/
/// data from sessionStorage/localStorage (empty in a fresh replay session). Returns the fix message.
pub(crate) fn script_replay_hazard(code: &str) -> Option<&'static str> {
    let low = code.to_lowercase();
    if low.contains("fetch(") || low.contains("xmlhttprequest") || low.contains(".ajax(") {
        return Some("this script calls the network itself (fetch/XHR) — do NOT do that inside a script. Use the api_call action instead: it's a first-class replayable step and its auth header resolves from the vault. e.g. {\"type\":\"api_call\",\"url\":\"…\",\"headers\":{\"Authorization\":\"Bearer {{login_key}}\"},\"variable\":\"…\"}.");
    }
    if low.contains("sessionstorage") || low.contains("localstorage") {
        return Some("this script reads sessionStorage/localStorage — those are EMPTY when the workflow replays in a fresh browser, so it returns nothing / unauthorized at call time. Put the credential in an api_call's header as {{login_key}} (resolved from the vault), or read the data from the DOM — never from web storage.");
    }
    None
}

/// Detect an extraction script that HARDCODES the specific data it returns — e.g. an inline array of
/// the exact row identities it saw during recording — instead of DISCOVERING them from the DOM. Such
/// a function passes the live test (those items are on the page right now) but silently breaks the
/// moment the data changes (a new/renamed monitor never appears). Signal: quoted string literals in
/// the code that also appear as VALUES in the returned data AND look like identities (dotted domains/
/// emails, or longer tokens), excluding the structural labels a generic parser legitimately contains.
pub(crate) fn code_hardcodes_returned_data(code: &str, returned: &Value) -> bool {
    let mut values: Vec<String> = Vec::new();
    collect_string_values(returned, &mut values);
    if values.is_empty() {
        return false;
    }
    const STRUCT: &[&str] = &[
        "enabled",
        "disabled",
        "active",
        "inactive",
        "status",
        "check",
        "changes",
        "name",
        "url",
        "http",
        "https",
        "true",
        "false",
        "null",
        "span",
        "div",
        "href",
        "text",
        "content",
        "innertext",
        "queryselector",
        "queryselectorall",
        "price",
        "state",
        "title",
        "value",
    ];
    let mut hits = 0;
    for lit in extract_string_literals(code) {
        let l = lit.trim();
        if l.len() < 4 {
            continue;
        }
        let low = l.to_lowercase();
        if STRUCT.contains(&low.as_str()) {
            continue;
        }
        // Does this literal appear as data the function actually returned?
        let is_data = values
            .iter()
            .any(|v| v.contains(l) || (l.len() >= 6 && l.contains(v.as_str()) && v.len() >= 4));
        if !is_data {
            continue;
        }
        // Identity-looking token (a dotted domain/email, or simply long) — the kind of value a
        // generic extractor would DISCOVER, not embed.
        if l.contains('.') || l.contains('@') || l.chars().count() >= 8 {
            hits += 1;
        }
    }
    hits >= 2
}

/// Collect every string leaf of a JSON value (for the hardcode detector).
fn collect_string_values(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => {
            let s = s.trim();
            if !s.is_empty() {
                out.push(s.to_string());
            }
        }
        Value::Array(a) => a.iter().for_each(|x| collect_string_values(x, out)),
        Value::Object(o) => o.values().for_each(|x| collect_string_values(x, out)),
        _ => {}
    }
}

/// Extract quoted string literals from JS source (', ", ` — escapes skipped). Not a full parser;
/// good enough to surface data baked into the code.
fn extract_string_literals(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = code.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\'' || c == '"' || c == '`' {
            let quote = c;
            let mut buf = String::new();
            while let Some(&n) = chars.peek() {
                chars.next();
                if n == '\\' {
                    chars.next(); // skip the escaped char
                    continue;
                }
                if n == quote {
                    break;
                }
                buf.push(n);
            }
            if !buf.is_empty() {
                out.push(buf);
            }
        }
    }
    out
}

/// Does an evaluated value actually carry data? (empty array/object/string/null ⇒ no)
fn value_has_data(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
        Value::String(s) => !s.trim().is_empty(),
        Value::Bool(_) | Value::Number(_) => true,
    }
}

/// Record a DELIVERABLE step (extract / evaluate / api_call), UPSERTING by its `variable`: a re-emit
/// for an existing variable is a CORRECTION — replace that step in place (same position in the
/// workflow) and return true; a new variable appends and returns false.
///
/// The match spans ALL three deliverable types on purpose: a capability's variable is its identity,
/// so re-emitting it with a DIFFERENT backing (DOM `evaluate` → `api_call`, or back) REPLACES the one
/// step instead of leaving both. Without this, an api-backed correction of a DOM extraction left two
/// steps for one capability and the agent oscillated forever "fixing" the stale one.
fn upsert_extract_step(recorded: &mut Vec<Value>, step: Value, var: &str) -> bool {
    if let Some(existing) = recorded.iter_mut().find(|s| {
        matches!(
            s.get("type").and_then(|t| t.as_str()),
            Some("extract") | Some("evaluate") | Some("api_call")
        ) && s.pointer("/config/variable").and_then(|v| v.as_str()) == Some(var)
    }) {
        *existing = step;
        true
    } else {
        recorded.push(step);
        false
    }
}

/// Upsert a value into a Vec keyed by its `name` field (replace if present, else push).
fn upsert_by_name(list: &mut Vec<Value>, name: &str, item: Value) {
    if let Some(slot) = list
        .iter_mut()
        .find(|f| f.get("name").and_then(|n| n.as_str()) == Some(name))
    {
        *slot = item;
    } else {
        list.push(item);
    }
}

/// Upsert a function intent into orchestration_intents (kind=="function" + matching name).
fn upsert_fn_intent(intents: &mut Vec<Value>, name: &str, item: Value) {
    if let Some(slot) = intents.iter_mut().find(|f| {
        f.get("kind").and_then(|k| k.as_str()) == Some("function")
            && f.get("name").and_then(|n| n.as_str()) == Some(name)
    }) {
        *slot = item;
    } else {
        intents.push(item);
    }
}

/// Outcome of parking on an ask-the-user pause.
enum Park {
    Answered(super::ask_gate::AskAnswers),
    TimedOut,
    Cancelled,
}

/// How long a parked session holds its browser open waiting for the user (then it falls back to
/// the classic close-and-resume path — the pending question stays answerable either way).
const PARK_TIMEOUT_SECS: u64 = 900;

/// Park the running session on an ask: write the concierge pause row (so the panel shows the
/// question/credential inputs), then wait for `/respond` to hand the answers over via
/// [`super::ask_gate`]. The browser/page stay untouched for the whole wait.
async fn park_for_answer(
    pool: &SqlitePool,
    concierge_id: i64,
    question: &str,
    credential_fields: &Value,
    cancel: Option<&AtomicBool>,
) -> Park {
    use crate::local::store::concierge_sessions::{self, ConciergeUpdate};

    // Register the waiter BEFORE the pause row becomes visible: the row write is what makes the
    // answer form appear, so an instant answer must already find the waiter — otherwise /respond
    // would take the respawn path while this session sits parked (two loops on one mission).
    let mut rx = super::ask_gate::register(concierge_id);

    let requests = build_ask_requests(question, credential_fields);
    // resume_status "planning" is the FALLBACK contract: if this park times out and the run ends
    // Blocked, a later /respond (no waiter) re-spawns the planner, which re-runs the build.
    let pending =
        json!({ "requests": requests, "resume_status": "planning", "phase": "discover_workflow" })
            .to_string();
    let _ = concierge_sessions::update(
        pool,
        concierge_id,
        &ConciergeUpdate {
            status: Some("awaiting_input"),
            phase: Some("discover_workflow"),
            progress_message: Some(question),
            pending_request: Some(&pending),
            ..Default::default()
        },
    )
    .await;
    crate::local::flow::push_pending_toast("Assistant needs your input", question);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(PARK_TIMEOUT_SECS);
    loop {
        tokio::select! {
            r = &mut rx => {
                return match r {
                    Ok(answers) => Park::Answered(answers),
                    Err(_) => Park::TimedOut, // sender dropped without an answer
                };
            }
            _ = tokio::time::sleep(Duration::from_secs(2)) => {
                // Drain-before-exit on EVERY exit path: an answer resolve()d microseconds before a
                // cancel/timeout tick must be honored, never dropped (the waiter was already taken
                // by resolve, so /respond will NOT respawn — dropping it would strand the mission).
                let drained = |rx: &mut tokio::sync::oneshot::Receiver<super::ask_gate::AskAnswers>| rx.try_recv().ok();
                if cancel.map(|c| c.load(std::sync::atomic::Ordering::Relaxed)).unwrap_or(false) {
                    super::ask_gate::unregister(concierge_id);
                    if let Some(ans) = drained(&mut rx) { return Park::Answered(ans); }
                    return Park::Cancelled;
                }
                if let Ok(Some(row)) = concierge_sessions::get_by_id(pool, concierge_id).await {
                    if row.cancel_requested != 0 {
                        super::ask_gate::unregister(concierge_id);
                        if let Some(ans) = drained(&mut rx) { return Park::Answered(ans); }
                        return Park::Cancelled;
                    }
                }
                if tokio::time::Instant::now() >= deadline {
                    super::ask_gate::unregister(concierge_id);
                    if let Some(ans) = drained(&mut rx) { return Park::Answered(ans); }
                    return Park::TimedOut;
                }
            }
        }
    }
}

/// Shape the pause's elicitation requests: named credential inputs (secret → password field sealed
/// by /respond) when the agent listed them, else a free-text clarification.
fn build_ask_requests(question: &str, credential_fields: &Value) -> Vec<Value> {
    let creds = credential_fields.as_array().cloned().unwrap_or_default();
    let requests: Vec<Value> = creds
        .iter()
        .filter_map(|f| {
            let field = f.get("field").and_then(|v| v.as_str())?;
            let field = if field.starts_with("login_") {
                field.to_string()
            } else {
                format!("login_{field}")
            };
            let secret = f.get("secret").and_then(|v| v.as_bool()).unwrap_or(true);
            let label = f.get("label").and_then(|v| v.as_str()).unwrap_or(question);
            Some(json!({
                "field": field,
                "kind": if secret { "secret" } else { "text" },
                "question": label,
            }))
        })
        .collect();
    if requests.is_empty() {
        vec![json!({ "field": "clarification", "kind": "text", "question": question })]
    } else {
        requests
    }
}

/// Resolve `{{key}}` placeholders against `fill_data` for EXECUTION (the recorded step keeps
/// the template so secrets never bake into the workflow).
fn resolve_placeholders(value: &str, fill_data: &HashMap<String, String>) -> String {
    let mut out = value.to_string();
    for (k, v) in fill_data {
        let needle = format!("{{{{{k}}}}}");
        if out.contains(&needle) {
            out = out.replace(&needle, v);
        }
    }
    out
}

/// Rewrite `{{key}}` placeholders into their REPLAY-RESOLVABLE spelling for a recorded step: a
/// vault-backed credential → `{{secret:VAULT_KEY}}` (the engine opens the vault at run time), a
/// plaintext answer → its literal (per `record_templates`). A key with NO mapping keeps the raw
/// `{{key}}` placeholder — an unresolvable template is an honest gap; a baked secret is a leak.
fn record_value(template: &str, record_templates: &HashMap<String, String>) -> String {
    let mut out = template.to_string();
    for (k, repl) in record_templates {
        let needle = format!("{{{{{k}}}}}");
        if out.contains(&needle) {
            out = out.replace(&needle, repl);
        }
    }
    out
}

/// Replace every CREDENTIAL plaintext (a fill value that differs from its masked display and isn't
/// trivially short) with `[SECURE:key]`. Applied to every string that can reach the model thread or
/// persisted rows — action results (a probe reading a just-filled input), extracted values, the
/// observation text — so a secret that echoes off the live DOM never propagates.
fn scrub_credentials(
    text: &str,
    fill_data: &HashMap<String, String>,
    available_data: &HashMap<String, String>,
) -> String {
    let mut out = text.to_string();
    for (k, v) in fill_data {
        if v.len() < 4 {
            continue; // too short to be a real credential; replacing would shred normal text
        }
        let is_credential = available_data
            .get(k)
            .map(|shown| shown != v)
            .unwrap_or(true);
        if is_credential && out.contains(v.as_str()) {
            out = out.replace(v.as_str(), &format!("[SECURE:{k}]"));
        }
    }
    out
}

/// Recursively scrub credential plaintexts out of an extracted VALUE before it is stored,
/// surfaced, or fed back to the model.
pub(crate) fn scrub_value(
    v: Value,
    fill_data: &HashMap<String, String>,
    available_data: &HashMap<String, String>,
) -> Value {
    match v {
        Value::String(s) => Value::String(scrub_credentials(&s, fill_data, available_data)),
        Value::Array(a) => Value::Array(
            a.into_iter()
                .map(|x| scrub_value(x, fill_data, available_data))
                .collect(),
        ),
        Value::Object(o) => Value::Object(
            o.into_iter()
                .map(|(k, x)| (k, scrub_value(x, fill_data, available_data)))
                .collect(),
        ),
        other => other,
    }
}

/// Resolve a model-supplied navigate target (absolute, root-relative `/x`, or bare `x`)
/// against the current page URL.
fn to_absolute_url(current: &str, target: &str) -> Option<String> {
    let t = target.trim();
    if t.is_empty() {
        return None;
    }
    if t.starts_with("http://") || t.starts_with("https://") {
        return Some(t.to_string());
    }
    let base = current.trim();
    let scheme_end = base.find("://")? + 3;
    let host_end = base[scheme_end..]
        .find('/')
        .map(|i| scheme_end + i)
        .unwrap_or(base.len());
    let origin = &base[..host_end];
    if let Some(path) = t.strip_prefix('/') {
        Some(format!("{origin}/{path}"))
    } else {
        Some(format!("{origin}/{t}"))
    }
}

/// Validate + normalize one `setup` action into a grounded orchestration intent (stamped with
/// the live URL). Mirrors the cloud runner's `_normalize_orchestration_intent`.
fn normalize_setup_intent(action: &Value, current_url: &str) -> Option<Value> {
    let kind = action
        .get("type")
        .and_then(|v| v.as_str())
        .or_else(|| action.get("action").and_then(|v| v.as_str()))?;
    match kind {
        "create_monitor" => {
            let selector = action
                .get("selector")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if selector.is_empty() {
                return None;
            }
            let watch_raw = action
                .get("watch")
                .and_then(|v| v.as_str())
                .unwrap_or("price")
                .to_ascii_lowercase();
            let watch = if matches!(
                watch_raw.as_str(),
                "content" | "text" | "change" | "changed"
            ) {
                "content"
            } else {
                "price"
            };
            let mut intent = json!({
                "kind": "monitor",
                "selector": selector.chars().take(600).collect::<String>(),
                "watch": watch,
                "url": current_url,
            });
            if let Some(name) = action
                .get("name")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                intent["name"] = json!(name.chars().take(120).collect::<String>());
            }
            match action.get("threshold") {
                Some(Value::Number(n)) => intent["threshold"] = json!(n),
                Some(Value::String(s)) if !s.trim().is_empty() => intent["threshold"] = json!(s),
                _ => {}
            }
            Some(intent)
        }
        "wire_automation" => Some(json!({ "kind": "notify", "url": current_url })),
        "expose_api" => {
            let mut surfaces = serde_json::Map::new();
            for s in ["rest", "openai", "mcp"] {
                if action.get(s).and_then(|v| v.as_bool()).unwrap_or(false) {
                    surfaces.insert(s.into(), json!(true));
                }
            }
            if surfaces.is_empty() {
                surfaces.insert("rest".into(), json!(true));
            }
            Some(json!({ "kind": "connect", "surfaces": Value::Object(surfaces) }))
        }
        _ => None,
    }
}

/// Harvest the page's real navigation affordances so "go to Monitors" is grounded in a link the
/// model can SEE. Best-effort (empty on failure).
async fn collect_links(page: &Page) -> Vec<Value> {
    let js = "(() => Array.from(document.querySelectorAll('a[href]')).map(a => ({ text: (a.innerText || a.getAttribute('aria-label') || '').trim().slice(0, 80), href: a.getAttribute('href') })).filter(l => l.text && l.href && !l.href.startsWith('javascript:') && !l.href.startsWith('#')).slice(0, 40))()";
    page_query::evaluate::<Value>(page, js)
        .await
        .ok()
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
}

/// The per-turn user text: mission status (REAL progress — the ground truth for "am I done?"),
/// then the fresh observation (fields/buttons/links/text).
#[allow(clippy::too_many_arguments)]
fn build_turn_text(
    cfg: &SessionConfig,
    available_data: &HashMap<String, String>,
    fill_data: &HashMap<String, String>,
    obs: &Value,
    links: &[Value],
    network_block: &str,
    dom_html: &str,
    turns: &[Turn],
    extracted: &serde_json::Map<String, Value>,
    recorded_steps: &[Value],
    setup_kinds: &[String],
    defined_functions: &[Value],
    step: u32,
    max_steps: u32,
    filled_keys: &[String],
) -> String {
    let mut data_lines: Vec<String> = available_data
        .iter()
        .map(|(k, v)| {
            // A key whose REAL fill value differs from its displayed value is a held credential —
            // show the [SECURE] marker so the model knows to use the {{key}} placeholder. (The
            // available_data value is by contract already masked; this never prints fill_data.)
            let is_credential = fill_data.get(k).map(|real| real != v).unwrap_or(false);
            let shown = if is_credential {
                "[SECURE]".to_string()
            } else {
                truncate(v, 80)
            };
            let filled = if filled_keys.contains(k) {
                " (already filled)"
            } else {
                ""
            };
            format!("- {k}: {shown}{filled}")
        })
        .collect();
    data_lines.sort();
    let data_block = if data_lines.is_empty() {
        "  (none)".to_string()
    } else {
        data_lines.join("\n")
    };

    // INVENTORY of the recorded workflow — WITH STEP INDICES so a callable can be a "steps" function
    // over a [navigate…extract] range (which replays login + navigation on every call), and so a
    // correction can target an existing extraction by its variable.
    let step_lines: Vec<String> = recorded_steps
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let ty = s.get("type").and_then(|t| t.as_str()).unwrap_or("step");
            let hint = s
                .pointer("/config/url")
                .and_then(|v| v.as_str())
                .or_else(|| s.pointer("/config/variable").and_then(|v| v.as_str()))
                .or_else(|| s.pointer("/config/selector").and_then(|v| v.as_str()))
                .unwrap_or("");
            let sample = s
                .pointer("/config/variable")
                .and_then(|v| v.as_str())
                .and_then(|var| extracted.get(var))
                .map(|v| format!(" → {}", truncate(&v.to_string(), 60)))
                .unwrap_or_default();
            format!("  [{i}] {ty} {}{sample}", truncate(hint, 80))
        })
        .collect();
    let extractions_inv = if step_lines.is_empty() {
        "  (none yet)".to_string()
    } else {
        step_lines.join("\n")
    };

    let function_lines: Vec<String> = defined_functions
        .iter()
        .map(|f| {
            format!(
                "  - \"{}\" ({}) → {}",
                f.get("name").and_then(|v| v.as_str()).unwrap_or("?"),
                f.get("fn_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("script"),
                truncate(
                    f.get("test_sample").and_then(|v| v.as_str()).unwrap_or(""),
                    80
                ),
            )
        })
        .collect();
    let functions_inv = if function_lines.is_empty() {
        "  (none yet)".to_string()
    } else {
        function_lines.join("\n")
    };

    let links_block = if links.is_empty() {
        "  (none visible)".to_string()
    } else {
        links
            .iter()
            .map(|l| {
                format!(
                    "  - \"{}\" → {}",
                    l.get("text").and_then(|v| v.as_str()).unwrap_or(""),
                    l.get("href").and_then(|v| v.as_str()).unwrap_or(""),
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    let fields = obs.get("fields").and_then(|v| v.as_array()).map(|a| {
        a.iter()
            .take(40)
            .map(|f| {
                format!(
                    "  [{}] {} \"{}\" selector={}",
                    f.get("index").and_then(|v| v.as_u64()).unwrap_or(0),
                    f.get("type").and_then(|v| v.as_str()).unwrap_or("?"),
                    f.get("label").and_then(|v| v.as_str()).unwrap_or(""),
                    f.get("selector").and_then(|v| v.as_str()).unwrap_or("?"),
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    });
    let buttons = obs.get("buttons").and_then(|v| v.as_array()).map(|a| {
        a.iter()
            .take(30)
            .map(|b| {
                format!(
                    "  \"{}\" selector={}",
                    b.get("text").and_then(|v| v.as_str()).unwrap_or(""),
                    b.get("selector").and_then(|v| v.as_str()).unwrap_or("?"),
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    });
    let current_url = obs
        .get("current_url")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let last_result = turns
        .last()
        .map(|t| t.result.as_str())
        .unwrap_or("(session start)");
    let wrap_hint = if step + 3 >= max_steps {
        "\nBUDGET NEARLY EXHAUSTED — deliver what you have (done, with deliverables you have SEEN work) or ask the user."
    } else {
        ""
    };

    format!(
        "RESULT OF YOUR PREVIOUS DECISION:\n{last_result}\n\n\
GOAL: {goal}\n\n\
AVAILABLE DATA (fill via {{{{key}}}}; [SECURE] = credential you hold):\n{data_block}\n\n\
MISSION STATUS: turn {turn}/{max}; workflow steps recorded: {nsteps}; setup noted: {setup}.{wrap_hint}\n\n\
WHAT YOU'VE BUILT (correct an extraction by re-emitting its SAME variable; a steps function's step_range uses these [i] indices):\n\
WORKFLOW STEPS (recorded, replay in order):\n{extractions_inv}\n\
DEFINED FUNCTIONS:\n{functions_inv}\n\n\
CURRENT PAGE: {current_url}\n\n\
CAPTURED BACKEND API CALLS (the site's real API — prefer calling these with api_call over scraping the DOM; auth values are redacted, the in-page call reuses the live session):\n{network_block}\n\n\
FORM FIELDS:\n{fields}\n\nBUTTONS:\n{buttons}\n\nLINKS:\n{links_block}\n\n\
PAGE DOM (cleaned live HTML — the REAL structure; write your querySelectorAll against the tags/classes you SEE here. To extract a list, find the REPEATING element — the same tag+class appearing once per row — and map over it. A long list is shown as the first few REAL rows followed by a marker `…+N more <tag> siblings, same structure…`: those rows are real and there ARE N more just like them, so your selector must match the whole set, not only what's printed):\n{dom_html}\n\n\
Decide the next step now. Reply with ONE JSON object.",
        network_block = network_block,
        goal = cfg.goal,
        turn = step + 1,
        max = max_steps,
        nsteps = recorded_steps.len(),
        setup = if setup_kinds.is_empty() { "none".to_string() } else { setup_kinds.join(", ") },
        fields = fields.unwrap_or_else(|| "  (none)".into()),
        buttons = buttons.unwrap_or_else(|| "  (none)".into()),
    )
}

/// Assemble the multi-turn thread: prior (decision → result) pairs, then the fresh observation
/// (with screenshot) as the final user turn. Older results are truncated to keep local-model
/// context bounded; the LAST turn's result is folded into the final user text by the caller.
fn build_thread(
    _cfg: &SessionConfig,
    turns: &[Turn],
    final_user_text: &str,
    screenshot_b64: &str,
) -> Vec<crate::models::ai::AiMessage> {
    use crate::models::ai::{AiContentPart, AiMessage, AiMessageContent, ImageSource};

    let mut messages: Vec<AiMessage> = Vec::new();
    let n = turns.len();
    if n > 0 {
        // Providers require the thread to START with a user turn; the log preamble also frames
        // the replayed decisions for the model.
        messages.push(AiMessage {
            role: "user".into(),
            content: AiMessageContent::Text(
                "(mission log — your prior decisions and their REAL results follow)".into(),
            ),
        });
    }
    for (i, t) in turns.iter().enumerate() {
        messages.push(AiMessage {
            role: "assistant".into(),
            content: AiMessageContent::Text(t.decision.clone()),
        });
        // The LAST turn's result rides inside the final user text (keeps strict alternation);
        // older results are emitted as their own user turns, compacted with age.
        if i + 1 < n {
            let keep = if i + 3 >= n { 800 } else { 150 };
            messages.push(AiMessage {
                role: "user".into(),
                content: AiMessageContent::Text(truncate(&t.result, keep)),
            });
        }
    }

    let mut parts: Vec<AiContentPart> = Vec::new();
    if !screenshot_b64.is_empty() {
        parts.push(AiContentPart::Image {
            source: ImageSource {
                source_type: "base64".into(),
                media_type: "image/jpeg".into(),
                data: screenshot_b64.to_string(),
            },
        });
    }
    parts.push(AiContentPart::Text {
        text: final_user_text.to_string(),
    });
    messages.push(AiMessage {
        role: "user".into(),
        content: AiMessageContent::Parts(parts),
    });
    messages
}

/// One-line human summary of a `do` batch for the live-preview timeline.
fn batch_summary(actions: &[Value]) -> String {
    let parts: Vec<String> = actions
        .iter()
        .take(MAX_BATCH_ACTIONS)
        .map(|a| {
            let ty = a.get("type").and_then(|v| v.as_str()).unwrap_or("?");
            match ty {
                "navigate" => format!(
                    "Navigate {}",
                    a.get("url").and_then(|v| v.as_str()).unwrap_or("")
                ),
                "fill" => format!(
                    "Fill {}",
                    a.get("selector").and_then(|v| v.as_str()).unwrap_or("")
                ),
                "click" => format!(
                    "Click {}",
                    a.get("selector").and_then(|v| v.as_str()).unwrap_or("")
                ),
                other => other.to_string(),
            }
        })
        .collect();
    let s = parts.join("; ");
    if s.is_empty() {
        "Observing".into()
    } else {
        s.chars().take(200).collect()
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max).collect();
        format!("{cut}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const U: &str = "https://app.example.com/dashboard?x=1";

    #[test]
    fn to_absolute_url_resolves_relative_and_absolute() {
        assert_eq!(
            to_absolute_url(U, "/workflows").as_deref(),
            Some("https://app.example.com/workflows")
        );
        assert_eq!(
            to_absolute_url(U, "targets").as_deref(),
            Some("https://app.example.com/targets")
        );
        assert_eq!(
            to_absolute_url(U, "https://other.com/x").as_deref(),
            Some("https://other.com/x")
        );
        assert_eq!(to_absolute_url(U, "   ").as_deref(), None);
    }

    #[test]
    fn placeholders_resolve_for_execution_only() {
        let mut fill = HashMap::new();
        fill.insert("login_key".to_string(), "sk-REAL-SECRET".to_string());
        assert_eq!(
            resolve_placeholders("{{login_key}}", &fill),
            "sk-REAL-SECRET"
        );
        assert_eq!(
            resolve_placeholders("prefix {{login_key}} suffix", &fill),
            "prefix sk-REAL-SECRET suffix"
        );
        // Unknown keys stay as-is (never guessed).
        assert_eq!(resolve_placeholders("{{other}}", &fill), "{{other}}");
    }

    #[test]
    fn record_value_uses_replay_spelling_never_the_secret() {
        let mut cfg = SessionConfig::new("g");
        cfg.fill_data
            .insert("login_key".into(), "sk-REAL-SECRET".into());
        cfg.available_data
            .insert("login_key".into(), "[a secret credential you hold]".into());
        cfg.record_templates.insert(
            "login_key".into(),
            "{{secret:watchtow3r_app_login_key}}".into(),
        );
        // Vault credential → the replay-resolvable {{secret:...}} ref.
        assert_eq!(
            record_value("{{login_key}}", &cfg.record_templates),
            "{{secret:watchtow3r_app_login_key}}"
        );
        // Unknown key → placeholder preserved (an honest gap, never a baked secret).
        assert_eq!(
            record_value("{{persona_pass}}", &cfg.record_templates),
            "{{persona_pass}}"
        );
        // The raw secret NEVER appears in a recorded value.
        assert!(!record_value("{{login_key}}", &cfg.record_templates).contains("sk-REAL-SECRET"));
    }

    #[test]
    fn scrub_replaces_credential_plaintext_everywhere() {
        let mut cfg = SessionConfig::new("g");
        cfg.fill_data
            .insert("login_key".into(), "sk-REAL-SECRET".into());
        cfg.available_data
            .insert("login_key".into(), "[a secret credential you hold]".into());
        // Non-credential plaintext (shown == fill) is NOT scrubbed.
        cfg.fill_data
            .insert("login_username".into(), "benjamin".into());
        cfg.available_data
            .insert("login_username".into(), "benjamin".into());

        let line = scrub_credentials(
            "evaluate_js → \"sk-REAL-SECRET\" (from #apikey)",
            &cfg.fill_data,
            &cfg.available_data,
        );
        assert_eq!(line, "evaluate_js → \"[SECURE:login_key]\" (from #apikey)");
        assert_eq!(
            scrub_credentials("hello benjamin", &cfg.fill_data, &cfg.available_data),
            "hello benjamin"
        );

        let v = scrub_value(
            json!({ "rows": ["ok", "key=sk-REAL-SECRET"] }),
            &cfg.fill_data,
            &cfg.available_data,
        );
        assert_eq!(v, json!({ "rows": ["ok", "key=[SECURE:login_key]"] }));
    }

    #[test]
    fn value_has_data_rejects_empty_shapes() {
        assert!(!value_has_data(&json!(null)));
        assert!(!value_has_data(&json!([])));
        assert!(!value_has_data(&json!({})));
        assert!(!value_has_data(&json!("  ")));
        assert!(value_has_data(&json!([1])));
        assert!(value_has_data(&json!({"a": 1})));
        assert!(value_has_data(&json!("x")));
        assert!(value_has_data(&json!(0)));
    }

    #[test]
    fn setup_create_monitor_price_default() {
        let intent = normalize_setup_intent(
            &json!({ "type": "create_monitor", "selector": ".price" }),
            U,
        )
        .unwrap();
        assert_eq!(intent["kind"], "monitor");
        assert_eq!(intent["selector"], ".price");
        assert_eq!(intent["watch"], "price");
        assert_eq!(intent["url"], U);
    }

    #[test]
    fn setup_create_monitor_content_threshold_name() {
        let intent = normalize_setup_intent(
            &json!({ "type": "create_monitor", "selector": "h1", "watch": "change", "threshold": 99.5, "name": "Latest" }),
            U,
        )
        .unwrap();
        assert_eq!(intent["watch"], "content");
        assert_eq!(intent["name"], "Latest");
        assert_eq!(intent["threshold"], 99.5);
    }

    #[test]
    fn setup_create_monitor_without_selector_rejected() {
        assert!(normalize_setup_intent(&json!({ "type": "create_monitor" }), U).is_none());
        assert!(
            normalize_setup_intent(&json!({ "type": "create_monitor", "selector": "  " }), U)
                .is_none()
        );
    }

    #[test]
    fn setup_wire_and_expose_and_non_orchestration() {
        assert_eq!(
            normalize_setup_intent(&json!({ "type": "wire_automation" }), U).unwrap()["kind"],
            "notify"
        );
        let c = normalize_setup_intent(&json!({ "type": "expose_api" }), U).unwrap();
        assert_eq!(c["kind"], "connect");
        assert_eq!(c["surfaces"], json!({ "rest": true }));
        let c2 =
            normalize_setup_intent(&json!({ "type": "expose_api", "openai": true }), U).unwrap();
        assert_eq!(c2["surfaces"], json!({ "openai": true }));
        // Browser actions are NOT orchestration intents.
        assert!(
            normalize_setup_intent(&json!({ "type": "click", "selector": "#go" }), U).is_none()
        );
        // Legacy "action" key form still accepted.
        assert_eq!(
            normalize_setup_intent(&json!({ "action": "wire_automation" }), U).unwrap()["kind"],
            "notify"
        );
    }

    #[test]
    fn thread_alternates_and_folds_last_result_into_final_turn() {
        let cfg = SessionConfig::new("g");
        let turns = vec![
            Turn {
                decision: "{\"action\":\"act\"}".into(),
                result: "RESULTS: old".into(),
            },
            Turn {
                decision: "{\"action\":\"act\",\"n\":2}".into(),
                result: "RESULTS: last".into(),
            },
        ];
        let msgs = build_thread(&cfg, &turns, "FINAL TEXT with RESULTS: last folded", "");
        // user(log preamble), assistant, user(old result), assistant, user(final) — starts with
        // user, strict alternation, last result NOT emitted standalone (it rides in the final
        // text the caller builds).
        let roles: Vec<&str> = msgs.iter().map(|m| m.role.as_str()).collect();
        assert_eq!(
            roles,
            vec!["user", "assistant", "user", "assistant", "user"]
        );
    }

    #[test]
    fn script_replay_hazard_flags_fetch_and_storage() {
        // The exact bug: a script fetch with auth from sessionStorage — passes live, dies at replay.
        let bad = "(() => fetch('https://x/api/workflows', { headers: { authorization: 'Bearer ' + (sessionStorage.getItem('apiKey') || '') } }).then(r => r.json()))()";
        assert!(script_replay_hazard(bad).is_some());
        assert!(script_replay_hazard(
            "Array.from(document.querySelectorAll('.row')).map(e => e.innerText)"
        )
        .is_none());
        assert!(script_replay_hazard("const x = localStorage.getItem('t'); return x;").is_some());
        assert!(script_replay_hazard("new XMLHttpRequest()").is_some());
    }

    #[test]
    fn api_call_step_records_replay_spelling_not_the_secret() {
        let mut rt = HashMap::new();
        rt.insert(
            "login_key".to_string(),
            "{{secret:watchtow3r_app_login_key}}".to_string(),
        );
        let action = json!({
            "type": "api_call",
            "url": "https://watchtow3r.app/api/monitors",
            "method": "GET",
            "headers": { "Authorization": "Bearer {{login_key}}" },
            "variable": "monitors"
        });
        let step = build_api_call_step(&action, "monitors", &rt);
        assert_eq!(step["type"], "api_call");
        assert_eq!(step["config"]["url"], "https://watchtow3r.app/api/monitors");
        assert_eq!(step["config"]["method"], "GET");
        assert_eq!(step["config"]["variable"], "monitors");
        // The credential placeholder is rewritten to its vault ref for replay — never the raw value.
        assert_eq!(
            step["config"]["headers"]["Authorization"],
            "Bearer {{secret:watchtow3r_app_login_key}}"
        );
    }

    #[test]
    fn hardcode_detector_flags_baked_row_list_but_not_structural_extractor() {
        // The exact bug: an inline array of the row identities the function returns.
        let baked = "(() => { const names = ['korben.info','platform.openai.com','orbitclient.online']; return names.map(n => ({ name: n })); })()";
        let returned = json!([{"name":"korben.info"},{"name":"platform.openai.com"},{"name":"orbitclient.online"}]);
        assert!(code_hardcodes_returned_data(baked, &returned));

        // A generic structural extractor: selectors, no data identities baked in → allowed.
        let generic = "Array.from(document.querySelectorAll('.monitor-row')).map(el => ({ name: el.querySelector('.name').innerText.trim(), status: el.querySelector('.status').innerText.trim() }))";
        assert!(!code_hardcodes_returned_data(generic, &returned));

        // Structural label literals ('Enabled') that appear in output must NOT trigger it.
        let labels = "Array.from(document.querySelectorAll('tr')).map(r => ({ status: r.innerText.includes('Enabled') ? 'Enabled' : 'Disabled' }))";
        let statuses = json!([{"status":"Enabled"},{"status":"Disabled"}]);
        assert!(!code_hardcodes_returned_data(labels, &statuses));
    }

    #[test]
    fn apply_clean_spec_removes_dup_and_renames_but_protects_login() {
        let mut steps = vec![
            json!({ "type": "navigate", "config": { "url": "/login" } }),
            json!({ "type": "fill", "config": { "selector": "#apiKey" } }),
            json!({ "type": "click", "config": { "selector": "#go" } }),
            json!({ "type": "navigate", "config": { "url": "/workflows" } }),
            json!({ "type": "evaluate", "config": { "variable": "get_workflows_list" } }),
            json!({ "type": "navigate", "config": { "url": "/targets" } }),
            json!({ "type": "evaluate", "config": { "variable": "get_targets_list" } }),
            json!({ "type": "evaluate", "config": { "variable": "targets" } }),
        ];
        let mut ex = serde_json::Map::new();
        ex.insert("get_workflows_list".into(), json!([1]));
        ex.insert("targets".into(), json!([2]));
        let spec = json!({ "remove": [7, 2], "rename": { "get_workflows_list": "workflows", "get_targets_list": "targets" } });
        apply_clean_spec(&mut steps, &mut ex, &spec);
        let types: Vec<&str> = steps
            .iter()
            .map(|s| s.get("type").and_then(|t| t.as_str()).unwrap())
            .collect();
        assert_eq!(
            types,
            vec!["navigate", "fill", "click", "navigate", "evaluate", "navigate", "evaluate"]
        );
        assert_eq!(steps[4].pointer("/config/variable").unwrap(), "workflows");
        assert_eq!(steps[6].pointer("/config/variable").unwrap(), "targets");
        assert!(ex.contains_key("workflows") && !ex.contains_key("get_workflows_list"));
    }

    #[test]
    fn apply_clean_spec_never_removes_entry_navigate() {
        let mut steps = vec![
            json!({ "type": "navigate", "config": { "url": "/x" } }),
            json!({ "type": "evaluate", "config": { "variable": "d" } }),
        ];
        let mut ex = serde_json::Map::new();
        apply_clean_spec(&mut steps, &mut ex, &json!({ "remove": [0] }));
        assert_eq!(steps.len(), 2);
    }

    #[test]
    fn prune_dead_navigations_removes_bounced_navs() {
        let mut steps = vec![
            json!({ "type": "navigate", "config": { "url": "/login" } }),
            json!({ "type": "fill", "config": { "selector": "#k" } }),
            json!({ "type": "click", "config": { "selector": "#go" } }),
            json!({ "type": "navigate", "config": { "url": "/workflows" } }),
            json!({ "type": "navigate", "config": { "url": "/targets" } }),
            json!({ "type": "navigate", "config": { "url": "/workflows" } }),
            json!({ "type": "evaluate", "config": { "variable": "workflows" } }),
        ];
        prune_dead_navigations(&mut steps);
        let types: Vec<&str> = steps
            .iter()
            .map(|s| s.get("type").and_then(|t| t.as_str()).unwrap())
            .collect();
        assert_eq!(
            types,
            vec!["navigate", "fill", "click", "navigate", "evaluate"]
        );
        assert_eq!(steps[3].pointer("/config/url").unwrap(), "/workflows");
    }

    #[test]
    fn login_post_replaces_the_dom_login_block() {
        // navigate(login) → fill user (tagged) → fill pass (tagged) → click submit → navigate(data) → extract
        // A login_post swap must drop the three form steps and splice in ONE login_post, leaving the
        // leading navigate and everything from the data navigate onward intact.
        let login = json!({ "type": "login_post", "enabled": true, "config": { "url": "https://x/api/login", "method": "POST" } });
        let mut steps = vec![
            json!({ "type": "navigate", "enabled": true, "config": { "url": "https://x/login" } }),
            json!({ "type": "fill", "enabled": true, "_auth_fill": true, "config": { "selector": "#u", "value": "{{login_username}}" } }),
            json!({ "type": "fill", "enabled": true, "_auth_fill": true, "config": { "selector": "#p", "value": "{{login_password}}" } }),
            json!({ "type": "click", "enabled": true, "config": { "selector": "#go" } }),
            json!({ "type": "navigate", "enabled": true, "config": { "url": "https://x/data" } }),
            json!({ "type": "extract", "enabled": true, "config": { "selector": ".d", "variable": "data" } }),
        ];
        let removed = strip_dom_login_and_insert(&mut steps, login.clone());
        assert_eq!(removed, 3, "the two fills + submit click should be removed");
        let types: Vec<&str> = steps
            .iter()
            .map(|s| s.get("type").and_then(|t| t.as_str()).unwrap())
            .collect();
        assert_eq!(types, vec!["navigate", "login_post", "navigate", "extract"]);
        assert_eq!(steps[1], login);
    }

    #[test]
    fn prune_navigates_drops_redundant_nav_before_api_but_keeps_entry() {
        // navigate(login) → login_post → navigate(dashboard) → api_call(data)
        // The dashboard navigate is redundant (login_post + api_call fetch directly). It goes; the
        // ENTRY navigate and the requests stay.
        let mut steps = vec![
            json!({ "type": "navigate", "enabled": true, "config": { "url": "https://x.com/login" } }),
            json!({ "type": "login_post", "enabled": true, "config": { "url": "https://x.com/api/login" } }),
            json!({ "type": "navigate", "enabled": true, "config": { "url": "https://x.com/dashboard" } }),
            json!({ "type": "api_call", "enabled": true, "config": { "url": "https://x.com/api/data", "variable": "data" } }),
        ];
        prune_navigates_before_api_only(&mut steps);
        let types: Vec<&str> = steps
            .iter()
            .map(|s| s.get("type").and_then(|t| t.as_str()).unwrap())
            .collect();
        assert_eq!(types, vec!["navigate", "login_post", "api_call"]);
        assert_eq!(
            steps[0].pointer("/config/url").unwrap(),
            "https://x.com/login",
            "entry navigate must survive"
        );
    }

    #[test]
    fn prune_navigates_never_removes_the_entry_navigate_even_if_followed_only_by_api() {
        // The entry navigate establishes origin + cookies for the in-page fetches; it is never dropped.
        let mut steps = vec![
            json!({ "type": "navigate", "enabled": true, "config": { "url": "https://x.com/" } }),
            json!({ "type": "api_call", "enabled": true, "config": { "url": "https://x.com/api/data", "variable": "data" } }),
        ];
        prune_navigates_before_api_only(&mut steps);
        let types: Vec<&str> = steps
            .iter()
            .map(|s| s.get("type").and_then(|t| t.as_str()).unwrap())
            .collect();
        assert_eq!(types, vec!["navigate", "api_call"], "entry navigate stays");
    }

    #[test]
    fn prune_navigates_keeps_nav_before_dom_step_and_cross_origin_api() {
        // A navigate before a DOM extract is REQUIRED (the page must be there) → kept.
        let mut dom = vec![
            json!({ "type": "navigate", "enabled": true, "config": { "url": "https://x.com/" } }),
            json!({ "type": "navigate", "enabled": true, "config": { "url": "https://x.com/list" } }),
            json!({ "type": "extract", "enabled": true, "config": { "selector": ".row", "variable": "rows" } }),
        ];
        prune_navigates_before_api_only(&mut dom);
        assert_eq!(dom.len(), 3, "navigate before a DOM step must be kept");

        // A navigate to a DIFFERENT origin whose api is also that origin is kept — removing it would
        // make the fetch cross-origin from the entry page (a CORS regression).
        let mut cross = vec![
            json!({ "type": "navigate", "enabled": true, "config": { "url": "https://x.com/" } }),
            json!({ "type": "navigate", "enabled": true, "config": { "url": "https://api.other.com/" } }),
            json!({ "type": "api_call", "enabled": true, "config": { "url": "https://api.other.com/data", "variable": "d" } }),
        ];
        prune_navigates_before_api_only(&mut cross);
        assert_eq!(cross.len(), 3, "cross-origin api keeps its navigate");
    }

    #[test]
    fn login_post_without_tagged_fills_inserts_after_leading_navigates() {
        // No DOM login recorded (e.g. the agent went straight for login_post): the step is inserted
        // after the leading navigate(s) so it still runs before the data calls.
        let login = json!({ "type": "login_post", "enabled": true, "config": { "url": "https://x/api/login" } });
        let mut steps = vec![
            json!({ "type": "navigate", "enabled": true, "config": { "url": "https://x/" } }),
            json!({ "type": "api_call", "enabled": true, "config": { "url": "https://x/api/data", "variable": "data" } }),
        ];
        let removed = strip_dom_login_and_insert(&mut steps, login.clone());
        assert_eq!(removed, 0);
        let types: Vec<&str> = steps
            .iter()
            .map(|s| s.get("type").and_then(|t| t.as_str()).unwrap())
            .collect();
        assert_eq!(types, vec!["navigate", "login_post", "api_call"]);
    }

    #[test]
    fn prune_strips_the_internal_auth_fill_marker() {
        // The _auth_fill tag must never survive into the persisted workflow.
        let mut steps = vec![
            json!({ "type": "navigate", "config": { "url": "https://x/login" } }),
            json!({ "type": "fill", "_auth_fill": true, "config": { "selector": "#u", "value": "{{login_username}}" } }),
        ];
        prune_dead_navigations(&mut steps);
        assert!(
            steps[1].get("_auth_fill").is_none(),
            "marker must be stripped before persist"
        );
    }

    #[test]
    fn value_references_credential_detects_login_placeholder() {
        let available = HashMap::from([
            ("login_password".to_string(), "[SECURE]".to_string()),
            ("search_term".to_string(), "shoes".to_string()),
        ]);
        let fill = HashMap::from([
            ("login_password".to_string(), "realSecret123".to_string()),
            ("search_term".to_string(), "shoes".to_string()),
        ]);
        // A held credential placeholder → true; a plain non-secret data field → false.
        assert!(value_references_credential(
            "{{login_password}}",
            &available,
            &fill
        ));
        assert!(!value_references_credential(
            "{{search_term}}",
            &available,
            &fill
        ));
    }

    #[test]
    fn build_login_post_step_rewrites_body_to_replay_spelling() {
        let mut rt = HashMap::new();
        rt.insert(
            "login_password".to_string(),
            "{{secret:acme_login_password}}".to_string(),
        );
        let action = json!({
            "type": "login_post",
            "url": "https://x/api/login",
            "method": "POST",
            "headers": { "Content-Type": "application/json" },
            "body": "{\"user\":\"{{login_username}}\",\"pass\":\"{{login_password}}\"}"
        });
        let step = build_login_post_step(&action, &rt);
        assert_eq!(step.pointer("/type").unwrap(), "login_post");
        assert_eq!(step.pointer("/config/variable").unwrap(), "_login");
        let body = step.pointer("/config/body").unwrap().as_str().unwrap();
        // A vaulted credential becomes its {{secret:...}} ref; a non-mapped key keeps its placeholder.
        assert!(
            body.contains("{{secret:acme_login_password}}"),
            "vault ref: {body}"
        );
        assert!(
            body.contains("{{login_username}}"),
            "unmapped key kept: {body}"
        );
        assert!(!body.contains("realSecret"), "no plaintext");
    }

    #[test]
    fn upsert_extract_replaces_same_variable_in_place() {
        let mut steps = vec![
            json!({ "type": "navigate", "enabled": true, "config": { "url": "https://x/workflows" } }),
            json!({ "type": "extract", "enabled": true, "config": { "selector": ".old", "variable": "workflows" } }),
            json!({ "type": "navigate", "enabled": true, "config": { "url": "https://x/monitors" } }),
        ];
        let corrected = json!({ "type": "evaluate", "enabled": true, "config": { "script": "fixed", "variable": "workflows" } });
        let replaced = upsert_extract_step(&mut steps, corrected.clone(), "workflows");
        assert!(replaced);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[1], corrected);
        let fresh = json!({ "type": "extract", "enabled": true, "config": { "selector": ".m", "variable": "monitors" } });
        let appended = upsert_extract_step(&mut steps, fresh.clone(), "monitors");
        assert!(!appended);
        assert_eq!(steps.len(), 4);
        assert_eq!(steps[3], fresh);
    }

    #[test]
    fn upsert_capability_step_switches_backing_dom_to_api_in_place() {
        // The oscillation fix: re-emitting a capability's variable with a DIFFERENT backing
        // (evaluate DOM → api_call) must REPLACE the one step, not leave both.
        let mut steps = vec![
            json!({ "type": "navigate", "enabled": true, "config": { "url": "https://x/workflows" } }),
            json!({ "type": "evaluate", "enabled": true, "config": { "script": "domScrape()", "variable": "get_workflows_list" } }),
        ];
        let api = json!({ "type": "api_call", "enabled": true, "config": { "url": "https://x/api/workflows", "method": "GET", "variable": "get_workflows_list" } });
        let replaced = upsert_extract_step(&mut steps, api.clone(), "get_workflows_list");
        assert!(
            replaced,
            "api_call should replace the DOM evaluate of the same variable"
        );
        assert_eq!(steps.len(), 2, "no duplicate — one capability, one step");
        assert_eq!(steps[1], api);
        // And the reverse: an evaluate correction replaces an api_call of the same variable.
        let dom = json!({ "type": "evaluate", "enabled": true, "config": { "script": "domScrape2()", "variable": "get_workflows_list" } });
        assert!(upsert_extract_step(
            &mut steps,
            dom.clone(),
            "get_workflows_list"
        ));
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[1], dom);
    }

    #[test]
    fn list_extract_script_is_structural_and_json_safe() {
        // A text field, an attribute field, and a quote-containing selector — none may corrupt the JS,
        // and the script must DISCOVER rows (querySelectorAll + map), never bake values.
        let fields = json!({
            "name": ".title",
            "link": { "selector": "a", "attr": "href" },
            "tricky": "[data-x=\"1\"]"
        });
        let code = build_list_extract_script(".row.card", &fields);
        assert!(
            code.contains("querySelectorAll"),
            "must discover rows: {code}"
        );
        assert!(code.contains(".map("), "must map over rows: {code}");
        assert!(
            code.contains("getAttribute"),
            "attr field must read an attribute: {code}"
        );
        // The row selector and the quote-containing sub-selector are JSON-encoded, so the raw
        // double-quote from the attribute selector is escaped, never a bare " that breaks the string.
        assert!(
            code.contains("\\\"1\\\""),
            "quote-containing selector must be escaped: {code}"
        );
        // Whole thing is a valid single JS expression (balanced), and carries no literal row values.
        assert!(code.starts_with("Array.from("));
        // An empty-fields spec falls back to each row's own text.
        let bare = build_list_extract_script("li", &Value::Null);
        assert!(
            bare.contains("innerText"),
            "no-fields spec reads row text: {bare}"
        );
    }

    #[test]
    fn upsert_fn_intent_replaces_same_name() {
        let mut intents = vec![
            json!({ "kind": "monitor", "name": "x" }),
            json!({ "kind": "function", "name": "get_list", "test_sample": "OLD" }),
        ];
        upsert_fn_intent(
            &mut intents,
            "get_list",
            json!({ "kind": "function", "name": "get_list", "test_sample": "NEW" }),
        );
        assert_eq!(intents.len(), 2);
        assert_eq!(intents[1]["test_sample"], "NEW");
        upsert_fn_intent(
            &mut intents,
            "get_state",
            json!({ "kind": "function", "name": "get_state" }),
        );
        assert_eq!(intents.len(), 3);
    }

    #[test]
    fn batch_summary_names_key_actions() {
        let s = batch_summary(&[
            json!({"type":"navigate","url":"https://x.com/a"}),
            json!({"type":"fill","selector":"#k"}),
        ]);
        assert!(s.contains("Navigate https://x.com/a"));
        assert!(s.contains("Fill #k"));
    }
}
