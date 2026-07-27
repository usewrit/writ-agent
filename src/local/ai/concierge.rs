//! The AI concierge assistant — desktop watch+notify mission loop.
//!
//! From ONE natural-language goal ("watch the price of X on site Y and alert me when it drops"), a
//! planner (one AI call per turn) picks ONE tool from a fixed registry and this loop dispatches it:
//!
//!   * `find_page{query, seed_url?}`       — open the daemon's background browser, navigate, read the
//!                                            landing URL + DOM, set `plan.resolved_url`.
//!   * `propose_selectors{want}`           — on the open page, use the FIND_SELECTORS brain to propose
//!                                            a stable price CSS selector, VALIDATE it on the live page
//!                                            (`querySelectorAll(...).length > 0`), set
//!                                            `plan.price_selector`.
//!   * `create_monitor{mode?,render?}`     — Target + watched target_selector (+ text/price extractor
//!                                            for non-visual). DECIDES HTTP vs browser (auto-probes the
//!                                            raw HTML, or `render` forces it) and text-selector vs a
//!                                            visual screenshot-zone (`mode:"visual"` → clip + pixel-diff).
//!   * `ask_user{requests}`                — pause: status='awaiting_input' + a `pending_request`; the
//!                                            FE polls, then POSTs answers to `/respond`.
//!   * `wire_automation{}`                 — a validated block tree
//!                                            [change_detected → condition(price `lt`) → notification
//!                                            (desktop,in_app)] + a legacy actions array, persisted as
//!                                            an Automation bound to the monitor's target. Finalize done.
//!   * `finish{summary}`                   — finalize `done` (or `error`).
//!
//! HARD desktop rule: NO autobuy. If the goal implies buying, the loop still only builds watch+notify
//! and the final message says autobuy is cloud-only. Local AI is FREE (no credit gate) — token counts
//! are accrued on the row only for display. Notification channels that work locally are
//! `desktop`/`in_app`/`webhook`; email/SMS are cloud-only and never emitted.
//!
//! Transport is POLLING: the loop advances the DB row; the FE reads `GET /v1/ai-concierge/{id}`. A
//! pause parks the loop (it returns); `/respond` re-spawns [`run_mission`], which reloads all state
//! from the row — so no in-process resume registry is needed.

use crate::local::ai::provider::{self};
use crate::local::server::AppState;
use crate::local::store::{
    automations, concierge_sessions, personas, selector_extractors, target_selectors, targets,
    workflows,
};
use crate::local::store::concierge_sessions::{ConciergeSession, ConciergeUpdate};
use crate::models::ai::{AiContentPart, AiMessage, AiMessageContent, ImageSource};
use serde_json::{json, Value};
use std::time::Duration;

/// Bounded planner turns per (re)spawn — a runaway model can't loop forever.
const MAX_TURNS: usize = 20;

/// Stop early when the planner makes no real progress for this many turns in a row (it keeps
/// re-picking a tool whose precondition isn't met, or re-browsing to the same result). Much tighter
/// than `MAX_TURNS`, so the user isn't stuck watching a spin.
const STALL_LIMIT: usize = 3;

/// Consecutive `discover_workflow` runs that SIGN IN but extract NO data before we stop re-running it.
/// Tracked in the PLAN (survives the ASK/respond respawn that resets the per-spawn stall counter), so
/// the DISCOVER→ASK("refresh login?")→DISCOVER loop the planner falls into actually terminates. A
/// completed sign-in with no data is an EXTRACTION problem, not a credential one — don't loop on it.
const MAX_NO_DATA_DISCOVERS: u64 = 3;

/// Statuses in which the mission loop should keep advancing. A pause (`awaiting_input`) parks it, and
/// the terminal set (`done|error|cancelled`) stops it.
fn is_active(status: &str) -> bool {
    matches!(status, "planning" | "browsing" | "proposing" | "building" | "armed")
}

/// The concierge planner system prompt. Describes the tool registry + the hard rules and pins the
/// output to a single JSON object `{tool, thought, args, message}`.
const CONCIERGE_SYSTEM: &str = r##"You are Scribe, Writ's desktop monitoring & automation concierge. From ONE natural-language goal you build a live WATCH + NOTIFY automation on the user's own machine — or crawl a whole site into one queryable dataset (Dragnet) — by picking exactly ONE tool per turn.

You orchestrate a fixed tool registry — reply with ONE JSON object and nothing else:
{"tool": "<name>", "thought": "<short reasoning>", "args": { ... }, "message": "<one human sentence for the user>"}
`<name>` MUST be one of the EXACT tool names listed under TOOLS below — copy it verbatim. NEVER invent a tool name (no "create_plan", "respond", "clarify_requirements", "generate_openapi", …); to talk to the user, use ask_user; to plan, just call the next real tool. Put a tool's parameters under the "args" key (not "arguments").

TOOLS (pick ONE per turn):
- find_page   {"query": "<what to search/open>", "seed_url": "<optional direct URL>"}
    Open a background browser and land on the target page. Use seed_url when the goal already names a URL; else give a query THAT IS A URL — a bare domain works (e.g. "korben.info"). There is no search-engine hop, so pass the site, not a sentence. Sets plan.resolved_url.
- propose_selectors {"want": "price", "field": "price_selector"}
    On the open page (plan.resolved_url), propose ONE stable CSS selector for the described element and VALIDATE it on the live page. "want" describes it (e.g. "price", "the main/latest post title or link", "the article body", "username/email input", "login submit button", "list of workflow rows"); "field" is the plan key the validated selector is stored under (default price_selector). Only call AFTER plan.resolved_url is set — find_page the RIGHT page first (the login page for login fields).
- create_monitor {"watch": "price", "mode": "selector", "render": "auto"}
    Create the monitor (target + selector) from plan.resolved_url + plan.price_selector. Call this ONLY after BOTH are set. "watch" picks WHAT to track:
      • "price" (default) — extracts a NUMBER from the element so you can alert below a threshold.
      • "content" — watches the element's TEXT and alerts on ANY change. USE THIS for "notify me when X changes/updates", a new blog post, a headline/status/availability change — anything that is NOT a numeric threshold. No threshold is needed for a content watch.
    "mode" picks HOW to read the element — YOU choose based on what it is:
      • "selector" (default) — read the element's TEXT/number via its CSS selector. Right for prices, headlines, statuses, counts, availability.
      • "visual" — clip a SCREENSHOT ZONE of the element and diff the pixels. Choose this for a chart/graph, an image/photo, a <canvas>/<svg>/map, a logo/badge or rendered banner — or when propose_selectors couldn't find a stable text selector. A visual watch fires on ANY visual change (no threshold); it's captured live from the element's on-screen box, so the warm browser must still be open (it is, right after find_page/propose_selectors).
    "render" picks HTTP vs a full browser — leave it "auto" and the system DECIDES by probing whether the element is in the raw server HTML (server-rendered ⇒ a fast/cheap HTTP check; JS-injected ⇒ a real browser). Only force it when you KNOW: "http" (simple static/server-rendered page) or "js" (heavy SPA / value appears only after scripts run). A "visual" watch always uses a browser.
- ask_user {"requests": [{"field":"threshold","kind":"value","question":"Alert me when the price drops below what?","default":"<optional>"}]}
    Pause and ask the user for something you cannot decide. kind is one of: text | value | choice | confirm | secret. A "secret" answer (passwords, tokens) is stored in the local encrypted vault and reaches you ONLY as its {{secret:KEY}} placeholder in plan/answers — never ask for a password with any other kind. For choice add "options":[..] (and "multi":true to allow several). Ask for a THRESHOLD ONLY for a price watch — NEVER for a content/change watch (it fires on any change). NEVER ask for a payment method or persona to BUY — buying is not available here.
- wire_automation {}
    Wire the alert from the monitor. A "price" watch → change_detected -> condition (price below threshold) -> desktop + in-app notification (call after you have a threshold). A "content" watch → change_detected -> notification on ANY change (no condition, no threshold). Call after the monitor exists.

WORKFLOW TOOLS (build + expose a reusable, callable local workflow — full parity with the cloud app):
- discover_workflow {"goal": "<what to accomplish>", "url": "<optional start URL>", "name": "<optional>"}   ← PREFERRED for anything that needs a LOGIN or real multi-step navigation
    Run the site as an autonomous AI SESSION: an agent opens a live browser, LOOKS at the real page, signs in by filling whatever the login ACTUALLY shows (a single API key, OR username+password — it ADAPTS; you do NOT assume a shape and you do NOT propose_selectors for login fields), clicks/advances, extracts the data, and RECORDS the steps into a runnable workflow. Any credentials the user entered (a login_* answer; a secret is a {{secret:KEY}} the runtime injects — you never see it) are handed to the agent automatically. Sets plan.workflow_id (+ a live auto-test in plan.test_result). If plan.workflow_id is already set it UPDATES in place. It can PAUSE mid-run to ASK the user when it needs a decision or data it doesn't have (which account, which item, an unexpected login field, a CAPTCHA) — the mission goes to awaiting_input; after the user answers, just call discover_workflow AGAIN and it resumes with the answer. UNIFIED: this same session ALSO SETS UP THE WHOLE AUTOMATION in-loop — if the goal asks to watch/notify or expose an API, the agent creates the monitor + notification + API itself while browsing (grounded on the live element). So after discover_workflow, CHECK THE STATE: if resources already show target_id / trigger_rule_id / connect, those are DONE — do NOT call create_monitor / wire_automation / enable_connect again for them; just finish. Use this INSTEAD of find_page+propose_selectors+build_workflow for login-gated data, API-builder missions, or any flow with real navigation.
- build_workflow {"goal": "<what the workflow does>", "name": "<optional name>", "steps": [<explicit steps — strongly preferred>]}   ← only for a SIMPLE, no-login workflow when you already have validated selectors
    Persist a runnable workflow. PASS EXPLICIT "steps" that really accomplish the goal end-to-end (login, navigation, extraction); without them only navigate(+price extract) is recorded, which is NOT enough for goals that need login or data extraction. If plan.workflow_id is ALREADY set this UPDATES that workflow's steps/name in place (use it to fix or extend the built workflow) instead of creating a duplicate. Sets plan.workflow_id + resources.workflow_id.
    Step vocabulary (each item: {"type":"...","config":{...}}):
      {"type":"navigate","config":{"url":"https://..."}}
      {"type":"fill","config":{"selector":"<css>","value":"<text or {{secret:KEY}}>"}}
      {"type":"click","config":{"selector":"<css>"}}
      {"type":"wait","config":{"timeout":3000}}   (ms — or {"selector":"<css>"} to wait for an element)
      {"type":"extract","config":{"selector":"<css>","variable":"<name>"}}   (ONE element's text)
      {"type":"evaluate","config":{"script":"<js expression returning a value>","variable":"<name>"}}   (use for LISTS, e.g. [...document.querySelectorAll('.row')].map(e=>e.textContent.trim()))
      also allowed: select, check, press, scroll, scroll_into_view, hover, wait_for_change
    Use ONLY selectors you validated with propose_selectors (they are in the plan) — never invent selectors.
- add_callable_function {"name": "<alnum_underscore>", "type": "script|extraction|steps", "description": "<optional>", "code": "<script>", "selector": "<for extraction>", "step_range": [start,end], "input_variables": {"<name>":"<desc>"}, "output_fields": ["<field>", ...]}
    Add a named callable function to the workflow. A callable MUST return LIVE data at every call — never the data you saw during the build. DEFAULT to type "steps" with step_range [start,end] over the workflow's recorded steps (0-based, end exclusive): at call time those steps REPLAY on the live site (navigate + extract fresh), and the caller's arguments merge into the steps' {{placeholders}} — that is what makes a function like get_monitor_state(name) work. "extraction" = one live selector read on the final page. "script" ONLY for computing/transforming — code that RETURNS values you saw recorded is REJECTED. Every script/extraction function is LIVE-TESTED the moment you add it (the workflow RUNS for real with your candidate appended; no data returned ⇒ rejected with the real error — fix and re-add). ONE function per capability: STATE plan.functions lists what already exists — if the capability is covered, do NOT add a variant; move on. Map INPUTS to input_variables and returned data to output_fields.
- test_workflow {"sample_inputs": {"<input_var>": "<value>"}}
    RUN the built workflow to validate it and get PASS/FAIL + the error (or a sample of the extracted data) back. Pass sample_inputs for any input variables the workflow needs. Call AFTER build_workflow. If it FAILS, fix the step/selector via build_workflow (it updates in place) and test_workflow AGAIN — repeat until it passes.
- configure_schedule {"interval_minutes": <n>, "cron": "<optional display cron>"}
    Turn on a time schedule for the workflow so it runs automatically every interval_minutes. (The local scheduler runs on interval; any cron is stored for display only.) Call AFTER build_workflow.
- enable_connect {"rest": true, "openai": true, "mcp": true}
    Expose the workflow on the chosen call surfaces (REST run endpoint / OpenAI-compatible chat / MCP tool). An omitted surface stays ENABLED. Call AFTER build_workflow.
- propose_connect_setup {}
    PAUSE and show the user the exact endpoints to call the workflow (REST/OpenAI/MCP) so they can mint a key and wire it up. Call AFTER enable_connect. This emits a connect_setup elicitation (NOT ask_user).
- finish {"summary": "<what you built or why you stopped>"}
    End the mission. Use when everything is wired, or to stop with an explanation. When you built real resources, finish ENDS the mission (done) and its summary shows the user exactly what you created (the workflow + its steps, the monitor, the API) — it does NOT wait for a confirmation. So as soon as everything the goal asked for is built, call finish; do NOT keep going or ask the user to confirm.

DRAGNET (crawl/scrape a site into a queryable dataset, or fold it into an answer):
- dragnet_crawl {"url": "<site or page to crawl>", "extract": "markdown|schema", "max_pages": <n>, "rank_cap": <N>, "include": ["<regex>"], "exclude": ["<regex>"]}   (alias: crawl_site)
    Crawl/scrape a site with a fleet of workers and collect the pages into ONE queryable, deduped dataset. Use this for ANY "get/list/find/show/scrape/summarize the data from <site>" ask, a whole-site sweep ("all/every page", "the entire site"), OR a bounded DISCOVER-AND-EXTRACT ("the top N stories/posts/items and the top M comments/details for each"). It maps the site (sitemap + robots.txt + link graph), then workers fetch every in-scope page (HTTP-first, browser fallback), extracting clean markdown per page ("extract":"markdown", the default) or replaying a prebuilt CSS extractor ("extract":"schema"). NOT a single page (that's find_page) and NOT one login-gated data flow (that's discover_workflow).
    TARGETED TOP-N (discover-and-extract): pass "rank_cap":N + "include":["<regex for the DETAIL/item link, e.g. item\\?id=>"] and Dragnet scrapes the seed LIST page plus EXACTLY the top-N ranked detail links off it (DOM order = ranking, depth 1, no wander) — this is how you get "the top N items and their content" WITHOUT crawling the whole site. Always set rank_cap for a "top N" ask so it never turns into a runaway whole-site crawl. "max_pages" caps a whole-site crawl (default 500).
    Pass "url" (else it uses plan.resolved_url or the site named in the goal); if the site is login-gated, attach a persona first (plan.persona_id) so pages behind the login are reachable. On a CLOUD-LINKED account this runs on the cloud FLEET (metered like the cloud app) — same as every other crawl on a linked desktop; on OSS/self-host it runs the local worker pool. This tool BLOCKS while the crawl runs, streaming live progress. When it returns, resources.crawl_id + resources.workflow_id are set — then synthesize_crawl_answer to fold it into an answer (a data QUESTION), OR enable_connect -> propose_connect_setup to expose the dataset as an API, OR just finish with the dataset link. Politeness (robots.txt, a delay, a concurrency cap) is enforced for you. Do NOT loop find_page over pages yourself — dragnet_crawl IS the crawl.
- synthesize_crawl_answer {"question": "<the user's ask>", "max_rows": <M>}
    Fold a FINISHED dragnet_crawl's collected pages into ONE clean Markdown answer to the user's question (e.g. "top 3 HN stories + top 3 comments each") and write it straight to the chat. Use this for a DISCOVER-AND-EXTRACT QUESTION — it returns an ANSWER, not a monitor or a dataset link. "max_rows" caps rows-per-page (the M in "top M comments"). PRECONDITION: resources.crawl_id + resources.workflow_id (dragnet_crawl already ran). After it, call finish.

DATASETS (read data you have ALREADY collected — check these BEFORE crawling; answering from data on hand is free and instant):
- list_datasets {}
    List the user's EXISTING datasets — every past crawl/workflow that has ALREADY accumulated extracted data (each with dataset_id, name, source_type crawl|workflow, run_count, last_updated). No crawl, no AI. Results land in STATE.plan._available.datasets. Use it when the user says "my data / my datasets / what have I collected", or to find the dataset_id to search/answer from before crawling anything new.
- search_datasets {"q": "<keywords>", "dataset_id": <optional id>}
    Full-text search the user's ALREADY-collected data — GLOBALLY, or one dataset when you pass dataset_id. No crawl, no AI. It tells you whether the answer is already on hand: STATE.plan._available.dataset_hits gets the top matches (dataset + snippet) and _last_result gets the total. "q" is space-separated keywords. Run this FIRST for a data question — if it finds matches, answer_from_datasets; if it finds nothing, THEN crawl.
- answer_from_datasets {"question": "<the ask>", "q": "<optional keywords>", "dataset_id": <optional id>}
    Answer a data question STRAIGHT from the user's already-collected datasets: it searches their past records (globally, or one dataset via dataset_id), folds the matches into ONE Markdown answer, and writes it to the chat. This is the CHEAP path — no crawl. If nothing matches it nudges you to collect the data first (dragnet_crawl / discover_workflow). "q" defaults to the question if omitted. After it, call finish.

TOOL ORDERING:
- CLASSIFY THE GOAL FIRST (decide this before picking a tool):
  • A data QUESTION or one-shot PULL — "top N X (and the top M Y for each)", "get / list / find / show / summarize / how many … from <site>", "what are the …", "scrape … into an answer" — is a DISCOVER-AND-EXTRACT. CHECK ON-HAND DATA FIRST: if the ask is about data the user may ALREADY have collected (they say "my data / my crawl / the dataset / what I scraped", or the site is one already in STATE.plan._available.datasets), run search_datasets (then answer_from_datasets) BEFORE crawling — answering from existing data is free and instant. Only when nothing is on hand does the DISCOVER-AND-EXTRACT proceed: dragnet_crawl, then synthesize_crawl_answer. NEVER open a browser (find_page) or propose_selectors for a data question — those build a MONITOR, not an answer, and will NOT produce the list the user asked for.
  • An ongoing ALERT — "notify/tell me WHEN <page> changes/drops/updates" — is a MONITOR: find_page -> propose_selectors -> create_monitor -> wire_automation.
  • A reusable/login-gated CALLABLE — "make an API for <site>", "log in and pull my …" — is a WORKFLOW: discover_workflow.
  If the goal just asks for information from a site (no ongoing alert, no API, no login), it is ALWAYS a discover-and-extract (dragnet_crawl + synthesize_crawl_answer), never a find_page browse.
- ANSWER FROM EXISTING DATA ("what did I collect on X", "search my datasets for Y", "from my crawl of <site>, …", a data question about a site already in STATE.plan._available.datasets): search_datasets {"q":"<keywords>"} (optionally list_datasets first to find the dataset_id) -> if it has matches, answer_from_datasets {"question":"<the ask>"} -> finish. If search_datasets finds NOTHING, fall through to the DISCOVER-AND-EXTRACT crawl below. This is the cheapest path — no crawl — so reach for it first whenever the data may already be on hand.
- DISCOVER-AND-EXTRACT ("top N X and the top M Y for each", "get the best/top … and drill into each"): dragnet_crawl {"url":"<the ranked LIST page, e.g. https://news.ycombinator.com/>", "rank_cap":N, "include":["<regex for the DETAIL/item link, e.g. item\\?id=>"], "extract":"markdown"} -> synthesize_crawl_answer {"question":"<the ask>", "max_rows":M} -> finish. rank_cap + include make Dragnet harvest the top-N ranked links off the list page (DOM order IS the ranking) and scrape EXACTLY those detail pages — NOT a blind wander over nav/pagination pages. This produces an ANSWER — do NOT create_monitor or wire_automation.
- WHOLE-SITE crawl ("get all data of this site", "crawl the entire site", "every page"): (attach a persona first if login-gated) -> dragnet_crawl (maps + crawls, blocks with live progress) -> then either enable_connect -> propose_connect_setup (expose the collected dataset as an API) -> finish, or just finish with the dataset link. Do NOT use discover_workflow for a whole-site sweep, and do NOT loop find_page over pages — dragnet_crawl IS the crawl.
- Price watch: find_page -> propose_selectors (the price) -> create_monitor {"watch":"price"} -> (ask_user for threshold) -> wire_automation -> finish.
- CHANGE watch ("notify me when X changes/updates", a new post, a status/headline/availability change): find_page -> propose_selectors (the element to watch, e.g. the main/latest post title) -> create_monitor {"watch":"content"} -> wire_automation -> finish. Do NOT ask for a threshold, and do NOT try to extract a price.
- VISUAL watch ("tell me when this chart/graph/image/map/banner changes", or the thing to watch has no reliable text): find_page -> propose_selectors (the element whose ZONE to watch) -> create_monitor {"watch":"content","mode":"visual"} -> wire_automation -> finish. It clips that element's on-screen box and diffs the pixels; fires on any visual change (no threshold).
- Build+expose workflow mission: discover_workflow (the agent logs in + navigates + extracts + records — no propose_selectors) -> (add_callable_function)* -> (configure_schedule) -> enable_connect -> propose_connect_setup -> finish. Use build_workflow only for a trivial no-login workflow.
- A goal may need BOTH (watch a price AND expose a callable workflow) — do the watch chain and the workflow chain, then finish.

API-BUILDER missions ("make/build/create an API for <site>", "expose <site> as an API", "turn <site> into an API"): build ONE workflow that exposes the site's data + actions as callable functions, then connect it. Do this in order:
  1. If the data is behind a login, decide the login identity FIRST (LOGIN-PROTECTED DATA: persona, or ask for the site's actual credential — a single api key is common, do NOT force username+password).
  2. discover_workflow — the autonomous agent signs in (filling whatever the site needs), navigates the key pages, extracts the data, and RECORDS a runnable workflow. It ADAPTS to the site; you do NOT propose_selectors or hand-write steps. ONE discover_workflow browse reaches every relevant page and captures ALL the functions the goal needs in that single run — you do NOT run a second discovery for "another page" or "another list". It also reports a live auto-test in plan.test_result.
  3. The agent usually DEFINES the functions during discover_workflow itself (define_function — tested live on the real page the moment it's created; they appear in STATE plan.functions). Only add_callable_function for a capability that is GENUINELY MISSING from plan.functions — ONCE per capability, never a variant of an existing one. Prefer type "steps" over the recorded navigate+extract range so every call REPLAYS live (fresh data; caller args fill the {{placeholders}}); a function must never return the data you saw while building. Map INPUTS to input_variables and the returned data to output_fields.
  3b. DONE-CHECK: once resources/plan.workflow_id is set AND plan.functions is non-empty AND plan.test_result.ok is true (STATE.workflow_built is true), the workflow is BUILT — do NOT call discover_workflow or build_workflow again; it just repeats work. Go straight to enable_connect -> propose_connect_setup -> finish.
  5. test_workflow to confirm the auto-test PASSED (from discover_workflow's live run). Read plan.test_result / the latest OBSERVATION.
  6. If the test FAILED, FIX it ONCE or TWICE, then stop — do NOT loop. Re-run discover_workflow (workflow_id is set → it updates in place) with a MORE SPECIFIC extraction goal (name the exact page and what the list looks like), or re-add the function, then test_workflow AGAIN. CRITICAL: a run that SIGNED IN but extracted no data is an EXTRACTION problem, NOT a credential problem — do NOT ask the user to re-enter/refresh the login in that case, and do NOT re-run discover more than a couple of times. After 2-3 no-data attempts, call finish and honestly report that the sign-in works but the list(s) couldn't be extracted. Only ask about the login when discover_workflow actually BLOCKED on it.
  7. enable_connect {"rest":true,"openai":true,"mcp":true} -> propose_connect_setup -> finish, summarizing the functions you exposed and their inputs/outputs.

LOGIN-PROTECTED DATA:
- If the goal's data only exists behind a login (account pages, dashboards, "my ..." lists, anything user-specific), the workflow MUST authenticate — a workflow that just opens the page will NOT see the data. Do NOT skip this and do NOT pretend it works without it.
- The autonomous agent (discover_workflow) LOGS IN ITSELF: it looks at the live login form and fills whatever it shows — a single API key, OR username+password, OR email+token — you do NOT assume a shape, you do NOT propose_selectors for login fields, and you do NOT hand-write fill steps. You only decide the login IDENTITY (a persona, or credentials the user types), then call discover_workflow.
- If plan.persona_id is ALREADY set, the user attached a login identity inline — DON'T ask how to log in; just discover_workflow (the persona restores its session + mints TOTP; the agent navigates + extracts).
- Otherwise ask the user HOW to log in with ONE ask_user offering the two paths — but do NOT pre-guess the credential inputs (you have not seen the login form yet, and guessing username+password when the site wants an API key is exactly what breaks). Ask ONLY the choice; if they pick "credentials", just run discover_workflow and the AGENT asks for the EXACT credential the site shows when it reaches the login (a single API key, or user+pass — whatever is really there), sealed to the vault. So:
    ask_user {"requests":[{"field":"login_method","kind":"choice","question":"How should I sign in to <site>?","options":[{"id":"persona","label":"Use a saved login identity (persona) — handles 2FA/MFA automatically"},{"id":"credentials","label":"Sign in with a credential — I'll ask for exactly what the site needs"}]}]}
  Only pre-fill `credential_fields` on this call if you ALREADY looked at the login page (find_page) and KNOW the exact inputs; otherwise omit them and let the agent ask.
- PERSONA path (preferred, and REQUIRED when the site uses MFA/2FA — a persona carries the saved session and TOTP, so it can pass 2FA; raw credentials cannot):
  1. ask_user {"requests":[{"field":"persona","kind":"persona","question":"Which login identity should I use?"}]}  (options are filled from the user's personas; if none, tell them to create one in Personas for this site — with its 2FA — then come back).
  2. discover_workflow — the agent signs in with the attached persona, navigates to the data, extracts it, and records the workflow. No login steps to write.
- CREDENTIALS path (when the user chose it AND the site has no MFA): just call discover_workflow — do NOT ask for credentials up front and do NOT propose_selectors. The agent opens the site, reads the REAL login form, and if it needs a credential it PAUSES to ask for exactly what the form shows (a single API key, or user+pass), which is sealed to the vault; on the automatic re-run it fills that credential (login_* → fill_data), submits, navigates, extracts, and records the workflow. If a login_* credential is ALREADY in answers (a re-run, or the user typed it earlier), it's used as-is — a secret is its {{secret:KEY}} placeholder; never re-ask.
- NEVER echo a credential in message/thought/plan — a password exists only as its {{secret:KEY}} placeholder, and a persona's secrets never leave the vault.
- Your finish summary MUST reassure the user that credentials stay in the local encrypted vault (in the persona, or as a {{secret:KEY}} reference) and that you the AI only ever see a placeholder, never the value. On the persona path, note that 2FA is handled automatically; on the credentials path, note that a run pauses if the site unexpectedly asks for MFA or CAPTCHA.

REVISION:
- When the transcript ends with a user correction or change request AFTER resources were created (e.g. "you missed the login step"), FIX the actual resources: gather anything missing (find_page/propose_selectors/ask_user), then call build_workflow again — with plan.workflow_id set it UPDATES the existing workflow — and finish by saying exactly what changed. Never answer with advice instead of fixing, and never create a duplicate workflow.

HARD RULES:
- NEVER repeat yourself. RECENT ACTIONS lists the tools you already ran. If a tool just failed its preconditions (see the CURRENT PLAN's _last_result / a system note), FIX the precondition or pick a different tool — do NOT call the same tool again with the same args, and do NOT keep re-opening the same page. If you've tried the same step twice without progress, either ask_user for what's missing or finish and explain what stopped you.
- NO AUTOBUY. This desktop app can only WATCH, NOTIFY, and build/expose reusable workflows — it can NOT buy/checkout/place orders. If the goal asks to BUY / purchase / checkout / auto-order, build ONLY the watch/notify/workflow parts, and in your finish message say autobuy is available only in the Writ cloud app.
- "price below X" is expressed as operator `lt` on the extracted `price` field. There is NO "decreased" or "dropped" operator — you compare the current price to the threshold with `lt`.
- Always establish plan.resolved_url (find_page) BEFORE propose_selectors / build_workflow, and both plan.resolved_url + plan.price_selector BEFORE create_monitor.
- The workflow tools (add_callable_function / configure_schedule / enable_connect / propose_connect_setup) require plan.workflow_id — call build_workflow first.
- Ask the user for the threshold (ask_user) if the goal does not state a concrete number.
- Notifications are delivered to the desktop + in the app only. Do not promise email or SMS.
- Keep `message` to ONE friendly sentence. Keep `thought` short. Output ONLY the JSON object."##;

/// Canonical Concierge API-builder policy for a connected-AI transport. MCP replaces only the
/// model transport; discovery, validation, persistence, and Connect semantics stay the same.
pub(crate) fn connected_api_builder_contract() -> &'static str {
    r#"Writ Concierge API-builder contract (mandatory):
1. DISCOVER one complete workflow in the live local browser. Inspect the real DOM and captured network traffic; prefer a replayable backend request when it can authenticate at replay, otherwise use a live DOM extraction. Never invent selectors or endpoints.
2. DEFINE every requested callable function while on the page that provides it. Live-test it and require real, non-empty data. Keep one function per capability and never hardcode observed sample data.
3. DONE-CHECK: do not save until at least one callable function is tested and the recording contains the complete route needed to reproduce it. Represent caller data as {{input.name}} placeholders so Writ asks for it before a run.
4. SAVE one workflow. API-builder save enables the same REST, OpenAI-compatible, and MCP Connect surfaces as desktop Concierge.
5. Return the local Connect setup. Never restart discovery after the workflow is built and tested.
Ask every clarification, login, CAPTCHA/2FA guidance, choice, missing run input, and recovery question in the connected AI conversation. The connected AI is the model only for this MCP path; do not call Writ's configured provider."#
}

/// The canonical tool names, in call order — the ONLY names dispatch accepts. Used to build the
/// forceful "pick one of exactly these" nudge for a model that invents tool names.
const VALID_TOOLS: &[&str] = &[
    "find_page", "propose_selectors", "create_monitor", "ask_user", "wire_automation",
    "build_workflow", "discover_workflow", "add_callable_function", "test_workflow", "configure_schedule",
    "enable_connect", "propose_connect_setup", "dragnet_crawl", "synthesize_crawl_answer",
    "list_datasets", "search_datasets", "answer_from_datasets", "finish",
];

/// Map a model-emitted tool name to a CANONICAL concierge tool, tolerating the common synonyms a
/// general agent model reaches for (e.g. `clarify_requirements`→`ask_user`, `create_workflow`→
/// `build_workflow`). Truly unknown names pass through unchanged so dispatch nudges with the valid
/// list. Conservative: only unambiguous synonyms are mapped.
fn normalize_tool_name(raw: &str) -> String {
    let t = raw.trim().to_ascii_lowercase();
    let canonical = match t.as_str() {
        "find_page" | "open_page" | "open_url" | "navigate" | "browse" | "goto" | "visit" | "load_page" => "find_page",
        "propose_selectors" | "find_selector" | "find_selectors" | "get_selector" | "get_selectors" | "propose_selector" => "propose_selectors",
        "create_monitor" | "add_monitor" | "make_monitor" | "watch" | "monitor" | "watch_page" => "create_monitor",
        "ask_user" | "ask" | "clarify" | "clarify_requirements" | "clarify_goal" | "clarify_requirement"
        | "ask_question" | "request_input" | "ask_for_input" | "get_input" | "gather_requirements" => "ask_user",
        "wire_automation" | "wire" | "create_alert" | "setup_alert" | "create_automation" => "wire_automation",
        "build_workflow" | "create_workflow" | "record_workflow" | "make_workflow" | "generate_workflow" | "build" => "build_workflow",
        "discover_workflow" | "autonomous_build" | "discover" | "smart_build" | "auto_build" | "explore_site" | "browse_and_build" => "discover_workflow",
        "add_callable_function" | "add_function" | "create_function" | "define_function" | "add_callable" | "add_api_function" => "add_callable_function",
        "test_workflow" | "test" | "run_test" | "validate_workflow" | "run_workflow" | "verify_workflow" => "test_workflow",
        "configure_schedule" | "schedule" | "set_schedule" | "add_schedule" => "configure_schedule",
        "enable_connect" | "connect" | "expose_api" | "expose" | "enable_api" | "publish_api" | "create_api" => "enable_connect",
        "propose_connect_setup" | "connect_setup" | "setup_connect" | "show_endpoints" | "propose_setup" | "create_api_key" => "propose_connect_setup",
        "dragnet_crawl" | "crawl_site" | "crawl" | "dragnet" | "crawl_website" | "site_crawl" | "crawl_all" | "scrape_site" => "dragnet_crawl",
        "synthesize_crawl_answer" | "synthesize" | "synthesize_answer" | "crawl_answer" | "answer_from_crawl"
        | "summarize_crawl" | "fold_crawl" | "compose_answer" => "synthesize_crawl_answer",
        "list_datasets" | "list_data" | "datasets" | "my_datasets" | "list_collected_data" => "list_datasets",
        "search_datasets" | "search_data" | "search_dataset" | "query_datasets" | "find_in_data"
        | "check_existing_data" => "search_datasets",
        "answer_from_datasets" | "answer_from_data" | "answer_from_dataset" | "query_data" | "answer_data" => {
            "answer_from_datasets"
        }
        "finish" | "done" | "complete" | "end" | "stop" | "conclude" => "finish",
        _ => return raw.trim().to_string(),
    };
    canonical.to_string()
}

/// A parsed planner decision. Lenient — missing fields default. `tool` drives the dispatch.
struct ToolDecision {
    tool: String,
    args: Value,
    thought: String,
    message: String,
}

fn parse_tool_decision(text: &str) -> Option<ToolDecision> {
    let v = crate::ai::json_parser::parse_ai_json(text)?;
    // Some models put the call under `function`/`tool_call` (OpenAI function-calling shape); unwrap it.
    let call = v
        .get("function")
        .or_else(|| v.get("tool_call"))
        .filter(|c| c.is_object())
        .unwrap_or(&v);
    let raw_tool = call
        .get("tool")
        .or_else(|| call.get("name"))
        .or_else(|| call.get("tool_name"))
        .and_then(|t| t.as_str())?
        .trim();
    if raw_tool.is_empty() {
        return None;
    }
    // Map common synonyms to a canonical tool so a general agent model's near-misses still dispatch.
    let tool = normalize_tool_name(raw_tool);
    // Accept `args`/`arguments`/`parameters`/`input` (models routinely emit the OpenAI `arguments`
    // key). `arguments` is sometimes a JSON-encoded STRING per the OpenAI schema — parse it.
    let args = call
        .get("args")
        .or_else(|| call.get("arguments"))
        .or_else(|| call.get("parameters"))
        .or_else(|| call.get("input"))
        .map(|a| match a {
            Value::String(s) => serde_json::from_str::<Value>(s).unwrap_or_else(|_| json!({})),
            other => other.clone(),
        })
        .unwrap_or_else(|| json!({}));
    let thought = call
        .get("thought")
        .or_else(|| call.get("reasoning"))
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .to_string();
    let message = call
        .get("message")
        .or_else(|| call.get("content"))
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_string();
    Some(ToolDecision { tool, args, thought, message })
}

// ── Row-state accessors (JSON-TEXT columns parsed on read) ───────────────────

fn parse_obj(raw: Option<&str>) -> serde_json::Map<String, Value> {
    raw.and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default()
}

fn parse_arr(raw: Option<&str>) -> Vec<Value> {
    raw.and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
}

fn now_ts() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Signature of REAL mission progress: the created resources + the non-scratch plan keys. A nudge only
/// rewrites `plan._last_result` (a `_`-prefixed scratch key, excluded here), so an unchanged
/// fingerprint across turns means the planner advanced nothing and is looping.
fn progress_fingerprint(sess: &ConciergeSession) -> String {
    let mut r: Vec<(String, Value)> = parse_obj(sess.resources.as_deref()).into_iter().collect();
    r.sort_by(|a, b| a.0.cmp(&b.0));
    let mut p: Vec<(String, Value)> = parse_obj(sess.plan.as_deref())
        .into_iter()
        .filter(|(k, _)| !k.starts_with('_'))
        .collect();
    p.sort_by(|a, b| a.0.cmp(&b.0));
    serde_json::to_string(&json!({ "r": r, "p": p })).unwrap_or_default()
}

/// End a mission that stopped making progress. If it built something usable, close it as `done` with
/// a partial-success note; otherwise stop with a concrete hint from the last precondition failure so
/// the user knows how to unblock it. Mirrors the cloud orchestrator's `_finalize_stalled`.
async fn finalize_stalled(state: &AppState, sess: &ConciergeSession) {
    let resources = parse_obj(sess.resources.as_deref());
    let made = ["target_id", "workflow_id", "trigger_rule_id"]
        .iter()
        .any(|k| resources.get(*k).is_some_and(|v| !v.is_null()));
    let hint: String = parse_obj(sess.plan.as_deref())
        .get("_last_result")
        .and_then(|v| v.as_object())
        .map(|m| m.values().map(|v| v.to_string()).collect::<Vec<_>>().join("; "))
        .unwrap_or_default()
        .chars()
        .take(200)
        .collect();
    let suffix = if hint.is_empty() { String::new() } else { format!(" ({hint})") };
    let (status, msg, err): (&str, String, Option<&str>) = if made {
        ("done", format!("I've set up what I could, but couldn't finish the rest on my own{suffix}. Tell me what to change and I'll adjust it."), None)
    } else {
        ("error", format!("I kept trying the same step without making progress{suffix}. Try giving me the exact page URL or a more specific goal."), Some("stalled"))
    };
    // Append the note as an assistant line so it reads as a chat message, then finalize (mirrors tool_finish).
    let mut transcript = parse_arr(sess.transcript.as_deref());
    transcript.push(json!({ "role": "assistant", "content": msg, "ts": now_ts() }));
    let transcript_s = serde_json::to_string(&transcript).unwrap_or_else(|_| "[]".into());
    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate { transcript: Some(&transcript_s), ..Default::default() },
    )
    .await;
    let _ = concierge_sessions::finalize(&state.db, sess.id, status, Some(&msg), err).await;
}

// ── Public entry ─────────────────────────────────────────────────────────────

/// Drive the concierge mission for `session_id` to a pause or a terminal state. Reloads state from the
/// DB each turn (idempotent across re-spawns from `/respond`). Never panics: any hard failure
/// finalizes the row to `error`.
pub async fn run_mission(state: AppState, session_id: i64) {
    // An AI provider is required UNLESS the cloud AI gateway is on (which supplies AI itself).
    // Missing both ⇒ finalize error (the FE surfaces it).
    if !provider::cloud_gateway_enabled(&state.db).await {
        let has_local = matches!(
            provider::resolve_config(&state.db, &state.vault).await,
            Ok(Some(c)) if !c.provider.trim().is_empty()
        );
        if !has_local {
            let _ = concierge_sessions::finalize(
                &state.db,
                session_id,
                "error",
                None,
                Some("No AI provider configured. Open Settings → AI and choose a provider + API key, or turn on the cloud AI gateway."),
            )
            .await;
            return;
        }
    }

    // "Watch the AI": a mission-level live-preview channel. Each browsing tool spawns a short
    // screencast on its page (looked up via `live_preview::sender_for`) so the FE Preview shows a real
    // screencast — not a DB-poll — and persists a disk-cheap replay keyframe per browse step. The
    // handle deregisters on ANY return below (it is function-scoped), closing spectators' sockets.
    let preview = crate::local::ai::live_preview::register(format!("concierge-{session_id}"));
    preview.sender().send_status("running");

    // ONE warm browser context+page reused across the whole loop (find_page opens it, propose_selectors
    // reads the same warm session). Owned here so it is closed exactly once, however the loop exits.
    let mut warm: Option<WarmBrowse> = None;
    mission_loop(&state, session_id, &mut warm).await;
    // Tell any spectator the mission ENDED so the live view unsticks — otherwise the preview freezes on
    // the warm browser's last frame (the socket just closes on handle-drop with no terminal signal).
    // Broadcast the row's FINAL status (cancelled / done / error) BEFORE closing the page + dropping the
    // handle. This is the mission-channel twin of the AI-session channel's send_status in run.rs.
    let final_status = concierge_sessions::get_by_id(&state.db, session_id)
        .await
        .ok()
        .flatten()
        .map(|s| s.status)
        .unwrap_or_else(|| "done".into());
    preview.sender().send_status(&final_status);
    if let Some(w) = warm.take() {
        crate::local::ai::live_preview::set_page(&format!("concierge-{session_id}"), None).await;
        let _ = w.context.close().await;
    }
}

/// The planner loop body. Extracted so [`run_mission`] can close the warm browse on the SINGLE exit
/// (the loop has many early returns). Drives turns until a pause/terminal outcome; finalizes the row
/// itself on error / step-budget exhaustion.
async fn mission_loop(state: &AppState, session_id: i64, warm: &mut Option<WarmBrowse>) {
    let mut stall = 0usize;
    let mut last_fp: Option<String> = None;
    for _turn in 0..MAX_TURNS {
        // Reload the row every turn — a `/respond` re-spawn or a cancel is picked up here.
        let sess = match concierge_sessions::get_by_id(&state.db, session_id).await {
            Ok(Some(s)) => s,
            _ => return, // vanished (deleted) — nothing to do.
        };

        // STATUS FIRST, then the stop flag — the order carries meaning and must not be swapped back.
        // Both /cancel and /interrupt raise `cancel_requested` (it's the one flag a running discovery
        // polls to stop and close its browser), so the flag alone can't tell "end this mission" from
        // "just stop this turn". What separates them is the status each parked: /interrupt parks at
        // `awaiting_input` and lands HERE, returning quietly so the mission survives and the next
        // message resumes it in place. /cancel finalizes to `cancelled` inline, so it lands here too,
        // already terminal.
        if !is_active(&sess.status) {
            // Paused (awaiting_input — a real ask, or an interrupt) or terminal — done for now.
            return;
        }
        // Still ACTIVE with the flag set = a stop that never got to park the row (a /cancel that
        // raced the loop, or an orphaned flag). Settle it honestly.
        if sess.cancel_requested != 0 {
            let _ = concierge_sessions::finalize(
                &state.db,
                session_id,
                "cancelled",
                Some("Mission cancelled."),
                None,
            )
            .await;
            return;
        }

        // No-progress circuit breaker: if the last turn changed nothing real, the planner is
        // looping — stop honestly instead of spinning to the turn budget.
        let fp = progress_fingerprint(&sess);
        stall = if last_fp.as_deref() == Some(fp.as_str()) { stall + 1 } else { 0 };
        last_fp = Some(fp);
        if stall >= STALL_LIMIT {
            finalize_stalled(state, &sess).await;
            return;
        }

        match run_one_turn(state, &sess, warm).await {
            TurnOutcome::Continue => continue,
            TurnOutcome::Pause | TurnOutcome::Done => return,
            TurnOutcome::Error(msg) => {
                let _ = concierge_sessions::finalize(&state.db, session_id, "error", None, Some(&msg)).await;
                return;
            }
        }
    }

    // Ran out of turns without finishing — stop honestly rather than spin.
    let _ = concierge_sessions::finalize(
        &state.db,
        session_id,
        "error",
        Some("The assistant reached its step limit before finishing. Try a more specific goal."),
        Some("max_turns_exceeded"),
    )
    .await;
}

enum TurnOutcome {
    Continue,
    Pause,
    Done,
    Error(String),
}

/// One browser context + page kept WARM across the mission loop. `find_page` opens+navigates it and
/// leaves it open; `propose_selectors` (and any later browse in the same spawn) then reads the SAME
/// live session — cookies, JS state, login, and scroll all intact — instead of re-opening a fresh
/// context and re-navigating. Created lazily on the first browse and closed exactly once when the loop
/// exits (`run_mission`), so a pause/`/respond` re-spawn starts a fresh warm session.
struct WarmBrowse {
    context: playwright_rs::BrowserContext,
    page: playwright_rs::Page,
    /// The URL the warm page is currently on, so a browse tool can skip a redundant re-navigation.
    url: String,
}

/// Return the mission's warm page, lazily creating the context+page (and binding it to the preview
/// screencast channel for its whole life) on first use. The context is owned by `warm` and closed
/// once by [`run_mission`]; callers must NOT close it.
async fn ensure_warm_page(
    browser: &crate::browser::manager::BrowserManager,
    warm: &mut Option<WarmBrowse>,
    session_id: i64,
) -> Result<playwright_rs::Page, String> {
    if let Some(w) = warm.as_ref() {
        return Ok(w.page.clone());
    }
    let (context, page, _fp) = browser
        .create_stealth_context_with_fingerprint_proxy(None, None)
        .await
        .map_err(|e| format!("browser context failed: {e}"))?;
    // Bind the warm page to the concierge preview channel; the LAZY screencast (started only when a
    // spectator opens the preview) follows it until run_mission clears the binding + closes the context.
    crate::local::ai::live_preview::set_page(&format!("concierge-{session_id}"), Some(page.clone())).await;
    *warm = Some(WarmBrowse { context, page: page.clone(), url: String::new() });
    Ok(page)
}

/// Broadcast a live "thinking" event to any Preview spectators + persist a disk-cheap replay step for
/// the concierge. `shot_b64` is the frame just captured for `live_screenshot` (may be empty; stored
/// downscaled + deduped). Best-effort — never breaks the mission.
async fn report_concierge_step(state: &AppState, session_id: i64, action: &str, thought: &str, url: &str, shot_b64: &str) {
    use crate::local::store::ai_preview_steps;
    let step_num = ai_preview_steps::next_step_num(&state.db, "concierge", session_id).await.unwrap_or(1);
    if let Some(sender) = crate::local::ai::live_preview::sender_for(&format!("concierge-{session_id}")) {
        sender.send_thought(step_num, thought, action, url, "browsing");
    }
    let screenshot = if shot_b64.is_empty() {
        None
    } else {
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, shot_b64)
            .ok()
            .map(|raw| {
                crate::local::ai::live_preview::downscale_jpeg(
                    &raw,
                    ai_preview_steps::KEYFRAME_MAX_EDGE,
                    ai_preview_steps::KEYFRAME_QUALITY,
                )
            })
    };
    let _ = ai_preview_steps::insert(
        &state.db,
        &ai_preview_steps::NewStep {
            kind: "concierge".into(),
            ref_id: session_id,
            step_num,
            thought: (!thought.is_empty()).then(|| thought.to_string()),
            action: (!action.is_empty()).then(|| action.to_string()),
            url: (!url.is_empty()).then(|| url.to_string()),
            status: Some("browsing".into()),
            screenshot,
        },
    )
    .await;
    let _ = ai_preview_steps::trim(&state.db, "concierge", session_id, ai_preview_steps::MAX_STEPS).await;
}

/// Run one planner turn: build the prompt, call the model, dispatch the chosen tool.
async fn run_one_turn(state: &AppState, sess: &ConciergeSession, warm: &mut Option<WarmBrowse>) -> TurnOutcome {
    let transcript = parse_arr(sess.transcript.as_deref());

    // Build the planner prompt as a REAL conversation thread (not a fresh one-shot each
    // turn): the model sees its OWN prior tool-calls as `assistant` turns and each
    // observation as a `user` turn, then the authoritative CURRENT STATE + decision cue
    // as the final user turn. See `build_planner_thread`.
    let messages = build_planner_thread(sess);

    let max_tokens = provider::resolve_max_tokens(&state.db, "agent", 2500).await;
    let completion = match provider::complete_routed(&state.db, &state.vault, &messages, Some(CONCIERGE_SYSTEM), max_tokens, "agent").await {
        Ok(c) => c,
        Err(e) => return TurnOutcome::Error(format!("AI planner call failed: {e}")),
    };

    // Accrue token counts (local AI is free — display only).
    let input_tokens = sess.input_tokens + completion.input_tokens as i64;
    let output_tokens = sess.output_tokens + completion.output_tokens as i64;
    let total_tokens = input_tokens + output_tokens;
    let ai_calls = sess.ai_calls_count + 1;

    let decision = match parse_tool_decision(&completion.text) {
        Some(d) => d,
        None => {
            // Unparseable turn — record the token spend and retry on the next loop iteration.
            let _ = concierge_sessions::update(
                &state.db,
                sess.id,
                &ConciergeUpdate {
                    input_tokens: Some(input_tokens),
                    output_tokens: Some(output_tokens),
                    total_tokens: Some(total_tokens),
                    ai_calls_count: Some(ai_calls),
                    progress_message: Some("Thinking…"),
                    ..Default::default()
                },
            )
            .await;
            return TurnOutcome::Continue;
        }
    };

    // Append the planner turn to brain_history (thought + tool) and (if present) an assistant line to
    // the transcript, then persist the token accrual with the same write.
    let mut brain_history = parse_arr(sess.brain_history.as_deref());
    brain_history.push(json!({
        "thought": decision.thought,
        "tool": decision.tool,
        "args": redact_args(&decision.args),
        "ts": now_ts(),
    }));
    // Bound growth across re-spawns (respond/revise re-enter the loop).
    let bh_len = brain_history.len();
    if bh_len > 40 {
        brain_history.drain(0..bh_len - 40);
    }
    let brain_history_s = serde_json::to_string(&brain_history).unwrap_or_else(|_| "[]".into());

    let mut new_transcript = transcript.clone();
    if !decision.message.trim().is_empty() {
        new_transcript.push(json!({ "role": "assistant", "content": decision.message, "ts": now_ts() }));
    }
    let transcript_s = serde_json::to_string(&new_transcript).unwrap_or_else(|_| "[]".into());

    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate {
            phase: Some(&decision.tool),
            progress_message: (!decision.message.trim().is_empty()).then_some(decision.message.as_str()),
            transcript: Some(&transcript_s),
            brain_history: Some(&brain_history_s),
            input_tokens: Some(input_tokens),
            output_tokens: Some(output_tokens),
            total_tokens: Some(total_tokens),
            ai_calls_count: Some(ai_calls),
            ..Default::default()
        },
    )
    .await;

    // Re-load the up-to-date row (with the just-written transcript/tokens) for the tool to mutate.
    let sess = match concierge_sessions::get_by_id(&state.db, sess.id).await {
        Ok(Some(s)) => s,
        _ => return TurnOutcome::Error("session vanished mid-turn".into()),
    };

    let outcome = dispatch_tool(state, &sess, &decision, warm).await;
    // Record this turn's observation (the tool's resulting progress line) onto its
    // brain_history entry, so the next planner turn's thread carries a faithful
    // assistant(decision) → user(observation) pair.
    record_turn_result(state, sess.id).await;
    outcome
}

/// Build the planner prompt as a real, accumulating conversation thread so the mission continues ONE
/// model thread across turns: the model sees its OWN prior tool-calls (`assistant` JSON turns) and each
/// observation (`user` turns), then the authoritative CURRENT STATE (plan/resources/answers/recent
/// transcript) + the decision cue as the FINAL user turn. The proven state turn is unchanged, so
/// nothing the old one-shot carried is lost — a REVISE correction in the transcript still reaches the
/// planner. Replaying prior JSON assistant turns reinforces the JSON-only output discipline.
/// Consecutive same-role turns are merged so the thread strictly alternates.
fn build_planner_thread(sess: &ConciergeSession) -> Vec<AiMessage> {
    let plan = parse_obj(sess.plan.as_deref());
    let resources = parse_obj(sess.resources.as_deref());
    let answers = parse_obj(sess.answers.as_deref());
    let transcript = parse_arr(sess.transcript.as_deref());
    let brain = parse_arr(sess.brain_history.as_deref());
    let recent: Vec<Value> = transcript.iter().rev().take(6).rev().cloned().collect();

    let mut raw: Vec<(&str, String)> = vec![("user", format!("GOAL: {}", sess.goal))];
    // Replay prior turns: assistant(decision) → user(observation).
    let start = brain.len().saturating_sub(16);
    for h in &brain[start..] {
        let tool = h.get("tool").and_then(|t| t.as_str()).unwrap_or("");
        if tool.is_empty() {
            continue;
        }
        let decision = json!({
            "tool": tool,
            "thought": h.get("thought").and_then(|t| t.as_str()).unwrap_or(""),
            "args": h.get("args").cloned().unwrap_or(Value::Null),
        });
        raw.push(("assistant", cap(&decision.to_string(), 1500)));
        let obs = h.get("result").and_then(|r| r.as_str()).filter(|s| !s.is_empty()).unwrap_or("(done)");
        raw.push(("user", format!("OBSERVATION: {}", cap(obs, 1000))));
    }
    // The tools already run this mission (name + one-line outcome) — the anti-repeat signal the HARD
    // RULES tell the planner to read ("RECENT ACTIONS"). Without it the planner can't see it already
    // built the workflow and wrongly starts a fresh discovery.
    let recent_actions: Vec<Value> = brain
        .iter()
        .rev()
        .take(8)
        .rev()
        .filter_map(|h| {
            let tool = h.get("tool").and_then(|t| t.as_str())?;
            Some(json!({
                "tool": tool,
                "result": cap(h.get("result").and_then(|r| r.as_str()).unwrap_or(""), 120),
            }))
        })
        .collect();
    // Explicit done-signal so the planner can't miss that the workflow is already built.
    let workflow_built = (plan.get("workflow_id").is_some_and(|v| !v.is_null())
        || resources.get("workflow_id").is_some_and(|v| !v.is_null()))
        && plan.get("functions").and_then(|v| v.as_array()).is_some_and(|a| !a.is_empty())
        && plan.get("test_result").and_then(|t| t.get("ok")).and_then(|v| v.as_bool()).unwrap_or(false);
    // Final turn — the authoritative current state (unchanged from the proven one-shot) + the cue.
    let state = json!({
        "goal": sess.goal,
        "platform": sess.platform,
        "phase": sess.phase,
        "plan": plan,
        "resources": resources,
        "answers": answers,
        "recent_actions": recent_actions,
        "workflow_built": workflow_built,
        "recent_transcript": recent,
    });
    raw.push((
        "user",
        format!(
            "CURRENT STATE:\n{}\n\nDecide the ONE next tool now and reply with ONE JSON object.",
            cap(&serde_json::to_string(&state).unwrap_or_else(|_| "{}".into()), 12000)
        ),
    ));

    // Collapse consecutive same-role turns so the thread strictly alternates (some providers require
    // it): e.g. the last OBSERVATION and the CURRENT STATE, or GOAL and CURRENT STATE on turn one.
    let mut msgs: Vec<AiMessage> = Vec::new();
    for (role, content) in raw {
        if let Some(last) = msgs.last_mut() {
            if last.role.as_str() == role {
                if let AiMessageContent::Text(t) = &mut last.content {
                    t.push_str("\n\n");
                    t.push_str(&content);
                }
                continue;
            }
        }
        msgs.push(AiMessage { role: role.into(), content: AiMessageContent::Text(content) });
    }
    msgs
}

/// Light key-name redaction for planner args stored in brain_history (mirrors the cloud `_redact`):
/// mask obvious credential/card keys so replayed decisions never carry a secret. (Desktop secrets are
/// vaulted as `{{secret:KEY}}` placeholders anyway, so this is defense-in-depth.)
fn redact_args(args: &Value) -> Value {
    const DENY: &[&str] = &["card", "pan", "cvc", "cvv", "password", "secret", "number", "token", "credential"];
    match args {
        Value::Object(m) => {
            let mut out = serde_json::Map::new();
            for (k, v) in m {
                let lk = k.to_ascii_lowercase();
                if DENY.iter().any(|s| lk.contains(s)) {
                    out.insert(k.clone(), json!("[REDACTED]"));
                } else {
                    out.insert(k.clone(), redact_args(v));
                }
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(redact_args).collect()),
        _ => args.clone(),
    }
}

/// After a tool runs, stamp its resulting progress line onto this turn's brain_history entry as its
/// `result`, so the next planner turn's thread has a faithful observation for the decision it just
/// made. Best-effort — never breaks the mission.
async fn record_turn_result(state: &AppState, session_id: i64) {
    let Ok(Some(s)) = concierge_sessions::get_by_id(&state.db, session_id).await else {
        return;
    };
    let mut brain = parse_arr(s.brain_history.as_deref());
    let Some(last) = brain.last_mut() else { return };
    let Some(obj) = last.as_object_mut() else { return };
    // Don't clobber a result already recorded (defensive against a double call).
    if obj.get("result").and_then(|r| r.as_str()).is_some_and(|s| !s.is_empty()) {
        return;
    }
    obj.insert("result".into(), json!(s.progress_message.clone().unwrap_or_default()));
    let brain_s = serde_json::to_string(&brain).unwrap_or_else(|_| "[]".into());
    let _ = concierge_sessions::update(
        &state.db,
        session_id,
        &ConciergeUpdate { brain_history: Some(&brain_s), ..Default::default() },
    )
    .await;
}

/// Dispatch the chosen tool. Each arm mutates the row (plan/resources/status) and returns the outcome.
async fn dispatch_tool(
    state: &AppState,
    sess: &ConciergeSession,
    decision: &ToolDecision,
    warm: &mut Option<WarmBrowse>,
) -> TurnOutcome {
    match decision.tool.as_str() {
        "find_page" => tool_find_page(state, sess, &decision.args, warm).await,
        "propose_selectors" => tool_propose_selectors(state, sess, &decision.args, warm).await,
        "create_monitor" => tool_create_monitor(state, sess, &decision.args, warm).await,
        "ask_user" => tool_ask_user(state, sess, &decision.args).await,
        "wire_automation" => tool_wire_automation(state, sess).await,
        "build_workflow" => tool_build_workflow(state, sess, &decision.args).await,
        "discover_workflow" => tool_discover_workflow(state, sess, &decision.args).await,
        "add_callable_function" => tool_add_callable_function(state, sess, &decision.args).await,
        "test_workflow" => tool_test_workflow(state, sess, &decision.args).await,
        "configure_schedule" => tool_configure_schedule(state, sess, &decision.args).await,
        "enable_connect" => tool_enable_connect(state, sess, &decision.args).await,
        "propose_connect_setup" => tool_propose_connect_setup(state, sess).await,
        "dragnet_crawl" | "crawl_site" => tool_dragnet_crawl(state, sess, &decision.args).await,
        "synthesize_crawl_answer" => tool_synthesize_crawl_answer(state, sess, &decision.args).await,
        "list_datasets" => tool_list_datasets(state, sess).await,
        "search_datasets" => tool_search_datasets(state, sess, &decision.args).await,
        "answer_from_datasets" => tool_answer_from_datasets(state, sess, &decision.args).await,
        "finish" => tool_finish(state, sess, &decision.args).await,
        other => {
            // Unknown tool — nudge with the EXACT valid list so a model that invents names (e.g.
            // create_plan / respond) picks a real tool next instead of guessing again.
            let mut transcript = parse_arr(sess.transcript.as_deref());
            transcript.push(json!({
                "role": "system",
                "content": format!(
                    "'{other}' is NOT a tool. Reply again choosing ONE tool from EXACTLY this list \
                     (use the name verbatim, put its arguments under \"args\"): {}. Do NOT invent \
                     other names like create_plan/respond/clarify_requirements.",
                    VALID_TOOLS.join(", ")
                ),
                "ts": now_ts(),
            }));
            let ts = serde_json::to_string(&transcript).unwrap_or_else(|_| "[]".into());
            let _ = concierge_sessions::update(
                &state.db,
                sess.id,
                &ConciergeUpdate { transcript: Some(&ts), ..Default::default() },
            )
            .await;
            TurnOutcome::Continue
        }
    }
}

// ── Tool: find_page ──────────────────────────────────────────────────────────

/// Open (or reuse) the mission's WARM browser page, navigate to `seed_url` (or a URL guessed from
/// `query`), let it settle, read the final URL, and set `plan.resolved_url`. Leaves the page OPEN so
/// `propose_selectors` reads the same warm session; the context is closed once by `run_mission`.
async fn tool_find_page(
    state: &AppState,
    sess: &ConciergeSession,
    args: &Value,
    warm: &mut Option<WarmBrowse>,
) -> TurnOutcome {
    let Some(browser) = state.engine.browser() else {
        return TurnOutcome::Error("this engine cannot browse (no browser)".into());
    };
    let seed_url = args.get("seed_url").and_then(|s| s.as_str()).map(str::trim).filter(|s| !s.is_empty());
    let query = args.get("query").and_then(|s| s.as_str()).unwrap_or("").trim().to_string();

    // Resolve the navigation URL: an explicit seed wins; else if the query is itself a URL use it;
    // else pull a bare domain out of the query OR the goal ("monitor korben.info …" → korben.info)
    // so a site-named goal isn't a dead end. Only when NO domain is anywhere do we ask the model to
    // seed (desktop does no search-engine hop). A bare-domain nudge here would not change the progress
    // fingerprint, so without this fallback a domain-in-goal request stalls the whole mission.
    let nav_url = match seed_url {
        Some(u) => u.to_string(),
        None if looks_like_url(&query) => normalize_url(&query),
        None => match guess_domain_url(&format!("{query} {}", sess.goal)) {
            Some(u) => u,
            None => {
                let mut transcript = parse_arr(sess.transcript.as_deref());
                transcript.push(json!({
                    "role": "system",
                    "content": "find_page needs a seed_url (or a query that is a URL). Provide the exact page URL to open.",
                    "ts": now_ts(),
                }));
                let ts = serde_json::to_string(&transcript).unwrap_or_else(|_| "[]".into());
                let _ = concierge_sessions::update(
                    &state.db,
                    sess.id,
                    &ConciergeUpdate {
                        status: Some("planning"),
                        transcript: Some(&ts),
                        ..Default::default()
                    },
                )
                .await;
                return TurnOutcome::Continue;
            }
        },
    };

    // Mark the browsing phase for the FE narration + surface the streaming live preview: the shared
    // BrowserPreview button gates on resources.browse_session_id. The desktop preview streams over
    // `/ws/ai-preview/concierge-{id}` (keyed off the session id), so the value is just a truthy marker
    // — the mission's own id — set the moment a browse begins (button shows live, then replay at end).
    let mut resources = parse_obj(sess.resources.as_deref());
    resources
        .entry("browse_session_id".to_string())
        .or_insert_with(|| json!(sess.id));
    let resources_s = serde_json::to_string(&resources).unwrap_or_else(|_| "{}".into());
    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate {
            status: Some("browsing"),
            phase: Some("find_page"),
            progress_message: Some("Opening the page…"),
            resources: Some(&resources_s),
            ..Default::default()
        },
    )
    .await;

    // URL-guard BEFORE navigation (rejects file:/internal/metadata hosts).
    if !crate::security::url_guard::is_navigation_url_safe_async(&nav_url).await {
        return TurnOutcome::Error(format!("Refused unsafe URL: {nav_url}"));
    }

    if let Err(e) = browser.ensure_warm_browser_with(true).await {
        return TurnOutcome::Error(format!("browser launch failed: {e}"));
    }
    // Reuse the mission's warm page if one is already open; else create it (and bind it to the preview
    // channel). On a hard error we just return — run_mission closes the warm context on loop exit.
    let page = match ensure_warm_page(&browser, warm, sess.id).await {
        Ok(p) => p,
        Err(e) => return TurnOutcome::Error(e),
    };

    if let Err(e) = crate::browser::navigation::goto(&page, &nav_url, "domcontentloaded", Duration::from_secs(30)).await {
        return TurnOutcome::Error(format!("navigation failed: {e}"));
    }
    // Let late content settle (best-effort — a load-state timeout is not fatal).
    let _ = page.wait_for_load_state(None).await;

    let final_url = page.url();
    let title = page.title().await.unwrap_or_default();
    // Remember where the warm page is now, so propose_selectors can skip re-navigating to it.
    if let Some(w) = warm.as_mut() {
        w.url = final_url.clone();
    }

    // Capture one frame for the disk-cheap replay keyframe below. The LIVE view is the streaming
    // `/ws/ai-preview/concierge-{id}` screencast, not a DB-poll. Best-effort.
    let shot = crate::local::ai::observation::capture_screenshot_b64(&page).await;

    // Live thinking event + disk-cheap replay keyframe for this browse step.
    report_concierge_step(state, sess.id, "Opened the page", "Found and opened the target page.", &final_url, &shot).await;

    // The page stays WARM — do NOT close it. propose_selectors reads this same session next.

    // Record resolved_url + product_title into the plan.
    let mut plan = parse_obj(sess.plan.as_deref());
    plan.insert("resolved_url".into(), json!(final_url));
    if !title.trim().is_empty() {
        plan.insert("product_title".into(), json!(title));
    }
    let plan_s = serde_json::to_string(&plan).unwrap_or_else(|_| "{}".into());

    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate {
            status: Some("planning"),
            plan: Some(&plan_s),
            progress_message: Some("Found the page. Proposing a price selector…"),
            ..Default::default()
        },
    )
    .await;
    TurnOutcome::Continue
}

// ── Tool: propose_selectors ──────────────────────────────────────────────────

/// On the WARM page for `plan.resolved_url` (reused from `find_page` — same cookies/JS/login/scroll —
/// and navigated there only if the warm page isn't already), ask the FIND_SELECTORS brain for
/// candidate selectors, pick the best, and VALIDATE it on the live page (`querySelectorAll(...).length
/// > 0`). Sets `plan.<field>` (default `price_selector`). Leaves the page open; `run_mission` closes it.
async fn tool_propose_selectors(
    state: &AppState,
    sess: &ConciergeSession,
    args: &Value,
    warm: &mut Option<WarmBrowse>,
) -> TurnOutcome {
    let plan = parse_obj(sess.plan.as_deref());
    let Some(resolved_url) = plan.get("resolved_url").and_then(|u| u.as_str()).filter(|s| !s.is_empty()) else {
        // No page yet — nudge back to find_page.
        return nudge(state, sess, "propose_selectors needs plan.resolved_url first — call find_page.").await;
    };
    let resolved_url = resolved_url.to_string();
    let want = args.get("want").and_then(|w| w.as_str()).unwrap_or("price").to_string();
    // The plan key the validated selector is stored under. Default keeps the classic
    // price flow; login/list flows pass e.g. "login_username_selector".
    let field = args
        .get("field")
        .and_then(|f| f.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or("price_selector")
        .to_string();

    let Some(browser) = state.engine.browser() else {
        return TurnOutcome::Error("this engine cannot browse (no browser)".into());
    };

    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate {
            status: Some("proposing"),
            phase: Some("propose_selectors"),
            progress_message: Some("Reading the page to find a stable selector…"),
            ..Default::default()
        },
    )
    .await;

    if !crate::security::url_guard::is_navigation_url_safe_async(&resolved_url).await {
        return TurnOutcome::Error(format!("Refused unsafe URL: {resolved_url}"));
    }
    if let Err(e) = browser.ensure_warm_browser_with(true).await {
        return TurnOutcome::Error(format!("browser launch failed: {e}"));
    }
    // Reuse the warm session find_page landed on. Navigate only if the warm page isn't already on
    // resolved_url (or there is no warm page yet — e.g. a /respond re-spawn started a fresh loop).
    let page = match ensure_warm_page(&browser, warm, sess.id).await {
        Ok(p) => p,
        Err(e) => return TurnOutcome::Error(e),
    };
    let already_there = warm.as_ref().map(|w| w.url == resolved_url).unwrap_or(false);
    if !already_there {
        if let Err(e) = crate::browser::navigation::goto(&page, &resolved_url, "domcontentloaded", Duration::from_secs(30)).await {
            return TurnOutcome::Error(format!("navigation failed: {e}"));
        }
        let _ = page.wait_for_load_state(None).await;
        if let Some(w) = warm.as_mut() {
            w.url = resolved_url.clone();
        }
    }

    // Gather DOM + a screenshot for the selector brain (mirrors /v1/ai-assist/find-selectors input).
    // Send it the SAME way the Python AI assist does: a NOISE-STRIPPED DOM (no
    // scripts/styles/svg/base64) and a compressed JPEG — never a raw page.content() +
    // full-PNG dump. The warm page is already bound to the preview channel (in ensure_warm_page).
    let raw_dom = page.content().await.unwrap_or_default();
    let dom = crate::local::ai::context_clean::clean_dom_for_ai(&raw_dom);
    let shot = crate::local::ai::observation::capture_screenshot_b64(&page).await;
    let screenshot_b64 = if shot.is_empty() { None } else { Some(shot) };

    report_concierge_step(state, sess.id, "Read the page", "Reading the page to find a stable selector.", &resolved_url, screenshot_b64.as_deref().unwrap_or("")).await;

    let mut text = if field == "price_selector" {
        format!("URL: {resolved_url}\n\nThe user wants to monitor: the {want} on this page (a numeric value to watch for changes).")
    } else {
        format!("URL: {resolved_url}\n\nThe user wants a stable selector for: the {want} on this page.")
    };
    text.push_str(&format!("\n\nPAGE DOM:\n{}", cap(&dom, 24000)));
    let messages = vec![find_selectors_user_msg(text, screenshot_b64.as_deref())];

    let max_tokens = provider::resolve_max_tokens(&state.db, "assist", 2000).await;
    let completion = match provider::complete_routed(&state.db, &state.vault, &messages, Some(crate::local::ai::prompts::FIND_SELECTORS_SYSTEM), max_tokens, "assist").await {
        Ok(c) => c,
        // The warm context is closed by run_mission on loop exit — just surface the error here.
        Err(e) => return TurnOutcome::Error(format!("selector AI call failed: {e}")),
    };

    // Accrue tokens from this secondary call too.
    let input_tokens = sess.input_tokens + completion.input_tokens as i64;
    let output_tokens = sess.output_tokens + completion.output_tokens as i64;
    let total_tokens = input_tokens + output_tokens;

    // Parse candidate selectors, then pick the first that validates (count > 0) on the live page.
    let parsed = crate::ai::json_parser::parse_ai_json(&completion.text).unwrap_or_else(|| json!({}));
    let candidates: Vec<String> = parsed
        .get("selectors")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.get("selector").and_then(|s| s.as_str()))
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    let mut chosen: Option<String> = None;
    for sel in &candidates {
        if selector_matches(&page, sel).await {
            chosen = Some(sel.clone());
            break;
        }
    }
    // The page stays WARM (validated on the live session) — run_mission closes the context on exit.

    let Some(selector) = chosen else {
        // No candidate validated — record + retry (the model may re-navigate or ask the user).
        let _ = concierge_sessions::update(
            &state.db,
            sess.id,
            &ConciergeUpdate {
                status: Some("planning"),
                progress_message: Some("Could not find a stable selector automatically — retrying."),
                input_tokens: Some(input_tokens),
                output_tokens: Some(output_tokens),
                total_tokens: Some(total_tokens),
                ..Default::default()
            },
        )
        .await;
        return TurnOutcome::Continue;
    };

    let mut plan = parse_obj(sess.plan.as_deref());
    plan.insert(field.clone(), json!(selector));
    let plan_s = serde_json::to_string(&plan).unwrap_or_else(|_| "{}".into());

    let progress = if field == "price_selector" {
        "Selector found. Creating the monitor…".to_string()
    } else {
        format!("Selector found for the {want}.")
    };
    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate {
            status: Some("planning"),
            plan: Some(&plan_s),
            progress_message: Some(&progress),
            input_tokens: Some(input_tokens),
            output_tokens: Some(output_tokens),
            total_tokens: Some(total_tokens),
            ..Default::default()
        },
    )
    .await;
    TurnOutcome::Continue
}

// ── Tool: create_monitor ─────────────────────────────────────────────────────

/// Can this element be watched over PLAIN HTTP (no browser)? Fetch the RAW server HTML (the exact
/// bytes the HTTP check path sees — no JS) and test whether the selector matches an element with real
/// text there. `Some(true)` ⇒ server-rendered → a fast/cheap HTTP check works; `Some(false)` ⇒ the
/// selector is absent/empty in raw HTML → the value is injected by JS → needs a real browser; `None` ⇒
/// couldn't fetch/parse (caller defaults to the browser path — the safe choice). Mirrors the runtime
/// HTTP check (reqwest + scraper — see `monitor/checker.rs`), so `Some(true)` means the real check
/// will find it too.
async fn probe_http_viable(url: &str, selector: &str) -> Option<bool> {
    if url.is_empty() || selector.is_empty() || selector.starts_with("viewport-zone") {
        return None;
    }
    if !crate::security::url_guard::is_navigation_url_safe_async(url).await {
        return None;
    }
    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        .timeout(Duration::from_secs(20))
        .build()
        .ok()?;
    let body = client.get(url).send().await.ok()?.text().await.ok()?;
    if body.trim().is_empty() {
        return None;
    }
    // Parse AFTER the awaits — scraper's Html/Selector are !Send and must not be held across .await.
    let css = scraper::Selector::parse(selector).ok()?; // exotic selector scraper can't parse ⇒ unknown
    let doc = scraper::Html::parse_document(&body);
    match doc.select(&css).next() {
        Some(el) => Some(!el.text().collect::<String>().trim().is_empty()),
        None => Some(false),
    }
}

/// The MONITOR viewport (see `monitor/checker.rs` — checks run in 1280x800). A visual_region's coords
/// are viewport-relative, so they are ONLY valid if captured at the SAME resolution the check clips at.
const MONITOR_VIEWPORT: playwright_rs::Viewport = playwright_rs::Viewport { width: 1280, height: 800 };

/// Measure the element on the WARM page for a VISUAL (screenshot-zone) watch: its bounding box + the
/// page scroll (viewport-relative — the coordinate model `extract_visual` clips at). Returns the region
/// object `{x,y,width,height,scroll_x,scroll_y,viewport}` (rounded) or `None` (element gone / zero-area).
///
/// CRITICAL: the warm/discovery browser runs at 1920x1080 but the monitor checks at 1280x800 — a box
/// measured at the wrong resolution clips the wrong pixels and the zone is invalid. So we RESIZE the
/// page to the monitor viewport, let it reflow, measure there, then RESTORE the original size (so the
/// live preview + later tools are unaffected). Best-effort — a `None` means fall back to a text selector.
async fn probe_visual_region(page: &playwright_rs::Page, selector: &str) -> Option<Value> {
    let prev_vp = page.viewport_size();
    let resized = page.set_viewport_size(MONITOR_VIEWPORT).await.is_ok();
    if resized {
        tokio::time::sleep(Duration::from_millis(250)).await; // let the reflow settle before measuring
    }
    let sel_json = serde_json::to_string(selector).unwrap_or_else(|_| "\"\"".into());
    let js = format!(
        "() => {{ try {{ const el = document.querySelector({sel_json}); if (!el) return null; \
         const r = el.getBoundingClientRect(); if (r.width < 1 || r.height < 1) return null; \
         const rd = (n) => Math.round(n * 10) / 10; \
         return {{ x: rd(r.x), y: rd(r.y), width: rd(r.width), height: rd(r.height), \
         scroll_x: rd(window.scrollX), scroll_y: rd(window.scrollY), \
         viewport: {{ width: {mw}, height: {mh} }} }}; }} catch (e) {{ return null; }} }}",
        mw = MONITOR_VIEWPORT.width,
        mh = MONITOR_VIEWPORT.height,
    );
    let region = match page.evaluate::<(), Value>(&js, None::<&()>).await {
        Ok(v) if v.is_object() => Some(v),
        _ => None,
    };
    // Restore the warm page's original viewport so the live preview + subsequent tools see it unchanged.
    if resized {
        if let Some(vp) = prev_vp {
            let _ = page.set_viewport_size(vp).await;
        }
    }
    region
}

/// Create the Target + watched target_selector (+ a text/price extractor for non-visual watches) from
/// the plan. Records the ids in `resources`. Requires `plan.resolved_url` + `plan.price_selector`.
/// DECIDES how to watch: HTTP vs a full browser (auto-probed, or forced via `render`), and a text
/// selector vs a visual screenshot-zone (via `mode`), mirroring the cloud concierge.
async fn tool_create_monitor(
    state: &AppState,
    sess: &ConciergeSession,
    args: &Value,
    warm: &mut Option<WarmBrowse>,
) -> TurnOutcome {
    let plan = parse_obj(sess.plan.as_deref());
    let resolved_url = plan.get("resolved_url").and_then(|u| u.as_str()).unwrap_or("").to_string();
    let price_selector = plan.get("price_selector").and_then(|s| s.as_str()).unwrap_or("").to_string();
    if resolved_url.is_empty() {
        return nudge(state, sess, "create_monitor needs plan.resolved_url — call find_page first.").await;
    }
    if price_selector.is_empty() {
        return nudge(state, sess, "create_monitor needs plan.price_selector — call propose_selectors first.").await;
    }

    // What to WATCH: "content" tracks the element's TEXT and alerts on ANY change (blog posts,
    // status, availability, "notify me when X changes"); "price" (default) extracts a number so a
    // threshold alert is possible. Anything non-price collapses to content.
    let watch = args.get("watch").and_then(|w| w.as_str()).unwrap_or("price").to_ascii_lowercase();
    let mut is_content = matches!(watch.as_str(), "content" | "text" | "change" | "changed");
    // HOW to watch (planner decides): mode "visual" → clip a screenshot ZONE and diff pixels (charts,
    // images, canvas, maps, styled areas). render "http"|"js"|"auto" → force a plain-HTTP check, force
    // a browser, or (default) AUTO-DETECT by probing whether the element is in the raw server HTML.
    let mode = args
        .get("mode")
        .or_else(|| args.get("watch_via"))
        .and_then(|m| m.as_str())
        .unwrap_or("selector")
        .to_ascii_lowercase();
    let render = args
        .get("render")
        .or_else(|| args.get("render_mode"))
        .and_then(|r| r.as_str())
        .unwrap_or("auto")
        .to_ascii_lowercase();
    let want_visual = matches!(mode.as_str(), "visual" | "zone" | "screenshot" | "image" | "pixel");

    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate {
            status: Some("building"),
            phase: Some("create_monitor"),
            progress_message: Some("Deciding how best to watch this…"),
            ..Default::default()
        },
    )
    .await;

    // ── Decide content_type + visual_region (selector vs. visual zone) ───────────────────────────
    let mut content_type = "text".to_string();
    let mut visual_region_json: Option<String> = None;
    let mut visual_note = "";
    if want_visual {
        // Measure the element's on-screen box on the WARM page (reused from find_page/propose_selectors).
        let region = if let Some(browser) = state.engine.browser() {
            if browser.ensure_warm_browser_with(true).await.is_ok() {
                match ensure_warm_page(&browser, warm, sess.id).await {
                    Ok(page) => probe_visual_region(&page, &price_selector).await,
                    Err(_) => None,
                }
            } else {
                None
            }
        } else {
            None
        };
        if let Some(r) = region {
            content_type = "visual".into();
            visual_region_json = Some(r.to_string());
            is_content = true; // a pixel diff is a change-alert by nature — no threshold
        } else {
            visual_note = " (couldn't capture the visual zone on the live page, so it watches the element's text instead)";
        }
    }

    // ── Decide requires_playwright (HTTP vs. JS) ─────────────────────────────────────────────────
    // A visual zone can only be clipped in a real browser. Otherwise honor an explicit render, else
    // AUTO-DETECT: server-rendered element ⇒ fast HTTP check; JS-injected ⇒ browser.
    let (requires_playwright, render_decided): (bool, &str) = if content_type == "visual" {
        (true, "js")
    } else if render == "http" {
        (false, "http")
    } else if render == "js" {
        (true, "js")
    } else {
        match probe_http_viable(&resolved_url, &price_selector).await {
            Some(true) => (false, "http"), // only skip the browser when POSITIVELY confirmed
            _ => (true, "js"),
        }
    };

    // Target: NO target-level selector (the per-selector row drives the check). Interval floored to the
    // HTTP or JS anti-detection minimum depending on the chosen path.
    let check_period_ms =
        crate::local::scheduler::clamp::clamp_monitor_interval_ms(Some(300_000), requires_playwright);
    let target_id = match targets::insert(
        &state.db,
        &targets::NewTarget {
            url: resolved_url.clone(),
            check_type: Some("content".into()),
            requires_playwright: Some(if requires_playwright { 1 } else { 0 }),
            check_period_ms: Some(check_period_ms),
            enabled: Some(1),
            ..Default::default()
        },
    )
    .await
    {
        Ok(id) => id,
        Err(e) => return TurnOutcome::Error(format!("could not create monitor target: {e}")),
    };

    // Watched selector — text/price (CSS text) or visual (screenshot zone with a region).
    let sel_name = if content_type == "visual" {
        "zone"
    } else if is_content {
        "content"
    } else {
        "price"
    };
    let selector_id = match target_selectors::insert(
        &state.db,
        &target_selectors::NewTargetSelector {
            target_id,
            name: sel_name.into(),
            selector: price_selector.clone(),
            content_type: Some(content_type.clone()),
            visual_region: visual_region_json.clone(),
            enabled: Some(1),
            ..Default::default()
        },
    )
    .await
    {
        Ok(id) => id,
        Err(e) => return TurnOutcome::Error(format!("could not create the watched selector: {e}")),
    };

    // Field extractor: NONE for a visual zone (the change signal is the region's pixel-hash, compared
    // at the selector level). content → capture the element's TEXT verbatim; price → a regex pulling
    // the first number-like token so a threshold can apply.
    let extractor_id: Option<i64> = if content_type == "visual" {
        None
    } else {
        let (ex_name, ex_output, ex_type, ex_config) = if is_content {
            ("content", "content", "text", None)
        } else {
            ("price", "price", "regex", Some(json!({ "pattern": "([0-9][0-9.,]*)", "group": 1 }).to_string()))
        };
        match selector_extractors::insert(
            &state.db,
            &selector_extractors::NewSelectorExtractor {
                target_selector_id: selector_id,
                name: ex_name.into(),
                output_name: ex_output.into(),
                extract_type: Some(ex_type.into()),
                config: ex_config,
                enabled: Some(1),
                ..Default::default()
            },
        )
        .await
        {
            Ok(id) => Some(id),
            Err(e) => return TurnOutcome::Error(format!("could not create the extractor: {e}")),
        }
    };

    // Record ids + the watch kind (wire_automation reads it to build a change-only vs threshold alert).
    let mut resources = parse_obj(sess.resources.as_deref());
    resources.insert("target_id".into(), json!(target_id));
    resources.insert("target_selector_id".into(), json!(selector_id));
    if let Some(ex) = extractor_id {
        resources.insert("extractor_id".into(), json!(ex));
    }
    let resources_s = serde_json::to_string(&resources).unwrap_or_else(|_| "{}".into());

    let mut plan = plan;
    plan.insert("watch_kind".into(), json!(if is_content { "content" } else { "price" }));
    plan.insert("watch_render".into(), json!(render_decided)); // "http" | "js" — for the finish summary
    plan.insert("watch_via".into(), json!(content_type)); // "text" | "visual"
    let plan_s = serde_json::to_string(&plan).unwrap_or_else(|_| "{}".into());

    // A human line so the finish summary (and the transcript) states WHAT + HOW it watches.
    let watch_what = if content_type == "visual" {
        "a visual zone for any change"
    } else if is_content {
        "for changes"
    } else {
        "the price"
    };
    let how = if render_decided == "http" { "over fast HTTP checks" } else { "in a full browser (JS-rendered)" };
    let line = format!("Created a monitor on {resolved_url} watching {watch_what} {how}.{visual_note}");
    let mut transcript = parse_arr(sess.transcript.as_deref());
    transcript.push(json!({ "role": "assistant", "content": line, "ts": now_ts() }));
    let transcript_s = serde_json::to_string(&transcript).unwrap_or_else(|_| "[]".into());

    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate {
            status: Some("building"),
            resources: Some(&resources_s),
            plan: Some(&plan_s),
            transcript: Some(&transcript_s),
            progress_message: Some("Monitor created. Wiring the alert…"),
            ..Default::default()
        },
    )
    .await;
    TurnOutcome::Continue
}

// ── Tool: ask_user (pause) ───────────────────────────────────────────────────

/// Pause the mission: store the `pending_request` and flip to `awaiting_input`. `resume_status` is
/// `building` once a target exists (we are mid-build) else `planning`. Fires a desktop toast so the
/// user knows the assistant is waiting.
async fn tool_ask_user(state: &AppState, sess: &ConciergeSession, args: &Value) -> TurnOutcome {
    let requests = args.get("requests").and_then(|r| r.as_array()).cloned().unwrap_or_default();
    // Keep only well-formed, desktop-safe requests (never payment_method/secret_card_fields).
    // "secret" pauses for a credential that /respond stores in the local vault (the planner only
    // ever sees its {{secret:KEY}} placeholder). "persona" lets the user pick a saved login
    // identity (which carries the session + TOTP, so it can pass MFA).
    let allowed_kinds = ["text", "value", "choice", "confirm", "secret", "persona"];

    // Persona options are populated HERE (the planner doesn't know persona ids) — the user's local
    // personas as {id, label, domain}, so the picker renders and the answer carries a real id.
    let persona_opts: Vec<Value> = personas::list(&state.db, Some(50))
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|p| {
            let mut o = serde_json::Map::new();
            o.insert("id".into(), json!(p.id));
            o.insert("label".into(), json!(p.name));
            if let Some(d) = p.target_domain.filter(|s| !s.is_empty()) {
                o.insert("domain".into(), json!(d));
            }
            Value::Object(o)
        })
        .collect();

    let clean: Vec<Value> = requests
        .into_iter()
        .filter(|r| r.is_object())
        .filter_map(|r| {
            let field = r.get("field").and_then(|f| f.as_str())?.to_string();
            if field.is_empty() {
                return None;
            }
            let kind = r.get("kind").and_then(|k| k.as_str()).unwrap_or("text");
            let kind = if allowed_kinds.contains(&kind) { kind } else { "text" };
            let question = r.get("question").and_then(|q| q.as_str()).unwrap_or("").to_string();
            let mut out = serde_json::Map::new();
            out.insert("field".into(), json!(field));
            out.insert("kind".into(), json!(kind));
            out.insert("question".into(), json!(question));
            // Persona kind: inject the local persona list unless the planner supplied options.
            if kind == "persona" && !r.get("options").is_some_and(|o| o.is_array()) {
                out.insert("options".into(), json!(persona_opts));
            } else if let Some(opts) = r.get("options").filter(|o| o.is_array()) {
                out.insert("options".into(), opts.clone());
            }
            if let Some(multi) = r.get("multi").and_then(|m| m.as_bool()) {
                out.insert("multi".into(), json!(multi));
            }
            if let Some(default) = r.get("default") {
                out.insert("default".into(), default.clone());
            }
            // Login asks: pass the site-specific credential fields through so the FE reveals them
            // INLINE under the "enter credentials" option (a single key, or username + password, …).
            if let Some(cf) = r.get("credential_fields").filter(|c| c.is_array()) {
                out.insert("credential_fields".into(), cf.clone());
            }
            Some(Value::Object(out))
        })
        .collect();

    if clean.is_empty() {
        return nudge(state, sess, "ask_user needs at least one valid request {field, kind, question}.").await;
    }

    let resources = parse_obj(sess.resources.as_deref());
    let resume_status = if resources.get("target_id").is_some() { "building" } else { "planning" };
    let pending = json!({ "requests": clean, "resume_status": resume_status });
    let pending_s = pending.to_string();

    // A friendly progress line = the first question.
    let first_q = clean
        .first()
        .and_then(|r| r.get("question").and_then(|q| q.as_str()))
        .unwrap_or("The assistant needs your input.")
        .to_string();

    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate {
            status: Some("awaiting_input"),
            phase: Some("ask_user"),
            progress_message: Some(&first_q),
            pending_request: Some(&pending_s),
            ..Default::default()
        },
    )
    .await;

    // Notify the app so the user knows to come back and answer.
    crate::local::flow::push_pending_toast("Assistant needs your input", &first_q);
    TurnOutcome::Pause
}

// ── Tool: wire_automation ────────────────────────────────────────────────────

/// Build + self-validate the alert block tree and persist it as an Automation bound to the monitor's
/// target. Threshold comes from `answers.threshold` (fallback: baseline). Finalizes the mission.
async fn tool_wire_automation(state: &AppState, sess: &ConciergeSession) -> TurnOutcome {
    let resources = parse_obj(sess.resources.as_deref());
    let plan = parse_obj(sess.plan.as_deref());
    let answers = parse_obj(sess.answers.as_deref());

    let Some(target_id) = resources.get("target_id").and_then(Value::as_i64) else {
        return nudge(state, sess, "wire_automation needs a monitor — call create_monitor first.").await;
    };
    let selector_id = resources.get("target_selector_id").and_then(Value::as_i64);

    // Watch kind decides the alert shape: "content" fires on ANY change (no condition, no threshold);
    // "price" applies a `lt threshold` condition when a numeric threshold is known.
    let is_content = plan.get("watch_kind").and_then(|w| w.as_str()) == Some("content");
    let threshold_value = if is_content {
        Value::Null
    } else {
        coerce_number(
            &answers
                .get("threshold")
                .or_else(|| plan.get("threshold"))
                .or_else(|| plan.get("baseline_price"))
                .cloned()
                .unwrap_or(Value::Null),
        )
    };
    // A price watch with no numeric threshold falls back to "alert on any change" rather than writing
    // a broken `extracted.price lt null` condition.
    let has_threshold = threshold_value.is_number();

    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate {
            status: Some("building"),
            phase: Some("wire_automation"),
            progress_message: Some("Wiring the alert…"),
            ..Default::default()
        },
    )
    .await;

    // Build the block tree: event -> [condition?] -> notification.
    let event_id = "evt";
    let cond_id = "cond";
    let notif_id = "notif";
    let product = plan.get("product_title").and_then(|t| t.as_str()).filter(|s| !s.is_empty());
    let (title, template): (String, &str) = if is_content {
        (
            product.map(|t| format!("Update: {t}")).unwrap_or_else(|| "Page updated".into()),
            "The page you're watching just changed:\n{{extracted.content}}",
        )
    } else {
        (
            product.map(|t| format!("Price alert: {t}")).unwrap_or_else(|| "Price alert".into()),
            "The price is now {{extracted.price}} (below your target).",
        )
    };

    let mut event_cfg = json!({ "target_id": target_id });
    if let Some(sid) = selector_id {
        event_cfg["target_selector_id"] = json!(sid);
    }
    // The notification hangs off the condition when there is one, else straight off the event.
    let notif_parent = if has_threshold { cond_id } else { event_id };
    // Each block carries BOTH `blockType` (which block) AND `type` (event/condition/action). The
    // desktop builder categorizes blocks by `type` (FlowBuilder finds the root via `type === 'event'`
    // and actions via `type === 'action'`); OMITTING it makes the trigger + notification render EMPTY
    // even though their config is correct — the "content-change block has no monitor" bug.
    let mut block_arr: Vec<Value> = vec![
        json!({ "id": event_id, "blockType": "change_detected", "type": "event", "parentId": Value::Null, "config": event_cfg }),
    ];
    if has_threshold {
        block_arr.push(json!({
            "id": cond_id, "blockType": "condition", "type": "condition", "parentId": event_id,
            "config": { "field": "extracted.price", "operator": "lt", "value": threshold_value.clone() }
        }));
    }
    block_arr.push(json!({
        "id": notif_id, "blockType": "notification", "type": "action", "parentId": notif_parent,
        "config": { "channels": ["desktop", "in_app"], "title": title, "template": template }
    }));
    let blocks = Value::Array(block_arr);

    // Self-validate the tree before persisting (fail closed rather than write a broken automation).
    if let Err(reason) = validate_block_tree(&blocks) {
        return TurnOutcome::Error(format!("built an invalid automation tree: {reason}"));
    }

    // Legacy actions array (parity with the cloud/daemon dual shape).
    let actions = json!([
        { "type": "notify", "channels": ["desktop", "in_app"], "title": title, "template": template }
    ]);
    let blocks_s = blocks.to_string();
    let actions_s = actions.to_string();
    // Legacy top-level condition only for a real price threshold; a content/any-change watch has none.
    let conditions_s = has_threshold
        .then(|| json!({ "field": "extracted.price", "operator": "lt", "value": threshold_value }).to_string());

    let (auto_name, auto_desc) = if is_content {
        ("Content change alert", "Created by the AI concierge — notify when the watched content changes.")
    } else {
        ("Price drop alert", "Created by the AI concierge — notify when the watched price drops below the target.")
    };
    let automation = match automations::insert(
        &state.db,
        &automations::NewAutomation {
            name: auto_name.into(),
            description: Some(auto_desc.into()),
            event_type: Some("change_detected".into()),
            target_id: Some(target_id),
            target_selector_id: selector_id,
            enabled: Some(1),
            conditions: conditions_s,
            actions: Some(actions_s),
            blocks: Some(blocks_s),
            ..Default::default()
        },
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return TurnOutcome::Error(format!("could not create the alert automation: {e}")),
    };

    let mut resources = resources;
    resources.insert("trigger_rule_id".into(), json!(automation.id));
    let resources_s = serde_json::to_string(&resources).unwrap_or_else(|_| "{}".into());

    // Final transcript line + done.
    let mut transcript = parse_arr(sess.transcript.as_deref());
    let summary = if is_content {
        "Your monitor and change alert are live. I'll notify you on this device when the watched content changes."
    } else {
        "Your monitor and price-drop alert are live. I'll notify you on this device when the price drops below your target."
    };
    transcript.push(json!({ "role": "assistant", "content": summary, "ts": now_ts() }));
    let transcript_s = serde_json::to_string(&transcript).unwrap_or_else(|_| "[]".into());

    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate {
            resources: Some(&resources_s),
            transcript: Some(&transcript_s),
            ..Default::default()
        },
    )
    .await;
    let _ = concierge_sessions::finalize(&state.db, sess.id, "done", Some(summary), None).await;
    TurnOutcome::Done
}

// ── Tool: finish ─────────────────────────────────────────────────────────────

// The `finish` tool: end the mission — `done` unless the model asked for `error`; the summary is
// appended to the transcript. Its model-facing contract lives in the planner prompt above.
// ── Tool: dragnet_crawl (crawl_site) ─────────────────────────────────────────

/// Write `plan._last_result.dragnet_crawl = <value>` (re-reading the freshest plan so the mirroring
/// loop's updates aren't clobbered) and continue the mission — the next planner turn reads it to
/// decide whether to expose the dataset or finish. Takes the session id (not a borrow) so it can be
/// called after the row has been mutated many times during progress mirroring.
async fn dragnet_finish_turn(state: &AppState, session_id: i64, result: Value) -> TurnOutcome {
    if let Ok(Some(cs)) = concierge_sessions::get_by_id(&state.db, session_id).await {
        let mut plan = parse_obj(cs.plan.as_deref());
        plan.insert("_last_result".into(), json!({ "dragnet_crawl": result }));
        let plan_s = serde_json::to_string(&plan).unwrap_or_else(|_| "{}".into());
        let _ = concierge_sessions::update(
            &state.db,
            session_id,
            &ConciergeUpdate { plan: Some(&plan_s), ..Default::default() },
        )
        .await;
    }
    TurnOutcome::Continue
}

/// DRAGNET — crawl a WHOLE site LOCALLY into ONE dataset. Resolves a seed (arg → plan.resolved_url →
/// the site named in the goal), starts a local crawl, and BLOCKS the turn while mirroring live crawl
/// counters into the mission progress (like a browse does), propagating a mission Stop into the
/// crawl. Sets resources.crawl_id + resources.workflow_id so the next planner turn can expose the
/// dataset as an API or finish with the dataset link. Parallels the cloud `_tool_dragnet_crawl`.
async fn tool_dragnet_crawl(state: &AppState, sess: &ConciergeSession, args: &Value) -> TurnOutcome {
    let plan = parse_obj(sess.plan.as_deref());

    // Seed URL: explicit arg → the resolved page → a domain named in the goal.
    let mut seed = args
        .get("url")
        .and_then(|v| v.as_str())
        .or_else(|| args.get("seed_url").and_then(|v| v.as_str()))
        .unwrap_or("")
        .trim()
        .to_string();
    if seed.is_empty() {
        seed = plan.get("resolved_url").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    }
    if seed.is_empty() {
        let q = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
        seed = guess_domain_url(&format!("{q} {}", sess.goal)).unwrap_or_default();
    }
    if !seed.is_empty() && !looks_like_url(&seed) && seed.contains('.') && !seed.contains(' ') {
        seed = normalize_url(&seed);
    }
    if seed.is_empty() {
        return dragnet_finish_turn(state, sess.id, json!("no site to crawl — give a URL")).await;
    }

    let extract_raw = args
        .get("extract")
        .and_then(|v| v.as_str())
        .or_else(|| args.get("extract_mode").and_then(|v| v.as_str()))
        .unwrap_or("markdown")
        .to_ascii_lowercase();
    let extract_mode = if extract_raw == "schema" { "schema" } else { "markdown" };
    let max_pages = args
        .get("max_pages")
        .and_then(|v| v.as_i64())
        .or_else(|| args.get("limit").and_then(|v| v.as_i64()))
        .unwrap_or(500)
        .clamp(1, 50_000);
    let to_list = |v: Option<&Value>| -> Vec<String> {
        match v {
            Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
            Some(Value::String(s)) if !s.trim().is_empty() => vec![s.trim().to_string()],
            _ => Vec::new(),
        }
    };
    let include = to_list(args.get("include").or_else(|| args.get("include_paths")));
    let exclude = to_list(args.get("exclude").or_else(|| args.get("exclude_paths")));
    let persona_id = plan.get("persona_id").and_then(|v| v.as_i64());
    let content = args.get("content").filter(|v| !v.is_null()).cloned();

    // TARGETED DISCOVER-AND-EXTRACT: a "top N" ask passes rank_cap → scrape the seed LIST page plus
    // EXACTLY the top-N ranked detail links off it (depth 1, budget N+1), never a whole-site wander.
    // Both crawl engines match `include` on path+query, so include=["item\\?id="] admits only detail
    // pages (and pagination like "/news?p=2" is rejected). max_rows caps rows-per-page for synthesis.
    let rank_cap = args
        .get("rank_cap")
        .and_then(|v| v.as_i64())
        .or_else(|| args.get("top_n").and_then(|v| v.as_i64()))
        .filter(|n| *n > 0)
        .map(|n| n.clamp(1, 100));
    let max_rows = args.get("max_rows").and_then(|v| v.as_i64()).filter(|n| *n > 0);
    // max_depth: forced to 1 for a targeted top-N; else the planner's arg (None ⇒ engine default /
    // cloud intent-derivation). page_budget: N+1 for targeted (seed + top N), else the whole-site cap.
    let (max_depth_opt, page_budget): (Option<i64>, i64) = match rank_cap {
        Some(n) => (Some(1), (n + 1).clamp(2, 200)),
        None => (
            args.get("max_depth").and_then(|v| v.as_i64()).map(|d| d.clamp(0, 20)),
            max_pages,
        ),
    };

    // Mark the building phase + the mapping line.
    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate {
            status: Some("building"),
            phase: Some("dragnet_crawl"),
            progress_message: Some(&format!("Dragnet: mapping {seed}…")),
            ..Default::default()
        },
    )
    .await;

    // CLOUD-LINKED: Dragnet is a cloud feature on the managed desktop app — the crawl runs on the
    // cloud FLEET (many egress IPs, managed browsers, gateway-metered AI), exactly like the REST/MCP
    // crawl paths, and NEVER on this one machine. A linked account routes to the fleet; without a
    // credential we REFUSE (defense in depth behind the UI's cloud gate). The on-device worker pool
    // below is compiled ONLY into the OSS / self-host build (no `cloud` feature).
    #[cfg(feature = "cloud")]
    {
        if crate::local::cloud::crawl::is_linked(&state.db).await {
            return dragnet_crawl_cloud(
                state,
                sess,
                &seed,
                extract_mode,
                &include,
                &exclude,
                persona_id,
                max_depth_opt,
                page_budget,
                max_rows,
                content.as_ref(),
            )
            .await;
        }
        dragnet_finish_turn(
            state,
            sess.id,
            json!("crawling needs a linked cloud account — Dragnet runs on the cloud fleet, not this machine"),
        )
        .await
    }

    #[cfg(not(feature = "cloud"))]
    {
    let crawl = match crate::local::crawl::start_crawl(
        state,
        crate::local::crawl::StartParams {
            seed_url: seed.clone(),
            extract_mode: extract_mode.into(),
            persona_id,
            include_paths: include,
            exclude_paths: exclude,
            max_depth: max_depth_opt.unwrap_or(3),
            page_budget,
            content,
            concierge_session_id: Some(sess.id),
            ..Default::default()
        },
    )
    .await
    {
        Ok(c) => c,
        Err(e) => return dragnet_finish_turn(state, sess.id, json!(format!("couldn't start: {e}"))).await,
    };

    let crawl_id = crawl.id;
    let workflow_id = crawl.workflow_id.unwrap_or(0);

    // Record the resources so the planner can expose/finish (+ max_rows for synthesis).
    let mut resources = parse_obj(sess.resources.as_deref());
    resources.insert("crawl_id".into(), json!(crawl_id));
    resources.insert("workflow_id".into(), json!(workflow_id));
    let resources_s = serde_json::to_string(&resources).unwrap_or_else(|_| "{}".into());
    let mut plan_m = plan.clone();
    plan_m.insert("crawl_id".into(), json!(crawl_id));
    if let Some(m) = max_rows {
        plan_m.insert("crawl_max_rows".into(), json!(m));
    }
    let plan_s = serde_json::to_string(&plan_m).unwrap_or_else(|_| "{}".into());
    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate { resources: Some(&resources_s), plan: Some(&plan_s), ..Default::default() },
    )
    .await;

    // Mirror live crawl progress (≈15 min safety cap; the FE keeps polling the mission row).
    // Host label for the live card (scheme-stripped, path-stripped).
    let seed_host = seed
        .split("://")
        .nth(1)
        .unwrap_or(seed.as_str())
        .split('/')
        .next()
        .unwrap_or("")
        .to_string();
    let mut last_msg: Option<String> = None;
    for _ in 0..600 {
        tokio::time::sleep(Duration::from_millis(1500)).await;
        // Re-read the mission this tick: honor a Stop, and reuse its resources as the
        // base we merge live counters onto (preserving crawl_id/workflow_id).
        let cs = match concierge_sessions::get_by_id(&state.db, sess.id).await {
            Ok(Some(cs)) => {
                if cs.cancel_requested != 0 {
                    let _ = crate::local::crawl::cancel_crawl(state, crawl_id).await;
                    break;
                }
                Some(cs)
            }
            _ => None,
        };
        let crawl = match crate::local::store::crawl_jobs::get_by_id(&state.db, crawl_id).await {
            Ok(Some(c)) => c,
            _ => break,
        };
        let active = crawl.workers_active.max(0);
        let terminal = crawl.is_terminal();
        let msg = if terminal {
            format!(
                "Dragnet {}: {} pages captured{}",
                crawl.status,
                crawl.pages_done,
                if crawl.pages_failed > 0 { format!(", {} failed", crawl.pages_failed) } else { String::new() }
            )
        } else {
            format!(
                "Dragnet: {}/{} pages, {} working, depth {}",
                crawl.pages_done, crawl.pages_discovered, active, crawl.current_depth
            )
        };
        let progress_changed = last_msg.as_deref() != Some(msg.as_str());
        if progress_changed {
            last_msg = Some(msg.clone());
        }
        // Mirror the STRUCTURED live counters onto the mission as `resources.crawl_live` —
        // the ONLY progress feed the desktop live-crawl card reads (the desktop has no
        // run-events SSE store). Without it the card is frozen on "Mapping 0/…" for the
        // whole crawl. (Same field the linked-cloud path and the Python orchestrator write.)
        if cs.is_some() {
            // Write ONLY `resources.crawl_live`, never the whole `resources` column. This loop ticks
            // roughly once a second for up to 15 minutes; `POST /v1/ai-concierge/:id/persona` writes
            // `resources.persona_id` on the same row at any time. Both used to read-modify-write the
            // entire column, so whichever committed second erased the other's key: a persona attached
            // mid-crawl silently vanished, or `crawl_live` reverted and the live card froze.
            // `json_set` on one path makes the two writers independent.
            let live = json!({
                "crawl_id": crawl_id,
                "seed_host": seed_host,
                "status": crawl.status,
                "event": if terminal { "ended" } else { "updated" },
                "pages_done": crawl.pages_done,
                "pages_discovered": crawl.pages_discovered,
                "pages_failed": crawl.pages_failed,
                "pages_skipped": crawl.pages_skipped,
                "agents_active": active,
                "current_depth": crawl.current_depth,
                "page_budget": crawl.page_budget,
            });
            let _ = concierge_sessions::set_json_key(
                &state.db,
                sess.id,
                "resources",
                "crawl_live",
                Some(&live.to_string()),
            )
            .await;
            if progress_changed {
                let _ = concierge_sessions::update(
                    &state.db,
                    sess.id,
                    &ConciergeUpdate { progress_message: Some(msg.as_str()), ..Default::default() },
                )
                .await;
            }
        } else if progress_changed {
            // Session read failed this tick — still keep the human progress line moving.
            let _ = concierge_sessions::update(
                &state.db,
                sess.id,
                &ConciergeUpdate { progress_message: Some(msg.as_str()), ..Default::default() },
            )
            .await;
        }
        if terminal {
            break;
        }
    }

    // Record the outcome so the next planner turn can expose the dataset or finish.
    let final_crawl = crate::local::store::crawl_jobs::get_by_id(&state.db, crawl_id).await.ok().flatten();
    let result = json!({
        "crawl_id": crawl_id,
        "workflow_id": workflow_id,
        "status": final_crawl.as_ref().map(|c| c.status.clone()).unwrap_or_else(|| "unknown".into()),
        "pages_done": final_crawl.as_ref().map(|c| c.pages_done).unwrap_or(0),
        "pages_failed": final_crawl.as_ref().map(|c| c.pages_failed).unwrap_or(0),
    });
    dragnet_finish_turn(state, sess.id, result).await
    }
}

/// CLOUD-LINKED Dragnet: dispatch the crawl to the fleet (`POST /api/crawl`) and BLOCK the turn
/// mirroring the cloud crawl's live progress into the mission — the linked-desktop twin of the local
/// worker-pool path in [`tool_dragnet_crawl`]. Stores the CLOUD crawl id + its synthetic data-workflow
/// id as resources so `synthesize_crawl_answer` reads the fleet dataset and the planner can expose/finish.
#[cfg(feature = "cloud")]
#[allow(clippy::too_many_arguments)]
async fn dragnet_crawl_cloud(
    state: &AppState,
    sess: &ConciergeSession,
    seed: &str,
    extract_mode: &str,
    include: &[String],
    exclude: &[String],
    persona_id: Option<i64>,
    max_depth: Option<i64>,
    page_budget: i64,
    max_rows: Option<i64>,
    content: Option<&Value>,
) -> TurnOutcome {
    // The cloud StartCrawlRequest. A forced `max_depth`/`include` gives the fleet an EXPLICIT scope
    // (targeted top-N); leaving max_depth null lets the cloud derive scope for a whole-site sweep.
    let body = json!({
        "url": seed,
        "executor": "regular",
        "extract_mode": extract_mode,
        "include_paths": include,
        "exclude_paths": exclude,
        "max_depth": max_depth,
        "page_budget": page_budget,
        "max_concurrent_shards": 6,
        "delay_ms": 250,
        "relevance_threshold": 0.0,
        "respect_robots": true,
        "same_domain": true,
        "allow_subdomains": true,
        "persona_id": persona_id,
        "content": content,
    });

    let view = match crate::local::cloud::crawl::start(&state.db, &body).await {
        Ok(v) => v,
        Err(e) => return dragnet_finish_turn(state, sess.id, json!(format!("couldn't start: {e}"))).await,
    };
    let crawl_id = view.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    let workflow_id = view
        .get("data_workflow_id")
        .and_then(|v| v.as_i64())
        .or_else(|| view.get("workflow_id").and_then(|v| v.as_i64()))
        .unwrap_or(0);
    if crawl_id == 0 {
        return dragnet_finish_turn(state, sess.id, json!("cloud crawl did not start")).await;
    }

    // Record the CLOUD ids as resources so the dataset read (synthesize / data view) forwards to the
    // fleet, and stash max_rows for synthesis.
    let mut resources = parse_obj(sess.resources.as_deref());
    resources.insert("crawl_id".into(), json!(crawl_id));
    resources.insert("workflow_id".into(), json!(workflow_id));
    let resources_s = serde_json::to_string(&resources).unwrap_or_else(|_| "{}".into());
    let mut plan_m = parse_obj(sess.plan.as_deref());
    plan_m.insert("crawl_id".into(), json!(crawl_id));
    plan_m.insert("crawl_venue".into(), json!("cloud"));
    if let Some(m) = max_rows {
        plan_m.insert("crawl_max_rows".into(), json!(m));
    }
    let plan_s = serde_json::to_string(&plan_m).unwrap_or_else(|_| "{}".into());
    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate { resources: Some(&resources_s), plan: Some(&plan_s), ..Default::default() },
    )
    .await;

    // Mirror live cloud-crawl progress (≈15 min safety cap). A mission Stop cancels the cloud crawl.
    let is_terminal = |status: &str| matches!(status, "completed" | "failed" | "cancelled");
    // Host label for the live card (scheme-stripped, path-stripped).
    let seed_host = seed
        .split("://")
        .nth(1)
        .unwrap_or(seed)
        .split('/')
        .next()
        .unwrap_or("")
        .to_string();
    let mut last_msg: Option<String> = None;
    let mut final_view = view.clone();
    for _ in 0..600 {
        tokio::time::sleep(Duration::from_millis(1500)).await;
        // Re-read the mission this tick: honor a Stop, and reuse its resources as the
        // base we merge live counters onto (preserving crawl_id/workflow_id).
        let cs = match concierge_sessions::get_by_id(&state.db, sess.id).await {
            Ok(Some(cs)) => {
                if cs.cancel_requested != 0 {
                    let _ = crate::local::cloud::crawl::cancel(&state.db, crawl_id).await;
                    break;
                }
                Some(cs)
            }
            _ => None,
        };
        let v = match crate::local::cloud::crawl::get(&state.db, crawl_id).await {
            Ok(v) => v,
            Err(_) => break,
        };
        let status = v.get("status").and_then(|s| s.as_str()).unwrap_or("running").to_string();
        let pages_done = v.get("pages_done").and_then(|x| x.as_i64()).unwrap_or(0);
        let discovered = v.get("pages_discovered").and_then(|x| x.as_i64()).unwrap_or(0);
        let failed = v.get("pages_failed").and_then(|x| x.as_i64()).unwrap_or(0);
        let disp = v.get("shards_dispatched").and_then(|x| x.as_i64()).unwrap_or(0);
        let done = v.get("shards_done").and_then(|x| x.as_i64()).unwrap_or(0);
        let depth = v.get("current_depth").and_then(|x| x.as_i64()).unwrap_or(0);
        final_view = v;
        let terminal = is_terminal(&status);
        let active = (disp - done).max(0);
        let msg = if terminal {
            format!(
                "Dragnet {status}: {pages_done} pages captured{}",
                if failed > 0 { format!(", {failed} failed") } else { String::new() }
            )
        } else {
            format!("Dragnet: {pages_done}/{discovered} pages, {active} working, depth {depth}")
        };
        let progress_changed = last_msg.as_deref() != Some(msg.as_str());
        if progress_changed {
            last_msg = Some(msg.clone());
        }
        // Mirror the STRUCTURED live counters onto the mission as `resources.crawl_live`.
        // This is the ONLY progress feed the desktop live-crawl card reads (unlike the
        // cloud web app, the desktop has no run-events SSE store) — without it the card
        // is frozen on "Mapping 0/…" for the entire crawl, even on a fully successful run.
        // Mirrors the Python cloud orchestrator's `_tool_dragnet_crawl` loop.
        if let Some(cs) = cs.as_ref() {
            let mut resources = parse_obj(cs.resources.as_deref());
            resources.insert(
                "crawl_live".into(),
                json!({
                    "crawl_id": crawl_id,
                    "seed_host": seed_host,
                    "status": status,
                    "event": if terminal { "ended" } else { "updated" },
                    "pages_done": pages_done,
                    "pages_discovered": discovered,
                    "pages_failed": failed,
                    "agents_active": active,
                    "shards_dispatched": disp,
                    "shards_done": done,
                    "current_depth": depth,
                    "page_budget": page_budget,
                }),
            );
            let resources_s = serde_json::to_string(&resources).unwrap_or_else(|_| "{}".into());
            let _ = concierge_sessions::update(
                &state.db,
                sess.id,
                &ConciergeUpdate {
                    resources: Some(&resources_s),
                    progress_message: if progress_changed { Some(msg.as_str()) } else { None },
                    ..Default::default()
                },
            )
            .await;
        } else if progress_changed {
            // Session read failed this tick — still keep the human progress line moving.
            let _ = concierge_sessions::update(
                &state.db,
                sess.id,
                &ConciergeUpdate { progress_message: Some(msg.as_str()), ..Default::default() },
            )
            .await;
        }
        if terminal {
            break;
        }
    }

    let result = json!({
        "crawl_id": crawl_id,
        "workflow_id": workflow_id,
        "venue": "cloud",
        "status": final_view.get("status").and_then(|s| s.as_str()).unwrap_or("unknown"),
        "pages_done": final_view.get("pages_done").and_then(|x| x.as_i64()).unwrap_or(0),
        "pages_failed": final_view.get("pages_failed").and_then(|x| x.as_i64()).unwrap_or(0),
    });
    dragnet_finish_turn(state, sess.id, result).await
}

/// Per-page and total corpus caps for [`tool_synthesize_crawl_answer`] — keep the focused detail
/// pages within a small model's budget so an HN item thread's top comments survive the fold.
const SYNTH_PAGE_CHARS: usize = 9000;
const SYNTH_CORPUS_CHARS: usize = 90_000;

/// Fold a FINISHED dragnet_crawl's dataset into ONE Markdown answer (discover-and-extract, e.g. "top 3
/// HN stories + top 3 comments each") and write it to the chat. Reads the per-page records collected
/// under the crawl's synthetic workflow — from the cloud dataset when linked (the crawl ran on the
/// fleet) or the local `runs` store otherwise — folds them with ONE AI call, orders detail pages before
/// index/listing pages so a capped corpus never drops an item page's comments, and guards against a
/// degenerate/looping completion. No monitor, no trigger. For a discover-and-extract the ANSWER *is*
/// the deliverable, so this ENDS the mission itself rather than trusting the planner to call `finish`
/// next (a small planner model otherwise re-picks synthesize and loops, re-billing the fold each turn).
/// Parallels the cloud `_tool_synthesize_crawl_answer`.
async fn tool_synthesize_crawl_answer(state: &AppState, sess: &ConciergeSession, args: &Value) -> TurnOutcome {
    let resources = parse_obj(sess.resources.as_deref());
    let plan = parse_obj(sess.plan.as_deref());

    // Already answered (the planner re-picked this tool): never re-run the fold — that bills a second
    // AI call and pushes a duplicate answer bubble. The answer is in the chat; just end the mission.
    if plan.get("crawl_answer").and_then(Value::as_str).is_some_and(|s| !s.trim().is_empty()) {
        let _ =
            concierge_sessions::finalize(&state.db, sess.id, "done", Some("Answer ready."), None).await;
        return TurnOutcome::Done;
    }

    let crawl_id = resources.get("crawl_id").and_then(|v| v.as_i64()).unwrap_or(0);
    let workflow_id = resources.get("workflow_id").and_then(|v| v.as_i64()).unwrap_or(0);
    if crawl_id == 0 || workflow_id == 0 {
        return nudge_system(
            state,
            sess,
            "Run dragnet_crawl first — there is no crawl dataset to synthesize.",
        )
        .await;
    }

    let question = args
        .get("question")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| sess.goal.clone());
    let max_rows = args
        .get("max_rows")
        .and_then(|v| v.as_i64())
        .or_else(|| plan.get("crawl_max_rows").and_then(|v| v.as_i64()))
        .filter(|n| *n > 0)
        .map(|n| n as usize);

    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate {
            status: Some("building"),
            phase: Some("synthesize_crawl_answer"),
            progress_message: Some("Folding the crawled pages into an answer…"),
            ..Default::default()
        },
    )
    .await;

    // Collect per-page records: cloud dataset (fleet) when linked, else the local runs store.
    let cloud_venue = plan.get("crawl_venue").and_then(|v| v.as_str()) == Some("cloud");
    let pages = collect_synth_pages(state, workflow_id, cloud_venue, max_rows).await;
    if pages.is_empty() {
        return nudge_system(
            state,
            sess,
            "The crawl returned no page data to synthesize — finish and report that honestly.",
        )
        .await;
    }

    let corpus = {
        let mut s = serde_json::to_string(&pages).unwrap_or_default();
        s.truncate(SYNTH_CORPUS_CHARS.min(s.len()));
        s
    };
    let system = "You turn crawled web-page records into the exact answer the user asked for. \
        Use ONLY the provided data and respect any 'top N' the user specified. Output ONLY the final \
        answer as clean, concise Markdown (headings/lists) — do NOT show any working, reasoning, sorting \
        steps, or intermediate thoughts, and never repeat a line. If the data is insufficient, say so in \
        ONE sentence and stop.";
    let user = format!(
        "User's request:\n{question}\n\nCrawled page records (JSON):\n{corpus}\n\nFinal answer only:"
    );
    let messages = vec![AiMessage { role: "user".into(), content: AiMessageContent::Text(user) }];

    let max_tokens = provider::resolve_max_tokens(&state.db, "assist", 1500).await;
    let completion =
        match provider::complete_routed(&state.db, &state.vault, &messages, Some(system), max_tokens, "assist").await {
            Ok(c) => c,
            // A failed fold used to nudge the planner, which re-picked this same tool and failed the
            // same way every turn — three silent retries, then the stall breaker closed the mission
            // with the generic "I've set up what I could, but couldn't finish the rest on my own".
            // The crawl itself succeeded, so report what actually broke and END, rather than spinning
            // and then blaming the build.
            Err(e) => {
                let msg = format!(
                    "I crawled the pages but couldn't turn them into an answer: {e}\n\n\
                     The collected pages are saved — open the crawl to read them, or ask me again \
                     with a narrower request."
                );
                let mut transcript = parse_arr(sess.transcript.as_deref());
                transcript.push(json!({ "role": "assistant", "content": msg, "ts": now_ts() }));
                let ts = serde_json::to_string(&transcript).unwrap_or_else(|_| "[]".into());
                let _ = concierge_sessions::update(
                    &state.db,
                    sess.id,
                    &ConciergeUpdate { transcript: Some(&ts), ..Default::default() },
                )
                .await;
                let _ = concierge_sessions::finalize(
                    &state.db, sess.id, "error", Some("Couldn't synthesize the answer."), Some(&msg),
                )
                .await;
                return TurnOutcome::Done;
            }
        };

    let mut answer = completion.text.trim().to_string();
    if answer.is_empty() || looks_degenerate(&answer) {
        answer = "I couldn't assemble a clean answer from the crawled pages. Try narrowing the crawl to \
            the specific detail pages you need (e.g. the top few item pages) and re-run."
            .to_string();
    }

    // Accrue token counts (local AI is free — display only) and write the answer to the chat.
    let input_tokens = sess.input_tokens + completion.input_tokens as i64;
    let output_tokens = sess.output_tokens + completion.output_tokens as i64;
    let total_tokens = input_tokens + output_tokens;
    let ai_calls = sess.ai_calls_count + 1;
    let mut plan_m = plan.clone();
    plan_m.insert("crawl_answer".into(), json!(answer));
    plan_m.insert(
        "_last_result".into(),
        json!({ "synthesize_crawl_answer": { "pages": pages.len() } }),
    );
    let plan_s = serde_json::to_string(&plan_m).unwrap_or_else(|_| "{}".into());
    let mut transcript = parse_arr(sess.transcript.as_deref());
    transcript.push(json!({ "role": "assistant", "content": answer, "ts": now_ts() }));
    let transcript_s = serde_json::to_string(&transcript).unwrap_or_else(|_| "[]".into());
    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate {
            plan: Some(&plan_s),
            transcript: Some(&transcript_s),
            progress_message: Some("Answer ready."),
            input_tokens: Some(input_tokens),
            output_tokens: Some(output_tokens),
            total_tokens: Some(total_tokens),
            ai_calls_count: Some(ai_calls),
            ..Default::default()
        },
    )
    .await;
    // END the mission here. The answer IS the deliverable — nothing is left to build, and the
    // documented recipe is "synthesize -> finish". Ending inline (instead of returning Continue and
    // trusting the planner to pick `finish`) is what stops the observed loop where a small planner
    // model re-picked synthesize every turn, re-billing the fold and re-posting the answer until the
    // step budget ran out. `tool_finish` already suppresses its "here's what I built" review when
    // plan.crawl_answer is set, so no user-visible summary is lost by not routing through it.
    let _ = concierge_sessions::finalize(&state.db, sess.id, "done", Some("Answer ready."), None).await;
    TurnOutcome::Done
}

/// `list_datasets` — enumerate the user's EXISTING datasets (every past crawl/workflow that has
/// accumulated extracted data, local + merged cloud crawl datasets on a linked desktop). No crawl,
/// no AI: a cheap catalogue so the planner can search or answer from data already on hand instead of
/// re-crawling. Stashes the list into `plan._available.datasets` for the next planner turn. Parallels
/// the cloud `_tool_list_datasets`.
async fn tool_list_datasets(state: &AppState, sess: &ConciergeSession) -> TurnOutcome {
    let list = match crate::local::api::v1::data::concierge_list_datasets(state).await {
        Ok(v) => v,
        Err(e) => return nudge_system(state, sess, &format!("Couldn't list datasets: {e}")).await,
    };
    let datasets = list.get("datasets").and_then(|d| d.as_array()).cloned().unwrap_or_default();
    let count = datasets.len();
    let shown: Vec<Value> = datasets.into_iter().take(40).collect();

    let mut plan = parse_obj(sess.plan.as_deref());
    let mut avail = plan.get("_available").and_then(|v| v.as_object()).cloned().unwrap_or_default();
    avail.insert("datasets".into(), json!(shown));
    plan.insert("_available".into(), Value::Object(avail));
    plan.insert("_last_result".into(), json!({ "list_datasets": { "count": count } }));
    let plan_s = serde_json::to_string(&plan).unwrap_or_else(|_| "{}".into());
    let msg = format!("Found {count} existing dataset(s).");
    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate { plan: Some(&plan_s), progress_message: Some(&msg), ..Default::default() },
    )
    .await;
    TurnOutcome::Continue
}

/// `search_datasets` — full-text search the user's ALREADY-collected data (the same FTS5 engine
/// behind the `/v1/datasets/search` route), globally or one dataset via `dataset_id`. No crawl, no
/// AI: it tells the planner whether the answer is already on hand. The top matches land in
/// `plan._available.dataset_hits` and the total in `_last_result` so the next turn can answer from
/// data (matches) or crawl (none). Parallels the cloud `_tool_search_datasets`.
async fn tool_search_datasets(state: &AppState, sess: &ConciergeSession, args: &Value) -> TurnOutcome {
    let q = args
        .get("q")
        .or_else(|| args.get("query"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| sess.goal.clone());
    if q.trim().is_empty() {
        return nudge_system(state, sess, "Pass q — the keywords to search your datasets for.").await;
    }
    let dataset_id = args.get("dataset_id").or_else(|| args.get("workflow_id")).and_then(|v| v.as_i64());

    let found = match crate::local::api::v1::data::concierge_dataset_search(state, dataset_id, &q, 20, 0).await {
        Ok(v) => v,
        Err(e) => return nudge_system(state, sess, &format!("Dataset search failed: {e}")).await,
    };
    let results = found.get("results").and_then(|r| r.as_array()).cloned().unwrap_or_default();
    let total = found.get("total").and_then(|v| v.as_i64()).unwrap_or(results.len() as i64);
    let hits: Vec<Value> = results
        .iter()
        .take(10)
        .map(|r| {
            let ds = r.get("dataset");
            json!({
                "dataset_id": ds.and_then(|d| d.get("id")).cloned().unwrap_or(Value::Null),
                "dataset_name": ds.and_then(|d| d.get("name")).cloned().unwrap_or(Value::Null),
                "run_at": r.get("run_at").cloned().unwrap_or(Value::Null),
                "snippet": r.get("highlight").and_then(|h| h.get("snippet")).cloned().unwrap_or(Value::Null),
            })
        })
        .collect();

    let mut plan = parse_obj(sess.plan.as_deref());
    let mut avail = plan.get("_available").and_then(|v| v.as_object()).cloned().unwrap_or_default();
    avail.insert("dataset_hits".into(), json!(hits));
    plan.insert("_available".into(), Value::Object(avail));
    plan.insert(
        "_last_result".into(),
        json!({ "search_datasets": { "query": q, "total": total, "shown": hits.len() } }),
    );
    let plan_s = serde_json::to_string(&plan).unwrap_or_else(|_| "{}".into());
    let msg = format!("{total} match(es) in your datasets for \u{201c}{q}\u{201d}.");
    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate { plan: Some(&plan_s), progress_message: Some(&msg), ..Default::default() },
    )
    .await;
    TurnOutcome::Continue
}

/// `answer_from_datasets` — answer a data question STRAIGHT from the user's already-collected datasets:
/// full-text search their past records (globally, or one dataset via `dataset_id`), fold the matches
/// into ONE Markdown answer with a single AI call, and write it to the chat. The cheap path — no crawl.
/// Nudges (so the planner can crawl instead) when nothing matches. Parallels the cloud
/// `_tool_answer_from_datasets`.
async fn tool_answer_from_datasets(state: &AppState, sess: &ConciergeSession, args: &Value) -> TurnOutcome {
    let question = args
        .get("question")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| sess.goal.clone());
    let q = args
        .get("q")
        .or_else(|| args.get("query"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| question.clone());
    if q.trim().is_empty() {
        return nudge_system(state, sess, "Pass q/question so I know what to look for in your datasets.").await;
    }
    let dataset_id = args.get("dataset_id").or_else(|| args.get("workflow_id")).and_then(|v| v.as_i64());

    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate {
            status: Some("building"),
            phase: Some("answer_from_datasets"),
            progress_message: Some("Searching your existing datasets…"),
            ..Default::default()
        },
    )
    .await;

    let found = match crate::local::api::v1::data::concierge_dataset_search(state, dataset_id, &q, 60, 0).await {
        Ok(v) => v,
        Err(e) => return nudge_system(state, sess, &format!("Dataset search failed: {e}")).await,
    };
    let results = found.get("results").and_then(|r| r.as_array()).cloned().unwrap_or_default();
    if results.is_empty() {
        return nudge_system(
            state,
            sess,
            "No existing dataset matched — collect the data first (dragnet_crawl / discover_workflow), \
             then answer, or finish and say you don't have it yet.",
        )
        .await;
    }

    // Fold the matched records (each carries its source dataset + the run's fields) into ONE answer.
    let records: Vec<Value> = results
        .iter()
        .map(|r| {
            json!({
                "dataset": r.get("dataset").and_then(|d| d.get("name")).cloned().unwrap_or(Value::Null),
                "run_at": r.get("run_at").cloned().unwrap_or(Value::Null),
                "fields": r.get("fields").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();
    let corpus = {
        let mut s = serde_json::to_string(&records).unwrap_or_default();
        s.truncate(SYNTH_CORPUS_CHARS.min(s.len()));
        s
    };
    let system = "You answer the user's question using ONLY the provided records, which come from \
        datasets the user has already collected. Respect any 'top N' the user specified and cite the \
        dataset a fact came from when useful. Output ONLY the final answer as clean, concise Markdown \
        (headings/lists) — no working, reasoning, or intermediate steps, and never repeat a line. If \
        the records don't contain enough to answer, say so in ONE sentence and stop.";
    let user = format!(
        "User's question:\n{question}\n\nMatching records from the user's datasets (JSON):\n{corpus}\n\nFinal answer only:"
    );
    let messages = vec![AiMessage { role: "user".into(), content: AiMessageContent::Text(user) }];

    let max_tokens = provider::resolve_max_tokens(&state.db, "assist", 1500).await;
    let completion =
        match provider::complete_routed(&state.db, &state.vault, &messages, Some(system), max_tokens, "assist").await {
            Ok(c) => c,
            Err(e) => return nudge_system(state, sess, &format!("Couldn't answer from your datasets: {e}")).await,
        };
    let mut answer = completion.text.trim().to_string();
    if answer.is_empty() || looks_degenerate(&answer) {
        answer = "I found matching data but couldn't assemble a clean answer. Try a more specific \
            question, or re-collect the data with a fresh crawl."
            .to_string();
    }

    // Accrue token counts (local AI is free — display only) and write the answer to the chat.
    let input_tokens = sess.input_tokens + completion.input_tokens as i64;
    let output_tokens = sess.output_tokens + completion.output_tokens as i64;
    let total_tokens = input_tokens + output_tokens;
    let ai_calls = sess.ai_calls_count + 1;
    let mut plan = parse_obj(sess.plan.as_deref());
    plan.insert("dataset_answer".into(), json!(answer));
    plan.insert(
        "_last_result".into(),
        json!({ "answer_from_datasets": { "records": records.len() } }),
    );
    let plan_s = serde_json::to_string(&plan).unwrap_or_else(|_| "{}".into());
    let mut transcript = parse_arr(sess.transcript.as_deref());
    transcript.push(json!({ "role": "assistant", "content": answer, "ts": now_ts() }));
    let transcript_s = serde_json::to_string(&transcript).unwrap_or_else(|_| "[]".into());
    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate {
            plan: Some(&plan_s),
            transcript: Some(&transcript_s),
            progress_message: Some("Answer ready."),
            input_tokens: Some(input_tokens),
            output_tokens: Some(output_tokens),
            total_tokens: Some(total_tokens),
            ai_calls_count: Some(ai_calls),
            ..Default::default()
        },
    )
    .await;
    // END the mission — same reasoning as `tool_synthesize_crawl_answer`: the answer is the whole
    // deliverable, so don't return Continue and rely on the planner picking `finish` (it may re-pick
    // this tool instead and loop, re-billing the fold each turn).
    let _ = concierge_sessions::finalize(&state.db, sess.id, "done", Some("Answer ready."), None).await;
    TurnOutcome::Done
}

/// One crawled page reduced to what synthesis needs: its URL/title plus either the page markdown
/// (markdown mode) or its structured records (schema / on-agent AI extraction).
#[derive(serde::Serialize)]
struct SynthPage {
    url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rows: Option<Vec<Value>>,
}

/// Read the crawl dataset (up to 200 pages) and reduce each page to a [`SynthPage`]. Cloud crawls read
/// the fleet dataset (`/api/workflows/{id}/data`); local crawls read the `runs` store. Detail pages are
/// ordered before index/listing pages so a capped corpus drops the least-useful page (a bare listing),
/// never an item page's comments.
async fn collect_synth_pages(
    state: &AppState,
    workflow_id: i64,
    cloud_venue: bool,
    max_rows: Option<usize>,
) -> Vec<SynthPage> {
    // Each crawl page is persisted as one row/record carrying either `markdown` (markdown mode) or
    // structured fields. Normalize both shapes into a SynthPage.
    let record_to_page = |rec: &Value| -> Option<SynthPage> {
        let obj = rec.as_object()?;
        let url = obj
            .get("url")
            .or_else(|| obj.get("_source_url"))
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let title = obj.get("title").and_then(|v| v.as_str()).map(str::to_string);
        if let Some(md) = obj.get("markdown").and_then(|v| v.as_str()) {
            let mut content = md.to_string();
            content.truncate(SYNTH_PAGE_CHARS.min(content.len()));
            if content.is_empty() {
                return None;
            }
            Some(SynthPage { url, title, content: Some(content), rows: None })
        } else {
            None
        }
    };

    let mut records: Vec<Value> = Vec::new();
    if cloud_venue {
        #[cfg(feature = "cloud")]
        {
            // The cloud data table is {columns, rows:[…]} where each row is run PROVENANCE wrapping
            // the record: {run_id, run_at, status, record_index, fields:{url,title,markdown,…}}. The
            // scraped page lives under `fields`, NOT at the row's top level — the same shape the crawl
            // data grid reads (CrawlDetailView: `const f = row.fields || {}`).
            //
            // Taking the row as-is didn't just mislabel things, it broke the fold: with no top-level
            // `markdown` every row missed the markdown branch below and fell through to the raw-record
            // fallback, which applies NO per-page character cap and yields no url — so instead of 4
            // pages capped at SYNTH_PAGE_CHARS each and ordered detail-first, the corpus became whole
            // raw rows (full comment threads) truncated only at the 90k overall ceiling, with the
            // detail-vs-index ordering neutralized. That is what left the HN run with no answer.
            if let Ok(v) = crate::local::cloud::workflow_data::get(&state.db, workflow_id, "", Some("limit=200")).await
            {
                if let Some(rows) = v.get("rows").and_then(|r| r.as_array()) {
                    records.extend(
                        rows.iter()
                            .map(|r| r.get("fields").cloned().unwrap_or_else(|| r.clone())),
                    );
                }
            }
        }
    } else {
        // Local: each `runs` row's result_data is {"extracted_data": [record, ...]}.
        if let Ok(runs) = crate::local::store::runs::list_by_workflow(&state.db, workflow_id, 200).await {
            for run in runs {
                let Some(rd) = run.result_data.as_deref() else { continue };
                let Ok(parsed) = serde_json::from_str::<Value>(rd) else { continue };
                if let Some(arr) = parsed.get("extracted_data").and_then(|x| x.as_array()) {
                    records.extend(arr.iter().cloned());
                }
            }
        }
    }

    let mut pages: Vec<SynthPage> = Vec::new();
    for rec in &records {
        if pages.len() >= 200 {
            break;
        }
        if let Some(page) = record_to_page(rec) {
            // Markdown mode: one row/page carrying the page markdown (already capped per page).
            pages.push(page);
        } else if let Some(rows) = rec.get("rows").and_then(|r| r.as_array()) {
            // A record that itself holds sub-rows (schema extraction): cap per max_rows.
            let capped: Vec<Value> = match max_rows {
                Some(m) => rows.iter().take(m).cloned().collect(),
                None => rows.clone(),
            };
            if !capped.is_empty() {
                let url = rec.get("url").and_then(|v| v.as_str()).map(str::to_string);
                let title = rec.get("title").and_then(|v| v.as_str()).map(str::to_string);
                pages.push(SynthPage { url, title, content: None, rows: Some(capped) });
            }
        } else if rec.is_object() {
            // A bare structured record (schema mode): carry it as a single-row page so schema-extracted
            // data isn't dropped from the fold.
            let url = rec
                .get("_source_url")
                .or_else(|| rec.get("url"))
                .and_then(|v| v.as_str())
                .map(str::to_string);
            pages.push(SynthPage { url, title: None, content: None, rows: Some(vec![rec.clone()]) });
        }
    }

    // Order DETAIL pages before index/listing pages (a bare single-segment path with no query is
    // index-like) so a capped corpus drops the listing, never an item page's comments.
    pages.sort_by_key(|p| if is_index_url(p.url.as_deref().unwrap_or("")) { 1 } else { 0 });
    pages
}

/// An index/listing URL: a bare single-segment path with no query (e.g. "/news"). A detail page has a
/// query id or a deeper path (e.g. "/item?id=1", "/a/b"). Used to rank detail pages ahead of listings.
fn is_index_url(u: &str) -> bool {
    let Ok(parsed) = url::Url::parse(u) else { return false };
    if parsed.query().map(|q| !q.is_empty()).unwrap_or(false) {
        return false;
    }
    parsed.path().split('/').filter(|s| !s.is_empty()).count() <= 1
}

/// A cheap guard against a small model looping or emitting garbage over a large/repetitive corpus:
/// an answer that is mostly one repeated line, or riddled with `<unk>`/replacement chars, is rejected.
fn looks_degenerate(text: &str) -> bool {
    let t = text.trim();
    if t.len() < 8 {
        return true;
    }
    if t.matches("<unk>").count() >= 3 || t.matches('\u{fffd}').count() >= 3 {
        return true;
    }
    let lines: Vec<&str> = t.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    if lines.len() >= 6 {
        let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for l in &lines {
            *counts.entry(*l).or_insert(0) += 1;
        }
        if let Some(max) = counts.values().max() {
            if *max as f64 / lines.len() as f64 > 0.5 {
                return true;
            }
        }
    }
    false
}

/// Append a SYSTEM correction to the transcript and continue the loop — the planner reads it next turn
/// and corrects course (e.g. run dragnet_crawl first, or finish honestly). No status change.
async fn nudge_system(state: &AppState, sess: &ConciergeSession, note: &str) -> TurnOutcome {
    let mut transcript = parse_arr(sess.transcript.as_deref());
    transcript.push(json!({ "role": "system", "content": note, "ts": now_ts() }));
    let ts = serde_json::to_string(&transcript).unwrap_or_else(|_| "[]".into());
    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate { transcript: Some(&ts), ..Default::default() },
    )
    .await;
    TurnOutcome::Continue
}

async fn tool_finish(state: &AppState, sess: &ConciergeSession, args: &Value) -> TurnOutcome {
    let summary = args.get("summary").and_then(|s| s.as_str()).unwrap_or("Mission complete.").to_string();
    let status = match args.get("status").and_then(|s| s.as_str()) {
        Some("error") => "error",
        _ => "done",
    };

    // AUTO-FINISH: a successful build ENDS the mission (status `done`) instead of parking in
    // `awaiting_input` for a confirm-to-finish. It still SHOWS exactly what was created — the workflow
    // with its steps, the monitor, the API surfaces — appended to the finish summary, but doesn't block
    // on the user's OK (they can review/edit the created resources from their own pages). This is why
    // the assistant no longer sits in the "needs attention" state after it has built everything.
    let mut summary = summary;
    if status == "done" {
        let resources = parse_obj(sess.resources.as_deref());
        let plan = parse_obj(sess.plan.as_deref());
        // A discover-and-extract (synthesize_crawl_answer) already wrote the ANSWER to the chat — the
        // crawl's synthetic workflow is not a deliverable to list, so skip the "here's what I built"
        // review in that case (mirrors the cloud, where plan.crawl_answer is the deliverable).
        let has_answer = plan
            .get("crawl_answer")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.trim().is_empty());
        let built = !has_answer
            && ["workflow_id", "target_id", "trigger_rule_id"]
                .iter()
                .any(|k| resources.get(*k).and_then(Value::as_i64).is_some());
        if built {
            let (_review, human) = build_finish_review(state, &resources, &plan).await;
            summary = format!("{summary}\n\nHere's what I built for you:\n{human}");
        }
    }

    let mut transcript = parse_arr(sess.transcript.as_deref());
    transcript.push(json!({ "role": "assistant", "content": summary, "ts": now_ts() }));
    let transcript_s = serde_json::to_string(&transcript).unwrap_or_else(|_| "[]".into());
    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate { transcript: Some(&transcript_s), ..Default::default() },
    )
    .await;
    let err = (status == "error").then_some(summary.as_str());
    let _ = concierge_sessions::finalize(&state.db, sess.id, status, Some(&summary), err).await;
    TurnOutcome::Done
}

/// Build the review shown at the confirm-to-finish pause: a machine-readable object (for rich FE
/// rendering) + a human-readable multi-line summary of EXACTLY what was created — the workflow with its
/// steps, the monitor, and any exposed API surfaces — so the user sees the automation before it's saved.
async fn build_finish_review(state: &AppState, resources: &serde_json::Map<String, Value>, plan: &serde_json::Map<String, Value>) -> (Value, String) {
    let mut lines: Vec<String> = Vec::new();
    let mut review = serde_json::Map::new();

    if let Some(wid) = resources.get("workflow_id").and_then(Value::as_i64) {
        if let Ok(Some(wf)) = workflows::get_by_id(&state.db, wid).await {
            let steps: Vec<Value> = serde_json::from_str(&wf.steps).unwrap_or_default();
            let step_descs: Vec<String> = steps
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    let ty = s.get("type").and_then(|v| v.as_str()).unwrap_or("step");
                    let desc = s
                        .get("description")
                        .and_then(|v| v.as_str())
                        .filter(|d| !d.is_empty())
                        .or_else(|| s.get("config").and_then(|c| c.get("url")).and_then(|v| v.as_str()))
                        .unwrap_or("");
                    if desc.is_empty() {
                        format!("{}. {ty}", i + 1)
                    } else {
                        format!("{}. {ty} — {desc}", i + 1)
                    }
                })
                .collect();
            lines.push(format!("• Workflow “{}” — {} step(s):", wf.name, steps.len()));
            for d in &step_descs {
                lines.push(format!("    {d}"));
            }
            review.insert("workflow".into(), json!({ "id": wid, "name": wf.name, "steps": step_descs }));
        }
    }

    if let Some(tid) = resources.get("target_id").and_then(Value::as_i64) {
        let is_price = plan.get("watch_kind").and_then(|v| v.as_str()) == Some("price");
        lines.push(format!("• A monitor watching {}.", if is_price { "the price" } else { "for changes" }));
        review.insert("monitor".into(), json!({ "target_id": tid, "watch": if is_price { "price" } else { "content" } }));
    }
    if resources.get("trigger_rule_id").and_then(Value::as_i64).is_some() {
        lines.push("• A notification when it changes.".into());
    }
    if let Some(conn) = plan.get("connect").filter(|c| c.is_object()) {
        let surfaces: Vec<&str> = ["rest", "openai", "mcp"]
            .iter()
            .filter(|s| conn.get(**s).and_then(Value::as_bool).unwrap_or(false))
            .copied()
            .collect();
        if !surfaces.is_empty() {
            lines.push(format!("• Exposed as a callable API ({}).", surfaces.join(", ")));
            review.insert("connect".into(), conn.clone());
        }
    }

    // PROOF, not narration: the sample of real data the workflow extracted during its live-verified
    // run — the user sees exactly what the API/workflow returns before confirming.
    if let Some(sample) = plan
        .get("test_result")
        .and_then(|t| t.get("sample"))
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
    {
        let shown: String = sample.chars().take(240).collect();
        lines.push(format!("• Live data it returned when tested: {shown}"));
        review.insert("sample".into(), json!(sample));
    }

    let human = if lines.is_empty() { "the automation".to_string() } else { lines.join("\n") };
    (Value::Object(review), human)
}

// ── Tool: build_workflow ─────────────────────────────────────────────────────

/// Record a reusable, runnable local workflow from the browsing so far. The autonomous AI session does
/// not expose a harvestable executed-action buffer (its `SessionResult` carries only `current_url` +
/// `filled_fields`), so v1 builds the workflow from what the concierge already knows: a `navigate`
/// step to `plan.resolved_url`, plus an `extract` step for `plan.price_selector` when one was proposed.
/// This is a GENUINELY runnable workflow (not a placeholder), just not a full click-by-click replay —
/// see the module report. Sets `plan.workflow_id` + `resources.workflow_id`.
async fn tool_build_workflow(state: &AppState, sess: &ConciergeSession, args: &Value) -> TurnOutcome {
    let plan = parse_obj(sess.plan.as_deref());
    let resolved_url = plan.get("resolved_url").and_then(|u| u.as_str()).unwrap_or("").to_string();
    if resolved_url.is_empty() {
        return nudge(state, sess, "build_workflow needs plan.resolved_url — call find_page first.").await;
    }
    let price_selector = plan.get("price_selector").and_then(|s| s.as_str()).filter(|s| !s.is_empty());

    let name = args
        .get("name")
        .and_then(|n| n.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| plan.get("product_title").and_then(|t| t.as_str()).filter(|s| !s.is_empty()).map(|t| format!("Watch: {t}")))
        .unwrap_or_else(|| "Concierge workflow".to_string());
    let goal = args.get("goal").and_then(|g| g.as_str()).unwrap_or(sess.goal.as_str());

    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate {
            status: Some("building"),
            phase: Some("build_workflow"),
            progress_message: Some("Recording a reusable workflow…"),
            ..Default::default()
        },
    )
    .await;

    // Planner-supplied explicit steps (login flows, list extraction, …) beat the legacy
    // navigate(+price extract) synthesis. Invalid steps nudge the planner instead of persisting.
    let steps = match args.get("steps").filter(|s| s.is_array()) {
        Some(raw) => match validate_planner_steps(raw) {
            Ok(steps) => Value::Array(steps),
            Err(msg) => return nudge(state, sess, &format!("build_workflow steps rejected: {msg}")).await,
        },
        None => build_workflow_steps(&resolved_url, price_selector),
    };
    // A reconstructed HTTP sign-in recipe (AGENT_API mode) the planner returns alongside the steps, so
    // the built workflow authenticates over HTTP without a browser. Stored as JSON TEXT.
    let auth_config_s: Option<String> = args
        .get("auth_config")
        .filter(|v| v.is_object())
        .map(|v| serde_json::to_string(v).unwrap_or_default())
        .filter(|s| !s.is_empty());
    // The run entry point is the FIRST navigate of the steps (a login page for auth
    // flows), falling back to the resolved page.
    let entry_url = steps
        .as_array()
        .and_then(|a| {
            a.iter()
                .find(|s| s.get("type").and_then(|t| t.as_str()) == Some("navigate"))
                .and_then(|s| s.pointer("/config/url"))
                .and_then(|u| u.as_str())
        })
        .unwrap_or(&resolved_url)
        .to_string();
    let steps_s = serde_json::to_string(&steps).unwrap_or_else(|_| "[]".into());

    // A linked persona is the workflow's login identity: at run time the engine restores its saved
    // session and mints its TOTP, so the workflow logs in (and passes 2FA) on its own.
    let persona_id = plan.get("persona_id").and_then(Value::as_i64);

    // REVISION path: a workflow already exists for this mission — update it in place
    // (steps/name/description) instead of leaving the broken one and minting a duplicate.
    let existing_id = plan.get("workflow_id").and_then(Value::as_i64);
    let workflow_id = match existing_id {
        Some(id) => {
            match workflows::update(
                &state.db,
                id,
                &workflows::WorkflowUpdate {
                    name: Some(name),
                    steps: Some(steps_s),
                    entry_url: Some(entry_url),
                    default_persona_id: persona_id,
                    ..Default::default()
                },
            )
            .await
            {
                Ok(w) => w.id,
                Err(e) => return TurnOutcome::Error(format!("could not update workflow {id}: {e}")),
            }
        }
        None => {
            match workflows::insert(
                &state.db,
                &workflows::NewWorkflow {
                    name,
                    description: Some(format!("Created by the AI concierge — {goal}")),
                    workflow_type: Some("recorded".into()),
                    steps: Some(steps_s),
                    entry_url: Some(entry_url),
                    default_persona_id: persona_id,
                    auth_config: auth_config_s,
                    ..Default::default()
                },
            )
            .await
            {
                Ok(w) => w.id,
                Err(e) => return TurnOutcome::Error(format!("could not create workflow: {e}")),
            }
        }
    };

    let mut plan = plan;
    plan.insert("workflow_id".into(), json!(workflow_id));
    let plan_s = serde_json::to_string(&plan).unwrap_or_else(|_| "{}".into());
    let mut resources = parse_obj(sess.resources.as_deref());
    resources.insert("workflow_id".into(), json!(workflow_id));
    let resources_s = serde_json::to_string(&resources).unwrap_or_else(|_| "{}".into());

    let progress = if existing_id.is_some() { "Workflow updated." } else { "Workflow recorded." };
    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate {
            status: Some("building"),
            plan: Some(&plan_s),
            resources: Some(&resources_s),
            progress_message: Some(progress),
            ..Default::default()
        },
    )
    .await;
    TurnOutcome::Continue
}

// ── Tool: add_callable_function ──────────────────────────────────────────────

/// Append a named callable function to the workflow's `functions` JSON array (types: script /
/// extraction / steps). Validates the name (alnum + underscore) and dedupes by name (a repeat is
/// skipped, not duplicated). Requires `plan.workflow_id`.
async fn tool_add_callable_function(state: &AppState, sess: &ConciergeSession, args: &Value) -> TurnOutcome {
    let Some(workflow_id) = workflow_id_of(sess) else {
        return nudge(state, sess, "add_callable_function needs a workflow — call build_workflow first.").await;
    };
    // HONEST GATE: no callable function over a workflow whose auto-test says it extracts NOTHING —
    // an API surface over an empty workflow is a lie. Fix the workflow first (discover_workflow
    // updates it in place), or ask the user.
    if test_result_failed(sess) {
        return nudge(state, sess, "the workflow's auto-test FAILED (it extracted no data). Do NOT add functions yet — re-run discover_workflow to fix the workflow (it updates in place), or ask_user.").await;
    }
    let name = args.get("name").and_then(|n| n.as_str()).unwrap_or("").trim().to_string();
    if !valid_function_name(&name) {
        return nudge(state, sess, "add_callable_function name must be alphanumeric + underscore (e.g. get_price).").await;
    }
    // ALLOWLIST — not an `unwrap_or`. `args` is model-authored JSON; only these three function
    // types are handled downstream, so anything else must collapse to the safe default instead of
    // being persisted verbatim. `clippy::manual_unwrap_or` suggests `.unwrap_or("script")` here,
    // which silently DROPS the allowlist — do not apply it.
    #[allow(clippy::manual_unwrap_or)]
    let ftype = match args.get("type").and_then(|t| t.as_str()) {
        Some(t @ ("script" | "extraction" | "steps")) => t,
        _ => "script",
    };

    let workflow = match workflows::get_by_id(&state.db, workflow_id).await {
        Ok(Some(w)) => w,
        _ => return TurnOutcome::Error(format!("workflow {workflow_id} not found")),
    };
    let mut functions = workflow
        .functions
        .as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();

    // Dedupe by name — a repeat is a no-op (idempotent).
    if functions.iter().any(|f| f.get("name").and_then(|n| n.as_str()) == Some(name.as_str())) {
        return nudge(state, sess, &format!("callable function '{name}' already exists — pick another name or move on.")).await;
    }
    // Dedupe by SUBSTANCE: the same capability under a new name is still a duplicate (the live bug:
    // three near-identical extract functions per page because the planner couldn't see what existed).
    let same_substance = functions.iter().find(|f| {
        f.get("type").and_then(|t| t.as_str()) == Some(ftype)
            && match ftype {
                "extraction" => f.get("selector") == args.get("selector"),
                "steps" => f.get("step_range") == args.get("step_range"),
                _ => f.get("code").and_then(|c| c.as_str()).map(str::trim) == args.get("code").and_then(|c| c.as_str()).map(str::trim),
            }
    });
    if let Some(existing) = same_substance {
        let existing_name = existing.get("name").and_then(|n| n.as_str()).unwrap_or("?");
        return nudge(state, sess, &format!(
            "an equivalent function already exists ('{existing_name}') — do NOT create variants of the same capability. plan.functions lists what exists; move on."
        )).await;
    }
    // HONEST GATE: a callable must fetch LIVE data at call time. A script whose code embeds the data
    // the recording SAW would return stale constants forever — reject it and steer to type "steps"
    // (replays the workflow's navigate+extract live on every call).
    let code = args.get("code").and_then(|c| c.as_str()).unwrap_or("").trim().to_string();
    let selector = args.get("selector").and_then(|c| c.as_str()).unwrap_or("").trim().to_string();
    if ftype == "script" {
        if code.is_empty() {
            return nudge(state, sess, "a script function needs non-empty code.").await;
        }
        if let Some(hazard) = crate::local::ai::explorer::script_replay_hazard(&code) {
            return nudge(state, sess, hazard).await;
        }
        let sample = parse_obj(sess.plan.as_deref())
            .get("test_result")
            .and_then(|t| t.get("sample"))
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        if sample.len() >= 40 && code_bakes_sample(&code, &sample) {
            return nudge(state, sess, "that script EMBEDS data you saw during recording — it would return stale constants forever. A callable must extract LIVE data at call time: use type \"steps\" with the step_range covering the workflow's navigate+extract steps (they replay live on every call), or a \"script\" that reads the page, never one that returns literals.").await;
        }
    }
    if ftype == "extraction" && selector.is_empty() {
        return nudge(state, sess, "an extraction function needs a non-empty selector.").await;
    }
    // A steps-range function replays recorded (already live-verified) steps — validate the RANGE.
    if ftype == "steps" {
        let steps_len = serde_json::from_str::<Vec<Value>>(&workflow.steps).map(|v| v.len()).unwrap_or(0);
        let range = args.get("step_range").and_then(|r| r.as_array()).cloned().unwrap_or_default();
        let start = range.first().and_then(Value::as_u64).unwrap_or(0) as usize;
        let end = range.get(1).and_then(Value::as_u64).unwrap_or(0) as usize;
        if range.len() != 2 || start >= end || end > steps_len {
            return nudge(state, sess, &format!(
                "step_range [{start},{end}] is invalid — the workflow has {steps_len} steps (0-based, end exclusive). Pick the range covering the navigate+extract steps of this capability."
            )).await;
        }
    }

    // LIVE FUNCTION TEST: a script/extraction callable is PLANNER-authored — never persist it on
    // faith. Append it as a final deliverable step to a THROWAWAY copy of the workflow, run that for
    // real through the engine (login + navigation + the candidate, on the live site), judge the
    // ACTUAL returned data, and delete the copy. Only a function that returned real data is saved.
    let mut tested_sample: Option<String> = None;
    if matches!(ftype, "script" | "extraction") {
        let _ = concierge_sessions::update(
            &state.db,
            sess.id,
            &ConciergeUpdate {
                status: Some("building"),
                phase: Some("add_callable_function"),
                progress_message: Some("Testing the new function on the live site…"),
                ..Default::default()
            },
        )
        .await;

        let mut test_steps: Vec<Value> = serde_json::from_str(&workflow.steps).unwrap_or_default();
        let test_step = if ftype == "script" {
            json!({ "type": "evaluate", "enabled": true, "config": { "script": crate::local::ai::brain::sanitize_js_script(&code), "variable": "fn_test" } })
        } else {
            json!({ "type": "extract", "enabled": true, "config": { "selector": selector, "variable": "fn_test" } })
        };
        test_steps.push(test_step);
        let throwaway = workflows::insert(
            &state.db,
            &workflows::NewWorkflow {
                name: format!("__fn_test_{name}"),
                description: Some("Transient function-test copy created by the AI assistant (auto-deleted).".into()),
                workflow_type: Some("ai_generated".into()),
                steps: Some(serde_json::to_string(&test_steps).unwrap_or_else(|_| "[]".into())),
                entry_url: workflow.entry_url.clone(),
                ..Default::default()
            },
        )
        .await;
        let tw = match throwaway {
            Ok(tw) => tw,
            Err(e) => return TurnOutcome::Error(format!("could not set up the live function test: {e}")),
        };
        let persona_id = parse_obj(sess.plan.as_deref()).get("persona_id").and_then(Value::as_i64);
        let run = state
            .engine
            .run(crate::local::engine::RunRequest {
                workflow_id: tw.id,
                inputs: json!({}),
                source: crate::local::engine::RunSource::Api,
                lane: crate::local::engine::Lane::Interactive,
                dry_run: false,
                persona_id,
                allow_local_secret_refs: true,
            })
            .await;
        let _ = workflows::delete(&state.db, tw.id).await;

        let value_ok = |v: &Value| match v {
            Value::Null => false,
            Value::Array(a) => !a.is_empty(),
            Value::Object(o) => !o.is_empty(),
            Value::String(s) => !s.trim().is_empty(),
            Value::Bool(_) | Value::Number(_) => true,
        };
        match run {
            Ok(r) if r.success => {
                let out = r.extracted_data.get("fn_test").cloned().unwrap_or(Value::Null);
                if !value_ok(&out) {
                    return nudge(state, sess, &format!(
                        "function '{name}' FAILED its live test — the workflow ran, but the {ftype} returned NO data on the live page. Fix the selector/script (probe what the final page really contains) and add it again. It was NOT saved."
                    )).await;
                }
                // Returned data, but does the script HARDCODE the items instead of querying the DOM?
                // (Passes the run today, breaks when the data changes.) Reject it.
                if ftype == "script" && crate::local::ai::explorer::code_hardcodes_returned_data(&code, &out) {
                    return nudge(state, sess, &format!(
                        "function '{name}' HARDCODES the items it returns instead of discovering them from the page — it would break when the data changes. Rewrite it to query the repeating rows generically (Array.from(document.querySelectorAll('<row selector>')).map(el => ...)) with NO literal names/values baked in, then add it again."
                    )).await;
                }
                tested_sample = Some(cap(&out.to_string(), 300));
            }
            Ok(r) => {
                return nudge(state, sess, &format!(
                    "function '{name}' FAILED its live test — the run errored before the {ftype} could produce data: {}. Fix the workflow/function and add it again. It was NOT saved.",
                    r.error.unwrap_or_else(|| "unknown".into())
                )).await;
            }
            Err(e) => {
                return nudge(state, sess, &format!(
                    "function '{name}' could not be live-tested (run failed to start: {e}). Do not save untested functions — fix and retry."
                )).await;
            }
        }
    }

    let mut fn_obj = serde_json::Map::new();
    fn_obj.insert("name".into(), json!(name));
    fn_obj.insert("type".into(), json!(ftype));
    if let Some(desc) = args.get("description").and_then(|d| d.as_str()).filter(|s| !s.is_empty()) {
        fn_obj.insert("description".into(), json!(desc));
    }
    match ftype {
        "script" => {
            fn_obj.insert("code".into(), json!(crate::local::ai::brain::sanitize_js_script(&code)));
        }
        "extraction" => {
            fn_obj.insert("selector".into(), json!(selector));
        }
        "steps" => {
            if let Some(range) = args.get("step_range").filter(|r| r.is_array()) {
                fn_obj.insert("step_range".into(), range.clone());
            }
        }
        _ => {}
    }
    // Input→parameter / extract→output mapping (the API contract of the function). Kept as given so
    // the connect surfaces (REST/OpenAI/MCP) expose the right parameters + result shape.
    if let Some(inputs) = args.get("input_variables").filter(|v| v.is_object()) {
        fn_obj.insert("input_variables".into(), inputs.clone());
    }
    if let Some(outputs) = args.get("output_fields").filter(|v| v.is_array()) {
        fn_obj.insert("output_fields".into(), outputs.clone());
    }
    // Live-test proof (script/extraction only): recorded so the review/UI can show the function
    // demonstrably returned real data when added. Steps-type functions inherit the recording's
    // own live verification.
    if let Some(sample) = &tested_sample {
        fn_obj.insert("tested".into(), json!(true));
        fn_obj.insert("test_sample".into(), json!(sample));
    }
    functions.push(Value::Object(fn_obj));
    let functions_s = serde_json::to_string(&functions).unwrap_or_else(|_| "[]".into());

    if let Err(e) = workflows::update(
        &state.db,
        workflow_id,
        &workflows::WorkflowUpdate { functions: Some(functions_s), ..Default::default() },
    )
    .await
    {
        return TurnOutcome::Error(format!("could not add callable function: {e}"));
    }

    // Surface the workflow's function roster into the PLAN so every later planner turn SEES what
    // already exists (the state is the planner's only memory — without this it re-creates the same
    // capability under new names, turn after turn).
    let roster: Vec<Value> = functions
        .iter()
        .map(|f| {
            json!({
                "name": f.get("name").cloned().unwrap_or(Value::Null),
                "type": f.get("type").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();
    let mut plan = parse_obj(sess.plan.as_deref());
    plan.insert("functions".into(), json!(roster));
    let plan_s = serde_json::to_string(&plan).unwrap_or_else(|_| "{}".into());

    let progress = format!("Added callable function ({} total).", functions.len());
    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate {
            status: Some("building"),
            progress_message: Some(&progress),
            plan: Some(&plan_s),
            ..Default::default()
        },
    )
    .await;
    TurnOutcome::Continue
}

/// Does a script-function's `code` EMBED the recorded sample data (returning stale constants instead
/// of extracting live)? Heuristic: any 32-char window of the sample's content appearing verbatim in
/// the code. Windows are drawn from the sample's data characters, so JSON punctuation alone can't
/// false-positive.
fn code_bakes_sample(code: &str, sample: &str) -> bool {
    let chars: Vec<char> = sample.chars().collect();
    if chars.len() < 32 || code.len() < 32 {
        return false;
    }
    let mut i = 0;
    while i + 32 <= chars.len() {
        let window: String = chars[i..i + 32].iter().collect();
        // Skip windows that are mostly structure (quotes/braces/commas) — demand real content.
        let content = window.chars().filter(|c| c.is_alphanumeric() || c.is_whitespace()).count();
        if content >= 20 && code.contains(&window) {
            return true;
        }
        i += 16;
    }
    false
}

/// Loop-breaker terminal: too many sign-in-but-no-data discovery attempts. Finish the mission HONESTLY
/// — the login worked, the extraction didn't — instead of asking to refresh the credential forever.
/// Finalize the mission as `done` with a summary line (appended to the transcript so the user sees
/// it). Used by the already-built guard to converge instead of re-running discovery.
async fn finalize_concierge_done(state: &AppState, sess: &ConciergeSession, msg: String) -> TurnOutcome {
    let mut transcript = parse_arr(sess.transcript.as_deref());
    transcript.push(json!({ "role": "assistant", "content": &msg, "ts": now_ts() }));
    let transcript_s = serde_json::to_string(&transcript).unwrap_or_else(|_| "[]".into());
    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate { transcript: Some(&transcript_s), ..Default::default() },
    )
    .await;
    let _ = concierge_sessions::finalize(&state.db, sess.id, "done", Some(msg.as_str()), None).await;
    TurnOutcome::Done
}

async fn finish_extraction_exhausted(state: &AppState, sess: &ConciergeSession) -> TurnOutcome {
    let has_wf = parse_obj(sess.resources.as_deref())
        .get("workflow_id")
        .is_some_and(|v| !v.is_null());
    let msg = if has_wf {
        "I signed in to the site successfully, but after several attempts I couldn't extract the requested list(s) as live data — the page delivers them in a way I can't reliably capture for replay. The login works; the extraction is the blocker, so I've stopped rather than keep retrying (this is not a credential problem). The recorded sign-in workflow is saved. If you can tell me exactly where each list appears on the page, I can try a more targeted extraction."
    } else {
        "I could reach the site but couldn't extract the requested data after several attempts, so I've stopped rather than loop. This looks like an extraction limitation rather than a login problem."
    };
    let mut transcript = parse_arr(sess.transcript.as_deref());
    transcript.push(json!({ "role": "assistant", "content": msg, "ts": now_ts() }));
    let transcript_s = serde_json::to_string(&transcript).unwrap_or_else(|_| "[]".into());
    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate { transcript: Some(&transcript_s), ..Default::default() },
    )
    .await;
    let _ = concierge_sessions::finalize(&state.db, sess.id, "done", Some(msg), None).await;
    TurnOutcome::Done
}

// ── Tool: discover_workflow (unified: run the build AS an autonomous AI session) ──

/// UNIFIED build — run the site as an autonomous AI SESSION instead of a rigid selector script. The
/// agent observes the live page, signs in by filling whatever the login ACTUALLY needs (a single API
/// key, OR username + password — it adapts; no assumption), clicks/advances, extracts the data, and
/// RECORDS the steps as a reusable workflow. The credentials the user entered are handed to the agent
/// as `fill_data`: a `{{secret:KEY}}` answer is opened from the local vault into its real value (the
/// model references it by key and the value is injected only at fill time — never seen by the model
/// nor saved raw). Sets plan.workflow_id + resources.workflow_id + a live auto-test result. Prefer this
/// over propose_selectors + build_workflow-with-hand-written-login-steps for any login-gated /
/// API-builder / multi-step build.
async fn tool_discover_workflow(state: &AppState, sess: &ConciergeSession, args: &Value) -> TurnOutcome {
    use std::collections::HashMap;

    let plan = parse_obj(sess.plan.as_deref());
    // LOOP-BREAKER: if discovery has already signed in but extracted nothing this many times in a row,
    // stop re-running it and finish honestly. This streak lives in the PLAN so it survives the
    // ASK→/respond respawn that resets the per-spawn stall counter (the exact gap that let the planner
    // loop DISCOVER→"refresh login?"→DISCOVER forever).
    if plan.get("_no_data_streak").and_then(|v| v.as_u64()).unwrap_or(0) >= MAX_NO_DATA_DISCOVERS {
        return finish_extraction_exhausted(state, sess).await;
    }
    // ALREADY-BUILT guard: one discovery browse captures ALL the functions the goal needs, so once the
    // workflow exists (workflow_id) WITH functions AND a passing test, re-running discovery only repeats
    // work — the reported "restarted discovery after it was already done" loop. Do NOT re-browse:
    // converge to connect/finish. (A NOT-yet-built or failed-test workflow still re-discovers normally,
    // which is the legitimate retry path.)
    let funcs = plan.get("functions").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let test_ok = plan
        .get("test_result")
        .and_then(|t| t.get("ok"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let has_wf = plan.get("workflow_id").is_some_and(|v| !v.is_null())
        || parse_obj(sess.resources.as_deref()).get("workflow_id").is_some_and(|v| !v.is_null());
    // Don't fire on a user-driven REVISION: if the latest transcript entry is a fresh user message (a
    // correction), the planner SHOULD act on it. The autonomous re-discovery loop we guard against ends
    // in a tool/system result, not a user turn.
    let last_is_user = parse_arr(sess.transcript.as_deref())
        .last()
        .and_then(|e| e.get("role").and_then(|r| r.as_str())) == Some("user");
    if has_wf && !funcs.is_empty() && test_ok && !last_is_user {
        let names: Vec<String> = funcs
            .iter()
            .filter_map(|f| f.get("name").and_then(|n| n.as_str()).map(str::to_string))
            .collect();
        let names_s = if names.is_empty() { "the recorded functions".to_string() } else { names.join(", ") };
        let n_funcs = names.len().max(1);
        let connected = plan.get("connect").is_some_and(|v| !v.is_null());
        if connected {
            return finalize_concierge_done(state, sess, format!(
                "Done — the workflow is built, tested, and connected with {n_funcs} callable function(s): {names_s}."
            ))
            .await;
        }
        let n = plan.get("_postbuild_rediscover").and_then(|v| v.as_u64()).unwrap_or(0) + 1;
        if n >= 2 {
            // It ignored the first nudge and tried to re-discover again — stop the loop cleanly.
            return finalize_concierge_done(state, sess, format!(
                "Done — I built and tested the workflow with {n_funcs} callable function(s): {names_s}. \
                 Enable it on the REST/OpenAI/MCP surfaces from the workflow's Connect tab whenever you're ready."
            ))
            .await;
        }
        // First redundant attempt: persist the counter, block the re-browse, and steer to the finish chain.
        let mut plan2 = plan.clone();
        plan2.insert("_postbuild_rediscover".into(), json!(n));
        let plan_s = serde_json::to_string(&plan2).unwrap_or_else(|_| "{}".into());
        let _ = concierge_sessions::update(
            &state.db,
            sess.id,
            &ConciergeUpdate { plan: Some(&plan_s), ..Default::default() },
        )
        .await;
        return nudge(
            state,
            sess,
            "The workflow is ALREADY built and tested — its functions are in plan.functions and \
             plan.test_result.ok is true. Do NOT discover_workflow/build_workflow again (it just repeats \
             work). Call enable_connect then propose_connect_setup then finish now. Use \
             add_callable_function ONLY for a function the goal needs that is genuinely missing.",
        )
        .await;
    }
    let answers = parse_obj(sess.answers.as_deref());
    let base_goal = args
        .get("goal")
        .and_then(|g| g.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| sess.goal.clone());
    // Carry the user's answers to any earlier question the agent PAUSED to ask (see the block-pause
    // below): each answer accumulates in plan._clarifications and is fed back into the goal, so on
    // re-run the agent has the growing context and gets past the point it stopped.
    let mut clarifications: Vec<String> = plan
        .get("_clarifications")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    if let Some(latest) = answers.get("clarification").and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()) {
        if !clarifications.iter().any(|c| c == latest) {
            clarifications.push(latest.to_string());
        }
    }
    let goal = if clarifications.is_empty() {
        base_goal
    } else {
        format!("{base_goal}\n\nThe user has answered your earlier questions:\n- {}", clarifications.join("\n- "))
    };
    // UNIFIED build (one loop, both toolsets): tell the agent it is building the WHOLE automation, so if
    // the goal also asks to WATCH/notify or expose an API it should use its `setup` actions
    // (create_monitor / wire_automation / expose_api) on the right page — no separate step needed.
    let goal = format!(
        "{goal}\n\nYou are building the complete automation, not just the workflow. If this goal also \
asks to WATCH something and alert/notify on a change or price, add a create_monitor setup action (with \
the CSS selector of the element to watch) on the page where that element lives, then a wire_automation \
action. If it asks to make the result a callable API: DEFINE each callable function with define_function \
while you are ON the page whose data it returns (it is tested live the moment you emit it), then add an \
expose_api action. Only do what the goal actually asks."
    );
    let entry_url = args
        .get("url")
        .and_then(|u| u.as_str())
        .or_else(|| plan.get("resolved_url").and_then(|u| u.as_str()))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    // Provider (or the cloud AI gateway) + a real browser are required.
    let ai_cfg = match provider::resolve_config(&state.db, &state.vault).await {
        Ok(Some(c)) if !c.provider.trim().is_empty() => c,
        _ if provider::cloud_gateway_enabled(&state.db).await => provider::AiConfig {
            provider: String::new(),
            model: String::new(),
            base_url: None,
            api_key: None,
        },
        _ => return TurnOutcome::Error("No AI provider configured for the autonomous build.".into()),
    };
    let Some(browser) = state.engine.browser() else {
        return TurnOutcome::Error("this engine cannot browse (no browser)".into());
    };

    // Surface the live view for the discovery browse too: the FE's embedded
    // frame (and the old Watch button) gates on resources.browse_session_id —
    // the same truthy marker find_page sets (the mission's own id; the stream
    // rides `/ws/ai-preview/concierge-{id}`, mirrored onto the mission channel
    // by run_ai_session_and_record). Without it a mission that goes straight
    // to discovery never shows the browser at all.
    let mut resources = parse_obj(sess.resources.as_deref());
    resources
        .entry("browse_session_id".to_string())
        .or_insert_with(|| json!(sess.id));
    let resources_s = serde_json::to_string(&resources).unwrap_or_else(|_| "{}".into());
    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate {
            status: Some("building"),
            phase: Some("discover_workflow"),
            progress_message: Some("Signing in and recording the workflow autonomously…"),
            resources: Some(&resources_s),
            ..Default::default()
        },
    )
    .await;

    // fill_data = the login credentials the user entered. A `login_*` answer that is a {{secret:KEY}}
    // is opened from the vault into its real value (keyed so the agent maps the login input to it);
    // plaintext answers ride verbatim. available_data shows the model the KEYS (secrets masked) so it
    // knows what it has to fill without ever seeing the secret value. record_templates carries the
    // REPLAY spelling for each key: the {{secret:VAULT_KEY}} ref for a vault credential (the engine
    // re-opens the vault at run time), the literal for a plaintext answer — so a recorded fill step
    // resolves at replay instead of shipping a dead {{login_*}} placeholder.
    let mut fill_data: HashMap<String, String> = HashMap::new();
    let mut available_data: HashMap<String, String> = HashMap::new();
    let mut record_templates: HashMap<String, String> = HashMap::new();
    for (k, v) in &answers {
        if !k.starts_with("login_") {
            continue;
        }
        let Some(s) = v.as_str() else { continue };
        if let Some(key) = s.strip_prefix("{{secret:").and_then(|x| x.strip_suffix("}}")) {
            if let Ok(Some(row)) = crate::local::store::vault_secrets::get_by_key(&state.db, key).await {
                if let Ok(bytes) = state
                    .vault
                    .open_field(&row.value_encrypted, &crate::local::api::v1::secrets::value_aad(&row.key))
                {
                    if let Ok(plaintext) = String::from_utf8(bytes) {
                        fill_data.insert(k.clone(), plaintext);
                        available_data.insert(k.clone(), "[a secret credential you hold]".into());
                        record_templates.insert(k.clone(), s.to_string());
                    }
                }
            }
        } else if !s.is_empty() {
            fill_data.insert(k.clone(), s.to_string());
            available_data.insert(k.clone(), s.to_string());
            record_templates.insert(k.clone(), s.to_string());
        }
    }

    // Optional persona: restore its saved session + merge its credentials into fill_data (caller wins).
    let resolved_persona = match plan.get("persona_id").and_then(Value::as_i64) {
        Some(pid) => crate::local::engine::persona::resolve_persona(&state.db, &state.vault, pid)
            .await
            .ok()
            .flatten(),
        None => None,
    };
    if let Some(p) = resolved_persona.as_ref() {
        let mut creds: HashMap<String, String> = HashMap::new();
        p.merge_into_credentials(&mut creds);
        for (k, v) in creds {
            if fill_data.contains_key(&k) {
                continue; // caller-entered answers win
            }
            fill_data.insert(k.clone(), v);
            // The agent can only USE a {{key}} it can SEE: list persona keys in available_data with a
            // masked value (the [SECURE] display derives from fill≠shown). No record template — replay
            // logs in via the persona (default_persona_id + session restore), never a baked credential.
            available_data
                .entry(k)
                .or_insert_with(|| "[a secret credential you hold]".into());
        }
    }

    // A workflow already recorded for this mission ⇒ update it in place (revision), never a duplicate.
    let existing_wf = plan.get("workflow_id").and_then(Value::as_i64);
    // REVISION CONTEXT: the re-run's recording REPLACES the workflow's steps wholesale — a partial
    // run ("just fix the monitors extraction") would silently DELETE the pages that already worked.
    // Show the agent the current steps and demand the FULL flow.
    let goal = match existing_wf {
        Some(wf_id) => {
            let mut g = goal;
            if let Ok(Some(wf)) = workflows::get_by_id(&state.db, wf_id).await {
                let steps: Vec<Value> = serde_json::from_str(&wf.steps).unwrap_or_default();
                if !steps.is_empty() {
                    let mut listing = steps
                        .iter()
                        .take(30)
                        .enumerate()
                        .map(|(i, st)| {
                            let ty = st.get("type").and_then(|v| v.as_str()).unwrap_or("step");
                            let hint: String = st
                                .pointer("/config/url")
                                .and_then(|v| v.as_str())
                                .or_else(|| st.pointer("/config/selector").and_then(|v| v.as_str()))
                                .or_else(|| st.pointer("/config/variable").and_then(|v| v.as_str()))
                                .unwrap_or("")
                                .chars()
                                .take(100)
                                .collect();
                            format!("{}. {ty} {hint}", i + 1)
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    if steps.len() > 30 {
                        listing.push_str(&format!("\n… and {} more steps", steps.len() - 30));
                    }
                    g = format!(
                        "{g}\n\nREVISION: your recording REPLACES the existing workflow's steps ENTIRELY. Its current steps:\n{listing}\nRe-perform the FULL flow — every page and extraction that already works, PLUS the fix. A partial run deletes the working parts."
                    );
                }
            }
            g
        }
        None => goal,
    };
    let name = args
        .get("name")
        .and_then(|n| n.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        // Fallback: a clean, human name from the site host — never the goal sentence (which makes
        // truncated monstrosities like "AI: Sign in to … using the provided API key, naviga…").
        .or_else(|| {
            entry_url.as_deref().and_then(|u| {
                let host = u.split("://").nth(1)?.split('/').next()?.trim_start_matches("www.");
                if host.is_empty() { None } else { Some(format!("Workflow: {host}")) }
            })
        });

    // Bridge the DB `cancel_requested` flag into an in-memory cooperative-cancel flag the discovery
    // loop polls each step. Without this the discovery ran with `cancel: None`, so clicking Stop during
    // a (possibly minutes-long) discovery could not reach the AI loop or close the browser — it blocked
    // the whole mission until the discovery finished on its own. A tiny poller watches the row and flips
    // the flag; the explorer returns Cancelled and `run_ai_session_and_record` closes the browser.
    let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let canceller = {
        let cancel_poll = cancel.clone();
        let poll_db = state.db.clone();
        let poll_sid = sess.id;
        tokio::spawn(async move {
            use std::sync::atomic::Ordering;
            loop {
                tokio::time::sleep(Duration::from_millis(750)).await;
                if cancel_poll.load(Ordering::Relaxed) {
                    break;
                }
                match concierge_sessions::get_by_id(&poll_db, poll_sid).await {
                    Ok(Some(s)) if s.cancel_requested != 0 => {
                        cancel_poll.store(true, Ordering::Relaxed);
                        break;
                    }
                    Ok(Some(_)) => {}
                    // Row gone or DB error — nothing left to cancel; stop polling.
                    _ => break,
                }
            }
        })
    };

    let outcome = crate::local::ai::run::run_ai_session_and_record(
        &state.db,
        &state.engine,
        &browser,
        &ai_cfg,
        crate::local::ai::run::AiSessionParams {
            name,
            goal,
            entry_url,
            available_data,
            fill_data,
            // Room for the probe-heavy flow: sign-in + several pages, each needing a few
            // inspect/list_candidates turns before a deliverable. The explorer's own per-page stall
            // guards stop a dead loop well before this ceiling.
            max_steps: 40,
            workflow_id: existing_wf,
            resolved_persona,
            generate_workflow: existing_wf.is_none(),
            // The concierge build IS a general navigate+extract agent (parity with cloud): it logs in,
            // navigates the pages the goal needs, and extracts the data — it does NOT stop at login.
            explore: true,
            record_templates,
            // Ask-pauses PARK the live session (browser open) until the user answers via /respond.
            ask_concierge_session_id: Some(sess.id),
            cancel: Some(cancel),
        },
    )
    .await;
    canceller.abort();
    let outcome = match outcome {
        Ok(o) => o,
        Err(e) => return TurnOutcome::Error(format!("autonomous build failed: {e}")),
    };
    let workflow_id = outcome.workflow_id.or(existing_wf);

    // A cancelled run (the user hit Stop mid-discovery, or a parked ask was cancelled). Do NOT persist
    // anything here — that would resurrect a terminal mission. Return Continue so the mission loop's own
    // top-of-turn cancel check (`cancel_requested != 0`) FINALIZES the row as 'cancelled'. Returning
    // Pause instead would exit the loop WITHOUT finalizing, leaving the session stuck non-terminal
    // (cancel_requested=1, status active) forever — the "assistant gets stuck after Stop" bug.
    if outcome.status == "cancelled" {
        return TurnOutcome::Continue;
    }

    // A HARD technical error (bad AI model/provider, provider down, page crash) — NOT a login or
    // extraction problem, so re-running or a "clearer goal" won't help. Finalize the mission as 'error'
    // with the exact cause so the user actually SEES what broke (the FE shows error_message as a red
    // banner) instead of a silent "didn't produce a workflow" that the planner then loops on.
    if outcome.status == "error" {
        let reason = outcome
            .error
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or_else(|| {
                let m = outcome.message.trim();
                (!m.is_empty()).then_some(m)
            })
            .unwrap_or("The autonomous session hit a technical error.")
            .to_string();
        return TurnOutcome::Error(reason);
    }

    // Persona-authenticated build: stamp the login identity on the recorded workflow so replays
    // restore the persona session (+ mint TOTP) instead of relying on unresolvable placeholders.
    if let (Some(wf_id), Some(pid)) = (workflow_id, plan.get("persona_id").and_then(Value::as_i64)) {
        let _ = workflows::update(
            &state.db,
            wf_id,
            &workflows::WorkflowUpdate { default_persona_id: Some(pid), ..Default::default() },
        )
        .await;
    }

    // The agent STOPPED needing the user's help — a decision it can't make, data it doesn't have, or a
    // block it can't clear on its own (an unexpected login field, "which account?", a CAPTCHA). Surface
    // its message as a QUESTION and PAUSE the mission; the user's answer accumulates in
    // plan._clarifications and the planner re-runs discover_workflow (workflow_id set → updates in
    // place) so the agent resumes with the new context instead of dead-ending.
    if outcome.status == "blocked" {
        // OWNERSHIP CHECK (the park-timeout race): if the user's answer landed during the unwind,
        // /respond already consumed the pause, bumped turn_seq, and spawned a fresh mission loop —
        // this stale loop must NOT rewrite awaiting_input over it (that would re-ask an answered
        // question and invite a THIRD loop). turn_seq unchanged ⇔ the pause is still ours.
        match concierge_sessions::get_by_id(&state.db, sess.id).await {
            Ok(Some(row)) if row.turn_seq != sess.turn_seq => {
                tracing::info!(concierge_id = sess.id, "pause consumed by /respond during unwind — stale loop exiting");
                return TurnOutcome::Pause; // exit quietly; the new loop owns the mission
            }
            _ => {}
        }
        let question = {
            // The clean, question-phrased reason is in `error` (the agent's "reason"); `message` carries
            // a "Blocked: …" prefix, so prefer `error` and only fall back to a trimmed message.
            let raw = outcome
                .error
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| outcome.message.trim().trim_start_matches("Blocked:").trim().to_string());
            if raw.is_empty() {
                "I need a decision or some information from you to continue — what should I do?".to_string()
            } else {
                raw
            }
        };
        let mut plan2 = parse_obj(sess.plan.as_deref());
        plan2.insert("_clarifications".into(), json!(clarifications));
        if let Some(id) = workflow_id {
            plan2.insert("workflow_id".into(), json!(id));
        }
        let plan2_s = serde_json::to_string(&plan2).unwrap_or_else(|_| "{}".into());
        let mut resources = parse_obj(sess.resources.as_deref());
        if let Some(id) = workflow_id {
            resources.insert("workflow_id".into(), json!(id));
        }
        let resources_s = serde_json::to_string(&resources).unwrap_or_else(|_| "{}".into());
        // Did the agent block because it needs a LOGIN CREDENTIAL it saw on the page but wasn't given?
        // The blocked run stamps the field(s) it saw into result_data.credential_fields. If so, ask for
        // exactly those inputs (secret → sealed to the vault), named login_* so the value flows back into
        // fill_data on the re-run — instead of a plain text clarification. This is the adaptive login: the
        // agent reads the real form (a single API key, or user+pass) and the concierge asks for THAT.
        let cred_fields: Vec<Value> = match crate::local::store::ai_sessions::get_by_id(&state.db, outcome.session_id).await {
            Ok(Some(row)) => row
                .result_data
                .as_deref()
                .and_then(|s| serde_json::from_str::<Value>(s).ok())
                .and_then(|rd| rd.get("credential_fields").and_then(|v| v.as_array()).cloned())
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        let pending = if !cred_fields.is_empty() {
            // One request per credential field the agent named. A field flagged secret renders a password
            // input and is sealed to the vault on submit; the daemon /respond seals kind:"secret" answers
            // into {{secret:concierge_ID_field}} and the discover re-run opens it into fill_data.
            let requests: Vec<Value> = cred_fields
                .iter()
                .filter_map(|f| {
                    let field = f.get("field").and_then(|v| v.as_str())?;
                    // Force a login_* name so tool_discover_workflow's fill_data picks it up next run.
                    let field = if field.starts_with("login_") { field.to_string() } else { format!("login_{field}") };
                    let secret = f.get("secret").and_then(|v| v.as_bool()).unwrap_or(true);
                    let label = f.get("label").and_then(|v| v.as_str()).unwrap_or(&question);
                    Some(json!({
                        "field": field,
                        "kind": if secret { "secret" } else { "text" },
                        "question": label,
                    }))
                })
                .collect();
            json!({ "requests": requests, "resume_status": "planning", "phase": "discover_workflow" }).to_string()
        } else {
            json!({
                "requests": [{ "field": "clarification", "kind": "text", "question": question }],
                "resume_status": "planning",
            })
            .to_string()
        };
        let _ = concierge_sessions::update(
            &state.db,
            sess.id,
            &ConciergeUpdate {
                status: Some("awaiting_input"),
                phase: Some("discover_workflow"),
                progress_message: Some(&question),
                pending_request: Some(&pending),
                plan: Some(&plan2_s),
                resources: Some(&resources_s),
                ..Default::default()
            },
        )
        .await;
        crate::local::flow::push_pending_toast("Assistant needs your input", &question);
        return TurnOutcome::Pause;
    }

    // Auto-test signal: the LIVE-VERIFIED extracted data specifically (result_data.extracted — the
    // explorer only records a deliverable that returned real data on the live page). Reading the whole
    // result_data blob here would ALWAYS look non-empty (it carries current_url/filled_fields) and
    // fake a PASS for a login-only run — the exact dishonest signal that let the planner narrate
    // "tested ✓" over nothing. Only .extracted counts.
    let extracted = match crate::local::store::ai_sessions::get_by_id(&state.db, outcome.session_id).await {
        Ok(Some(row)) => row
            .result_data
            .as_deref()
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
            .and_then(|rd| rd.get("extracted").cloned())
            .unwrap_or(Value::Null),
        _ => Value::Null,
    };
    // PASS requires BOTH real extracted data AND a `complete` finish: a stuck/max_steps run may have
    // extracted values mid-run whose recording never settled — narrating that as a passed test is
    // exactly the dishonesty the gates exist to stop.
    let got_data = outcome.status == "complete"
        && outcome.error.is_none()
        && !extracted.is_null()
        && extracted != json!({})
        && extracted != json!([]);
    // A bounded sample of the real data — shown in the finish review + grounds the planner.
    let sample = if got_data {
        let s = extracted.to_string();
        Some(s.chars().take(400).collect::<String>())
    } else {
        None
    };

    // Consecutive no-data streak (persisted in the plan so it survives an ASK/respond respawn). Real
    // data resets it; a completed-but-empty run grows it toward the loop-breaker cap.
    let prior_streak = plan.get("_no_data_streak").and_then(|v| v.as_u64()).unwrap_or(0);
    let no_data_streak = if got_data { 0 } else { prior_streak + 1 };
    // A run that COMPLETED (signed in fine) but extracted nothing is an EXTRACTION problem, not a
    // credential one — never suggest re-entering the login in that case.
    let signed_in_ok = outcome.status == "complete";

    let mut plan = plan;
    if let Some(id) = workflow_id {
        plan.insert("workflow_id".into(), json!(id));
    }
    plan.insert("_no_data_streak".into(), json!(no_data_streak));
    plan.insert(
        "test_result".into(),
        json!({
            "ok": got_data,
            "detail": if got_data { "the autonomous session extracted real data live".to_string() }
                      else { format!("session ended '{}' with NO data extracted", outcome.status) },
            "sample": sample,
        }),
    );
    plan.insert(
        "_last_result".into(),
        json!({ "discover_workflow": { "workflow_id": workflow_id, "status": outcome.status } }),
    );
    let plan_s = serde_json::to_string(&plan).unwrap_or_else(|_| "{}".into());

    let mut resources = parse_obj(sess.resources.as_deref());
    if let Some(id) = workflow_id {
        resources.insert("workflow_id".into(), json!(id));
    }
    let resources_s = serde_json::to_string(&resources).unwrap_or_else(|_| "{}".into());

    // The REAL failure cause the explorer recorded (e.g. "AI provider error: HTTP 404 — No endpoints
    // found that support image input", a network error, a page crash). Without this the user only saw
    // "didn't produce a workflow ('error')" and had no idea what actually went wrong.
    let failure_reason: Option<String> = outcome
        .error
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            let m = outcome.message.trim();
            (!m.is_empty() && m != "Marked complete").then_some(m)
        })
        .map(str::to_string);

    let mut transcript = parse_arr(sess.transcript.as_deref());
    transcript.push(json!({
        "role": "assistant",
        "content": if workflow_id.is_some() {
            "Signed in and recorded the workflow autonomously.".to_string()
        } else {
            match &failure_reason {
                Some(r) => format!("The autonomous session couldn't finish: {r}"),
                None => format!("The autonomous session didn't produce a workflow ('{}').", outcome.status),
            }
        },
        "ts": now_ts(),
    }));
    if !got_data {
        // Steer the planner HONESTLY and break the loop. Distinguish the failure modes and escalate as
        // the no-data streak grows — never keep suggesting a login refresh after a successful sign-in.
        let guidance = if no_data_streak >= MAX_NO_DATA_DISCOVERS {
            "STOP re-running discover_workflow — it has signed in successfully but extracted NO data several times. This is an EXTRACTION problem, NOT a login problem: do NOT ask the user to refresh the credential. Call finish and honestly report that the sign-in works but the list(s) couldn't be extracted."
                .to_string()
        } else if signed_in_ok {
            "discover_workflow SIGNED IN but extracted NO data — an extraction problem, not a login one. Re-run discover_workflow ONCE with a MORE SPECIFIC extraction goal (name the exact page and what the list looks like). Do NOT ask the user to re-enter the login — the sign-in succeeded.".to_string()
        } else {
            format!("discover_workflow ended '{}' with no data. If it was blocked on the login, the user may need to re-enter the credential; otherwise re-run once with a clearer goal.", outcome.status)
        };
        transcript.push(json!({ "role": "system", "content": guidance, "ts": now_ts() }));
    }
    // A revision REPLACED the steps — functions pinned to step positions can now dangle. Surface it
    // honestly so the planner re-adds them instead of exposing an API over broken ranges.
    if existing_wf.is_some() {
        if let Some(wf_id) = workflow_id {
            if let Ok(Some(wf)) = workflows::get_by_id(&state.db, wf_id).await {
                let steps_len = serde_json::from_str::<Vec<Value>>(&wf.steps).map(|v| v.len()).unwrap_or(0);
                let dangling: Vec<String> = wf
                    .functions
                    .as_deref()
                    .and_then(|f| serde_json::from_str::<Value>(f).ok())
                    .and_then(|v| v.as_array().cloned())
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|f| {
                        // A revision replaces steps WHOLESALE — every range-pinned function is
                        // suspect (same length ≠ same steps), not just ones past the new end.
                        let name = f.get("name").and_then(|n| n.as_str())?;
                        f.get("step_range").and_then(|r| r.as_array())?;
                        Some(name.to_string())
                    })
                    .collect();
                if !dangling.is_empty() {
                    transcript.push(json!({
                        "role": "system",
                        "content": format!(
                            "the revision REPLACED the workflow's steps wholesale — every step_range function ({}) may now point at DIFFERENT steps ({} steps total). Re-verify each against the new step listing and re-add any that moved, BEFORE connecting.",
                            dangling.join(", "), steps_len
                        ),
                        "ts": now_ts(),
                    }));
                }
            }
        }
    }
    let transcript_s = serde_json::to_string(&transcript).unwrap_or_else(|_| "[]".into());

    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate {
            status: Some("planning"),
            plan: Some(&plan_s),
            resources: Some(&resources_s),
            transcript: Some(&transcript_s),
            progress_message: Some(if workflow_id.is_some() { "Workflow recorded." } else { "Autonomous build finished." }),
            ..Default::default()
        },
    )
    .await;

    // UNIFIED loop: the browse ran as a concierge session, so the agent may have emitted orchestration
    // setup actions (create_monitor / wire_automation / expose_api) IN-LOOP, grounded on the live pages
    // it saw. Materialize them now into the real monitor/automation/connect rows via the SAME tool
    // bodies the planner uses — so "make an API for X and alert me when it changes" is one warm session.
    if !outcome.orchestration_intents.is_empty() {
        materialize_orchestration_intents(state, sess.id, &outcome.orchestration_intents).await;
    }
    TurnOutcome::Continue
}

/// Turn the in-loop orchestration intents the concierge agent emitted during the build browse into real
/// rows, in dependency order (monitors → notify → expose-API), by driving the SAME tool bodies the
/// planner uses. Each intent is grounded (the selector/url is the live element the agent was looking at
/// when it emitted it), so no re-derivation / re-browse is needed. Best-effort per intent — a failure on
/// one does not abort the rest, and the planner can still finish the setup afterward.
async fn materialize_orchestration_intents(state: &AppState, session_id: i64, intents: &[Value]) {
    let mut made_monitor = false;
    let mut want_notify = false;
    let mut connect_surfaces: Option<Value> = None;
    for intent in intents {
        match intent.get("kind").and_then(|v| v.as_str()) {
            Some("monitor") => {
                let selector = intent.get("selector").and_then(|v| v.as_str()).unwrap_or("").trim();
                if selector.is_empty() {
                    continue;
                }
                // Stash the grounded selector/url/threshold where tool_create_monitor reads them.
                let Ok(Some(sess)) = concierge_sessions::get_by_id(&state.db, session_id).await else { return };
                let mut plan = parse_obj(sess.plan.as_deref());
                if let Some(url) = intent.get("url").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
                    plan.insert("resolved_url".into(), json!(url));
                }
                plan.insert("price_selector".into(), json!(selector));
                if let Some(name) = intent.get("name").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
                    plan.insert("price_selector_name".into(), json!(name));
                }
                if let Some(thr) = intent.get("threshold") {
                    plan.insert("threshold".into(), thr.clone());
                }
                let plan_s = serde_json::to_string(&plan).unwrap_or_else(|_| "{}".into());
                let _ = concierge_sessions::update(
                    &state.db,
                    session_id,
                    &ConciergeUpdate { plan: Some(&plan_s), ..Default::default() },
                )
                .await;
                // Reload so the tool body sees the freshly-stashed plan, then create the monitor. No
                // warm page in this post-browse intent path — the HTTP-viability probe still runs (a
                // fresh fetch), and a "visual" intent degrades to a text selector (no live box to clip).
                if let Ok(Some(fresh)) = concierge_sessions::get_by_id(&state.db, session_id).await {
                    let watch = intent.get("watch").and_then(|v| v.as_str()).unwrap_or("price");
                    let mut mon_args = serde_json::Map::new();
                    mon_args.insert("watch".into(), json!(watch));
                    if let Some(m) = intent.get("mode").or_else(|| intent.get("watch_via")) {
                        mon_args.insert("mode".into(), m.clone());
                    }
                    if let Some(r) = intent.get("render").or_else(|| intent.get("render_mode")) {
                        mon_args.insert("render".into(), r.clone());
                    }
                    let mut no_warm: Option<WarmBrowse> = None;
                    let _ = tool_create_monitor(state, &fresh, &Value::Object(mon_args), &mut no_warm).await;
                    made_monitor = true;
                }
            }
            Some("function") => {
                // LIVE-TESTED in the session (define_function verified the script/selector on the
                // real page the moment it was emitted) — persist directly, NO re-run needed.
                let Some(name) = intent.get("name").and_then(|v| v.as_str()).filter(|n| !n.is_empty()) else { continue };
                let Ok(Some(sess_row)) = concierge_sessions::get_by_id(&state.db, session_id).await else { return };
                let Some(wf_id) = workflow_id_of(&sess_row) else { continue };
                let Ok(Some(wf)) = workflows::get_by_id(&state.db, wf_id).await else { continue };
                let mut functions = wf
                    .functions
                    .as_deref()
                    .and_then(|f| serde_json::from_str::<Value>(f).ok())
                    .and_then(|v| v.as_array().cloned())
                    .unwrap_or_default();
                if functions.iter().any(|f| f.get("name").and_then(|n| n.as_str()) == Some(name)) {
                    continue; // already persisted (idempotent)
                }
                let mut fn_obj = serde_json::Map::new();
                fn_obj.insert("name".into(), json!(name));
                fn_obj.insert(
                    "type".into(),
                    intent.get("fn_type").cloned().unwrap_or_else(|| json!("script")),
                );
                for k in ["code", "selector", "url", "method", "headers", "body", "description", "input_variables", "output_fields", "test_sample"] {
                    if let Some(v) = intent.get(k) {
                        fn_obj.insert(k.to_string(), v.clone());
                    }
                }
                fn_obj.insert("tested".into(), json!(true));
                functions.push(Value::Object(fn_obj));
                let functions_s = serde_json::to_string(&functions).unwrap_or_else(|_| "[]".into());
                if workflows::update(
                    &state.db,
                    wf_id,
                    &workflows::WorkflowUpdate { functions: Some(functions_s), ..Default::default() },
                )
                .await
                .is_ok()
                {
                    // Keep the planner's roster (its only memory of what exists) in sync.
                    let roster: Vec<Value> = functions
                        .iter()
                        .map(|f| json!({ "name": f.get("name").cloned().unwrap_or(Value::Null), "type": f.get("type").cloned().unwrap_or(Value::Null) }))
                        .collect();
                    let mut plan = parse_obj(sess_row.plan.as_deref());
                    plan.insert("functions".into(), json!(roster));
                    let plan_s = serde_json::to_string(&plan).unwrap_or_else(|_| "{}".into());
                    let _ = concierge_sessions::update(
                        &state.db,
                        session_id,
                        &ConciergeUpdate { plan: Some(&plan_s), ..Default::default() },
                    )
                    .await;
                }
            }
            Some("notify") => want_notify = true,
            Some("connect") => {
                connect_surfaces = Some(
                    intent
                        .get("surfaces")
                        .filter(|s| s.is_object())
                        .cloned()
                        .unwrap_or_else(|| json!({ "rest": true })),
                );
            }
            _ => {}
        }
    }
    // Wire the notification once the monitor exists (wire_automation reads resources.target_id).
    if want_notify && made_monitor {
        if let Ok(Some(fresh)) = concierge_sessions::get_by_id(&state.db, session_id).await {
            let _ = tool_wire_automation(state, &fresh).await;
        }
    }
    // Expose the recorded workflow as an API last (enable_connect needs resources.workflow_id).
    if let Some(surfaces) = connect_surfaces {
        if let Ok(Some(fresh)) = concierge_sessions::get_by_id(&state.db, session_id).await {
            let _ = tool_enable_connect(state, &fresh, &surfaces).await;
        }
    }
}

// ── Tool: test_workflow (auto-test + feed errors back for self-repair) ────────

/// Actually RUN the workflow the concierge built and feed the outcome back into the mission so the
/// planner can self-repair. Uses the in-process engine (a real run, awaited to completion), records
/// PASS/FAIL + the error (or a sample of the extracted data) into `plan.test_result`, and writes a
/// `system` transcript line the next planner turn reads. On FAIL the planner is told to fix the
/// offending step/selector via build_workflow (which updates the workflow in place) and test again.
/// Requires a built workflow. `args.sample_inputs` supplies values for the workflow's input variables.
/// Whether a JSON value carries real content (a non-empty list/object/string, or a number/bool).
fn value_is_nonempty(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Array(a) => !a.is_empty(),
        Value::Object(m) => !m.is_empty(),
        Value::String(s) => !s.trim().is_empty(),
        _ => true,
    }
}

/// Whether a run's `extracted_data` actually returned data — at least one keyed value with content.
/// Tolerates both the raw extracted map and a `{ extracted_data: {...} }` envelope; ignores the
/// `success` bookkeeping key so it can't fake a data-bearing result.
fn extracted_has_data(v: &Value) -> bool {
    let obj = v.get("extracted_data").filter(|x| x.is_object()).unwrap_or(v);
    match obj {
        Value::Object(m) => m.iter().any(|(k, val)| k != "success" && value_is_nonempty(val)),
        other => value_is_nonempty(other),
    }
}

/// Compact list of the data keys returned (for the PASS message), e.g. "workflows (3), targets (5)".
fn extracted_keys(v: &Value) -> String {
    let obj = v.get("extracted_data").filter(|x| x.is_object()).unwrap_or(v);
    let Value::Object(m) = obj else { return "—".into() };
    let mut parts: Vec<String> = m
        .iter()
        .filter(|(k, val)| *k != "success" && value_is_nonempty(val))
        .map(|(k, val)| match val {
            Value::Array(a) => format!("{k} ({})", a.len()),
            _ => k.clone(),
        })
        .collect();
    parts.sort();
    if parts.is_empty() { "—".into() } else { parts.join(", ") }
}

async fn tool_test_workflow(state: &AppState, sess: &ConciergeSession, args: &Value) -> TurnOutcome {
    let Some(workflow_id) = workflow_id_of(sess) else {
        return nudge(state, sess, "test_workflow needs a workflow — call build_workflow first.").await;
    };
    let plan = parse_obj(sess.plan.as_deref());
    let persona_id = plan.get("persona_id").and_then(Value::as_i64);
    let mut inputs = args.get("sample_inputs").cloned().filter(Value::is_object).unwrap_or_else(|| json!({}));

    // FILE UPLOAD SLOTS: a workflow with `upload` steps needs a vault file bound to each `file_slot`
    // before it can run. Bindings come from earlier answers (`file_<slot>` → file_id). Any UNBOUND slot
    // pauses the mission with a real file picker (the vault list); once every slot is bound we build
    // `inputs.files` (which the engine materializes from the vault) and run.
    if let Ok(Some(wf)) = workflows::get_by_id(&state.db, workflow_id).await {
        let slots = crate::local::mcp::tools::scan_file_slots(&wf.steps);
        if !slots.is_empty() {
            let answers = parse_obj(sess.answers.as_deref());
            let mut bindings: Vec<(String, String)> = Vec::new();
            let mut unbound: Vec<String> = Vec::new();
            for slot in &slots {
                match answers.get(&format!("file_{slot}")).and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
                    Some(fid) => bindings.push((slot.clone(), fid.to_string())),
                    None => unbound.push(slot.clone()),
                }
            }
            if !unbound.is_empty() {
                let file_opts: Vec<Value> = crate::local::store::stored_files::list(&state.db, Some(50))
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .map(|f| json!({ "id": f.id, "label": format!("{} ({} bytes)", f.filename, f.size_bytes) }))
                    .collect();
                let requests: Vec<Value> = unbound
                    .iter()
                    .map(|slot| json!({
                        "field": format!("file_{slot}"),
                        "kind": "file",
                        "question": format!("Which file should the workflow upload for \u{201c}{slot}\u{201d}?"),
                        "options": file_opts,
                    }))
                    .collect();
                let pending = json!({ "requests": requests, "resume_status": "building", "phase": "test_workflow" }).to_string();
                let first_q = requests.first().and_then(|r| r.get("question")).and_then(|q| q.as_str()).unwrap_or("Pick a file").to_string();
                let _ = concierge_sessions::update(
                    &state.db,
                    sess.id,
                    &ConciergeUpdate {
                        status: Some("awaiting_input"),
                        phase: Some("test_workflow"),
                        progress_message: Some(&first_q),
                        pending_request: Some(&pending),
                        ..Default::default()
                    },
                )
                .await;
                crate::local::flow::push_pending_toast("Assistant needs a file", &first_q);
                return TurnOutcome::Pause;
            }
            // Every slot is bound → assemble inputs.files = { file_id: { file_id, slots:[…] } }.
            if !bindings.is_empty() {
                let mut by_file: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
                for (slot, fid) in bindings {
                    by_file.entry(fid).or_default().push(slot);
                }
                let mut files_map = serde_json::Map::new();
                for (fid, fslots) in by_file {
                    files_map.insert(fid.clone(), json!({ "file_id": fid, "slots": fslots }));
                }
                match inputs.as_object_mut() {
                    Some(obj) => { obj.insert("files".into(), Value::Object(files_map)); }
                    None => inputs = json!({ "files": Value::Object(files_map) }),
                }
            }
        }
    }

    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate {
            status: Some("building"),
            phase: Some("test_workflow"),
            progress_message: Some("Testing the workflow…"),
            ..Default::default()
        },
    )
    .await;

    let req = crate::local::engine::RunRequest {
        workflow_id,
        inputs,
        source: crate::local::engine::RunSource::Api,
        lane: crate::local::engine::Lane::Interactive,
        dry_run: false,
        persona_id,
        allow_local_secret_refs: true,
    };
    let (ok, detail, extracted) = match state.engine.run(req).await {
        // PASS requires BOTH a clean run AND real data back from the (api_call / evaluate) steps — a run
        // that completes but extracts nothing is NOT a working data workflow. Checking data (not just
        // `success`) is what makes "it works" truthful: it confirms the api_call steps actually returned
        // rows on this replay, exactly what the mission needs to know before exposing the API.
        Ok(r) if r.success && extracted_has_data(&r.extracted_data) => (
            true,
            format!("PASS ({:?}) in {}ms — data returned: {}", r.status, r.duration_ms, extracted_keys(&r.extracted_data)),
            r.extracted_data,
        ),
        Ok(r) if r.success => (
            false,
            format!("FAIL ({:?}): the workflow ran but extracted NO data — the steps completed yet returned empty. Check the extract/api_call steps.", r.status),
            r.extracted_data,
        ),
        Ok(r) => (
            false,
            format!("FAIL ({:?}): {}", r.status, r.error.unwrap_or_else(|| "no data extracted".into())),
            r.extracted_data,
        ),
        Err(e) => (false, format!("run could not start: {e}"), Value::Null),
    };

    // Persist the outcome (durable, in the planner's CURRENT STATE) + a system transcript line the
    // next turn reads verbatim so it knows exactly what to fix.
    let mut plan = plan;
    plan.insert(
        "test_result".into(),
        json!({ "ok": ok, "detail": detail, "sample": cap(&serde_json::to_string(&extracted).unwrap_or_default(), 600) }),
    );
    let plan_s = serde_json::to_string(&plan).unwrap_or_else(|_| "{}".into());

    let mut transcript = parse_arr(sess.transcript.as_deref());
    let note = if ok {
        format!("test_workflow PASS — {detail}. The workflow runs; you can enable_connect + propose_connect_setup now.")
    } else {
        format!("test_workflow FAIL — {detail}. Fix the failing step/selector: call build_workflow again with corrected steps (workflow_id is set, so it UPDATES in place), then test_workflow again. Do not give up after one failure.")
    };
    transcript.push(json!({ "role": "system", "content": note, "ts": now_ts() }));
    let transcript_s = serde_json::to_string(&transcript).unwrap_or_else(|_| "[]".into());

    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate {
            status: Some("building"),
            plan: Some(&plan_s),
            transcript: Some(&transcript_s),
            progress_message: Some(if ok { "Workflow test passed." } else { "Workflow test failed — repairing." }),
            ..Default::default()
        },
    )
    .await;
    TurnOutcome::Continue
}

// ── Tool: configure_schedule ─────────────────────────────────────────────────

/// Turn on a time schedule for the workflow. `interval_minutes` (default 60) → `schedule_interval_ms`,
/// floored to the workflow anti-detection minimum. Any `cron` is stored in the plan for display only
/// (the local scheduler runs on interval). Requires `plan.workflow_id`.
async fn tool_configure_schedule(state: &AppState, sess: &ConciergeSession, args: &Value) -> TurnOutcome {
    let Some(workflow_id) = workflow_id_of(sess) else {
        return nudge(state, sess, "configure_schedule needs a workflow — call build_workflow first.").await;
    };
    let minutes = args.get("interval_minutes").and_then(|m| m.as_f64()).filter(|m| *m > 0.0).unwrap_or(60.0);
    let requested_ms = (minutes * 60_000.0) as i64;
    let interval_ms = crate::local::scheduler::clamp::clamp_workflow_interval_ms(Some(requested_ms));

    if let Err(e) = workflows::update(
        &state.db,
        workflow_id,
        &workflows::WorkflowUpdate {
            schedule_enabled: Some(1),
            schedule_interval_ms: Some(interval_ms),
            is_active: Some(1),
            ..Default::default()
        },
    )
    .await
    {
        return TurnOutcome::Error(format!("could not configure the schedule: {e}"));
    }

    // Store the cron for display in the plan (scheduler runs on interval).
    let mut plan = parse_obj(sess.plan.as_deref());
    if let Some(cron) = args.get("cron").and_then(|c| c.as_str()).filter(|s| !s.is_empty()) {
        plan.insert("schedule_cron".into(), json!(cron));
    }
    plan.insert("schedule_interval_ms".into(), json!(interval_ms));
    let plan_s = serde_json::to_string(&plan).unwrap_or_else(|_| "{}".into());

    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate {
            status: Some("building"),
            plan: Some(&plan_s),
            progress_message: Some("Schedule enabled."),
            ..Default::default()
        },
    )
    .await;
    TurnOutcome::Continue
}

// ── Tool: enable_connect ─────────────────────────────────────────────────────

/// Expose the workflow on the chosen call surfaces by merging a `connect` object into the workflow's
/// `streaming_config` JSON. An omitted surface stays ENABLED (matches `connect_surfaces` semantics).
/// Requires `plan.workflow_id`.
async fn tool_enable_connect(state: &AppState, sess: &ConciergeSession, args: &Value) -> TurnOutcome {
    let Some(workflow_id) = workflow_id_of(sess) else {
        return nudge(state, sess, "enable_connect needs a workflow — call build_workflow first.").await;
    };
    // HONEST GATE: never expose an API over a workflow whose auto-test FAILED — the endpoints would
    // return nothing. Fix the workflow first (discover_workflow updates in place) or ask the user.
    if test_result_failed(sess) {
        return nudge(state, sess, "the workflow's auto-test FAILED (it extracted no data) — do NOT expose an API over it. Re-run discover_workflow to fix it first, or ask_user.").await;
    }
    let workflow = match workflows::get_by_id(&state.db, workflow_id).await {
        Ok(Some(w)) => w,
        _ => return TurnOutcome::Error(format!("workflow {workflow_id} not found")),
    };

    let rest = args.get("rest").and_then(|b| b.as_bool());
    let openai = args.get("openai").and_then(|b| b.as_bool());
    let mcp = args.get("mcp").and_then(|b| b.as_bool());
    let merged = merge_connect_config(workflow.streaming_config.as_deref(), rest, openai, mcp);
    let merged_s = merged.to_string();

    if let Err(e) = workflows::update(
        &state.db,
        workflow_id,
        &workflows::WorkflowUpdate { streaming_config: Some(merged_s), ..Default::default() },
    )
    .await
    {
        return TurnOutcome::Error(format!("could not enable connect surfaces: {e}"));
    }

    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate {
            status: Some("building"),
            progress_message: Some("Connect surfaces enabled."),
            ..Default::default()
        },
    )
    .await;
    TurnOutcome::Continue
}

// ── Tool: propose_connect_setup (pause) ──────────────────────────────────────

/// PAUSE with a `connect_setup` elicitation: the exact daemon endpoints to call the workflow on each
/// ENABLED surface, so the FE can render the setup card (and let the user mint a `read|run` key). This
/// is emitted here (NOT via ask_user). Requires `plan.workflow_id`.
async fn tool_propose_connect_setup(state: &AppState, sess: &ConciergeSession) -> TurnOutcome {
    let Some(workflow_id) = workflow_id_of(sess) else {
        return nudge(state, sess, "propose_connect_setup needs a workflow — call build_workflow first.").await;
    };
    let workflow = match workflows::get_by_id(&state.db, workflow_id).await {
        Ok(Some(w)) => w,
        _ => return TurnOutcome::Error(format!("workflow {workflow_id} not found")),
    };
    let surfaces = build_connect_surfaces(workflow_id, workflow.streaming_config.as_deref());
    if surfaces.is_empty() {
        return nudge(state, sess, "no connect surfaces are enabled — call enable_connect first.").await;
    }

    let pending = json!({
        "requests": [{
            "field": "connect_ack",
            "kind": "connect_setup",
            "question": "Your workflow is exposed. Mint a key and call it on any of these endpoints:",
            "workflow_id": workflow_id,
            "surfaces": surfaces,
        }],
        "resume_status": "building",
    });
    let pending_s = pending.to_string();

    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate {
            status: Some("awaiting_input"),
            phase: Some("propose_connect_setup"),
            progress_message: Some("Here's how to call your workflow — mint a key to finish."),
            pending_request: Some(&pending_s),
            ..Default::default()
        },
    )
    .await;

    crate::local::flow::push_pending_toast(
        "Your workflow is callable",
        "Open the assistant to see the endpoints and mint a key.",
    );
    TurnOutcome::Pause
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Record a system nudge in the transcript, reset to `planning`, and continue (the model retries).
async fn nudge(state: &AppState, sess: &ConciergeSession, note: &str) -> TurnOutcome {
    let mut transcript = parse_arr(sess.transcript.as_deref());
    transcript.push(json!({ "role": "system", "content": note, "ts": now_ts() }));
    let ts = serde_json::to_string(&transcript).unwrap_or_else(|_| "[]".into());
    let _ = concierge_sessions::update(
        &state.db,
        sess.id,
        &ConciergeUpdate {
            status: Some("planning"),
            transcript: Some(&ts),
            ..Default::default()
        },
    )
    .await;
    TurnOutcome::Continue
}

/// One `user` turn carrying an optional screenshot + the DOM/goal text (mirrors ai_assist's user_msg).
fn find_selectors_user_msg(text: String, screenshot_b64: Option<&str>) -> AiMessage {
    let mut parts: Vec<AiContentPart> = Vec::new();
    if let Some(b64) = screenshot_b64.filter(|s| !s.is_empty()) {
        parts.push(AiContentPart::Image {
            source: ImageSource {
                source_type: "base64".into(),
                media_type: "image/jpeg".into(),
                data: b64.to_string(),
            },
        });
    }
    parts.push(AiContentPart::Text { text });
    AiMessage { role: "user".into(), content: AiMessageContent::Parts(parts) }
}

/// Validate a `querySelectorAll(<sel>).length > 0` on the live page. Any evaluate failure = no match
/// (reject the candidate). The selector is embedded as a JSON string literal to survive quoting.
async fn selector_matches(page: &playwright_rs::Page, selector: &str) -> bool {
    let sel_json = serde_json::to_string(selector).unwrap_or_else(|_| "\"\"".into());
    let js = format!("() => {{ try {{ return document.querySelectorAll({sel_json}).length; }} catch (e) {{ return 0; }} }}");
    match page.evaluate::<(), i64>(&js, None::<&()>).await {
        Ok(n) => n > 0,
        Err(_) => false,
    }
}

/// Coerce an answer/plan value to a JSON number when it parses (e.g. `"19.99"` or `"$19.99"`), else
/// keep it as-is. Keeps the `lt` condition numeric where possible.
fn coerce_number(v: &Value) -> Value {
    match v {
        Value::Number(_) => v.clone(),
        Value::String(s) => {
            let cleaned: String = s.chars().filter(|c| c.is_ascii_digit() || *c == '.').collect();
            if let Ok(f) = cleaned.parse::<f64>() {
                serde_json::Number::from_f64(f).map(Value::Number).unwrap_or_else(|| v.clone())
            } else {
                v.clone()
            }
        }
        _ => v.clone(),
    }
}

/// Round-trip block-tree self-validation: exactly one root event, known blockTypes, a valid condition
/// operator, and every non-root `parentId` referencing an existing block. Returns `Err(reason)` on the
/// first problem so `wire_automation` fails closed rather than persist a broken tree.
fn validate_block_tree(blocks: &Value) -> Result<(), String> {
    let arr = blocks.as_array().ok_or("blocks is not an array")?;
    if arr.is_empty() {
        return Err("no blocks".into());
    }
    let known_types = ["change_detected", "condition", "notification"];
    let valid_ops = [
        "exists", "changed", "contains", "not_contains", "equals", "not_equals", "matches", "gt",
        "gte", "lt", "lte",
    ];
    let event_types = ["change_detected"];

    let ids: std::collections::HashSet<String> = arr
        .iter()
        .filter_map(|b| b.get("id").and_then(|i| i.as_str()).map(str::to_string))
        .collect();

    let mut root_events = 0;
    for b in arr {
        let bt = b.get("blockType").and_then(|t| t.as_str()).ok_or("block missing blockType")?;
        if !known_types.contains(&bt) {
            return Err(format!("unknown blockType '{bt}'"));
        }
        // Every block MUST carry the category `type` (event/condition/action) that matches its
        // blockType — the desktop builder finds blocks by `type`, so a missing/wrong one renders the
        // trigger + actions EMPTY even with correct config. Fail closed rather than persist that.
        let expected_type = if event_types.contains(&bt) {
            "event"
        } else if bt == "condition" {
            "condition"
        } else {
            "action"
        };
        match b.get("type").and_then(|t| t.as_str()) {
            Some(t) if t == expected_type => {}
            Some(t) => return Err(format!("block '{bt}' has type '{t}' but should be '{expected_type}'")),
            None => return Err(format!("block '{bt}' is missing its category type '{expected_type}'")),
        }
        let parent = b.get("parentId");
        let is_root = parent.map(|p| p.is_null()).unwrap_or(true);
        if is_root {
            if event_types.contains(&bt) {
                root_events += 1;
            } else {
                return Err(format!("root block '{bt}' is not an event"));
            }
        } else if let Some(pid) = parent.and_then(|p| p.as_str()) {
            if !ids.contains(pid) {
                return Err(format!("dangling parentId '{pid}'"));
            }
        }
        if bt == "condition" {
            let op = b.get("config").and_then(|c| c.get("operator")).and_then(|o| o.as_str()).unwrap_or("");
            if !valid_ops.contains(&op) {
                return Err(format!("invalid condition operator '{op}'"));
            }
        }
    }
    if root_events != 1 {
        return Err(format!("expected exactly one root event, found {root_events}"));
    }
    Ok(())
}

/// Whether a string looks like an http(s) URL or a bare host we can prefix.
fn looks_like_url(s: &str) -> bool {
    let s = s.trim();
    s.starts_with("http://") || s.starts_with("https://") || (s.contains('.') && !s.contains(' '))
}

/// Prefix a bare host with `https://` so it's navigable.
fn normalize_url(s: &str) -> String {
    let s = s.trim();
    if s.starts_with("http://") || s.starts_with("https://") {
        s.to_string()
    } else {
        format!("https://{s}")
    }
}

/// Pull the first bare domain (`korben.info`, `example.co.uk`, `shop.site.com/x`) out of free text and
/// return it as an `https://` URL, so a goal that NAMES a site can be opened even when the planner
/// didn't pass a clean URL. `None` when no domain-like token is present. Prose words don't match
/// (a domain is a single dotted token with an alphabetic TLD; "main post" has a space so it can't).
fn guess_domain_url(text: &str) -> Option<String> {
    for raw in text.split(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | '"' | '\'' | '(' | ')' | '<' | '>')) {
        // Trim surrounding punctuation but keep interior dots / slashes / hyphens.
        let tok = raw.trim_matches(|c: char| !c.is_ascii_alphanumeric());
        if tok.is_empty() {
            continue;
        }
        let host = tok.split('/').next().unwrap_or(tok);
        let labels: Vec<&str> = host.split('.').collect();
        if labels.len() < 2 {
            continue;
        }
        let tld = labels[labels.len() - 1];
        let tld_ok = tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic());
        let labels_ok = labels.iter().all(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
        if tld_ok && labels_ok {
            return Some(format!("https://{}", host.to_ascii_lowercase()));
        }
    }
    None
}

fn cap(s: &str, n: usize) -> String {
    if s.chars().count() > n {
        s.chars().take(n).collect()
    } else {
        s.to_string()
    }
}

/// The workflow id recorded by `build_workflow` (from resources, falling back to plan).
fn workflow_id_of(sess: &ConciergeSession) -> Option<i64> {
    parse_obj(sess.resources.as_deref())
        .get("workflow_id")
        .and_then(Value::as_i64)
        .or_else(|| parse_obj(sess.plan.as_deref()).get("workflow_id").and_then(Value::as_i64))
}

/// Does the mission's recorded auto-test say the workflow extracts NO data? (`plan.test_result.ok ==
/// false`). Used as the HONEST GATE: no callable functions / API surfaces over an empty workflow —
/// downstream claims must derive from the verified signal, never from the planner's narration. A
/// missing test_result is NOT a failure (older/simple missions never ran one).
fn test_result_failed(sess: &ConciergeSession) -> bool {
    parse_obj(sess.plan.as_deref())
        .get("test_result")
        .and_then(|t| t.get("ok"))
        .and_then(Value::as_bool)
        == Some(false)
}

/// A callable-function name must be non-empty, alphanumeric + underscore (a stable identifier the
/// OpenAI/MCP surfaces can expose as a tool name).
fn valid_function_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Build the minimal-but-runnable workflow step array: a `navigate` to `url`, plus an `extract` for
/// `price_selector` (into `variable=price`) when one is known. Step shape mirrors the engine's
/// consumed `{type, config, enabled}` (config.url for navigate; config.selector + config.variable for
/// extract).
/// Validate + normalize planner-supplied workflow steps into the executor's step shape
/// (`{type, enabled, config}`). Whitelist-only: unknown types are rejected (never persisted as
/// dead steps), scripts go through the shared JS sanitizer, and navigate URLs must be http(s)
/// (the run-time URL guard still vets them again at execution).
fn validate_planner_steps(raw: &Value) -> Result<Vec<Value>, String> {
    const ALLOWED: [&str; 15] = [
        "navigate", "fill", "click", "select", "check", "press", "wait", "scroll",
        "scroll_into_view", "hover", "extract", "evaluate", "wait_for_change", "api_call",
        "login_post",
    ];
    const MAX_STEPS: usize = 30;

    let items = raw.as_array().cloned().unwrap_or_default();
    if items.is_empty() {
        return Err("steps must be a non-empty array".into());
    }
    if items.len() > MAX_STEPS {
        return Err(format!("too many steps ({} > {MAX_STEPS})", items.len()));
    }

    let mut out = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let ty = item
            .get("type")
            .and_then(|t| t.as_str())
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .ok_or_else(|| format!("step {i} has no type"))?;
        if !ALLOWED.contains(&ty) {
            return Err(format!("step {i} type '{ty}' is not allowed"));
        }
        let mut config = item
            .get("config")
            .and_then(|c| c.as_object().cloned())
            .unwrap_or_default();

        match ty {
            "navigate" => {
                let url = config.get("url").and_then(|u| u.as_str()).unwrap_or("").trim().to_string();
                if !(url.starts_with("https://") || url.starts_with("http://")) {
                    return Err(format!("step {i} navigate needs an http(s) config.url"));
                }
                config.insert("url".into(), json!(url));
            }
            "api_call" | "login_post" => {
                let has_url = config
                    .get("url")
                    .and_then(|u| u.as_str())
                    .is_some_and(|u| u.starts_with("http://") || u.starts_with("https://"));
                if !has_url {
                    return Err(format!("step {i} {ty} needs an http(s) config.url"));
                }
            }
            "fill" | "click" | "select" | "check" | "hover" | "scroll_into_view" | "extract" | "wait_for_change" => {
                let has_selector = config
                    .get("selector")
                    .and_then(|s| s.as_str())
                    .is_some_and(|s| !s.trim().is_empty());
                if !has_selector {
                    return Err(format!("step {i} ({ty}) needs a config.selector"));
                }
            }
            "evaluate" => {
                let script = config.get("script").and_then(|s| s.as_str()).unwrap_or("").to_string();
                if script.trim().is_empty() {
                    return Err(format!("step {i} evaluate needs a config.script"));
                }
                config.insert("script".into(), json!(crate::local::ai::brain::sanitize_js_script(&script)));
            }
            _ => {}
        }

        out.push(json!({ "type": ty, "enabled": true, "config": config }));
    }
    Ok(out)
}

fn build_workflow_steps(url: &str, price_selector: Option<&str>) -> Value {
    let mut steps = vec![json!({
        "type": "navigate",
        "enabled": true,
        "config": { "url": url },
    })];
    if let Some(sel) = price_selector.filter(|s| !s.is_empty()) {
        steps.push(json!({
            "type": "extract",
            "enabled": true,
            "config": { "selector": sel, "variable": "price" },
        }));
    }
    Value::Array(steps)
}

/// Merge a `connect` toggle object into a workflow's `streaming_config` JSON. An `Option::None` toggle
/// leaves that surface as-is (absent key = enabled per `connect_surfaces`); `Some(b)` writes it. Other
/// `streaming_config` keys are preserved.
fn merge_connect_config(
    streaming_config: Option<&str>,
    rest: Option<bool>,
    openai: Option<bool>,
    mcp: Option<bool>,
) -> Value {
    let mut root = streaming_config
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    let mut connect = root
        .get("connect")
        .and_then(|c| c.as_object().cloned())
        .unwrap_or_default();
    if let Some(b) = rest {
        connect.insert("rest".into(), json!(b));
    }
    if let Some(b) = openai {
        connect.insert("openai".into(), json!(b));
    }
    if let Some(b) = mcp {
        connect.insert("mcp".into(), json!(b));
    }
    root.insert("connect".into(), Value::Object(connect));
    Value::Object(root)
}

/// Build the `connect_setup` surface list for the ENABLED call surfaces of a workflow — the exact
/// daemon endpoint PATHS the FE prepends the loopback origin to. REST run body field is `inputs`
/// (confirmed from `api/v1/workflows.rs`'s `RunBody`). Only enabled surfaces (per `connect_surfaces`,
/// absent = enabled) are emitted.
pub(crate) fn build_connect_surfaces(workflow_id: i64, streaming_config: Option<&str>) -> Vec<Value> {
    let surfaces = workflows::connect_surfaces(streaming_config);
    let mut out: Vec<Value> = Vec::new();
    if surfaces.rest {
        out.push(json!({
            "id": "rest",
            "label": "REST",
            "method": "POST",
            "url": format!("/v1/workflows/{workflow_id}/run"),
            "example_body": "{\"inputs\":{}}",
        }));
    }
    if surfaces.openai {
        out.push(json!({
            "id": "openai",
            "label": "OpenAI-compatible",
            "method": "POST",
            "url": format!("/v1/workflows/{workflow_id}/v1/chat/completions"),
            "base_url": format!("/v1/workflows/{workflow_id}/v1"),
            "example_body": "{\"messages\":[{\"role\":\"user\",\"content\":\"run\"}]}",
        }));
    }
    if surfaces.mcp {
        out.push(json!({
            "id": "mcp",
            "label": "MCP",
            "method": "GET",
            "url": format!("/v1/workflows/{workflow_id}/v1/models"),
            "note": "Add as an MCP tool from the workflow's Connect tab.",
        }));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_tree_passes() {
        let blocks = json!([
            { "id": "e", "blockType": "change_detected", "type": "event", "parentId": Value::Null, "config": {} },
            { "id": "c", "blockType": "condition", "type": "condition", "parentId": "e", "config": { "operator": "lt" } },
            { "id": "n", "blockType": "notification", "type": "action", "parentId": "c", "config": {} }
        ]);
        assert!(validate_block_tree(&blocks).is_ok());
    }

    #[test]
    fn tree_rejects_missing_category_type() {
        // Correct blockType + config but no category `type` — the "empty block in the builder" bug.
        let no_type = json!([
            { "id": "e", "blockType": "change_detected", "parentId": Value::Null, "config": { "target_id": 1 } },
            { "id": "n", "blockType": "notification", "parentId": "e", "config": { "channels": ["desktop"] } }
        ]);
        assert!(validate_block_tree(&no_type).is_err());
    }

    #[test]
    fn tree_rejects_bad_operator_and_dangling_parent_and_two_roots() {
        let bad_op = json!([
            { "id": "e", "blockType": "change_detected", "type": "event", "parentId": Value::Null },
            { "id": "c", "blockType": "condition", "type": "condition", "parentId": "e", "config": { "operator": "decreased" } }
        ]);
        assert!(validate_block_tree(&bad_op).is_err());

        let dangling = json!([
            { "id": "e", "blockType": "change_detected", "type": "event", "parentId": Value::Null },
            { "id": "n", "blockType": "notification", "type": "action", "parentId": "missing" }
        ]);
        assert!(validate_block_tree(&dangling).is_err());

        let two_roots = json!([
            { "id": "e1", "blockType": "change_detected", "type": "event", "parentId": Value::Null },
            { "id": "e2", "blockType": "change_detected", "type": "event", "parentId": Value::Null }
        ]);
        assert!(validate_block_tree(&two_roots).is_err());
    }

    #[test]
    fn coerce_number_parses_currency_and_keeps_text() {
        assert_eq!(coerce_number(&json!("$19.99")), json!(19.99));
        assert_eq!(coerce_number(&json!(5)), json!(5));
        assert_eq!(coerce_number(&json!("cheap")), json!("cheap"));
    }

    #[test]
    fn url_detection() {
        assert!(looks_like_url("https://example.com/x"));
        assert!(looks_like_url("example.com/widget"));
        assert!(!looks_like_url("just a query"));
        assert_eq!(normalize_url("example.com"), "https://example.com");
        assert_eq!(normalize_url("http://a.com"), "http://a.com");
    }

    #[test]
    fn planner_steps_validate_and_normalize() {
        // A login flow: navigate → fill(user) → fill(secret placeholder) → click → wait → evaluate.
        let raw = json!([
            {"type": "navigate", "config": {"url": "https://site.app/login"}},
            {"type": "fill", "config": {"selector": "#user", "value": "me"}},
            {"type": "fill", "config": {"selector": "#pass", "value": "{{secret:concierge_1_password}}"}},
            {"type": "click", "config": {"selector": "button[type=submit]"}},
            {"type": "wait", "config": {"timeout": 2000}},
            {"type": "evaluate", "config": {"script": "[...document.querySelectorAll('.row')].map(e=>e.textContent)", "variable": "rows"}}
        ]);
        let steps = validate_planner_steps(&raw).expect("valid steps");
        assert_eq!(steps.len(), 6);
        // Each normalized step carries type + enabled + config.
        assert_eq!(steps[0]["type"], "navigate");
        assert_eq!(steps[0]["enabled"], true);
        // The secret placeholder is preserved verbatim in the fill value (resolved only at run time).
        assert_eq!(steps[2]["config"]["value"], "{{secret:concierge_1_password}}");
    }

    #[test]
    fn persona_only_navigate_extract_steps_are_valid() {
        // On the persona login path the workflow just navigates + extracts (the persona logs in),
        // so a login-free step list must still validate.
        let raw = json!([
            {"type": "navigate", "config": {"url": "https://site.app/account/workflows"}},
            {"type": "evaluate", "config": {"script": "[...document.querySelectorAll('.wf')].map(e=>e.textContent)", "variable": "workflows"}}
        ]);
        let steps = validate_planner_steps(&raw).expect("valid");
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0]["config"]["url"], "https://site.app/account/workflows");
    }

    fn sess_with(goal: &str, plan: Value, brain: Value) -> ConciergeSession {
        // The JSON-TEXT columns (plan/brain_history) are stored as strings, like the DB.
        serde_json::from_value(json!({
            "id": 1,
            "goal": goal,
            "platform": "desktop",
            "status": "planning",
            "plan": plan.to_string(),
            "brain_history": brain.to_string(),
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "ai_calls_count": 0,
            "turn_seq": 0,
            "cancel_requested": 0,
            "created_at": "now",
        }))
        .expect("valid ConciergeSession")
    }

    fn text_of(m: &AiMessage) -> &str {
        match &m.content {
            AiMessageContent::Text(t) => t,
            _ => "",
        }
    }

    #[test]
    fn planner_thread_turn_one_is_single_user_turn() {
        // No prior tool-calls yet → GOAL + CURRENT STATE collapse into ONE user turn (== old one-shot).
        let s = sess_with("watch X", json!({}), json!([]));
        let msgs = build_planner_thread(&s);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].role, "user");
        assert!(text_of(&msgs[0]).contains("GOAL: watch X"));
        assert!(text_of(&msgs[0]).contains("CURRENT STATE"));
        assert!(text_of(&msgs[0]).contains("reply with ONE JSON object"));
    }

    #[test]
    fn planner_thread_replays_prior_toolcalls_and_alternates() {
        let brain = json!([
            { "tool": "find_page", "thought": "open it", "args": {"seed_url": "https://x.com/p"}, "result": "Found the page. Proposing a price selector…" },
            { "tool": "propose_selectors", "thought": "find price", "args": {"want": "price"}, "result": "Selector found. Creating the monitor…" }
        ]);
        let s = sess_with("watch X", json!({ "resolved_url": "https://x.com/p", "price_selector": ".price" }), brain);
        let msgs = build_planner_thread(&s);
        let roles: Vec<&str> = msgs.iter().map(|m| m.role.as_str()).collect();
        assert_eq!(roles, ["user", "assistant", "user", "assistant", "user"]);
        // strict alternation
        assert!(roles.windows(2).all(|w| w[0] != w[1]));
        // assistant turns are the JSON decisions it actually made
        assert!(text_of(&msgs[1]).contains("\"tool\":\"find_page\""));
        assert!(text_of(&msgs[3]).contains("\"tool\":\"propose_selectors\""));
        // observations from the recorded results
        assert!(text_of(&msgs[2]).contains("OBSERVATION: Found the page"));
        // final authoritative state + cue
        assert!(text_of(&msgs[4]).contains("CURRENT STATE"));
        assert!(text_of(&msgs[4]).contains("reply with ONE JSON object"));
    }

    #[test]
    fn guess_domain_url_extracts_site_from_prose_goal() {
        // The domain-in-goal case that used to dead-end find_page into a stall.
        assert_eq!(
            guess_domain_url("monitor korben.info to notify me when the main post changes"),
            Some("https://korben.info".into())
        );
        assert_eq!(guess_domain_url("watch example.co.uk/deals"), Some("https://example.co.uk".into()));
        // Prose without a domain → None (find_page then asks for a URL instead of looping).
        assert_eq!(guess_domain_url("notify me when the main post changes"), None);
        // A version-like token is not a domain (numeric TLD).
        assert_eq!(guess_domain_url("upgrade to v1.2 today"), None);
    }

    #[test]
    fn normalize_tool_name_maps_synonyms_and_keeps_unknown() {
        // Common general-agent synonyms map to the canonical tools.
        assert_eq!(normalize_tool_name("clarify_requirements"), "ask_user");
        assert_eq!(normalize_tool_name("Ask"), "ask_user");
        assert_eq!(normalize_tool_name("create_workflow"), "build_workflow");
        assert_eq!(normalize_tool_name("expose_api"), "enable_connect");
        assert_eq!(normalize_tool_name("done"), "finish");
        assert_eq!(normalize_tool_name("navigate"), "find_page");
        assert_eq!(normalize_tool_name("crawl"), "dragnet_crawl");
        assert_eq!(normalize_tool_name("scrape_site"), "dragnet_crawl");
        assert_eq!(normalize_tool_name("synthesize"), "synthesize_crawl_answer");
        assert_eq!(normalize_tool_name("answer_from_crawl"), "synthesize_crawl_answer");
        // Dataset-reading tools (search / list / answer-on-hand) + their synonyms.
        assert_eq!(normalize_tool_name("search_data"), "search_datasets");
        assert_eq!(normalize_tool_name("query_datasets"), "search_datasets");
        assert_eq!(normalize_tool_name("my_datasets"), "list_datasets");
        assert_eq!(normalize_tool_name("answer_from_data"), "answer_from_datasets");
        assert_eq!(normalize_tool_name("search_datasets"), "search_datasets");
        // Every dataset tool is in VALID_TOOLS so dispatch accepts it.
        for t in ["list_datasets", "search_datasets", "answer_from_datasets"] {
            assert!(VALID_TOOLS.contains(&t), "{t} missing from VALID_TOOLS");
        }
        // Canonical names pass through.
        assert_eq!(normalize_tool_name("build_workflow"), "build_workflow");
        assert_eq!(normalize_tool_name("synthesize_crawl_answer"), "synthesize_crawl_answer");
        // A truly unknown/invented name is kept verbatim so dispatch nudges with the valid list.
        assert_eq!(normalize_tool_name("create_plan"), "create_plan");
        assert_eq!(normalize_tool_name("respond"), "respond");
    }

    #[test]
    fn parse_tool_decision_accepts_openai_arguments_shape() {
        // Models routinely emit OpenAI-style `arguments` (object) + `name` instead of `args`+`tool`.
        let d = parse_tool_decision(
            r#"{"tool":"ask_user","arguments":{"requests":[{"field":"x","kind":"text","question":"q"}]}}"#,
        )
        .unwrap();
        assert_eq!(d.tool, "ask_user");
        assert!(d.args.get("requests").is_some());
        // `arguments` as a JSON-ENCODED STRING (also OpenAI schema) + `name` for the tool.
        let d2 = parse_tool_decision(r#"{"name":"find_page","arguments":"{\"query\":\"korben.info\"}"}"#).unwrap();
        assert_eq!(d2.tool, "find_page");
        assert_eq!(d2.args["query"], "korben.info");
        // Canonical shape still parses, incl. thought/message.
        let d3 = parse_tool_decision(r#"{"tool":"finish","args":{"summary":"done"},"thought":"t","message":"m"}"#).unwrap();
        assert_eq!(d3.tool, "finish");
        assert_eq!(d3.thought, "t");
        assert_eq!(d3.args["summary"], "done");
    }

    #[test]
    fn is_index_url_flags_bare_listing_not_detail() {
        // Bare single-segment path, no query → an index/listing page (sorted LAST in synthesis).
        assert!(is_index_url("https://news.ycombinator.com/news"));
        assert!(is_index_url("https://news.ycombinator.com/"));
        assert!(is_index_url("https://example.com"));
        // A query id or a deeper path → a DETAIL page (kept ahead of listings).
        assert!(!is_index_url("https://news.ycombinator.com/item?id=123"));
        assert!(!is_index_url("https://news.ycombinator.com/news?p=2"));
        assert!(!is_index_url("https://example.com/blog/a-post"));
    }

    #[test]
    fn synth_orders_detail_pages_before_listings() {
        // A capped corpus must drop the bare listing, never an item page — so detail sorts first.
        let mut pages = [SynthPage { url: Some("https://news.ycombinator.com/news".into()), title: None, content: Some("list".into()), rows: None },
            SynthPage { url: Some("https://news.ycombinator.com/item?id=2".into()), title: None, content: Some("thread".into()), rows: None }];
        pages.sort_by_key(|p| if is_index_url(p.url.as_deref().unwrap_or("")) { 1 } else { 0 });
        assert!(pages[0].url.as_deref().unwrap().contains("item?id="));
        assert!(pages[1].url.as_deref().unwrap().ends_with("/news"));
    }

    #[test]
    fn looks_degenerate_catches_loops_and_garbage() {
        // A healthy multi-line answer is fine.
        assert!(!looks_degenerate("# Top stories\n- Story A (120 pts)\n- Story B (98 pts)\n- Story C (75 pts)"));
        // A mostly-repeated line (small-model loop) is rejected.
        let looped = "Inkling 1036\n".repeat(8);
        assert!(looks_degenerate(&looped));
        // Replacement-char / <unk> garbage is rejected.
        assert!(looks_degenerate("answer <unk> <unk> <unk> value"));
        // Trivially short output is rejected.
        assert!(looks_degenerate("ok"));
    }

    #[test]
    fn redact_args_masks_secret_keys_only() {
        let a = json!({ "want": "price", "password": "hunter2", "steps": [{ "config": { "cardNumber": "4111" } }] });
        let r = redact_args(&a);
        assert_eq!(r["want"], "price"); // benign kept
        assert_eq!(r["password"], "[REDACTED]"); // secret masked
        assert_eq!(r["steps"][0]["config"]["cardNumber"], "[REDACTED]"); // nested + substring match
    }

    #[test]
    fn planner_steps_reject_bad_input() {
        // Unknown step type.
        assert!(validate_planner_steps(&json!([{"type": "wire_money", "config": {}}])).is_err());
        // Navigate without an http(s) URL (SSRF-adjacent / file scheme).
        assert!(validate_planner_steps(&json!([{"type": "navigate", "config": {"url": "file:///etc/passwd"}}])).is_err());
        // Fill without a selector.
        assert!(validate_planner_steps(&json!([{"type": "fill", "config": {"value": "x"}}])).is_err());
        // Empty array.
        assert!(validate_planner_steps(&json!([])).is_err());
    }
}
