//! Static `writ_*` MCP tools — the fixed catalog that ships alongside the per-workflow tools.
//!
//! Per-workflow tools let a client REPLAY what already exists; these tools let it CREATE and manage:
//! start a concierge build mission (`writ_build`), follow/answer/cancel it (`writ_mission_*`), and
//! run/inspect/schedule saved workflows generically (`writ_run_workflow`, `writ_workflow_data`,
//! `writ_workflow_runs`, `writ_set_schedule`, `writ_list_workflows`). Together they make the
//! build-once-replay-forever loop drivable end-to-end from an MCP client.
//!
//! They deliberately REUSE the REST cores (`api::v1::ai_concierge::{start_core, respond_core,
//! cancel_core}`, `api::v1::data::scan_workflow_data_runs_pool`) so MCP and the app share one code
//! path — same provider gate, same secret sealing, same turn_seq semantics.
//!
//! SECURITY: credentials NEVER transit this surface. Mission questions of kind `secret` are
//! surfaced with `secret:true` + an instruction to enter them in the Writ app; answers matching a
//! secret-kind field are refused. `writ_run_workflow` honors the per-workflow Connect → MCP toggle
//! exactly like the derived tools (disabled ⇒ not runnable here).

use crate::local::api::v1::ai_concierge::{self, RespondBody, RespondFailure};
use crate::local::api::v1::data;
#[cfg(feature = "cloud")]
use crate::local::cloud::{marketplace as cloud_marketplace, state::LinkState};
use crate::local::error::LocalError;
use crate::local::server::AppState;
#[cfg(feature = "cloud")]
use crate::local::store::installed_workflows;
use crate::local::store::{
    automations, concierge_sessions, personas, runs, targets, vault_secrets, workflows,
};
// Local crawl-job store: reachable ONLY in the OSS self-host build. In the managed (`cloud`) build
// a crawl never runs on this machine (it forwards to the fleet), so the local job table is never read.
#[cfg(not(feature = "cloud"))]
use crate::local::store::crawl_jobs;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use super::tool_executor::CallError;

/// Every static tool name — reserved in the workflow-derived catalog so a workflow named e.g.
/// "writ build" can never shadow a static tool (it falls back to `workflow_<id>`).
pub const NAMES: [&str; 32] = [
    "writ_browser_use",
    "writ_personas",
    "writ_build",
    "writ_record_website",
    "writ_website_to_api",
    "writ_crawl_site",
    "writ_crawl_status",
    "writ_saved_crawls",
    "writ_run_saved_crawl",
    "writ_saved_crawl_data",
    "writ_scrape",
    "writ_map",
    "writ_browser_act",
    "writ_browser_context",
    "writ_browser_network",
    "writ_browser_save",
    "writ_browser_cancel",
    "writ_expose_workflow_api",
    "writ_list_workflows",
    "writ_run_workflow",
    "writ_workflow_data",
    "writ_workflow_runs",
    "writ_list_datasets",
    "writ_dataset",
    "writ_dataset_search",
    "writ_set_schedule",
    "writ_create_monitor",
    "writ_wire_monitor",
    "writ_create_automation",
    "writ_search_data",
    "writ_search_api",
    "writ_install_api",
];

/// The subset of [`NAMES`] that requires a linked Writ Cloud account: `tools/list` only advertises
/// them when the app is cloud-linked (see `tools::list_tools`), and their handlers re-check the link
/// at call time (a client may cache an older list). They stay in [`NAMES`] unconditionally so a
/// workflow can never shadow them, linked or not.
pub const CLOUD_LINKED_NAMES: [&str; 2] = ["writ_search_api", "writ_install_api"];

/// The public `tools/list` entries for the static tools. Descriptions are written FOR the model:
/// they teach the build-once-replay-forever pattern (that's the whole point of the connector).
pub fn entries() -> Vec<Value> {
    #[allow(unused_mut)]
    let mut list = vec![
        tool(
            "writ_browser_use",
            "Use a REAL browser through Writ to do ANY web task — Writ IS your browser, so route \
             EVERY browsing need here instead of a separate/built-in browser or a scraper. Reach \
             for this WHENEVER you must browse: look something up on a site, click through a flow, \
             fill and submit a form, sign in (including behind a login), navigate pages, take an \
             action on a site, or read/extract what's on the page. Writ opens its OWN local \
             browser (the user's real profile, saved personas + sealed vault, stealth driver) and \
             returns a live page observation; then drive it turn-by-turn with writ_browser_act \
             using the full action vocabulary (navigate, click, fill, select, press_key, scroll, \
             evaluate_js, extract, api_call, and more). The cleaned DOM comes back automatically \
             after every navigation and on demand via writ_browser_context(section=page); every \
             request the page makes is captured passively and searchable with writ_browser_network. \
             FOLLOW THE USER'S DIRECTIONS and ASK the user directly in chat whenever you need a \
             decision, a value to type, a credential, or a 2FA/OTP code — never guess or invent \
             secrets (for a sensitive fill set data_key so the saved step keeps a placeholder, \
             never the raw value). Recording is automatic but SAVING IS ON DEMAND: just complete \
             the task; only if the user wants to REUSE it, call writ_browser_save to store a clean, \
             deterministic workflow that then replays at zero AI-token cost. No Writ AI-provider \
             key or cloud link is needed. Prefer replaying an existing saved workflow \
             (writ_list_workflows → writ_run_workflow) when one already does the task.",
            browser_use_schema(),
        ),
        tool(
            "writ_personas",
            "See and operate the saved sign-in identities (personas) on this device so tasks \
             behind a login run unattended. A persona holds a site's username plus credentials \
             sealed on-device (never readable here), optional 2FA whose codes are minted by the \
             daemon, and a warm signed-in session. USE one by passing `persona` (its id or name) \
             to writ_crawl_site, writ_run_workflow or writ_install_api — the build tools also \
             offer the saved personas interactively when a flow needs a login. BEFORE asking the \
             user for credentials for a site, call action='list' (filter by domain) — an existing \
             persona already answers a login-gated task. action='get' inspects one persona \
             (include_runs adds its recent runs); action='sign_in' runs its login workflow NOW to \
             establish or refresh the warm session (force=true re-logs-in even when the session \
             still looks usable); action='record_login' launches a local AI session that signs in \
             as the persona once and RECORDS the flow as its login workflow, after which it can \
             always sign itself back in. This tool can NOT create, edit or delete personas, and \
             no credential or one-time code ever passes through it — the user manages those in \
             the Writ app on the Personas page; send them there when no persona fits.",
            json!({
                "type": "object",
                "properties": {
                    "action": { "type": "string", "enum": ["list", "get", "sign_in", "record_login"], "description": "What to do (default list)." },
                    "persona_id": { "type": ["integer", "string"], "description": "Which persona (id, or its exact name) — required for get / sign_in / record_login." },
                    "domain": { "type": "string", "description": "list: only personas usable on this host (suffix match), e.g. 'github.com'." },
                    "include_runs": { "type": "boolean", "description": "get: include the persona's recent runs (which workflows acted as it, and whether they succeeded)." },
                    "force": { "type": "boolean", "description": "sign_in: re-run the login even when the current session still looks usable." },
                    "login_url": { "type": "string", "description": "record_login: exact sign-in page URL when known; defaults to the persona's domain root (the AI finds the form from there)." }
                },
                "required": ["action"]
            }),
        ),
        tool(
            "writ_build",
            "Start building a reusable browser workflow with the CONNECTED MCP client as the AI. \
             Writ opens its local browser and returns an observation; continue with \
             writ_browser_act and finish with writ_browser_save. Use for repeatable web tasks when \
             no more specific Writ start tool applies. This path never calls Writ's configured AI \
             provider and never requires a cloud link or second model key.",
            website_build_schema("What to automate, in plain language"),
        ),
        tool(
            "writ_record_website",
            "Start recording a website task with the connected MCP client as the AI. Use whenever the \
             user asks to record, capture, teach, automate, or repeat actions on a website. Writ \
             opens its LOCAL browser and returns an observation; then call writ_browser_act as \
             needed and writ_browser_save when the goal is complete. No Writ AI-provider key or \
             cloud link is needed.",
            website_build_schema("What should be recorded on the website, in plain language"),
        ),
        tool(
            "writ_website_to_api",
            "Start turning a website into a callable API with the connected MCP client as the AI — \
             the answer when a service exposes NO official/public/practical API but the user wants \
             its data or actions programmatically. Writ \
             opens its LOCAL browser; use writ_browser_act to navigate and create live extraction \
             steps, then writ_browser_save. Saving automatically enables the secured REST and \
             OpenAI-compatible local endpoints. No Writ AI-provider key or cloud link is needed. \
             The first call may instead return existing_workflows — the user's OWN workflows \
             already matching the goal (propose replaying those first; skip_existing=true to \
             bypass) — or, on a cloud-linked app, marketplace_candidates — ready-made marketplace \
             APIs compatible with the goal: propose them to the user (install with \
             writ_install_api), and only record fresh by calling again with skip_marketplace=true \
             if the user declines.",
            website_build_schema("What the website API should do or return, in plain language"),
        ),
        tool(
            "writ_crawl_site",
            "Crawl a WHOLE website into ONE queryable, deduped dataset with Writ's Dragnet crawler. \
             USE THIS whenever the user wants ALL/EVERY page, the ENTIRE site, a whole section \
             swept, 'crawl <site>', or 'get all the data of this site' — NOT a single page and NOT \
             one login-gated data flow (use writ_website_to_api / writ_build for those; do NOT loop \
             those over pages yourself — this tool IS the site-wide crawl). Writ maps the site \
             (sitemap + robots.txt + link graph), then fetches every in-scope page on the Writ Cloud \
             FLEET (many egress IPs, managed browsers; HTTP-first, browser fallback) — never on this \
             machine (the self-hosted build uses a local worker pool) — honoring robots.txt, a \
             politeness delay and a concurrency cap. extract='markdown' (default) captures clean \
             markdown per page; extract='schema' replays a prebuilt CSS extractor at zero AI cost. \
             The crawl runs in the BACKGROUND: this call returns immediately with crawl_id + \
             workflow_id + queued status. Poll writ_crawl_status until the status is terminal, then \
             read the collected pages with writ_workflow_data (workflow = the returned workflow_id) \
             or expose the whole dataset as an API with writ_expose_workflow_api. For a login-gated \
             site, pass a persona so pages behind the login are reachable. On the managed app a \
             whole-site crawl needs a linked cloud account or API key and is metered per page; to try \
             a single page without a key, use writ_scrape.",
            json!({
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "Seed URL of the site or section to crawl" },
                    "extract": { "type": "string", "enum": ["markdown", "schema"], "description": "markdown (default) = clean markdown per page; schema = replay a prebuilt CSS extractor (supply extract_schema)" },
                    "extract_schema": { "type": "object", "description": "CSS extraction schema (row_selector + fields) applied to every page when extract='schema'" },
                    "max_pages": { "type": "integer", "description": "Cap on pages fetched (default 500, max 50000)" },
                    "max_depth": { "type": "integer", "description": "Maximum link depth from the seed (default 3)" },
                    "include": { "type": "array", "items": { "type": "string" }, "description": "Only crawl URL paths matching these regexes" },
                    "exclude": { "type": "array", "items": { "type": "string" }, "description": "Skip URL paths matching these regexes" },
                    "same_domain": { "type": "boolean", "description": "Stay on the seed's registered domain (default true)" },
                    "allow_subdomains": { "type": "boolean", "description": "Allow subdomains of the seed domain (default true)" },
                    "content": { "type": "object", "description": "Content-selection spec applied to every page: {preset, include_comments (keep discussion/comment threads), exclude_selectors[], include_selectors[], keep}. Omit for default extraction." },
                    "persona": { "description": "Persona id or name to crawl a login-gated site as; omit for public sites", "type": ["string", "integer"] },
                    "save_as": { "type": "string", "description": "Save these settings under this name so the crawl becomes callable by API and re-runnable. Reusing the same name updates that saved crawl instead of creating a duplicate. See writ_saved_crawls." },
                    "max_age": { "type": "integer", "minimum": 0, "description": "Only meaningful with save_as: if that saved crawl already completed within this many seconds, return its collected data instead of crawling again. 0 (default) always crawls." }
                },
                "required": ["url"]
            }),
        ),
        tool(
            "writ_crawl_status",
            "Poll a Dragnet crawl started with writ_crawl_site. Pass crawl_id for one crawl's live \
             status — status, pages done / discovered / failed / skipped, active workers, current \
             depth; omit crawl_id for a newest-first list of recent crawls. When status is terminal \
             (completed / failed / cancelled), read the collected pages with writ_workflow_data \
             (workflow = the crawl's workflow_id) or expose the whole dataset as an API with \
             writ_expose_workflow_api.",
            json!({
                "type": "object",
                "properties": {
                    "crawl_id": { "type": "integer", "description": "Crawl id returned by writ_crawl_site; omit to list recent crawls" },
                    "limit": { "type": "integer", "description": "When listing, max crawls to return (default 20, max 100)" }
                },
                "required": []
            }),
        ),
        tool(
            "writ_saved_crawls",
            "List SAVED crawls — stored crawl configurations that are callable by API and re-runnable, \
             each of which may already hold collected data. Check here BEFORE crawling a site again: a \
             saved crawl with recent data answers instantly and costs nothing, where a fresh whole-site \
             crawl is slow and metered. Run one with writ_run_saved_crawl.",
            json!({
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "description": "Max saved crawls to return (default 50, max 200)" }
                },
                "required": []
            }),
        ),
        tool(
            "writ_run_saved_crawl",
            "Run a SAVED crawl with its stored settings. Pass max_age to get the data it already \
             collected when that run is recent enough — the cheap, instant path; otherwise the site is \
             crawled again. The response carries `_cache.hit` and `_cache.age_seconds` so you can tell \
             which happened. A fresh crawl returns a crawl id to poll with writ_crawl_status, because a \
             whole-site crawl takes far longer than one tool call.",
            json!({
                "type": "object",
                "properties": {
                    "crawl": { "description": "Saved crawl slug, name, or id (from writ_saved_crawls)", "type": ["string", "integer"] },
                    "max_age": { "type": "integer", "minimum": 0, "description": "Reuse the last completed crawl if it finished within this many seconds. 0 (default) always re-crawls." },
                    "limit": { "type": "integer", "description": "Rows of collected data to include (default 50, max 500)" }
                },
                "required": ["crawl"]
            }),
        ),
        tool(
            "writ_saved_crawl_data",
            "Read the data a SAVED crawl already collected on its most recent completed run. Never \
             starts a crawl — use this when you want whatever is already there, at any age. To insist \
             on recency instead, use writ_run_saved_crawl with max_age.",
            json!({
                "type": "object",
                "properties": {
                    "crawl": { "description": "Saved crawl slug, name, or id (from writ_saved_crawls)", "type": ["string", "integer"] },
                    "limit": { "type": "integer", "description": "Rows to return (default 50, max 500)" }
                },
                "required": ["crawl"]
            }),
        ),
        tool(
            "writ_scrape",
            "Scrape ONE page to clean markdown — the fast single-URL read (Firecrawl's /scrape). Use for \
             a SINGLE page; for a whole site or section use writ_crawl_site instead. Runs on Writ Cloud, \
             never on this machine: with a linked account or API key it is metered per page (uncapped by \
             your plan); WITHOUT a credential it uses the FREE keyless tier (daily-capped, just to test). \
             Returns the page title + markdown immediately.",
            json!({
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "The page URL to scrape to markdown" }
                },
                "required": ["url"]
            }),
        ),
        tool(
            "writ_map",
            "Map a site's URLs — sitemap + a shallow link harvest, ranked by relevance to an optional \
             search (Firecrawl's /map). Cheap discovery to decide what to scrape or crawl next; spends no \
             pages. Runs on Writ Cloud: the metered path when a cloud account or API key is present, else \
             the FREE keyless tier (daily-capped). Not a whole-site crawl — use writ_crawl_site for that.",
            json!({
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "The site URL to map" },
                    "search": { "type": "string", "description": "Optional plain-English intent to rank the URLs by relevance" }
                },
                "required": ["url"]
            }),
        ),
        tool(
            "writ_browser_act",
            "Continue a connected-AI recording session. Execute structured browser actions in \
             Writ's local browser, receive the next page observation, and record every successful \
             replayable action. Prefer selectors over coordinates. Use evaluate_js with a variable \
             for live structured extraction. Ask for every clarification or intervention directly \
             in the connected AI chat, then continue this session. For sensitive fill values set \
             data_key so the saved step contains a placeholder, never the raw value.",
            json!({
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" },
                    "actions": { "type": "array", "items": { "type": "object" }, "description": "Desktop explorer actions: navigate, inspect, find_text, list_candidates, fill, click, select, capture_network, api_call, login_post, extract/evaluate, upload, download, and more" },
                    "inputs": { "type": "object", "description": "User answers for {{placeholders}} needed by this turn. Ask in the connected AI chat, then pass them here; sensitive values are ephemeral." },
                    "include_page_context": { "type":"boolean", "description":"Force cleaned DOM/fields/links in this result. Normally automatic for navigation/URL changes and omitted for same-page clicks/fills." }
                },
                "required": ["session_id", "actions"]
            }),
        ),
        tool(
            "writ_browser_context",
            "Read the full desktop Concierge/explorer operating policy in bounded pages. Use this during connected discovery whenever the compact guidance is insufficient; it preserves all DOM probing, network/API discovery, authentication, function-definition, correction, and done-check rules without overflowing MCP result limits.",
            json!({
                "type":"object",
                "properties":{
                    "session_id":{"type":"string"},
                    "section":{"type":"string","enum":["page","explorer","concierge_api"],"default":"page","description":"page returns the current cleaned DOM/fields/links on demand; the other sections return paginated operating instructions"},
                    "offset":{"type":"integer","minimum":0,"description":"Character offset; default 0"},
                    "max_chars":{"type":"integer","minimum":1000,"maximum":10000,"description":"Page size; default 8000"}
                },
                "required":["session_id"]
            }),
        ),
        tool(
            "writ_browser_network",
            "Search and inspect the actual structured NetworkCall objects passively captured by Writ. Normal browser responses include only a count. First use operation=search to receive indexed summaries; then use operation=detail with index to receive that call's method, URL, status, content types, headers, request body, response body, trigger and step. list/get remain aliases. Bodies are bounded and credentials are replaced by placeholders.",
            json!({
                "type":"object",
                "properties":{
                    "session_id":{"type":"string"},
                    "operation":{"type":"string","enum":["search","detail","list","get"]},
                    "query":{"type":"string","description":"Search URL, method, status, content type, request body and response body"},
                    "url":{"type":"string","description":"Backward-compatible URL substring filter"},
                    "index":{"type":"integer","minimum":0,"description":"Stable capture index returned by search; preferred for detail"},
                    "method":{"type":"string","description":"Optional HTTP method filter"},
                    "offset":{"type":"integer","minimum":0},
                    "max_chars":{"type":"integer","minimum":1000,"maximum":10000}
                },
                "required":["session_id","operation"]
            }),
        ),
        tool(
            "writ_browser_save",
            "Finish a connected-AI browser session and save its recorded steps as a reusable \
             workflow in the Writ desktop library. The workflow immediately becomes available for \
             deterministic replay and as an MCP tool. API-building sessions also enable local API \
             surfaces. If a DOM login was recorded, the first call returns needs_finalization: inspect \
             the captured auth calls and retry with the regular Writ optimizer proposal. Writ \
             live-verifies every substitution and keeps the DOM path when it is unsafe. For a \
             build/record or API session, call this once the task is complete; for a writ_browser_use \
             session, saving is ON DEMAND — save only when the user wants to reuse the flow.",
            json!({
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" },
                    "name": { "type": "string", "description": "Optional concise workflow name" },
                    "optimization": { "type":"object", "description":"Optional regular Writ optimizer proposal: {substitutions:[{replace_indices:[...],with:{type:'login_post'|'api_call',config:{url,method,headers,body,variable}}}],removals:[...]}. Writ live-verifies every substitution before applying it." }
                },
                "required": ["session_id"]
            }),
        ),
        tool(
            "writ_browser_cancel",
            "Cancel a connected-AI browser recording without saving a workflow.",
            json!({
                "type": "object",
                "properties": { "session_id": { "type": "string" } },
                "required": ["session_id"]
            }),
        ),
        tool(
            "writ_expose_workflow_api",
            "Expose an existing saved workflow as a callable API endpoint. venue='local' (default) \
             enables Writ's secured LOOPBACK HTTP server (REST and/or OpenAI-compatible) — only \
             callable from THIS machine; the Writ daemon owns the server, never create a separate \
             web-server process. venue='cloud' returns a PUBLIC Writ Cloud HTTPS endpoint instead \
             — use it whenever the user's app/caller does NOT run on this machine (it pushes the \
             workflow to the cloud first when needed, or reuses its existing cloud copy, and needs \
             the free cloud link). Always relay the returned endpoint directly.",
            json!({
                "type": "object",
                "properties": {
                    "workflow": { "description": "Workflow name or id", "type": ["string", "integer"] },
                    "surface": { "type": "string", "enum": ["rest", "openai", "both"], "description": "Local API style to expose (default: rest; venue='local' only)" },
                    "venue": { "type": "string", "enum": ["local", "cloud"], "description": "local = loopback server on this machine (default); cloud = public Writ Cloud endpoint for external apps" }
                },
                "required": ["workflow"]
            }),
        ),
        tool(
            "writ_list_workflows",
            "List the saved replayable workflows (id, name, schedule, last run, whether each is \
             exposed as an MCP tool). Use this to discover what can be replayed or scheduled \
             instead of re-browsing.",
            json!({ "type": "object", "properties": {}, "required": [] }),
        ),
        tool(
            "writ_run_workflow",
            "Run a saved workflow by name or id and return its extracted data. Deterministic replay \
             — zero AI tokens. Use for workflows just created by writ_build (their dedicated tools \
             appear on the next tools/list). Pass max_age when a recent answer is good enough: the \
             previous result comes back instead of driving the browser again. Pass persona (a saved \
             identity from writ_personas) to run the workflow signed in as that identity instead of \
             its default.",
            json!({
                "type": "object",
                "properties": {
                    "workflow": { "description": "Workflow name or id", "type": ["string", "integer"] },
                    "inputs": { "type": "object", "description": "Values for the workflow's {{input.*}} placeholders" },
                    "persona": { "description": "Run AS this saved identity (id or name; see writ_personas) — signs in with the persona's session. Omit to use the workflow's default persona, if it has one.", "type": ["string", "integer"] },
                    "max_age": { "type": "integer", "minimum": 0, "description": "Reuse a previous result if it is younger than this many seconds, instead of running the workflow again. 0 (the default) always runs fresh. Much faster and cheaper when a recent answer will do." },
                },
                "required": ["workflow"],
            }),
        ),
        tool(
            "writ_workflow_data",
            "Read the extracted data of a workflow's most recent successful run(s) WITHOUT running \
             it — the cheap way to fetch the latest results of a scheduled workflow (e.g. a daily \
             data pull). Pass run_id (from writ_workflow_runs) to read ONE specific run's data \
             instead. To find data by content across runs, use writ_search_data. YOU CHOOSE THE \
             OUTPUT SHAPE via 'format': 'markdown' hands you readable prose (a crawl's pages as \
             documents, structured data as a table) — pick it when you want to READ or SUMMARIZE \
             the content, it costs far fewer tokens than JSON with markdown escaped inside it; \
             'csv' for a compact table; 'json' (the default) when you need to parse fields.",
            json!({
                "type": "object",
                "properties": {
                    "workflow": { "description": "Workflow name or id", "type": ["string", "integer"] },
                    "runs": { "type": "integer", "description": "How many recent successful runs to return (default 1, max 20)" },
                    "run_id": { "type": "integer", "description": "Read this specific run's data instead of the latest" },
                    "format": { "type": "string", "enum": ["json", "markdown", "csv"], "description": "Output shape for the aggregate read (ignored with run_id). json (default) = structured records. markdown = READABLE prose — a crawl's pages render as documents, structured data as a table; prefer this to READ/summarize content (far fewer tokens than JSON-escaped markdown). csv = compact tabular." },
                },
                "required": ["workflow"],
            }),
        ),
        tool(
            "writ_workflow_runs",
            "Recent run history: status, error, duration, timestamps. With 'workflow' → that \
             workflow's runs; WITHOUT it → the latest runs across ALL workflows (a feed). Use to \
             check whether a scheduled workflow is healthy, or to find a run_id for \
             writ_workflow_data.",
            json!({
                "type": "object",
                "properties": {
                    "workflow": { "description": "Optional workflow name or id; omit for the latest runs across all workflows", "type": ["string", "integer"] },
                    "limit": { "type": "integer", "description": "Max runs to return (default 10, max 50)" },
                },
                "required": [],
            }),
        ),
        tool(
            "writ_list_datasets",
            "List your DATASETS — every data source that has accumulated extracted data, framed as \
             a queryable dataset. Each entry has an id, name, source_type ('crawl' for a whole-site \
             Dragnet crawl, 'workflow' for a recorded/looped workflow), a run count and a \
             last-updated time. Use this to discover what data already exists BEFORE running \
             anything, then read a dataset's rows with writ_dataset (filter + paginate) or search \
             across all of them with writ_search_data.",
            json!({ "type": "object", "properties": {}, "required": [] }),
        ),
        tool(
            "writ_dataset",
            "Query ONE dataset's accumulated records as a single flat, filterable table — the rows \
             every run of that data source produced, deduped into columns. Pass 'dataset' (name or \
             id, from writ_list_datasets), an optional 'query' to keep only rows matching that free \
             text, and 'limit'. Returns the columns + matching records with the run each came from. \
             This is the cheap way to pull a scheduled workflow's or a crawl's collected data \
             WITHOUT re-running it; for one specific run's raw payload use writ_workflow_data, and \
             to search across ALL datasets at once use writ_search_data. YOU CHOOSE THE OUTPUT \
             SHAPE via 'format': 'markdown' hands you readable prose (a crawl's pages as documents, \
             structured data as a table) — pick it when you want to READ or SUMMARIZE the content, \
             it costs far fewer tokens than JSON with markdown escaped inside it; 'csv' for a \
             compact table; 'json' (the default) when you need to parse fields.",
            json!({
                "type": "object",
                "properties": {
                    "dataset": { "description": "Dataset name or id (a workflow/crawl id)", "type": ["string", "integer"] },
                    "query": { "type": "string", "description": "Optional free text; keep only records matching it across every column" },
                    "limit": { "type": "integer", "description": "Max records to return (default 50, max 500)" },
                    "format": { "type": "string", "enum": ["json", "markdown", "csv"], "description": "Output shape. json (default) = structured records. markdown = READABLE prose — a crawl's pages render as documents, structured data as a table; prefer this to READ/summarize content (far fewer tokens than JSON-escaped markdown). csv = compact tabular." }
                },
                "required": ["dataset"]
            }),
        ),
        tool(
            "writ_dataset_search",
            "FAST full-text search over a dataset's records — one dataset (pass 'dataset') or \
             EVERY dataset at once (omit it). Backed by a full-text INDEX, so it's fast and \
             COMPLETE (it doesn't miss older data the way an in-memory scan capped at the recent \
             runs would), and it searches BOTH structured JSON fields AND captured markdown/page \
             text. Query = space-separated keywords, ANDed, case-insensitive, prefix-matched \
             (typing 'amaz stor' finds 'amazon storefront'). Returns matching records newest-first, \
             each tagged with the dataset it came from and a highlighted snippet. Use this to \
             answer 'where did we capture X' / 'find the row mentioning Y' from data Writ already \
             collected, without re-running anything. YOU CHOOSE THE OUTPUT SHAPE via 'format': \
             'markdown' hands you readable prose (a crawl's pages as documents, structured data as \
             a table) — pick it when you want to READ or SUMMARIZE the hits, it costs far fewer \
             tokens than JSON with markdown escaped inside it; 'csv' for a compact table; 'json' \
             (the default) when you need to parse individual fields.",
            json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Space-separated keywords (ANDed, prefix-matched)" },
                    "dataset": { "description": "Optional dataset name or id to scope to; omit to search across all datasets", "type": ["string", "integer"] },
                    "limit": { "type": "integer", "description": "Max matching records to return (default 20, max 200)" },
                    "format": { "type": "string", "enum": ["json", "markdown", "csv"], "description": "Output shape. json (default) = structured records. markdown = READABLE prose — a crawl's pages render as documents, structured data as a table; prefer this when you want to READ/summarize the content rather than parse fields (far fewer tokens than JSON-escaped markdown). csv = compact tabular." },
                },
                "required": ["query"]
            }),
        ),
        tool(
            "writ_set_schedule",
            "Schedule a workflow to run automatically in the background (results accumulate; read \
             them later with writ_workflow_data). kind='interval' needs interval_minutes; \
             kind='daily' needs time (HH:MM) + tz (IANA); kind='weekly' needs time + tz + days \
             (ISO weekdays 1-7); kind='off' disables the schedule.",
            json!({
                "type": "object",
                "properties": {
                    "workflow": { "description": "Workflow name or id", "type": ["string", "integer"] },
                    "kind": { "type": "string", "enum": ["interval", "daily", "weekly", "off"] },
                    "interval_minutes": { "type": "integer" },
                    "time": { "type": "string", "description": "HH:MM, user-local" },
                    "days": { "type": "array", "items": { "type": "integer" }, "description": "ISO weekdays 1 (Mon) – 7 (Sun)" },
                    "tz": { "type": "string", "description": "IANA timezone, e.g. Europe/Paris" },
                },
                "required": ["workflow", "kind"],
            }),
        ),
        tool(
            "writ_create_monitor",
            "Create an enabled local monitor using Writ's existing scheduler. Use when the user asks to watch a URL or selector at an interval. The requested interval is automatically clamped to Writ's safe HTTP/browser minimum. Returns the monitor id for writ_wire_monitor.",
            json!({"type":"object","properties":{
                "url":{"type":"string"},"selector":{"type":"string","description":"CSS selector for content changes; omit for uptime/status monitoring"},
                "interval_minutes":{"type":"integer","minimum":1},
                "requires_browser":{"type":"boolean","description":"Use JS/browser rendering instead of HTTP"},
                "name":{"type":"string"}
            },"required":["url","interval_minutes"]}),
        ),
        tool(
            "writ_wire_monitor",
            "Automatically wire a monitor's change_detected event through Writ Automations. action=notify sends desktop/in-app alerts; action=workflow runs a saved Writ workflow; action=ai_task WAKES WRIT'S LOCAL AI AGENT with a task prompt — on each detected change it opens the monitored page with the change context (diff, changed selector) and works the prompt autonomously (needs an AI provider or the cloud AI gateway in Settings → AI); action=webhook POSTs to a supplied HTTP(S) endpoint (for example a user-run local bridge that queues an external AI process).",
            json!({"type":"object","properties":{
                "monitor_id":{"type":"integer"},"action":{"type":"string","enum":["notify","workflow","ai_task","webhook"]},
                "workflow":{"type":["string","integer"],"description":"Required for action=workflow"},
                "webhook_url":{"type":"string","description":"Required for action=webhook"},
                "prompt":{"type":"string","description":"Required for action=ai_task: what the agent should do when the monitor fires. Supports {{placeholders}} like {{diff_snippet}} and {{selector_name}}"},
                "entry_url":{"type":"string","description":"action=ai_task: page the agent starts on (defaults to the monitored URL)"},
                "max_steps":{"type":"integer","description":"action=ai_task: cap on agent steps per wake (default 20, max 100)"},
                "title":{"type":"string"},"message":{"type":"string"},"name":{"type":"string"}
            },"required":["monitor_id","action"]}),
        ),
        tool(
            "writ_create_automation",
            "Create an automation that runs a saved workflow and/or sends a notification when an EVENT \
             fires. when='workflow_completed' / 'workflow_started' reacts to a source workflow \
             finishing/starting — name it with on_workflow (chain workflow A → run workflow B, or \
             alert on completion). when='change_detected' reacts to a monitor (pass monitor_id from \
             writ_create_monitor) — writ_wire_monitor is the shortcut for that case. Give it something \
             to do with run_workflow and/or notify. Uses Writ's existing local automation runtime.",
            json!({"type":"object","properties":{
                "name":{"type":"string","description":"Automation name"},
                "when":{"type":"string","enum":["workflow_completed","workflow_started","change_detected"],"description":"Event that fires the automation (default workflow_completed)"},
                "on_workflow":{"type":["string","integer"],"description":"Source workflow (name or id) for workflow_* events"},
                "monitor_id":{"type":"integer","description":"Monitor id (from writ_create_monitor) for when=change_detected"},
                "run_workflow":{"type":["string","integer"],"description":"Workflow to RUN when the event fires (name or id)"},
                "notify":{"type":"string","description":"Send a desktop/in-app notification with this message when the event fires"},
                "ai_prompt":{"type":"string","description":"Wake Writ's local AI agent with this task when the event fires (needs an AI provider or the cloud AI gateway in Settings → AI). Supports {{placeholders}}"},
                "ai_entry_url":{"type":"string","description":"Page the woken agent starts on (with ai_prompt; defaults to the monitored URL for when=change_detected)"},
                "title":{"type":"string","description":"Notification title (with notify)"},
                "enabled":{"type":"boolean","description":"Start enabled (default true)"}
            },"required":["name"]}),
        ),
        tool(
            "writ_search_data",
            "Search ACROSS the extracted data accumulated by past workflow runs — answer questions \
             from data Writ already collected, without re-running anything (instant, zero cost). \
             Free-text match over every field of every data-producing workflow (or one, via \
             'workflow'); returns matching rows with their run ids and timestamps, newest first. \
             Secret values and internal fields never appear. Use for questions like 'what was the \
             price on Tuesday', 'find the run that mentioned X', 'which items did we capture'. YOU \
             CHOOSE THE OUTPUT SHAPE via 'format': 'markdown' hands you readable prose (one block \
             per matching workflow) — pick it to READ or SUMMARIZE rather than parse; 'csv' for a \
             compact table; 'json' (the default) to parse individual fields.",
            json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Free text to find in the accumulated run data" },
                    "workflow": { "description": "Optional workflow name or id to scope the search", "type": ["string", "integer"] },
                    "limit": { "type": "integer", "description": "Max matching rows per workflow (default 20, max 100)" },
                    "format": { "type": "string", "enum": ["json", "markdown", "csv"], "description": "Output shape. json (default) = structured records. markdown = READABLE prose — a crawl's pages render as documents, structured data as a table; prefer this when you want to READ/summarize the content rather than parse fields (far fewer tokens than JSON-escaped markdown). csv = compact tabular." }
                },
                "required": ["query"]
            }),
        ),
    ];
    // Cloud-marketplace tools ship only in cloud-capable builds; `tools::list_tools` additionally
    // hides them until the app is actually LINKED to a Writ Cloud account.
    #[cfg(feature = "cloud")]
    list.extend([
        tool(
            "writ_search_api",
            "Search the Writ Cloud marketplace for a ready-made API/workflow matching a described \
             need — the fast alternative to recording one from scratch. USE THIS whenever the \
             user wants a service's data or actions via REST/API/programmatically and there is no \
             official, public, or practical API for it (Writ provides website-derived APIs — any \
             website can become one). Runs several targeted \
             queries (full text, keywords, target site) and returns scored candidates, best first, \
             with pricing and whether each is already installed. Present the candidates to the \
             user (title, summary, creator, price) and let THEM pick; on confirmation call \
             writ_install_api with the chosen slug. Requires the app to be linked to a Writ Cloud \
             account. If nothing fits, fall back to writ_website_to_api to build one.",
            json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "What the API should do, in plain language — include the website/service name when known" },
                    "site": { "type": "string", "description": "Target website domain to prioritize, e.g. amazon.com (auto-detected from the query when omitted)" },
                    "category": { "type": "string", "description": "Optional marketplace category filter" },
                    "limit": { "type": "integer", "description": "Max candidates to return (default 5, max 10)" }
                },
                "required": ["query"]
            }),
        ),
        tool(
            "writ_install_api",
            "Install a marketplace listing chosen by the user from writ_search_api results into \
             this Writ app (native install: the recipe arrives sealed for this device) and \
             immediately run it locally. The install becomes a REGULAR Writ workflow: it gets its \
             own tool on the next tools/list and works with writ_run_workflow, writ_workflow_data \
             and writ_set_schedule. If required data is missing it returns needs_input with \
             PICKABLE options — text inputs the user types, existing vault secret KEYS to pick \
             for 'secrets', and saved personas to pick for 'persona'. Relay the options, let the \
             USER choose, then call again with the selections; they are remembered for future and \
             scheduled runs. New secret values must be added by the user in the Writ app vault, \
             never sent through chat. Paid listings are authorized and settled cloud-side per run; \
             a denied run executes nothing. Set run=false to install without running.",
            json!({
                "type": "object",
                "properties": {
                    "slug": { "type": "string", "description": "Marketplace listing slug from writ_search_api" },
                    "inputs": { "type": "object", "description": "Values for the listing's required input slots" },
                    "secrets": { "type": "object", "description": "Secret-slot picks: {slot: existing vault secret KEY} (names only, never values)" },
                    "persona": { "type": ["string", "integer"], "description": "Persona pick (id or name) for login listings, or \"none\" to run without" },
                    "run": { "type": "boolean", "description": "Run right after install (default true)" }
                },
                "required": ["slug"]
            }),
        ),
    ]);
    list
}

/// One public tool entry.
fn tool(name: &str, description: &str, input_schema: Value) -> Value {
    json!({ "name": name, "description": description, "inputSchema": input_schema })
}

/// Schema for `writ_browser_use` — a general "launch a browser and act" front door.
/// Both fields are optional: the model can start blank and navigate, and it drives from the
/// user's directive rather than a required workflow goal (saving is on-demand, not the point).
fn browser_use_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "goal": { "type": "string", "description": "What to do in the browser, in plain language — the user's directive. Optional; you can also just open a page and drive turn-by-turn." },
            "url": { "type": "string", "description": "Starting URL to open (recommended). Omit to start on a blank page and navigate with writ_browser_act." }
        },
        "required": []
    })
}

fn website_build_schema(goal_description: &str) -> Value {
    json!({
        "type": "object",
        "properties": {
            "goal": { "type": "string", "description": goal_description },
            "url": { "type": "string", "description": "Website URL (recommended when known)" },
            "skip_existing": { "type": "boolean", "description": "API builds first propose the user's OWN matching workflows (replaying is instant and free); set true after the user declined those" },
            "skip_marketplace": { "type": "boolean", "description": "API builds on a cloud-linked app then propose compatible ready-made marketplace APIs; set true to skip that and record fresh (after the user declined, or when they explicitly want their own recording)" },
        },
        "required": ["goal", "url"],
    })
}

/// Dispatch a static tool by name. `None` ⇒ not a static tool (the executor falls through to the
/// workflow-derived catalog). Domain outcomes (mission failed to start, no data yet) come back as
/// NORMAL results with `isError:true` so the model can relay them; malformed arguments are
/// `CallError::BadArgument` (JSON-RPC invalid-params).
pub async fn call(state: &AppState, name: &str, args: &Value) -> Option<Result<Value, CallError>> {
    let r = match name {
        "writ_personas" => personas_tool(state, args).await,
        "writ_browser_use" => connected_browser_start(state, args, false, true).await,
        "writ_build" => connected_browser_start(state, args, false, false).await,
        "writ_record_website" => connected_browser_start(state, args, false, false).await,
        "writ_website_to_api" => connected_browser_start(state, args, true, false).await,
        "writ_crawl_site" => crawl_site(state, args).await,
        "writ_crawl_status" => crawl_status(state, args).await,
        "writ_saved_crawls" => saved_crawls(state, args).await,
        "writ_run_saved_crawl" => run_saved_crawl(state, args).await,
        "writ_saved_crawl_data" => saved_crawl_data(state, args).await,
        "writ_scrape" => scrape(state, args).await,
        "writ_map" => site_map(state, args).await,
        "writ_expose_workflow_api" => expose_workflow_api(state, args).await,
        "writ_browser_act" => connected_browser_act(state, args).await,
        "writ_browser_context" => connected_browser_context(state, args).await,
        "writ_browser_network" => connected_browser_network(state, args).await,
        "writ_browser_save" => connected_browser_save(state, args).await,
        "writ_browser_cancel" => connected_browser_cancel(state, args).await,
        "writ_mission_status" => mission_status(state, args).await,
        "writ_mission_respond" => mission_respond(state, args).await,
        "writ_mission_cancel" => mission_cancel(state, args).await,
        "writ_list_workflows" => list_workflows(state).await,
        "writ_run_workflow" => run_workflow(state, args).await,
        "writ_workflow_data" => workflow_data(state, args).await,
        "writ_workflow_runs" => workflow_runs(state, args).await,
        "writ_list_datasets" => list_datasets(state).await,
        "writ_dataset" => dataset(state, args).await,
        "writ_dataset_search" => dataset_search(state, args).await,
        "writ_set_schedule" => set_schedule(state, args).await,
        "writ_create_monitor" => create_monitor(state, args).await,
        "writ_wire_monitor" => wire_monitor(state, args).await,
        "writ_create_automation" => create_automation(state, args).await,
        "writ_search_data" => search_run_data(state, args).await,
        #[cfg(feature = "cloud")]
        "writ_search_api" => search_api(state, args).await,
        #[cfg(feature = "cloud")]
        "writ_install_api" => install_api(state, args).await,
        _ => return None,
    };
    Some(r)
}

// ── missions ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct ConnectedBrowserSession {
    goal: String,
    name: String,
    entry_url: String,
    api: bool,
    /// True when opened via `writ_browser_use`: a task-oriented "Writ is your browser" session
    /// where completing the user's task is the point and saving a workflow is on-demand (as
    /// opposed to build/record/api sessions whose whole purpose is to produce a saved workflow).
    use_mode: bool,
    steps: Vec<Value>,
    fill_data: HashMap<String, String>,
    secret_refs: HashMap<String, String>,
    functions: Vec<Value>,
    /// Wall-clock ms of the last tool call against this session, for the idle reaper.
    ///
    /// SHARED (`Arc`) rather than a plain field because the act path works on a
    /// `.cloned()` session and re-inserts it when it is done. With a plain i64 that
    /// write-back would restore the timestamp captured at entry, silently undoing
    /// any touch that happened during the call. An Arc cell is written through by
    /// every clone, so the map always holds the newest value.
    last_used_ms: Arc<AtomicI64>,
}

fn connected_sessions() -> &'static Mutex<HashMap<String, ConnectedBrowserSession>> {
    static SESSIONS: OnceLock<Mutex<HashMap<String, ConnectedBrowserSession>>> = OnceLock::new();
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Whether a session last touched at `last_used_ms` is idle past `idle_ms` as of `now_ms`.
///
/// `saturating_sub` matters: these are wall-clock stamps, so an NTP step backwards
/// (or a `now_ms()` that fell back to 0) can put `last_used` in the future.
/// Saturating yields 0 there, i.e. "not idle" — a clock adjustment must never reap
/// a session out from under a client that is actively driving it.
fn is_idle_past(last_used_ms: i64, now_ms: i64, idle_ms: i64) -> bool {
    now_ms.saturating_sub(last_used_ms) > idle_ms
}

/// Mark a connected session as used right now, so the reapers measure idleness
/// rather than age. Every MCP tool that touches a live session calls this.
///
/// Stamps BOTH clocks, because two independent reapers watch this browser and each
/// reads its own:
///
///  * `last_used_ms` here, for the MCP reaper (5-minute TTL); and
///  * `RecordingSession::last_activity`, for `PlaywrightRecorder::start_cleanup_loop`
///    (30-minute TTL). That field is otherwise only stamped by
///    `action_handler::handle_action`, which the MCP act path never calls — so
///    without this an MCP session looks frozen at its open time, and a session a
///    model drove continuously for half an hour would be torn down mid-task.
fn touch_connected_session(state: &AppState, sid: &str) {
    if let Some(sess) = connected_sessions().lock().unwrap().get(sid) {
        sess.last_used_ms.store(now_ms(), Ordering::Relaxed);
    }
    if let Some(recorder) = state.recorder.as_ref() {
        if let Some(mut s) = recorder.get_session_mut(sid) {
            s.last_activity = std::time::Instant::now();
        }
    }
}

/// Start the idle reaper for MCP-opened browser sessions (idempotent — only the
/// first call spawns it).
///
/// Without this an MCP session lived until the app quit. `PlaywrightRecorder`'s own
/// `start_cleanup_loop` does not cover them: it measures `RecordingSession::last_activity`,
/// which only `action_handler::handle_action` stamps, and the MCP act path never goes
/// through it — so to that loop an MCP session looks frozen at its open time.
///
/// This reaper owns BOTH halves of the teardown: the `connected_sessions()` entry
/// (which holds the recorded steps and held fill values) and the underlying recorder
/// session (which holds the real Chromium context). Dropping only the first would
/// leak the browser, which is the whole point of reaping.
pub fn start_connected_session_reaper(
    recorder: Arc<crate::recorder::core::PlaywrightRecorder>,
) {
    static STARTED: OnceLock<()> = OnceLock::new();
    if STARTED.set(()).is_err() {
        return; // already running
    }
    tokio::spawn(async move {
        let idle_ms = crate::config::constants::MCP_SESSION_IDLE_TIMEOUT.as_millis() as i64;
        loop {
            tokio::time::sleep(crate::config::constants::MCP_REAPER_INTERVAL).await;
            let now = now_ms();
            // Collect under the lock, close outside it: `end_session` is async and the
            // registry guard is a std Mutex, which must never be held across an await.
            let stale: Vec<String> = connected_sessions()
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, s)| {
                    is_idle_past(s.last_used_ms.load(Ordering::Relaxed), now, idle_ms)
                })
                .map(|(sid, _)| sid.clone())
                .collect();
            for sid in stale {
                // Re-check under the lock: a call may have landed between the scan and
                // here, which would make this session live again.
                let claimed = {
                    let mut map = connected_sessions().lock().unwrap();
                    match map.get(&sid) {
                        Some(s)
                            if is_idle_past(
                                s.last_used_ms.load(Ordering::Relaxed), now_ms(), idle_ms,
                            ) =>
                        {
                            map.remove(&sid).is_some()
                        }
                        _ => false,
                    }
                };
                if claimed {
                    tracing::warn!(
                        session_id = %sid,
                        "Reaping abandoned MCP browser session (idle past TTL)"
                    );
                    let _ = recorder.end_session(&sid).await;
                }
            }
        }
    });
}

/// OWN-LIBRARY-FIRST proposal for the build tools: before marketplace suggestions — and long
/// before recording — check whether the user ALREADY has workflows matching the goal/site.
/// Replaying an existing workflow is instant and free, so it always outranks installing or
/// rebuilding. Works in every build (no cloud needed). `None` = no match, continue the ladder.
async fn existing_workflow_proposal(
    state: &AppState,
    goal: &str,
    url: &str,
) -> Result<Option<Value>, CallError> {
    let rows = workflows::list(&state.db, true, 1000).await?;
    let matches = match_own_workflows(&rows, goal, url_host(url).as_deref());
    if matches.is_empty() {
        return Ok(None);
    }
    let next = if cfg!(feature = "cloud") {
        "Propose these to the user FIRST — replaying an existing workflow is instant and free. If \
         one fits, run it with writ_run_workflow (missing inputs are elicited) or read its latest \
         results with writ_workflow_data. If none fits, call this build tool again with \
         skip_existing=true — compatible marketplace APIs are proposed next, before recording."
    } else {
        "Propose these to the user FIRST — replaying an existing workflow is instant and free. If \
         one fits, run it with writ_run_workflow (missing inputs are elicited) or read its latest \
         results with writ_workflow_data. If none fits, call this build tool again with \
         skip_existing=true to start recording."
    };
    Ok(Some(text_result(&json!({
        "status": "existing_workflows",
        "message": "The user's own library already has workflows matching this goal — prefer \
                    replaying one over installing or recording anything new.",
        "goal": goal,
        "workflows": matches,
        "next": next,
    }))))
}

/// Pure matcher over the user's saved workflows: an entry-url HOST match qualifies; otherwise most
/// of the goal's distinctive terms must appear in the name/description/entry-url. Conservative so
/// builds are never hijacked by weak matches. Compact projections only — never steps.
fn match_own_workflows(
    rows: &[workflows::Workflow],
    goal: &str,
    host: Option<&str>,
) -> Vec<Value> {
    let terms = goal_terms(goal);
    let mut scored: Vec<(f64, Value)> = rows
        .iter()
        .filter_map(|w| {
            let hay = format!(
                "{} {} {}",
                w.name.to_lowercase(),
                w.description.as_deref().unwrap_or("").to_lowercase(),
                w.entry_url.as_deref().unwrap_or("").to_lowercase()
            );
            let matched = terms.iter().filter(|t| hay.contains(t.as_str())).count();
            let coverage = if terms.is_empty() {
                0.0
            } else {
                matched as f64 / terms.len() as f64
            };
            let host_match = host.is_some_and(|h| {
                w.entry_url
                    .as_deref()
                    .is_some_and(|u| u.to_lowercase().contains(h))
            });
            if !(host_match || (coverage >= 0.6 && matched >= 2)) {
                return None;
            }
            let score = coverage * 3.0 + if host_match { 2.0 } else { 0.0 };
            Some((
                score,
                json!({
                    "id": w.id,
                    "name": w.name,
                    "description": w.description,
                    "tool": if w.connect_surfaces().mcp {
                        Value::String(super::tools::sanitize(&w.name))
                    } else {
                        Value::Null
                    },
                    "marketplace_install": w.marketplace_slug.as_deref().is_some_and(|s| !s.is_empty()),
                    "last_run": w.last_run_status,
                    "has_data": w.last_run_has_extracted_data == Some(1),
                }),
            ))
        })
        .collect();
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    scored.truncate(3);
    scored.into_iter().map(|(_, v)| v).collect()
}

/// Distinctive lowercase terms of a build goal — the own-library twin of the marketplace tokenizer
/// (kept separate + ungated: the library matcher must work in cloud-free builds too). Drops the
/// request-phrasing words ("get X data by rest api") that carry no signal.
fn goal_terms(goal: &str) -> Vec<String> {
    const STOP: [&str; 22] = [
        "the", "and", "for", "that", "this", "with", "from", "api", "apis", "get", "data",
        "rest", "call", "want", "une", "les", "des", "pour", "avec", "que", "qui", "veux",
    ];
    let mut out: Vec<String> = Vec::new();
    for raw in goal.split(|c: char| !(c.is_alphanumeric() || c == '.' || c == '-')) {
        let t = raw.trim_matches(|c| c == '.' || c == '-').to_lowercase();
        if t.len() < 3 || STOP.contains(&t.as_str()) || out.contains(&t) {
            continue;
        }
        out.push(t);
        if out.len() == 6 {
            break;
        }
    }
    out
}

// ── writ_personas — saved sign-in identities, read + operate, never create ───

/// The MCP-facing projection of one shaped persona row: the cross-edition field
/// set the cloud and self-host connectors return, minus anything an agent has no
/// read use for (mailbox/relay plumbing, fingerprint, timestamps of record).
/// Secrets are already absent at the source — `shape()` emits `has_*` booleans.
fn persona_mcp_view(row: &Value) -> Value {
    const ALWAYS: [&str; 7] = [
        "id", "name", "is_active", "twofa_method", "has_password", "has_warm_session",
        "can_self_login",
    ];
    const OPTIONAL: [&str; 14] = [
        "description", "target_domain", "login_username", "email_otp_mode",
        "validation_status", "has_totp_seed", "session_expires_at", "login_workflow_id",
        "login_workflow_name", "last_login_at", "last_login_error", "last_used_at",
        "has_proxy", "linked_workflows",
    ];
    let mut out = serde_json::Map::new();
    for k in ALWAYS {
        out.insert(k.into(), row.get(k).cloned().unwrap_or(Value::Null));
    }
    for k in OPTIONAL {
        match row.get(k) {
            None | Some(Value::Null) => {}
            Some(v) if v.as_array().is_some_and(Vec::is_empty) => {}
            Some(v) => {
                out.insert(k.into(), v.clone());
            }
        }
    }
    Value::Object(out)
}

/// What to do next — the part a connected model gets wrong without guidance:
/// personas are USED via the `persona` argument on the run/crawl/install tools,
/// and they are CREATED only in the Writ app (credentials must never transit MCP).
fn personas_usage_note(rows: &[Value]) -> String {
    if rows.is_empty() {
        return "No personas saved. A persona is a saved sign-in identity (username + \
                credentials sealed on-device, optional 2FA) that lets runs act behind a \
                login. Creating one requires credentials, which never pass through this \
                connection — ask the user to add it in the Writ app on the Personas \
                page, then use it here by id or name."
            .into();
    }
    let stale: Vec<i64> = rows
        .iter()
        .filter(|r| {
            r.get("is_active").and_then(Value::as_bool).unwrap_or(false)
                && !r.get("has_warm_session").and_then(Value::as_bool).unwrap_or(false)
        })
        .filter_map(|r| r.get("id").and_then(Value::as_i64))
        .collect();
    let mut note = String::from(
        "Use a persona by passing `persona` (its id or name) to writ_crawl_site, \
         writ_run_workflow or writ_install_api — the run then acts signed in as that \
         identity, with any 2FA code minted by the daemon. ",
    );
    if !stale.is_empty() {
        note.push_str(&format!(
            "Personas {stale:?} have no warm session right now: action='sign_in' \
             refreshes one that can_self_login; otherwise action='record_login' has \
             the AI record its sign-in once. "
        ));
    }
    note.push_str(
        "Credentials are managed only in the Writ app (Personas page) — this tool \
         cannot create, edit or delete a persona.",
    );
    note
}

/// `writ_personas` — list/get/sign_in/record_login over the LOCAL persona store,
/// riding the same cores as the `/v1/personas` REST surface. Deliberately no
/// create/update/delete: those carry credentials, and no secret may transit the
/// MCP surface in either direction (the same line `tool_executor` draws for the
/// vault). `sign_in`/`record_login` escalate to the `run` capability there.
async fn personas_tool(state: &AppState, args: &Value) -> Result<Value, CallError> {
    use crate::local::api::v1::personas as api;

    let action = args
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("list")
        .trim()
        .to_lowercase();

    // Domain outcomes (unknown persona, vault locked, no AI provider, login
    // already recording) come back in-band so the model can relay and repair;
    // only store/engine failures stay protocol errors.
    fn relay(e: LocalError) -> Result<Value, CallError> {
        match e {
            LocalError::BadRequest(m) | LocalError::NotFound(m) => Ok(err_result(m)),
            other => Err(other.into()),
        }
    }

    if action == "list" {
        let domain = args.get("domain").and_then(Value::as_str);
        let rows = match api::list_shaped(state, domain, 100).await {
            Ok(rows) => rows,
            Err(e) => return relay(e),
        };
        let out: Vec<Value> = rows.iter().map(persona_mcp_view).collect();
        let note = personas_usage_note(&out);
        return Ok(text_result(&json!({
            "personas": out,
            "total": out.len(),
            "next": note,
        })));
    }

    let pid = match args.get("persona_id") {
        Some(v) if !v.is_null() => resolve_persona(state, v).await?,
        _ => {
            return Ok(err_result(format!(
                "action '{action}' needs persona_id (an id or exact name) — find it \
                 with writ_personas action='list'."
            )))
        }
    };

    match action.as_str() {
        "get" => {
            let mut row = match api::get_shaped(state, pid).await {
                Ok(row) => persona_mcp_view(&row),
                Err(e) => return relay(e),
            };
            if args.get("include_runs").and_then(Value::as_bool) == Some(true) {
                let runs = match api::runs_shaped(state, pid, 10).await {
                    Ok(runs) => runs,
                    Err(e) => return relay(e),
                };
                if let Some(obj) = row.as_object_mut() {
                    obj.insert("recent_runs".into(), Value::Array(runs));
                }
            }
            Ok(text_result(&row))
        }
        "sign_in" => {
            let force = args.get("force").and_then(Value::as_bool) == Some(true);
            let mut res = match api::sign_in_core(state, pid, force).await {
                Ok(res) => res,
                Err(e) => return relay(e),
            };
            if res.get("ok").and_then(Value::as_bool) != Some(true) {
                if let Some(obj) = res.as_object_mut() {
                    obj.insert(
                        "next".into(),
                        json!(
                            "The persona is not signed in. If it cannot self-login (no \
                             login workflow), run writ_personas action='record_login' so \
                             the AI records the sign-in once; if the error points at \
                             wrong credentials, the user must fix them in the Writ app \
                             (Personas page)."
                        ),
                    );
                }
            }
            Ok(text_result(&res))
        }
        "record_login" => {
            let login_url = args.get("login_url").and_then(Value::as_str);
            let mut res = match api::record_login_core(state, pid, login_url).await {
                Ok(res) => res,
                Err(e) => return relay(e),
            };
            if let Some(obj) = res.as_object_mut() {
                obj.insert(
                    "next".into(),
                    json!(
                        "A local AI session is signing in as this persona and recording \
                         the flow (credentials stay masked; it never needs you). Poll \
                         writ_personas action='get' for this persona: when \
                         can_self_login turns true the recording became its login \
                         workflow — then action='sign_in' establishes the warm session. \
                         A last_login_error instead means the attempt failed."
                    ),
                );
            }
            Ok(text_result(&res))
        }
        other => Ok(err_result(format!(
            "unknown action '{other}'. Use one of: list, get, sign_in, record_login."
        ))),
    }
}

async fn connected_browser_start(
    state: &AppState,
    args: &Value,
    api: bool,
    use_mode: bool,
) -> Result<Value, CallError> {
    // writ_browser_use is a task-oriented front door: the goal (a directive) is optional and the
    // session is not obligated to produce a saved workflow. The build/record/api tools still
    // require a goal via their schema.
    let goal = if use_mode {
        args.get("goal").and_then(Value::as_str).map(str::trim).unwrap_or("").to_string()
    } else {
        require_str(args, "goal")?
    };
    // Do not trust the connected model to pick the specialized start tool perfectly. Concierge
    // classifies API-builder intent from the user's goal; MCP must do the same so a generic
    // writ_build/writ_record_website call cannot silently downgrade discovery and save api=false.
    // writ_browser_use is an explicit "just use the browser" request — never auto-upgrade it to an
    // API build (that would gate the session behind a done-check the user did not ask for).
    let api = !use_mode && (api || goal_requests_api_builder(&goal));
    // In use-mode a URL is optional — the model may open blank and navigate with writ_browser_act.
    let url = match args
        .get("url")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(u) => u.to_string(),
        None if use_mode => "about:blank".to_string(),
        None => {
            return Err(CallError::BadArgument(
                "missing required 'url' for local browsing".into(),
            ))
        }
    };
    // BUILD LADDER for API intent — cheapest answer first, recording last:
    //   1. the user's OWN saved workflows (instant, free, every build) — skip_existing=true skips;
    //   2. compatible ready-made MARKETPLACE listings (cloud-linked, time-bounded, best-effort —
    //      any failure falls through; never blocks a build) — skip_marketplace=true skips;
    //   3. record a new workflow.
    // Checked BEFORE the browser opens so a declined proposal costs nothing.
    if api && !args.get("skip_existing").and_then(Value::as_bool).unwrap_or(false) {
        if let Some(proposal) = existing_workflow_proposal(state, &goal, &url).await? {
            return Ok(proposal);
        }
    }
    #[cfg(feature = "cloud")]
    if api && !args.get("skip_marketplace").and_then(Value::as_bool).unwrap_or(false) {
        if let Some(proposal) = marketplace_recipe_proposal(state, &goal, &url).await {
            return Ok(proposal);
        }
    }
    // When UNLINKED, the marketplace rung above cannot run — say so instead of silently skipping,
    // so the model TELLS the user that a FREE cloud link unlocks the ready-made marketplace APIs.
    #[cfg(feature = "cloud")]
    let marketplace_note: Value = if api
        && !LinkState::load_or_default(&state.db)
            .await
            .map(|l| l.is_linked())
            .unwrap_or(false)
    {
        json!(
            "Ready-made marketplace APIs were NOT checked for this goal: the app is not linked \
             to a Writ Cloud account. Tell the user that creating/linking a Writ Cloud account \
             is FREE (Writ app → Settings → Account) and unlocks searching and installing \
             ready-made marketplace APIs — then recording may not even be needed."
        )
    } else {
        Value::Null
    };
    #[cfg(not(feature = "cloud"))]
    let marketplace_note = Value::Null;
    let recorder = state.recorder.as_ref().ok_or_else(|| {
        CallError::BadArgument(
            "Writ's local browser is not ready. Open the Writ desktop app and retry.".into(),
        )
    })?;
    let sid = recorder
        .start_session(url.clone(), true, None)
        .await
        .map_err(|e| CallError::BadArgument(format!("could not open local browser: {e}")))?;
    // Always capture passively. Details are NOT pushed into routine MCP responses; the connected AI
    // pulls them only when useful through writ_browser_network. This makes API discovery available
    // even when a generic recording later reveals a backend opportunity, without prompt bloat.
    let handles = recorder.get_session_mut(&sid).and_then(|s| {
        s.event_tx.as_ref().map(|tx| (
            s.context.clone(), s.network_capture.clone(), tx.clone()
        ))
    });
    if let Some((context, capture, event_tx)) = handles {
        crate::local::record::session::attach_recording_network_capture(
            &context, capture, event_tx,
        ).await;
    } else {
        let _ = recorder.end_session(&sid).await;
        return Err(CallError::BadArgument("could not initialize Writ network capture".into()));
    }
    let page = recorder
        .get_session_mut(&sid)
        .map(|s| s.page.clone())
        .ok_or_else(|| CallError::BadArgument("local browser session disappeared".into()))?;
    let name = concise_workflow_name(&goal);
    let session = ConnectedBrowserSession {
        goal,
        name,
        entry_url: url.clone(),
        api,
        use_mode,
        steps: vec![json!({"type":"navigate","enabled":true,"config":{"url":url}})],
        fill_data: HashMap::new(),
        secret_refs: HashMap::new(),
        functions: Vec::new(),
        last_used_ms: Arc::new(AtomicI64::new(now_ms())),
    };
    connected_sessions()
        .lock()
        .unwrap()
        .insert(sid.clone(), session);
    let capture = recorder.get_session_mut(&sid).map(|s| s.network_capture.clone());
    let discovery = crate::local::ai::explorer::connected_discovery_context(
        &page, capture, &HashMap::new(),
        &[json!({"type":"navigate","enabled":true,"config":{"url":url}})], &[],
    ).await;
    let mode = if use_mode {
        "browser_use"
    } else if api {
        "concierge_api_builder"
    } else {
        "concierge_discovery"
    };
    let next = if use_mode {
        "Writ is your browser. Drive the task with writ_browser_act (navigate/click/fill/select/press_key/scroll/evaluate_js/extract/api_call/…). The cleaned DOM returns automatically after navigations and on demand via writ_browser_context(section=page); search captured requests with writ_browser_network. Ask the user in chat for any decision, value, credential, or 2FA code. You do NOT have to save — just finish the task. Only if the user wants to reuse it, call writ_browser_save to store a clean replayable workflow. writ_browser_cancel closes the browser without saving."
    } else if api {
        "Follow the Concierge API-builder contract. Read writ_browser_context(section=explorer) in pages whenever you need the complete desktop policy. Start with the live DOM and capture_network; use list_requests/get_request before defining live-tested callable functions. Save only after the done-check passes."
    } else {
        "Use writ_browser_act until the complete repeatable workflow is recorded. The full desktop explorer policy is available page-by-page through writ_browser_context; then writ_browser_save."
    };
    Ok(text_result(&json!({
        "session_id": sid,
        "status": "browsing",
        "mode": mode,
        "concierge_contract": if api { Value::String(crate::local::ai::concierge::connected_api_builder_contract().into()) } else { Value::Null },
        "marketplace_note": marketplace_note,
        "discovery": discovery,
        "next": next
    })))
}

fn goal_requests_api_builder(goal: &str) -> bool {
    let g = goal.to_ascii_lowercase();
    [
        "website to api", "site to api", "turn this website into an api",
        "turn the website into an api", "transform this website to api",
        "transform the website to api", "build an api", "create an api",
        "make an api", "expose as an api", "expose it as an api",
        "callable api", "api endpoint", "structured api",
    ].iter().any(|needle| g.contains(needle))
}

async fn connected_browser_context(state: &AppState, args: &Value) -> Result<Value, CallError> {
    let sid = require_str(args, "session_id")?;
    let session = connected_sessions().lock().unwrap().get(&sid).cloned()
        .ok_or_else(|| CallError::BadArgument(format!("no connected browser session '{sid}'")))?;
    touch_connected_session(state, &sid);
    let section = args.get("section").and_then(Value::as_str).unwrap_or("page");
    if section == "page" {
        let recorder = state.recorder.as_ref()
            .ok_or_else(|| CallError::BadArgument("Writ's local browser is not ready".into()))?;
        let (page, capture) = recorder.get_session_mut(&sid)
            .map(|s| (s.page.clone(), s.network_capture.clone()))
            .ok_or_else(|| CallError::BadArgument("local browser session is no longer active".into()))?;
        let context = crate::local::ai::explorer::connected_discovery_context(
            &page, Some(capture), &session.fill_data, &session.steps, &session.functions,
        ).await;
        return Ok(text_result(&json!({"session_id":sid,"section":"page","url":page.url(),"page":context})));
    }
    let source = match section {
        "explorer" => crate::local::ai::explorer::connected_explorer_instructions(),
        "concierge_api" => crate::local::ai::concierge::connected_api_builder_contract(),
        _ => return Err(CallError::BadArgument("section must be explorer or concierge_api".into())),
    };
    let chars: Vec<char> = source.chars().collect();
    let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
    let max_chars = args.get("max_chars").and_then(Value::as_u64).unwrap_or(8_000).clamp(1_000, 10_000) as usize;
    let end = offset.saturating_add(max_chars).min(chars.len());
    let content: String = chars.get(offset.min(chars.len())..end).unwrap_or(&[]).iter().collect();
    Ok(text_result(&json!({
        "session_id":sid,"section":section,"offset":offset,"end":end,"total_chars":chars.len(),
        "content":content,"has_more":end < chars.len(),
        "next_offset":if end < chars.len() { Value::from(end) } else { Value::Null }
    })))
}

async fn connected_browser_network(state: &AppState, args: &Value) -> Result<Value, CallError> {
    let sid = require_str(args, "session_id")?;
    let raw_operation = require_str(args, "operation")?;
    let operation = match raw_operation.as_str() { "list" => "search", "get" => "detail", x => x };
    if !matches!(operation, "search" | "detail") {
        return Err(CallError::BadArgument("operation must be search or detail (list/get are aliases)".into()));
    }
    let query = args.get("query").and_then(Value::as_str)
        .or_else(|| args.get("url").and_then(Value::as_str)).unwrap_or("").trim().to_lowercase();
    let method = args.get("method").and_then(Value::as_str).map(|m| m.to_ascii_uppercase());
    let requested_index = args.get("index").and_then(Value::as_u64).map(|v| v as usize);
    let fill_data = connected_sessions().lock().unwrap().get(&sid)
        .map(|s| s.fill_data.clone())
        .ok_or_else(|| CallError::BadArgument(format!("no connected browser session '{sid}'")))?;
    touch_connected_session(state, &sid);
    let recorder = state.recorder.as_ref()
        .ok_or_else(|| CallError::BadArgument("Writ's local browser is not ready".into()))?;
    let capture = recorder.get_session_mut(&sid).map(|s| s.network_capture.clone())
        .ok_or_else(|| CallError::BadArgument("local browser session is no longer active".into()))?;
    let cap = capture.lock().await;
    let calls = cap.get_all_calls();
    let matched: Vec<(usize, &crate::models::network::NetworkCall)> = calls.iter().enumerate().filter(|(_, call)| {
        let searchable = format!("{} {} {} {} {} {}", call.method, call.url,
            call.response_status.map(|s| s.to_string()).unwrap_or_default(),
            call.request_content_type.as_deref().unwrap_or(""),
            call.request_body.as_deref().unwrap_or(""), call.response_body.as_deref().unwrap_or("")).to_lowercase();
        (query.is_empty() || searchable.contains(&query))
            && method.as_ref().map(|m| call.method.eq_ignore_ascii_case(m)).unwrap_or(true)
    }).collect();
    if operation == "search" {
        let summaries: Vec<Value> = matched.iter().rev().take(100).rev().map(|(index, call)| json!({
            "index":index,"method":call.method,"url":call.url,"status":call.response_status,
            "resource_type":call.resource_type,"step":call.step,"triggered_by":call.triggered_by,
            "request_content_type":call.request_content_type,"response_content_type":call.response_content_type,
            "request_body_chars":call.request_body.as_ref().map(|s| s.chars().count()).unwrap_or(0),
            "response_body_chars":call.response_body.as_ref().map(|s| s.chars().count()).unwrap_or(0),
        })).collect();
        return Ok(text_result(&json!({
            "session_id":sid,"operation":"search","captured":calls.len(),"matched":matched.len(),
            "calls":summaries,"next":"Choose the relevant call and invoke writ_browser_network with operation=detail and its index."
        })));
    }
    let (index, call) = if let Some(index) = requested_index {
        calls.get(index).map(|call| (index, call))
            .ok_or_else(|| CallError::BadArgument(format!("network call index {index} does not exist")))?
    } else {
        matched.last().copied().ok_or_else(|| CallError::BadArgument("no matching network call; search first or provide a valid index".into()))?
    };
    let mut detail = serde_json::to_value(call).unwrap_or_else(|_| json!({}));
    scrub_held_values(&mut detail, &fill_data);
    let rendered = detail.to_string();
    let chars: Vec<char> = rendered.chars().collect();
    let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
    let max_chars = args.get("max_chars").and_then(Value::as_u64).unwrap_or(8_000).clamp(1_000, 10_000) as usize;
    let start = offset.min(chars.len());
    let end = start.saturating_add(max_chars).min(chars.len());
    let content: String = chars[start..end].iter().collect();
    let complete = start == 0 && end == chars.len();
    Ok(text_result(&json!({
        "session_id":sid,"operation":"detail","index":index,"matched":matched.len(),
        "offset":start,"end":end,
        "total_chars":chars.len(),
        "network_call":if complete { detail } else { Value::Null },
        "content_page":if complete { Value::Null } else { Value::String(content) },
        "has_more":end < chars.len(),
        "next_offset":if end < chars.len() { Value::from(end) } else { Value::Null },
        "hint":"content is the selected structured NetworkCall JSON. Continue with next_offset only if has_more is true."
    })))
}

async fn connected_browser_act(state: &AppState, args: &Value) -> Result<Value, CallError> {
    let sid = require_str(args, "session_id")?;
    let actions = args
        .get("actions")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| CallError::BadArgument("'actions' must be a non-empty array".into()))?
        .clone();
    let mut session = connected_sessions()
        .lock()
        .unwrap()
        .get(&sid)
        .cloned()
        .ok_or_else(|| CallError::BadArgument(format!("no connected browser session '{sid}'")))?;
    touch_connected_session(state, &sid);
    if let Some(values) = args.get("inputs").and_then(Value::as_object) {
        for (key, value) in values {
            if let Some(value) = value.as_str() {
                session.fill_data.insert(key.clone(), value.to_string());
                session
                    .fill_data
                    .insert(format!("input.{key}"), value.to_string());
            }
        }
    }
    // A connected AI commonly receives a credential in chat and sends it directly on the fill action
    // with `data_key`. Register that value before execution so passive network capture can reveal the
    // resulting auth header/body as a placeholder and api_call/define_function can resolve it live.
    for action in &actions {
        let kind = action.get("type").and_then(Value::as_str)
            .or_else(|| action.get("action").and_then(Value::as_str));
        if kind == Some("fill") {
            if let (Some(key), Some(value)) = (
                action.get("data_key").and_then(Value::as_str),
                action.get("value").and_then(Value::as_str),
            ) {
                if !key.trim().is_empty() && !value.is_empty() {
                    let bare = key.trim().strip_prefix("input.").unwrap_or(key.trim());
                    session.fill_data.insert(bare.to_string(), value.to_string());
                    session.fill_data.insert(format!("input.{bare}"), value.to_string());
                    if sensitive_data_key(bare) {
                        let safe: String = bare.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
                        let prefix: String = sid.chars().take(8).collect();
                        let vault_key = format!("mcp_{prefix}_{}", if safe.is_empty() { "credential" } else { &safe });
                        let encrypted = state.vault.seal_field(
                            value.as_bytes(),
                            &crate::local::api::v1::secrets::value_aad(&vault_key),
                        )?;
                        vault_secrets::upsert(&state.db, &vault_secrets::NewVaultSecret {
                            key: vault_key.clone(), value_encrypted: encrypted,
                            description: Some(format!("Credential captured for connected workflow: {bare}")),
                            category: Some("credentials".into()),
                        }).await?;
                        session.secret_refs.insert(bare.to_string(), vault_key);
                    }
                }
            }
        }
    }
    let recorder = state
        .recorder
        .as_ref()
        .ok_or_else(|| CallError::BadArgument("Writ's local browser is not ready".into()))?;
    let page = recorder
        .get_session_mut(&sid)
        .map(|s| s.page.clone())
        .ok_or_else(|| {
            CallError::BadArgument("local browser session is no longer active".into())
        })?;
    let initial_url = page.url();
    let explicit_page_context = args.get("include_page_context").and_then(Value::as_bool).unwrap_or(false);
    let navigation_action = actions.iter().any(|a| matches!(
        a.get("type").and_then(Value::as_str).or_else(|| a.get("action").and_then(Value::as_str)),
        Some("navigate" | "goto" | "go_back" | "back" | "reload")
    ));
    let record_templates: HashMap<String, String> = session.fill_data.keys().map(|key| {
        let bare = key.strip_prefix("input.").unwrap_or(key);
        let template = session.secret_refs.get(bare)
            .map(|vault_key| format!("{{{{secret:{vault_key}}}}}"))
            .unwrap_or_else(|| format!("{{{{input.{bare}}}}}"));
        (key.clone(), template)
    }).collect();
    let mut results = Vec::new();
    let mut recorded = Vec::new();
    for raw in &actions {
        let mut action = raw.clone();
        if action.get("type").is_none() {
            if let Some(kind) = action.get("action").cloned() {
                action["type"] = kind;
            }
        }
        let kind = action.get("type").and_then(Value::as_str).unwrap_or("").to_string();
        if kind == "fill" {
            if let Some(key) = action.get("data_key").and_then(Value::as_str).map(str::to_string) {
                let bare = key.trim().strip_prefix("input.").unwrap_or(key.trim());
                if !bare.is_empty() {
                    action["value"] = json!(format!("{{{{input.{bare}}}}}"));
                }
            }
        }
        let rejected = connected_action_rejection(&action, &session.fill_data);
        let (message, success, step, data) = if let Some(reason) = rejected {
            (format!("{kind} → REJECTED: {reason}"), false, None, None)
        } else { match kind.as_str() {
            "define_function" => {
                let name = action
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();
                let fn_type = action
                    .get("fn_type")
                    .and_then(Value::as_str)
                    .unwrap_or("script");
                if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    (
                        "define_function → ERROR: invalid name".into(),
                        false,
                        None,
                        None,
                    )
                } else if fn_type == "api" {
                    match crate::local::ai::explorer::run_api_call(
                        &page,
                        &action,
                        &session.fill_data,
                        name,
                    )
                    .await
                    {
                        Ok(value) => {
                            let step = crate::local::ai::explorer::build_api_call_step(
                                &action,
                                name,
                                &record_templates,
                            );
                            upsert_connected_function(
                                &mut session.functions,
                                json!({
                                    "name":name,"type":"api","description":action.get("description"),
                                    "input_variables":action.get("input_variables"),"output_fields":action.get("output_fields"),
                                    "tested":true,"test_sample":compact_tool_value(&value),
                                }),
                            );
                            (
                                format!("define_function {name} (api) → tested live"),
                                true,
                                Some(step),
                                Some(value),
                            )
                        }
                        Err((_, error)) => (
                            format!("define_function {name} → ERROR: {error}"),
                            false,
                            None,
                            None,
                        ),
                    }
                } else {
                    let deliverable = if fn_type == "list" {
                        let row = action.get("row_selector").and_then(Value::as_str).unwrap_or("");
                        let fields = action.get("fields").cloned().unwrap_or_else(|| json!({}));
                        if row.is_empty() || !fields.is_object() {
                            json!({"type":"invalid","variable":name})
                        } else {
                            json!({"type":"evaluate","script":crate::local::ai::explorer::build_list_extract_script(row, &fields),"variable":name})
                        }
                    } else if let Some(selector) = action.get("selector") {
                        json!({"type":"extract","selector":selector,"variable":name})
                    } else {
                        json!({"type":"evaluate","script":action.get("code").or_else(|| action.get("script")).cloned().unwrap_or(Value::Null),"variable":name})
                    };
                    match crate::local::ai::explorer::verify_deliverable(&page, &deliverable).await
                    {
                        Ok((step, _, value)) => {
                            upsert_connected_function(
                                &mut session.functions,
                                json!({
                                    "name":name,"type":if fn_type == "list" {"list"} else if deliverable["type"] == "extract" {"extraction"} else {"script"},
                                    "description":action.get("description"),"input_variables":action.get("input_variables"),
                                    "output_fields":action.get("output_fields"),"tested":true,"test_sample":compact_tool_value(&value),
                                }),
                            );
                            (
                                format!("define_function {name} → tested live"),
                                true,
                                Some(step),
                                Some(value),
                            )
                        }
                        Err(error) => (
                            format!("define_function {name} → ERROR: {error}"),
                            false,
                            None,
                            None,
                        ),
                    }
                }
            }
            "api_call" => {
                let var = action
                    .get("variable")
                    .and_then(Value::as_str)
                    .unwrap_or("api_result");
                match crate::local::ai::explorer::run_api_call(
                    &page,
                    &action,
                    &session.fill_data,
                    var,
                )
                .await
                {
                    Ok(value) => (
                        if session.api {
                            format!("api_call {var} → live probe succeeded (NOT recorded as a callable API function). Now emit define_function with fn_type=api for this capability")
                        } else {
                            format!("api_call {var} → ok")
                        },
                        true,
                        if session.api { None } else { Some(crate::local::ai::explorer::build_api_call_step(
                            &action, var, &record_templates,
                        )) },
                        Some(value),
                    ),
                    Err((_, error)) => (format!("api_call → ERROR: {error}"), false, None, None),
                }
            }
            "login_post" => {
                match crate::local::ai::explorer::run_login_post(&page, &action, &session.fill_data)
                    .await
                {
                    Ok(status) => (
                        format!("login_post → HTTP {status}"),
                        true,
                        Some(crate::local::ai::explorer::build_login_post_step(
                            &action,
                            &record_templates,
                        )),
                        None,
                    ),
                    Err((_, error)) => (format!("login_post → ERROR: {error}"), false, None, None),
                }
            }
            "capture_network" => {
                let _ =
                    crate::browser::navigation::reload(&page, std::time::Duration::from_secs(25))
                        .await;
                let capture = recorder
                    .get_session_mut(&sid)
                    .map(|s| s.network_capture.clone());
                let count = if let Some(capture) = capture {
                    let cap = capture.lock().await;
                    cap.get_all_calls().len()
                } else {
                    0
                };
                (format!("capture_network → reload complete; {count} request(s) captured. Use writ_browser_network search/detail only if needed"), true, None, None)
            }
            _ => {
                let (message, success, step) = crate::local::ai::explorer::execute_explorer_action(
                    &page,
                    &action,
                    &session.fill_data,
                    &record_templates,
                )
                .await;
                (message, success, step, None)
            }
        }};
        // MCP-connected AI actions have the same settle contract as desktop replay: do not expose
        // an intermediate SPA shell or race the next action against XHR/fetch triggered by this one.
        // `wait_for_page_quiet` is Writ's real in-flight-request quiescence poll (the Playwright
        // driver's nominal `networkidle` is only readyState-based here). It is bounded so pages with
        // analytics streams / long polling cannot wedge the connected AI indefinitely.
        crate::browser::navigation::wait_for_page_quiet(
            &page,
            std::time::Duration::from_secs(15),
        )
        .await;
        if let Some(mut step) = step.clone() {
            if kind == "fill" && action.get("data_key").is_some() {
                if let Some(obj) = step.as_object_mut() {
                    obj.insert("_auth_fill".into(), json!(true));
                }
            }
            recorded.push(step);
        }
        results.push(json!({
            "action": kind, "success": success, "message": message,
            "data": data.as_ref().map(compact_tool_value), "recorded": step.is_some(),
        }));
    }
    session.steps.extend(recorded.clone());
    connected_sessions()
        .lock()
        .unwrap()
        .insert(sid.clone(), session.clone());
    let capture = recorder.get_session_mut(&sid).map(|s| s.network_capture.clone());
    let network_request_count = if let Some(capture) = capture {
        capture.lock().await.get_all_calls().len()
    } else { 0 };
    let current_url = page.url();
    let include_page_context = explicit_page_context || navigation_action || current_url != initial_url;
    let page_context = if include_page_context {
        let capture = recorder.get_session_mut(&sid).map(|s| s.network_capture.clone());
        crate::local::ai::explorer::connected_discovery_context(
            &page, capture, &session.fill_data, &session.steps, &session.functions,
        ).await
    } else { Value::Null };
    let mode = if session.use_mode {
        "browser_use"
    } else if session.api {
        "concierge_api_builder"
    } else {
        "concierge_discovery"
    };
    let next = if session.use_mode {
        "Continue the task. The updated DOM is included after navigations; otherwise pull it on demand with writ_browser_context(section=page), and search captured requests with writ_browser_network. Ask the user for anything you need. Saving is optional — call writ_browser_save only if the user wants to reuse this as a workflow, or writ_browser_cancel to close without saving."
    } else if session.api && session.functions.is_empty() {
        "Continue Concierge discovery. Call writ_browser_context(section=page) only when you need the updated DOM; use writ_browser_network only for backend inspection. Do not save until a callable function is live-tested."
    } else {
        "Continue directly when the action result is sufficient. Pull writ_browser_context(section=page) only when the updated page must be inspected."
    };
    Ok(text_result(&json!({
        "session_id": sid,
        "results": results,
        "mode": mode,
        "current_url": current_url,
        "network_request_count": network_request_count,
        "page_context_included": include_page_context,
        "page": page_context,
        "recorded_steps_added": recorded.len(),
        "next": next
    })))
}

async fn connected_browser_save(state: &AppState, args: &Value) -> Result<Value, CallError> {
    let sid = require_str(args, "session_id")?;
    let mut sess = connected_sessions()
        .lock()
        .unwrap()
        .get(&sid)
        .cloned()
        .ok_or_else(|| CallError::BadArgument(format!("no connected browser session '{sid}'")))?;
    touch_connected_session(state, &sid);
    if let Some(name) = args
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        sess.name = name.chars().take(100).collect();
    }
    let has_dom_auth = sess.steps.iter().any(|s| s.get("_auth_fill").and_then(Value::as_bool).unwrap_or(false));
    let has_login_post = sess.steps.iter().any(|s| s.get("type").and_then(Value::as_str) == Some("login_post"));
    let proposal = args.get("optimization").filter(|v| v.is_object());
    if has_dom_auth && !has_login_post && proposal.is_none() {
        return Ok(text_result(&json!({
            "status":"needs_finalization","session_id":sid,
            "reason":"The workflow contains a DOM login. Before saving, try the regular Writ optimization path.",
            "steps":sess.steps.iter().enumerate().map(|(i,s)| step_brief(i, s)).collect::<Vec<_>>(),
            "next":"Steps are summarized; reference them by index. Use writ_browser_network search/detail to inspect the captured authentication sequence and full request payloads. Then call writ_browser_save again with an optimization proposal using the regular substitutions/removals schema. Propose login_post only for a credentials-only request; for CSRF/nonce/SSO/multi-request auth keep the DOM login unless you can express and verify the complete safe request sequence. Writ live-verifies substitutions and preserves original steps on failure."
        })));
    }
    let login_optimization = if let (Some(recorder), Some(proposal)) = (state.recorder.as_ref(), proposal) {
        let handles = recorder.get_session_mut(&sid)
            .map(|s| s.page.clone());
        if let Some(page) = handles {
            let templates: HashMap<String, String> = sess.fill_data.keys().map(|key| {
                let bare = key.strip_prefix("input.").unwrap_or(key);
                let template = sess.secret_refs.get(bare)
                    .map(|vault_key| format!("{{{{secret:{vault_key}}}}}"))
                    .unwrap_or_else(|| format!("{{{{input.{bare}}}}}"));
                (key.clone(), template)
            }).collect();
            let (optimized, changes, warnings, removed) = crate::local::ai::optimize_live::assemble_optimized(
                &page, &sess.steps, proposal, &sess.fill_data, &templates,
            ).await;
            sess.steps = optimized;
            Some(json!({"applied":true,"changes":changes,"warnings":warnings,"removed":removed}))
        } else { None }
    } else { None };
    let before_clean = sess.steps.len();
    dedupe_connected_outputs(&mut sess.steps);
    let all_functions_http = !sess.functions.is_empty() && sess.functions.iter().all(|f| {
        f.get("type").and_then(Value::as_str) == Some("api")
    });
    if sess.api && all_functions_http {
        collapse_http_dominated_workflow(&mut sess.steps);
    } else {
        remove_superseded_dom_login(&mut sess.steps);
    }
    crate::local::ai::explorer::prune_dead_navigations(&mut sess.steps);
    crate::local::ai::explorer::prune_navigates_before_api_only(&mut sess.steps);
    crate::local::ai::explorer::prune_dead_navigations(&mut sess.steps);
    if sess.steps.len() < 2 {
        return Ok(err_result("Nothing replayable was recorded. Continue this browser session with selector-based actions before saving."));
    }
    if sess.api && sess.functions.is_empty() {
        return Ok(err_result("Concierge API-builder done-check failed: no live-tested callable function exists. Continue discovery, inspect DOM/network, and define_function before saving."));
    }
    connected_sessions().lock().unwrap().remove(&sid);
    if let Some(recorder) = state.recorder.as_ref() {
        let _ = recorder.end_session(&sid).await;
    }
    let streaming_config = if sess.api {
        Some(json!({"connect":{"rest":true,"openai":true,"mcp":true}}).to_string())
    } else {
        Some(json!({"connect":{"rest":false,"openai":false,"mcp":true}}).to_string())
    };
    let wf = workflows::insert(
        &state.db,
        &workflows::NewWorkflow {
            name: sess.name,
            description: Some(format!("Recorded by connected AI: {}", sess.goal)),
            workflow_type: Some(if sess.api { "api_recorded" } else { "recorded" }.into()),
            steps: Some(serde_json::to_string(&sess.steps).unwrap_or_else(|_| "[]".into())),
            entry_url: Some(sess.entry_url),
            streaming_config,
            functions: if sess.functions.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&sess.functions).unwrap_or_else(|_| "[]".into()))
            },
            api_functions: if sess.functions.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&sess.functions).unwrap_or_else(|_| "[]".into()))
            },
            ..Default::default()
        },
    )
    .await?;
    Ok(text_result(&json!({
        "status": "saved",
        "workflow_id": wf.id,
        "workflow": wf.name,
        "steps": sess.steps.len(),
        "finalization": {
            "login_post": login_optimization,
            "steps_removed_by_cleanup": before_clean.saturating_sub(sess.steps.len()),
        },
        "visible_in_desktop": true,
        "mcp_tool": super::tools::sanitize(&wf.name),
        "api_enabled": sess.api,
        "next": "Use writ_run_workflow for future requests. Do not rebuild this task when the saved workflow matches."
    })))
}

fn dedupe_connected_outputs(steps: &mut Vec<Value>) {
    let mut seen = std::collections::HashSet::new();
    let mut keep = vec![true; steps.len()];
    for (index, step) in steps.iter().enumerate().rev() {
        let ty = step.get("type").and_then(Value::as_str).unwrap_or("");
        if !matches!(ty, "extract" | "evaluate" | "api_call") { continue; }
        let Some(variable) = step.pointer("/config/variable").and_then(Value::as_str) else { continue };
        if !seen.insert(variable.to_string()) { keep[index] = false; }
    }
    let mut i = 0usize;
    steps.retain(|_| { let yes = keep[i]; i += 1; yes });
}

fn remove_superseded_dom_login(steps: &mut Vec<Value>) {
    if !steps.iter().any(|s| s.get("type").and_then(Value::as_str) == Some("login_post")) {
        return;
    }
    let form = |s: &Value| matches!(s.get("type").and_then(Value::as_str),
        Some("fill" | "select" | "press" | "click" | "check"));
    while let Some(at) = steps.iter().position(|s| s.get("_auth_fill").and_then(Value::as_bool).unwrap_or(false)) {
        let mut lo = at;
        while lo > 0 && form(&steps[lo - 1]) { lo -= 1; }
        let mut hi = at + 1;
        while hi < steps.len() && form(&steps[hi]) { hi += 1; }
        steps.drain(lo..hi);
    }
}

/// A workflow whose complete callable surface is backed by verified request steps no longer needs
/// the discovery browser route. Keep only request/return/wait semantics; dropping navigation, fills,
/// clicks and DOM probes makes it eligible for Writ's fast HTTP lane.
fn collapse_http_dominated_workflow(steps: &mut Vec<Value>) {
    let has_login = steps.iter().any(|s| s.get("type").and_then(Value::as_str) == Some("login_post"));
    let has_api = steps.iter().any(|s| s.get("type").and_then(Value::as_str) == Some("api_call"));
    if !has_api { return; }
    steps.retain(|s| {
        let ty = s.get("type").and_then(Value::as_str).unwrap_or("");
        matches!(ty, "api_call" | "login_post" | "return" | "wait")
            || (!has_login && ty == "navigate")
    });
}

fn upsert_connected_function(functions: &mut Vec<Value>, function: Value) {
    let name = function.get("name").and_then(Value::as_str).unwrap_or("");
    if let Some(pos) = functions
        .iter()
        .position(|f| f.get("name").and_then(Value::as_str) == Some(name))
    {
        functions[pos] = function;
    } else {
        functions.push(function);
    }
}

/// Enforce the same security/discovery boundary that Concierge describes in its prompt. Connected
/// models may inspect DOM structure, but may not read browser credential stores, issue hidden fetches
/// from arbitrary JS, or bake a user-provided secret into an action. Backend discovery goes through
/// capture_network/list_requests/get_request and replayable api_call/define_function actions.
fn connected_action_rejection(action: &Value, fill_data: &HashMap<String, String>) -> Option<String> {
    let kind = action.get("type").and_then(Value::as_str).unwrap_or("");
    if matches!(kind, "evaluate" | "evaluate_js") {
        let script = action.get("script").or_else(|| action.get("code"))
            .and_then(Value::as_str).unwrap_or("").to_ascii_lowercase();
        if ["sessionstorage", "localstorage", "document.cookie"].iter().any(|x| script.contains(x)) {
            return Some("browser credential stores are private. Never read sessionStorage/localStorage/cookies; use captured request placeholders or ask the user in chat".into());
        }
        if ["fetch(", "xmlhttprequest", "navigator.sendbeacon"].iter().any(|x| script.contains(x)) {
            return Some("network calls inside JavaScript bypass Writ discovery and replay safety. Use capture_network → list_requests/get_request, then api_call or define_function(fn_type=api)".into());
        }
    }
    let encoded = action.to_string();
    let templated_fill = kind == "fill" && action.get("data_key").and_then(Value::as_str)
        .map(|s| !s.trim().is_empty()).unwrap_or(false);
    if !templated_fill && fill_data.values().any(|secret| secret.chars().count() >= 6 && encoded.contains(secret)) {
        return Some("a user-provided value was embedded literally. Replace it with {{input.<name>}}; Writ resolves it only for the live test and keeps the recorded workflow templated".into());
    }
    None
}

fn sensitive_data_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase().replace('-', "_");
    ["password", "passwd", "api_key", "apikey", "token", "secret", "credential", "auth_key", "private_key"]
        .iter().any(|part| normalized.contains(part))
}

/// Tool results must teach the model the response shape without copying an unbounded dataset into
/// the MCP conversation. The complete value remains the workflow's live result at replay time.
fn compact_tool_value(value: &Value) -> Value {
    const LIMIT: usize = 6_000;
    let rendered = value.to_string();
    if rendered.chars().count() <= LIMIT {
        return value.clone();
    }
    let preview: String = rendered.chars().take(LIMIT).collect();
    json!({
        "truncated": true,
        "preview": preview,
        "original_chars": rendered.chars().count(),
        "note": "Live test succeeded. The complete dataset is retained by the workflow/run; this MCP preview is bounded."
    })
}

/// One-line step summary for MCP responses. The needs_finalization proposal only references
/// steps by index, so full configs (evaluate scripts, api_call headers/bodies) must not be
/// copied into the connected-AI context — writ_browser_network detail serves the full payloads.
fn step_brief(index: usize, step: &Value) -> Value {
    fn clip(text: &str) -> String {
        if text.chars().count() <= 80 {
            text.into()
        } else {
            let mut short: String = text.chars().take(80).collect();
            short.push('…');
            short
        }
    }
    let mut summary: Vec<String> = Vec::new();
    if let Some(config) = step.get("config").and_then(Value::as_object) {
        for key in ["method", "url", "selector", "variable", "key", "condition", "value"] {
            if let Some(text) = config.get(key).and_then(Value::as_str) {
                summary.push(format!("{key}={}", clip(text)));
            }
        }
        if let Some(script) = config.get("script").and_then(Value::as_str) {
            summary.push(format!("script({} chars)", script.chars().count()));
        }
    }
    let mut brief = json!({
        "index": index,
        "type": step.get("type"),
        "summary": summary.join(" "),
    });
    if step.get("_auth_fill").and_then(Value::as_bool).unwrap_or(false) {
        brief["auth_fill"] = json!(true);
    }
    brief
}

fn scrub_held_values(value: &mut Value, fill_data: &HashMap<String, String>) {
    match value {
        Value::String(text) => {
            let mut pairs: Vec<_> = fill_data.iter().collect();
            pairs.sort_by_key(|(_, secret)| std::cmp::Reverse(secret.len()));
            for (key, secret) in pairs {
                if secret.chars().count() >= 4 && text.contains(secret) {
                    *text = text.replace(secret, &format!("{{{{{key}}}}}"));
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|v| scrub_held_values(v, fill_data)),
        Value::Object(map) => map.values_mut().for_each(|v| scrub_held_values(v, fill_data)),
        _ => {}
    }
}

async fn connected_browser_cancel(state: &AppState, args: &Value) -> Result<Value, CallError> {
    let sid = require_str(args, "session_id")?;
    connected_sessions().lock().unwrap().remove(&sid);
    if let Some(recorder) = state.recorder.as_ref() {
        let _ = recorder.end_session(&sid).await;
    }
    Ok(text_result(&json!({"session_id":sid,"status":"cancelled"})))
}

fn concise_workflow_name(goal: &str) -> String {
    let name: String = goal
        .split_whitespace()
        .take(8)
        .collect::<Vec<_>>()
        .join(" ");
    if name.is_empty() {
        "Recorded website task".into()
    } else {
        name.chars().take(100).collect()
    }
}

async fn expose_workflow_api(state: &AppState, args: &Value) -> Result<Value, CallError> {
    // A cloud Dragnet crawl's dataset is ALREADY a served cloud REST resource (the Workflow Data
    // API) — there's no local workflow to toggle Connect on. Hand back that public endpoint + auth
    // directly instead of failing to resolve a local row.
    #[cfg(feature = "cloud")]
    if let Some(id) = cloud_dataset_id(state, args.get("workflow")).await? {
        return expose_cloud_crawl_dataset(state, id).await;
    }
    let wf = resolve_workflow(state, args.get("workflow")).await?;
    if wf.is_active != 1 {
        return Ok(err_result(format!(
            "workflow '{}' (id {}) is disabled — enable it before exposing an API",
            wf.name, wf.id
        )));
    }
    // venue='cloud' → a PUBLIC Writ Cloud endpoint (push-on-demand), for callers that are NOT on
    // this machine. venue='local' (default) keeps the loopback server behavior unchanged.
    match args.get("venue").and_then(Value::as_str).unwrap_or("local") {
        "local" => {}
        "cloud" => {
            #[cfg(feature = "cloud")]
            return expose_workflow_cloud(state, &wf).await;
            #[cfg(not(feature = "cloud"))]
            return Ok(err_result(
                "This build has no Writ Cloud support — expose the loopback endpoint \
                 (venue='local') and put your own reverse proxy or tunnel in front of it.",
            ));
        }
        other => {
            return Err(CallError::BadArgument(format!(
                "'venue' must be local or cloud, got '{other}'"
            )))
        }
    }
    let surface = args
        .get("surface")
        .and_then(Value::as_str)
        .unwrap_or("rest");
    let (rest, openai) = match surface {
        "rest" => (Some(true), None),
        "openai" => (None, Some(true)),
        "both" => (Some(true), Some(true)),
        _ => {
            return Err(CallError::BadArgument(
                "'surface' must be one of: rest, openai, both".into(),
            ))
        }
    };
    let merged = merge_connect_config(wf.streaming_config.as_deref(), rest, openai, None);
    workflows::update(
        &state.db,
        wf.id,
        &workflows::WorkflowUpdate {
            streaming_config: Some(merged.to_string()),
            ..Default::default()
        },
    )
    .await?;

    let base = format!("http://127.0.0.1:{}", state.config.port);
    let mut endpoints = Vec::new();
    if matches!(surface, "rest" | "both") {
        endpoints.push(json!({
            "style": "rest",
            "method": "POST",
            "url": format!("{base}/v1/workflows/{}/run", wf.id),
            "body": { "inputs": {} },
        }));
    }
    if matches!(surface, "openai" | "both") {
        endpoints.push(json!({
            "style": "openai",
            "method": "POST",
            "base_url": format!("{base}/v1/workflows/{}/v1", wf.id),
            "url": format!("{base}/v1/workflows/{}/v1/chat/completions", wf.id),
        }));
    }
    // COMPLETE instructions: the loopback endpoint only serves THIS machine — always say how to
    // get a public one, so the model never improvises tunnels or invents UI steps.
    #[cfg(feature = "cloud")]
    let cloud_hint: Value = {
        let linked = LinkState::load_or_default(&state.db)
            .await
            .map(|l| l.is_linked())
            .unwrap_or(false);
        json!({
            "linked": linked,
            "hint": if linked {
                "This endpoint is LOOPBACK-ONLY (works only on this machine). If the caller/app \
                 runs anywhere else, call writ_expose_workflow_api again with venue='cloud' — it \
                 returns a public Writ Cloud HTTPS endpoint, pushing the workflow to the cloud \
                 first when needed."
            } else {
                "This endpoint is LOOPBACK-ONLY (works only on this machine). For a public HTTPS \
                 endpoint, tell the user: linking a Writ Cloud account is FREE (Writ app → \
                 Settings → Account); afterwards call writ_expose_workflow_api with venue='cloud'."
            },
        })
    };
    #[cfg(not(feature = "cloud"))]
    let cloud_hint = Value::Null;
    Ok(text_result(&json!({
        "workflow_id": wf.id,
        "workflow": wf.name,
        "server": { "managed_by": "writ-agentd", "base_url": base, "scope": "loopback" },
        "endpoints": endpoints,
        "authentication": {
            "scheme": "Bearer",
            "next": "In the Writ app open Connect for this workflow and mint a run-scoped local API key. The raw key is shown once and must be copied directly by the user; it is never sent through Claude/MCP. Call with Authorization: Bearer <wlk_key>."
        },
        "remote_access": cloud_hint,
        "verification": "After the user has minted a key, call the endpoint from an authorized local client. Use writ_run_workflow now to verify the workflow itself without exposing the key."
    })))
}

/// `writ_expose_workflow_api` with venue='cloud' — the PUBLIC endpoint story. An installed
/// marketplace listing already has a cloud-runnable proxy (by slug). A local workflow is exposed
/// through its cloud TWIN: reuse the sync mapping when one exists, otherwise PUSH the workflow now
/// (the existing granular sync-push lane; bodies are SECRET-STRIPPED — credential values never
/// leave the vault). Returns the concrete endpoint so the model shows it DIRECTLY.
#[cfg(feature = "cloud")]
async fn expose_workflow_cloud(
    state: &AppState,
    wf: &workflows::Workflow,
) -> Result<Value, CallError> {
    use crate::local::cloud::{client::CloudClient, sync};
    use crate::local::store::cloud_sync_map;

    let link = LinkState::load_or_default(&state.db).await?;
    if !link.is_linked() {
        return Ok(err_result(NOT_LINKED_MSG));
    }
    let base = CloudClient::resolve_base_url(Some(&link));
    let auth = "Authorization: Bearer <Writ Cloud API key>. The user mints one in the Writ Cloud \
                dashboard (Settings → API Keys) — the raw key is shown once and is never sent \
                through Claude/MCP.";

    // Installed marketplace listing → its consumer proxy is already runnable IN the cloud by slug.
    if let Some(slug) = wf.marketplace_slug.as_deref().filter(|s| !s.is_empty()) {
        let url = format!("{base}/api/marketplace/listings/{slug}/run");
        return Ok(text_result(&json!({
            "status": "cloud_endpoint",
            "workflow": wf.name,
            "venue": "cloud",
            "endpoint": { "method": "POST", "url": url, "body": { "inputs": {} } },
            "authentication": auth,
            "note": "Installed marketplace listing: the CLOUD executes it (billed per the \
                     listing's pricing) — this device does not need to stay online. Show the user \
                     this endpoint directly.",
        })));
    }

    // Regular workflow → reuse the existing cloud twin, else push it now.
    let existing =
        cloud_sync_map::get_by_local_id(&state.db, sync::ENTITY_WORKFLOW, wf.id).await?;
    let (cloud_id, pushed_now) = match existing {
        Some(m) => (m.cloud_id, false),
        None => {
            let res = sync::push(&state.db, &link, sync::ENTITY_WORKFLOW, &[wf.id]).await;
            match res.pushed.into_iter().next() {
                Some(p) => (p.cloud_id, true),
                None => {
                    let reason = res
                        .skipped
                        .first()
                        .map(|s| s.reason.clone())
                        .unwrap_or_else(|| "push failed".into());
                    return Ok(err_result(format!(
                        "Could not push '{}' to the Writ Cloud: {reason}",
                        wf.name
                    )));
                }
            }
        }
    };
    let uses_local_secrets =
        wf.steps.contains("{{secret:") || wf.steps.contains("{{vault:");
    let url = format!("{base}/api/automation/workflows/{cloud_id}/run");
    Ok(text_result(&json!({
        "status": "cloud_endpoint",
        "workflow": wf.name,
        "venue": "cloud",
        "cloud_workflow_id": cloud_id,
        "pushed_now": pushed_now,
        "endpoint": { "method": "POST", "url": url, "body": { "inputs": {} } },
        "authentication": auth,
        "example": format!(
            "curl -X POST {url} -H 'Authorization: Bearer <key>' -H 'Content-Type: application/json' -d '{{\"inputs\":{{}}}}'"
        ),
        "note": if uses_local_secrets {
            "The cloud runs this workflow on Writ's fleet — this device can be offline. IMPORTANT: \
             vault secret VALUES are never pushed; the user must attach cloud-side secrets to the \
             pushed workflow (Writ Cloud → workflow → credentials) before cloud runs will succeed."
        } else {
            "The cloud runs this workflow on Writ's fleet — this device does not need to stay \
             online. Show the user this endpoint directly."
        },
    })))
}

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
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    for (name, enabled) in [("rest", rest), ("openai", openai), ("mcp", mcp)] {
        if let Some(enabled) = enabled {
            connect.insert(name.into(), json!(enabled));
        }
    }
    root.insert("connect".into(), Value::Object(connect));
    Value::Object(root)
}

async fn mission_status(state: &AppState, args: &Value) -> Result<Value, CallError> {
    let id = require_i64(args, "session_id")?;
    let sess = concierge_sessions::get_by_id(&state.db, id)
        .await?
        .ok_or_else(|| CallError::BadArgument(format!("no mission with session_id {id}")))?;

    let awaiting = sess.status == "awaiting_input";
    let questions: Vec<Value> = pending_requests(&sess)
        .iter()
        .map(|r| {
            let secret = r.get("kind").and_then(Value::as_str) == Some("secret");
            json!({
                "field": r.get("field").cloned().unwrap_or(Value::Null),
                "kind": r.get("kind").cloned().unwrap_or(Value::Null),
                "label": r.get("label").or_else(|| r.get("question")).cloned().unwrap_or(Value::Null),
                "options": r.get("options").cloned().unwrap_or(Value::Null),
                "secret": secret,
            })
        })
        .collect();

    let mut out = json!({
        "session_id": sess.id,
        "status": sess.status,
        "phase": sess.phase,
        "progress": sess.progress_message,
        "turn_seq": sess.turn_seq,
        "resources": decode_obj(sess.resources.as_deref()),
        "error": sess.error_message,
    });
    if awaiting {
        out["questions"] = Value::Array(questions);
        out["next"] = json!(
            "Ask the user these questions, then call writ_mission_respond with {session_id, \
             turn_seq, answers}. Questions with secret:true must be answered by the user IN THE \
             WRIT APP (Assistant → this mission) — never collect or send credentials here."
        );
    } else if matches!(sess.status.as_str(), "done" | "armed") {
        out["next"] = json!(
            "Mission finished. Run created workflows with writ_run_workflow (see resources for \
             ids), read data with writ_workflow_data, or schedule with writ_set_schedule. Newly \
             created workflows also appear as dedicated tools on the next tools/list."
        );
    }
    Ok(text_result(&out))
}

async fn mission_respond(state: &AppState, args: &Value) -> Result<Value, CallError> {
    let id = require_i64(args, "session_id")?;
    let turn_seq = require_i64(args, "turn_seq")?;
    let answers = args
        .get("answers")
        .cloned()
        .filter(Value::is_object)
        .ok_or_else(|| {
            CallError::BadArgument("'answers' must be an object of field → value".into())
        })?;

    // Refuse any answer that targets a secret-kind question — credentials never transit MCP.
    if let Some(sess) = concierge_sessions::get_by_id(&state.db, id).await? {
        let secret_fields: Vec<String> = pending_requests(&sess)
            .iter()
            .filter(|r| r.get("kind").and_then(Value::as_str) == Some("secret"))
            .filter_map(|r| r.get("field").and_then(Value::as_str).map(str::to_string))
            .collect();
        if let Some(hit) = secret_fields
            .iter()
            .find(|f| answers.get(f.as_str()).is_some())
        {
            return Ok(err_result(format!(
                "'{hit}' is a credential — for security it can only be entered by the user in the \
                 Writ app (Assistant → this mission), not through this connection. Answer the \
                 other questions here if any remain."
            )));
        }
    }

    let body = RespondBody {
        turn_seq,
        answers,
        ..Default::default()
    };
    match ai_concierge::respond_core(state, id, body).await {
        Ok(v) => Ok(text_result(&json!({
            "session_id": v["session_id"],
            "status": v["status"],
            "turn_seq": v["turn_seq"],
            "next": "Mission resumed — keep polling writ_mission_status.",
        }))),
        // Wrong state / stale turn_seq: a normal outcome the model should react to (re-poll).
        Err(RespondFailure::Conflict { message, .. }) => Ok(err_result(format!(
            "{message}. Call writ_mission_status and retry with the current turn_seq."
        ))),
        Err(RespondFailure::Local(LocalError::NotFound(m))) => Err(CallError::BadArgument(m)),
        Err(RespondFailure::Local(e)) => Err(CallError::Internal(e)),
    }
}

async fn mission_cancel(state: &AppState, args: &Value) -> Result<Value, CallError> {
    let id = require_i64(args, "session_id")?;
    match ai_concierge::cancel_core(state, id).await {
        Ok(v) => Ok(text_result(&v)),
        Err(LocalError::NotFound(m)) => Err(CallError::BadArgument(m)),
        Err(e) => Err(CallError::Internal(e)),
    }
}

// ── workflows ────────────────────────────────────────────────────────────────

async fn list_workflows(state: &AppState) -> Result<Value, CallError> {
    let rows = workflows::list(&state.db, false, 200).await?;
    let items: Vec<Value> = rows
        .iter()
        .map(|w| {
            let surfaces = w.connect_surfaces();
            json!({
                "id": w.id,
                "name": w.name,
                "description": w.description,
                "active": w.is_active == 1,
                "mcp_tool": if w.is_active == 1 && surfaces.mcp {
                    Value::String(super::tools::sanitize(&w.name))
                } else {
                    Value::Null
                },
                "schedule": schedule_view(w),
                "last_run": { "status": w.last_run_status, "at": w.last_run_at },
                "has_data": w.last_run_has_extracted_data == Some(1),
            })
        })
        .collect();
    Ok(text_result(&json!({
        "workflows": items,
        "note": "Run with writ_run_workflow, read results with writ_workflow_data, schedule with \
                 writ_set_schedule. mcp_tool null means the workflow is inactive or its Connect → \
                 MCP surface is off.",
    })))
}

async fn run_workflow(state: &AppState, args: &Value) -> Result<Value, CallError> {
    let wf = resolve_workflow(state, args.get("workflow")).await?;
    if wf.is_active != 1 {
        return Ok(err_result(format!(
            "workflow '{}' (id {}) is disabled — enable it in Writ first",
            wf.name, wf.id
        )));
    }
    if !wf.connect_surfaces().mcp {
        return Ok(err_result(format!(
            "workflow '{}' (id {}) has its MCP surface turned off (Connect tab in Writ)",
            wf.name, wf.id
        )));
    }
    let mut inputs = args.get("inputs").cloned().unwrap_or_else(|| json!({}));
    if !inputs.is_object() {
        return Err(CallError::BadArgument(
            "'inputs' must be a JSON object".into(),
        ));
    }
    // `max_age` and `persona` are top-level controls on this tool but the runner reads them alongside
    // the inputs (it is the shared entry point for the derived per-workflow tools, which take these
    // inline). Carry them through; the runner strips each before the values reach the workflow —
    // `persona` becomes the run-as identity, not an `{{input.persona}}` value.
    if let Some(obj) = inputs.as_object_mut() {
        if let Some(requested) = args.get(super::tool_executor::FRESHNESS_ARG) {
            obj.insert(super::tool_executor::FRESHNESS_ARG.to_string(), requested.clone());
        }
        if let Some(persona) = args.get("persona").filter(|v| !v.is_null()) {
            obj.insert("persona".to_string(), persona.clone());
        }
    }
    super::tool_executor::run_workflow_tool(state, wf.id, inputs).await
}

async fn workflow_data(state: &AppState, args: &Value) -> Result<Value, CallError> {
    let fmt = mcp_format(args)?;
    // A cloud Dragnet crawl aggregates its pages under a synthetic per-crawl workflow that lives on
    // the fleet — its `workflow_id` (returned by writ_crawl_site/status) has NO local row. When the
    // named workflow is a numeric id absent locally AND a cloud account is linked, it's that cloud
    // dataset, so forward the read to the fleet's Workflow Data API and hand the pages straight back.
    #[cfg(feature = "cloud")]
    if let Some(id) = cloud_dataset_id(state, args.get("workflow")).await? {
        return cloud_crawl_data(state, id, args, &fmt).await;
    }
    let wf = resolve_workflow(state, args.get("workflow")).await?;
    // run_id → ONE specific run's data (works for failed runs too — their partial payload and
    // error are part of the answer). The run must belong to the resolved workflow.
    if let Some(run_id) = args.get("run_id").and_then(Value::as_i64) {
        let run = runs::get_by_id(&state.db, run_id)
            .await?
            .filter(|r| r.workflow_id == Some(wf.id))
            .ok_or_else(|| {
                CallError::BadArgument(format!(
                    "run {run_id} does not exist or does not belong to workflow '{}'",
                    wf.name
                ))
            })?;
        let data = run
            .result_data
            .as_deref()
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
            .and_then(|v| v.get("extracted_data").cloned())
            .unwrap_or(Value::Null);
        return Ok(text_result(&json!({
            "workflow": wf.name,
            "run_id": run.id,
            "status": run.status,
            "success": run.success.map(|s| s == 1),
            "run_at": run.completed_at.clone().unwrap_or_else(|| run.created_at.clone()),
            "error": run.error_message,
            "data": data,
        })));
    }
    let n = args
        .get("runs")
        .and_then(Value::as_i64)
        .unwrap_or(1)
        .clamp(1, 20) as usize;
    let (inputs, _truncated) = data::scan_workflow_data_runs_pool(&state.db, wf.id).await?;
    if inputs.is_empty() {
        return Ok(err_result(format!(
            "no successful runs with extracted data yet for '{}' — run it with writ_run_workflow \
             or wait for its schedule",
            wf.name
        )));
    }
    // markdown/csv: flatten the same runs into the shared (columns, rows) table and
    // render. This is the big one for agents — a crawl's pages come back as readable
    // documents instead of `extracted_data` JSON blobs full of escaped markdown.
    if fmt != "json" {
        let taken: Vec<_> = inputs.iter().take(n).cloned().collect();
        let declared = data::declared_output_fields(&wf);
        let (columns, rows) = crate::local::data_query::flatten(&taken, &declared, true);
        let body = if fmt == "csv" {
            crate::local::data_query::to_csv(&columns, &rows)
        } else {
            crate::local::data_query::to_markdown(&columns, &rows, Some(&wf.name))
        };
        return Ok(raw_text_result(body));
    }
    let runs_out: Vec<Value> = inputs
        .iter()
        .take(n)
        .map(|ri| {
            json!({
                "run_id": ri.run_id,
                "run_at": ri.run_at,
                "data": ri.result_data.get("extracted_data").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();
    Ok(text_result(
        &json!({ "workflow": wf.name, "runs": runs_out }),
    ))
}

async fn workflow_runs(state: &AppState, args: &Value) -> Result<Value, CallError> {
    let limit = args
        .get("limit")
        .and_then(Value::as_i64)
        .unwrap_or(10)
        .clamp(1, 50);
    // No 'workflow' → the latest runs across ALL workflows (a feed), each tagged with its
    // workflow name so the model can drill in with writ_workflow_data { workflow, run_id }.
    let workflow_arg = args.get("workflow").filter(|v| !v.is_null());
    // A cloud Dragnet crawl's runs live on the fleet, not this db — forward the run index there.
    #[cfg(feature = "cloud")]
    if let Some(id) = cloud_dataset_id(state, workflow_arg).await? {
        return cloud_crawl_runs(state, id).await;
    }
    if workflow_arg.is_none() {
        let rows = runs::list(&state.db, limit).await?;
        let ids: Vec<i64> = rows.iter().filter_map(|r| r.workflow_id).collect();
        let names: HashMap<i64, String> = workflows::names_and_types(&state.db, &ids)
            .await?
            .into_iter()
            .map(|(id, name, _, _)| (id, name))
            .collect();
        let items: Vec<Value> = rows
            .iter()
            .map(|r| {
                json!({
                    "run_id": r.id,
                    "workflow_id": r.workflow_id,
                    "workflow": r.workflow_id.and_then(|id| names.get(&id).cloned()),
                    "status": r.status,
                    "success": r.success.map(|s| s == 1),
                    "error": r.error_message,
                    "duration_ms": r.duration_ms,
                    "at": r.completed_at.clone().unwrap_or_else(|| r.created_at.clone()),
                })
            })
            .collect();
        return Ok(text_result(&json!({
            "runs": items,
            "note": "Latest runs across all workflows. Read a run's data with writ_workflow_data \
                     { workflow, run_id }; search accumulated data with writ_search_data.",
        })));
    }
    let wf = resolve_workflow(state, workflow_arg).await?;
    let rows = runs::list_by_workflow(&state.db, wf.id, limit).await?;
    let items: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "run_id": r.id,
                "status": r.status,
                "success": r.success.map(|s| s == 1),
                "error": r.error_message,
                "duration_ms": r.duration_ms,
                "at": r.completed_at.clone().unwrap_or_else(|| r.created_at.clone()),
            })
        })
        .collect();
    Ok(text_result(&json!({ "workflow": wf.name, "runs": items })))
}

/// `writ_search_data` — free-text search ACROSS the extracted data accumulated by past runs.
/// Reuses the Data page's pure query engine (`data_query`), including its SECURITY-CRITICAL
/// redaction: the internal envelope and secret-shaped run inputs can never surface in a row.
/// `writ_list_datasets` — enumerate every data-bearing source as a dataset. Mirrors the Data
/// explorer picker: local workflows whose runs produced ≥1 row, plus (when cloud-linked) forwarded
/// Dragnet crawl datasets that collected pages. `source_type` tags crawl vs workflow.
async fn list_datasets(state: &AppState) -> Result<Value, CallError> {
    let mut out: Vec<Value> = Vec::new();
    for wf in workflows::list(&state.db, false, 200).await? {
        let (runs, _truncated) = data::scan_workflow_data_runs_pool(&state.db, wf.id).await?;
        if runs.is_empty() {
            continue;
        }
        let last = runs.iter().filter_map(|r| r.run_at.clone()).max();
        out.push(json!({
            "id": wf.id,
            "name": wf.name,
            "source_type": if wf.workflow_type == "crawl" { "crawl" } else { "workflow" },
            "run_count": runs.len(),
            "last_updated": last,
            "origin": "local",
        }));
    }
    // Linked desktop: a Dragnet crawl's dataset lives on the fleet — merge those in so the model
    // sees the same datasets the Outputs picker does. Best-effort: a cloud hiccup never blanks the
    // local list.
    #[cfg(feature = "cloud")]
    if crate::local::cloud::crawl::is_linked(&state.db).await {
        if let Ok(listing) = crate::local::cloud::crawl::list(&state.db, 100).await {
            let crawls = listing
                .get("crawls")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            for c in crawls {
                let dwid = c
                    .get("data_workflow_id")
                    .and_then(|v| v.as_i64())
                    .or_else(|| c.get("workflow_id").and_then(|v| v.as_i64()));
                let Some(dwid) = dwid else { continue };
                let records = c.get("records_total").and_then(|v| v.as_i64()).unwrap_or(0);
                let done = c.get("pages_done").and_then(|v| v.as_i64()).unwrap_or(0);
                if records <= 0 && done <= 0 {
                    continue;
                }
                out.push(json!({
                    "id": dwid,
                    "name": c.get("name").and_then(|v| v.as_str()).unwrap_or("Crawl"),
                    "source_type": "crawl",
                    "run_count": 1,
                    "last_updated": c.get("completed_at").and_then(|v| v.as_str())
                        .or_else(|| c.get("created_at").and_then(|v| v.as_str())),
                    "origin": "cloud",
                }));
            }
        }
    }
    if out.is_empty() {
        return Ok(err_result(
            "no datasets yet — run a workflow (writ_run_workflow) or crawl a site \
             (writ_crawl_site) to accumulate data, then list again",
        ));
    }
    Ok(text_result(&json!({
        "datasets": out,
        "note": "Read a dataset's rows with writ_dataset { dataset, query, limit }; search across \
                 every dataset with writ_search_data.",
    })))
}

/// `writ_dataset` — query one dataset's accumulated records as a single flat, filterable table.
async fn dataset(state: &AppState, args: &Value) -> Result<Value, CallError> {
    let fmt = mcp_format(args)?;
    // A linked cloud Dragnet crawl dataset lives on the fleet — read its table there.
    #[cfg(feature = "cloud")]
    if let Some(id) = cloud_dataset_id(state, args.get("dataset")).await? {
        return cloud_crawl_data(state, id, args, &fmt).await;
    }
    let wf = resolve_workflow(state, args.get("dataset")).await?;
    let (runs, truncated) = data::scan_workflow_data_runs_pool(&state.db, wf.id).await?;
    if runs.is_empty() {
        return Ok(err_result(format!(
            "dataset '{}' has no accumulated data yet — run it with writ_run_workflow or wait for \
             its schedule",
            wf.name
        )));
    }
    let declared = data::declared_output_fields(&wf);
    let limit = args
        .get("limit")
        .and_then(Value::as_i64)
        .unwrap_or(50)
        .clamp(1, 500) as usize;
    let query = args.get("query").and_then(Value::as_str).map(str::to_string);
    let table = crate::local::data_query::build_table(
        &runs,
        &declared,
        &crate::local::data_query::TableQuery {
            q: query,
            col_filters: std::collections::BTreeMap::new(),
            filters: Vec::new(),
            sort_by: None,
            sort_dir: "desc".into(),
            offset: 0,
            limit: Some(limit),
        },
        false,
    );
    // markdown/csv reuse the SAME renderers the REST `?format=` serves, so a tool
    // call and a REST read of the same dataset agree.
    if fmt != "json" {
        let body = if fmt == "csv" {
            crate::local::data_query::to_csv(&table.columns, &table.rows)
        } else {
            crate::local::data_query::to_markdown(&table.columns, &table.rows, Some(&wf.name))
        };
        return Ok(raw_text_result(body));
    }
    Ok(text_result(&json!({
        "dataset": wf.name,
        "dataset_id": wf.id,
        "source_type": if wf.workflow_type == "crawl" { "crawl" } else { "workflow" },
        "columns": table.columns,
        "total": table.total,
        "truncated_scan": truncated,
        "records": crate::local::data_query::rows_to_json(&table.rows, &table.columns),
    })))
}

/// `writ_dataset_search` — fast full-text search over one dataset (or all). Serves the SAME
/// results as the `/v1/datasets/search[/:id]` REST route (shared `run_dataset_search`).
async fn dataset_search(state: &AppState, args: &Value) -> Result<Value, CallError> {
    let query = require_str(args, "query")?;
    let fmt = mcp_format(args)?;
    let limit = args
        .get("limit")
        .and_then(Value::as_i64)
        .unwrap_or(20)
        .clamp(1, 200) as usize;
    let dataset_arg = args.get("dataset").filter(|v| !v.is_null());
    let workflow_id = match dataset_arg {
        None => None,
        Some(v) => {
            // A cloud crawl dataset lives on the fleet — search its copy there (server-side q).
            #[cfg(feature = "cloud")]
            if let Some(id) = cloud_dataset_id(state, Some(v)).await? {
                return cloud_crawl_search(state, id, &query, limit, &fmt).await;
            }
            Some(resolve_workflow(state, Some(v)).await?.id)
        }
    };
    let value =
        crate::local::api::v1::data::run_dataset_search(state, workflow_id, &query, limit, 0).await?;
    Ok(render_mcp(&value, &fmt, "results", &format!("Search: {query}")))
}

async fn search_run_data(state: &AppState, args: &Value) -> Result<Value, CallError> {
    let query = require_str(args, "query")?;
    let fmt = mcp_format(args)?;
    let limit = args
        .get("limit")
        .and_then(Value::as_i64)
        .unwrap_or(20)
        .clamp(1, 100) as usize;
    let workflow_arg = args.get("workflow").filter(|v| !v.is_null());
    // Scoped to a cloud Dragnet crawl dataset → search the fleet's copy (server-side `q`), since
    // those pages never landed in this local db.
    #[cfg(feature = "cloud")]
    if let Some(id) = cloud_dataset_id(state, workflow_arg).await? {
        return cloud_crawl_search(state, id, &query, limit, &fmt).await;
    }
    let scoped = match workflow_arg {
        Some(v) => Some(resolve_workflow(state, Some(v)).await?),
        None => None,
    };
    // Candidate set: the scoped workflow, or every workflow that actually HAS extracted data
    // (the store's precomputed flag keeps this cheap), bounded.
    let candidates: Vec<workflows::Workflow> = match scoped {
        Some(wf) => vec![wf],
        None => workflows::list(&state.db, false, 1000)
            .await?
            .into_iter()
            .filter(|w| w.last_run_has_extracted_data == Some(1))
            .take(50)
            .collect(),
    };

    let mut sections: Vec<Value> = Vec::new();
    // Per-workflow rendered blocks, used only when `format` is markdown/csv.
    let mut rendered: Vec<String> = Vec::new();
    let mut total_matches = 0usize;
    for wf in &candidates {
        let (inputs, truncated) = data::scan_workflow_data_runs_pool(&state.db, wf.id).await?;
        if inputs.is_empty() {
            continue;
        }
        let declared = data::declared_output_fields(wf);
        let table = crate::local::data_query::build_table(
            &inputs,
            &declared,
            &crate::local::data_query::TableQuery {
                q: Some(query.clone()),
                col_filters: std::collections::BTreeMap::new(),
                filters: Vec::new(),
                sort_by: None,
                sort_dir: "desc".into(),
                offset: 0,
                limit: Some(limit),
            },
            true,
        );
        if table.total == 0 {
            continue;
        }
        total_matches += table.total;
        // A non-json format renders each matching workflow as its own block (their
        // columns differ, so one flat table across workflows would be meaningless)
        // and the blocks are concatenated below.
        if fmt != "json" {
            let title = format!("{} (#{})", wf.name, wf.id);
            rendered.push(if fmt == "csv" {
                format!(
                    "# {title}\n{}",
                    crate::local::data_query::to_csv(&table.columns, &table.rows)
                )
            } else {
                crate::local::data_query::to_markdown(&table.columns, &table.rows, Some(&title))
            });
        }
        sections.push(json!({
            "workflow": wf.name,
            "workflow_id": wf.id,
            "matches": table.total,
            "truncated_scan": truncated,
            "rows": crate::local::data_query::rows_to_json(&table.rows, &table.columns),
        }));
    }

    if sections.is_empty() {
        return Ok(text_result(&json!({
            "status": "no_matches",
            "query": query,
            "next": "Nothing in the accumulated run data matched. Broaden the query, see what \
                     exists with writ_list_workflows / writ_workflow_data, or run the workflow to \
                     produce fresh data.",
        })));
    }
    if fmt != "json" {
        return Ok(raw_text_result(rendered.join("\n\n")));
    }
    Ok(text_result(&json!({
        "query": query,
        "total_matches": total_matches,
        "workflows": sections,
        "note": "Rows are redacted (secret values / internal fields never appear). Read one run's \
                 full data with writ_workflow_data { workflow, run_id }.",
    })))
}

async fn create_monitor(state: &AppState, args: &Value) -> Result<Value, CallError> {
    let url = require_str(args, "url")?;
    if !crate::security::url_guard::is_navigation_url_safe_async(&url).await {
        return Err(CallError::BadArgument("monitor URL is not allowed".into()));
    }
    let minutes = args.get("interval_minutes").and_then(Value::as_i64)
        .filter(|v| *v >= 1).ok_or_else(|| CallError::BadArgument("interval_minutes must be >= 1".into()))?;
    let requires_browser = args.get("requires_browser").and_then(Value::as_bool).unwrap_or(false);
    let requested = minutes.saturating_mul(60_000);
    let interval = crate::local::scheduler::clamp::clamp_monitor_interval_ms(Some(requested), requires_browser);
    let selector = args.get("selector").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
    let id = targets::insert(&state.db, &targets::NewTarget {
        url: url.clone(), check_type: Some(if selector.is_some() { "content" } else { "uptime" }.into()),
        selector, check_period_ms: Some(interval), requires_playwright: Some(requires_browser as i64),
        enabled: Some(1), ..Default::default()
    }).await?;
    Ok(text_result(&json!({
        "status":"created","monitor_id":id,"url":url,"interval_ms":interval,
        "interval_was_clamped":interval != requested,"requires_browser":requires_browser,
        "next":"Call writ_wire_monitor to choose what happens when a change is detected."
    })))
}

async fn wire_monitor(state: &AppState, args: &Value) -> Result<Value, CallError> {
    let target_id = require_i64(args, "monitor_id")?;
    let target = targets::get_by_id(&state.db, target_id).await?
        .ok_or_else(|| CallError::BadArgument(format!("monitor {target_id} does not exist")))?;
    let action = require_str(args, "action")?;
    let title = args.get("title").and_then(Value::as_str).unwrap_or("Writ detected a change");
    let message = args.get("message").and_then(Value::as_str)
        .unwrap_or("The monitored page changed: {{event.url}}");
    let event = json!({"id":"evt","type":"event","blockType":"change_detected","parentId":Value::Null,"config":{"target_id":target_id}});
    let (action_block, legacy_action) = match action.as_str() {
        "notify" => (
            json!({"id":"act","type":"action","blockType":"notification","parentId":"evt","config":{"channels":["desktop","in_app"],"title":title,"template":message}}),
            json!({"type":"notify","channels":["desktop","in_app"],"title":title,"template":message}),
        ),
        "webhook" => {
            let webhook = require_str(args, "webhook_url")?;
            if !(webhook.starts_with("http://") || webhook.starts_with("https://")) {
                return Err(CallError::BadArgument("webhook_url must be HTTP(S)".into()));
            }
            (
                json!({"id":"act","type":"action","blockType":"notification","parentId":"evt","config":{"channels":["webhook"],"webhook_url":webhook,"title":title,"template":message}}),
                json!({"type":"notify","channels":["webhook"],"webhook_url":webhook,"title":title,"template":message}),
            )
        }
        "workflow" => {
            let wf = resolve_workflow(state, args.get("workflow")).await?;
            (
                json!({"id":"act","type":"action","blockType":"workflow","parentId":"evt","config":{"workflow_id":wf.id,"on_error":"continue"}}),
                json!({"type":"workflow","workflow_id":wf.id}),
            )
        }
        "ai_task" => {
            // Wake the LOCAL AI agent: the flow runtime's ai_session lane
            // (flow.rs::run_ai_session_action) renders the goal's
            // {{placeholders}} against the change scope and appends the wake
            // note, then drives the autonomous loop on the engine browser.
            // entry_url is baked at wiring time — the change scope carries no
            // URL, and the monitored page is the natural place to start.
            let prompt = require_str(args, "prompt")?;
            let entry_url = args.get("entry_url").and_then(Value::as_str)
                .map(str::trim).filter(|s| !s.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| target.url.clone());
            let mut cfg = json!({"goal": prompt, "entry_url": entry_url});
            if let Some(ms) = args.get("max_steps").and_then(Value::as_u64) {
                cfg["max_steps"] = json!(ms.clamp(1, 100));
            }
            (
                json!({"id":"act","type":"action","blockType":"ai_session","parentId":"evt","config": cfg.clone()}),
                json!({"type":"ai_session","goal": cfg["goal"], "entry_url": cfg["entry_url"]}),
            )
        }
        _ => return Err(CallError::BadArgument("action must be notify, workflow, ai_task, or webhook".into())),
    };
    let name = args.get("name").and_then(Value::as_str).filter(|s| !s.trim().is_empty())
        .unwrap_or("Monitor change automation");
    let blocks = json!([event, action_block]);
    let row = automations::insert(&state.db, &automations::NewAutomation {
        target_id: Some(target_id), event_type: Some("change_detected".into()), name: name.into(),
        enabled: Some(1), actions: Some(json!([legacy_action]).to_string()), blocks: Some(blocks.to_string()),
        ..Default::default()
    }).await?;
    Ok(text_result(&json!({
        "status":"wired","monitor_id":target_id,"automation_id":row.id,"action":action,
        "note": match action.as_str() {
            "webhook" => "The webhook endpoint is responsible for launching or queueing an external AI process; Writ does not execute arbitrary shell commands.",
            "ai_task" => "On each detected change the local AI agent opens the monitored page with the change context and works the prompt. It needs an AI provider or the cloud AI gateway configured (Settings → AI).",
            _ => "Automation is enabled and uses Writ's existing change_detected runtime.",
        }
    })))
}

/// Create a generic event-driven automation (the local twin of the cloud/coordinator
/// `writ_create_automation`): on `workflow_completed`/`workflow_started`/`change_detected`, run a
/// saved workflow and/or send a notification. Wires the automation's routing columns so the local
/// runtime dispatches it for the right source — `flow_events` matches workflow-events on the
/// `workflow_id` column; the monitor runner matches `change_detected` on the `target_id` column —
/// and always writes a real executable block tree (event → action chain) so it never falls back to
/// the legacy "re-run the linked workflow" path.
async fn create_automation(state: &AppState, args: &Value) -> Result<Value, CallError> {
    let name = args
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CallError::BadArgument("writ_create_automation requires a 'name'".into()))?
        .to_string();
    let event = args
        .get("when")
        .or_else(|| args.get("event"))
        .and_then(Value::as_str)
        .unwrap_or("workflow_completed")
        .to_string();
    if !matches!(
        event.as_str(),
        "change_detected" | "workflow_started" | "workflow_completed"
    ) {
        return Err(CallError::BadArgument(
            "'when' must be one of change_detected, workflow_started, workflow_completed".into(),
        ));
    }

    // Resolve the event scope and the routing column the runtime filters on.
    let mut event_cfg = serde_json::Map::new();
    let mut new_workflow_id: Option<i64> = None;
    let mut new_target_id: Option<i64> = None;
    let mut monitor_url: Option<String> = None;
    if event == "change_detected" {
        let mid = args
            .get("monitor_id")
            .or_else(|| args.get("on_monitor"))
            .or_else(|| args.get("target_id"))
            .and_then(Value::as_i64)
            .ok_or_else(|| {
                CallError::BadArgument(
                    "when=change_detected needs 'monitor_id' — create one with writ_create_monitor \
                     (writ_wire_monitor is the shortcut for this case)"
                        .into(),
                )
            })?;
        let target = targets::get_by_id(&state.db, mid)
            .await?
            .ok_or_else(|| CallError::BadArgument(format!("monitor {mid} does not exist")))?;
        monitor_url = Some(target.url);
        event_cfg.insert("target_id".into(), json!(mid));
        new_target_id = Some(mid);
    } else {
        let src =
            resolve_workflow(state, args.get("on_workflow").or_else(|| args.get("on_workflow_id")))
                .await?;
        event_cfg.insert("workflow_id".into(), json!(src.id));
        new_workflow_id = Some(src.id);
    }

    // Build a linear event → action chain (children by parentId run in order).
    let mut blocks: Vec<Value> = vec![json!({
        "id": "evt", "type": "event", "blockType": event, "parentId": Value::Null,
        "config": Value::Object(event_cfg),
    })];
    let mut legacy: Vec<Value> = Vec::new();
    let mut parent = "evt".to_string();
    let mut n = 0;
    if let Some(wfv) = args.get("run_workflow").or_else(|| args.get("run_workflow_id")) {
        let wf = resolve_workflow(state, Some(wfv)).await?;
        let id = format!("act{n}");
        n += 1;
        blocks.push(json!({
            "id": id.clone(), "type": "action", "blockType": "workflow", "parentId": parent.clone(),
            "config": {"workflow_id": wf.id, "on_error": "continue"},
        }));
        legacy.push(json!({"type": "workflow", "workflow_id": wf.id}));
        parent = id;
    }
    if let Some(msg) = args.get("notify").and_then(Value::as_str) {
        let title = args.get("title").and_then(Value::as_str).unwrap_or("Writ automation");
        let id = format!("act{n}");
        n += 1;
        blocks.push(json!({
            "id": id.clone(), "type": "action", "blockType": "notification", "parentId": parent.clone(),
            "config": {"channels": ["desktop", "in_app"], "title": title, "template": msg},
        }));
        legacy.push(json!({"type": "notify", "channels": ["desktop", "in_app"], "title": title, "template": msg}));
        parent = id;
    }
    if let Some(prompt) = args
        .get("ai_prompt")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        // Wake the local AI agent on the event. The flow runtime renders the
        // goal's {{placeholders}} against the event scope and appends the wake
        // note (flow.rs::run_ai_session_action). entry_url falls back to the
        // monitored page for change_detected wirings.
        let entry_url = args
            .get("ai_entry_url")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or(monitor_url);
        let id = format!("act{n}");
        let mut cfg = serde_json::Map::new();
        cfg.insert("goal".into(), json!(prompt));
        if let Some(u) = entry_url {
            cfg.insert("entry_url".into(), json!(u));
        }
        blocks.push(json!({
            "id": id, "type": "action", "blockType": "ai_session", "parentId": parent.clone(),
            "config": Value::Object(cfg),
        }));
        legacy.push(json!({"type": "ai_session", "goal": prompt}));
    }
    if legacy.is_empty() {
        return Err(CallError::BadArgument(
            "give the automation something to do: pass 'run_workflow', 'notify', and/or 'ai_prompt'".into(),
        ));
    }

    let enabled = args.get("enabled").and_then(Value::as_bool).unwrap_or(true);
    let action_types: Vec<Value> = legacy
        .iter()
        .map(|a| a.get("type").cloned().unwrap_or(Value::Null))
        .collect();
    let row = automations::insert(
        &state.db,
        &automations::NewAutomation {
            target_id: new_target_id,
            event_type: Some(event.clone()),
            workflow_id: new_workflow_id,
            name: name.clone(),
            enabled: Some(enabled as i64),
            actions: Some(json!(legacy).to_string()),
            blocks: Some(json!(blocks).to_string()),
            ..Default::default()
        },
    )
    .await?;
    Ok(text_result(&json!({
        "status": "created",
        "automation_id": row.id,
        "name": name,
        "event": event,
        "on_workflow_id": new_workflow_id,
        "monitor_id": new_target_id,
        "actions": action_types,
        "enabled": enabled,
    })))
}

async fn set_schedule(state: &AppState, args: &Value) -> Result<Value, CallError> {
    let wf = resolve_workflow(state, args.get("workflow")).await?;
    let kind = require_str(args, "kind")?;

    let mut patch = workflows::WorkflowUpdate::default();
    match kind.as_str() {
        "off" => {
            patch.schedule_enabled = Some(0);
        }
        "interval" => {
            let minutes = args
                .get("interval_minutes")
                .and_then(Value::as_i64)
                .filter(|m| *m >= 1)
                .ok_or_else(|| {
                    CallError::BadArgument("kind='interval' needs interval_minutes >= 1".into())
                })?;
            patch.schedule_enabled = Some(1);
            patch.schedule_kind = Some("interval".into());
            patch.schedule_interval_ms = Some(minutes * 60_000);
        }
        "daily" | "weekly" => {
            let time = require_str(args, "time")?;
            if !valid_hhmm(&time) {
                return Err(CallError::BadArgument("'time' must be HH:MM (24h)".into()));
            }
            let tz = require_str(args, "tz")?;
            if tz.parse::<chrono_tz::Tz>().is_err() {
                return Err(CallError::BadArgument(format!(
                    "'{tz}' is not a valid IANA timezone (e.g. Europe/Paris)"
                )));
            }
            if kind == "weekly" {
                let days: Vec<i64> = args
                    .get("days")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_i64).collect())
                    .unwrap_or_default();
                if days.is_empty() || days.iter().any(|d| !(1..=7).contains(d)) {
                    return Err(CallError::BadArgument(
                        "kind='weekly' needs days: ISO weekdays 1 (Mon) – 7 (Sun)".into(),
                    ));
                }
                patch.schedule_days = Some(json!(days).to_string());
            }
            patch.schedule_enabled = Some(1);
            patch.schedule_kind = Some(kind.clone());
            patch.schedule_time = Some(time);
            patch.schedule_tz = Some(tz);
        }
        other => {
            return Err(CallError::BadArgument(format!(
                "unknown kind '{other}' — use interval | daily | weekly | off"
            )));
        }
    }

    let updated = workflows::update(&state.db, wf.id, &patch).await?;
    Ok(text_result(&json!({
        "workflow": updated.name,
        "id": updated.id,
        "schedule": schedule_view(&updated),
        "note": "Writ runs this in the background while the daemon is up; results accumulate — \
                 read them any time with writ_workflow_data.",
    })))
}

// ── cloud marketplace (linked-account tools) ─────────────────────────────────
//
// `writ_search_api` / `writ_install_api` are the only static tools that talk to the Writ Cloud.
// They are advertised in tools/list ONLY when the app is cloud-linked (tools::list_tools filters on
// CLOUD_LINKED_NAMES) and re-check the link at call time, since a client may cache an older list.
// SECURITY: same posture as the rest of this surface — the `wto_` token never leaves the daemon
// (CloudClient), the recipe stays sealed (install) / in-memory (run), and SECRET VALUES never
// transit MCP: missing vault secrets are reported by KEY with an instruction to add them in the
// Writ app. Billing authority stays cloud-side (authorize-run/finalize inside marketplace::run).

/// Guidance when a cloud tool is called on an unlinked app (cached tools/list, or unlinked
/// mid-session).
#[cfg(feature = "cloud")]
const NOT_LINKED_MSG: &str = "Writ is not linked to a Writ Cloud account, so marketplace search \
     and install are unavailable. Tell the user: creating and linking a Writ Cloud account is \
     FREE (Writ app → Settings → Account) and unlocks searching + installing ready-made \
     marketplace APIs. After linking, try again. To build the API locally without an account, \
     use writ_website_to_api.";

/// Guidance when link metadata exists but the cloud session is dead (revoked/expired token).
#[cfg(feature = "cloud")]
const SESSION_DEAD_MSG: &str = "The Writ Cloud session is no longer valid. Ask the user to \
     re-link their account in the Writ app (Settings → Account), then try again.";

/// `None` when the app is cloud-linked; otherwise the `err_result` the caller returns verbatim.
#[cfg(feature = "cloud")]
async fn cloud_link_gate(state: &AppState) -> Result<Option<Value>, CallError> {
    let link = LinkState::load_or_default(&state.db).await?;
    Ok(if link.is_linked() {
        None
    } else {
        Some(err_result(NOT_LINKED_MSG))
    })
}

/// INSTALL-OVER-REBUILD lookup for the build tools: before RECORDING a new website API, search the
/// marketplace for compatible ready-made listings to propose. Returns `Some(tool result)` ONLY when
/// the app is linked AND compatible candidates exist; every other outcome — unlinked, no matches,
/// search error, or a slow cloud (hard 4s bound) — returns `None` so the build proceeds normally.
#[cfg(feature = "cloud")]
async fn marketplace_recipe_proposal(state: &AppState, goal: &str, url: &str) -> Option<Value> {
    let linked = LinkState::load_or_default(&state.db).await.ok()?.is_linked();
    if !linked {
        return None;
    }
    let host = url_host(url);
    let search = tokio::time::timeout(
        std::time::Duration::from_secs(4),
        cloud_marketplace::search_api(&state.db, goal, host.as_deref(), None, 5),
    )
    .await
    .ok()?
    .ok()?;
    let candidates = search.get("candidates")?.as_array()?.clone();
    let compatible = filter_compatible_candidates(&candidates, host.as_deref());
    if compatible.is_empty() {
        return None;
    }
    let best = compatible[0].get("slug").cloned().unwrap_or(Value::Null);
    Some(text_result(&json!({
        "status": "marketplace_candidates",
        "message": "Ready-made marketplace APIs already match this goal — installing one takes \
                    seconds and needs no recording session.",
        "goal": goal,
        "site": host,
        "candidates": compatible,
        "best": best,
        "next": "Propose these to the user (title, summary, creator, price; 'installed' means \
                 it's already on this machine). If the user picks one, call writ_install_api with \
                 its slug. If none fits or the user prefers to build fresh, call this build tool \
                 again with the same goal/url plus skip_marketplace=true (keep any skip flags you \
                 already passed) to start recording.",
    })))
}

/// Pure compatibility filter for build-time proposals — deliberately CONSERVATIVE so recording is
/// never hijacked by weak matches: a candidate qualifies only when it targets the SAME site as the
/// build url, or (no/foreign site) its relevance score is strong. Already-installed candidates
/// float first (ready to run, nothing to buy). Top 3.
#[cfg(feature = "cloud")]
fn filter_compatible_candidates(candidates: &[Value], host: Option<&str>) -> Vec<Value> {
    let mut out: Vec<Value> = candidates
        .iter()
        .filter(|c| {
            let site_match = match (host, c.get("target_site").and_then(Value::as_str)) {
                (Some(h), Some(d)) if !d.is_empty() => {
                    let (h, d) = (h.to_lowercase(), d.to_lowercase());
                    d.contains(&h) || h.contains(&d)
                }
                _ => false,
            };
            let score = c.get("score").and_then(Value::as_f64).unwrap_or(0.0);
            site_match || score >= 3.0
        })
        .cloned()
        .collect();
    out.sort_by_key(|c| !c.get("installed").and_then(Value::as_bool).unwrap_or(false));
    out.truncate(3);
    out
}

/// Host of a build url (scheme optional), lowercased, `www.` stripped. `None` when nothing
/// host-shaped (never guesses).
fn url_host(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit('@').next().unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host);
    let host = host.trim_start_matches("www.").trim_matches('.').to_lowercase();
    if host.contains('.') && host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        Some(host)
    } else {
        None
    }
}

#[cfg(feature = "cloud")]
async fn search_api(state: &AppState, args: &Value) -> Result<Value, CallError> {
    if let Some(gate) = cloud_link_gate(state).await? {
        return Ok(gate);
    }
    let query = require_str(args, "query")?;
    let site = opt_str(args, "site");
    let category = opt_str(args, "category");
    let limit = args
        .get("limit")
        .and_then(Value::as_i64)
        .unwrap_or(5)
        .clamp(1, 10) as usize;

    let mut found = match cloud_marketplace::search_api(
        &state.db,
        &query,
        site.as_deref(),
        category.as_deref(),
        limit,
    )
    .await
    {
        Ok(v) => v,
        Err(LocalError::Unauthorized) => return Ok(err_result(SESSION_DEAD_MSG)),
        Err(e) => return Err(e.into()),
    };

    let empty = found
        .get("candidates")
        .and_then(Value::as_array)
        .map_or(true, Vec::is_empty);
    if empty {
        return Ok(text_result(&json!({
            "status": "no_matches",
            "query": query,
            "next": "No marketplace API matched. Retry writ_search_api with different terms or a \
                     'site', or build the API from scratch with writ_website_to_api.",
        })));
    }
    let best = found
        .pointer("/candidates/0/slug")
        .cloned()
        .unwrap_or(Value::Null);
    // OWN LIBRARY FIRST: surface the user's already-saved workflows matching the same need —
    // replaying one is instant and free, so it outranks any install.
    let own_rows = workflows::list(&state.db, true, 1000).await?;
    let own = match_own_workflows(&own_rows, &query, site.as_deref());
    if let Some(obj) = found.as_object_mut() {
        obj.insert("existing_workflows".into(), json!(own));
        obj.insert("best".into(), best);
        obj.insert(
            "next".into(),
            json!(
                "If existing_workflows is non-empty, propose THOSE first — the user already owns \
                 them; run one with writ_run_workflow (instant, free). Otherwise present the \
                 marketplace candidates to the user (best first: title, summary, creator, price) \
                 and let THEM choose; on confirmation call writ_install_api with the slug — it \
                 installs the listing and runs it, asking for any missing inputs."
            ),
        );
    }
    Ok(text_result(&found))
}

#[cfg(feature = "cloud")]
async fn install_api(state: &AppState, args: &Value) -> Result<Value, CallError> {
    if let Some(gate) = cloud_link_gate(state).await? {
        return Ok(gate);
    }
    let slug = require_str(args, "slug")?;
    let run = args.get("run").and_then(Value::as_bool).unwrap_or(true);
    let mut inputs = args.get("inputs").cloned().unwrap_or_else(|| json!({}));
    if !inputs.is_object() {
        return Err(CallError::BadArgument(
            "'inputs' must be a JSON object".into(),
        ));
    }
    // Fold the top-level selection args into the inputs object — the shared manifest gate lifts
    // the reserved `secrets`/`persona` keys back out (they are never treated as run inputs).
    if let Some(obj) = inputs.as_object_mut() {
        if let Some(s) = args.get("secrets").filter(|v| v.is_object()) {
            obj.insert("secrets".into(), s.clone());
        }
        if let Some(p) = args.get("persona").filter(|v| !v.is_null()) {
            obj.insert("persona".into(), p.clone());
        }
    }

    // Install once — an already-installed slug skips the cloud install entirely (the re-run path),
    // reusing the EXISTING native plumbing: cloud install → sealed recipe → encrypted local row +
    // the local PROXY workflow row (0017) that makes the install a regular callable workflow.
    let newly_installed = installed_workflows::get_meta(&state.db, &slug).await?.is_none();
    if newly_installed {
        if let Err(e) = cloud_marketplace::install(&state.db, &state.vault, &slug).await {
            return match e {
                LocalError::Unauthorized => Ok(err_result(SESSION_DEAD_MSG)),
                LocalError::BadRequest(m) | LocalError::NotFound(m) => {
                    Ok(err_result(format!("Install of '{slug}' failed: {m}")))
                }
                other => Err(other.into()),
            };
        }
    }
    let meta = installed_workflows::get_meta(&state.db, &slug)
        .await?
        .ok_or_else(|| CallError::Internal(LocalError::Internal("install did not persist".into())))?;
    // Idempotent; also lazily heals pre-0017 installs that predate proxy rows.
    let proxy =
        cloud_marketplace::ensure_proxy_workflow(&state.db, &slug, meta.listing_title.as_deref())
            .await?;
    let tool_name = super::tools::sanitize(&proxy.name);

    if !run {
        return Ok(text_result(&json!({
            "status": "installed",
            "slug": meta.slug,
            "title": meta.listing_title,
            "is_free": meta.is_free,
            "price_micros": meta.price_micros,
            "workflow_id": proxy.id,
            "next": format!(
                "Installed as a regular Writ workflow: run it with writ_install_api or \
                 writ_run_workflow (workflow {}), via its own '{tool_name}' tool on the next \
                 tools/list, or schedule it with writ_set_schedule.",
                proxy.id
            ),
        })));
    }

    // Run through the SAME lane as the derived tool / writ_run_workflow: the manifest gate elicits
    // missing inputs/secret picks/persona picks first, then the engine's marketplace intercept
    // authorizes (paid), unseals, executes, and finalizes.
    super::tool_executor::run_workflow_tool(state, proxy.id, inputs).await
}

/// Pre-run `needs_input` gate for an INSTALLED marketplace listing (shared by `writ_install_api`,
/// `writ_run_workflow`, and the derived proxy tool via `tool_executor`). Driven by the install's
/// BYO data manifest, it makes every unmet slot PICKABLE:
///   * required `input_slots` the caller hasn't supplied → plain text fields the user answers in
///     the connected AI chat;
///   * `secret_slots` with no binding and no same-named vault secret → the LOCAL vault's secret
///     KEY NAMES are offered as options; the user picks with `secrets: {slot: key}` (or adds a new
///     secret in the Writ app). SECURITY: names only — secret VALUES never transit MCP;
///   * `persona_slots` with no persona chosen → the LOCAL personas (id/name/domain) are offered;
///     the user picks with `persona: <id|name>` or declines with `persona: "none"`.
///
/// Selections persist as install BINDINGS (names/ids + non-secret input defaults) so scheduled and
/// background runs of the proxy resolve without re-asking; the engine applies them on every run.
/// Best-effort: a missing/unparseable manifest never blocks the run. `None` = proceed.
#[cfg(feature = "cloud")]
pub(crate) async fn marketplace_needs_input(
    state: &AppState,
    slug: &str,
    inputs: &mut Value,
) -> Result<Option<Value>, CallError> {
    let Some(install) = installed_workflows::get_by_slug(&state.db, slug).await? else {
        return Ok(Some(err_result(format!(
            "marketplace install '{slug}' is missing — reinstall it with writ_install_api"
        ))));
    };
    let mut bindings = cloud_marketplace::InstallBindings::parse(install.bindings.as_deref());
    let mut bindings_dirty = false;
    let manifest = install
        .input_schema
        .as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .unwrap_or_else(|| json!({}));
    let slot_key = |slot: &Value| -> Option<String> {
        ["key", "name"].iter().find_map(|k| {
            slot.get(*k)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        })
    };
    let slot_label = |slot: &Value, key: &str| -> String {
        slot.get("label")
            .and_then(Value::as_str)
            .filter(|l| !l.is_empty())
            .unwrap_or(key)
            .to_string()
    };

    // ── Lift + apply the reserved SELECTION args (never treated as run inputs) ──
    let picked_secrets = inputs.as_object_mut().and_then(|o| o.remove("secrets"));
    let picked_persona = inputs.as_object_mut().and_then(|o| o.remove("persona"));

    let secret_slots: Vec<Value> = manifest
        .get("secret_slots")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if let Some(Value::Object(picks)) = picked_secrets {
        for (slot, key) in picks {
            let Some(key) = key.as_str().map(str::trim).filter(|k| !k.is_empty()) else {
                continue;
            };
            if !secret_slots.iter().filter_map(&slot_key).any(|s| s == slot) {
                return Ok(Some(err_result(format!(
                    "'{slot}' is not a secret slot of this listing"
                ))));
            }
            if vault_secrets::get_by_key(&state.db, key).await?.is_none() {
                return Ok(Some(err_result(format!(
                    "no vault secret named '{key}' — offer the user the listed options, or have \
                     them add it in the Writ app (Vault) first"
                ))));
            }
            bindings.secrets.insert(slot, key.to_string());
            bindings_dirty = true;
        }
    }
    match picked_persona {
        None | Some(Value::Null) => {}
        Some(Value::String(s)) if s.eq_ignore_ascii_case("none") => {
            if !bindings.persona_none || bindings.persona_id.is_some() {
                bindings.persona_none = true;
                bindings.persona_id = None;
                bindings_dirty = true;
            }
        }
        Some(p) => {
            let persona = match p.as_i64() {
                Some(id) => crate::local::store::personas::get_by_id(&state.db, id).await?,
                None => match p.as_str() {
                    Some(name) => {
                        crate::local::store::personas::get_by_name(&state.db, name.trim()).await?
                    }
                    None => {
                        return Err(CallError::BadArgument(
                            "'persona' must be a persona id, name, or \"none\"".into(),
                        ))
                    }
                },
            };
            let Some(persona) = persona else {
                return Ok(Some(err_result(
                    "no such persona — offer the user the listed options (id or name)",
                )));
            };
            bindings.persona_id = Some(persona.id);
            bindings.persona_none = false;
            bindings_dirty = true;
        }
    }

    // ── Compute what is STILL missing, with pickable options ──
    let supplied = inputs.as_object().cloned().unwrap_or_default();
    let mut fields = Vec::new();

    for slot in manifest
        .get("input_slots")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(key) = slot_key(slot) else { continue };
        if !slot.get("required").and_then(Value::as_bool).unwrap_or(true) {
            continue;
        }
        let has = |v: Option<&Value>| {
            v.map_or(false, |v| {
                !v.is_null() && v.as_str().map_or(true, |s| !s.trim().is_empty())
            })
        };
        if !has(supplied.get(&key)) && !has(bindings.inputs.get(&key)) {
            fields.push(json!({
                "key": key,
                "label": slot_label(slot, &key),
                "kind": "text",
                "sensitive": false,
                "answer_with": "inputs",
            }));
        }
    }

    let mut vault_key_options: Option<Vec<String>> = None;
    for slot in &secret_slots {
        let Some(key) = slot_key(slot) else { continue };
        let bound = bindings.secrets.contains_key(&key);
        let exact = vault_secrets::get_by_key(&state.db, &key).await?.is_some();
        if bound || exact {
            continue;
        }
        if vault_key_options.is_none() {
            // KEY NAMES only — never values (VaultSecret rows carry ciphertext we must not touch).
            vault_key_options = Some(
                vault_secrets::list(&state.db, Some(50))
                    .await?
                    .into_iter()
                    .map(|s| s.key)
                    .collect(),
            );
        }
        fields.push(json!({
            "key": key,
            "label": slot_label(slot, &key),
            "kind": "secret",
            "sensitive": true,
            "options": vault_key_options.clone().unwrap_or_default(),
            "answer_with": "secrets",
        }));
    }

    let persona_slots: Vec<Value> = manifest
        .get("persona_slots")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !persona_slots.is_empty() && bindings.persona_id.is_none() && !bindings.persona_none {
        let domain = persona_slots
            .first()
            .and_then(|s| s.get("target_domain"))
            .and_then(Value::as_str)
            .map(str::to_string);
        let personas = match domain.as_deref().filter(|d| !d.is_empty()) {
            Some(d) => crate::local::store::personas::list_by_domain(&state.db, d).await?,
            None => crate::local::store::personas::list(&state.db, Some(50)).await?,
        };
        // Metadata only: id/name/domain/2FA capability — never credentials/session material.
        let options: Vec<Value> = personas
            .iter()
            .map(|p| {
                json!({
                    "id": p.id,
                    "name": p.name,
                    "domain": p.target_domain,
                    "twofa": p.twofa_method != "none",
                })
            })
            .collect();
        fields.push(json!({
            "key": "persona",
            "label": persona_slots
                .first()
                .map(|s| slot_label(s, "persona"))
                .unwrap_or_else(|| "persona".to_string()),
            "kind": "persona",
            "sensitive": false,
            "options": options,
            "answer_with": "persona",
        }));
    }

    if fields.is_empty() {
        // Everything satisfied — persist the caller's NON-secret inputs as defaults (plus any new
        // picks) so scheduled/background runs of the proxy resolve without re-asking.
        for (k, v) in supplied {
            if bindings.inputs.get(&k) != Some(&v) {
                bindings.inputs.insert(k, v);
                bindings_dirty = true;
            }
        }
        if bindings_dirty {
            installed_workflows::set_bindings(&state.db, slug, Some(&bindings.to_json())).await?;
        }
        return Ok(None);
    }

    // Persist partial picks so they stick across the elicitation round-trip.
    if bindings_dirty {
        installed_workflows::set_bindings(&state.db, slug, Some(&bindings.to_json())).await?;
    }
    let body = json!({
        "status": "needs_input",
        "slug": install.slug,
        "listing": install.listing_title,
        "fields": fields,
        "next": "Show the user each field. For 'text' fields ask for the value and pass it in \
                 'inputs'. For 'secret' fields let the user PICK one of the offered vault keys and \
                 pass {\"secrets\": {\"<slot>\": \"<picked key>\"}} — to use a new secret the user \
                 must add it in the Writ app (Vault) first; NEVER send secret values through this \
                 chat. For the 'persona' field let the user pick one of the offered personas and \
                 pass {\"persona\": <id or name>} (or \"none\" to run without). Then call the same \
                 tool again with the selections; they are remembered for future and scheduled runs.",
    });
    Ok(Some(json!({
        "content": [{"type":"text","text": serde_json::to_string_pretty(&body).unwrap_or_else(|_| body.to_string())}],
        "isError": false,
    })))
}

// ── helpers ──────────────────────────────────────────────────────────────────

// ── Dragnet whole-site crawl ─────────────────────────────────────────────────

/// Start a Dragnet whole-site crawl and return the queued row immediately. Venue mirrors the REST
/// `/v1/crawl` handler: a linked desktop routes the crawl to the cloud FLEET (many egress IPs,
/// managed browsers), OSS/unlinked drives the local `crawl::start_crawl` worker pool — so `writ_
/// crawl_status`/`writ_workflow_data` read back from the SAME place the crawl runs. Scope/politeness/
/// SSRF gating is single-sourced with the REST core. A bad or disallowed seed comes back as a normal
/// isError result (a domain outcome the model relays), not a protocol error.
async fn crawl_site(state: &AppState, args: &Value) -> Result<Value, CallError> {
    let url = require_str(args, "url")?;
    let extract_mode = match args
        .get("extract")
        .and_then(Value::as_str)
        .unwrap_or("markdown")
        .to_ascii_lowercase()
        .as_str()
    {
        "schema" => "schema",
        _ => "markdown",
    }
    .to_string();
    let to_list = |v: Option<&Value>| -> Vec<String> {
        match v {
            Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
            Some(Value::String(s)) if !s.trim().is_empty() => vec![s.trim().to_string()],
            _ => Vec::new(),
        }
    };
    let persona_id = match args.get("persona") {
        Some(v) if !v.is_null() => Some(resolve_persona(state, v).await?),
        _ => None,
    };
    let defaults = crate::local::crawl::StartParams::default();
    let params = crate::local::crawl::StartParams {
        seed_url: url,
        extract_schema: args.get("extract_schema").filter(|v| !v.is_null()).cloned(),
        extract_mode,
        persona_id,
        include_paths: to_list(args.get("include").or_else(|| args.get("include_paths"))),
        exclude_paths: to_list(args.get("exclude").or_else(|| args.get("exclude_paths"))),
        max_depth: args.get("max_depth").and_then(Value::as_i64).unwrap_or(defaults.max_depth),
        page_budget: args
            .get("max_pages")
            .and_then(Value::as_i64)
            .or_else(|| args.get("page_budget").and_then(Value::as_i64))
            .map(|n| n.clamp(1, 50_000))
            .unwrap_or(defaults.page_budget),
        same_domain: args.get("same_domain").and_then(Value::as_bool).unwrap_or(defaults.same_domain),
        allow_subdomains: args
            .get("allow_subdomains")
            .and_then(Value::as_bool)
            .unwrap_or(defaults.allow_subdomains),
        content: args.get("content").filter(|v| !v.is_null()).cloned(),
        ..Default::default()
    };
    // Dragnet crawl is CLOUD-ONLY on the managed desktop app. A whole-site crawl fans out across the
    // cloud FLEET (many egress IPs, managed browsers, gateway-metered AI extraction) and NEVER runs on
    // this one machine. A linked account routes to the fleet; WITHOUT a credential we REFUSE rather than
    // silently crawl locally — keyless callers get single-page scrape / site map only (writ_scrape,
    // writ_map). The local worker pool is compiled in ONLY for the OSS self-host build (no `cloud`).
    // `save_as` turns this into a SAVED crawl: the settings are persisted under that name so the
    // crawl becomes callable by API and re-runnable, and the run goes through the definition so this
    // very call already benefits from `max_age`. Re-using a name updates that saved crawl rather than
    // minting a near-duplicate every time an agent repeats itself.
    let save_as = args
        .get("save_as")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    #[cfg(feature = "cloud")]
    {
        if crate::local::cloud::crawl::is_linked(&state.db).await {
            if let Some(label) = save_as {
                return save_and_run_cloud_crawl(state, &params, &label, requested_max_age(args)).await;
            }
            let cloud = match crate::local::cloud::crawl::start(&state.db, &build_cloud_crawl_body(&params)).await {
                Ok(v) => v,
                // Seed rejected by the cloud (SSRF/scope/plan) → relayable outcome, not a protocol error.
                Err(LocalError::BadRequest(m)) => return Ok(err_result(m)),
                Err(e) => return Err(e.into()),
            };
            let mut view = cloud_crawl_view(&cloud);
            if let Some(obj) = view.as_object_mut() {
                obj.insert("next".into(), json!(CRAWL_STARTED_NEXT));
            }
            return Ok(text_result(&view));
        }
        Ok(err_result(CRAWL_NEEDS_CLOUD))
    }
    #[cfg(not(feature = "cloud"))]
    {
        if let Some(label) = save_as {
            return save_and_run_local_crawl(state, &params, &label, args).await;
        }
        let crawl = match crate::local::crawl::start_crawl(state, params).await {
            Ok(c) => c,
            // Bad/SSRF-blocked seed → relayable domain outcome, not a JSON-RPC error.
            Err(LocalError::BadRequest(m)) => return Ok(err_result(m)),
            Err(e) => return Err(e.into()),
        };
        let mut view = crawl_view(&crawl);
        if let Some(obj) = view.as_object_mut() {
            obj.insert("next".into(), json!(CRAWL_STARTED_NEXT));
        }
        Ok(text_result(&view))
    }
}

/// `save_as` on a linked desktop: upsert the saved crawl on the fleet, then run it there.
#[cfg(feature = "cloud")]
async fn save_and_run_cloud_crawl(
    state: &AppState,
    params: &crate::local::crawl::StartParams,
    label: &str,
    max_age: i64,
) -> Result<Value, CallError> {
    let config = build_cloud_crawl_body(params);
    let existing = crate::local::cloud::crawl::list_definitions(&state.db, 200)
        .await
        .unwrap_or_else(|_| json!({}));
    let matched = existing
        .get("definitions")
        .and_then(Value::as_array)
        .and_then(|arr| {
            arr.iter()
                .find(|d| {
                    d.get("slug").and_then(Value::as_str) == Some(label)
                        || d.get("name").and_then(Value::as_str) == Some(label)
                })
                .and_then(|d| d.get("slug").and_then(Value::as_str).map(str::to_string))
        });

    let defn = match matched {
        Some(slug) => {
            crate::local::cloud::crawl::update_definition(
                &state.db,
                &slug,
                &json!({ "config": config }),
            )
            .await?
        }
        None => {
            crate::local::cloud::crawl::create_definition(
                &state.db,
                &json!({ "name": label, "slug": label, "config": config }),
            )
            .await?
        }
    };
    let slug = defn
        .get("slug")
        .and_then(Value::as_str)
        .ok_or_else(|| LocalError::Internal("saved crawl has no slug".into()))?
        .to_string();
    let res = crate::local::cloud::crawl::run_definition(
        &state.db,
        &slug,
        &json!({ "max_age": max_age, "wait": false }),
    )
    .await?;
    Ok(text_result(&annotate_saved_crawl_run(res)))
}

/// `save_as` on the OSS build: upsert the local definition, then run it locally.
#[cfg(not(feature = "cloud"))]
async fn save_and_run_local_crawl(
    state: &AppState,
    params: &crate::local::crawl::StartParams,
    label: &str,
    args: &Value,
) -> Result<Value, CallError> {
    use crate::local::store::crawl_definitions as defs;

    // Persist the config in the SAME vocabulary the local start body uses, so
    // `saved_config_to_params` re-hydrates it losslessly.
    let config = json!({
        "url": params.seed_url,
        "name": params.name,
        "extract_mode": params.extract_mode,
        "extract_schema": params.extract_schema,
        "persona_id": params.persona_id,
        "include_paths": params.include_paths,
        "exclude_paths": params.exclude_paths,
        "max_depth": params.max_depth,
        "page_budget": params.page_budget,
        "max_concurrent": params.max_concurrent,
        "delay_ms": params.delay_ms,
        "respect_robots": params.respect_robots,
        "same_domain": params.same_domain,
        "allow_subdomains": params.allow_subdomains,
        "content_spec": params.content,
    });
    let raw = serde_json::to_string(&config)
        .map_err(|e| CallError::from(LocalError::Internal(format!("config serialize: {e}"))))?;

    let defn = match defs::resolve(&state.db, label).await? {
        Some(found) => {
            defs::update_config(&state.db, found.id, &raw, &params.seed_url).await?;
            defs::get_by_id(&state.db, found.id)
                .await?
                .ok_or_else(|| LocalError::Internal("saved crawl vanished".into()))?
        }
        None => {
            let slug = defs::mint_slug(&state.db, label).await?;
            defs::insert(
                &state.db,
                &defs::NewCrawlDefinition {
                    name: label.chars().take(200).collect(),
                    slug,
                    description: None,
                    config: raw,
                    seed_url: params.seed_url.clone(),
                    default_max_age_seconds: None,
                },
            )
            .await?
        }
    };

    // Route through the saved-crawl runner so `max_age` behaves identically whether the agent called
    // writ_crawl_site with save_as or writ_run_saved_crawl directly.
    let mut run_args = json!({ "crawl": defn.slug });
    if let (Some(obj), Some(requested)) = (run_args.as_object_mut(), args.get("max_age")) {
        obj.insert("max_age".into(), requested.clone());
    }
    run_saved_crawl(state, &run_args).await
}

// ── Saved crawls ─────────────────────────────────────────────────────────────
//
// A saved crawl is a stored configuration with a stable slug: callable by API, re-runnable with the
// same settings, and — with `max_age` — answerable from the data it already collected instead of
// crawling the site again. For a driving model this is the difference between a slow metered crawl
// and an instant free read, so the tools are worth surfacing prominently.
//
// Same build split as every other crawl path here: the managed desktop proxies to the fleet (that is
// where its crawls and their history live), the OSS build owns the local `crawl_definitions` table.

/// The MCP tool arg naming the saved crawl. Accepts a slug, a name, or a numeric id so the model can
/// pass whatever it has on hand.
fn saved_crawl_ref(args: &Value) -> Result<String, CallError> {
    let raw = args.get("crawl").or_else(|| args.get("saved_crawl"));
    match raw {
        Some(Value::String(s)) if !s.trim().is_empty() => Ok(s.trim().to_string()),
        Some(Value::Number(n)) => Ok(n.to_string()),
        _ => Err(CallError::BadArgument(
            "`crawl` is required — a saved crawl slug, name, or id (see writ_saved_crawls)".into(),
        )),
    }
}

/// Caller's freshness ceiling in seconds. 0 (the default) means always crawl.
///
/// A malformed value degrades to 0 rather than failing the call: freshness is a hint, and refusing to
/// answer over an unparseable number would be the worse outcome.
fn requested_max_age(args: &Value) -> i64 {
    args.get("max_age")
        .and_then(Value::as_i64)
        .unwrap_or(0)
        .clamp(0, 30 * 24 * 3600)
}

async fn saved_crawls(state: &AppState, args: &Value) -> Result<Value, CallError> {
    let limit = args.get("limit").and_then(Value::as_i64).unwrap_or(50).clamp(1, 200);
    #[cfg(feature = "cloud")]
    {
        if crate::local::cloud::crawl::is_linked(&state.db).await {
            let res = crate::local::cloud::crawl::list_definitions(&state.db, limit).await?;
            return Ok(text_result(&res));
        }
        Ok(err_result(CRAWL_STATUS_NEEDS_CLOUD))
    }
    #[cfg(not(feature = "cloud"))]
    {
        let rows = crate::local::store::crawl_definitions::list(&state.db, limit).await?;
        if rows.is_empty() {
            return Ok(err_result(
                "No saved crawls yet. Create one by passing `save_as` to writ_crawl_site — that makes \
                 the crawl callable by API and re-runnable, and lets later calls reuse its data via \
                 max_age.",
            ));
        }
        let out: Vec<Value> = rows
            .iter()
            .map(|d| {
                json!({
                    "id": d.id,
                    "slug": d.slug,
                    "name": d.name,
                    "seed_url": d.seed_url,
                    "last_run_at": d.last_run_at,
                    "default_max_age_seconds": d.default_max_age_seconds,
                })
            })
            .collect();
        Ok(text_result(&json!({ "saved_crawls": out, "total": out.len() })))
    }
}

async fn run_saved_crawl(state: &AppState, args: &Value) -> Result<Value, CallError> {
    let reference = saved_crawl_ref(args)?;
    let max_age = requested_max_age(args);
    let limit = args.get("limit").and_then(Value::as_i64).unwrap_or(50).clamp(1, 500);

    #[cfg(feature = "cloud")]
    {
        if crate::local::cloud::crawl::is_linked(&state.db).await {
            let body = json!({ "max_age": max_age, "wait": false, "limit": limit });
            let res = match crate::local::cloud::crawl::run_definition(&state.db, &reference, &body).await {
                Ok(v) => v,
                Err(LocalError::NotFound(m)) => return Ok(err_result(m)),
                Err(LocalError::BadRequest(m)) => return Ok(err_result(m)),
                Err(e) => return Err(e.into()),
            };
            return Ok(text_result(&annotate_saved_crawl_run(res)));
        }
        Ok(err_result(CRAWL_NEEDS_CLOUD))
    }
    #[cfg(not(feature = "cloud"))]
    {
        use crate::local::store::crawl_definitions as defs;
        let defn = defs::resolve(&state.db, &reference)
            .await?
            .ok_or_else(|| CallError::BadArgument(format!("no saved crawl '{reference}'")))?;

        // The definition's stored default applies only when the caller said nothing at all; an
        // explicit max_age=0 means "crawl it fresh" and must win.
        let effective = if args.get("max_age").is_some() {
            max_age
        } else {
            defn.default_max_age_seconds.unwrap_or(0)
        };

        if effective > 0 {
            if let Some(fresh) = defs::find_fresh_run(&state.db, defn.id, effective).await? {
                let age = defs::run_age_seconds(&state.db, fresh.id).await?;
                let data = saved_crawl_rows(state, &fresh, limit).await;
                return Ok(text_result(&json!({
                    "cached": true,
                    "_cache": { "hit": true, "age_seconds": age.map(|a| a as i64), "source_crawl_id": fresh.id },
                    "saved_crawl": defn.slug,
                    "crawl": crawl_view(&fresh),
                    "data": data,
                })));
            }
        }

        let config: Value = serde_json::from_str(&defn.config)
            .map_err(|e| CallError::from(LocalError::Internal(format!("saved crawl config: {e}"))))?;
        let params = saved_config_to_params(state, &config).await?;
        let crawl = match crate::local::crawl::start_crawl(state, params).await {
            Ok(c) => c,
            Err(LocalError::BadRequest(m)) => return Ok(err_result(m)),
            Err(e) => return Err(e.into()),
        };
        defs::attach_run(&state.db, crawl.id, defn.id).await?;
        defs::touch_last_run(&state.db, defn.id).await?;
        let mut view = crawl_view(&crawl);
        if let Some(obj) = view.as_object_mut() {
            obj.insert("next".into(), json!(CRAWL_STARTED_NEXT));
        }
        Ok(text_result(&json!({
            "cached": false,
            "_cache": { "hit": false },
            "saved_crawl": defn.slug,
            "crawl": view,
        })))
    }
}

async fn saved_crawl_data(state: &AppState, args: &Value) -> Result<Value, CallError> {
    let reference = saved_crawl_ref(args)?;
    let limit = args.get("limit").and_then(Value::as_i64).unwrap_or(50).clamp(1, 500);
    #[cfg(feature = "cloud")]
    {
        if crate::local::cloud::crawl::is_linked(&state.db).await {
            let res = match crate::local::cloud::crawl::definition_data(&state.db, &reference, limit).await {
                Ok(v) => v,
                Err(LocalError::NotFound(m)) => return Ok(err_result(m)),
                Err(e) => return Err(e.into()),
            };
            return Ok(text_result(&res));
        }
        Ok(err_result(CRAWL_STATUS_NEEDS_CLOUD))
    }
    #[cfg(not(feature = "cloud"))]
    {
        use crate::local::store::crawl_definitions as defs;
        let defn = defs::resolve(&state.db, &reference)
            .await?
            .ok_or_else(|| CallError::BadArgument(format!("no saved crawl '{reference}'")))?;
        // A very large window rather than a separate "any age" query: reusing find_fresh_run keeps ONE
        // definition of what counts as a usable run (completed, non-empty).
        match defs::find_fresh_run(&state.db, defn.id, i64::MAX / 4).await? {
            None => Ok(err_result(format!(
                "'{}' has not completed a crawl with any pages yet — run it with writ_run_saved_crawl.",
                defn.slug
            ))),
            Some(last) => {
                let age = defs::run_age_seconds(&state.db, last.id).await?;
                let data = saved_crawl_rows(state, &last, limit).await;
                Ok(text_result(&json!({
                    "saved_crawl": defn.slug,
                    "crawl": crawl_view(&last),
                    "age_seconds": age.map(|a| a as i64),
                    "data": data,
                })))
            }
        }
    }
}

/// Stamp a proxied saved-crawl run with the same post-start guidance the local path gives, when the
/// cloud actually dispatched a crawl rather than answering from its data.
#[cfg(feature = "cloud")]
fn annotate_saved_crawl_run(mut res: Value) -> Value {
    let was_cached = res.get("cached").and_then(Value::as_bool).unwrap_or(false);
    if !was_cached {
        if let Some(obj) = res.as_object_mut() {
            obj.insert("next".into(), json!(CRAWL_STARTED_NEXT));
        }
    }
    res
}

/// Re-hydrate a saved config into local crawl params.
///
/// Goes through the same field vocabulary `crawl_site` accepts, so a saved config and a direct call
/// cannot be interpreted differently.
#[cfg(not(feature = "cloud"))]
async fn saved_config_to_params(
    state: &AppState,
    config: &Value,
) -> Result<crate::local::crawl::StartParams, CallError> {
    let seed = config
        .get("url")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| CallError::BadArgument("saved crawl config has no url".into()))?
        .to_string();
    let to_list = |v: Option<&Value>| -> Vec<String> {
        match v {
            Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
            Some(Value::String(s)) if !s.trim().is_empty() => vec![s.trim().to_string()],
            _ => Vec::new(),
        }
    };
    let persona_id = match config.get("persona_id").or_else(|| config.get("persona")) {
        Some(v) if !v.is_null() => Some(resolve_persona(state, v).await?),
        _ => None,
    };
    let defaults = crate::local::crawl::StartParams::default();
    Ok(crate::local::crawl::StartParams {
        seed_url: seed,
        name: config.get("name").and_then(Value::as_str).map(str::to_string),
        extract_mode: match config
            .get("extract_mode")
            .or_else(|| config.get("extract"))
            .and_then(Value::as_str)
            .unwrap_or("markdown")
        {
            "schema" => "schema".to_string(),
            _ => "markdown".to_string(),
        },
        extract_schema: config.get("extract_schema").filter(|v| !v.is_null()).cloned(),
        persona_id,
        include_paths: to_list(config.get("include_paths").or_else(|| config.get("include"))),
        exclude_paths: to_list(config.get("exclude_paths").or_else(|| config.get("exclude"))),
        max_depth: config
            .get("max_depth")
            .and_then(Value::as_i64)
            .unwrap_or(defaults.max_depth),
        page_budget: config
            .get("page_budget")
            .or_else(|| config.get("max_pages"))
            .and_then(Value::as_i64)
            .map(|n| n.clamp(1, 50_000))
            .unwrap_or(defaults.page_budget),
        max_concurrent: config
            .get("max_concurrent")
            .and_then(Value::as_i64)
            .unwrap_or(defaults.max_concurrent),
        delay_ms: config.get("delay_ms").and_then(Value::as_i64).unwrap_or(defaults.delay_ms),
        respect_robots: config
            .get("respect_robots")
            .and_then(Value::as_bool)
            .unwrap_or(defaults.respect_robots),
        same_domain: config
            .get("same_domain")
            .and_then(Value::as_bool)
            .unwrap_or(defaults.same_domain),
        allow_subdomains: config
            .get("allow_subdomains")
            .and_then(Value::as_bool)
            .unwrap_or(defaults.allow_subdomains),
        content: config
            .get("content_spec")
            .or_else(|| config.get("content"))
            .filter(|v| !v.is_null())
            .cloned(),
        concierge_session_id: None,
    })
}

/// The rows a crawl collected, in the shared table shape. JSON null on any read problem — a data
/// hiccup must not sink an otherwise-successful answer.
#[cfg(not(feature = "cloud"))]
async fn saved_crawl_rows(
    state: &AppState,
    crawl: &crate::local::store::crawl_jobs::CrawlJob,
    limit: i64,
) -> Value {
    let Some(workflow_id) = crawl.workflow_id else {
        return Value::Null;
    };
    let Ok((inputs, _truncated)) =
        crate::local::api::v1::data::scan_workflow_data_runs_pool(&state.db, workflow_id).await
    else {
        return Value::Null;
    };
    if inputs.is_empty() {
        return Value::Null;
    }
    let (columns, mut rows) = crate::local::data_query::flatten(&inputs, &[], true);
    rows.truncate(limit.max(0) as usize);
    let rows = crate::local::data_query::rows_to_table_json(&rows, &columns);
    json!({ "columns": columns, "rows": rows })
}

/// Refusal shown when a managed (cloud-feature) desktop asks to crawl without a linked account or API
/// key. Dragnet is cloud-only — we never run a whole-site crawl on the user's machine — so we point at
/// the credential paths and at the keyless verbs that DO work without one.
#[cfg(feature = "cloud")]
const CRAWL_NEEDS_CLOUD: &str = "Whole-site Dragnet crawl runs on the Writ cloud fleet, never on this \
     machine. Link a cloud account or set an API key to run a crawl. Keyless access covers single-page \
     scrape and site map only — use writ_scrape or writ_map to try without a key.";

/// Refusal for a status poll on a managed desktop with no linked account: there are no local crawls to
/// report because crawl never runs locally here.
#[cfg(feature = "cloud")]
const CRAWL_STATUS_NEEDS_CLOUD: &str = "No linked account. Dragnet crawls run on the Writ cloud fleet, \
     so there are no local crawls to track — link a cloud account or set an API key to start and poll a \
     crawl. (writ_scrape and writ_map work without a key.)";

/// Post-start guidance shared by the local and cloud crawl paths (single-sourced so the two stay
/// in lockstep). Steers the driving model to poll status, then read the dataset.
const CRAWL_STARTED_NEXT: &str = "The crawl runs in the background. Poll writ_crawl_status with \
     this crawl_id until status is terminal, then read the collected pages with writ_workflow_data \
     (workflow = workflow_id) or expose the whole dataset as an API with writ_expose_workflow_api.";

/// Map the MCP crawl params → the cloud `StartCrawlRequest` JSON. The MCP tool speaks the smaller
/// public vocabulary (no `executor`/`extract_prompt` axis — regular deterministic extraction only);
/// `max_concurrent` becomes the fleet's `max_concurrent_shards`. Mirrors the REST handler's
/// `build_cloud_start_body`, sourced from `StartParams` so scope/politeness stay single-sourced.
#[cfg(feature = "cloud")]
fn build_cloud_crawl_body(p: &crate::local::crawl::StartParams) -> Value {
    json!({
        "url": p.seed_url,
        "name": p.name,
        "executor": "regular",
        "extract_mode": p.extract_mode,
        "extract_schema": p.extract_schema,
        "persona_id": p.persona_id,
        "include_paths": p.include_paths,
        "exclude_paths": p.exclude_paths,
        "max_depth": p.max_depth,
        "page_budget": p.page_budget,
        "max_concurrent_shards": p.max_concurrent,
        "delay_ms": p.delay_ms,
        "respect_robots": p.respect_robots,
        "same_domain": p.same_domain,
        "allow_subdomains": p.allow_subdomains,
        "content": p.content,
    })
}

/// Normalize a cloud crawl `_view` (the cloud backend's `crawl` router) into the SAME compact status shape as
/// [`crawl_view`] so an MCP client sees one crawl schema whether the crawl ran locally or on the
/// fleet. The cloud sends `brand` as `{crawl, agent}` and omits `is_terminal`/`workers_active` (a
/// per-shard concept), so derive them here. Null-safe + idempotent.
#[cfg(feature = "cloud")]
fn cloud_crawl_view(v: &Value) -> Value {
    let get = |k: &str| v.get(k).cloned().unwrap_or(Value::Null);
    let status = v.get("status").and_then(Value::as_str).unwrap_or("");
    let is_terminal = matches!(status, "completed" | "failed" | "cancelled");
    let dispatched = v.get("shards_dispatched").and_then(Value::as_i64).unwrap_or(0);
    let done = v.get("shards_done").and_then(Value::as_i64).unwrap_or(0);
    let brand = v
        .get("brand")
        .and_then(|b| b.get("crawl"))
        .and_then(Value::as_str)
        .unwrap_or("Dragnet");
    json!({
        "crawl_id": get("id"),
        "brand": brand,
        "name": get("name"),
        "seed_url": get("seed_url"),
        "status": status,
        "is_terminal": is_terminal,
        "workflow_id": get("workflow_id"),
        "extract_mode": get("extract_mode"),
        "pages_discovered": get("pages_discovered"),
        "pages_done": get("pages_done"),
        "pages_failed": get("pages_failed"),
        "pages_skipped": get("pages_skipped"),
        "workers_active": (dispatched - done).max(0),
        "current_depth": get("current_depth"),
        "error": get("error"),
    })
}

/// Poll one crawl (by `crawl_id`) or list recent crawls (when omitted). A linked desktop reads the
/// crawl from the cloud fleet (where `writ_crawl_site` started it), so the poll tracks the SAME
/// crawl the model launched; OSS/unlinked reads the local worker pool.
async fn crawl_status(state: &AppState, args: &Value) -> Result<Value, CallError> {
    #[cfg(feature = "cloud")]
    {
        if crate::local::cloud::crawl::is_linked(&state.db).await {
            if let Some(id) = args.get("crawl_id").and_then(Value::as_i64) {
                let cloud = match crate::local::cloud::crawl::get(&state.db, id).await {
                    Ok(v) => v,
                    // A genuine miss → relayable outcome (mirrors the local BadArgument). A network/auth
                    // failure is NOT a miss — surface it truthfully instead of a misleading "no crawl".
                    Err(LocalError::NotFound(_)) => {
                        return Ok(err_result(format!("no crawl with id {id} on the linked account")))
                    }
                    Err(e) => return Err(e.into()),
                };
                let mut view = cloud_crawl_view(&cloud);
                let terminal = view.get("is_terminal").and_then(Value::as_bool).unwrap_or(false);
                if let Some(obj) = view.as_object_mut() {
                    obj.insert("next".into(), json!(crawl_status_next(terminal)));
                }
                return Ok(text_result(&view));
            }
            let limit = args.get("limit").and_then(Value::as_i64).unwrap_or(20).clamp(1, 100);
            let cloud = crate::local::cloud::crawl::list(&state.db, limit).await?;
            let crawls: Vec<Value> = cloud
                .get("crawls")
                .and_then(Value::as_array)
                .map(|arr| arr.iter().map(cloud_crawl_view).collect())
                .unwrap_or_default();
            return Ok(text_result(&json!({ "crawls": crawls })));
        }
        Ok(err_result(CRAWL_STATUS_NEEDS_CLOUD))
    }
    #[cfg(not(feature = "cloud"))]
    {
        if let Some(id) = args.get("crawl_id").and_then(Value::as_i64) {
            let job = crawl_jobs::get_by_id(&state.db, id)
                .await?
                .ok_or_else(|| CallError::BadArgument(format!("no crawl with id {id}")))?;
            let terminal = job.is_terminal();
            let mut view = crawl_view(&job);
            if let Some(obj) = view.as_object_mut() {
                obj.insert("next".into(), json!(crawl_status_next(terminal)));
            }
            return Ok(text_result(&view));
        }
        let limit = args.get("limit").and_then(Value::as_i64).unwrap_or(20).clamp(1, 100);
        let rows = crawl_jobs::list(&state.db, limit).await?;
        let crawls: Vec<Value> = rows.iter().map(crawl_view).collect();
        Ok(text_result(&json!({ "crawls": crawls })))
    }
}

/// Scrape ONE page to clean markdown. Cloud-only on the managed app: a linked account uses the metered
/// authed path (`/api/crawl/scrape`); an UNLINKED app uses the keyless tier (daily-capped, per install).
/// Never runs on this machine in the managed build. The OSS self-host build has no cloud tier, so it
/// points the caller at writ_crawl_site.
async fn scrape(state: &AppState, args: &Value) -> Result<Value, CallError> {
    let url = require_str(args, "url")?;
    #[cfg(feature = "cloud")]
    {
        let body = json!({ "url": url });
        let out = if crate::local::cloud::crawl::is_linked(&state.db).await {
            crate::local::cloud::crawl::scrape(&state.db, &body).await
        } else {
            crate::local::cloud::keyless::scrape(&state.db, &body).await
        };
        return match out {
            Ok(v) => Ok(text_result(&v)),
            // A 402 needs-key / 429 over-quota / bad seed → relayable outcome, not a protocol error.
            Err(LocalError::BadRequest(m)) => Ok(err_result(m)),
            Err(e) => Err(e.into()),
        };
    }
    #[cfg(not(feature = "cloud"))]
    {
        let _ = state;
        match crate::local::crawl::scrape_one(&url, None).await {
            Ok(v) => Ok(text_result(&v)),
            Err(LocalError::BadRequest(m)) => Ok(err_result(m)),
            Err(e) => Err(e.into()),
        }
    }
}

/// Map a site's URLs (sitemap + shallow harvest), ranked by an optional `search`. Same cloud tiering as
/// [`scrape`]: metered when linked, keyless (daily-capped) otherwise, never local in the managed build.
async fn site_map(state: &AppState, args: &Value) -> Result<Value, CallError> {
    let url = require_str(args, "url")?;
    let search = args.get("search").and_then(Value::as_str).unwrap_or("").to_string();
    #[cfg(feature = "cloud")]
    {
        let body = json!({ "url": url, "search": search });
        let out = if crate::local::cloud::crawl::is_linked(&state.db).await {
            crate::local::cloud::crawl::map(&state.db, &body).await
        } else {
            crate::local::cloud::keyless::map(&state.db, &body).await
        };
        return match out {
            Ok(v) => Ok(text_result(&v)),
            Err(LocalError::BadRequest(m)) => Ok(err_result(m)),
            Err(e) => Err(e.into()),
        };
    }
    #[cfg(not(feature = "cloud"))]
    {
        let _ = state;
        let search = if search.is_empty() { None } else { Some(search.as_str()) };
        match crate::local::crawl::map_site(&url, search).await {
            Ok(v) => Ok(text_result(&v)),
            Err(LocalError::BadRequest(m)) => Ok(err_result(m)),
            Err(e) => Err(e.into()),
        }
    }
}

/// The `next` guidance for a polled crawl, keyed on whether it has reached a terminal state.
fn crawl_status_next(terminal: bool) -> &'static str {
    if terminal {
        "Crawl finished. Read the collected pages with writ_workflow_data (workflow = workflow_id), \
         or expose the whole dataset as an API with writ_expose_workflow_api."
    } else {
        "Crawl still running — call writ_crawl_status again in a few seconds until status is terminal."
    }
}

/// Compact status view of a LOCAL crawl row for MCP results (the fields a driving model reasons
/// about). Local crawls exist only in the OSS self-host build — the managed build always routes to the
/// fleet and renders [`cloud_crawl_view`] instead.
#[cfg(not(feature = "cloud"))]
fn crawl_view(job: &crawl_jobs::CrawlJob) -> Value {
    json!({
        "crawl_id": job.id,
        "brand": "Dragnet",
        "name": job.name,
        "seed_url": job.seed_url,
        "status": job.status,
        "is_terminal": job.is_terminal(),
        "workflow_id": job.workflow_id,
        "extract_mode": job.extract_mode,
        "pages_discovered": job.pages_discovered,
        "pages_done": job.pages_done,
        "pages_failed": job.pages_failed,
        "pages_skipped": job.pages_skipped,
        "workers_active": job.workers_active.max(0),
        "current_depth": job.current_depth,
        "error": job.error,
    })
}

/// Resolve a persona reference (id or name) to its id, for a login-gated crawl.
pub(crate) async fn resolve_persona(state: &AppState, v: &Value) -> Result<i64, CallError> {
    if let Some(id) = v
        .as_i64()
        .or_else(|| v.as_str().and_then(|s| s.trim().parse::<i64>().ok()))
    {
        return personas::get_by_id(&state.db, id)
            .await?
            .map(|p| p.id)
            .ok_or_else(|| CallError::BadArgument(format!("no persona with id {id}")));
    }
    let name = v
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CallError::BadArgument("'persona' must be a persona id or name".into()))?;
    personas::get_by_name(&state.db, name)
        .await?
        .map(|p| p.id)
        .ok_or_else(|| CallError::BadArgument(format!("no persona named '{name}'")))
}

/// Resolve the `workflow` argument (numeric id, digit-string, `workflow_<id>` alias, or a name —
/// matched through the same sanitizer the derived tool names use) to a full workflow row.
async fn resolve_workflow(
    state: &AppState,
    v: Option<&Value>,
) -> Result<workflows::Workflow, CallError> {
    let v = v.ok_or_else(|| CallError::BadArgument("missing 'workflow' (name or id)".into()))?;
    if let Some(id) = v
        .as_i64()
        .or_else(|| v.as_str().and_then(|s| s.trim().parse::<i64>().ok()))
        .or_else(|| {
            v.as_str()
                .and_then(|s| s.strip_prefix("workflow_"))
                .and_then(|s| s.parse().ok())
        })
    {
        return workflows::get_by_id(&state.db, id)
            .await?
            .ok_or_else(|| CallError::BadArgument(format!("no workflow with id {id}")));
    }
    let name = v
        .as_str()
        .ok_or_else(|| CallError::BadArgument("'workflow' must be a name or id".into()))?;
    let want = super::tools::sanitize(name);
    let all = workflows::list(&state.db, false, 1000).await?;
    all.iter()
        .find(|w| super::tools::sanitize(&w.name) == want)
        .cloned()
        .ok_or_else(|| {
            CallError::BadArgument(format!(
                "no workflow named '{name}' — call writ_list_workflows to see what exists"
            ))
        })
}

/// Resolve a `workflow` argument to a CLOUD crawl dataset id, or `None` to fall through to the
/// local resolver. `Some(id)` only when: the arg is a numeric id (a name can't name a fleet
/// dataset), NO local workflow owns that id (a real local workflow always wins), and a cloud
/// account is linked. Cloud dataset ids come from a large shared server sequence and never collide
/// with the small local id space, so "numeric + absent locally + linked ⇒ cloud" is unambiguous —
/// the same rule the REST data handlers use ([`api::v1::data::try_forward_cloud_data`]).
#[cfg(feature = "cloud")]
async fn cloud_dataset_id(state: &AppState, v: Option<&Value>) -> Result<Option<i64>, CallError> {
    let Some(v) = v else { return Ok(None) };
    let Some(id) = v
        .as_i64()
        .or_else(|| v.as_str().and_then(|s| s.trim().parse::<i64>().ok()))
        .or_else(|| {
            v.as_str()
                .and_then(|s| s.strip_prefix("workflow_"))
                .and_then(|s| s.parse().ok())
        })
    else {
        return Ok(None); // a name — only a local workflow can be named.
    };
    if workflows::get_by_id(&state.db, id).await?.is_some() {
        return Ok(None); // a real local workflow — never forward.
    }
    if !crate::local::cloud::crawl::is_linked(&state.db).await {
        return Ok(None); // unlinked / OSS — let the local resolver report "no workflow".
    }
    Ok(Some(id))
}

/// Read a cloud crawl's aggregated dataset (the pages the fleet collected) via the Workflow Data
/// API and shape it as an MCP result. The cloud returns one flat table (columns + rows) rather than
/// the local per-run shape, so surface that directly — it IS the whole deduped crawl output.
#[cfg(feature = "cloud")]
async fn cloud_crawl_data(
    state: &AppState,
    id: i64,
    args: &Value,
    fmt: &str,
) -> Result<Value, CallError> {
    let limit = args
        .get("limit")
        .and_then(Value::as_i64)
        .unwrap_or(200)
        .clamp(1, 500);
    let table = crate::local::cloud::workflow_data::get(&state.db, id, "", Some(&format!("limit={limit}"))).await?;
    // The cloud data route has no `format` of its own — render the forwarded table
    // here so a cloud crawl reads exactly like a local dataset.
    if fmt != "json" {
        let title = table
            .get("workflow_name")
            .and_then(Value::as_str)
            .unwrap_or("Dataset")
            .to_string();
        return Ok(render_mcp(&table, fmt, "rows", &title));
    }
    let take = |k: &str| table.get(k).cloned().unwrap_or(Value::Null);
    let total = table
        .get("total")
        .or_else(|| table.get("row_count"))
        .cloned()
        .unwrap_or(Value::Null);
    Ok(text_result(&json!({
        "workflow_id": id,
        "brand": "Dragnet",
        "source": "cloud",
        "total": total,
        "columns": take("columns"),
        "rows": take("rows"),
        "note": "Aggregated pages from a cloud Dragnet crawl (deduped across the fleet). Expose the \
                 whole dataset as an API with writ_expose_workflow_api, or search it with \
                 writ_search_data.",
    })))
}

/// `writ_workflow_runs` for a CLOUD crawl id → the fleet's run index (successful data-bearing runs,
/// newest first with per-run record counts) via the Workflow Data API. Same auth funnel as the data
/// read; shaped like the local runs feed so the model reasons about one schema.
#[cfg(feature = "cloud")]
async fn cloud_crawl_runs(state: &AppState, id: i64) -> Result<Value, CallError> {
    let index = crate::local::cloud::workflow_data::get(&state.db, id, "/runs", None).await?;
    let runs = index.get("runs").cloned().unwrap_or_else(|| json!([]));
    Ok(text_result(&json!({
        "workflow_id": id,
        "source": "cloud",
        "brand": "Dragnet",
        "runs": runs,
        "note": "Runs of a cloud Dragnet crawl (fleet-side). Read a run's rows with \
                 writ_workflow_data { workflow: <this id>, run_id }.",
    })))
}

/// `writ_search_data` scoped to a CLOUD crawl id → free-text search over the fleet's dataset using
/// the cloud data endpoint's own `q` filter (server-side, same redaction guarantees). Shaped as a
/// single-workflow section so the result matches the local multi-section envelope.
#[cfg(feature = "cloud")]
async fn cloud_crawl_search(
    state: &AppState,
    id: i64,
    query: &str,
    limit: usize,
    fmt: &str,
) -> Result<Value, CallError> {
    let q = format!("q={}&limit={}", encode_query_value(query), limit);
    let table = crate::local::cloud::workflow_data::get(&state.db, id, "", Some(&q)).await?;
    let rows = table.get("rows").cloned().unwrap_or_else(|| json!([]));
    let matches = table
        .get("total")
        .or_else(|| table.get("row_count"))
        .and_then(Value::as_i64)
        .unwrap_or_else(|| rows.as_array().map(|a| a.len() as i64).unwrap_or(0));
    if matches == 0 {
        return Ok(text_result(&json!({
            "status": "no_matches",
            "query": query,
            "next": "Nothing in this cloud crawl's data matched. Broaden the query, or read the \
                     whole dataset with writ_workflow_data.",
        })));
    }
    // The cloud data route has no `format` of its own — render the forwarded table
    // here so a cloud crawl formats exactly like a local dataset.
    if fmt != "json" {
        return Ok(render_mcp(&table, fmt, "rows", &format!("Search: {query}")));
    }
    Ok(text_result(&json!({
        "query": query,
        "total_matches": matches,
        "workflows": [{
            "workflow_id": id,
            "source": "cloud",
            "brand": "Dragnet",
            "matches": matches,
            "columns": table.get("columns").cloned().unwrap_or(Value::Null),
            "rows": rows,
        }],
        "note": "Cloud crawl dataset (deduped fleet pages, redacted server-side). Read one run's \
                 full data with writ_workflow_data { workflow: <this id>, run_id }.",
    })))
}

/// `writ_expose_workflow_api` for a CLOUD crawl id → the dataset IS a public cloud REST resource
/// already (the Workflow Data API), so return that endpoint + the cloud-key auth story. READ-ONLY:
/// crawl pages are served data, not a runnable workflow, so there's no push / Connect toggle and no
/// run endpoint.
#[cfg(feature = "cloud")]
async fn expose_cloud_crawl_dataset(state: &AppState, id: i64) -> Result<Value, CallError> {
    use crate::local::cloud::client::CloudClient;
    let link = LinkState::load_or_default(&state.db).await?;
    if !link.is_linked() {
        return Ok(err_result(NOT_LINKED_MSG));
    }
    let base = CloudClient::resolve_base_url(Some(&link));
    Ok(text_result(&json!({
        "workflow_id": id,
        "brand": "Dragnet",
        "venue": "cloud",
        "access": "read-only",
        "server": { "managed_by": "writ-cloud", "base_url": base, "scope": "public-https" },
        "endpoints": [{
            "style": "rest",
            "method": "GET",
            "url": format!("{base}/api/workflows/{id}/data"),
            "query": "q, filters, sort_by, limit, offset, view — see the Workflow Data API",
            "export": format!("{base}/api/workflows/{id}/data/export?format=csv"),
        }],
        "authentication": {
            "scheme": "Bearer",
            "next": "The user mints a Writ Cloud API key in the dashboard (Settings → API Keys) — \
                     shown once, never sent through Claude/MCP. Call with Authorization: Bearer \
                     <writ cloud key>.",
        },
        "note": "A cloud Dragnet crawl is served read-only through the Workflow Data API — the \
                 pages are data, not a runnable workflow, so there is no run endpoint.",
    })))
}

/// Percent-encode a query-string VALUE (RFC 3986 unreserved pass through; everything else escaped,
/// spaces → %20). Small + self-contained so a search term carrying spaces/`&`/`=` can't corrupt the
/// forwarded query string.
#[cfg(feature = "cloud")]
fn encode_query_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The `requests` array of a session's pending_request (empty when none).
fn pending_requests(sess: &concierge_sessions::ConciergeSession) -> Vec<Value> {
    sess.pending_request
        .as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| v.get("requests").and_then(Value::as_array).cloned())
        .unwrap_or_default()
}

/// A compact schedule summary for list/schedule results.
fn schedule_view(w: &workflows::Workflow) -> Value {
    if w.schedule_enabled != 1 {
        return json!({ "enabled": false });
    }
    json!({
        "enabled": true,
        "kind": w.schedule_kind,
        "interval_minutes": w.schedule_interval_ms.map(|ms| ms / 60_000),
        "time": w.schedule_time,
        "days": w.schedule_days.as_deref().and_then(|s| serde_json::from_str::<Value>(s).ok()),
        "tz": w.schedule_tz,
    })
}

fn decode_obj(raw: Option<&str>) -> Value {
    raw.and_then(|s| serde_json::from_str::<Value>(s).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}))
}

fn require_str(args: &Value, key: &str) -> Result<String, CallError> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| CallError::BadArgument(format!("missing required '{key}' (string)")))
}

#[cfg(feature = "cloud")]
/// Optional trimmed non-empty string argument.
fn opt_str(args: &Value, key: &str) -> Option<String> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn require_i64(args: &Value, key: &str) -> Result<i64, CallError> {
    args.get(key)
        .and_then(Value::as_i64)
        .ok_or_else(|| CallError::BadArgument(format!("missing required '{key}' (integer)")))
}

fn valid_hhmm(s: &str) -> bool {
    let Some((h, m)) = s.split_once(':') else {
        return false;
    };
    matches!(h.parse::<u32>(), Ok(h) if h < 24)
        && h.len() <= 2
        && m.len() == 2
        && matches!(m.parse::<u32>(), Ok(m) if m < 60)
}

/// Shape a JSON payload as an MCP text result.
fn text_result(v: &Value) -> Value {
    let text = serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string());
    json!({ "content": [{ "type": "text", "text": text }], "isError": false })
}

/// A result whose text is ALREADY the payload (a markdown/csv render), not JSON to
/// pretty-print. Used by the dataset tools' `format` arg: an agent reading a crawl
/// wants the prose, and wrapping it in JSON would only re-escape it and burn tokens.
fn raw_text_result(text: impl Into<String>) -> Value {
    json!({ "content": [{ "type": "text", "text": text.into() }], "isError": false })
}

/// The output formats the dataset MCP tools accept. Deliberately a SUBSET of the REST
/// surface: `html` is for browsers and would only spend an agent's context on markup,
/// so it is not offered here.
const MCP_DATASET_FORMATS: [&str; 3] = ["json", "markdown", "csv"];

/// Validate a dataset tool's `format` arg, defaulting to `json`.
fn mcp_format(args: &Value) -> Result<String, CallError> {
    let f = args
        .get("format")
        .and_then(Value::as_str)
        .unwrap_or("json")
        .trim()
        .to_ascii_lowercase();
    if !MCP_DATASET_FORMATS.contains(&f.as_str()) {
        return Err(CallError::BadArgument(format!(
            "Unsupported format '{}'. Use one of: {}",
            f,
            MCP_DATASET_FORMATS.join(", ")
        )));
    }
    Ok(f)
}

/// Render a search/records payload in `fmt` for an MCP result. `json` keeps the
/// documented envelope; markdown/csv reuse the SAME renderers the REST `?format=`
/// serves, so a tool call and a REST read agree.
fn render_mcp(payload: &Value, fmt: &str, rows_key: &str, title: &str) -> Value {
    if fmt == "json" {
        return text_result(payload);
    }
    let (columns, rows) = crate::local::api::v1::data::rows_from_payload(payload, rows_key);
    let body = if fmt == "csv" {
        crate::local::data_query::to_csv(&columns, &rows)
    } else {
        crate::local::data_query::to_markdown(&columns, &rows, Some(title))
    };
    raw_text_result(body)
}

/// A domain-outcome error the model should relay/react to (NOT a protocol error).
fn err_result(msg: impl Into<String>) -> Value {
    json!({ "content": [{ "type": "text", "text": msg.into() }], "isError": true })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::config::LocalConfig;
    use crate::local::{db, engine, vault};
    use std::sync::Arc;

    /// A session goes stale only once it has been quiet LONGER than the window —
    /// exactly at the boundary it is still live.
    #[test]
    fn idle_predicate_is_exclusive_at_the_boundary() {
        let idle_ms = 300_000; // MCP_SESSION_IDLE_TIMEOUT
        assert!(!is_idle_past(0, idle_ms, idle_ms), "exactly at the TTL is still live");
        assert!(is_idle_past(0, idle_ms + 1, idle_ms), "one ms past the TTL is stale");
        assert!(!is_idle_past(0, idle_ms - 1, idle_ms));
    }

    /// A backwards clock step must never reap a live session.
    ///
    /// `now_ms` is wall-clock, so an NTP correction (or a `now_ms()` that fell back
    /// to 0 on a SystemTime error) can place `last_used` in the future. Saturating
    /// arithmetic has to read that as "not idle" — the alternative is a huge unsigned
    /// wrap that reaps every browser the moment the clock is adjusted.
    #[test]
    fn idle_predicate_survives_a_backwards_clock_step() {
        let idle_ms = 300_000;
        // last_used is an hour in the FUTURE relative to now.
        assert!(!is_idle_past(3_600_000, 0, idle_ms));
        // and the degenerate now_ms() == 0 fallback.
        assert!(!is_idle_past(1_000, 0, idle_ms));
    }

    /// The act path drives a `.cloned()` session and writes it back when it is done.
    /// The idle stamp must survive that round trip, or every long action would
    /// restore the timestamp captured at entry and the session would look idle
    /// while it was in fact being driven.
    #[test]
    fn touching_a_session_survives_the_act_path_write_back() {
        let sid = "sess_touch_writeback";
        let session = ConnectedBrowserSession {
            goal: "g".into(),
            name: "n".into(),
            entry_url: "https://example.com".into(),
            api: false,
            use_mode: true,
            steps: Vec::new(),
            fill_data: HashMap::new(),
            secret_refs: HashMap::new(),
            functions: Vec::new(),
            last_used_ms: Arc::new(AtomicI64::new(1_000)),
        };
        connected_sessions().lock().unwrap().insert(sid.into(), session.clone());

        // What `connected_browser_act` does: stamp, work on the clone, insert it back.
        session.last_used_ms.store(50_000, Ordering::Relaxed);
        connected_sessions().lock().unwrap().insert(sid.into(), session.clone());

        let stored = connected_sessions().lock().unwrap()
            .get(sid).unwrap().last_used_ms.load(Ordering::Relaxed);
        assert_eq!(stored, 50_000, "write-back must not restore the entry timestamp");

        connected_sessions().lock().unwrap().remove(sid);
    }

    async fn state() -> AppState {
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::local::config::Paths::at(dir.keep());
        paths.ensure_dirs().unwrap();
        let v = vault::Vault::load_or_create(&paths.root, false).unwrap();
        let pool = db::open(&paths.db(), &v.db_key_hex()).await.unwrap();
        AppState {
            db: pool,
            vault: Arc::new(v),
            engine: Arc::new(engine::StubEngine),
            config: LocalConfig::default(),
            token: Arc::new("wlt_test".into()),
            health: crate::local::app::health::DaemonHealth::shared(),
            recorder: None,
        }
    }

    #[test]
    fn entries_match_reserved_names() {
        let names: Vec<String> = entries()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect();
        // NAMES reserves every static name in every build (a workflow can never shadow one), but
        // the cloud-marketplace entries ship only in cloud-capable builds.
        let mut expected: Vec<String> = NAMES.iter().map(|s| s.to_string()).collect();
        if cfg!(not(feature = "cloud")) {
            expected.retain(|n| !CLOUD_LINKED_NAMES.contains(&n.as_str()));
        }
        assert_eq!(names, expected, "entries and NAMES stay in lockstep");
        // Every entry has a description + an object schema (MCP contract).
        for t in entries() {
            assert!(!t["description"].as_str().unwrap().is_empty());
            assert_eq!(t["inputSchema"]["type"], "object");
        }
    }

    #[test]
    fn persona_tool_is_advertised_read_only_of_lifecycle() {
        let listed = entries();
        let p = listed
            .iter()
            .find(|v| v["name"] == "writ_personas")
            .expect("writ_personas listed");
        // Its whole action vocabulary is read + operate — no create/update/delete.
        let actions = p["inputSchema"]["properties"]["action"]["enum"].clone();
        assert_eq!(actions, json!(["list", "get", "sign_in", "record_login"]));
        assert_eq!(p["inputSchema"]["required"], json!(["action"]));
        // No credential-shaped input is even declarable here.
        let props = p["inputSchema"]["properties"].as_object().unwrap();
        for forbidden in ["password", "totp_seed", "extra_login_fields", "proxy_password"] {
            assert!(!props.contains_key(forbidden), "must not accept {forbidden}");
        }
    }

    #[test]
    fn persona_projection_carries_no_secret_or_relay_material() {
        // Even if the shaped REST row grew a raw secret column, the fixed-field MCP view drops it
        // (unknown keys never pass), and the mailbox/relay plumbing an agent can't use stays out.
        let row = json!({
            "id": 7, "name": "Grafikart", "is_active": true, "twofa_method": "totp",
            "has_password": true, "has_warm_session": true, "can_self_login": true,
            "target_domain": "grafikart.fr", "login_workflow_name": "Grafikart login",
            "linked_workflows": [], "relay_address": "otp@relay", "connected_mailbox": "a@b.c",
            "password": "hunter2", "totp_seed": "JBSWY3DP", "session_state": "{...}",
        });
        let view = persona_mcp_view(&row);
        let dumped = view.to_string();
        assert!(!dumped.contains("hunter2"));
        assert!(!dumped.contains("JBSWY3DP"));
        assert!(view.get("relay_address").is_none());
        assert!(view.get("connected_mailbox").is_none());
        // Empty arrays are dropped; the readiness fields a model decides on are kept.
        assert!(view.get("linked_workflows").is_none());
        assert_eq!(view["id"], json!(7));
        assert_eq!(view["can_self_login"], json!(true));
        assert_eq!(view["target_domain"], json!("grafikart.fr"));
    }

    #[tokio::test]
    async fn persona_list_tool_is_empty_and_guides_to_the_app_on_a_fresh_store() {
        let st = state().await;
        let out = personas_tool(&st, &json!({ "action": "list" })).await.unwrap();
        assert_eq!(out["isError"], json!(false));
        let body: Value = serde_json::from_str(out["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(body["total"], json!(0));
        assert!(body["next"].as_str().unwrap().contains("Writ app"));
    }

    #[tokio::test]
    async fn persona_get_needs_an_identifier_and_reports_unknown_in_band() {
        let st = state().await;
        // Missing persona_id → in-band guidance, not a protocol error.
        let missing = personas_tool(&st, &json!({ "action": "get" })).await.unwrap();
        assert_eq!(missing["isError"], json!(true));
        // A persona_id that doesn't resolve is a BadArgument (invalid-params) from resolve_persona.
        let unknown = personas_tool(&st, &json!({ "action": "get", "persona_id": 987654 })).await;
        assert!(matches!(unknown, Err(CallError::BadArgument(_))));
    }

    #[test]
    fn crawl_tools_are_advertised_and_teach_whole_site_intent() {
        let listed = entries();
        let site = listed
            .iter()
            .find(|v| v["name"] == "writ_crawl_site")
            .expect("writ_crawl_site listed");
        assert_eq!(site["inputSchema"]["required"], json!(["url"]));
        let desc = site["description"].as_str().unwrap();
        // Steers the model to whole-site crawls and away from looping the single-page tools.
        assert!(desc.contains("WHOLE"));
        assert!(desc.contains("writ_crawl_status"));
        assert!(desc.contains("writ_workflow_data"));
        let status = listed
            .iter()
            .find(|v| v["name"] == "writ_crawl_status")
            .expect("writ_crawl_status listed");
        assert_eq!(status["inputSchema"]["required"], json!([]));
    }

    #[test]
    fn browser_use_is_the_front_door_with_optional_args() {
        let listed = entries();
        let bu = listed
            .iter()
            .find(|v| v["name"] == "writ_browser_use")
            .expect("writ_browser_use listed");
        // Nothing is required — the model can open blank and drive from a directive.
        assert_eq!(bu["inputSchema"]["required"], json!([]));
        let desc = bu["description"].as_str().unwrap();
        // Framed as THE browser front door, human-in-the-loop, save-on-demand.
        assert!(desc.contains("Writ IS your browser"));
        assert!(desc.contains("writ_browser_act"));
        assert!(desc.to_ascii_uppercase().contains("ON DEMAND"));
        assert!(desc.contains("2FA") || desc.contains("credential"));
    }

    #[tokio::test]
    async fn crawl_status_lists_and_404s() {
        let st = state().await;
        #[cfg(not(feature = "cloud"))]
        {
            // OSS self-host: crawls run locally, so an empty library → an empty list (never an error),
            // and a concrete unknown id is a relayable bad-argument.
            let listed = crawl_status(&st, &json!({})).await.unwrap();
            let text = listed["content"][0]["text"].as_str().unwrap();
            let parsed: Value = serde_json::from_str(text).unwrap();
            assert_eq!(parsed["crawls"], json!([]));
            assert!(matches!(
                crawl_status(&st, &json!({"crawl_id": 424242})).await,
                Err(CallError::BadArgument(_))
            ));
        }
        #[cfg(feature = "cloud")]
        {
            // Managed app, UNLINKED: crawls never run locally, so a status poll is a relayable refusal
            // pointing at the cloud paths — not a local (empty) list.
            let out = crawl_status(&st, &json!({})).await.unwrap();
            assert_eq!(out["isError"], json!(true));
            let text = out["content"][0]["text"].as_str().unwrap();
            assert!(text.contains("cloud"));
        }
    }

    #[tokio::test]
    async fn crawl_site_refuses_or_relays_when_unlinked() {
        let st = state().await;
        let out = crawl_site(&st, &json!({"url": "http://127.0.0.1/admin"})).await.unwrap();
        // Managed + unlinked → CLOUD-only refusal (never runs the crawl locally). OSS build → the
        // loopback seed is an SSRF domain outcome the model relays. Both surface as isError.
        assert_eq!(out["isError"], json!(true));
        #[cfg(feature = "cloud")]
        {
            let text = out["content"][0]["text"].as_str().unwrap();
            assert!(text.contains("cloud fleet") && text.contains("writ_scrape"));
        }
    }

    #[test]
    fn scrape_and_map_are_listed_and_cloud_tiered() {
        let listed = entries();
        for name in ["writ_scrape", "writ_map"] {
            let t = listed
                .iter()
                .find(|v| v["name"] == name)
                .unwrap_or_else(|| panic!("{name} listed"));
            assert_eq!(t["inputSchema"]["required"], json!(["url"]));
            let desc = t["description"].as_str().unwrap();
            // Framed as cloud-run with a keyless fallback — never local on the managed app.
            assert!(desc.contains("Writ Cloud"));
            assert!(desc.to_ascii_lowercase().contains("keyless"));
        }
    }

    #[cfg(feature = "cloud")]
    #[test]
    fn cloud_crawl_view_normalizes_fleet_shape_to_the_local_crawl_schema() {
        // A cloud `_view`: brand is {crawl,agent}, id (not crawl_id), shards instead of workers,
        // no is_terminal flag. cloud_crawl_view must fold it into the SAME shape crawl_view emits.
        let cloud = json!({
            "id": 900123,
            "brand": {"crawl": "Dragnet", "agent": "Scribe"},
            "name": "Dragnet: example.com",
            "seed_url": "https://example.com",
            "status": "running",
            "workflow_id": 900124,
            "extract_mode": "markdown",
            "pages_discovered": 40, "pages_done": 12, "pages_failed": 1, "pages_skipped": 0,
            "shards_dispatched": 5, "shards_done": 2,
            "current_depth": 2,
            "error": null,
        });
        let v = cloud_crawl_view(&cloud);
        assert_eq!(v["crawl_id"], json!(900123)); // id → crawl_id
        assert_eq!(v["brand"], json!("Dragnet")); // {crawl,..} → plain string
        assert_eq!(v["workflow_id"], json!(900124));
        assert_eq!(v["workers_active"], json!(3)); // dispatched(5) - done(2)
        assert_eq!(v["is_terminal"], json!(false)); // derived from status
        assert_eq!(v["pages_done"], json!(12));

        // A terminal status flips is_terminal and clamps workers to 0.
        let done = cloud_crawl_view(&json!({
            "id": 1, "status": "completed", "shards_dispatched": 3, "shards_done": 3,
        }));
        assert_eq!(done["is_terminal"], json!(true));
        assert_eq!(done["workers_active"], json!(0));
        assert_eq!(done["brand"], json!("Dragnet")); // brand defaults when absent
    }

    #[cfg(feature = "cloud")]
    #[test]
    fn build_cloud_crawl_body_maps_mcp_params_to_the_fleet_request() {
        let p = crate::local::crawl::StartParams {
            seed_url: "https://example.com".into(),
            extract_mode: "schema".into(),
            persona_id: Some(7),
            include_paths: vec!["^/docs".into()],
            max_depth: 3,
            page_budget: 250,
            max_concurrent: 8,
            ..Default::default()
        };
        let body = build_cloud_crawl_body(&p);
        assert_eq!(body["url"], json!("https://example.com"));
        assert_eq!(body["extract_mode"], json!("schema"));
        assert_eq!(body["executor"], json!("regular")); // MCP has no AI-extract axis
        assert_eq!(body["persona_id"], json!(7));
        assert_eq!(body["include_paths"], json!(["^/docs"]));
        assert_eq!(body["max_depth"], json!(3));
        assert_eq!(body["page_budget"], json!(250));
        assert_eq!(body["max_concurrent_shards"], json!(8)); // local worker cap → fleet shard count
    }

    #[cfg(feature = "cloud")]
    #[tokio::test]
    async fn cloud_dataset_id_never_hijacks_names_or_local_workflows() {
        let st = state().await;
        // A name can only be a LOCAL workflow — never routed to the cloud dataset path.
        assert_eq!(cloud_dataset_id(&st, Some(&json!("my crawl"))).await.unwrap(), None);
        // A numeric id owned by a REAL local workflow stays local (local always wins).
        let wf = workflows::insert(
            &st.db,
            &workflows::NewWorkflow { name: "Local WF".into(), ..Default::default() },
        )
        .await
        .unwrap();
        assert_eq!(cloud_dataset_id(&st, Some(&json!(wf.id))).await.unwrap(), None);
        // A numeric id absent locally, but UNLINKED → still None (local resolver reports "no workflow").
        assert_eq!(cloud_dataset_id(&st, Some(&json!(987654))).await.unwrap(), None);
        // Missing arg → None (no crash).
        assert_eq!(cloud_dataset_id(&st, None).await.unwrap(), None);
    }

    #[cfg(feature = "cloud")]
    #[test]
    fn encode_query_value_escapes_search_terms_safely() {
        // Unreserved chars pass through; a space, `&`, and `=` are escaped so they can't corrupt the
        // forwarded `q=...&limit=...` string.
        assert_eq!(encode_query_value("blue widget"), "blue%20widget");
        assert_eq!(encode_query_value("a&b=c"), "a%26b%3Dc");
        assert_eq!(encode_query_value("price:$5.00_x-y~z"), "price%3A%245.00_x-y~z");
    }

    #[test]
    fn website_intent_tools_are_explicit_and_provider_free() {
        let listed = entries();
        for name in ["writ_record_website", "writ_website_to_api"] {
            let entry = listed
                .iter()
                .find(|v| v["name"] == name)
                .expect("intent tool listed");
            assert_eq!(entry["inputSchema"]["required"], json!(["goal", "url"]));
            assert!(entry["description"].as_str().unwrap().contains("LOCAL"));
        }

        let record = listed
            .iter()
            .find(|v| v["name"] == "writ_record_website")
            .unwrap();
        assert!(record["description"]
            .as_str()
            .unwrap()
            .contains("No Writ AI-provider key"));
        let api = listed
            .iter()
            .find(|v| v["name"] == "writ_website_to_api")
            .unwrap();
        assert!(api["description"]
            .as_str()
            .unwrap()
            .contains("connected MCP client"));
    }

    #[test]
    fn connected_actions_become_replayable_steps() {
        let click =
            crate::local::ai::session::action_to_step(&json!({"action":"click","selector":"#go"}))
                .unwrap();
        assert_eq!(click["type"], "click");
        assert_eq!(click["config"]["selector"], "#go");
        let extract = crate::local::ai::session::action_to_step(
            &json!({"action":"evaluate_js","script":"() => document.title","variable":"title"}),
        )
        .unwrap();
        assert_eq!(extract["type"], "evaluate");
        assert_eq!(extract["config"]["variable"], "title");
        let secret = crate::local::ai::session::action_to_step(&json!({"action":"fill","selector":"#password","value":"do-not-save","data_key":"password"})).unwrap();
        assert_eq!(secret["config"]["value"], "{{password}}");
        assert!(!secret.to_string().contains("do-not-save"));
        assert!(
            crate::local::ai::session::action_to_step(&json!({"action":"click","x":1,"y":2}))
                .is_none()
        );
    }

    #[test]
    fn step_brief_keeps_index_type_and_identity_without_full_configs() {
        let script: String = "x".repeat(5_000);
        let brief = step_brief(3, &json!({
            "type": "evaluate", "enabled": true, "_auth_fill": true,
            "config": { "script": script, "variable": "orders" },
        }));
        assert_eq!(brief["index"], 3);
        assert_eq!(brief["type"], "evaluate");
        assert_eq!(brief["auth_fill"], true);
        let rendered = brief.to_string();
        assert!(rendered.contains("variable=orders"));
        assert!(rendered.contains("script(5000 chars)"));
        assert!(rendered.len() < 300, "brief must stay bounded, got {} chars", rendered.len());

        let long_selector: String = "div > ".repeat(50);
        let clipped = step_brief(0, &json!({
            "type": "click", "config": { "selector": long_selector },
        }));
        assert!(clipped["summary"].as_str().unwrap().chars().count() < 100);
        assert!(clipped.get("auth_fill").is_none());
    }

    #[tokio::test]
    async fn non_static_name_falls_through() {
        let st = state().await;
        assert!(call(&st, "some_workflow_tool", &json!({})).await.is_none());
    }

    /// Build-time INSTALL-OVER-REBUILD: the compatibility filter is conservative — same-site
    /// candidates qualify, off-site ones only on a strong score, installed ones float first.
    #[cfg(feature = "cloud")]
    #[test]
    fn compatible_candidates_filter_is_conservative() {
        let cands = vec![
            json!({"slug": "weak-offsite", "target_site": "other.com", "score": 1.2}),
            json!({"slug": "same-site", "target_site": "amazon.com", "score": 0.9}),
            json!({"slug": "strong-offsite", "target_site": "other.com", "score": 3.4}),
            json!({"slug": "installed-same-site", "target_site": "amazon.com", "score": 1.0, "installed": true}),
        ];
        let out = filter_compatible_candidates(&cands, Some("amazon.com"));
        let slugs: Vec<&str> = out.iter().filter_map(|c| c["slug"].as_str()).collect();
        assert_eq!(slugs[0], "installed-same-site", "installed floats first");
        assert!(slugs.contains(&"same-site") && slugs.contains(&"strong-offsite"));
        assert!(!slugs.contains(&"weak-offsite"), "weak off-site never proposed");
        assert!(out.len() <= 3);
        // No host: only strong scores qualify.
        let out = filter_compatible_candidates(&cands, None);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["slug"], "strong-offsite");
    }

    /// venue='cloud' exposure returns the REAL public endpoint (no improvised UI steps): an
    /// existing cloud twin is reused without any network; a marketplace install maps to its slug
    /// run endpoint; unlinked gets the FREE-link guidance. The local venue always carries a
    /// remote_access hint so the first answer is complete.
    #[cfg(feature = "cloud")]
    #[tokio::test]
    async fn expose_cloud_returns_real_endpoints() {
        let st = state().await;
        let wf = workflows::insert(
            &st.db,
            &workflows::NewWorkflow { name: "Google Moments Api".into(), ..Default::default() },
        )
        .await
        .unwrap();

        // UNLINKED → free-link guidance, never an invented endpoint.
        let r = call(
            &st,
            "writ_expose_workflow_api",
            &json!({"workflow": wf.id, "venue": "cloud"}),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(r["isError"], true);
        assert!(r["content"][0]["text"].as_str().unwrap().contains("FREE"));

        crate::local::cloud::state::LinkState {
            account_id: "acct_1".into(),
            cloud_base_url: "https://api.writ.test".into(),
            ..Default::default()
        }
        .save(&st.db)
        .await
        .unwrap();

        // LINKED + existing cloud twin → the twin's run endpoint, reused WITHOUT any push.
        crate::local::store::cloud_sync_map::upsert(
            &st.db,
            crate::local::cloud::sync::ENTITY_WORKFLOW,
            wf.id,
            "wf_cloud_123",
            None,
            "local",
        )
        .await
        .unwrap();
        let r = call(
            &st,
            "writ_expose_workflow_api",
            &json!({"workflow": wf.id, "venue": "cloud"}),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(r["isError"], false, "{r}");
        let text = r["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("/api/automation/workflows/wf_cloud_123/run"), "{text}");
        assert!(text.contains("\"pushed_now\": false"), "twin reused, no push: {text}");

        // A marketplace install exposes through its slug run endpoint (cloud executes it).
        let proxy = crate::local::cloud::marketplace::ensure_proxy_workflow(
            &st.db,
            "price-watch",
            Some("Price Watch"),
        )
        .await
        .unwrap();
        let r = call(
            &st,
            "writ_expose_workflow_api",
            &json!({"workflow": proxy.id, "venue": "cloud"}),
        )
        .await
        .unwrap()
        .unwrap();
        let text = r["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("/api/marketplace/listings/price-watch/run"), "{text}");

        // venue='local' still answers with the loopback endpoint + a remote_access hint.
        let r = call(&st, "writ_expose_workflow_api", &json!({"workflow": wf.id}))
            .await
            .unwrap()
            .unwrap();
        let text = r["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("127.0.0.1"), "{text}");
        assert!(text.contains("remote_access") && text.contains("venue='cloud'"), "{text}");
    }

    /// Run data is fully reachable over MCP: cross-workflow run feed, per-run data by id, and
    /// free-text search across everything already collected (redacted by the Data engine).
    #[tokio::test]
    async fn run_data_is_searchable_and_retrievable_via_mcp() {
        let st = state().await;
        let wf = workflows::insert(
            &st.db,
            &workflows::NewWorkflow { name: "Price Watch".into(), ..Default::default() },
        )
        .await
        .unwrap();
        let run = runs::insert(
            &st.db,
            &runs::NewRun { workflow_id: Some(wf.id), ..Default::default() },
        )
        .await
        .unwrap();
        runs::complete(
            &st.db,
            run.id,
            Some(r#"{"success":true,"extracted_data":{"title":"Blue Widget","price":19.99}}"#),
            Some(1200),
        )
        .await
        .unwrap();

        // Cross-workflow free-text search finds the row, tagged with its workflow + run.
        let r = call(&st, "writ_search_data", &json!({"query": "widget"})).await.unwrap().unwrap();
        assert_eq!(r["isError"], false);
        let text = r["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("Blue Widget"), "{text}");
        assert!(text.contains("Price Watch"), "{text}");
        assert!(text.contains("run_id"), "{text}");

        // A miss is a clean no_matches, never an error.
        let r = call(&st, "writ_search_data", &json!({"query": "zebra"})).await.unwrap().unwrap();
        assert_eq!(r["isError"], false);
        assert!(r["content"][0]["text"].as_str().unwrap().contains("no_matches"));

        // The run feed works WITHOUT a workflow — latest runs across all, workflow names resolved.
        let r = call(&st, "writ_workflow_runs", &json!({})).await.unwrap().unwrap();
        let text = r["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("Price Watch") && text.contains("\"run_id\""), "{text}");

        // One specific run's data by id.
        let r = call(
            &st,
            "writ_workflow_data",
            &json!({"workflow": wf.id, "run_id": run.id}),
        )
        .await
        .unwrap()
        .unwrap();
        let text = r["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("19.99"), "{text}");

        // A run_id from another workflow is refused.
        let other = workflows::insert(
            &st.db,
            &workflows::NewWorkflow { name: "Other".into(), ..Default::default() },
        )
        .await
        .unwrap();
        let r = call(
            &st,
            "writ_workflow_data",
            &json!({"workflow": other.id, "run_id": run.id}),
        )
        .await
        .unwrap();
        assert!(matches!(r, Err(CallError::BadArgument(_))));
    }

    /// EVERY workflow born through MCP is automatically MCP-exposED: saved recordings (plain and
    /// api) persist an EXPLICIT `connect.mcp = true` and appear in the derived-tool catalog
    /// immediately — callable without waiting for a tools/list refresh.
    #[tokio::test]
    async fn mcp_built_workflows_are_mcp_exposed() {
        let st = state().await;
        let steps = vec![
            json!({"type":"click","config":{"selector":"#a"}}),
            json!({"type":"click","config":{"selector":"#b"}}),
        ];
        for (sid, api, name) in [
            ("sess_expose_plain", false, "Mcp Plain Recording"),
            ("sess_expose_api", true, "Mcp Api Build"),
        ] {
            connected_sessions().lock().unwrap().insert(
                sid.into(),
                ConnectedBrowserSession {
                    goal: "test goal".into(),
                    name: name.into(),
                    entry_url: "https://example.com".into(),
                    api,
                    use_mode: false,
                    steps: steps.clone(),
                    fill_data: HashMap::new(),
                    secret_refs: HashMap::new(),
                    functions: if api {
                        vec![json!({"name":"get_data","type":"dom"})]
                    } else {
                        Vec::new()
                    },
                    last_used_ms: Arc::new(AtomicI64::new(now_ms())),
                },
            );
            let r = call(&st, "writ_browser_save", &json!({"session_id": sid}))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(r["isError"], false, "{r}");
            let body: Value =
                serde_json::from_str(r["content"][0]["text"].as_str().unwrap()).unwrap();
            assert_eq!(body["status"], "saved", "{body}");
            assert!(body["mcp_tool"].as_str().is_some_and(|t| !t.is_empty()));
            let wf_id = body["workflow_id"].as_i64().unwrap();
            let wf = workflows::get_by_id(&st.db, wf_id).await.unwrap().unwrap();
            assert!(wf.connect_surfaces().mcp, "'{name}' must expose MCP");
            assert_eq!(wf.is_active, 1, "'{name}' must be active");
            let catalog = crate::local::mcp::tools::catalog(&st).await.unwrap();
            assert!(
                catalog.iter().any(|t| t.workflow_id == wf_id),
                "'{name}' missing from the live MCP catalog"
            );
            if api {
                let s = wf.connect_surfaces();
                assert!(s.rest && s.openai, "api builds also enable the local API surfaces");
            }
        }
    }

    /// The build ladder's FIRST rung: the user's own saved workflows are proposed before any
    /// marketplace lookup or recording — and `skip_existing=true` steps past them. Deterministic
    /// (no cloud): the unlinked test state skips the marketplace rung, so the skip call lands on
    /// the recorder gate, proving the full ladder order own → marketplace → record.
    #[tokio::test]
    async fn api_build_proposes_own_workflows_first() {
        let st = state().await;
        workflows::insert(
            &st.db,
            &workflows::NewWorkflow {
                name: "Google Popular Times".into(),
                description: Some("Extract popular times for a place".into()),
                entry_url: Some("https://www.google.com/maps".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let args = json!({"goal": "get google popular times data", "url": "https://google.com/maps"});
        let r = call(&st, "writ_website_to_api", &args).await.unwrap().unwrap();
        assert_eq!(r["isError"], false);
        let text = r["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("existing_workflows"), "{text}");
        assert!(text.contains("Google Popular Times"), "{text}");
        assert!(text.contains("writ_run_workflow"), "teaches replay: {text}");

        // Declined → skip_existing continues the ladder (unlinked ⇒ no marketplace ⇒ recorder).
        let r = call(
            &st,
            "writ_website_to_api",
            &json!({"goal": "get google popular times data", "url": "https://google.com/maps", "skip_existing": true}),
        )
        .await
        .unwrap();
        assert!(
            matches!(r, Err(CallError::BadArgument(ref m)) if m.contains("local browser")),
            "past both proposal rungs: {r:?}"
        );
    }

    /// Own-library matcher stays conservative: host match or strong term coverage only.
    #[test]
    fn match_own_workflows_is_conservative() {
        let mk = |id: i64, name: &str, entry: Option<&str>| {
            let mut w = make_wf_like(id, name);
            w.entry_url = entry.map(str::to_string);
            w
        };
        let rows = vec![
            mk(1, "Google Popular Times", Some("https://www.google.com/maps")),
            mk(2, "Amazon Price Watch", Some("https://amazon.com")),
            mk(3, "Daily News Digest", None),
        ];
        // Term coverage match (no host given).
        let m = match_own_workflows(&rows, "google popular times as an api", None);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0]["name"], "Google Popular Times");
        // Host match qualifies even with weak terms.
        let m = match_own_workflows(&rows, "product tracker", Some("amazon.com"));
        assert_eq!(m.len(), 1);
        assert_eq!(m[0]["name"], "Amazon Price Watch");
        // Nothing related → empty (never hijack the build).
        assert!(match_own_workflows(&rows, "weather forecast", Some("meteo.fr")).is_empty());
        // Projections are compact — no steps ever.
        assert!(m[0].get("steps").is_none());
    }

    fn make_wf_like(id: i64, name: &str) -> workflows::Workflow {
        workflows::Workflow {
            id,
            name: name.into(),
            description: None,
            workflow_type: "recorded".into(),
            steps: "[]".into(),
            raw_replay: None,
            form_data: None,
            exit_condition: None,
            input_rules: None,
            api_functions: None,
            streaming_config: None,
            functions: None,
            credentials_encrypted: None,
            entry_url: None,
            timeout_ms: 0,
            retry_count: 0,
            headless: 1,
            fast_mode: 0,
            is_active: 1,
            is_verified: 0,
            schedule_enabled: 0,
            schedule_interval_ms: None,
            schedule_kind: None,
            schedule_time: None,
            schedule_days: None,
            schedule_tz: None,
            last_scheduled_at: None,
            next_scheduled_at: None,
            session_persistence: 0,
            session_ttl_seconds: None,
            login_url_patterns: None,
            relogin_max_retries: 0,
            http_capable: -1,
            auth_config: None,
            recorded_session_encrypted: None,
            recorded_session_captured_at: None,
            default_persona_id: None,
            estimated_duration_ms: None,
            usage_count: 0,
            total_run_count: 0,
            total_failure_count: 0,
            consecutive_failures: 0,
            last_run_at: None,
            last_run_status: None,
            last_run_duration_ms: None,
            last_run_has_extracted_data: None,
            last_failure_at: None,
            last_failure_error: None,
            cloud_callable: 0,
            execution_target: None,
            ai_repair_enabled: 0,
            last_repaired_at: None,
            marketplace_slug: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: None,
        }
    }

    #[test]
    fn url_host_parses_and_never_guesses() {
        assert_eq!(url_host("https://www.amazon.com/dp/x?y=1").as_deref(), Some("amazon.com"));
        assert_eq!(url_host("amazon.com/deals").as_deref(), Some("amazon.com"));
        assert_eq!(url_host("http://shop.example.co.uk:8443/a").as_deref(), Some("shop.example.co.uk"));
        assert_eq!(url_host("localhost"), None, "no dot → no host");
        assert_eq!(url_host("not a url"), None);
    }

    /// An API build on an UNLINKED app never detours through the marketplace: the proposal step is
    /// skipped and the build proceeds straight to the local browser (which the test state lacks —
    /// hence the recorder BadArgument, proving we got past the marketplace check).
    #[cfg(feature = "cloud")]
    #[tokio::test]
    async fn api_build_falls_through_to_recording_when_unlinked() {
        let st = state().await;
        let r = call(
            &st,
            "writ_website_to_api",
            &json!({"goal": "product prices API", "url": "https://example.com"}),
        )
        .await
        .unwrap();
        match r {
            Err(CallError::BadArgument(msg)) => {
                assert!(msg.contains("local browser"), "reached the recorder gate: {msg}")
            }
            Ok(v) => {
                let text = v["content"][0]["text"].as_str().unwrap_or_default();
                assert!(
                    !text.contains("marketplace_candidates"),
                    "must not propose marketplace listings when unlinked: {text}"
                );
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    /// Cloud-marketplace tools are PROPOSED only when the app is cloud-linked: hidden from
    /// tools/list while unlinked (but still safely callable with a link-guidance error, since a
    /// client may cache an older list), and advertised once a link exists.
    #[cfg(feature = "cloud")]
    #[tokio::test]
    async fn cloud_marketplace_tools_gated_on_link() {
        let st = state().await;

        // UNLINKED: not advertised…
        let listed = crate::local::mcp::tools::list_tools(&st).await.unwrap();
        let names: Vec<&str> = listed.iter().filter_map(|t| t["name"].as_str()).collect();
        for name in CLOUD_LINKED_NAMES {
            assert!(!names.contains(&name), "{name} must be hidden when unlinked");
        }
        // …but a call still gets a clear, non-protocol guidance error (no cloud call attempted),
        // and it tells the model to relay that linking is FREE.
        let r = call(&st, "writ_search_api", &json!({"query": "track prices"}))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r["isError"], true);
        let text = r["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("link"), "{text}");
        assert!(text.contains("FREE"), "the free-account nudge must survive: {text}");
        let r = call(&st, "writ_install_api", &json!({"slug": "x"}))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r["isError"], true, "install is link-gated too");

        // LINKED: both tools advertised; every other static tool unchanged.
        crate::local::cloud::state::LinkState {
            account_id: "acct_1".into(),
            email: "u@example.com".into(),
            ..Default::default()
        }
        .save(&st.db)
        .await
        .unwrap();
        let listed = crate::local::mcp::tools::list_tools(&st).await.unwrap();
        let names: Vec<&str> = listed.iter().filter_map(|t| t["name"].as_str()).collect();
        for name in NAMES {
            assert!(names.contains(&name), "{name} advertised when linked");
        }
    }

    /// `writ_install_api` on an ALREADY-INSTALLED listing elicits the manifest's required inputs
    /// and locally-missing vault secrets BEFORE any engine/cloud work, exactly like the persisted-
    /// workflow needs_input contract. Once the inputs are supplied it proceeds past the gate.
    #[cfg(feature = "cloud")]
    #[tokio::test]
    async fn install_api_prompts_for_manifest_inputs_before_engine() {
        let st = state().await;
        crate::local::cloud::state::LinkState {
            account_id: "acct_1".into(),
            ..Default::default()
        }
        .save(&st.db)
        .await
        .unwrap();

        // Seed an installed FREE listing (no cloud install / authorize path) whose manifest wants
        // one required input and one vault secret.
        installed_workflows::upsert(
            &st.db,
            &installed_workflows::NewInstall {
                slug: "price-watch".into(),
                listing_title: Some("Price Watch".into()),
                creator: Some("acme".into()),
                is_free: true,
                price_micros: None,
                proxy_cloud_id: None,
                sealed_recipe: "WF1:opaque_test_blob".into(),
                input_schema: Some(
                    r#"{"input_slots":[{"key":"product_url","label":"Product URL","required":true}],
                        "secret_slots":[{"key":"shop_password","label":"Shop password"}]}"#
                        .into(),
                ),
            },
        )
        .await
        .unwrap();

        // Missing input + missing vault secret → needs_input (isError:false), engine untouched.
        let r = call(&st, "writ_install_api", &json!({"slug": "price-watch"}))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r["isError"], false);
        let text = r["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("needs_input"), "{text}");
        assert!(text.contains("product_url"), "{text}");
        assert!(text.contains("shop_password"), "{text}");
        assert!(text.contains("Writ app"), "secrets are directed to the app vault: {text}");

        // Supplying the input still blocks on the vault secret (values never transit MCP).
        let r = call(
            &st,
            "writ_install_api",
            &json!({"slug": "price-watch", "inputs": {"product_url": "https://x"}}),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(r["isError"], false);
        assert!(r["content"][0]["text"].as_str().unwrap().contains("needs_input"));

        // With the secret present in the local vault, the elicitation gate clears and the tool
        // proceeds to the run path — which fails at unseal here (garbage sealed blob), proving we
        // got PAST needs_input without any cloud call.
        vault_secrets::insert(
            &st.db,
            &crate::local::store::vault_secrets::NewVaultSecret {
                key: "shop_password".into(),
                value_encrypted: "sealed".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let r = call(
            &st,
            "writ_install_api",
            &json!({"slug": "price-watch", "inputs": {"product_url": "https://x"}}),
        )
        .await
        .unwrap();
        match r {
            // Either shape proves the elicitation gate cleared and the RUN path was reached,
            // where the garbage sealed blob fails (never another needs_input).
            Err(CallError::Internal(_)) => {}
            Ok(v) => {
                assert_eq!(v["isError"], true, "run failure is a relayable error: {v}");
                let text = v["content"][0]["text"].as_str().unwrap_or_default();
                assert!(!text.contains("needs_input"), "gate must not re-trigger: {text}");
            }
            other => panic!("unexpected result past the input gate: {other:?}"),
        }

        // run=false never elicits nor runs — plain install summary.
        let r = call(
            &st,
            "writ_install_api",
            &json!({"slug": "price-watch", "run": false}),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(r["isError"], false);
        assert!(r["content"][0]["text"].as_str().unwrap().contains("installed"));
    }

    #[tokio::test]
    async fn build_requires_goal_and_url_without_calling_a_provider() {
        let st = state().await;
        let r = call(&st, "writ_build", &json!({})).await.unwrap();
        assert!(matches!(r, Err(CallError::BadArgument(_))));
        let r = call(&st, "writ_build", &json!({"goal": "watch a page"}))
            .await
            .unwrap();
        assert!(matches!(r, Err(CallError::BadArgument(msg)) if msg.contains("url")));
    }

    #[tokio::test]
    async fn mission_status_unknown_id_is_bad_argument() {
        let st = state().await;
        let r = call(&st, "writ_mission_status", &json!({"session_id": 999}))
            .await
            .unwrap();
        assert!(matches!(r, Err(CallError::BadArgument(_))));
    }

    #[tokio::test]
    async fn respond_refuses_secret_fields() {
        let st = state().await;
        // Seed a session paused on a secret question.
        let sess = concierge_sessions::insert(
            &st.db,
            &crate::local::store::concierge_sessions::NewConciergeSession {
                goal: "g".into(),
                platform: Some("desktop".into()),
                plan: None,
                transcript: None,
            },
        )
        .await
        .unwrap();
        concierge_sessions::update(
            &st.db,
            sess.id,
            &crate::local::store::concierge_sessions::ConciergeUpdate {
                status: Some("awaiting_input"),
                pending_request: Some(
                    r#"{"requests":[{"kind":"secret","field":"login_password","label":"Password"}]}"#,
                ),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let r = call(
            &st,
            "writ_mission_respond",
            &json!({
                "session_id": sess.id,
                "turn_seq": 0,
                "answers": { "login_password": "hunter2" },
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(r["isError"], true, "secret answer must be refused");
        let text = r["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("Writ app"), "directs to the app: {text}");
        assert!(!text.contains("hunter2"), "plaintext never echoed");
    }

    #[tokio::test]
    async fn workflow_resolution_by_name_id_and_alias() {
        let st = state().await;
        let wf = workflows::insert(
            &st.db,
            &workflows::NewWorkflow {
                name: "Daily Prices".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        for key in [
            json!(wf.id),
            json!(wf.id.to_string()),
            json!("Daily Prices"),
            json!(format!("workflow_{}", wf.id)),
        ] {
            let got = resolve_workflow(&st, Some(&key)).await.unwrap();
            assert_eq!(got.id, wf.id, "resolves via {key}");
        }
        assert!(resolve_workflow(&st, Some(&json!("nope"))).await.is_err());
        assert!(resolve_workflow(&st, None).await.is_err());
    }

    #[tokio::test]
    async fn expose_workflow_api_enables_rest_and_returns_loopback_endpoint() {
        let st = state().await;
        let wf = workflows::insert(
            &st.db,
            &workflows::NewWorkflow {
                name: "Local endpoint".into(),
                streaming_config: Some(r#"{"connect":{"rest":false,"openai":false}}"#.into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let result = call(
            &st,
            "writ_expose_workflow_api",
            &json!({"workflow": wf.id, "surface": "rest"}),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(result["isError"], false);
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains(&format!("127.0.0.1:{}", st.config.port)));
        assert!(text.contains(&format!("/v1/workflows/{}/run", wf.id)));
        assert!(text.contains("never sent through Claude/MCP"));

        let updated = workflows::get_by_id(&st.db, wf.id).await.unwrap().unwrap();
        let connect = updated.connect_surfaces();
        assert!(connect.rest);
        assert!(!connect.openai, "unrequested surface remains unchanged");
    }

    #[tokio::test]
    async fn set_schedule_daily_and_off_round_trip() {
        let st = state().await;
        let wf = workflows::insert(
            &st.db,
            &workflows::NewWorkflow {
                name: "sched".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        // daily needs a valid time + tz.
        let r = call(
            &st,
            "writ_set_schedule",
            &json!({"workflow": wf.id, "kind": "daily", "time": "08:30", "tz": "Europe/Paris"}),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(r["isError"], false);
        let updated = workflows::get_by_id(&st.db, wf.id).await.unwrap().unwrap();
        assert_eq!(updated.schedule_enabled, 1);
        assert_eq!(updated.schedule_kind.as_deref(), Some("daily"));
        assert_eq!(updated.schedule_time.as_deref(), Some("08:30"));
        assert_eq!(updated.schedule_tz.as_deref(), Some("Europe/Paris"));

        // Bad tz / bad time / bad weekly days are invalid params.
        for bad in [
            json!({"workflow": wf.id, "kind": "daily", "time": "8:305", "tz": "Europe/Paris"}),
            json!({"workflow": wf.id, "kind": "daily", "time": "08:30", "tz": "Mars/Olympus"}),
            json!({"workflow": wf.id, "kind": "weekly", "time": "08:30", "tz": "Europe/Paris", "days": [0, 8]}),
            json!({"workflow": wf.id, "kind": "interval"}),
        ] {
            let r = call(&st, "writ_set_schedule", &bad).await.unwrap();
            assert!(
                matches!(r, Err(CallError::BadArgument(_))),
                "rejected: {bad}"
            );
        }

        // off disables.
        let r = call(
            &st,
            "writ_set_schedule",
            &json!({"workflow": wf.id, "kind": "off"}),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(r["isError"], false);
        let updated = workflows::get_by_id(&st.db, wf.id).await.unwrap().unwrap();
        assert_eq!(updated.schedule_enabled, 0);
    }

    /// Every dataset tool must TELL the agent it can choose the output shape — in the
    /// tool DESCRIPTION, not only the property schema. Agents select and configure a
    /// tool off the description; a `format` arg nobody is told about goes unused.
    #[test]
    fn dataset_tools_advertise_format_choice_in_their_description() {
        let catalog = entries();
        for name in ["writ_dataset", "writ_dataset_search", "writ_workflow_data", "writ_search_data"] {
            let t = catalog
                .iter()
                .find(|t| t["name"] == name)
                .unwrap_or_else(|| panic!("{name} missing from the catalog"));
            let desc = t["description"].as_str().unwrap();
            assert!(
                desc.contains("format"),
                "{name}: description must tell the agent it can choose an output format"
            );
            assert!(
                desc.contains("markdown"),
                "{name}: description must name markdown as the readable choice"
            );
            // ...and the arg must actually exist on the schema it advertises.
            let props = &t["inputSchema"]["properties"];
            assert!(!props["format"].is_null(), "{name}: schema is missing the `format` property");
        }
    }

    /// `format=markdown` on the dataset tools must return the RENDERED prose, not
    /// JSON-escaped blobs — the whole point for an agent reading a crawl. Also pins
    /// that an unknown format is rejected rather than silently treated as json.
    #[tokio::test]
    async fn dataset_tools_render_markdown_and_reject_bad_format() {
        let st = state().await;
        let wf = workflows::insert(
            &st.db,
            &workflows::NewWorkflow { name: "pages".into(), ..Default::default() },
        )
        .await
        .unwrap();
        // A document-shaped run: a long `markdown` column => renders as documents.
        let body = "y".repeat(300);
        let run = runs::insert(
            &st.db,
            &runs::NewRun { workflow_id: Some(wf.id), ..Default::default() },
        )
        .await
        .unwrap();
        let payload = json!({
            "extracted_data": [{
                "url": "https://ex.test/a", "title": "Page A", "markdown": body
            }]
        })
        .to_string();
        runs::complete(&st.db, run.id, Some(&payload), Some(5)).await.unwrap();

        // markdown => rendered document, NOT a JSON envelope.
        let r = call(&st, "writ_dataset", &json!({"dataset": wf.id, "format": "markdown"}))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r["isError"], false);
        let text = r["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("## Page A"), "expected a rendered heading, got: {text:.120}");
        assert!(text.contains("<https://ex.test/a>"), "expected the source link");
        assert!(!text.contains("\"extracted_data\""), "must not be the JSON envelope");

        // json (default) still returns the documented envelope.
        let r = call(&st, "writ_dataset", &json!({"dataset": wf.id})).await.unwrap().unwrap();
        let text = r["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"records\""), "default must stay json");

        // An unknown format is a bad argument, not a silent json fallback.
        let e = call(&st, "writ_dataset", &json!({"dataset": wf.id, "format": "xml"})).await;
        assert!(
            matches!(e, Some(Err(CallError::BadArgument(_)))),
            "unknown format must be rejected"
        );
    }

    #[tokio::test]
    async fn workflow_data_empty_is_actionable() {
        let st = state().await;
        let wf = workflows::insert(
            &st.db,
            &workflows::NewWorkflow {
                name: "empty".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let r = call(&st, "writ_workflow_data", &json!({"workflow": wf.id}))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r["isError"], true);
        assert!(r["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("writ_run_workflow"));
    }

    #[tokio::test]
    async fn workflow_run_prompts_for_missing_inputs_before_engine() {
        let st = state().await;
        let wf = workflows::insert(
            &st.db,
            &workflows::NewWorkflow {
                name: "Needs data".into(),
                steps: Some(r##"[{"type":"fill","config":{"selector":"#q","value":"{{input.query}}"}},{"type":"fill","config":{"selector":"#u","value":"{{ username }}"}}]"##.into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let result = call(
            &st,
            "writ_run_workflow",
            &json!({"workflow":wf.id,"inputs":{"query":"rust"}}),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(result["isError"], false);
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("needs_input"));
        assert!(text.contains("username"));
        assert!(!text.contains("local browser is unavailable"));
    }

    #[test]
    fn connected_actions_cannot_extract_or_bake_browser_credentials() {
        let mut held = HashMap::new();
        held.insert("input.api_key".into(), "ps_REAL_SECRET_123".into());
        assert!(connected_action_rejection(
            &json!({"type":"evaluate_js","script":"sessionStorage.getItem('apiKey')"}),
            &held,
        ).is_some());
        assert!(connected_action_rejection(
            &json!({"type":"evaluate_js","script":"fetch('/api/targets')"}),
            &held,
        ).is_some());
        assert!(connected_action_rejection(
            &json!({"type":"api_call","headers":{"Authorization":"Bearer ps_REAL_SECRET_123"}}),
            &held,
        ).is_some());
        assert!(connected_action_rejection(
            &json!({"type":"api_call","headers":{"Authorization":"Bearer {{input.api_key}}"}}),
            &held,
        ).is_none());
    }

    #[test]
    fn connected_tool_data_is_bounded() {
        let large = json!({"rows": vec!["x".repeat(100); 200]});
        let compact = compact_tool_value(&large);
        assert_eq!(compact["truncated"], true);
        assert!(compact["preview"].as_str().unwrap().chars().count() <= 6_000);
    }

    #[test]
    fn generic_build_cannot_downgrade_explicit_api_intent() {
        assert!(goal_requests_api_builder("Login, then expose targets and workflows as a structured API"));
        assert!(goal_requests_api_builder("Turn this website into an API"));
        assert!(!goal_requests_api_builder("Record the website login workflow"));
    }

    #[test]
    fn http_dominance_removes_superseded_browser_route() {
        let mut steps = vec![
            json!({"type":"navigate","config":{"url":"https://x/login"}}),
            json!({"type":"fill","_auth_fill":true,"config":{"selector":"#key","value":"{{secret:k}}"}}),
            json!({"type":"click","config":{"selector":"button"}}),
            json!({"type":"navigate","config":{"url":"https://x/data"}}),
            json!({"type":"extract","config":{"selector":".row","variable":"rows"}}),
            json!({"type":"login_post","config":{"url":"https://x/api/login"}}),
            json!({"type":"api_call","config":{"url":"https://x/api/rows","variable":"rows"}}),
        ];
        dedupe_connected_outputs(&mut steps);
        collapse_http_dominated_workflow(&mut steps);
        let types: Vec<_> = steps.iter().filter_map(|s| s.get("type").and_then(Value::as_str)).collect();
        assert_eq!(types, vec!["login_post", "api_call"]);
    }
}
