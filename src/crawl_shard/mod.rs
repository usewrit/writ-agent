//! Dragnet — the LOCAL distributed-crawl orchestrator (desktop twin of the cloud
//! `services/crawl_orchestrator`). ONE crawl maps a whole site (robots + sitemap + link graph) and
//! fetches every in-scope page with a bounded, in-process worker pool — HTTP-first via the same
//! `reqwest` primitives the monitor checker uses, with a browser fallback for JS-rendered pages via
//! the engine's warm Chromium — extracting clean markdown per page (or replaying a prebuilt CSS
//! extractor). Every page's data lands under a synthetic per-crawl workflow so it aggregates through
//! the normal Workflow Data API + lineage dedup: one queryable dataset.
//!
//! Unlike the cloud (a Redis frontier + a fleet of agents), the desktop crawl runs on ONE machine:
//! the frontier + visited-set are in-process and the "shards" are just the bounded worker pool.
//! Politeness is enforced HERE — robots.txt per URL, a delay between fetches, and a hard concurrency
//! cap — the only place global rate can be bounded when the workers can't see each other.
//!
//! Admission is atomic within the single-threaded manager: a URL enters the frontier only if it is
//! newly-seen (visited-set), in domain/path/depth scope, SSRF-safe, and robots-allowed. Convergence
//! is frontier-empty + zero workers in flight. A crash leaves the row non-terminal with no loop
//! behind it (the frontier was in memory), so boot reconciliation (`crawl_jobs::interrupt_orphaned`)
//! fails it rather than stranding it "crawling" forever.

pub mod body_limit;
pub mod doc_extract;
pub mod extract;
pub mod robots;

// Local-daemon control-loop deps (SQLite store, app state) — only compiled for the
// `local`/fleet builds. The cloud `writ-agent` build excludes them; it uses ONLY the
// ungated shard runner below.
#[cfg(feature = "local")]
use crate::local::error::{LocalError, LocalResult};
#[cfg(feature = "local")]
use crate::local::server::AppState;
#[cfg(feature = "local")]
use crate::local::store::{automations, crawl_jobs, runs, workflows};
#[cfg(feature = "local")]
use crate::local::store::crawl_jobs::{CounterSnapshot, CrawlJob, NewCrawlJob};
use regex::Regex;
use serde_json::{json, Value};
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;
use url::Url;

/// A consistent real-browser UA (same string the monitor checker uses) so a site sees one crawler.
const CRAWL_UA: &str = crate::monitor::checker::DEFAULT_UA;

/// Below this main-content length, an HTTP-fetched 200 is treated as a JS shell → browser fallback.
const MIN_TEXT_FOR_HTTP: usize = 200;
// Read only by the `local`-gated whole-crawl control loop (it needs the SQLite store), but the
// unit tests below exercise these helpers in EVERY build — so scope a dead-code allowance to
// the configuration where they legitimately have no non-test caller, rather than `cfg`-ing the
// item out and breaking those tests.
#[cfg_attr(not(feature = "local"), allow(dead_code))]
/// Pages buffered before a dataset run is flushed (one `runs` row per batch, like a cloud shard).
const FLUSH_BATCH: usize = 25;
// Read only by the `local`-gated whole-crawl control loop (it needs the SQLite store), but the
// unit tests below exercise these helpers in EVERY build — so scope a dead-code allowance to
// the configuration where they legitimately have no non-test caller, rather than `cfg`-ing the
// item out and breaking those tests.
#[cfg_attr(not(feature = "local"), allow(dead_code))]
/// Absolute ceiling on sitemap URLs pulled during seeding (budget still applies on top).
const SITEMAP_HARD_CAP: usize = 5_000;
// Read only by the `local`-gated whole-crawl control loop (it needs the SQLite store), but the
// unit tests below exercise these helpers in EVERY build — so scope a dead-code allowance to
// the configuration where they legitimately have no non-test caller, rather than `cfg`-ing the
// item out and breaking those tests.
#[cfg_attr(not(feature = "local"), allow(dead_code))]
/// Ceiling on the in-process visited-set. `page_budget` bounds how many URLs are FETCHED, but the
/// visited set also remembers everything rejected after the scope test (robots-denied, SSRF-refused),
/// and an in-scope infinite URL space (calendars, faceted search) mints those forever. Well above any
/// real site's in-scope surface; past it, discovery stops rather than growing the set unboundedly.
const VISITED_HARD_CAP: usize = 200_000;

// --- Block / rate-limit detection (mirrors the cloud fleet agent) ------------
// A 429/403/captcha is the site REFUSING this agent, not a dead link: those URLs
// are reported `blocked` so the coordinator requeues them to a DIFFERENT agent/IP
// instead of dropping them, and the crawl backs off the host.
/// Statuses that mean "slow down" specifically.
const RATE_LIMIT_STATUSES: &[u16] = &[429];
/// Statuses that mean the host is refusing us (auth walls, WAF, legal blocks).
const BLOCK_STATUSES: &[u16] = &[401, 403, 407, 429, 451];
/// After this many CONSECUTIVE blocked fetches, treat the host as blocking THIS agent: stop
/// hammering it and hand every un-fetched URL back for redispatch elsewhere.
const CONSEC_BLOCK_ABORT: usize = 3;
/// Ceiling on an honored `Retry-After` (seconds) — a hostile header can't park a crawl for a day.
const RETRY_AFTER_MAX_S: u32 = 3600;

/// Markers of a captcha / JS bot-wall in an otherwise-200 body.
const CHALLENGE_MARKERS: &[&str] = &[
    "just a moment",
    "checking your browser",
    "cf-browser-verification",
    "cf_chl_opt",
    "/cdn-cgi/challenge-platform",
    "captcha-delivery.com",
    "g-recaptcha",
    "h-captcha",
    "hcaptcha.com",
    "px-captcha",
    "are you a robot",
    "enable javascript and cookies to continue",
    "access denied",
    "request unsuccessful. incapsula",
];

/// How much of a body is scanned for a challenge marker, in CHARACTERS (not bytes — see
/// [`classify_block`]). A bot wall declares itself in the first screenful; scanning further only
/// burns CPU on pages that are already capped at [`body_limit::HTML_MAX`].
const CHALLENGE_SCAN_CHARS: usize = 20_000;

/// `"rate_limited"` (429) | `"forbidden"` (401/403/407/451) | `"challenge"` (captcha / bot wall) |
/// `None` when this is a genuine failure (404, DNS, timeout) rather than a refusal.
fn classify_block(status: Option<u16>, body: &str) -> Option<&'static str> {
    if let Some(s) = status {
        if RATE_LIMIT_STATUSES.contains(&s) {
            return Some("rate_limited");
        }
        if BLOCK_STATUSES.contains(&s) {
            return Some("forbidden");
        }
    }
    if !body.is_empty() {
        // Byte-slicing a `&str` PANICS off a UTF-8 char boundary, and this body is attacker
        // controlled: `"a".repeat(19_999) + "€"` puts byte 20_000 mid-character. The panic used to
        // land on the shard MANAGER task (via `resolve_outcome`), so the coordinator's awaited
        // future never got its frame and hung forever; on the local path it bypassed
        // `if let Err(e) = run_crawl(..)` (a panic is not an `Err`) and stranded the row in
        // "crawling". Take a CHARACTER prefix instead — the markers are all ASCII, so scanning
        // whole chars loses nothing.
        let low: String = body
            .chars()
            .take(CHALLENGE_SCAN_CHARS)
            .flat_map(char::to_lowercase)
            .collect();
        if CHALLENGE_MARKERS.iter().any(|m| low.contains(m)) {
            return Some("challenge");
        }
    }
    None
}

/// Parse a `Retry-After` header (delta-seconds form only; an HTTP-date is ignored), clamped.
fn parse_retry_after(value: Option<&str>) -> Option<u32> {
    let v = value?.trim();
    v.parse::<u32>().ok().map(|s| s.min(RETRY_AFTER_MAX_S))
}

/// Caller parameters to start a crawl. Sensible defaults mirror the cloud contract, adapted to the
/// single-machine scope (`max_concurrent` is the local worker cap, not a fleet shard count).
#[derive(Debug, Clone)]
pub struct StartParams {
    pub seed_url: String,
    pub name: Option<String>,
    pub extract_mode: String,
    pub extract_schema: Option<Value>,
    pub persona_id: Option<i64>,
    pub include_paths: Vec<String>,
    pub exclude_paths: Vec<String>,
    pub max_depth: i64,
    pub page_budget: i64,
    pub max_concurrent: i64,
    pub delay_ms: i64,
    pub respect_robots: bool,
    pub same_domain: bool,
    pub allow_subdomains: bool,
    /// Content-selection spec (preset/include_comments/exclude_selectors/include_selectors/keep),
    /// or None for default extraction. Persisted to `crawl_jobs.content_spec` and honored per page.
    pub content: Option<Value>,
    pub concierge_session_id: Option<i64>,
}

impl Default for StartParams {
    fn default() -> Self {
        Self {
            seed_url: String::new(),
            name: None,
            extract_mode: "markdown".into(),
            extract_schema: None,
            persona_id: None,
            include_paths: Vec::new(),
            exclude_paths: Vec::new(),
            max_depth: 3,
            page_budget: 500,
            max_concurrent: 4,
            delay_ms: 250,
            respect_robots: true,
            same_domain: true,
            allow_subdomains: true,
            content: None,
            concierge_session_id: None,
        }
    }
}

/// Validate the seed, mint the synthetic per-crawl workflow + the `crawl_jobs` row, and kick off the
/// crawl on a background task so the caller returns immediately with the queued row.
#[cfg(feature = "local")]
pub async fn start_crawl(state: &AppState, params: StartParams) -> LocalResult<CrawlJob> {
    // Normalize the seed (bare domain → https://) and SSRF-vet it up front.
    let seed = normalize_and_vet_seed(&params.seed_url).await?;

    let extract_mode = if params.extract_mode == "schema" { "schema" } else { "markdown" };
    let host = host_of(&seed);
    let name = params.name.clone().filter(|s| !s.trim().is_empty()).unwrap_or_else(|| {
        format!("Dragnet: {}", if host.is_empty() { seed.clone() } else { host.clone() })
    });

    // Mint the synthetic workflow the shard datasets aggregate under (Workflow Data API). A single
    // `crawl_batch` marker step mirrors the cloud's synthetic-workflow shape.
    let steps = json!([{
        "id": "1",
        "type": "crawl_batch",
        "config": { "extract_mode": extract_mode, "delay_ms": params.delay_ms },
    }])
    .to_string();
    let wf = workflows::insert(
        &state.db,
        &workflows::NewWorkflow {
            name: name.clone(),
            workflow_type: Some("crawl".into()),
            steps: Some(steps),
            form_data: Some("{}".into()),
            default_persona_id: params.persona_id,
            ..Default::default()
        },
    )
    .await?;

    let include_paths = serde_json::to_string(&params.include_paths).unwrap_or_else(|_| "[]".into());
    let exclude_paths = serde_json::to_string(&params.exclude_paths).unwrap_or_else(|_| "[]".into());
    let extract_schema = params
        .extract_schema
        .as_ref()
        .map(|v| serde_json::to_string(v).unwrap_or_default());
    let content_spec = params
        .content
        .as_ref()
        .filter(|v| !v.is_null())
        .map(|v| serde_json::to_string(v).unwrap_or_default());

    let crawl = crawl_jobs::insert(
        &state.db,
        &NewCrawlJob {
            name,
            seed_url: seed,
            include_paths: Some(include_paths),
            exclude_paths: Some(exclude_paths),
            max_depth: Some(params.max_depth.clamp(0, 20)),
            same_domain: Some(params.same_domain as i64),
            allow_subdomains: Some(params.allow_subdomains as i64),
            extract_mode: Some(extract_mode.into()),
            extract_schema,
            content_spec,
            persona_id: params.persona_id,
            respect_robots: Some(params.respect_robots as i64),
            delay_ms: Some(params.delay_ms.clamp(0, 60_000)),
            max_concurrent: Some(params.max_concurrent.clamp(1, 32)),
            page_budget: Some(params.page_budget.clamp(1, 50_000)),
            concierge_session_id: params.concierge_session_id,
        },
    )
    .await?;
    crawl_jobs::set_workflow_id(&state.db, crawl.id, wf.id).await?;

    // Run the crawl off the request path so the API returns the queued row immediately.
    let st = state.clone();
    let id = crawl.id;
    tokio::spawn(async move {
        if let Err(e) = run_crawl(st.clone(), id).await {
            tracing::warn!(crawl_id = id, error = %e, "crawl loop errored; finalizing failed");
            let _ = crawl_jobs::finalize(&st.db, id, "failed", Some(&e.to_string())).await;
        }
    });

    // Return the row WITH its workflow id populated.
    crawl_jobs::get_by_id(&state.db, crawl.id)
        .await?
        .ok_or_else(|| LocalError::Internal("crawl vanished after insert".into()))
}

/// Normalize a seed URL (bare domain → `https://`) and SSRF-vet it. Shared by [`start_crawl`] and the
/// standalone [`scrape_one`] / [`map_site`] entry points so every local fetch goes through one gate.
#[cfg(feature = "local")]
async fn normalize_and_vet_seed(raw: &str) -> LocalResult<String> {
    let mut seed = raw.trim().to_string();
    if seed.is_empty() {
        return Err(LocalError::BadRequest("A URL is required.".into()));
    }
    if !seed.starts_with("http://") && !seed.starts_with("https://") {
        seed = format!("https://{seed}");
    }
    if !crate::security::url_guard::is_navigation_url_safe_async(&seed).await {
        return Err(LocalError::BadRequest(format!("URL is not allowed: {seed}")));
    }
    if Url::parse(&seed).is_err() {
        return Err(LocalError::BadRequest(format!("Invalid URL: {seed}")));
    }
    Ok(seed)
}

/// Scrape ONE page to clean markdown, LOCALLY on this machine (the OSS self-host answer to the cloud
/// keyless/metered scrape). SSRF-vets the URL, fetches it (HTTP), and extracts markdown honoring the
/// optional content-selection `content` spec. Same result shape as the cloud scrape (+ `tier`).
#[cfg(all(feature = "local", not(feature = "cloud")))]
pub async fn scrape_one(seed: &str, content: Option<&Value>) -> LocalResult<Value> {
    let url = normalize_and_vet_seed(seed).await?;
    let client = build_http_client();
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| LocalError::BadRequest(format!("Couldn't fetch {url}: {e}")))?;
    if !resp.status().is_success() {
        return Err(LocalError::BadRequest(format!(
            "Couldn't fetch {url} (HTTP {})",
            resp.status().as_u16()
        )));
    }
    // Bounded read (see `body_limit`): reqwest transparently gunzips, so an uncapped `text()` lets a
    // ~1 MB decompression bomb inflate to ~1 GB resident.
    let html = body_limit::read_text_capped(resp, body_limit::HTML_MAX)
        .await
        .map_err(|e| LocalError::BadRequest(format!("Couldn't read {url}: {e}")))?;
    let now = now_iso();
    // Extraction is CPU-bound and synchronous; keep it off the daemon's HTTP worker threads.
    let ex = extract_offloaded(html, url.clone(), 0, now, "markdown".into(), None, content.cloned())
        .await
        .map_err(|e| LocalError::BadRequest(format!("Couldn't extract {url}: {e}")))?;
    let markdown = ex
        .rows
        .first()
        .and_then(|r| r.get("markdown"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    Ok(json!({
        "verb": "scrape",
        "url": url,
        "title": if ex.title.is_empty() { Value::Null } else { json!(ex.title) },
        "format": "markdown",
        "markdown": markdown,
        "counts": { "chars": markdown.len(), "links": ex.links.len() },
        "tier": "self-host",
    }))
}

/// Map a site's URLs LOCALLY (OSS self-host): sitemap `<loc>`s + a homepage link harvest, deduped and
/// capped. `search` is accepted for API symmetry with the cloud map (local ranking is order-of-arrival).
#[cfg(all(feature = "local", not(feature = "cloud")))]
pub async fn map_site(seed: &str, _search: Option<&str>) -> LocalResult<Value> {
    let url = normalize_and_vet_seed(seed).await?;
    let client = build_http_client();
    let mut urls: Vec<String> = discover_sitemap_urls(&client, &url).await;
    // Homepage link harvest — covers sites without a sitemap.
    if let Ok(resp) = client.get(&url).send().await {
        if resp.status().is_success() {
            if let Ok(html) = body_limit::read_text_capped(resp, body_limit::HTML_MAX).await {
                let now = now_iso();
                if let Ok(ex) =
                    extract_offloaded(html, url.clone(), 0, now, "markdown".into(), None, None).await
                {
                    urls.extend(ex.links.into_iter().map(|l| l.url));
                }
            }
        }
    }
    // Dedupe with the cap applied AS WE GO: `.take()` after collecting still retains every URL a
    // hostile sitemap emitted (the `seen` set is unbounded otherwise).
    let mut seen = std::collections::HashSet::new();
    let mut deduped: Vec<Value> = Vec::new();
    for u in urls {
        if deduped.len() >= SITEMAP_HARD_CAP {
            break;
        }
        if seen.insert(u.clone()) {
            deduped.push(json!({ "url": u }));
        }
    }
    Ok(json!({
        "verb": "map",
        "url": url,
        "count": deduped.len(),
        "urls": deduped,
        "tier": "self-host",
    }))
}

/// Request cancellation. The running loop observes the flag between waves, drains in-flight workers,
/// and finalizes as `cancelled`. A crawl with no live loop (already terminal) is a no-op.
#[cfg(feature = "local")]
pub async fn cancel_crawl(state: &AppState, id: i64) -> LocalResult<bool> {
    crawl_jobs::request_cancel(&state.db, id).await
}

// --------------------------------------------------------------------------- //
// Distributed SHARD execution (coordinator-dispatched, fleet topology)         //
// --------------------------------------------------------------------------- //
//
// In the SELF-HOST fleet topology the COORDINATOR owns the frontier/scope/robots and hands each
// agent a *shard* — a batch of already-admitted `{url, depth}` — inside an `execute_workflow`
// message whose step type is `crawl_batch` and whose `trigger_context` carries `_crawl_shard` +
// `_crawl_extract`. The agent fetches exactly that batch (HTTP-first + browser fallback, markdown/
// schema extraction, link harvest) and returns the fleet-crawl wire contract under `result_data`;
// the coordinator's `on_shard_complete` counts pages, admits the harvested links one depth deeper,
// and re-pumps. This reuses the SAME per-URL pipeline the in-process desktop crawler uses
// (`fetch_and_extract` → `resolve_outcome`) — only the frontier differs (it lives on the coordinator
// here rather than in-process).

/// Max URLs fetched concurrently within ONE shard. The coordinator already bounds GLOBAL concurrency
/// via `max_concurrent_shards`; a shard is small (~25 urls), so a modest in-shard cap plus the
/// politeness delay is enough.
const SHARD_CONCURRENCY: usize = 6;
/// Cap on links returned to the coordinator from ONE shard (its frontier still de-dupes on top).
const SHARD_DISCOVERED_CAP: usize = 3_000;

/// One already-admitted URL in a coordinator shard.
#[derive(Clone)]
pub struct ShardItem {
    pub url: String,
    pub depth: i64,
}

/// The extraction spec that rides in a shard's `_crawl_extract`.
#[derive(Clone)]
pub struct ShardExtract {
    /// `"markdown"` | `"schema"`.
    pub mode: String,
    pub schema: Option<Value>,
    pub delay_ms: u64,
    /// `"auto"` | `"http"` | `"browser"` — how each page's bytes are obtained.
    pub render_mode: String,
    /// `"auto"` | `"off"` | `"force"` — OCR policy for non-HTML docs + scans.
    pub ocr_mode: String,
    /// Content-selection spec (preset + include/exclude CSS selectors + keep toggles) — which page
    /// ELEMENTS the markdown keeps. `None` ⇒ default (main-content isolation).
    pub content: Option<Value>,
}

/// One HTTP cookie restored from a persona session (authenticated crawl).
#[derive(Clone)]
pub struct ShardCookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
}

/// What a shard POSTs back — mirrors the cloud fleet-crawl wire contract exactly.
pub struct ShardResult {
    /// `"http"` | `"browser"` (whether any page needed the browser fallback).
    pub engine: &'static str,
    /// One `{url, status:"ok", title, depth, fetched_at}` per fetched page.
    pub pages: Vec<Value>,
    /// One `{url, reason}` per failed page.
    pub failed: Vec<Value>,
    /// Absolute http(s) links harvested across the shard (deduped) — the coordinator's next
    /// frontier. Back-compat: the URL-only view of `discovered_links`.
    pub discovered_urls: Vec<String>,
    /// The same links WITH their anchor text (`{url, text}`) — what the coordinator scores the
    /// frontier on when the crawl has a plain-English goal.
    pub discovered_links: Vec<Value>,
    /// URLs the host REFUSED (429 / 403 / captcha): `{url, depth, status, block_kind, retry_after}`.
    /// Not dead links — the coordinator requeues them onto a different agent/IP.
    pub blocked: Vec<Value>,
    /// True once the host blocked this agent on `CONSEC_BLOCK_ABORT` consecutive fetches: the shard
    /// gave up early and handed its remaining URLs back. Tells the coordinator to back off the host.
    pub agent_blocked: bool,
    /// The largest `Retry-After` the host asked for, in seconds (0 when it never said).
    pub retry_after: u32,
    /// Markdown row / schema records per page (aggregated by the Workflow Data API).
    pub extracted_data: Vec<Value>,
    /// Per-lane page tallies `{http, browser, doc, ocr}` for lane-weighted billing.
    pub lane_counts: Value,
}

impl ShardResult {
    fn into_result_data(self) -> Value {
        json!({
            "engine": self.engine,
            "pages": self.pages,
            "failed": self.failed,
            "discovered_urls": self.discovered_urls,
            "discovered_links": self.discovered_links,
            "blocked": self.blocked,
            "agent_blocked": self.agent_blocked,
            "retry_after": self.retry_after,
            "extracted_data": self.extracted_data,
            "lane_counts": self.lane_counts,
        })
    }
}

/// Build a minimal per-shard [`CrawlConfig`]. Scope/robots/depth/budget are the COORDINATOR's job
/// (the URLs arrive pre-admitted), so those fields are inert here — only the extraction spec,
/// politeness delay, browser availability, and auth cookies matter for fetching the batch.
fn build_shard_config(spec: &ShardExtract, cookies: Vec<ShardCookie>, browser_available: bool) -> CrawlConfig {
    CrawlConfig {
        seed_host: String::new(),
        seed_reg: String::new(),
        same_domain: false,
        allow_subdomains: true,
        include_res: Vec::new(),
        exclude_res: Vec::new(),
        max_depth: 0,
        page_budget: 0,
        delay_ms: spec.delay_ms,
        respect_robots: false,
        extract_mode: if spec.mode == "schema" { "schema".into() } else { "markdown".into() },
        extract_schema: spec.schema.clone(),
        render_mode: spec.render_mode.clone(),
        ocr_mode: spec.ocr_mode.clone(),
        content: spec.content.clone(),
        browser_available,
        cookies,
        // Shard runs ship page thumbnails; the coordinator offloads them to storage.
        want_thumbnails: true,
    }
}

/// Execute ONE coordinator shard: fetch each URL (HTTP-first + browser fallback), extract, harvest
/// links. Reuses the exact per-URL pipeline of the in-process crawler; the frontier lives on the
/// coordinator, so there is no admission/scope pass here.
pub(crate) async fn run_crawl_shard(
    browser: Option<Arc<crate::browser::manager::BrowserManager>>,
    items: Vec<ShardItem>,
    spec: ShardExtract,
    cookies: Vec<ShardCookie>,
) -> ShardResult {
    let browser_available = browser.is_some();
    let cfg = Arc::new(build_shard_config(&spec, cookies, browser_available));
    let client = build_http_client();

    let mut queue: VecDeque<ShardItem> = items.into_iter().collect();
    let max_concurrent = SHARD_CONCURRENCY.min(queue.len().max(1));
    let mut join: JoinSet<WorkerOut> = JoinSet::new();

    let mut pages: Vec<Value> = Vec::new();
    let mut failed: Vec<Value> = Vec::new();
    let mut extracted: Vec<Value> = Vec::new();
    let mut discovered: Vec<extract::PageLink> = Vec::new();
    let mut seen_links: HashSet<String> = HashSet::new();
    let mut used_browser = false;
    // Per-lane page tallies for lane-weighted billing (http/browser/doc/ocr).
    let (mut n_http, mut n_browser, mut n_doc, mut n_ocr) = (0u64, 0u64, 0u64, 0u64);
    // --- Block / rate-limit tracking ---------------------------------------
    // A refusal is not a dead link: collect those URLs so the coordinator requeues them onto a
    // different agent/IP. After CONSEC_BLOCK_ABORT refusals in a row the host is clearly blocking
    // THIS agent — stop hammering it and hand the un-fetched remainder back too.
    let mut blocked: Vec<Value> = Vec::new();
    let mut consec_block: usize = 0;
    let mut agent_blocked = false;
    let mut max_retry_after: u32 = 0;

    loop {
        // EARLY ABORT: the host has refused this agent on the last N fetches. Stop dispatching and
        // hand every un-fetched URL back as blocked, so the coordinator redispatches the remainder
        // to another agent/IP instead of us burning the whole batch against a wall. In-flight
        // workers are still drained below (their results are kept — they were already paid for).
        if agent_blocked {
            while let Some(it) = queue.pop_front() {
                blocked.push(json!({
                    "url": it.url,
                    "depth": it.depth,
                    "status": Value::Null,
                    "block_kind": "host_blocked_agent",
                    "retry_after": Value::Null,
                }));
            }
        }
        // Refill the concurrency window from the batch.
        while join.len() < max_concurrent {
            match queue.pop_front() {
                Some(it) => {
                    let item = FrontierItem { url: it.url, depth: it.depth };
                    join.spawn(fetch_and_extract(client.clone(), cfg.clone(), item));
                }
                None => break,
            }
        }
        if join.is_empty() {
            break;
        }
        let out = match join.join_next().await {
            Some(Ok(o)) => o,
            Some(Err(_)) => continue, // a panicked worker: can't attribute the url — skip it
            None => break,
        };
        // The HTTP lane flags a browser retry via NeedsBrowser; record that for the `engine` field
        // BEFORE the outcome is moved into resolve_outcome.
        if matches!(out.outcome, PageOutcome::NeedsBrowser { .. }) {
            used_browser = true;
        }
        let now = now_iso();
        let url = out.url.clone();
        let depth = out.depth;
        match resolve_outcome(browser.as_ref(), &cfg, url.clone(), depth, out.outcome, &now).await {
            PageOutcome::Extracted { title, rows, links, favicon, content_kind, lane, screenshot } => {
                match lane {
                    "browser" => n_browser += 1,
                    "doc" => n_doc += 1,
                    "ocr" => n_ocr += 1,
                    _ => n_http += 1,
                }
                consec_block = 0; // a real page ends any run of refusals
                // A light JPEG of the rendered page. Wire transport ONLY — the coordinator moves it
                // to storage and rewrites the field to a served path, so it never persists inline.
                let shot_b64 = screenshot.as_ref().map(|b| {
                    use base64::Engine as _;
                    base64::engine::general_purpose::STANDARD.encode(b)
                });
                let mut page = json!({
                    "url": url,
                    "status": "ok",
                    "title": title,
                    "depth": depth,
                    "fetched_at": now,
                    "content_kind": content_kind,
                });
                // The favicon is a plain public URL, stamped on the page META only — a crawl is one
                // site, so the UI derives the glyph from it rather than every dataset row carrying it.
                if let (Some(obj), Some(fav)) = (page.as_object_mut(), favicon.as_ref()) {
                    obj.insert("favicon".into(), json!(fav));
                }
                if let (Some(obj), Some(b64)) = (page.as_object_mut(), shot_b64.as_ref()) {
                    obj.insert("screenshot_b64".into(), json!(b64));
                }
                pages.push(page);
                // The thumbnail is stamped on the PAGE only, never on every row. A schema page can
                // match tens of thousands of elements, and a ~100 KB base64 JPEG per row means
                // gigabytes held until the shard completes and then serialized onto the wire — for
                // bytes the coordinator would immediately dedup back down to one stored object
                // anyway. Rows carry `url`, which is the join key back to `pages[].screenshot_b64`.
                extracted.extend(rows);
                for l in links {
                    if discovered.len() >= SHARD_DISCOVERED_CAP {
                        break;
                    }
                    if seen_links.insert(l.url.clone()) {
                        discovered.push(l);
                    }
                }
            }
            PageOutcome::Blocked { kind, status, retry_after } => {
                consec_block += 1;
                if consec_block >= CONSEC_BLOCK_ABORT {
                    agent_blocked = true;
                }
                if let Some(ra) = retry_after {
                    max_retry_after = max_retry_after.max(ra);
                }
                blocked.push(json!({
                    "url": url,
                    "depth": depth,
                    "status": status,
                    "block_kind": kind,
                    "retry_after": retry_after,
                }));
                // Also reported as failed (with the refusal tagged) so page/failure counts stay
                // consistent with the cloud agent's contract.
                failed.push(json!({
                    "url": url,
                    "reason": format!("blocked ({kind})"),
                    "blocked": true,
                    "block_kind": kind,
                }));
            }
            PageOutcome::Failed { reason } => {
                consec_block = 0; // a plain failure is not a refusal
                failed.push(json!({ "url": url, "reason": reason }));
            }
            // resolve_outcome returns this only when the browser produced nothing and there was no
            // thin HTML to degrade to — a failed page.
            PageOutcome::NeedsBrowser { .. } => {
                failed.push(json!({ "url": url, "reason": "no content (browser unavailable)" }));
            }
        }
    }

    ShardResult {
        engine: if used_browser { "browser" } else { "http" },
        pages,
        failed,
        discovered_urls: discovered.iter().map(|l| l.url.clone()).collect(),
        discovered_links: discovered
            .iter()
            .map(|l| json!({ "url": l.url, "text": l.text }))
            .collect(),
        blocked,
        agent_blocked,
        retry_after: max_retry_after,
        extracted_data: extracted,
        lane_counts: json!({ "http": n_http, "browser": n_browser, "doc": n_doc, "ocr": n_ocr }),
    }
}

/// Parse a coordinator `execute_workflow` crawl shard out of its `config`, run it, and build the
/// reply-awaited `task_result` frame (payload under `result_data`, per the fleet-crawl contract).
/// ALWAYS returns a frame — an empty/garbled shard yields an empty (success) result so the
/// coordinator's awaited future resolves instead of hanging.
pub async fn run_shard_from_message(
    browser: Option<Arc<crate::browser::manager::BrowserManager>>,
    task_id: &str,
    config: &Value,
) -> Value {
    let tc = config
        .get("trigger_context")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let extract = tc.get("_crawl_extract").cloned().unwrap_or_else(|| json!({}));
    let mode = extract
        .get("mode")
        .and_then(|v| v.as_str())
        .unwrap_or("markdown")
        .to_string();
    let schema = extract.get("schema").cloned().filter(|v| !v.is_null());
    let render_mode = extract
        .get("render_mode")
        .and_then(|v| v.as_str())
        .filter(|s| matches!(*s, "auto" | "http" | "browser"))
        .unwrap_or("auto")
        .to_string();
    let ocr_mode = extract
        .get("ocr_mode")
        .and_then(|v| v.as_str())
        .filter(|s| matches!(*s, "auto" | "off" | "force"))
        .unwrap_or("auto")
        .to_string();
    // Politeness delay: prefer the extract spec, else the `crawl_batch` step config, else 0.
    let delay_ms = extract
        .get("delay_ms")
        .and_then(|v| v.as_i64())
        .or_else(|| {
            config
                .get("steps")
                .and_then(|s| s.as_array())
                .and_then(|a| a.first())
                .and_then(|s| s.get("config"))
                .and_then(|c| c.get("delay_ms"))
                .and_then(|v| v.as_i64())
        })
        .unwrap_or(0)
        .max(0) as u64;

    let items: Vec<ShardItem> = tc
        .get("_crawl_shard")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|it| {
                    let url = it.get("url").and_then(|v| v.as_str())?.to_string();
                    let depth = it.get("depth").and_then(|v| v.as_i64()).unwrap_or(0);
                    Some(ShardItem { url, depth })
                })
                .collect()
        })
        .unwrap_or_default();

    // Content-selection spec (which page elements the markdown keeps). Objects only; else None.
    let content = extract
        .get("content")
        .filter(|v| v.is_object())
        .cloned();

    let cookies = cookies_from_session(config.get("session_state"));
    let spec = ShardExtract { mode, schema, delay_ms, render_mode, ocr_mode, content };
    let result = run_crawl_shard(browser, items, spec, cookies).await;

    json!({
        "type": "task_result",
        "task_id": task_id,
        "success": true,
        "result_data": result.into_result_data(),
        "error": Value::Null,
    })
}

/// Restore persona session cookies from a workflow `session_state` (Playwright `storage_state` shape:
/// `{cookies:[{name,value,domain,path,...}], origins:[...]}`). Empty when unauthenticated.
fn cookies_from_session(session_state: Option<&Value>) -> Vec<ShardCookie> {
    let Some(ss) = session_state.filter(|v| !v.is_null()) else {
        return Vec::new();
    };
    let Some(cookies) = ss.get("cookies").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    cookies
        .iter()
        .filter_map(|c| {
            let name = c.get("name").and_then(|v| v.as_str())?.to_string();
            let value = c.get("value").and_then(|v| v.as_str())?.to_string();
            let domain = c
                .get("domain")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim_start_matches('.')
                .to_ascii_lowercase();
            let path = c
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("/")
                .to_string();
            Some(ShardCookie { name, value, domain, path })
        })
        .collect()
}

/// Build a `Cookie:` header value for `url` from the session cookies whose domain/path match. Returns
/// `None` when nothing matches (so the request goes out cookie-less rather than with an empty header).
fn cookie_header_for(url: &str, cookies: &[ShardCookie]) -> Option<String> {
    if cookies.is_empty() {
        return None;
    }
    let parsed = Url::parse(url).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    let path = parsed.path();
    let mut pairs: Vec<String> = Vec::new();
    for c in cookies {
        if c.domain.is_empty() {
            continue;
        }
        let host_match = host == c.domain || host.ends_with(&format!(".{}", c.domain));
        let path_match = c.path.is_empty() || c.path == "/" || path.starts_with(&c.path);
        if host_match && path_match {
            pairs.push(format!("{}={}", c.name, c.value));
        }
    }
    if pairs.is_empty() {
        None
    } else {
        Some(pairs.join("; "))
    }
}

// --------------------------------------------------------------------------- //
// Immutable per-crawl config the workers + manager share                       //
// --------------------------------------------------------------------------- //
#[cfg_attr(not(feature = "local"), allow(dead_code))]
struct CrawlConfig {
    seed_host: String,
    seed_reg: String,
    same_domain: bool,
    allow_subdomains: bool,
    include_res: Vec<Regex>,
    exclude_res: Vec<Regex>,
    max_depth: i64,
    page_budget: i64,
    delay_ms: u64,
    respect_robots: bool,
    extract_mode: String,
    extract_schema: Option<Value>,
    /// `"auto"` | `"http"` | `"browser"` — render strategy per page.
    render_mode: String,
    /// `"auto"` | `"off"` | `"force"` — OCR policy for the doc-extract lane.
    ocr_mode: String,
    /// Content-selection spec forwarded to `extract::extract` (which page elements to keep).
    content: Option<Value>,
    browser_available: bool,
    /// Persona session cookies for an authenticated crawl (empty otherwise). Applied by the HTTP
    /// lane; the local in-process crawler never sets these (it crawls logged-out).
    cookies: Vec<ShardCookie>,
    /// Capture a page thumbnail on every BROWSER-rendered page. Set for coordinator shards only —
    /// they ship it as `screenshot_b64` for the coordinator to move into storage. The local
    /// in-process crawler leaves it false so its SQLite rows stay lean.
    want_thumbnails: bool,
}

// Read only by the `local`-gated whole-crawl control loop (it needs the SQLite store), but the
// unit tests below exercise these helpers in EVERY build — so scope a dead-code allowance to
// the configuration where they legitimately have no non-test caller, rather than `cfg`-ing the
// item out and breaking those tests.
#[cfg_attr(not(feature = "local"), allow(dead_code))]
/// Live in-memory counters the manager accumulates and mirrors into the DB row.
#[derive(Default, Clone)]
struct Counters {
    discovered: i64,
    done: i64,
    failed: i64,
    skipped: i64,
    max_depth_seen: i64,
}

#[derive(Clone)]
struct FrontierItem {
    url: String,
    depth: i64,
}

/// What a worker (or the browser fallback) produced for one page.
enum PageOutcome {
    Extracted {
        title: String,
        rows: Vec<Value>,
        links: Vec<extract::PageLink>,
        /// The site's favicon URL parsed off the page (public URL; nothing stored).
        favicon: Option<String>,
        /// Row tag: `html` | `pdf` | `docx` | … | `ocr` — set on pages[] + rows.
        content_kind: String,
        /// Billing lane the page came through: `http` | `browser` | `doc` | `ocr`.
        lane: &'static str,
        /// Raw JPEG of the RENDERED page, when a thumbnail was requested (shard runs only). The
        /// shard runner base64s it onto the wire as `screenshot_b64`; the coordinator moves it into
        /// storage and rewrites it to a served path, so it never persists inline.
        screenshot: Option<Vec<u8>>,
    },
    /// HTTP came back but the content is a thin JS shell / an error status — retry with a browser.
    /// `thin_html` carries the HTTP body (if any) so a failed browser attempt can still degrade to it.
    NeedsBrowser { thin_html: Option<String> },
    /// The host REFUSED us (429 / 403 / captcha wall). Distinct from `Failed`: the URL is not dead,
    /// so the coordinator requeues it to a different agent instead of dropping it.
    Blocked {
        kind: &'static str,
        status: Option<u16>,
        retry_after: Option<u32>,
    },
    Failed { reason: String },
}

struct WorkerOut {
    url: String,
    depth: i64,
    outcome: PageOutcome,
}

// --------------------------------------------------------------------------- //
// The crawl loop                                                               //
// --------------------------------------------------------------------------- //
#[cfg(feature = "local")]
async fn run_crawl(state: AppState, id: i64) -> LocalResult<()> {
    let crawl = match crawl_jobs::get_by_id(&state.db, id).await? {
        Some(c) if !c.is_terminal() => c,
        _ => return Ok(()), // vanished or already terminal
    };
    let workflow_id = crawl.workflow_id.ok_or_else(|| LocalError::Internal("crawl has no workflow".into()))?;

    let cfg = Arc::new(build_config(&crawl, state.engine.browser().is_some()));
    let client = build_http_client();
    let mut robots = robots::RobotsCache::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut frontier: VecDeque<FrontierItem> = VecDeque::new();
    let mut counters = Counters::default();

    // --- Seed: robots + sitemap + homepage --------------------------------- //
    crawl_jobs::set_status(&state.db, id, "mapping").await?;
    admit(&cfg, &client, &mut robots, &mut visited, &mut frontier, &mut counters, &crawl.seed_url, 0).await;
    let sitemap_urls = discover_sitemap_urls(&client, &crawl.seed_url).await;
    for u in sitemap_urls.into_iter().take(SITEMAP_HARD_CAP) {
        if counters.discovered >= cfg.page_budget {
            break;
        }
        admit(&cfg, &client, &mut robots, &mut visited, &mut frontier, &mut counters, &u, 0).await;
    }
    crawl_jobs::set_status(&state.db, id, "crawling").await?;
    push_counters(&state.db, id, &counters, frontier.len() as i64).await;

    // --- Bounded worker pool ---------------------------------------------- //
    let max_concurrent = crawl.max_concurrent.max(1) as usize;
    let mut join: JoinSet<WorkerOut> = JoinSet::new();
    let mut buffer: Vec<Value> = Vec::new();
    let mut stopping = false;
    let mut cancel_poll: u32 = 0;

    loop {
        // Cancellation check (cheap local read; throttled to once per few waves).
        if !stopping {
            cancel_poll += 1;
            if cancel_poll.is_multiple_of(4) && crawl_jobs::is_cancel_requested(&state.db, id).await.unwrap_or(false) {
                stopping = true;
                frontier.clear();
            }
        }

        // Refill worker slots from the frontier (never while stopping).
        if !stopping {
            while join.len() < max_concurrent {
                match frontier.pop_front() {
                    Some(item) => {
                        join.spawn(fetch_and_extract(client.clone(), cfg.clone(), item));
                    }
                    None => break,
                }
            }
        }

        // Convergence: nothing running and nothing queued → done.
        if join.is_empty() {
            break;
        }

        // Await one worker; admit what it discovered, persist what it extracted.
        let Some(res) = join.join_next().await else { break };
        let out = match res {
            Ok(o) => o,
            Err(e) => {
                // A panicked worker: count it as one failed page and continue.
                counters.failed += 1;
                tracing::warn!(crawl_id = id, error = %e, "crawl worker panicked");
                push_counters(&state.db, id, &counters, join.len() as i64).await;
                continue;
            }
        };

        let now = now_iso();
        let _crawl_browser = state.engine.browser();
        let outcome = resolve_outcome(_crawl_browser.as_ref(), &cfg, out.url.clone(), out.depth, out.outcome, &now).await;
        match outcome {
            PageOutcome::Extracted { rows, links, .. } => {
                counters.done += 1;
                for r in rows {
                    buffer.push(r);
                }
                if !stopping {
                    for l in links {
                        if counters.discovered >= cfg.page_budget {
                            break;
                        }
                        admit(&cfg, &client, &mut robots, &mut visited, &mut frontier, &mut counters, &l.url, out.depth + 1)
                            .await;
                    }
                }
            }
            // The local crawler has no other agent to hand a refused URL to, so a block is simply a
            // failed page here (the coordinator path requeues it instead — see `run_crawl_shard`).
            PageOutcome::Blocked { kind, status, .. } => {
                counters.failed += 1;
                tracing::debug!(crawl_id = id, url = %out.url, kind, ?status, "crawl page blocked by host");
            }
            PageOutcome::Failed { reason } => {
                counters.failed += 1;
                tracing::debug!(crawl_id = id, url = %out.url, reason = %reason, "crawl page failed");
            }
            // resolve_outcome never returns NeedsBrowser (it resolves it).
            PageOutcome::NeedsBrowser { .. } => counters.failed += 1,
        }

        if buffer.len() >= FLUSH_BATCH {
            flush(&state.db, workflow_id, id, &mut buffer).await;
        }
        push_counters(&state.db, id, &counters, join.len() as i64).await;
    }

    // Final flush + finalize.
    flush(&state.db, workflow_id, id, &mut buffer).await;
    let final_status = if stopping { "cancelled" } else { "completed" };
    let _ = crawl_jobs::finalize(&state.db, id, final_status, None).await;
    tracing::info!(
        crawl_id = id,
        status = final_status,
        pages_done = counters.done,
        pages_failed = counters.failed,
        "crawl finished"
    );
    // Fire crawl-lifecycle automations so a flow can REACT to this crawl finishing
    // ("crawl finished → notify / run a workflow over the collected pages"). A user
    // cancel is deliberate and fires nothing. Best-effort — never fails the crawl.
    if final_status == "completed" {
        fire_crawl_lifecycle(&state, &crawl, workflow_id, &counters, "crawl_completed").await;
    }
    Ok(())
}

/// Dispatch the `crawl_*` lifecycle automations for a finished crawl. The desktop
/// daemon holds `AppState` here (unlike the flow interpreter's per-event call sites),
/// so it can drive the trigger engine directly. Mirrors the monitor runner's
/// change-automation dispatch. Best-effort: logs and swallows any error.
#[cfg(feature = "local")]
async fn fire_crawl_lifecycle(
    state: &AppState,
    crawl: &CrawlJob,
    workflow_id: i64,
    counters: &Counters,
    event: &str,
) {
    let autos = match automations::list_enabled_for_event(&state.db, event, 256).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(crawl_id = crawl.id, error = %e, "could not load crawl automations");
            return;
        }
    };
    if autos.is_empty() {
        return;
    }
    let seed_host = host_of(&crawl.seed_url);
    let context = json!({
        "crawl_id": crawl.id,
        "data_workflow_id": workflow_id,
        "crawl_workflow_id": workflow_id,
        "seed_url": crawl.seed_url,
        "seed_host": seed_host,
        "crawl_name": crawl.name,
        "status": crawl.status,
        "pages_done": counters.done,
        "pages_failed": counters.failed,
        "pages_discovered": counters.discovered,
    });
    for auto in autos {
        // Optional host filter on the event block (config.seed_host) — skip crawls of other sites.
        let want_host = auto
            .blocks
            .as_deref()
            .and_then(|b| serde_json::from_str::<Value>(b).ok())
            .and_then(|v| {
                v.as_array().and_then(|arr| {
                    arr.iter()
                        .find(|blk| blk.get("type").and_then(Value::as_str) == Some("event"))
                        .and_then(|blk| blk.get("config"))
                        .and_then(|c| c.get("seed_host"))
                        .and_then(Value::as_str)
                        .map(|s| s.to_string())
                })
            });
        if let Some(h) = want_host {
            if !h.trim().is_empty() && h != seed_host {
                continue;
            }
        }
        let trigger = crate::local::flow::FlowTrigger {
            event: event.to_string(),
            change_id: None,
            base_inputs: json!({}),
            context: context.clone(),
            source: crate::local::engine::RunSource::Monitor,
            lane: crate::local::engine::Lane::Background,
        };
        if let Err(e) = crate::local::flow::run_automation(&state.db, &state.engine, &auto, trigger).await {
            tracing::warn!(crawl_id = crawl.id, automation_id = auto.id, error = %e, "crawl automation failed");
        }
    }
}

/// What a single HTTP fetch produced. `text` is the charset-decoded body for
/// HTML-ish content types; `raw` is the undecoded body for binary docs (PDF /
/// office / image) so they can ride intact to doc-extract.
struct Fetched {
    status: u16,
    final_url: String,
    content_type: String,
    text: Option<String>,
    raw: Option<Vec<u8>>,
    /// `Retry-After` in seconds, when the host sent one (429/503). Rides back to the coordinator so
    /// the cross-crawl host cooldown honors the site's own ask.
    retry_after: Option<u32>,
}

/// True when a fetched resource is a document/image (not a web page). Positive
/// identification only — HTML is the default; mirrors the Python agent's
/// `_is_nonhtml`. The sidecar does the fine-grained kind routing.
fn is_nonhtml(content_type: &str, head: &[u8], url: &str) -> bool {
    let c = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let url_l = url.split('?').next().unwrap_or("").to_ascii_lowercase();

    // Magic bytes.
    if head.starts_with(b"%PDF") {
        return true;
    }
    let is_img = head.starts_with(b"\x89PNG")
        || head.starts_with(&[0xff, 0xd8, 0xff])
        || head.starts_with(b"GIF8")
        || head.starts_with(b"BM")
        || head.starts_with(b"II*\x00")
        || head.starts_with(b"MM\x00*")
        || (head.starts_with(b"RIFF") && head.len() >= 12 && &head[8..12] == b"WEBP");
    if is_img {
        return true;
    }
    let office_ct = c.contains("openxmlformats-officedocument")
        || c == "application/msword"
        || c == "application/vnd.ms-excel"
        || c == "application/vnd.ms-powerpoint";
    if head.starts_with(b"PK\x03\x04")
        && (office_ct
            || url_l.ends_with(".docx")
            || url_l.ends_with(".xlsx")
            || url_l.ends_with(".pptx"))
    {
        return true;
    }

    // Content-type.
    if c == "application/pdf" || office_ct || c.starts_with("image/") {
        return true;
    }
    if c == "application/json" || c == "text/json" || c.ends_with("+json") {
        return true;
    }
    if c == "text/csv" || c == "application/csv" || c == "text/tab-separated-values" {
        return true;
    }

    // URL-suffix fallback for octet-stream / empty content-types.
    if c.is_empty() || c == "application/octet-stream" {
        for suf in [
            ".pdf", ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt", ".json", ".csv",
            ".tsv", ".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tif", ".tiff",
        ] {
            if url_l.ends_with(suf) {
                return true;
            }
        }
    }
    false
}

/// First non-empty line, stripped of leading markdown markers (fallback title).
fn first_line(text: &str, limit: usize) -> String {
    for line in text.lines() {
        let s = line.trim().trim_start_matches(['#', '>', '-', '*', ' ']).trim();
        if !s.is_empty() {
            return s.chars().take(limit).collect();
        }
    }
    String::new()
}

/// Tag each object row with a `content_kind` (in place). Non-object rows untouched.
fn tag_content_kind(rows: &mut [Value], kind: &str) {
    for r in rows.iter_mut() {
        if let Some(obj) = r.as_object_mut() {
            obj.insert("content_kind".into(), Value::String(kind.to_string()));
        }
    }
}

/// Turn a doc-extract result into (title, rows, content_kind, lane). Mirrors the
/// Python agent's `_rows_from_doc_result`: schema mode surfaces structured
/// records; otherwise one markdown row (with `ocr_confidence` when OCR'd).
fn rows_from_doc(
    doc: &Value,
    url: &str,
    depth: i64,
    now: &str,
    mode: &str,
) -> (String, Vec<Value>, String, &'static str) {
    let content_kind = doc
        .get("content_kind")
        .or_else(|| doc.get("kind"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let md = doc
        .get("markdown")
        .and_then(|v| v.as_str())
        .or_else(|| doc.get("text").and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string();
    let title = doc
        .get("meta")
        .and_then(|m| m.get("title"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| first_line(&md, 200));

    let mut rows: Vec<Value> = Vec::new();
    if mode == "schema" {
        if let Some(recs) = doc.get("records").and_then(|v| v.as_array()) {
            for r in recs {
                if let Some(obj) = r.as_object() {
                    let mut m = obj.clone();
                    m.entry("_source_url").or_insert_with(|| Value::String(url.to_string()));
                    m.insert("content_kind".into(), Value::String(content_kind.clone()));
                    rows.push(Value::Object(m));
                }
            }
        }
    }
    if rows.is_empty() {
        let mut row = json!({
            "url": url,
            "title": title,
            "markdown": md,
            "word_count": md.split_whitespace().count(),
            "depth": depth,
            "fetched_at": now,
            "content_kind": content_kind,
        });
        if let Some(conf) = doc.get("ocr").and_then(|o| o.get("confidence")) {
            if !conf.is_null() {
                row["ocr_confidence"] = conf.clone();
            }
        }
        rows.push(row);
    }

    let lane = if content_kind == "ocr" { "ocr" } else { "doc" };
    (title, rows, content_kind, lane)
}

/// Wall-clock budget for ONE page's synchronous extraction. Generous enough that no legitimate page
/// trips it (a 2 MB document measured ~4 s before `strip_chrome` was made linear) and short enough
/// that a pathological one is abandoned rather than stalling a crawl slot.
const EXTRACT_BUDGET: Duration = Duration::from_secs(20);

/// Run [`extract::extract`] on the BLOCKING pool under a wall-clock budget.
///
/// WHY: `Html::parse_document`, `strip_chrome` and the markdown conversion are pure CPU with no
/// `.await` anywhere inside. Running them inline on a tokio worker — the same threads that host the
/// daemon's axum HTTP server — lets one hostile page stall every other task on that worker, and it
/// also makes any surrounding `tokio::time::timeout` INEFFECTIVE, because a timer can only fire at
/// an await point. `spawn_blocking` fixes both: the async workers stay responsive and the timeout can
/// actually elapse.
///
/// `scraper::Html` is deliberately NOT `Send` (see the `extract` module docs), so it is constructed
/// AND dropped entirely inside the closure — only owned `String`s go in and owned values come out.
///
/// A `spawn_blocking` task cannot be cancelled, so on timeout the thread runs to completion in the
/// background. That is acceptable and bounded: the input is capped at [`body_limit::HTML_MAX`], the
/// DOM depth is capped inside `extract`, and `strip_chrome` is linear — the timeout exists so the
/// CRAWL stops waiting on a bad page, not to kill the thread.
async fn extract_offloaded(
    html: String,
    base_url: String,
    depth: i64,
    fetched_at: String,
    mode: String,
    schema: Option<Value>,
    content: Option<Value>,
) -> Result<extract::PageExtract, String> {
    let job = tokio::task::spawn_blocking(move || {
        extract::extract(
            &html,
            &base_url,
            depth,
            &fetched_at,
            &mode,
            schema.as_ref(),
            content.as_ref(),
        )
    });
    match tokio::time::timeout(EXTRACT_BUDGET, job).await {
        Ok(Ok(ex)) => Ok(ex),
        Ok(Err(e)) => Err(format!("extraction task failed: {e}")),
        Err(_) => Err(format!("extraction exceeded {}s", EXTRACT_BUDGET.as_secs())),
    }
}

/// Resolve a worker outcome, running the (single-threaded, manager-side) browser fallback for a
/// `NeedsBrowser` page. Extraction is offloaded to the blocking pool (see [`extract_offloaded`]) —
/// the non-`Send` `scraper::Html` never crosses an `.await`.
async fn resolve_outcome(
    browser: Option<&Arc<crate::browser::manager::BrowserManager>>,
    cfg: &CrawlConfig,
    url: String,
    depth: i64,
    outcome: PageOutcome,
    now: &str,
) -> PageOutcome {
    let PageOutcome::NeedsBrowser { thin_html } = outcome else {
        return outcome;
    };
    // Try the warm browser for a JS-rendered render, when one is available.
    if let Some(browser) = browser {
        // A JPEG is captured when the OCR fallback might need it OR when the run wants page
        // thumbnails (shard runs only — the local crawler keeps its rows lean).
        let want_ocr_shot = cfg.ocr_mode != "off" && doc_extract::is_configured();
        let want_shot = want_ocr_shot || cfg.want_thumbnails;
        if let Some((final_url, html, shot)) = fetch_via_browser(browser, &url, want_shot).await {
            // Even a RENDERED page can be a bot wall (the browser solved nothing). Report it as a
            // refusal so the coordinator retries elsewhere rather than banking an empty page.
            // Checked BEFORE extraction so a wall never pays for a full parse.
            if let Some(kind) = classify_block(None, &html) {
                return PageOutcome::Blocked { kind, status: None, retry_after: None };
            }
            let ex = match extract_offloaded(
                html,
                final_url.clone(),
                depth,
                now.to_string(),
                cfg.extract_mode.clone(),
                cfg.extract_schema.clone(),
                cfg.content.clone(),
            )
            .await
            {
                Ok(ex) => ex,
                Err(reason) => return PageOutcome::Failed { reason },
            };
            let thumb = if cfg.want_thumbnails { shot.clone() } else { None };

            // Screenshot → OCR: rendered but the DOM produced almost no text
            // (canvas / image-only app) — OCR the screenshot as a last resort.
            if want_ocr_shot && ex.text_len < MIN_TEXT_FOR_HTTP {
                if let Some(png) = shot {
                    if let Some(doc) =
                        doc_extract::extract(&png, "image/jpeg", &final_url, &cfg.ocr_mode).await
                    {
                        let has_text = doc
                            .get("text")
                            .and_then(|v| v.as_str())
                            .map(|s| !s.trim().is_empty())
                            .unwrap_or(false);
                        if has_text {
                            let (title, rows, content_kind, _lane) =
                                rows_from_doc(&doc, &final_url, depth, now, &cfg.extract_mode);
                            // Keep the html-harvested links so discovery continues.
                            return PageOutcome::Extracted {
                                title,
                                rows,
                                links: ex.links,
                                favicon: ex.favicon,
                                content_kind,
                                lane: "ocr",
                                screenshot: thumb,
                            };
                        }
                    }
                }
            }

            let mut rows = ex.rows;
            tag_content_kind(&mut rows, "html");
            return PageOutcome::Extracted {
                title: ex.title,
                rows,
                links: ex.links,
                favicon: ex.favicon,
                content_kind: "html".into(),
                lane: "browser",
                screenshot: thumb,
            };
        }
    }
    // Browser unavailable / failed — degrade to the HTTP body if we captured one.
    if let Some(html) = thin_html {
        let ex = match extract_offloaded(
            html,
            url.clone(),
            depth,
            now.to_string(),
            cfg.extract_mode.clone(),
            cfg.extract_schema.clone(),
            cfg.content.clone(),
        )
        .await
        {
            Ok(ex) => ex,
            Err(reason) => return PageOutcome::Failed { reason },
        };
        let mut rows = ex.rows;
        tag_content_kind(&mut rows, "html");
        return PageOutcome::Extracted {
            title: ex.title,
            rows,
            links: ex.links,
            favicon: ex.favicon,
            content_kind: "html".into(),
            lane: "http",
            // No render happened, so there is no thumbnail (the favicon covers the HTTP lane).
            screenshot: None,
        };
    }
    PageOutcome::Failed { reason: "no content (HTTP failed, browser unavailable)".into() }
}

/// One worker: politeness delay, HTTP fetch, then synchronous extract. Returns owned data only, so
/// the future stays `Send` (the non-`Send` parse lives entirely inside `extract`, never across an
/// `.await`).
async fn fetch_and_extract(client: reqwest::Client, cfg: Arc<CrawlConfig>, item: FrontierItem) -> WorkerOut {
    if cfg.delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(cfg.delay_ms)).await;
    }
    // A browser retry is only allowed when a warm browser exists AND render_mode
    // isn't pinned to "http".
    let may_browser = cfg.browser_available && cfg.render_mode != "http";

    let mut fetched = match http_fetch(&client, &item.url, &cfg.cookies).await {
        Ok(f) => f,
        Err(reason) => {
            let outcome = if may_browser {
                PageOutcome::NeedsBrowser { thin_html: None }
            } else {
                PageOutcome::Failed { reason }
            };
            return WorkerOut { url: item.url, depth: item.depth, outcome };
        }
    };

    if fetched.status >= 400 {
        // REFUSAL vs failure. A 429/403/407/451 is the host turning US away — the URL is fine, this
        // agent (or its IP) isn't welcome. Report it `blocked` so the coordinator retries it on a
        // different agent rather than counting a dead link; a browser retry here would just burn a
        // render against the same wall. Anything else (404, 500, …) is a genuine failure, and an
        // HTML page may still render, so it keeps the browser-retry path.
        if let Some(kind) = classify_block(Some(fetched.status), "") {
            return WorkerOut {
                url: item.url,
                depth: item.depth,
                outcome: PageOutcome::Blocked {
                    kind,
                    status: Some(fetched.status),
                    retry_after: fetched.retry_after,
                },
            };
        }
        let outcome = if may_browser {
            PageOutcome::NeedsBrowser { thin_html: None }
        } else {
            PageOutcome::Failed { reason: format!("HTTP {}", fetched.status) }
        };
        return WorkerOut { url: item.url, depth: item.depth, outcome };
    }

    // --- Document lane: non-HTML (PDF / office / image / JSON / CSV) ----------
    // A document is a document regardless of render_mode — never render it in a
    // browser; forward the raw bytes to doc-extract (a Send-safe reqwest call, so
    // it runs right here in the worker, unlike the manager-side browser).
    // A short PREFIX is all `is_nonhtml` inspects (magic bytes, ≤12 of them). Copying 64 bytes here
    // instead of borrowing the whole body lets the body be MOVED below rather than cloned: the old
    // code cloned it before the size guard fired, doubling peak residency for every document fetch.
    let head: Vec<u8> = {
        let full: &[u8] = fetched
            .raw
            .as_deref()
            .or_else(|| fetched.text.as_deref().map(|s| s.as_bytes()))
            .unwrap_or(&[]);
        full[..full.len().min(64)].to_vec()
    };
    if is_nonhtml(&fetched.content_type, &head, &fetched.final_url) {
        // Moved, never cloned — and already capped at `body_limit::DOC_MAX` by `http_fetch`.
        let bytes: Vec<u8> = match fetched.raw.take() {
            Some(raw) => raw,
            None => fetched.text.take().unwrap_or_default().into_bytes(),
        };
        let outcome = if doc_extract::is_configured() {
            match doc_extract::extract(&bytes, &fetched.content_type, &fetched.final_url, &cfg.ocr_mode).await {
                Some(doc) => {
                    let now = now_iso();
                    let (title, rows, content_kind, lane) =
                        rows_from_doc(&doc, &fetched.final_url, item.depth, &now, &cfg.extract_mode);
                    PageOutcome::Extracted {
                        title, rows, links: Vec::new(), favicon: None, content_kind, lane,
                        screenshot: None,
                    }
                }
                None => PageOutcome::Failed {
                    reason: format!("non-html ({}); doc-extract failed", fetched.content_type),
                },
            }
        } else {
            PageOutcome::Failed {
                reason: format!("non-html ({}); doc-extract not configured", fetched.content_type),
            }
        };
        return WorkerOut { url: item.url, depth: item.depth, outcome };
    }

    // --- HTML lane -----------------------------------------------------------
    // Taken, not cloned (the body can be megabytes). `final_url`/`status`/`retry_after` are separate
    // fields and stay readable below.
    let html = fetched
        .text
        .take()
        .unwrap_or_else(|| String::from_utf8_lossy(&fetched.raw.take().unwrap_or_default()).into_owned());

    // A 200 that is really a captcha / JS bot-wall. Only worth reporting as a block
    // when we can't render: with a browser available, `auto`/`browser` render is
    // exactly how such a page is legitimately solved, so let it try first (a render
    // that still yields a wall comes back thin and is caught by the same check in
    // `resolve_outcome`).
    if !may_browser {
        if let Some(kind) = classify_block(None, &html) {
            return WorkerOut {
                url: item.url,
                depth: item.depth,
                outcome: PageOutcome::Blocked { kind, status: Some(fetched.status), retry_after: fetched.retry_after },
            };
        }
    }

    // render_mode=browser: always render this page in the manager's warm browser
    // (keep the HTTP body as a degrade fallback).
    if cfg.render_mode == "browser" && cfg.browser_available {
        return WorkerOut {
            url: item.url,
            depth: item.depth,
            outcome: PageOutcome::NeedsBrowser { thin_html: Some(html) },
        };
    }

    let now = now_iso();
    // The browser-escalation path needs the raw HTML back afterwards, and `extract_offloaded` takes
    // it by value (the blocking closure must own it), so keep one clone ONLY when a retry is
    // actually possible. When it isn't, the body is moved and never duplicated.
    let keep_for_browser = cfg.render_mode == "auto" && cfg.browser_available;
    let thin_html = if keep_for_browser { Some(html.clone()) } else { None };
    let ex = match extract_offloaded(
        html,
        fetched.final_url.clone(),
        item.depth,
        now,
        cfg.extract_mode.clone(),
        cfg.extract_schema.clone(),
        cfg.content.clone(),
    )
    .await
    {
        Ok(ex) => ex,
        Err(reason) => {
            return WorkerOut { url: item.url, depth: item.depth, outcome: PageOutcome::Failed { reason } }
        }
    };
    // auto: escalate a thin JS shell to the browser.
    let outcome = if keep_for_browser && ex.text_len < MIN_TEXT_FOR_HTTP {
        PageOutcome::NeedsBrowser { thin_html }
    } else {
        let mut rows = ex.rows;
        tag_content_kind(&mut rows, "html");
        PageOutcome::Extracted {
            title: ex.title, rows, links: ex.links, favicon: ex.favicon,
            content_kind: "html".into(), lane: "http",
            // HTTP lane: nothing was rendered, so there is no thumbnail.
            screenshot: None,
        }
    };
    WorkerOut { url: item.url, depth: item.depth, outcome }
}

/// HTTP GET → [`Fetched`]. Errors are stringified reasons (network/read failures). No longer
/// rejects non-HTML — a document body is returned as `raw` bytes for the doc-extract lane; an
/// HTML-ish body is charset-decoded into `text`. `cookies` (empty for an unauthenticated crawl)
/// are restored from a persona session and attached as a `Cookie:` header for the ones whose
/// domain/path match this URL — the HTTP lane's auth path.
async fn http_fetch(
    client: &reqwest::Client,
    url: &str,
    cookies: &[ShardCookie],
) -> Result<Fetched, String> {
    let mut req = client
        .get(url)
        .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        .header("Accept-Language", "en-US,en;q=0.9");
    if let Some(cookie) = cookie_header_for(url, cookies) {
        req = req.header(reqwest::header::COOKIE, cookie);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("fetch failed: {e}"))?;
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let retry_after = parse_retry_after(
        resp.headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok()),
    );
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();

    // Decode HTML-ish bodies as text (charset-aware via reqwest); keep everything
    // else as raw bytes so PDFs/office/images ride intact to doc-extract. JSON/CSV
    // are text but are still forwarded to the sidecar (its records lane).
    let texty = ct.is_empty()
        || ct.contains("html")
        || ct.contains("xml")
        || ct.starts_with("text/")
        || ct.contains("json")
        || ct.contains("csv");
    // BOUNDED reads (see `body_limit`). reqwest transparently gunzips, so an uncapped `text()`/
    // `bytes()` lets ~1 MB on the wire inflate to ~1 GB resident — an OOM from any crawled page.
    // JSON/CSV are "texty" but ride to the doc-extract lane, so they get the document budget; real
    // pages get the (much smaller) HTML budget.
    if texty {
        let limit = if ct.contains("json") || ct.contains("csv") || ct.contains("tab-separated") {
            body_limit::DOC_MAX
        } else {
            body_limit::HTML_MAX
        };
        let text = body_limit::read_text_capped(resp, limit)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Fetched { status, final_url, content_type: ct, text: Some(text), raw: None, retry_after })
    } else {
        let raw = body_limit::read_bytes_capped(resp, body_limit::DOC_MAX)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Fetched { status, final_url, content_type: ct, text: None, raw: Some(raw), retry_after })
    }
}

/// Browser fallback: render `url` in the engine's warm Chromium and return (final_url, html,
/// screenshot). Best effort — any error yields `None` and the caller degrades. When
/// `want_screenshot` is set, a viewport JPEG is captured for the screenshot→OCR fallback. A fresh
/// stealth context per page.
async fn fetch_via_browser(
    browser: &Arc<crate::browser::manager::BrowserManager>,
    url: &str,
    want_screenshot: bool,
) -> Option<(String, String, Option<Vec<u8>>)> {
    if browser.ensure_warm_browser_with(true).await.is_err() {
        return None;
    }
    // Re-vet the URL (defense-in-depth; admission already checked it).
    if !crate::security::url_guard::is_navigation_url_safe_async(url).await {
        return None;
    }
    let (context, page, _fp) = browser
        .create_stealth_context_full(None, Some(playwright_rs::Viewport { width: 1280, height: 800 }))
        .await
        .ok()?;
    let result = async {
        crate::browser::navigation::goto(&page, url, "domcontentloaded", Duration::from_secs(30)).await.ok()?;
        // Wait for the network to settle at the end of the load (bounded so a chatty
        // long-poll/streaming page can't hang the crawl).
        let _ = crate::browser::navigation::wait_for_load_state(&page, "networkidle", Duration::from_secs(8)).await;
        let final_url = crate::browser::page_query::get_url(&page).await;
        let html = crate::browser::page_query::get_content(&page).await.ok()?;
        let shot = if want_screenshot {
            crate::browser::page_query::screenshot_jpeg(&page, 80).await.ok()
        } else {
            None
        };
        Some((final_url, html, shot))
    }
    .await;
    let _ = context.close().await;
    result
}

// Read only by the `local`-gated whole-crawl control loop (it needs the SQLite store), but the
// unit tests below exercise these helpers in EVERY build — so scope a dead-code allowance to
// the configuration where they legitimately have no non-test caller, rather than `cfg`-ing the
// item out and breaking those tests.
#[cfg_attr(not(feature = "local"), allow(dead_code))]
// --------------------------------------------------------------------------- //
// Admission (manager-only, async: robots + SSRF)                               //
// --------------------------------------------------------------------------- //
#[allow(clippy::too_many_arguments)]
async fn admit(
    cfg: &CrawlConfig,
    client: &reqwest::Client,
    robots: &mut robots::RobotsCache,
    visited: &mut HashSet<String>,
    frontier: &mut VecDeque<FrontierItem>,
    counters: &mut Counters,
    raw_url: &str,
    depth: i64,
) {
    if depth > cfg.max_depth || counters.discovered >= cfg.page_budget {
        return;
    }
    let url = normalize_url(raw_url);
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return;
    }
    // SCOPE FIRST, then dedupe. Inserting into `visited` before the scope test made the set grow with
    // every OUT-OF-SCOPE link too — and those never bump `counters.discovered`, so the `page_budget`
    // guard above could not stop them: 50 000 pages x 2 000 links = 100 M retained URL strings.
    // Scope is a pure, cheap, synchronous check (host compare + precompiled regexes), so re-running it
    // for a repeated off-scope link is far cheaper than remembering every one of them.
    //
    // The entry page at depth 0 is the EXPLICIT seed — always admit it (subject to domain scope) so
    // its links can be discovered. Include/exclude PATH filters govern which DISCOVERED links to
    // follow, NOT whether to fetch the entry page (seed a list page, filter for detail pages → the
    // list page must still be crawled, or nothing is ever found).
    if !in_domain_scope(cfg, &url) || (depth > 0 && !passes_path_filters(cfg, &url)) {
        return; // out of scope — silent (not a "skip")
    }
    // Belt-and-braces cardinality cap: an in-scope but infinite URL space (calendars, faceted search)
    // can still mint unique URLs forever, and each is remembered for the crawl's lifetime.
    if visited.len() >= VISITED_HARD_CAP && !visited.contains(&url) {
        return;
    }
    // Dedupe: a URL that got this far is remembered so it is only ever evaluated once.
    if !visited.insert(url.clone()) {
        return;
    }
    if !crate::security::url_guard::is_navigation_url_safe_async(&url).await {
        counters.skipped += 1;
        return;
    }
    if cfg.respect_robots && !robots.allowed(client, &url).await {
        counters.skipped += 1;
        return;
    }
    counters.discovered += 1;
    counters.max_depth_seen = counters.max_depth_seen.max(depth);
    frontier.push_back(FrontierItem { url, depth });
}

// Read only by the `local`-gated whole-crawl control loop (it needs the SQLite store), but the
// unit tests below exercise these helpers in EVERY build — so scope a dead-code allowance to
// the configuration where they legitimately have no non-test caller, rather than `cfg`-ing the
// item out and breaking those tests.
#[cfg_attr(not(feature = "local"), allow(dead_code))]
// --------------------------------------------------------------------------- //
// Sitemap seeding                                                              //
// --------------------------------------------------------------------------- //
/// Fetch robots.txt `Sitemap:` directives + `/sitemap.xml`, returning `<loc>` URLs. Best-effort,
/// bounded, never raises. One level of sitemap-index expansion (mirrors the cloud seeder).
async fn discover_sitemap_urls(client: &reqwest::Client, seed_url: &str) -> Vec<String> {
    let Ok(parsed) = Url::parse(seed_url) else { return Vec::new() };
    let origin = match (parsed.scheme(), parsed.host_str()) {
        (s, Some(h)) => {
            let port = parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
            format!("{s}://{h}{port}")
        }
        _ => return Vec::new(),
    };

    let mut candidates: Vec<String> = Vec::new();
    let robots_url = format!("{origin}/robots.txt");
    if crate::security::url_guard::is_navigation_url_safe_async(&robots_url).await {
      if let Ok(resp) = client.get(&robots_url).send().await {
        if resp.status().is_success() {
            // 512 KiB cap — the de-facto robots.txt limit. Uncapped, a gzipped robots.txt is a
            // decompression bomb (and a 20 MB one is also a CPU bomb in `robots::parse`).
            if let Ok(text) = body_limit::read_text_capped(resp, body_limit::ROBOTS_MAX).await {
                for line in text.lines() {
                    let l = line.trim();
                    // `Sitemap: https://…` — the FIRST colon is the field separator; the URL's own
                    // `://` colon comes after it, so `l[first_colon+1..]` is the whole URL.
                    if l.to_ascii_lowercase().starts_with("sitemap:") {
                        if let Some(idx) = l.find(':') {
                            let v = l[idx + 1..].trim();
                            if !v.is_empty() {
                                candidates.push(v.to_string());
                            }
                        }
                    }
                }
            }
        }
      }
    }
    if candidates.is_empty() {
        candidates.push(format!("{origin}/sitemap.xml"));
    }

    let mut urls: Vec<String> = Vec::new();
    let mut seen_maps: HashSet<String> = HashSet::new();
    for sm in candidates.into_iter().take(5) {
        if !seen_maps.insert(sm.clone()) {
            continue;
        }
        // Vet the initial fetch target (DNS-resolving, fail-closed): a `Sitemap:`
        // directive is attacker-controlled, so an internal/metadata URL must not be
        // fetched. Redirect hops are already re-vetted by the client's redirect policy.
        if !crate::security::url_guard::is_navigation_url_safe_async(&sm).await {
            continue;
        }
        let Ok(resp) = client.get(&sm).send().await else { continue };
        if !resp.status().is_success() {
            continue;
        }
        let Ok(text) = body_limit::read_text_capped(resp, body_limit::SITEMAP_MAX).await else {
            continue;
        };
        // The remaining budget is passed DOWN into `extract_locs`: collecting every `<loc>` first and
        // capping afterwards still materializes 100 M strings for a hostile sitemap.
        let locs = extract_locs(&text, SITEMAP_HARD_CAP.saturating_sub(urls.len()).max(1));
        if text.to_ascii_lowercase().contains("<sitemapindex") {
            for child in locs.into_iter().take(20) {
                if !seen_maps.insert(child.clone()) {
                    continue;
                }
                // Sitemap-index children are attacker-controlled `<loc>` URLs — vet
                // the initial fetch target before hitting it (redirects re-vetted by
                // the client's redirect policy).
                if !crate::security::url_guard::is_navigation_url_safe_async(&child).await {
                    continue;
                }
                if let Ok(cr) = client.get(&child).send().await {
                    if cr.status().is_success() {
                        if let Ok(ct) =
                            body_limit::read_text_capped(cr, body_limit::SITEMAP_MAX).await
                        {
                            let room = SITEMAP_HARD_CAP.saturating_sub(urls.len());
                            if room == 0 {
                                break;
                            }
                            urls.extend(extract_locs(&ct, room));
                        }
                    }
                }
                if urls.len() >= SITEMAP_HARD_CAP {
                    break;
                }
            }
        } else {
            urls.extend(locs);
        }
        if urls.len() >= SITEMAP_HARD_CAP {
            break;
        }
    }
    // Dedup preserving order.
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for u in urls {
        if seen.insert(u.clone()) {
            out.push(u);
        }
    }
    out
}

// Read only by the `local`-gated whole-crawl control loop (it needs the SQLite store), but the
// unit tests below exercise these helpers in EVERY build — so scope a dead-code allowance to
// the configuration where they legitimately have no non-test caller, rather than `cfg`-ing the
// item out and breaking those tests.
#[cfg_attr(not(feature = "local"), allow(dead_code))]
/// Pull up to `limit` `<loc>…</loc>` values out of a sitemap document (cheap regex, no XML parser).
///
/// The limit is a PARAMETER, not a post-filter: a sitemap is attacker-controlled and can declare
/// millions of `<loc>`s, so collecting them all and truncating afterwards still retains every string.
fn extract_locs(xml: &str, limit: usize) -> Vec<String> {
    lazy_static::lazy_static! {
        static ref LOC_RE: Regex = Regex::new(r"(?is)<loc>\s*([^<\s]+)\s*</loc>").unwrap();
    }
    LOC_RE
        .captures_iter(xml)
        .filter_map(|c| c.get(1).map(|m| m.as_str().trim().to_string()))
        .take(limit)
        .collect()
}

// Read only by the `local`-gated whole-crawl control loop (it needs the SQLite store), but the
// unit tests below exercise these helpers in EVERY build — so scope a dead-code allowance to
// the configuration where they legitimately have no non-test caller, rather than `cfg`-ing the
// item out and breaking those tests.
#[cfg_attr(not(feature = "local"), allow(dead_code))]
// --------------------------------------------------------------------------- //
// Scope helpers (mirror the cloud orchestrator)                                //
// --------------------------------------------------------------------------- //
fn host_of(url: &str) -> String {
    Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
        .unwrap_or_default()
}

// Read only by the `local`-gated whole-crawl control loop (it needs the SQLite store), but the
// unit tests below exercise these helpers in EVERY build — so scope a dead-code allowance to
// the configuration where they legitimately have no non-test caller, rather than `cfg`-ing the
// item out and breaking those tests.
#[cfg_attr(not(feature = "local"), allow(dead_code))]
/// Cheap eTLD+1 (last two labels) — good enough for scoping; SSRF/blocklist still runs per URL.
fn registrable(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() >= 2 {
        labels[labels.len() - 2..].join(".")
    } else {
        host.to_string()
    }
}

// Read only by the `local`-gated whole-crawl control loop (it needs the SQLite store), but the
// unit tests below exercise these helpers in EVERY build — so scope a dead-code allowance to
// the configuration where they legitimately have no non-test caller, rather than `cfg`-ing the
// item out and breaking those tests.
#[cfg_attr(not(feature = "local"), allow(dead_code))]
fn in_domain_scope(cfg: &CrawlConfig, url: &str) -> bool {
    let h = host_of(url);
    if h.is_empty() {
        return false;
    }
    if !cfg.same_domain {
        return true;
    }
    if cfg.allow_subdomains {
        h == cfg.seed_host || h == cfg.seed_reg || h.ends_with(&format!(".{}", cfg.seed_reg))
    } else {
        h == cfg.seed_host
    }
}

// Read only by the `local`-gated whole-crawl control loop (it needs the SQLite store), but the
// unit tests below exercise these helpers in EVERY build — so scope a dead-code allowance to
// the configuration where they legitimately have no non-test caller, rather than `cfg`-ing the
// item out and breaking those tests.
#[cfg_attr(not(feature = "local"), allow(dead_code))]
fn passes_path_filters(cfg: &CrawlConfig, url: &str) -> bool {
    // Match include/exclude against path + `?query` (not path-only): many sites encode the
    // content-vs-chrome distinction in the query — e.g. HN `/item?id=123` (story) vs `/news?p=2`
    // (pagination) share a bare path, so path-only makes `^/item\?id=` never match and `^/news$`
    // match every `?p=` page.
    let path = Url::parse(url)
        .ok()
        .map(|u| match u.query() {
            Some(q) if !q.is_empty() => format!("{}?{}", u.path(), q),
            _ => u.path().to_string(),
        })
        .unwrap_or_else(|| "/".into());
    for re in &cfg.exclude_res {
        if re.is_match(&path) {
            return false;
        }
    }
    if !cfg.include_res.is_empty() {
        return cfg.include_res.iter().any(|re| re.is_match(&path));
    }
    true
}

// Read only by the `local`-gated whole-crawl control loop (it needs the SQLite store), but the
// unit tests below exercise these helpers in EVERY build — so scope a dead-code allowance to
// the configuration where they legitimately have no non-test caller, rather than `cfg`-ing the
// item out and breaking those tests.
#[cfg_attr(not(feature = "local"), allow(dead_code))]
/// Strip the fragment (and normalize the scheme prefix) so `#a`/`#b` don't fan out as distinct URLs.
fn normalize_url(raw: &str) -> String {
    match Url::parse(raw) {
        Ok(mut u) => {
            u.set_fragment(None);
            u.to_string()
        }
        Err(_) => raw.trim().to_string(),
    }
}

// --------------------------------------------------------------------------- //
// Config + persistence + small helpers                                         //
// --------------------------------------------------------------------------- //
#[cfg(feature = "local")]
fn build_config(crawl: &CrawlJob, browser_available: bool) -> CrawlConfig {
    let seed_host = host_of(&crawl.seed_url);
    let seed_reg = registrable(&seed_host);
    let compile = |raw: &str| -> Vec<Regex> {
        serde_json::from_str::<Vec<String>>(raw)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|p| Regex::new(&p).ok())
            .collect()
    };
    let extract_schema = crawl
        .extract_schema
        .as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok());
    CrawlConfig {
        seed_host,
        seed_reg,
        same_domain: crawl.same_domain != 0,
        allow_subdomains: crawl.allow_subdomains != 0,
        include_res: compile(&crawl.include_paths),
        exclude_res: compile(&crawl.exclude_paths),
        max_depth: crawl.max_depth,
        page_budget: crawl.page_budget,
        delay_ms: crawl.delay_ms.max(0) as u64,
        respect_robots: crawl.respect_robots != 0,
        extract_mode: crawl.extract_mode.clone(),
        extract_schema,
        // Content-selection spec, honored per page by the extractor (same shape the fleet uses).
        // NULL / unparseable → default extraction.
        content: crawl
            .content_spec
            .as_deref()
            .and_then(|s| serde_json::from_str::<Value>(s).ok()),
        // The desktop in-process crawler keeps today's render behaviour (HTTP-first with browser
        // fallback, OCR only pixels w/o text); render/ocr modes are a fleet crawl knob, default here.
        render_mode: "auto".into(),
        ocr_mode: "auto".into(),
        browser_available,
        cookies: Vec::new(),
        // No page thumbnails locally: there is no coordinator to offload them to, so they would
        // land as base64 inside the local SQLite rows.
        want_thumbnails: false,
    }
}

/// Build the crawl's shared reqwest client — same UA + per-hop redirect SSRF re-vetting as the
/// monitor checker's fast-HTTP tier.
fn build_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(CRAWL_UA)
        .timeout(Duration::from_secs(30))
        // reqwest's default connect timeout is None, so a black-holing host (SYN sent, nothing back)
        // would hold a crawl worker slot for the FULL 30 s total budget. Bound the handshake itself.
        .connect_timeout(Duration::from_secs(10))
        // SSRF: vet the dialed address on the initial connection AND every redirect hop, closing the
        // DNS-rebind TOCTOU and redirect-to-internal-hostname gap the string-based redirect policy
        // below cannot catch (it only sees IP literals / known hostnames, never resolves DNS).
        .dns_resolver(crate::security::vetting_resolver::shared())
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 10 {
                return attempt.stop();
            }
            if crate::security::url_guard::is_redirect_target_safe(attempt.url().as_str()) {
                attempt.follow()
            } else {
                attempt.stop()
            }
        }))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// Persist a batch of page rows as one terminal `runs` row under the synthetic workflow, so they
/// aggregate through the Workflow Data API (one queryable dataset).
#[cfg(feature = "local")]
async fn flush(pool: &sqlx::SqlitePool, workflow_id: i64, crawl_id: i64, buffer: &mut Vec<Value>) {
    if buffer.is_empty() {
        return;
    }
    let rows = std::mem::take(buffer);
    let result_data = json!({ "extracted_data": rows }).to_string();
    let trigger_context = json!({ "crawl_id": crawl_id }).to_string();
    if let Err(e) = runs::insert_imported(
        pool,
        workflow_id,
        "success",
        true,
        None,
        Some(&result_data),
        Some(&trigger_context),
    )
    .await
    {
        tracing::warn!(crawl_id, error = %e, "crawl page batch persist failed");
    }
}

/// Mirror the in-memory counters + live worker count into the durable row for the UI to poll.
#[cfg(feature = "local")]
async fn push_counters(pool: &sqlx::SqlitePool, id: i64, c: &Counters, workers_active: i64) {
    let snap = CounterSnapshot {
        pages_discovered: c.discovered,
        pages_done: c.done,
        pages_failed: c.failed,
        pages_skipped: c.skipped,
        workers_active,
        current_depth: c.max_depth_seen,
    };
    let _ = crawl_jobs::set_counters(pool, id, &snap).await;
}

fn now_iso() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A REFUSAL (429/403/captcha) must be told apart from a genuine failure: the coordinator
    /// requeues the former onto another agent and drops the latter as a dead link.
    #[test]
    fn classify_block_separates_refusals_from_failures() {
        assert_eq!(classify_block(Some(429), ""), Some("rate_limited"));
        for s in [401u16, 403, 407, 451] {
            assert_eq!(classify_block(Some(s), ""), Some("forbidden"), "status {s}");
        }
        // Genuine failures — NOT refusals.
        assert_eq!(classify_block(Some(404), "<html>gone</html>"), None);
        assert_eq!(classify_block(Some(500), ""), None);
        assert_eq!(classify_block(Some(200), "<html><body>real content</body></html>"), None);
        // A 200 that is really a bot wall.
        assert_eq!(
            classify_block(Some(200), "<title>Just a moment...</title><div id=cf_chl_opt>"),
            Some("challenge")
        );
        assert_eq!(classify_block(None, "<div class=\"g-recaptcha\"></div>"), Some("challenge"));
    }

    /// `Retry-After` is honored in delta-seconds form and clamped, so a hostile header can't park a
    /// crawl indefinitely; an HTTP-date form is simply ignored (the coordinator's own floor applies).
    #[test]
    fn retry_after_is_parsed_and_clamped() {
        assert_eq!(parse_retry_after(Some("90")), Some(90));
        assert_eq!(parse_retry_after(Some("  12 ")), Some(12));
        assert_eq!(parse_retry_after(Some("999999")), Some(RETRY_AFTER_MAX_S));
        assert_eq!(parse_retry_after(Some("Wed, 21 Oct 2026 07:28:00 GMT")), None);
        assert_eq!(parse_retry_after(Some("")), None);
        assert_eq!(parse_retry_after(None), None);
    }

    /// The shard wire contract keeps BOTH link views: `discovered_links` (with anchor text, what the
    /// coordinator ranks on) and `discovered_urls` (URL-only, for coordinators predating the change).
    #[test]
    fn shard_result_emits_both_link_views_and_block_fields() {
        let rd = ShardResult {
            engine: "http",
            pages: vec![],
            failed: vec![],
            discovered_urls: vec!["https://ex.test/a".into()],
            discovered_links: vec![json!({ "url": "https://ex.test/a", "text": "Pricing" })],
            blocked: vec![json!({ "url": "https://ex.test/b", "depth": 1, "block_kind": "rate_limited" })],
            agent_blocked: true,
            retry_after: 90,
            extracted_data: vec![],
            lane_counts: json!({ "http": 1, "browser": 0, "doc": 0, "ocr": 0 }),
        }
        .into_result_data();
        assert_eq!(rd["discovered_urls"], json!(["https://ex.test/a"]));
        assert_eq!(rd["discovered_links"][0]["text"], json!("Pricing"));
        assert_eq!(rd["blocked"][0]["block_kind"], json!("rate_limited"));
        assert_eq!(rd["agent_blocked"], json!(true));
        assert_eq!(rd["retry_after"], json!(90));
    }

    /// The OSS-local scrape/map entry points must SSRF-vet the seed before any fetch — a loopback or
    /// empty URL is a relayable `BadRequest`, never a request. (Guards the same gate as `start_crawl`.)
    #[cfg(all(feature = "local", not(feature = "cloud")))]
    #[tokio::test]
    async fn scrape_and_map_reject_ssrf_and_empty_seed() {
        assert!(matches!(
            scrape_one("http://127.0.0.1/admin", None).await,
            Err(LocalError::BadRequest(_))
        ));
        assert!(matches!(
            map_site("http://127.0.0.1/admin", None).await,
            Err(LocalError::BadRequest(_))
        ));
        assert!(matches!(scrape_one("   ", None).await, Err(LocalError::BadRequest(_))));
    }

    fn cfg(same_domain: bool, allow_sub: bool, inc: &[&str], exc: &[&str]) -> CrawlConfig {
        CrawlConfig {
            seed_host: "docs.example.com".into(),
            seed_reg: "example.com".into(),
            same_domain,
            allow_subdomains: allow_sub,
            include_res: inc.iter().filter_map(|p| Regex::new(p).ok()).collect(),
            exclude_res: exc.iter().filter_map(|p| Regex::new(p).ok()).collect(),
            max_depth: 3,
            page_budget: 100,
            delay_ms: 0,
            respect_robots: true,
            extract_mode: "markdown".into(),
            extract_schema: None,
            render_mode: "auto".into(),
            ocr_mode: "auto".into(),
            content: None,
            browser_available: false,
            cookies: Vec::new(),
            want_thumbnails: false,
        }
    }

    #[test]
    fn scope_same_domain_with_subdomains() {
        let c = cfg(true, true, &[], &[]);
        assert!(in_domain_scope(&c, "https://docs.example.com/x"));
        assert!(in_domain_scope(&c, "https://example.com/y"), "registrable root in scope");
        assert!(in_domain_scope(&c, "https://blog.example.com/z"), "sibling subdomain in scope");
        assert!(!in_domain_scope(&c, "https://other.test/a"), "off-domain rejected");
    }

    #[test]
    fn scope_same_domain_no_subdomains() {
        let c = cfg(true, false, &[], &[]);
        assert!(in_domain_scope(&c, "https://docs.example.com/x"));
        assert!(!in_domain_scope(&c, "https://blog.example.com/z"), "subdomain rejected when off");
    }

    #[test]
    fn scope_any_domain_when_not_same_domain() {
        let c = cfg(false, false, &[], &[]);
        assert!(in_domain_scope(&c, "https://anything.test/a"));
    }

    #[test]
    fn path_filters_match_path_and_query_not_path_only() {
        // HN: `/item?id=123` is a story, `/news?p=2` is pagination (same bare path). Include must
        // match path+query so `^/item\?id=` admits stories and `^/news$` rejects `?p=` pagination.
        let c = cfg(true, true, &[r"^/item\?id=", r"^/news$"], &[]);
        assert!(passes_path_filters(&c, "https://news.ycombinator.com/item?id=123"), "story admitted");
        assert!(passes_path_filters(&c, "https://news.ycombinator.com/news"), "front page admitted");
        assert!(!passes_path_filters(&c, "https://news.ycombinator.com/news?p=2"), "pagination rejected");
    }

    #[test]
    fn path_filters_include_and_exclude() {
        let c = cfg(true, true, &["^/docs"], &["\\.pdf$"]);
        assert!(passes_path_filters(&c, "https://docs.example.com/docs/intro"));
        assert!(!passes_path_filters(&c, "https://docs.example.com/blog/post"), "not in include");
        assert!(!passes_path_filters(&c, "https://docs.example.com/docs/manual.pdf"), "excluded");
    }

    #[test]
    fn registrable_last_two_labels() {
        assert_eq!(registrable("docs.example.com"), "example.com");
        assert_eq!(registrable("example.com"), "example.com");
        assert_eq!(registrable("localhost"), "localhost");
    }

    #[test]
    fn normalize_strips_fragment() {
        assert_eq!(normalize_url("https://x.test/a#section"), "https://x.test/a");
        assert_eq!(normalize_url("https://x.test/a"), "https://x.test/a");
    }

    #[test]
    fn locs_extracted_from_sitemap() {
        let xml = "<urlset><url><loc>https://x.test/a</loc></url><url><loc> https://x.test/b </loc></url></urlset>";
        assert_eq!(extract_locs(xml, 100), vec!["https://x.test/a", "https://x.test/b"]);
    }

    /// A hostile sitemap must not be materialized in full before the cap applies — the limit is
    /// enforced DURING the scan, so the returned Vec never exceeds it.
    #[test]
    fn locs_are_capped_during_the_scan() {
        let xml: String = (0..5_000)
            .map(|i| format!("<url><loc>https://x.test/{i}</loc></url>"))
            .collect();
        assert_eq!(extract_locs(&xml, 10).len(), 10);
        assert_eq!(extract_locs(&xml, 0).len(), 0);
        // Order is preserved (first-seen wins), so the cap keeps the earliest entries.
        assert_eq!(extract_locs(&xml, 2), vec!["https://x.test/0", "https://x.test/1"]);
    }

    /// A challenge scan must never PANIC on a multi-byte boundary. `"a".repeat(19_999) + "€"` puts
    /// byte 20_000 mid-character, and this body arrives straight off the wire. The panic used to hang
    /// the coordinator's awaited future (manager-side) or strand the crawl row (local path).
    #[test]
    fn classify_block_is_char_boundary_safe_on_hostile_bodies() {
        let mut body = "a".repeat(CHALLENGE_SCAN_CHARS - 1);
        body.push('€'); // 3 bytes → byte index CHALLENGE_SCAN_CHARS lands mid-codepoint
        assert_eq!(classify_block(None, &body), None, "must not panic and must find no marker");

        // Multi-byte padding does not hide a marker that falls inside the scanned prefix.
        let mut hostile = "é".repeat(10);
        hostile.push_str("Just A Moment");
        assert_eq!(classify_block(None, &hostile), Some("challenge"));

        // A marker pushed BEYOND the scan window is simply not scanned (bounded work, no panic).
        let far = format!("{}g-recaptcha", "é".repeat(CHALLENGE_SCAN_CHARS + 10));
        assert_eq!(classify_block(None, &far), None);
    }

    // ---- distributed shard execution -------------------------------------- //

    #[test]
    fn cookies_parsed_from_storage_state() {
        let ss = json!({
            "cookies": [
                {"name": "sid", "value": "abc", "domain": ".example.com", "path": "/"},
                {"name": "csrf", "value": "xyz", "domain": "app.example.com", "path": "/app"},
                {"name": "bad"} // missing value → dropped
            ],
            "origins": []
        });
        let cs = cookies_from_session(Some(&ss));
        assert_eq!(cs.len(), 2);
        assert_eq!(cs[0].name, "sid");
        assert_eq!(cs[0].domain, "example.com", "leading dot stripped, lowercased");
        assert_eq!(cs[1].path, "/app");
        assert!(cookies_from_session(None).is_empty());
        assert!(cookies_from_session(Some(&Value::Null)).is_empty());
    }

    #[test]
    fn cookie_header_matches_domain_and_path() {
        let cs = vec![
            ShardCookie { name: "sid".into(), value: "abc".into(), domain: "example.com".into(), path: "/".into() },
            ShardCookie { name: "csrf".into(), value: "xyz".into(), domain: "app.example.com".into(), path: "/app".into() },
        ];
        // Subdomain host gets the registrable-domain cookie; the /app cookie only on the /app path.
        let h = cookie_header_for("https://app.example.com/app/page", &cs).unwrap();
        assert!(h.contains("sid=abc"), "root-domain cookie applies to subdomain: {h}");
        assert!(h.contains("csrf=xyz"), "path-scoped cookie applies on its path: {h}");
        // Off the /app path: only the root cookie.
        let h2 = cookie_header_for("https://app.example.com/other", &cs).unwrap();
        assert!(h2.contains("sid=abc") && !h2.contains("csrf=xyz"), "path scope enforced: {h2}");
        // Off-domain: nothing.
        assert!(cookie_header_for("https://other.test/x", &cs).is_none());
        // No cookies: nothing.
        assert!(cookie_header_for("https://example.com/", &[]).is_none());
    }

    #[tokio::test]
    async fn empty_shard_yields_wellformed_frame() {
        // A garbled/empty shard must still produce a reply-awaited frame so the coordinator's
        // future resolves — no network is touched because there are no URLs to fetch.
        let config = json!({
            "steps": [{"id": "1", "type": "crawl_batch", "config": {"delay_ms": 0}}],
            "trigger_context": {"_crawl_id": 7, "_crawl_shard": [], "_crawl_extract": {"mode": "markdown"}}
        });
        // No browser needed for an empty shard (no URLs → no JS fallback).
        let frame = run_shard_from_message(None, "42", &config).await;
        assert_eq!(frame["type"], json!("task_result"));
        assert_eq!(frame["task_id"], json!("42"));
        assert_eq!(frame["success"], json!(true));
        let rd = &frame["result_data"];
        assert_eq!(rd["engine"], json!("http"));
        assert_eq!(rd["pages"], json!([]));
        assert_eq!(rd["failed"], json!([]));
        assert_eq!(rd["discovered_urls"], json!([]));
        assert_eq!(rd["extracted_data"], json!([]));
        assert_eq!(rd["lane_counts"], json!({"http": 0, "browser": 0, "doc": 0, "ocr": 0}));
    }

    #[test]
    fn is_nonhtml_positive_and_default_html() {
        // Magic bytes.
        assert!(is_nonhtml("application/octet-stream", b"%PDF-1.7", "https://x/a"));
        assert!(is_nonhtml("", b"\x89PNG\r\n\x1a\n", "https://x/a"));
        // Content-type.
        assert!(is_nonhtml("application/pdf", b"", "https://x/a"));
        assert!(is_nonhtml("application/json", b"{}", ""));
        assert!(is_nonhtml("text/csv", b"a,b", ""));
        assert!(is_nonhtml(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            b"PK\x03\x04", "https://x/a"
        ));
        // URL-suffix fallback for octet-stream.
        assert!(is_nonhtml("application/octet-stream", b"", "https://x/report.pdf"));
        // HTML is the default — never routed to the document lane.
        assert!(!is_nonhtml("text/html", b"<html>", "https://x/page"));
        assert!(!is_nonhtml("", b"<!doctype html>", "https://x/page"));
    }

    #[test]
    fn rows_from_doc_ocr_and_schema() {
        // OCR markdown row carries content_kind=ocr + ocr_confidence, lane=ocr.
        let doc = json!({
            "content_kind": "ocr", "markdown": "scanned invoice", "text": "scanned invoice",
            "records": [], "ocr": {"engine": "rapidocr", "confidence": 0.91, "pages": 1}, "meta": {}
        });
        let (_title, rows, kind, lane) = rows_from_doc(&doc, "https://x/s.png", 1, "now", "markdown");
        assert_eq!(kind, "ocr");
        assert_eq!(lane, "ocr");
        assert_eq!(rows[0]["content_kind"], json!("ocr"));
        assert_eq!(rows[0]["ocr_confidence"], json!(0.91));

        // Schema mode surfaces structured records, lane=doc.
        let doc2 = json!({
            "content_kind": "json", "markdown": "", "text": "",
            "records": [{"a": 1}, {"a": 2}], "ocr": Value::Null, "meta": {}
        });
        let (_t, rows2, kind2, lane2) = rows_from_doc(&doc2, "https://x/d.json", 0, "now", "schema");
        assert_eq!(kind2, "json");
        assert_eq!(lane2, "doc");
        assert_eq!(rows2.len(), 2);
        assert_eq!(rows2[0]["a"], json!(1));
        assert_eq!(rows2[0]["_source_url"], json!("https://x/d.json"));
        assert_eq!(rows2[0]["content_kind"], json!("json"));
    }

    #[test]
    fn shard_extract_spec_parsed_from_config() {
        // Verify the schema/mode/delay parsing without running the fetch (pure config plumbing).
        let cfg = build_shard_config(
            &ShardExtract { mode: "schema".into(), schema: Some(json!({"row_selector": ".x"})), delay_ms: 500, render_mode: "auto".into(), ocr_mode: "auto".into(), content: None },
            Vec::new(),
            false,
        );
        assert_eq!(cfg.extract_mode, "schema");
        assert_eq!(cfg.delay_ms, 500);
        assert!(cfg.extract_schema.is_some());
        assert!(!cfg.respect_robots, "coordinator owns admission; shard never re-checks robots");
    }
}
