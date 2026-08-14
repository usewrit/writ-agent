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
use std::collections::{HashMap, HashSet, VecDeque};
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

/// Concurrent BROWSER renders allowed inside one crawl.
///
/// The fetch window above is sized for the HTTP lane, which is cheap. A render is not: it holds a
/// real browser context, and the manager caps LIVE contexts and FAILS a request that waits past its
/// timeout — so letting the whole fetch window escalate at once would spend every context on one
/// crawl and start failing pages (its own, and any monitor check running beside it).
///
/// This bound is what makes escalation concurrent AT ALL. Before it existed the browser fetch was
/// awaited on the manager task, between `join_next()` and the refill — so a batch where every page
/// escalates (any Cloudflare-fronted site: the seed is served, every article gets a 403 challenge)
/// ran the whole shard ONE page at a time, at ~3s each, while the fetch window sat idle. A 25-URL
/// shard took ~75s and reported nothing until it finished.
const BROWSER_LANE_CONCURRENCY: usize = 4;

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
    pub expires: f64,
    pub http_only: bool,
    pub secure: bool,
    pub same_site: Option<String>,
}

/// The persona session an authenticated crawl replays, in the form BOTH fetch lanes need.
///
/// A crawl has two ways to obtain a page — the `reqwest` HTTP lane and a real browser render — and
/// an authenticated crawl must be logged in on BOTH. Before this existed only the HTTP lane carried
/// cookies, so any page that escalated to the browser (a JS shell, or a bot-wall challenge — i.e.
/// exactly the pages a login-gated SPA serves) was fetched logged-OUT and banked as content.
///
/// `domain` is the registrable domain the session belongs to. Auth is replayed ONLY to hosts inside
/// it: a crawl may legitimately leave the seed site (`same_domain=false`, or an off-site link on an
/// allowed subdomain), and a session cookie or `Authorization` header must never follow it there.
#[derive(Clone, Default)]
pub struct CrawlAuth {
    /// Cookies, matched per-request by domain/path.
    pub cookies: Vec<ShardCookie>,
    /// `localStorage` items — browser lane only (the HTTP lane has no DOM).
    pub local_storage: HashMap<String, String>,
    /// `sessionStorage` items — browser lane only.
    pub session_storage: HashMap<String, String>,
    /// Auth-bearing request headers captured at login (`Authorization`, `X-API-Key`, …) for
    /// token-auth sites whose session lives in a header rather than a cookie. HTTP lane only —
    /// see [`CrawlAuth::header_replay_allowed`].
    pub headers: HashMap<String, String>,
    /// Registrable domain this session authenticates against. Empty ⇒ no host restriction beyond
    /// each cookie's own domain (older coordinators that don't send one).
    pub domain: String,
}

impl CrawlAuth {
    /// True when there is nothing to replay — the unauthenticated crawl path.
    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
            && self.local_storage.is_empty()
            && self.session_storage.is_empty()
            && self.headers.is_empty()
    }

    /// True when this session carries browser-only state (storage) worth the extra
    /// navigate-inject-reload round trip on a render.
    fn has_storage(&self) -> bool {
        !self.local_storage.is_empty() || !self.session_storage.is_empty()
    }

    /// Is `url`'s host inside the session's registrable domain?
    ///
    /// Gates every non-cookie replay. Cookies carry their own domain and are matched individually
    /// (see [`cookie_header_for`]); headers and DOM storage do not, so without this a crawl that
    /// wandered off-site would hand a bearer token to a third party.
    fn host_in_domain(&self, url: &str) -> bool {
        if self.domain.is_empty() {
            return false; // no anchor ⇒ never replay un-domained auth
        }
        let Ok(parsed) = Url::parse(url) else { return false };
        let Some(host) = parsed.host_str() else { return false };
        let host = host.to_ascii_lowercase();
        host == self.domain || host.ends_with(&format!(".{}", self.domain))
    }

    /// Auth headers may only ride requests to the session's own domain, and only over HTTPS —
    /// a bearer token must never be emitted in plaintext.
    fn header_replay_allowed(&self, url: &str) -> bool {
        !self.headers.is_empty() && url.starts_with("https://") && self.host_in_domain(url)
    }
}

/// Live page counts for a shard that is still running.
///
/// A shard is the coordinator's unit of accounting: it credits `pages_done` when the whole batch
/// comes back. At 25 URLs a browser-lane shard runs for over a minute, so the crawl's page counter
/// could not move for that whole time and the run looked frozen on its first page — which is what
/// operators cancelled. Emitting the running tally lets the coordinator advance the counter while
/// the batch is still in flight; the final `task_result` stays authoritative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardProgress {
    /// Pages successfully extracted SO FAR (cumulative within this shard, never decreasing).
    pub done: u64,
    /// Pages failed or refused so far (cumulative within this shard).
    pub failed: u64,
    /// URLs in the batch — lets the receiver render "7/25" without tracking dispatch.
    pub total: u64,
}

/// Where a running shard reports [`ShardProgress`]. Unbounded on purpose: the sender is on the
/// shard's hot path and must never wait on a slow consumer, and the volume is one message per page.
/// The receiver decides how often to actually forward — see [`spawn_progress_forwarder`].
pub type ProgressSink = tokio::sync::mpsc::UnboundedSender<ShardProgress>;

/// Smallest gap between two `task_progress` frames for one shard.
///
/// Every frame costs the receiving coordinator a counter write, and the HTTP lane can retire pages
/// in milliseconds — so the tally is coalesced to its latest value rather than sent per page. Short
/// enough that a browser-lane shard (seconds per page) still reports essentially live.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(1_500);

/// Turn a shard's per-page tally into coalesced `task_progress` frames.
///
/// Lives here rather than in a bridge because BOTH bridges need it — the fleet bridge (self-host
/// coordinator) and the saas bridge (cloud backend) — and they must put the SAME frame on the wire
/// for the two coordinators to credit progress identically. They differ only in how a frame reaches
/// their socket, which is what `send_frame` abstracts.
///
/// The returned sink is what [`run_shard_from_message`] reports into. Dropping it (i.e. the shard
/// finishing) flushes the final tally and ends the task, so the last pre-result value is never lost.
pub fn spawn_progress_forwarder(
    task_id: String,
    send_frame: impl Fn(Value) + Send + 'static,
) -> ProgressSink {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ShardProgress>();
    tokio::spawn(async move {
        // `move`: the closure OWNS the sender and the id. Borrowing them instead would make it a
        // non-`Send` value held across the ticker await, which `tokio::spawn` rejects.
        let emit = move |p: ShardProgress| {
            // Distinct keys from the run-progress fields (`step` / `max_steps` / `phase`) that share
            // this frame type: a crawl shard is not a workflow run and must not be read as one.
            send_frame(json!({
                "type": "task_progress",
                "task_id": task_id,
                "crawl_pages_done": p.done,
                "crawl_pages_failed": p.failed,
                "crawl_pages_total": p.total,
                "message": format!("{}/{} pages", p.done + p.failed, p.total),
            }));
        };
        let mut latest: Option<ShardProgress> = None;
        let mut ticker = tokio::time::interval(PROGRESS_INTERVAL);
        // Delay (not Burst): after a quiet stretch we want ONE tick, not a catch-up salvo.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await; // the first tick resolves immediately — consume it
        loop {
            tokio::select! {
                msg = rx.recv() => match msg {
                    Some(p) => latest = Some(p),
                    // The shard finished and dropped its sink: flush and stop.
                    None => {
                        if let Some(p) = latest.take() {
                            emit(p);
                        }
                        break;
                    }
                },
                _ = ticker.tick() => {
                    if let Some(p) = latest.take() {
                        emit(p);
                    }
                }
            }
        }
    });
    tx
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
fn build_shard_config(spec: &ShardExtract, auth: CrawlAuth, browser_available: bool) -> CrawlConfig {
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
        auth,
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
    auth: CrawlAuth,
    progress: Option<ProgressSink>,
) -> ShardResult {
    let browser_available = browser.is_some();
    let cfg = Arc::new(build_shard_config(&spec, auth, browser_available));
    let client = build_http_client();

    let total = items.len() as u64;
    let mut queue: VecDeque<ShardItem> = items.into_iter().collect();
    let max_concurrent = SHARD_CONCURRENCY.min(queue.len().max(1));
    // Renders are bounded separately from fetches — see BROWSER_LANE_CONCURRENCY.
    let render_slots = Arc::new(tokio::sync::Semaphore::new(
        BROWSER_LANE_CONCURRENCY.min(max_concurrent),
    ));
    let mut join: JoinSet<ResolvedOut> = JoinSet::new();

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
                    join.spawn(fetch_resolve(
                        client.clone(),
                        cfg.clone(),
                        browser.clone(),
                        render_slots.clone(),
                        item,
                    ));
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
        // Whether the HTTP lane asked for a render, decided in the worker (where the escalation now
        // happens) and reported back for the `engine` field.
        if out.escalated {
            used_browser = true;
        }
        let now = out.fetched_at;
        let url = out.url;
        let depth = out.depth;
        match out.outcome {
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
        // Report the running tally after every page. Cheap (an unbounded send) and the receiver
        // decides how often to actually put a frame on the wire; without it the coordinator learns
        // nothing about this batch until the last page lands.
        if let Some(tx) = progress.as_ref() {
            let _ = tx.send(ShardProgress {
                done: pages.len() as u64,
                failed: failed.len() as u64,
                total,
            });
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
    progress: Option<ProgressSink>,
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

    // Registrable domain the coordinator scoped this crawl to — the boundary for replaying
    // un-domained auth (headers, DOM storage). Absent on an older coordinator: auth then falls
    // back to cookie-domain matching only.
    let auth_domain = extract
        .get("auth_domain")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let auth = auth_from_session(config.get("session_state"), auth_domain);
    if !auth.is_empty() {
        tracing::info!(
            task_id,
            cookies = auth.cookies.len(),
            local_storage = auth.local_storage.len(),
            headers = auth.headers.len(),
            domain = %auth.domain,
            "crawl shard running AUTHENTICATED (persona session restored)"
        );
    }
    let spec = ShardExtract { mode, schema, delay_ms, render_mode, ocr_mode, content };
    let result = run_crawl_shard(browser, items, spec, auth, progress).await;

    json!({
        "type": "task_result",
        "task_id": task_id,
        "success": true,
        "result_data": result.into_result_data(),
        "error": Value::Null,
    })
}

/// Restore a persona session from a workflow `session_state` blob.
///
/// The wire shape is the one [`crate::models::session::SessionState`] serializes — `cookies` plus
/// camelCase `localStorage`/`sessionStorage` and `headers`. Playwright's own `storage_state` shape
/// (`origins: [{origin, localStorage: [{name, value}]}]`) is ALSO accepted, because a session
/// captured by a raw Playwright export reaches us that way and silently losing its localStorage is
/// how a token-auth SPA ends up crawled logged-out.
///
/// `auth_domain` is the registrable domain the coordinator scoped this crawl to; when empty we fall
/// back to the widest cookie domain so an older coordinator still gets browser-lane auth.
fn auth_from_session(session_state: Option<&Value>, auth_domain: &str) -> CrawlAuth {
    let Some(ss) = session_state.filter(|v| !v.is_null()) else {
        return CrawlAuth::default();
    };

    let cookies: Vec<ShardCookie> = ss
        .get("cookies")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
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
                    Some(ShardCookie {
                        name,
                        value,
                        domain,
                        path,
                        expires: c.get("expires").and_then(|v| v.as_f64()).unwrap_or(-1.0),
                        http_only: c.get("httpOnly").and_then(|v| v.as_bool()).unwrap_or(false),
                        secure: c.get("secure").and_then(|v| v.as_bool()).unwrap_or(false),
                        same_site: c.get("sameSite").and_then(|v| v.as_str()).map(str::to_string),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    // Writ shape: flat `{key: value}` maps under camelCase keys.
    let flat_map = |key: &str| -> HashMap<String, String> {
        ss.get(key)
            .and_then(|v| v.as_object())
            .map(|o| {
                o.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut local_storage = flat_map("localStorage");
    let session_storage = flat_map("sessionStorage");

    // Playwright shape: `origins[].localStorage[] = {name, value}`. Merged in without clobbering
    // anything the Writ shape already provided.
    if let Some(origins) = ss.get("origins").and_then(|v| v.as_array()) {
        for origin in origins {
            let Some(items) = origin.get("localStorage").and_then(|v| v.as_array()) else {
                continue;
            };
            for item in items {
                let (Some(name), Some(value)) = (
                    item.get("name").and_then(|v| v.as_str()),
                    item.get("value").and_then(|v| v.as_str()),
                ) else {
                    continue;
                };
                local_storage
                    .entry(name.to_string())
                    .or_insert_with(|| value.to_string());
            }
        }
    }

    let headers: HashMap<String, String> = ss
        .get("headers")
        .and_then(|v| v.as_object())
        .map(|o| {
            o.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.to_ascii_lowercase(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    // Anchor for header/storage replay. An explicit coordinator domain wins; otherwise take the
    // SHORTEST cookie domain present (the registrable one, e.g. `site.com` over `app.site.com`).
    let domain = if !auth_domain.is_empty() {
        auth_domain.trim_start_matches('.').to_ascii_lowercase()
    } else {
        cookies
            .iter()
            .filter(|c| !c.domain.is_empty())
            .map(|c| c.domain.clone())
            .min_by_key(|d| d.len())
            .unwrap_or_default()
    };

    CrawlAuth { cookies, local_storage, session_storage, headers, domain }
}

/// Build a `Cookie:` header value for `url` from the session cookies whose domain/path match. Returns
/// `None` when nothing matches (so the request goes out cookie-less rather than with an empty header).
fn cookie_header_for(url: &str, cookies: &[ShardCookie]) -> Option<String> {
    if cookies.is_empty() {
        return None;
    }
    let pairs: Vec<String> = cookies
        .iter()
        .filter(|c| cookie_matches(url, c))
        .map(|c| format!("{}={}", c.name, c.value))
        .collect();
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
    /// Persona session for an authenticated crawl (empty otherwise). Applied by BOTH fetch lanes —
    /// cookies/headers on the HTTP lane, cookies + DOM storage on a browser render.
    auth: CrawlAuth,
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

/// A host refusal (429 / 403 / captcha wall), carried around so an escalation can report the
/// ORIGINAL refusal if the escalated attempt doesn't pan out.
#[derive(Clone)]
struct BlockInfo {
    kind: &'static str,
    status: Option<u16>,
    retry_after: Option<u32>,
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
    ///
    /// `blocked_fallback` is set when the HTTP lane was REFUSED (403/429/…) and we are escalating to
    /// the browser to see whether a real Chromium gets through. It carries the original refusal so a
    /// missing/failed browser reports that refusal verbatim instead of a generic failure — the URL is
    /// still not dead, and the coordinator must still be told to retry it elsewhere.
    NeedsBrowser {
        thin_html: Option<String>,
        blocked_fallback: Option<BlockInfo>,
    },
    /// The host REFUSED us (429 / 403 / captcha wall). Distinct from `Failed`: the URL is not dead,
    /// so the coordinator requeues it to a different agent instead of dropping it.
    Blocked {
        kind: &'static str,
        status: Option<u16>,
        retry_after: Option<u32>,
    },
    Failed { reason: String },
}

/// What the HTTP stage produced for one URL. `outcome` may still be `NeedsBrowser`.
struct WorkerOut {
    url: String,
    depth: i64,
    outcome: PageOutcome,
}

/// One URL, fully resolved — the HTTP stage AND any browser escalation, both done on the worker
/// task. This is what the crawl loops consume.
struct ResolvedOut {
    url: String,
    depth: i64,
    /// Never `NeedsBrowser`, unless the browser was unavailable or produced nothing.
    outcome: PageOutcome,
    /// The HTTP lane asked for a render (whether or not one was produced) — drives the shard's
    /// reported `engine`.
    escalated: bool,
    /// When this page was resolved. Stamped on the worker so the timestamp reflects the fetch, not
    /// when a busy manager task got around to reading the result.
    fetched_at: String,
}

/// Fetch one URL and resolve it completely, INCLUDING the browser escalation.
///
/// The escalation used to run on the manager task, awaited between `join_next()` and the refill of
/// the fetch window. That made the browser lane strictly serial: on a host that challenges the HTTP
/// lane (Cloudflare and friends), every page escalates, and a crawl that should saturate its window
/// crawled one page at a time with every other worker slot idle. Doing it here puts renders on the
/// same footing as fetches, bounded by `render_slots` because a context is a scarce resource.
async fn fetch_resolve(
    client: reqwest::Client,
    cfg: Arc<CrawlConfig>,
    browser: Option<Arc<crate::browser::manager::BrowserManager>>,
    render_slots: Arc<tokio::sync::Semaphore>,
    item: FrontierItem,
) -> ResolvedOut {
    let out = fetch_and_extract(client, cfg.clone(), item).await;
    let escalated = matches!(out.outcome, PageOutcome::NeedsBrowser { .. });
    let fetched_at = now_iso();
    let outcome = if escalated {
        // Hold a render slot only for the render itself. `acquire` fails only if the semaphore is
        // closed, which never happens here (it lives as long as the crawl) — resolve anyway rather
        // than dropping a page on an impossible branch.
        let _permit = render_slots.acquire().await.ok();
        resolve_outcome(browser.as_ref(), &cfg, out.url.clone(), out.depth, out.outcome, &fetched_at).await
    } else {
        out.outcome
    };
    ResolvedOut { url: out.url, depth: out.depth, outcome, escalated, fetched_at }
}

/// Load the persona's saved session for a LOCAL crawl and shape it for both fetch lanes.
///
/// `Err(message)` is a user-facing refusal: the persona vanished, or it has no usable session left.
/// The session itself is only ever produced by an interactive sign-in (persona linking / a prior
/// run) — a crawl replays one, it never logs in — so "expired" genuinely means the user has to
/// re-link before pages behind the login are reachable.
#[cfg(feature = "local")]
async fn resolve_local_crawl_auth(
    state: &AppState,
    persona_id: i64,
    seed_url: &str,
) -> Result<CrawlAuth, String> {
    use crate::local::engine::persona::resolve_persona;

    let resolved = resolve_persona(&state.db, &state.vault, persona_id)
        .await
        .map_err(|e| format!("Could not open the login identity for this crawl: {e}"))?
        .ok_or_else(|| {
            "The login identity for this crawl is missing. Re-link a persona for the site, \
             then start the crawl."
                .to_string()
        })?;

    let Some(session) = resolved.session_state.as_ref() else {
        return Err("This crawl's persona has no saved login session yet. Sign in once with \
                    the persona so pages behind the login are reachable, then start the crawl."
            .to_string());
    };
    // Serialize through the wire shape so the local and coordinator paths parse ONE format —
    // a divergence here is how the two editions drift apart.
    let blob = serde_json::to_value(session)
        .map_err(|e| format!("Could not read the persona's saved session: {e}"))?;
    let auth = auth_from_session(Some(&blob), &registrable(&host_of(seed_url)));
    if auth.is_empty() {
        return Err("The login session for this crawl's persona has expired. Sign in again with \
                    the persona, then start the crawl."
            .to_string());
    }
    tracing::info!(
        persona_id,
        cookies = auth.cookies.len(),
        local_storage = auth.local_storage.len(),
        "local crawl running AUTHENTICATED (persona session restored)"
    );
    Ok(auth)
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

    // LOGIN-BEFORE-CRAWL. A crawl with a persona must fetch every page signed in, so resolve the
    // saved session up front and REFUSE to run without one — a persona'd crawl that quietly fell
    // back to logged-out would bank a whole site of login walls as if it were content, which is
    // strictly worse than failing with something the user can act on.
    let auth = match crawl.persona_id {
        Some(pid) => match resolve_local_crawl_auth(&state, pid, &crawl.seed_url).await {
            Ok(a) => a,
            Err(msg) => {
                crawl_jobs::finalize(&state.db, id, "failed", Some(&msg)).await?;
                tracing::info!(crawl_id = id, persona_id = pid, "crawl blocked pre-seed: {msg}");
                return Ok(());
            }
        },
        None => CrawlAuth::default(),
    };

    let cfg = Arc::new(build_config(&crawl, state.engine.browser().is_some(), auth));
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
    // The browser lane is bounded separately and much lower: `max_concurrent` is the user's fetch
    // setting and a render costs a live browser context. See BROWSER_LANE_CONCURRENCY.
    let render_slots = Arc::new(tokio::sync::Semaphore::new(
        BROWSER_LANE_CONCURRENCY.min(max_concurrent),
    ));
    // Resolved once, not per iteration: the workers hold their own clone of the handle.
    let crawl_browser = state.engine.browser();
    let mut join: JoinSet<ResolvedOut> = JoinSet::new();
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
                        join.spawn(fetch_resolve(
                            client.clone(),
                            cfg.clone(),
                            crawl_browser.clone(),
                            render_slots.clone(),
                            item,
                        ));
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

        // Already fully resolved on the worker (browser escalation included).
        match out.outcome {
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
    let PageOutcome::NeedsBrowser { thin_html, blocked_fallback } = outcome else {
        return outcome;
    };
    // Escalating a refusal: if the browser can't run or can't get through, the page is still
    // REFUSED, not failed — reporting it as a failure would drop a live URL instead of requeueing it.
    let refused = |info: Option<BlockInfo>| -> Option<PageOutcome> {
        info.map(|i| PageOutcome::Blocked {
            kind: i.kind,
            status: i.status,
            retry_after: i.retry_after,
        })
    };
    // Try the warm browser for a JS-rendered render, when one is available.
    if let Some(browser) = browser {
        // A JPEG is captured when the OCR fallback might need it OR when the run wants page
        // thumbnails (shard runs only — the local crawler keeps its rows lean).
        let want_ocr_shot = cfg.ocr_mode != "off" && doc_extract::is_configured();
        let want_shot = want_ocr_shot || cfg.want_thumbnails;
        if let Some((final_url, html, shot)) = fetch_via_browser(browser, &url, want_shot, &cfg.auth).await {
            // Even a RENDERED page can be a bot wall (the browser solved nothing). Report it as a
            // refusal so the coordinator retries elsewhere rather than banking an empty page.
            // Checked BEFORE extraction so a wall never pays for a full parse.
            if let Some(kind) = classify_block(None, &html) {
                // The render hit a wall too. Prefer the ORIGINAL refusal when this was an
                // escalation — it carries the real status / Retry-After, which the rendered
                // wall (status None) does not.
                return refused(blocked_fallback)
                    .unwrap_or(PageOutcome::Blocked { kind, status: None, retry_after: None });
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
    // Browser unavailable / failed. An escalated refusal reports as refused (there is no usable
    // body — see the `thin_html: None` note at the escalation site), so it is checked first.
    if let Some(blocked) = refused(blocked_fallback) {
        return blocked;
    }
    // Otherwise degrade to the HTTP body if we captured one.
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
    claim_host_slot(&item.url, cfg.delay_ms).await;
    // A browser retry is only allowed when a warm browser exists AND render_mode
    // isn't pinned to "http".
    let may_browser = cfg.browser_available && cfg.render_mode != "http";

    let mut fetched = match http_fetch(&client, &item.url, &cfg.auth).await {
        Ok(f) => f,
        Err(reason) => {
            let outcome = if may_browser {
                PageOutcome::NeedsBrowser { thin_html: None, blocked_fallback: None }
            } else {
                PageOutcome::Failed { reason }
            };
            return WorkerOut { url: item.url, depth: item.depth, outcome };
        }
    };

    if fetched.status >= 400 {
        // REFUSAL vs failure. A 429/403/407/451 is the host turning US away — the URL is fine, this
        // agent (or its IP) isn't welcome. Anything else (404, 500, …) is a genuine failure, and an
        // HTML page may still render, so it keeps the browser-retry path.
        //
        // A refusal ESCALATES to the browser once before it is reported. This lane is a `reqwest`
        // client that sends a real Chrome User-Agent, so its TLS/HTTP2 fingerprint contradicts the
        // UA it claims — which is exactly what a bot-management edge (Cloudflare et al.) 403s, while
        // serving the very same URL to a real browser. Treating the refusal as terminal here meant a
        // whole site could be reported "blocked" without one render ever being attempted, and the
        // coordinator would then requeue those URLs to other agents that fail identically.
        //
        // `thin_html` is deliberately None: the body of a 403 is the wall's own error page, and
        // banking it as content would be worse than reporting the refusal.
        if let Some(kind) = classify_block(Some(fetched.status), "") {
            let info = BlockInfo {
                kind,
                status: Some(fetched.status),
                retry_after: fetched.retry_after,
            };
            let outcome = if may_browser {
                PageOutcome::NeedsBrowser { thin_html: None, blocked_fallback: Some(info) }
            } else {
                PageOutcome::Blocked {
                    kind: info.kind,
                    status: info.status,
                    retry_after: info.retry_after,
                }
            };
            return WorkerOut { url: item.url, depth: item.depth, outcome };
        }
        let outcome = if may_browser {
            PageOutcome::NeedsBrowser { thin_html: None, blocked_fallback: None }
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
            outcome: PageOutcome::NeedsBrowser { thin_html: Some(html), blocked_fallback: None },
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
        PageOutcome::NeedsBrowser { thin_html, blocked_fallback: None }
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
    auth: &CrawlAuth,
) -> Result<Fetched, String> {
    let mut req = client
        .get(url)
        .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        .header("Accept-Language", "en-US,en;q=0.9");
    if let Some(cookie) = cookie_header_for(url, &auth.cookies) {
        req = req.header(reqwest::header::COOKIE, cookie);
    }
    // Token auth (Bearer / X-API-Key / CSRF) captured at login. Domain- AND https-gated so a
    // crawl that leaves the session's site cannot leak the token to a third party.
    if auth.header_replay_allowed(url) {
        for (name, value) in &auth.headers {
            req = req.header(name.as_str(), value.as_str());
        }
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

/// Restore the persona session into a fresh browser context before rendering `url`.
///
/// Returns `true` when the caller's page is ALREADY navigated to `url` (the storage path has to
/// navigate in order to reach the origin, then reloads so the app boots with the session in place);
/// `false` when only cookies were applied and the caller still owns the navigation.
///
/// Cookies are filtered to the ones this URL would actually send — an unmatched cookie is not just
/// useless, it is state from another host sitting in the jar. DOM storage is domain-gated on top:
/// `localStorage` for `site.com` must never be written into a page on another origin.
async fn apply_browser_auth(
    context: &playwright_rs::BrowserContext,
    page: &playwright_rs::Page,
    url: &str,
    auth: &CrawlAuth,
) -> bool {
    if auth.is_empty() {
        return false;
    }
    let matching: Vec<playwright_rs::Cookie> = auth
        .cookies
        .iter()
        .filter(|c| cookie_matches(url, c))
        .map(|c| playwright_rs::Cookie {
            name: c.name.clone(),
            value: c.value.clone(),
            domain: c.domain.clone(),
            path: c.path.clone(),
            expires: c.expires,
            http_only: c.http_only,
            secure: c.secure,
            same_site: c.same_site.clone(),
        })
        .collect();
    if !matching.is_empty() {
        if let Err(e) = context.add_cookies(&matching).await {
            tracing::warn!(error = %e, "crawl render: could not restore session cookies");
        }
    }

    // Storage is only meaningful on the session's own origin, and only worth a second navigation
    // when there is something to write.
    if !auth.has_storage() || !auth.host_in_domain(url) {
        return false;
    }
    if crate::browser::navigation::goto(page, url, "domcontentloaded", Duration::from_secs(30))
        .await
        .is_err()
    {
        return false; // let the caller's own goto surface the failure
    }
    for (key, value) in auth.local_storage.iter() {
        let args = json!([key, value]);
        let _: Result<Value, _> = page
            .evaluate("(a) => localStorage.setItem(a[0], a[1])", Some(&args))
            .await;
    }
    for (key, value) in auth.session_storage.iter() {
        let args = json!([key, value]);
        let _: Result<Value, _> = page
            .evaluate("(a) => sessionStorage.setItem(a[0], a[1])", Some(&args))
            .await;
    }
    // Reload so the SPA boots and reads the token it now has.
    if crate::browser::navigation::reload(page, Duration::from_secs(30))
        .await
        .is_err()
    {
        return false;
    }
    true
}

/// Would `url` send this cookie? Host-suffix + path-prefix match, plus the `secure` rule.
/// Shared by the header builder and the browser-context restore so both lanes agree on scope.
fn cookie_matches(url: &str, c: &ShardCookie) -> bool {
    if c.domain.is_empty() {
        return false;
    }
    let Ok(parsed) = Url::parse(url) else { return false };
    let Some(host) = parsed.host_str() else { return false };
    let host = host.to_ascii_lowercase();
    let host_match = host == c.domain || host.ends_with(&format!(".{}", c.domain));
    let path = parsed.path();
    let path_match = c.path.is_empty() || c.path == "/" || path.starts_with(&c.path);
    let scheme_ok = !c.secure || parsed.scheme() == "https";
    host_match && path_match && scheme_ok
}

/// Browser fallback: render `url` in the engine's warm Chromium and return (final_url, html,
/// screenshot). Best effort — any error yields `None` and the caller degrades. When
/// `want_screenshot` is set, a viewport JPEG is captured for the screenshot→OCR fallback. A fresh
/// stealth context per page, carrying the persona session when the crawl is authenticated.
async fn fetch_via_browser(
    browser: &Arc<crate::browser::manager::BrowserManager>,
    url: &str,
    want_screenshot: bool,
    auth: &CrawlAuth,
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
    // AUTHENTICATE THE RENDER. The context is fresh per page, so without this every escalated
    // page — a JS shell, or anything a bot wall challenges — renders logged-OUT, which is exactly
    // the set of pages a login-gated SPA serves. Cookies go on BEFORE the first navigation;
    // DOM storage can only be written once we are on the origin, so it costs a reload.
    let injected_storage = apply_browser_auth(&context, &page, url, auth).await;
    let result = async {
        if !injected_storage {
            crate::browser::navigation::goto(&page, url, "domcontentloaded", Duration::from_secs(30)).await.ok()?;
        }
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
// --- Per-host politeness pacing ---------------------------------------------
// `delay_ms` is the gap between REQUESTS TO A HOST, and the host does not care how
// its pages were sharded — it sees ONE IP: this agent. So the pace is tracked per
// host for the whole PROCESS, not per worker and not per shard.
//
// Sleeping per worker (what this used to do) made the real rate `window / delay` —
// six concurrent fetches every `delay`, six times what the operator dialled in. That
// also silently divided the coordinator's ONLY throttle by the width of the window:
// when a shard reports blocks the coordinator raises `delay_ms` (×1.5 + 250ms) and
// cuts `max_concurrent_shards` to ease off the host, and both levers assume the
// delay means what it says. A crawl that had just been refused would keep six
// requests in flight against the wall.
//
// The concurrency win is untouched by this: it comes from overlapping the SLOW parts
// (renders at seconds each), not from a higher request rate.
static HOST_NEXT_SLOT: std::sync::LazyLock<tokio::sync::Mutex<HashMap<String, tokio::time::Instant>>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(HashMap::new()));

/// Above this many tracked hosts, expired entries are dropped — a long-lived agent
/// crawls many hosts and the map must not grow for the life of the process.
const HOST_SLOT_PRUNE_AT: usize = 512;

/// Wait until this agent may issue its next request to `url`'s host.
async fn claim_host_slot(url: &str, delay_ms: u64) {
    if delay_ms == 0 {
        return;
    }
    let delay = Duration::from_millis(delay_ms);
    // The registrable domain, not the full host: a site spread over `www.`/`cdn.`/
    // `m.` is still one edge doing the rate limiting, and the coordinator's
    // cross-crawl host cooldown keys the same way.
    let key = Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| registrable(&h.to_lowercase())))
        .unwrap_or_default();

    let start_at = {
        let mut slots = HOST_NEXT_SLOT.lock().await;
        let now = tokio::time::Instant::now();
        // First request to a host goes immediately; each later one takes the next slot.
        let at = slots.get(&key).copied().map(|t| t.max(now)).unwrap_or(now);
        slots.insert(key.clone(), at + delay);
        if slots.len() > HOST_SLOT_PRUNE_AT {
            slots.retain(|k, v| *v > now || *k == key);
        }
        at
    };
    // Slept OUTSIDE the lock, so workers wait on their own deadline in parallel
    // rather than queueing on the mutex.
    tokio::time::sleep_until(start_at).await;
}

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
fn build_config(crawl: &CrawlJob, browser_available: bool, auth: CrawlAuth) -> CrawlConfig {
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
        // The persona session for an authenticated local crawl, resolved by `run_crawl` before
        // seeding (empty for a public site).
        auth,
        // No page thumbnails locally: there is no coordinator to offload them to, so they would
        // land as base64 inside the local SQLite rows.
        want_thumbnails: false,
    }
}

/// Build the crawl's shared reqwest client — same UA + per-hop redirect SSRF re-vetting as the
/// monitor checker's fast-HTTP tier.
///
/// The client presents as the same Chrome the browser lane launches: matching UA major and Chrome's
/// real navigation header set (see [`crate::monitor::checker::browser_headers`]). Before this, the
/// lane sent `accept: */*` under a Chrome User-Agent — a contradiction bot-management edges score
/// on, and the reason a plain `curl` with no UA is served pages this lane is 403'd for.
///
/// KNOWN GAP: this does not change the TLS ClientHello or HTTP/2 SETTINGS fingerprint (JA3/JA4),
/// which still says native-tls, not Chrome. A determined edge fingerprints the handshake, not just
/// the headers, so a page that is refused here escalates to the real browser rather than being
/// reported blocked outright (see `fetch_and_extract`). Closing the handshake gap means swapping
/// this client for an impersonating one (e.g. `rquest`/BoringSSL) — a dependency change, not a
/// tweak, and deliberately not folded into this fix.
fn build_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(CRAWL_UA)
        .default_headers(crate::monitor::checker::browser_headers())
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
            auth: CrawlAuth::default(),
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

    /// Terse cookie builder for the matching tests below.
    fn tc(name: &str, domain: &str, path: &str) -> ShardCookie {
        ShardCookie {
            name: name.into(),
            value: "v".into(),
            domain: domain.into(),
            path: path.into(),
            expires: -1.0,
            http_only: false,
            secure: false,
            same_site: None,
        }
    }

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
        let a = auth_from_session(Some(&ss), "example.com");
        assert_eq!(a.cookies.len(), 2);
        assert_eq!(a.cookies[0].name, "sid");
        assert_eq!(a.cookies[0].domain, "example.com", "leading dot stripped, lowercased");
        assert_eq!(a.cookies[1].path, "/app");
        assert!(auth_from_session(None, "").is_empty());
        assert!(auth_from_session(Some(&Value::Null), "").is_empty());
    }

    #[test]
    fn session_storage_parsed_from_both_wire_shapes() {
        // Writ shape: camelCase flat maps. A localStorage-only session is a REAL session — a
        // token-auth SPA has no cookies at all, and treating it as empty crawled it logged-out.
        let writ = json!({
            "cookies": [],
            "localStorage": {"token": "jwt-abc"},
            "sessionStorage": {"tab": "1"},
            "headers": {"Authorization": "Bearer abc"}
        });
        let a = auth_from_session(Some(&writ), "example.com");
        assert!(!a.is_empty(), "localStorage-only session must count as authenticated");
        assert_eq!(a.local_storage.get("token").map(String::as_str), Some("jwt-abc"));
        assert_eq!(a.session_storage.get("tab").map(String::as_str), Some("1"));
        assert_eq!(
            a.headers.get("authorization").map(String::as_str),
            Some("Bearer abc"),
            "header names are lowercased for consistent replay"
        );

        // Playwright storage_state shape: origins[].localStorage[] = {name, value}.
        let pw = json!({
            "cookies": [],
            "origins": [{
                "origin": "https://example.com",
                "localStorage": [{"name": "token", "value": "jwt-xyz"}]
            }]
        });
        let b = auth_from_session(Some(&pw), "example.com");
        assert_eq!(b.local_storage.get("token").map(String::as_str), Some("jwt-xyz"));
    }

    #[test]
    fn auth_domain_falls_back_to_registrable_cookie_domain() {
        let ss = json!({"cookies": [
            {"name": "a", "value": "1", "domain": "app.example.com", "path": "/"},
            {"name": "b", "value": "2", "domain": "example.com", "path": "/"}
        ]});
        // No coordinator-supplied domain → the SHORTEST cookie domain anchors replay.
        let a = auth_from_session(Some(&ss), "");
        assert_eq!(a.domain, "example.com");
        // An explicit domain always wins.
        let b = auth_from_session(Some(&ss), "Other.COM");
        assert_eq!(b.domain, "other.com", "explicit domain wins and is normalized");
    }

    #[test]
    fn auth_headers_never_leave_the_session_domain() {
        let ss = json!({"cookies": [], "headers": {"Authorization": "Bearer secret"}});
        let a = auth_from_session(Some(&ss), "example.com");
        assert!(a.header_replay_allowed("https://example.com/x"));
        assert!(a.header_replay_allowed("https://app.example.com/x"), "subdomain is in-domain");
        // A crawl may legitimately leave the site — the bearer token must not follow it.
        assert!(!a.header_replay_allowed("https://evil.test/x"));
        assert!(!a.header_replay_allowed("https://notexample.com/x"), "suffix must be a label boundary");
        // Never in plaintext.
        assert!(!a.header_replay_allowed("http://example.com/x"));
        // No anchor ⇒ never replay.
        let loose = auth_from_session(Some(&ss), "");
        assert!(!loose.header_replay_allowed("https://example.com/x"));
    }

    #[test]
    fn secure_cookies_are_not_sent_over_plaintext() {
        let mut c = tc("sid", "example.com", "/");
        c.secure = true;
        assert!(cookie_matches("https://example.com/", &c));
        assert!(!cookie_matches("http://example.com/", &c), "Secure cookie is https-only");
    }

    #[test]
    fn cookie_header_matches_domain_and_path() {
        let cs = vec![
            {
                let mut c = tc("sid", "example.com", "/");
                c.value = "abc".into();
                c
            },
            {
                let mut c = tc("csrf", "app.example.com", "/app");
                c.value = "xyz".into();
                c
            },
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
        let frame = run_shard_from_message(None, "42", &config, None).await;
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

    #[tokio::test]
    async fn progress_forwarder_coalesces_and_flushes_the_last_tally() {
        // A shard reports after every page. Putting all of those on the wire would cost the
        // coordinator one counter write each, so they coalesce — but the LAST one must always be
        // sent, or the coordinator's count sits behind what the shard already knew when its
        // `task_result` arrives.
        use std::sync::{Arc, Mutex};

        let seen: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let tx = spawn_progress_forwarder("77".into(), move |frame| {
            sink.lock().unwrap().push(frame);
        });

        // Ten pages retired back-to-back, well inside one coalescing window.
        for i in 1..=10u64 {
            tx.send(ShardProgress { done: i, failed: 0, total: 25 }).unwrap();
        }
        drop(tx); // the shard finished → flush and stop

        // Wait in REAL time for the forwarder task to observe the closed channel and
        // flush. Yielding is not enough on a multi-threaded runtime — that task may
        // be parked on another worker while the whole suite runs in parallel.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while seen.lock().unwrap().is_empty() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let frames = seen.lock().unwrap().clone();
        assert!(!frames.is_empty(), "the final tally must always be sent");
        assert!(frames.len() < 10, "per-page frames must be coalesced, got {}", frames.len());

        let last = frames.last().unwrap();
        assert_eq!(last["type"], json!("task_progress"));
        assert_eq!(last["task_id"], json!("77"));
        assert_eq!(last["crawl_pages_done"], json!(10));
        assert_eq!(last["crawl_pages_failed"], json!(0));
        assert_eq!(last["crawl_pages_total"], json!(25));
        // Distinct from the run-progress keys (`step` / `max_steps` / `phase`) that share this
        // frame type — a crawl shard must not be read as a workflow run.
        assert!(last.get("step").is_none() && last.get("phase").is_none());
    }

    // The pace map is process-global by design (an agent runs many shards), so each
    // test below uses its OWN host names rather than resetting shared state.
    //
    // Every assertion is a MINIMUM elapsed time except where noted: pacing can only
    // ever add delay, so a loaded machine cannot make these fail spuriously.

    #[tokio::test]
    async fn delay_ms_paces_one_host_across_concurrent_workers() {
        // `delay_ms` is the gap between REQUESTS TO A HOST, so N concurrent workers
        // must NOT turn it into N requests per delay. It is also the coordinator's
        // only throttle — it raises the delay to back off a host that blocked us, and
        // a per-worker reading would divide that lever by the width of the window.
        let start = tokio::time::Instant::now();
        let mut set = JoinSet::new();
        for i in 0..4 {
            set.spawn(async move {
                claim_host_slot(&format!("https://paced-a.example/{i}"), 30).await;
                tokio::time::Instant::now()
            });
        }
        let mut stamps = Vec::new();
        while let Some(Ok(t)) = set.join_next().await {
            stamps.push(t);
        }
        stamps.sort();
        assert_eq!(stamps.len(), 4);
        // Timer granularity: a sleep may return a fraction of a millisecond before
        // the measured deadline. The property under test is "one delay apart, not
        // all at once", so absorb that rather than asserting to the microsecond.
        const TOL: Duration = Duration::from_millis(5);
        // Measure every stamp against `start`, never against its predecessor. The pacer gives
        // slot k the deadline `start + k * delay` and a sleep can only overshoot it — but an
        // overshoot on stamp k SHORTENS the k→k+1 gap by exactly what it added to k-1→k, so a
        // pairwise-gap assertion fails on a loaded machine even when pacing held perfectly
        // (observed: "gap 2 was 20.3ms" under a 30ms delay). Distances from `start` only ever
        // grow under load, so they state the same property in a jitter-proof way — and they pin
        // all four stamps, not just the last. A per-worker sleep fires the whole window after ONE
        // delay, which fails at k = 2.
        for (k, stamp) in stamps.iter().enumerate() {
            let paced_to = Duration::from_millis(30) * k as u32;
            assert!(
                stamp.duration_since(start) + TOL >= paced_to,
                "request {k} landed {:?} after start, inside the {paced_to:?} its slot was paced to",
                stamp.duration_since(start),
            );
        }
    }

    #[tokio::test]
    async fn subdomains_of_one_site_share_a_pace_but_other_hosts_do_not() {
        // The edge that rate-limits us sees one registrable domain, however many
        // subdomains the pages are spread over — and the coordinator's cross-crawl
        // cooldown keys the same way. A DIFFERENT site must not be throttled behind it.
        let start = tokio::time::Instant::now();
        claim_host_slot("https://www.paced-b.example/a", 120).await;
        claim_host_slot("https://cdn.paced-b.example/b", 120).await;
        assert!(
            tokio::time::Instant::now().duration_since(start) >= Duration::from_millis(120),
            "subdomains of one site must share a pace",
        );

        // Upper bound, generously slack: an unrelated host must not queue behind it.
        let before_other = tokio::time::Instant::now();
        claim_host_slot("https://paced-c.test/a", 120).await;
        assert!(
            tokio::time::Instant::now().duration_since(before_other) < Duration::from_millis(60),
            "an unrelated host waits on nobody",
        );
    }

    #[tokio::test]
    async fn zero_delay_means_no_pacing() {
        let start = tokio::time::Instant::now();
        for i in 0..10 {
            claim_host_slot(&format!("https://paced-d.example/{i}"), 0).await;
        }
        assert!(tokio::time::Instant::now().duration_since(start) < Duration::from_millis(50));
    }

    #[test]
    fn browser_lane_is_bounded_below_the_fetch_window() {
        // The fetch window is sized for cheap HTTP GETs; a render holds a live browser context and
        // the manager FAILS a request that waits past its timeout. If escalation used the full
        // window, one crawl on a challenge-walled host would spend every context — failing its own
        // pages and any monitor check running beside it.
        // `const { .. }` rather than a plain `assert!`: both operands are constants, so this is
        // decidable at compile time. Evaluating it in a const block turns a violation into a build
        // error instead of a test failure — you cannot land the bad constant at all.
        const {
            assert!(
                BROWSER_LANE_CONCURRENCY < SHARD_CONCURRENCY,
                "renders must be scarcer than fetches"
            );
        }
        const {
            assert!(BROWSER_LANE_CONCURRENCY >= 2, "escalation must still be concurrent");
        }
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
            CrawlAuth::default(),
            false,
        );
        assert_eq!(cfg.extract_mode, "schema");
        assert_eq!(cfg.delay_ms, 500);
        assert!(cfg.extract_schema.is_some());
        assert!(!cfg.respect_robots, "coordinator owns admission; shard never re-checks robots");
    }
}
