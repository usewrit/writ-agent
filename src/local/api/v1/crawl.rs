//! `/v1/crawl` REST handlers — start / list / poll / cancel a Dragnet whole-site crawl running
//! LOCALLY on this machine. House style: thin handlers over `crate::local::crawl` +
//! `store::crawl_jobs`, `LocalResult<Json<_>>` with `?` propagation, no auth layer here (server.rs
//! applies the loopback bearer middleware).
//!
//! The desktop twin of the cloud `/api/crawl` router (the cloud backend's `crawl` router): same start body +
//! status-view shape, but there is no cloud fleet — a bounded in-process worker pool does the crawl.
//! The row is the thing the UI + the "Scribe" concierge poll; results land under `workflow_id` and
//! are read through the existing Workflow Data API (`/v1/workflows/{id}/data`).

use crate::local::crawl;
// Local crawl execution (StartParams) is compiled ONLY in the OSS self-host build — the managed
// (`cloud`) build never starts a crawl on this machine, it forwards to the fleet.
#[cfg(not(feature = "cloud"))]
use crate::local::crawl::StartParams;
use crate::local::error::{LocalError, LocalResult};
use crate::local::server::AppState;
use crate::local::store::crawl_jobs::{self, CrawlJob};
use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Routes for this resource, mounted under the shared `/v1` namespace by the parent router.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/crawl", get(list).post(start))
        .route("/v1/crawl/map", post(map_site))
        // Saved crawls. `definitions` is a STATIC segment so matchit resolves these ahead of
        // `/v1/crawl/:id` regardless of declaration order — but they are declared first anyway, so
        // the precedence is visible to the next reader rather than implied by the router's internals.
        .route(
            "/v1/crawl/definitions",
            get(list_definitions).post(create_definition),
        )
        .route(
            "/v1/crawl/definitions/:reference",
            get(get_definition)
                .patch(update_definition)
                .delete(delete_definition),
        )
        .route("/v1/crawl/definitions/:reference/run", post(run_definition))
        .route(
            "/v1/crawl/definitions/:reference/data",
            get(definition_data),
        )
        .route("/v1/crawl/:id", get(get_one).delete(delete_one))
        .route("/v1/crawl/:id/cancel", post(cancel))
        .route("/v1/crawl/:id/favicon", get(favicon))
}

/// A tolerant boolean deserializer — accepts a real bool, 0/1, or "true"/"false" (the desktop form
/// posts JSON-natural shapes; a `<Switch>` sends a bool, a `<select>` may send a string).
fn de_bool<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<bool>, D::Error> {
    let v = <Option<Value> as serde::Deserialize>::deserialize(d)?;
    Ok(match v {
        None | Some(Value::Null) => None,
        Some(Value::Bool(b)) => Some(b),
        Some(Value::Number(n)) => Some(n.as_i64().map(|x| x != 0).unwrap_or(false)),
        Some(Value::String(s)) => Some(matches!(s.to_ascii_lowercase().as_str(), "true" | "1" | "yes")),
        _ => None,
    })
}

/// A tolerant i64 deserializer — accepts a number or a numeric string (form inputs).
fn de_i64<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<i64>, D::Error> {
    let v = <Option<Value> as serde::Deserialize>::deserialize(d)?;
    Ok(match v {
        None | Some(Value::Null) => None,
        Some(Value::Number(n)) => n.as_i64(),
        Some(Value::String(s)) if s.trim().is_empty() => None,
        Some(Value::String(s)) => s.trim().parse::<i64>().ok(),
        _ => None,
    })
}

/// The start-crawl request body (mirrors the cloud `StartCrawlRequest`, adapted to the local scope:
/// `max_concurrent` is the local worker cap rather than a fleet shard count). Several fields
/// (`executor`/`extract_prompt`/`intent`/`seed_urls`/`relevance_threshold`/`render_mode`/`ocr_mode`/
/// `use_residential`) are cloud-forward-only — read solely by `build_cloud_start_body`, so the OSS
/// build (no `cloud`) never touches them.
///
/// EVERY field the UI sends must exist here. Serde drops unknown keys silently, so a knob that is
/// missing from this struct is not a compile error and not a 4xx — the crawl just runs with the
/// cloud's default for it, which is indistinguishable from the user never having touched the
/// control. That is how the Render lane, the OCR policy and the residential opt-in were being
/// discarded on every desktop crawl.
#[cfg_attr(not(feature = "cloud"), allow(dead_code))]
#[derive(Debug, Default, Deserialize)]
struct StartCrawlRequest {
    url: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    extract_mode: Option<String>,
    #[serde(default)]
    extract_schema: Option<Value>,
    // `executor`/`extract_prompt` are cloud-only (the ai-agent fleet). Accepted here
    // so a cloud-routed crawl can carry them; ignored by the local worker pool.
    #[serde(default)]
    executor: Option<String>,
    #[serde(default)]
    extract_prompt: Option<String>,
    // Render + document lanes (cloud-only knobs — the local worker pool derives its own
    // per-page strategy). `render_mode` is INDEPENDENT of `executor`: the AI reader runs
    // on whichever lane fetched the page, so "AI + full browser" is a real combination
    // the UI offers and this must carry.
    #[serde(default)]
    render_mode: Option<String>,
    #[serde(default)]
    ocr_mode: Option<String>,
    /// Route shard egress through the platform residential broker (premium, cloud-only).
    /// The UI already handles the 402 this can raise (`maybeResidentialFork`), which could
    /// never fire while the flag was being dropped here.
    #[serde(default, deserialize_with = "de_bool")]
    use_residential: Option<bool>,
    // AI-supervised scoping (cloud-only): a plain-English goal the cloud fleet turns
    // into a scope + a relevance-ranked frontier. Accepted here so a cloud-routed
    // crawl can carry them; the local worker pool ignores them (deterministic sweep).
    #[serde(default)]
    intent: Option<String>,
    #[serde(default)]
    seed_urls: Option<Vec<String>>,
    #[serde(default)]
    relevance_threshold: Option<f64>,
    #[serde(default, deserialize_with = "de_i64")]
    persona_id: Option<i64>,
    #[serde(default)]
    include_paths: Option<Vec<String>>,
    #[serde(default)]
    exclude_paths: Option<Vec<String>>,
    #[serde(default, deserialize_with = "de_i64")]
    max_depth: Option<i64>,
    #[serde(default, deserialize_with = "de_i64")]
    page_budget: Option<i64>,
    #[serde(default, deserialize_with = "de_i64")]
    max_concurrent: Option<i64>,
    #[serde(default, deserialize_with = "de_i64")]
    delay_ms: Option<i64>,
    #[serde(default, deserialize_with = "de_bool")]
    respect_robots: Option<bool>,
    #[serde(default, deserialize_with = "de_bool")]
    same_domain: Option<bool>,
    #[serde(default, deserialize_with = "de_bool")]
    allow_subdomains: Option<bool>,
    /// Content-selection spec ({preset, include_comments, exclude_selectors, include_selectors,
    /// keep}) applied to every page; forwarded to the cloud when linked, honored locally otherwise.
    /// Accepted under BOTH wire names: `content` is the original, `content_spec` is what every
    /// client actually posts (and what the cloud model calls it) — with only `content` declared,
    /// the spec arrived null on every request the desktop UI made.
    #[serde(default, alias = "content_spec")]
    content: Option<Value>,
}

#[derive(Debug, Default, Deserialize)]
struct ListQuery {
    limit: Option<i64>,
}

/// `POST /v1/crawl` — validate the seed, mint the synthetic dataset workflow + the crawl row, and
/// kick the crawl off in the background. Returns the queued status view (with `workflow_id` set).
async fn start(State(st): State<AppState>, Json(body): Json<StartCrawlRequest>) -> LocalResult<Json<Value>> {
    if body.url.trim().is_empty() {
        return Err(LocalError::BadRequest("url is required".into()));
    }
    // Dragnet crawl is CLOUD-ONLY on the managed desktop app: a whole-site crawl fans out across the
    // cloud FLEET (many egress IPs, managed browsers, gateway-metered AI extraction) and NEVER runs on
    // this one machine. A linked account routes to the fleet; without a credential we REFUSE rather than
    // start locally (defense in depth behind the UI's cloud gate). The local worker pool is compiled in
    // ONLY for the OSS self-host build (no `cloud` feature).
    #[cfg(feature = "cloud")]
    {
        if crate::local::cloud::crawl::is_linked(&st.db).await {
            let cloud =
                crate::local::cloud::crawl::start(&st.db, &build_cloud_start_body(&body)).await?;
            return Ok(Json(cloud_to_view(cloud)));
        }
        Err(LocalError::BadRequest(CRAWL_NEEDS_CLOUD.into()))
    }
    #[cfg(not(feature = "cloud"))]
    {
        let crawl = crawl::start_crawl(&st, params_from_request(body)).await?;
        Ok(Json(to_view(&crawl)))
    }
}

/// Refusal for a managed (cloud-feature) desktop that asks to start a crawl without a linked account or
/// API key. Dragnet is cloud-only — the crawl never runs on this machine.
#[cfg(feature = "cloud")]
const CRAWL_NEEDS_CLOUD: &str = "Whole-site Dragnet crawl runs on the Writ cloud fleet, never on this \
     machine. Link a cloud account or set an API key to run a crawl.";

/// `POST /v1/crawl/map` — list a site's URLs (sitemap + harvest), ranked by relevance,
/// so the UI can pick which to crawl or scrape before committing. Cloud-only: forwarded
/// to the fleet when linked (the local worker pool has no standalone map). Spends nothing.
async fn map_site(State(st): State<AppState>, Json(body): Json<Value>) -> LocalResult<Json<Value>> {
    #[cfg(feature = "cloud")]
    if crate::local::cloud::crawl::is_linked(&st.db).await {
        return Ok(Json(crate::local::cloud::crawl::map(&st.db, &body).await?));
    }
    let _ = (&st, &body);
    Err(LocalError::BadRequest(
        "Site mapping requires a linked cloud account.".into(),
    ))
}

/// `GET /v1/crawl` — newest-first list of crawls, capped by `?limit` (default 50, max 500).
async fn list(State(st): State<AppState>, Query(q): Query<ListQuery>) -> LocalResult<Json<Value>> {
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    #[cfg(feature = "cloud")]
    if crate::local::cloud::crawl::is_linked(&st.db).await {
        let mut cloud = crate::local::cloud::crawl::list(&st.db, limit).await?;
        if let Some(arr) = cloud.get_mut("crawls").and_then(|c| c.as_array_mut()) {
            for item in arr.iter_mut() {
                *item = cloud_to_view(item.take());
            }
        }
        return Ok(Json(cloud));
    }
    let rows = crawl_jobs::list(&st.db, limit).await?;
    let crawls: Vec<Value> = rows.iter().map(to_view).collect();
    Ok(Json(json!({ "crawls": crawls })))
}

/// `GET /v1/crawl/:id` — one crawl's live status view, or 404.
async fn get_one(State(st): State<AppState>, Path(id): Path<i64>) -> LocalResult<Json<Value>> {
    #[cfg(feature = "cloud")]
    if crate::local::cloud::crawl::is_linked(&st.db).await {
        let cloud = crate::local::cloud::crawl::get(&st.db, id).await?;
        return Ok(Json(cloud_to_view(cloud)));
    }
    let row = crawl_jobs::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("crawl {id}")))?;
    Ok(Json(to_view(&row)))
}

/// `DELETE /v1/crawl/:id` — remove a crawl and its dataset. Cloud-routed when linked
/// (the id is a cloud crawl id); otherwise removes the local row. Terminal crawls only —
/// an in-flight crawl must be stopped first so its worker loop doesn't outlive the row.
async fn delete_one(State(st): State<AppState>, Path(id): Path<i64>) -> LocalResult<axum::http::StatusCode> {
    #[cfg(feature = "cloud")]
    if crate::local::cloud::crawl::is_linked(&st.db).await {
        crate::local::cloud::crawl::remove(&st.db, id).await?;
        return Ok(axum::http::StatusCode::NO_CONTENT);
    }
    let row = crawl_jobs::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("crawl {id}")))?;
    if !matches!(row.status.as_str(), "completed" | "failed" | "cancelled") {
        return Err(LocalError::BadRequest("Stop this crawl before removing it.".into()));
    }
    crawl_jobs::delete(&st.db, id).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// `POST /v1/crawl/:id/cancel` — request cancellation (the loop drains + finalizes `cancelled`).
async fn cancel(State(st): State<AppState>, Path(id): Path<i64>) -> LocalResult<Json<Value>> {
    #[cfg(feature = "cloud")]
    if crate::local::cloud::crawl::is_linked(&st.db).await {
        let cloud = crate::local::cloud::crawl::cancel(&st.db, id).await?;
        return Ok(Json(cloud_to_view(cloud)));
    }
    // 404 a missing crawl so a stale UI can't silently no-op.
    let row = crawl_jobs::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("crawl {id}")))?;
    let requested = crawl::cancel_crawl(&st, id).await?;
    let refreshed = crawl_jobs::get_by_id(&st.db, id).await?.unwrap_or(row);
    let mut view = to_view(&refreshed);
    if let Some(obj) = view.as_object_mut() {
        obj.insert("cancel_requested_now".into(), json!(requested));
    }
    Ok(Json(view))
}

// ── Site favicon ────────────────────────────────────────────────────────────
/// Hard cap on a fetched favicon — a site glyph is kilobytes; anything bigger isn't one
/// and must not be buffered.
const MAX_FAVICON_BYTES: usize = 512 * 1024;

/// In-process favicon cache for LOCAL (unlinked) crawls, keyed by crawl id: the site is
/// fetched once, then served from memory. The cloud path needs none — object storage
/// already caches it there.
static FAVICON_CACHE: OnceLock<Mutex<HashMap<i64, (Vec<u8>, String)>>> = OnceLock::new();

fn favicon_cache() -> &'static Mutex<HashMap<i64, (Vec<u8>, String)>> {
    FAVICON_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Content-type from magic bytes — doubles as an "is this actually an image?" gate, so an
/// HTML error body served at `/favicon.ico` is never cached or served as one.
fn sniff_image_type(raw: &[u8]) -> Option<&'static str> {
    if raw.starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]) {
        return Some("image/png");
    }
    if raw.starts_with(b"GIF") {
        return Some("image/gif");
    }
    if raw.starts_with(&[0xff, 0xd8]) {
        return Some("image/jpeg");
    }
    if raw.starts_with(&[0x00, 0x00, 0x01, 0x00]) {
        return Some("image/x-icon");
    }
    if raw.len() > 12 && raw.starts_with(b"RIFF") && &raw[8..12] == b"WEBP" {
        return Some("image/webp");
    }
    let head = String::from_utf8_lossy(&raw[..raw.len().min(256)]).to_ascii_lowercase();
    let head = head.trim_start();
    if head.starts_with("<svg") || (head.starts_with("<?xml") && head.contains("<svg")) {
        return Some("image/svg+xml");
    }
    None
}

/// Frame raw bytes as an image response the webview can load (same-origin, cacheable).
fn favicon_response(bytes: Vec<u8>, ctype: Option<String>) -> Response {
    let ct = ctype
        .filter(|c| c.starts_with("image/"))
        .or_else(|| sniff_image_type(&bytes).map(str::to_string))
        .unwrap_or_else(|| "image/x-icon".to_string());
    (
        [
            (header::CONTENT_TYPE, ct),
            (header::CACHE_CONTROL, "private, max-age=86400".to_string()),
        ],
        bytes,
    )
        .into_response()
}

/// First `<link rel="...icon...">` href in a homepage (mirrors the cloud resolver's regex).
/// Rejects `data:`/`javascript:` hrefs — a hostile declaration must never reach the fetch.
fn parse_icon_href(html: &str) -> Option<String> {
    static LINK_RE: OnceLock<regex::Regex> = OnceLock::new();
    static HREF_RE: OnceLock<regex::Regex> = OnceLock::new();
    let link_re = LINK_RE.get_or_init(|| {
        regex::Regex::new(r#"(?i)<link[^>]+rel=["']?[^"'>]*icon[^"'>]*["']?[^>]*>"#).unwrap()
    });
    let href_re =
        HREF_RE.get_or_init(|| regex::Regex::new(r#"(?i)href=["']([^"']+)["']"#).unwrap());
    let tag = link_re.find(html)?;
    let href = href_re.captures(tag.as_str())?.get(1)?.as_str().trim().to_string();
    if href.is_empty() {
        return None;
    }
    let lower = href.to_ascii_lowercase();
    if lower.starts_with("data:") || lower.starts_with("javascript:") {
        return None;
    }
    Some(href)
}

/// Best-effort favicon for a LOCAL crawl's site: the homepage's `<link rel=icon>` first
/// (accurate), else `/favicon.ico`. Size-capped + magic-byte sniffed, then cached per
/// crawl id. Mirrors the cloud resolver. None when the site has no usable icon.
async fn resolve_local_favicon(id: i64, seed_url: &str) -> Option<(Vec<u8>, String)> {
    if let Some(hit) = favicon_cache().lock().ok().and_then(|c| c.get(&id).cloned()) {
        return Some(hit);
    }
    let base = url::Url::parse(seed_url).ok()?;
    if !matches!(base.scheme(), "http" | "https") {
        return None;
    }
    let origin = base.origin().ascii_serialization();
    // SECURITY (SSRF): this resolver was the ONE outbound path in the crate without a URL guard, and
    // it follows a PAGE-CONTROLLED `<link rel=icon href>`. Three defenses, all required:
    //   1. `is_navigation_url_safe_async` on EVERY fetch target, including the homepage — the seed's
    //      own origin is user-supplied and may resolve internally.
    //   2. the vetting DNS resolver, so the address reqwest actually dials is filtered (closes the
    //      guard-then-connect rebind race the guard alone cannot).
    //   3. `redirect(Policy::none())` — reqwest's default follows up to 10 hops with no vetting, so a
    //      302 to `http://169.254.169.254/…` bypassed everything above. A favicon needs no redirects.
    let cli = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .connect_timeout(std::time::Duration::from_secs(5))
        .dns_resolver(crate::security::vetting_resolver::shared())
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .ok()?;

    // Declared icon first (accurate), then the conventional /favicon.ico.
    let mut candidates: Vec<String> = Vec::new();
    if crate::security::url_guard::is_navigation_url_safe_async(&origin).await {
        if let Ok(resp) = cli.get(&origin).send().await {
            if resp.status().is_success() {
                // Bounded read: reqwest transparently gunzips, so an uncapped `text()` here let the
                // crawled homepage inflate ~1 MB on the wire into ~1 GB resident.
                if let Ok(html) = crate::crawl_shard::body_limit::read_text_capped(
                    resp,
                    crate::crawl_shard::body_limit::HTML_MAX,
                )
                .await
                {
                    if let Some(href) = parse_icon_href(&html) {
                        // NB `Url::join` with an ABSOLUTE href discards the base entirely, so this
                        // candidate can point anywhere — it is vetted below like any other.
                        if let Ok(u) = base.join(&href) {
                            candidates.push(u.to_string());
                        }
                    }
                }
            }
        }
    }
    candidates.push(format!("{origin}/favicon.ico"));

    for url in candidates {
        if !crate::security::url_guard::is_navigation_url_safe_async(&url).await {
            tracing::warn!(crawl_id = id, %url, "favicon candidate refused by SSRF guard");
            continue;
        }
        let resp = match cli.get(&url).send().await {
            Ok(r) if r.status().is_success() => r,
            _ => continue,
        };
        // Capped read rather than `bytes()` then check: the old order buffered the whole (gunzipped)
        // body before deciding it was too big.
        let bytes = match crate::crawl_shard::body_limit::read_bytes_capped(resp, MAX_FAVICON_BYTES)
            .await
        {
            Ok(b) => b,
            Err(_) => continue,
        };
        if bytes.is_empty() {
            continue;
        }
        if let Some(ct) = sniff_image_type(&bytes) {
            let hit = (bytes, ct.to_string());
            if let Ok(mut c) = favicon_cache().lock() {
                c.insert(id, hit.clone());
            }
            return Some(hit);
        }
    }
    None
}

/// `GET /v1/crawl/:id/favicon` — the crawl's SITE favicon (a crawl is one site), served
/// same-origin: the desktop webview's CSP (`img-src 'self' data: blob:`) blocks a
/// cross-site `<img src>`, so the glyph bytes must come from the daemon. Cloud-routed
/// when linked (the cloud resolves + caches it in object storage); otherwise resolved
/// from the local crawl's seed URL and cached in-process. 404 → the UI's globe glyph.
async fn favicon(State(st): State<AppState>, Path(id): Path<i64>) -> LocalResult<Response> {
    #[cfg(feature = "cloud")]
    if crate::local::cloud::crawl::is_linked(&st.db).await {
        let (bytes, ctype) = crate::local::cloud::crawl::favicon(&st.db, id).await?;
        return Ok(favicon_response(bytes, ctype));
    }
    let row = crawl_jobs::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("crawl {id}")))?;
    let (bytes, ct) = resolve_local_favicon(id, &row.seed_url)
        .await
        .ok_or_else(|| LocalError::NotFound(format!("favicon for crawl {id}")))?;
    Ok(favicon_response(bytes, Some(ct)))
}

/// Serialize a crawl row into the API status view: parse the JSON-TEXT scope columns into arrays,
/// add the `Dragnet` brand + the `data_workflow_id` alias + the derived active-worker count the UI
/// meter reads. Mirrors the cloud `_view()` shape.
fn to_view(job: &CrawlJob) -> Value {
    let mut v = serde_json::to_value(job).unwrap_or_else(|_| json!({}));
    if let Some(obj) = v.as_object_mut() {
        // JSON-TEXT → arrays/objects for the UI.
        if let Some(inc) = obj.get("include_paths").and_then(|x| x.as_str()) {
            obj.insert("include_paths".into(), serde_json::from_str(inc).unwrap_or_else(|_| json!([])));
        }
        if let Some(exc) = obj.get("exclude_paths").and_then(|x| x.as_str()) {
            obj.insert("exclude_paths".into(), serde_json::from_str(exc).unwrap_or_else(|_| json!([])));
        }
        if let Some(schema) = obj.get("extract_schema").and_then(|x| x.as_str()) {
            obj.insert("extract_schema".into(), serde_json::from_str(schema).unwrap_or(Value::Null));
        }
        obj.insert("brand".into(), json!("Dragnet"));
        obj.insert("data_workflow_id".into(), obj.get("workflow_id").cloned().unwrap_or(Value::Null));
        obj.insert("is_terminal".into(), json!(job.is_terminal()));
        // Site-favicon proxy path (a crawl is one site). Relative to the client's `/v1`
        // base, so the webview loads it same-origin; 404 → the UI's globe glyph.
        obj.insert("favicon".into(), json!(format!("/crawl/{}/favicon", job.id)));
    }
    v
}

// ── Saved crawls — the callable crawl API ────────────────────────────────────
//
// A saved crawl is a stored configuration with a stable slug, so a crawl can be CALLED by API and
// re-run with the same settings — and, with `max_age`, answered from the data it already collected
// instead of crawling the site again.
//
// Build split, mirroring every other crawl route here: on the managed (`cloud`) desktop a crawl runs
// on the FLEET, so the definitions must live where the runs do — these proxy. Keeping a local mirror
// would give the user two divergent lists of "my saved crawls" and a `max_age` consulting the wrong
// history. The OSS build owns its definitions in the local `crawl_definitions` table.

/// Cap an echoed freshness window at 30 days — past that "reuse" means "never crawl again".
const MAX_FRESHNESS_SECONDS: i64 = 30 * 24 * 3600;

/// Body for saving a crawl: presentation fields plus the crawl settings themselves.
#[derive(Debug, Default, Deserialize)]
struct SaveDefinitionRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    slug: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default, deserialize_with = "de_i64")]
    default_max_age_seconds: Option<i64>,
    /// The crawl settings — the same shape `POST /v1/crawl` accepts.
    #[serde(default)]
    config: Option<Value>,
}

/// Body for running a saved crawl. Every field is a DELIVERY control, never a crawl setting — the
/// settings are the saved ones, which is the whole point.
#[derive(Debug, Default, Deserialize)]
struct RunDefinitionRequest {
    #[serde(default, deserialize_with = "de_i64")]
    max_age: Option<i64>,
    #[serde(default, deserialize_with = "de_bool")]
    wait: Option<bool>,
    #[serde(default, deserialize_with = "de_i64")]
    timeout: Option<i64>,
    #[serde(default, deserialize_with = "de_i64")]
    limit: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
struct DefinitionDataQuery {
    limit: Option<i64>,
}

/// Normalize a caller-supplied freshness window; `None` when unspecified or nonsense.
fn clamp_freshness(value: Option<i64>) -> Option<i64> {
    value.filter(|v| *v >= 0).map(|v| v.min(MAX_FRESHNESS_SECONDS))
}

/// The canonical `_cache` envelope, stamped into the response BODY.
///
/// Not headers-only: MCP tools and the SDK clients hand back a payload, not an HTTP response, so a
/// header-only freshness signal is invisible on exactly the surfaces that most need to know whether
/// they just paid for a crawl.
///
/// Cloud-free builds only — a linked build forwards the coordinator's own `_cache` stamp rather than
/// minting one, so both call sites live under `cfg(not(feature = "cloud"))` and this would be dead
/// code with `cloud` on. Matches the other local-only helpers below.
#[cfg(not(feature = "cloud"))]
fn cache_stamp(hit: bool, age_seconds: Option<f64>, source_crawl_id: Option<i64>) -> Value {
    let mut stamp = json!({ "hit": hit });
    if let (Some(age), Some(obj)) = (age_seconds, stamp.as_object_mut()) {
        obj.insert("age_seconds".into(), json!(age.max(0.0) as i64));
    }
    if let (Some(id), Some(obj)) = (source_crawl_id, stamp.as_object_mut()) {
        obj.insert("source_crawl_id".into(), json!(id));
    }
    stamp
}

/// The seed url out of a saved-config blob, for the denormalized column.
fn config_seed_url(config: &Value) -> LocalResult<String> {
    config
        .get("url")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| LocalError::BadRequest("config.url is required".into()))
}

/// `GET /v1/crawl/definitions` — the saved crawls.
async fn list_definitions(
    State(st): State<AppState>,
    Query(q): Query<ListQuery>,
) -> LocalResult<Json<Value>> {
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    #[cfg(feature = "cloud")]
    if crate::local::cloud::crawl::is_linked(&st.db).await {
        return Ok(Json(
            crate::local::cloud::crawl::list_definitions(&st.db, limit).await?,
        ));
    }
    #[cfg(feature = "cloud")]
    {
        let _ = limit;
        return Err(LocalError::BadRequest(CRAWL_NEEDS_CLOUD.into()));
    }
    #[cfg(not(feature = "cloud"))]
    {
        let rows = crate::local::store::crawl_definitions::list(&st.db, limit).await?;
        let definitions: Vec<Value> = rows.iter().map(definition_view).collect();
        Ok(Json(json!({ "definitions": definitions })))
    }
}

/// `POST /v1/crawl/definitions` — save a crawl configuration.
async fn create_definition(
    State(st): State<AppState>,
    Json(body): Json<SaveDefinitionRequest>,
) -> LocalResult<Json<Value>> {
    let config = body
        .config
        .clone()
        .filter(|v| v.is_object())
        .ok_or_else(|| LocalError::BadRequest("config (the crawl settings) is required".into()))?;
    let seed_url = config_seed_url(&config)?;

    #[cfg(feature = "cloud")]
    if crate::local::cloud::crawl::is_linked(&st.db).await {
        let payload = json!({
            "name": body.name,
            "slug": body.slug,
            "description": body.description,
            "default_max_age_seconds": clamp_freshness(body.default_max_age_seconds),
            "config": config,
        });
        return Ok(Json(
            crate::local::cloud::crawl::create_definition(&st.db, &payload).await?,
        ));
    }
    #[cfg(feature = "cloud")]
    {
        let _ = seed_url;
        return Err(LocalError::BadRequest(CRAWL_NEEDS_CLOUD.into()));
    }
    #[cfg(not(feature = "cloud"))]
    {
        use crate::local::store::crawl_definitions as defs;
        let label = body
            .name
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| seed_url.clone());
        let slug = defs::mint_slug(&st.db, body.slug.as_deref().unwrap_or(&label)).await?;
        let row = defs::insert(
            &st.db,
            &defs::NewCrawlDefinition {
                name: label.chars().take(200).collect(),
                slug,
                description: body.description.clone(),
                config: serde_json::to_string(&config)
                    .map_err(|e| LocalError::Internal(format!("config serialize: {e}")))?,
                seed_url,
                default_max_age_seconds: clamp_freshness(body.default_max_age_seconds),
            },
        )
        .await?;
        Ok(Json(definition_view(&row)))
    }
}

/// `GET /v1/crawl/definitions/:reference` — one saved crawl by id, slug, or exact name.
async fn get_definition(
    State(st): State<AppState>,
    Path(reference): Path<String>,
) -> LocalResult<Json<Value>> {
    #[cfg(feature = "cloud")]
    if crate::local::cloud::crawl::is_linked(&st.db).await {
        return Ok(Json(
            crate::local::cloud::crawl::get_definition(&st.db, &reference).await?,
        ));
    }
    #[cfg(feature = "cloud")]
    {
        let _ = reference;
        return Err(LocalError::BadRequest(CRAWL_NEEDS_CLOUD.into()));
    }
    #[cfg(not(feature = "cloud"))]
    {
        let row = resolve_definition(&st, &reference).await?;
        Ok(Json(definition_view(&row)))
    }
}

/// `PATCH /v1/crawl/definitions/:reference` — update saved settings or metadata.
async fn update_definition(
    State(st): State<AppState>,
    Path(reference): Path<String>,
    Json(body): Json<SaveDefinitionRequest>,
) -> LocalResult<Json<Value>> {
    #[cfg(feature = "cloud")]
    if crate::local::cloud::crawl::is_linked(&st.db).await {
        let mut payload = json!({});
        if let Some(obj) = payload.as_object_mut() {
            if let Some(v) = body.name.clone() {
                obj.insert("name".into(), json!(v));
            }
            if let Some(v) = body.description.clone() {
                obj.insert("description".into(), json!(v));
            }
            if let Some(v) = clamp_freshness(body.default_max_age_seconds) {
                obj.insert("default_max_age_seconds".into(), json!(v));
            }
            if let Some(v) = body.config.clone().filter(|c| c.is_object()) {
                obj.insert("config".into(), v);
            }
        }
        return Ok(Json(
            crate::local::cloud::crawl::update_definition(&st.db, &reference, &payload).await?,
        ));
    }
    #[cfg(feature = "cloud")]
    {
        let _ = (reference, body);
        return Err(LocalError::BadRequest(CRAWL_NEEDS_CLOUD.into()));
    }
    #[cfg(not(feature = "cloud"))]
    {
        use crate::local::store::crawl_definitions as defs;
        let row = resolve_definition(&st, &reference).await?;
        if let Some(config) = body.config.clone().filter(|c| c.is_object()) {
            let seed_url = config_seed_url(&config)?;
            let raw = serde_json::to_string(&config)
                .map_err(|e| LocalError::Internal(format!("config serialize: {e}")))?;
            defs::update_config(&st.db, row.id, &raw, &seed_url).await?;
        }
        defs::update_meta(
            &st.db,
            row.id,
            body.name.as_deref(),
            body.description.as_deref(),
            clamp_freshness(body.default_max_age_seconds),
        )
        .await?;
        let fresh = defs::get_by_id(&st.db, row.id)
            .await?
            .ok_or_else(|| LocalError::NotFound(format!("saved crawl {}", row.id)))?;
        Ok(Json(definition_view(&fresh)))
    }
}

/// `DELETE /v1/crawl/definitions/:reference` — remove a saved crawl.
///
/// Its past runs and their collected data survive: only the reusable configuration goes away.
async fn delete_definition(
    State(st): State<AppState>,
    Path(reference): Path<String>,
) -> LocalResult<axum::http::StatusCode> {
    #[cfg(feature = "cloud")]
    if crate::local::cloud::crawl::is_linked(&st.db).await {
        crate::local::cloud::crawl::delete_definition(&st.db, &reference).await?;
        return Ok(axum::http::StatusCode::NO_CONTENT);
    }
    #[cfg(feature = "cloud")]
    {
        let _ = reference;
        return Err(LocalError::BadRequest(CRAWL_NEEDS_CLOUD.into()));
    }
    #[cfg(not(feature = "cloud"))]
    {
        let row = resolve_definition(&st, &reference).await?;
        crate::local::store::crawl_definitions::delete(&st.db, row.id).await?;
        Ok(axum::http::StatusCode::NO_CONTENT)
    }
}

/// `POST /v1/crawl/definitions/:reference/run` — run a saved crawl.
///
/// Freshness: `max_age` returns the last completed run's already-collected data when it is recent
/// enough, dispatching nothing. Otherwise the saved settings are re-crawled. A cold call answers with
/// a crawl handle rather than blocking — a whole-site crawl routinely outlives an HTTP request.
async fn run_definition(
    State(st): State<AppState>,
    Path(reference): Path<String>,
    body: Option<Json<RunDefinitionRequest>>,
) -> LocalResult<Json<Value>> {
    let opts = body.map(|Json(b)| b).unwrap_or_default();

    #[cfg(feature = "cloud")]
    if crate::local::cloud::crawl::is_linked(&st.db).await {
        let payload = json!({
            "max_age": clamp_freshness(opts.max_age).unwrap_or(0),
            "wait": opts.wait.unwrap_or(false),
            "timeout": opts.timeout.unwrap_or(120).clamp(5, 300),
            "limit": opts.limit.unwrap_or(50).clamp(1, 500),
        });
        return Ok(Json(
            crate::local::cloud::crawl::run_definition(&st.db, &reference, &payload).await?,
        ));
    }
    #[cfg(feature = "cloud")]
    {
        let _ = (reference, opts);
        return Err(LocalError::BadRequest(CRAWL_NEEDS_CLOUD.into()));
    }
    #[cfg(not(feature = "cloud"))]
    {
        use crate::local::store::crawl_definitions as defs;

        // `wait` / `timeout` are delivery controls only the CLOUD path above can honour — it can
        // block on a managed crawl and hand the result back inline. Locally a crawl is always
        // dispatched asynchronously, so there is nothing to block on.
        //
        // Refuse loudly rather than accept a control we ignore: silently dropping `wait: true`
        // hands an empty body to a caller that explicitly asked for results, and it would read as
        // "the crawl returned nothing" rather than "this build cannot wait". (Reading both fields
        // here is also what keeps them from being dead code in the cloud-free build, where the
        // branch above is compiled out — `-D warnings` in CI turns that into a build failure.)
        if opts.wait.unwrap_or(false) || opts.timeout.is_some() {
            return Err(LocalError::BadRequest(
                "wait/timeout are not supported on a self-host crawl: the run is dispatched \
                 asynchronously — poll status_url, or pass max_age to reuse a recent run"
                    .into(),
            ));
        }

        let defn = resolve_definition(&st, &reference).await?;
        let limit = opts.limit.unwrap_or(50).clamp(1, 500);

        // The definition's own default applies ONLY when the caller said nothing. An explicit
        // max_age=0 means "run it fresh" and must win over the stored preference.
        let max_age = clamp_freshness(opts.max_age).or(defn.default_max_age_seconds).unwrap_or(0);

        if max_age > 0 {
            if let Some(fresh) = defs::find_fresh_run(&st.db, defn.id, max_age).await? {
                let age = defs::run_age_seconds(&st.db, fresh.id).await?;
                return Ok(Json(json!({
                    "cached": true,
                    "_cache": cache_stamp(true, age, Some(fresh.id)),
                    "definition": definition_view(&defn),
                    "crawl": to_view(&fresh),
                    "status_url": format!("/crawl/{}", fresh.id),
                    "data_url": fresh.workflow_id.map(|w| format!("/workflows/{w}/data")),
                    "data": inline_crawl_data(&st, &fresh, limit).await,
                })));
            }
        }

        let config: Value = serde_json::from_str(&defn.config)
            .map_err(|e| LocalError::Internal(format!("saved crawl config is not valid JSON: {e}")))?;
        // Re-parse the saved blob through the SAME request struct the live endpoint uses, so a
        // stored config can never dispatch a crawl `POST /v1/crawl` would have rejected.
        let request: StartCrawlRequest = serde_json::from_value(config)
            .map_err(|e| LocalError::BadRequest(format!("saved crawl config is invalid: {e}")))?;
        let crawl = crawl::start_crawl(&st, params_from_request(request)).await?;
        defs::attach_run(&st.db, crawl.id, defn.id).await?;
        defs::touch_last_run(&st.db, defn.id).await?;

        let mut view = to_view(&crawl);
        if let Some(obj) = view.as_object_mut() {
            obj.insert("definition_id".into(), json!(defn.id));
        }
        Ok(Json(json!({
            "cached": false,
            "_cache": cache_stamp(false, None, None),
            "definition": definition_view(&defn),
            "crawl": view,
            "status_url": format!("/crawl/{}", crawl.id),
            "data_url": crawl.workflow_id.map(|w| format!("/workflows/{w}/data")),
        })))
    }
}

/// `GET /v1/crawl/definitions/:reference/data` — the data a saved crawl already collected on its most
/// recent completed run. A pure read: never starts a crawl.
async fn definition_data(
    State(st): State<AppState>,
    Path(reference): Path<String>,
    Query(q): Query<DefinitionDataQuery>,
) -> LocalResult<Json<Value>> {
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    #[cfg(feature = "cloud")]
    if crate::local::cloud::crawl::is_linked(&st.db).await {
        return Ok(Json(
            crate::local::cloud::crawl::definition_data(&st.db, &reference, limit).await?,
        ));
    }
    #[cfg(feature = "cloud")]
    {
        let _ = (reference, limit);
        return Err(LocalError::BadRequest(CRAWL_NEEDS_CLOUD.into()));
    }
    #[cfg(not(feature = "cloud"))]
    {
        use crate::local::store::crawl_definitions as defs;
        let defn = resolve_definition(&st, &reference).await?;
        // A very large window, not "any age": this endpoint means "whatever is there", and reusing
        // find_fresh_run keeps ONE definition of what counts as a usable run (completed, non-empty)
        // instead of a second, subtly different query.
        match defs::find_fresh_run(&st.db, defn.id, i64::MAX / 4).await? {
            None => Ok(Json(json!({
                "definition": definition_view(&defn),
                "crawl": Value::Null,
                "age_seconds": Value::Null,
                "data_url": Value::Null,
                "data": Value::Null,
            }))),
            Some(last) => {
                let age = defs::run_age_seconds(&st.db, last.id).await?;
                Ok(Json(json!({
                    "definition": definition_view(&defn),
                    "crawl": to_view(&last),
                    "age_seconds": age,
                    "data_url": last.workflow_id.map(|w| format!("/workflows/{w}/data")),
                    "data": inline_crawl_data(&st, &last, limit).await,
                })))
            }
        }
    }
}

/// Resolve a saved crawl or 404. OSS-only — the managed build proxies instead.
#[cfg(not(feature = "cloud"))]
async fn resolve_definition(
    st: &AppState,
    reference: &str,
) -> LocalResult<crate::local::store::crawl_definitions::CrawlDefinition> {
    crate::local::store::crawl_definitions::resolve(&st.db, reference)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("saved crawl '{reference}'")))
}

/// A saved crawl's API view: the row plus the URLs that make it callable.
#[cfg(not(feature = "cloud"))]
fn definition_view(defn: &crate::local::store::crawl_definitions::CrawlDefinition) -> Value {
    let mut v = serde_json::to_value(defn).unwrap_or_else(|_| json!({}));
    if let Some(obj) = v.as_object_mut() {
        // JSON-TEXT → a real object for the UI, matching how to_view unpacks its blobs.
        if let Some(raw) = obj.get("config").and_then(|c| c.as_str()) {
            obj.insert(
                "config".into(),
                serde_json::from_str(raw).unwrap_or_else(|_| json!({})),
            );
        }
        obj.insert(
            "run_url".into(),
            json!(format!("/crawl/definitions/{}/run", defn.slug)),
        );
        obj.insert(
            "data_url".into(),
            json!(format!("/crawl/definitions/{}/data", defn.slug)),
        );
    }
    v
}

/// The rows a crawl collected, flattened the same way the Workflow Data API flattens them.
///
/// Returns JSON null rather than failing the call: a data-assembly problem must not sink an
/// otherwise-successful run, and the caller still has `data_url` to read at their leisure.
#[cfg(not(feature = "cloud"))]
async fn inline_crawl_data(st: &AppState, crawl: &CrawlJob, limit: i64) -> Value {
    let Some(workflow_id) = crawl.workflow_id else {
        return Value::Null;
    };
    let scanned = super::data::scan_workflow_data_runs_pool(&st.db, workflow_id).await;
    let Ok((inputs, truncated)) = scanned else {
        tracing::warn!(crawl_id = crawl.id, "inline crawl data scan failed");
        return Value::Null;
    };
    if inputs.is_empty() {
        return Value::Null;
    }
    let (columns, mut rows) = crate::local::data_query::flatten(&inputs, &[], true);
    rows.truncate(limit.max(0) as usize);
    // rows_to_table_json, not a bare serialize: the desktop table UI reads each cell from
    // `row.fields[column]`, so this is the same row shape `/v1/workflows/:id/data` returns. A flat
    // row would render every data cell blank.
    let rows = crate::local::data_query::rows_to_table_json(&rows, &columns);
    json!({ "columns": columns, "rows": rows, "truncated": truncated })
}

/// Build the local crawl params from a start request. Shared by `POST /v1/crawl` and the saved-crawl
/// run path so a saved config and a direct call cannot diverge in how they are interpreted.
#[cfg(not(feature = "cloud"))]
fn params_from_request(body: StartCrawlRequest) -> StartParams {
    let defaults = StartParams::default();
    StartParams {
        seed_url: body.url,
        name: body.name,
        extract_mode: body.extract_mode.unwrap_or_else(|| "markdown".into()),
        extract_schema: body.extract_schema,
        persona_id: body.persona_id,
        include_paths: body.include_paths.unwrap_or_default(),
        exclude_paths: body.exclude_paths.unwrap_or_default(),
        max_depth: body.max_depth.unwrap_or(defaults.max_depth),
        page_budget: body.page_budget.unwrap_or(defaults.page_budget),
        max_concurrent: body.max_concurrent.unwrap_or(defaults.max_concurrent),
        delay_ms: body.delay_ms.unwrap_or(defaults.delay_ms),
        respect_robots: body.respect_robots.unwrap_or(true),
        same_domain: body.same_domain.unwrap_or(true),
        allow_subdomains: body.allow_subdomains.unwrap_or(true),
        content: body.content.clone().filter(|v| !v.is_null()),
        concierge_session_id: None,
    }
}

/// Map the desktop start body → the cloud `StartCrawlRequest` JSON. The desktop form
/// speaks a slightly smaller vocabulary (`max_concurrent` = the local worker cap); the
/// cloud wants `max_concurrent_shards` plus the `executor` axis + `extract_prompt`.
#[cfg(feature = "cloud")]
fn build_cloud_start_body(b: &StartCrawlRequest) -> Value {
    json!({
        "url": b.url,
        "name": b.name,
        "executor": b.executor.clone().unwrap_or_else(|| "regular".into()),
        "extract_mode": b.extract_mode.clone().unwrap_or_else(|| "markdown".into()),
        "extract_schema": b.extract_schema,
        "extract_prompt": b.extract_prompt,
        // Fetch lane + document policy. Sent unset-safe: the cloud validates the string and
        // falls back to "auto" itself, so a null here means "the user didn't choose".
        "render_mode": b.render_mode.clone().unwrap_or_else(|| "auto".into()),
        "ocr_mode": b.ocr_mode.clone().unwrap_or_else(|| "auto".into()),
        "use_residential": b.use_residential.unwrap_or(false),
        // AI-supervised scoping — forwarded verbatim so the cloud derives the scope
        // + ranks the frontier by relevance. `intent`/`seed_urls`/`max_depth` are
        // Optional on the cloud (null reads as "unset", which is what triggers
        // goal-driven derivation); `relevance_threshold` is a plain float (default 0).
        "intent": b.intent,
        "seed_urls": b.seed_urls,
        "relevance_threshold": b.relevance_threshold.unwrap_or(0.0),
        "persona_id": b.persona_id,
        "include_paths": b.include_paths,
        "exclude_paths": b.exclude_paths,
        // Pass the depth through unset (null) rather than defaulting to 4 — a forced
        // depth would suppress intent-derivation on the cloud (which only derives when
        // include/exclude/depth are all unset). The cloud defaults an unset depth itself.
        "max_depth": b.max_depth,
        "content": b.content,
        "page_budget": b.page_budget.unwrap_or(1000),
        "max_concurrent_shards": b.max_concurrent.unwrap_or(6),
        "delay_ms": b.delay_ms.unwrap_or(250),
        "respect_robots": b.respect_robots.unwrap_or(true),
        "same_domain": b.same_domain.unwrap_or(true),
        "allow_subdomains": b.allow_subdomains.unwrap_or(true),
    })
}

/// Normalize a cloud crawl `_view` into the desktop status-view shape: the cloud sends
/// `brand` as an object `{crawl, agent}` and omits `workers_active`/`is_terminal` (a
/// per-shard fleet concept), so derive them here. Idempotent + null-safe.
#[cfg(feature = "cloud")]
fn cloud_to_view(mut v: Value) -> Value {
    if let Some(obj) = v.as_object_mut() {
        // Cloud brand is {crawl, agent}; the desktop UI reads brand as a plain string.
        if let Some(crawl_brand) = obj
            .get("brand")
            .and_then(|b| b.get("crawl"))
            .and_then(|c| c.as_str())
            .map(|s| s.to_string())
        {
            obj.insert("brand".into(), json!(crawl_brand));
        }
        // workers_active = shards dispatched but not yet done (the UI progress meter).
        if !obj.contains_key("workers_active") {
            let disp = obj.get("shards_dispatched").and_then(|x| x.as_i64()).unwrap_or(0);
            let done = obj.get("shards_done").and_then(|x| x.as_i64()).unwrap_or(0);
            obj.insert("workers_active".into(), json!((disp - done).max(0)));
        }
        // is_terminal from status (the cloud summary doesn't send the derived flag).
        let terminal = matches!(
            obj.get("status").and_then(|s| s.as_str()),
            Some("completed") | Some("failed") | Some("cancelled")
        );
        obj.insert("is_terminal".into(), json!(terminal));
        if !obj.contains_key("data_workflow_id") {
            let wf = obj.get("workflow_id").cloned().unwrap_or(Value::Null);
            obj.insert("data_workflow_id".into(), wf);
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::{db, engine, vault};
    use std::sync::Arc;

    async fn state() -> AppState {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let v = vault::Vault::load_or_create(dir.path(), false).unwrap();
        let pool = db::open(&dir.path().join("t.db"), &v.db_key_hex()).await.unwrap();
        AppState {
            db: pool,
            vault: Arc::new(v),
            engine: Arc::new(engine::StubEngine),
            config: crate::local::config::LocalConfig::default(),
            token: Arc::new("wlt_test".into()),
            health: crate::local::app::health::DaemonHealth::shared(),
            recorder: None,
        }
    }

    #[test]
    fn start_request_accepts_form_shapes() {
        // Bools as real bools + numeric strings from form inputs must all deserialize.
        let body: StartCrawlRequest = serde_json::from_value(json!({
            "url": "https://example.com",
            "extract_mode": "markdown",
            "max_depth": "2",
            "page_budget": 100,
            "respect_robots": true,
            "same_domain": "true",
            "include_paths": ["^/docs"],
        }))
        .unwrap();
        assert_eq!(body.url, "https://example.com");
        assert_eq!(body.max_depth, Some(2));
        assert_eq!(body.page_budget, Some(100));
        assert_eq!(body.respect_robots, Some(true));
        assert_eq!(body.same_domain, Some(true));
        assert_eq!(body.include_paths.as_ref().unwrap(), &vec!["^/docs".to_string()]);
    }

    #[cfg(feature = "cloud")]
    #[test]
    fn cloud_start_body_carries_every_knob_the_ui_sends() {
        // A crawl on the managed desktop RUNS ON THE CLOUD, so this body is the whole
        // contract. Serde drops unknown keys silently and the cloud defaults anything
        // absent, so a knob missing from either the struct or this body is invisible:
        // no error, just a crawl that ignored what the user chose. The Render lane in
        // particular is independent of the executor — "AI reader + full browser" is a
        // combination the UI offers, and both halves have to survive the hop.
        let body: StartCrawlRequest = serde_json::from_value(json!({
            "url": "https://example.com",
            "executor": "ai",
            "extract_prompt": "the product name and price",
            "render_mode": "browser",
            "ocr_mode": "force",
            "use_residential": true,
            // Every client posts `content_spec`; `content` is the legacy wire name.
            "content_spec": {"preset": "main"},
        }))
        .unwrap();

        let out = build_cloud_start_body(&body);
        assert_eq!(out["executor"], "ai");
        assert_eq!(out["extract_prompt"], "the product name and price");
        assert_eq!(out["render_mode"], "browser");
        assert_eq!(out["ocr_mode"], "force");
        assert_eq!(out["use_residential"], true);
        assert_eq!(out["content"]["preset"], "main");
    }

    #[cfg(feature = "cloud")]
    #[test]
    fn cloud_start_body_defaults_the_lane_when_unchosen() {
        let body: StartCrawlRequest =
            serde_json::from_value(json!({"url": "https://example.com"})).unwrap();
        let out = build_cloud_start_body(&body);
        assert_eq!(out["executor"], "regular");
        assert_eq!(out["render_mode"], "auto");
        assert_eq!(out["ocr_mode"], "auto");
        assert_eq!(out["use_residential"], false);
    }

    #[test]
    fn sniff_image_type_gates_non_images() {
        assert_eq!(sniff_image_type(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]), Some("image/png"));
        assert_eq!(sniff_image_type(&[0x00, 0x00, 0x01, 0x00, 0x01]), Some("image/x-icon"));
        assert_eq!(sniff_image_type(b"GIF89a"), Some("image/gif"));
        assert_eq!(sniff_image_type(&[0xff, 0xd8, 0xff]), Some("image/jpeg"));
        assert_eq!(sniff_image_type(b"<svg xmlns='...'></svg>"), Some("image/svg+xml"));
        // An HTML 404 body served at /favicon.ico must NOT pass as an image.
        assert_eq!(sniff_image_type(b"<!DOCTYPE html><html>not found</html>"), None);
        assert_eq!(sniff_image_type(b""), None);
    }

    #[test]
    fn parse_icon_href_picks_declared_icon_and_rejects_hostile() {
        assert_eq!(
            parse_icon_href(r#"<link rel="shortcut icon" href="/static/fav.png">"#),
            Some("/static/fav.png".to_string()),
        );
        assert_eq!(
            parse_icon_href(r#"<link rel="apple-touch-icon" href="https://cdn.x/i.png">"#),
            Some("https://cdn.x/i.png".to_string()),
        );
        // A hostile declaration must never reach the fetch (fall back to /favicon.ico).
        assert_eq!(parse_icon_href(r#"<link rel="icon" href="javascript:alert(1)">"#), None);
        assert_eq!(parse_icon_href(r#"<link rel="icon" href="data:image/png;base64,xx">"#), None);
        assert_eq!(parse_icon_href("<html><head></head></html>"), None);
    }

    #[tokio::test]
    async fn get_list_cancel_and_view_shape() {
        // Insert a crawl row directly (start() would resolve DNS via the SSRF guard, which is
        // non-deterministic offline) and exercise the read/cancel handlers + the view shape.
        let st = state().await;
        let row = crawl_jobs::insert(
            &st.db,
            &crawl_jobs::NewCrawlJob {
                name: "Dragnet: example.com".into(),
                seed_url: "https://example.com".into(),
                include_paths: Some("[\"^/docs\"]".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        // Bind a REAL synthetic workflow (the FK is enforced).
        let wf = crate::local::store::workflows::insert(
            &st.db,
            &crate::local::store::workflows::NewWorkflow {
                name: "Dragnet: example.com".into(),
                workflow_type: Some("crawl".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        crawl_jobs::set_workflow_id(&st.db, row.id, wf.id).await.unwrap();
        let id = row.id;

        // get_one → the view carries the brand, parsed scope arrays, and the data_workflow_id alias.
        let Json(one) = get_one(State(st.clone()), Path(id)).await.unwrap();
        assert_eq!(one["id"], json!(id));
        assert_eq!(one["brand"], json!("Dragnet"));
        assert_eq!(one["data_workflow_id"], json!(wf.id));
        assert_eq!(one["include_paths"], json!(["^/docs"]));
        assert_eq!(one["is_terminal"], json!(false));

        // list wraps it under "crawls".
        let Json(listed) = list(State(st.clone()), Query(ListQuery::default())).await.unwrap();
        assert!(listed["crawls"].as_array().unwrap().iter().any(|c| c["id"] == json!(id)));

        // cancel flips it to stopping.
        let Json(cancelled) = cancel(State(st.clone()), Path(id)).await.unwrap();
        assert_eq!(cancelled["id"], json!(id));
        assert_eq!(cancelled["status"], json!("stopping"));
        assert_eq!(cancelled["cancel_requested_now"], json!(true));

        // A missing crawl 404s on read + cancel.
        assert!(matches!(get_one(State(st.clone()), Path(999_999)).await.unwrap_err(), LocalError::NotFound(_)));
        assert!(matches!(cancel(State(st), Path(999_999)).await.unwrap_err(), LocalError::NotFound(_)));
    }

    /// SSRF: the favicon resolver is the one outbound path that follows a PAGE-CONTROLLED href, and
    /// `Url::join` with an absolute href discards the base — so `href="http://169.254.169.254/…"`
    /// became the fetch target. Every candidate (and the homepage itself) must now clear the guard.
    #[tokio::test]
    async fn favicon_resolver_refuses_internal_seed_origins() {
        // A loopback / link-local / metadata seed must produce no fetch at all → None.
        for seed in [
            "http://127.0.0.1/",
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost:6379/",
            "http://10.0.0.5/",
            "http://[::1]/",
        ] {
            assert!(
                resolve_local_favicon(0, seed).await.is_none(),
                "internal seed must be refused: {seed}"
            );
        }
        // A non-http(s) seed is rejected before any client is built.
        assert!(resolve_local_favicon(0, "file:///etc/passwd").await.is_none());
        assert!(resolve_local_favicon(0, "not a url").await.is_none());
    }

    /// The page-controlled href is joined against the base, and an ABSOLUTE href replaces the base
    /// entirely — the property that made the guard mandatory. Documented here so the guard above is
    /// never "optimized away" as redundant.
    #[test]
    fn absolute_icon_href_escapes_the_seed_origin() {
        let base = url::Url::parse("https://victim.test/page").unwrap();
        let href = parse_icon_href(
            r#"<link rel="icon" href="http://169.254.169.254/latest/meta-data/">"#,
        )
        .unwrap();
        let joined = base.join(&href).unwrap();
        assert_eq!(joined.host_str(), Some("169.254.169.254"), "join kept the base host?");
        assert!(
            !crate::security::url_guard::is_redirect_target_safe(joined.as_str()),
            "the guard must reject the joined candidate"
        );
    }

    #[tokio::test]
    async fn start_rejects_empty_url() {
        let st = state().await;
        let err = start(State(st), Json(StartCrawlRequest { url: "  ".into(), ..Default::default() }))
            .await
            .unwrap_err();
        assert!(matches!(err, LocalError::BadRequest(_)));
    }
}
