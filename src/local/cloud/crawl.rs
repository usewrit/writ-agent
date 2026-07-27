//! Authenticated passthroughs to the cloud Dragnet crawl API (`/api/crawl`).
//!
//! Desktop Dragnet is a CLOUD feature: a whole-site crawl fans out across the cloud
//! fleet (many egress IPs, managed browsers, gateway-metered AI extraction), NOT this
//! one machine. When a cloud account is linked the daemon forwards crawl
//! start/list/get/cancel here instead of driving the local worker pool — the same way
//! a cloud-gated workflow routes to the fleet. Mirrors the marketplace passthrough
//! style: one `client()` funnel so the `wto_` token is loaded once from the keyring
//! and never leaves the daemon; raw JSON in/out, the cloud owns every semantic.

use super::client::CloudClient;
use super::state::LinkState;
use crate::local::error::LocalResult;
use serde_json::{json, Value};
use sqlx::sqlite::SqlitePool;

/// Backend crawl router mount (the cloud backend's `crawl` router, `include_router(prefix="/api")`).
const CRAWL: &str = "/api/crawl";

/// True when a cloud account is linked — the signal that a desktop crawl should run
/// on the fleet rather than locally. Never panics; an unreadable link reads unlinked.
pub async fn is_linked(db: &SqlitePool) -> bool {
    LinkState::load_or_default(db)
        .await
        .map(|l| l.is_linked())
        .unwrap_or(false)
}

/// Open an authenticated cloud client for the current link, or a clean `Unauthorized`
/// when the desktop is not linked (no panic, no partial work).
async fn client(db: &SqlitePool) -> LocalResult<CloudClient> {
    let link = LinkState::load_or_default(db).await?;
    CloudClient::connect(Some(&link))
}

/// `POST /api/crawl` — start a crawl on the cloud fleet. `body` is the cloud
/// `StartCrawlRequest` JSON. Returns the cloud crawl status view.
pub async fn start(db: &SqlitePool, body: &Value) -> LocalResult<Value> {
    client(db).await?.post_json(CRAWL, body).await
}

/// `POST /api/crawl/map` — list a site's URLs (sitemap + harvest), ranked by relevance
/// to an optional `search`. Read-only, spends nothing (Firecrawl's /map).
pub async fn map(db: &SqlitePool, body: &Value) -> LocalResult<Value> {
    client(db).await?.post_json(&format!("{CRAWL}/map"), body).await
}

/// `POST /api/crawl/scrape` — scrape one page to markdown, metered per page against the linked plan.
/// The authed single-page twin of the keyless tier: a linked account gets uncapped scrape here.
pub async fn scrape(db: &SqlitePool, body: &Value) -> LocalResult<Value> {
    client(db).await?.post_json(&format!("{CRAWL}/scrape"), body).await
}

/// `GET /api/crawl?limit=N` — newest-first list of the account's crawls.
pub async fn list(db: &SqlitePool, limit: i64) -> LocalResult<Value> {
    let path = format!("{CRAWL}?limit={}", limit.clamp(1, 200));
    client(db).await?.get_json(&path).await
}

/// `GET /api/crawl/{id}` — one crawl's live status (the id is a CLOUD crawl id,
/// carried back from `list`/`start`, so the frontend polls it verbatim).
pub async fn get(db: &SqlitePool, id: i64) -> LocalResult<Value> {
    client(db).await?.get_json(&format!("{CRAWL}/{id}")).await
}

/// `GET /api/crawl/{id}/favicon` — the crawl's SITE favicon (raw image bytes + its
/// `Content-Type`). The cloud resolves it from the site once and caches it in object
/// storage; the daemon only relays the bytes so the webview can load the glyph
/// same-origin (its CSP blocks a cross-site `<img src>`). 404 → no favicon.
pub async fn favicon(db: &SqlitePool, id: i64) -> LocalResult<(Vec<u8>, Option<String>)> {
    let (bytes, ctype, _) = client(db)
        .await?
        .get_bytes(&format!("{CRAWL}/{id}/favicon"))
        .await?;
    Ok((bytes, ctype))
}

/// `DELETE /api/crawl/{id}` — remove a cloud crawl and its dataset (terminal only).
pub async fn remove(db: &SqlitePool, id: i64) -> LocalResult<()> {
    client(db).await?.delete(&format!("{CRAWL}/{id}")).await
}

/// `POST /api/crawl/{id}/cancel` — request cancellation of a cloud crawl.
pub async fn cancel(db: &SqlitePool, id: i64) -> LocalResult<Value> {
    client(db)
        .await?
        .post_json(&format!("{CRAWL}/{id}/cancel"), &json!({}))
        .await
}
