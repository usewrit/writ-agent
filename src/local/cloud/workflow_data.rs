//! Authenticated passthroughs to the cloud Workflow Data API (`/api/automation/workflows/{id}/data`).
//!
//! A cloud Dragnet crawl aggregates its pages under a synthetic per-crawl workflow that lives
//! on the fleet, NOT on this machine — so when a cloud account is linked the daemon holds no
//! local row for that `data_workflow_id`. The Outputs data routes detect the miss and forward
//! the read here (same `wto_` auth funnel as [`super::crawl`]), handing the cloud's own JSON
//! straight back to the desktop table. READ-ONLY: the desktop never mutates cloud-owned crawl
//! data through this path (deletes/edits stay local and simply 404 for a cloud id).

use super::client::CloudClient;
use super::state::LinkState;
use crate::local::error::LocalResult;
use serde_json::Value;
use sqlx::sqlite::SqlitePool;

/// Backend automation router mount for the Workflow Data API. The router itself declares
/// `APIRouter(prefix="/automation")` and is mounted at `/api` (`backend/main.py`,
/// `include_router(automation_router, prefix="/api")`), so the live path is
/// `/api/automation/workflows/{id}/data{,/facets,/runs,/records/{uid}/history,/export}`.
/// This route returns the FLAT shape (`workflow_id`, `workflow_name`, `rows`, `total`,
/// `scanned_runs`, …) the callers here re-key from — the versioned `/api/v1/workflows/{id}/data`
/// surface nests those under `workflow`/`pagination` and lacks the lineage sub-routes, so it is
/// NOT interchangeable here. The daemon's `wto_` OAuth token authenticates (get_current_api_key
/// accepts it, tenant-scoped) and is exempt from the CLIENT-key `/api/v1/*` path restriction.
const WORKFLOWS: &str = "/api/automation/workflows";

/// Open an authenticated cloud client for the current link, or a clean `Unauthorized` when the
/// desktop is not linked (no panic, no partial work).
async fn client(db: &SqlitePool) -> LocalResult<CloudClient> {
    let link = LinkState::load_or_default(db).await?;
    CloudClient::connect(Some(&link))
}

/// Join `?query` onto a base path only when the query is present and non-empty.
fn with_query(mut path: String, query: Option<&str>) -> String {
    if let Some(q) = query {
        if !q.is_empty() {
            path.push('?');
            path.push_str(q);
        }
    }
    path
}

/// `GET /api/workflows/{id}/data{sub}?{query}` — forward a JSON data read (base table when
/// `sub` is `""`, or a suffix like `/facets`, `/runs`, `/records/{uid}/history`) for a cloud
/// crawl's dataset and return the cloud's JSON verbatim. `query` is the already-encoded query
/// string (no leading `?`) carried through from the desktop request.
pub async fn get(db: &SqlitePool, id: i64, sub: &str, query: Option<&str>) -> LocalResult<Value> {
    let path = with_query(format!("{WORKFLOWS}/{id}/data{sub}"), query);
    client(db).await?.get_json(&path).await
}

/// `GET /api/workflows/{id}/data/export?{query}` — forward a data EXPORT for a cloud crawl's
/// dataset, returning the raw bytes + `Content-Type` / `Content-Disposition` so the daemon can
/// stream the CSV/JSON download straight through to the desktop.
pub async fn export(
    db: &SqlitePool,
    id: i64,
    query: Option<&str>,
) -> LocalResult<(Vec<u8>, Option<String>, Option<String>)> {
    let path = with_query(format!("{WORKFLOWS}/{id}/data/export"), query);
    client(db).await?.get_bytes(&path).await
}
