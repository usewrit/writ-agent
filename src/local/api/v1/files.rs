//! `/v1/files` REST handlers — metadata (list/get/delete) + byte I/O (upload/download).
//!
//! These are OpenAI-style file handles (TEXT id `file_<hex>`); the bytes live on disk under
//! `~/.writ/files` as a vault-encrypted `WFB1` envelope (Layer C, K_file) and the row here is
//! metadata. This module exposes both surfaces:
//!   - metadata: `GET /v1/files`, `GET /v1/files/:id`, `DELETE /v1/files/:id`
//!   - bytes:    `POST /v1/files` (multipart upload), `GET /v1/files/:id/content` (decrypt+stream)
//!
//! House style: thin handlers over `storage::files` + the store, `LocalResult<_>` with `?`
//! propagation, no auth layer here (server.rs applies the loopback bearer + Origin/Host middleware
//! at the router level). Nothing plaintext is ever written to disk by the upload path.

use crate::local::config::Paths;
use crate::local::error::{LocalError, LocalResult};
use crate::local::server::AppState;
use crate::local::storage;
use crate::local::store::stored_files::{self, StoredFile};
use axum::body::Body;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Default page size for the list endpoint when `?limit=` is omitted.
const DEFAULT_LIMIT: i64 = 100;
/// Hard cap so a client cannot ask for an unbounded scan.
const MAX_LIMIT: i64 = 500;
/// Upload size ceiling (50 MiB) — defense against a runaway multipart body filling memory/disk.
const MAX_UPLOAD_BYTES: usize = 50 * 1024 * 1024;

/// Wire shape returned by `/v1/files` — the OpenAI Files-API contract the frontends
/// consume (`bytes` not `size_bytes`, `created_at` as UNIX epoch int not RFC3339,
/// no internal columns like `storage_key`/`deleted_at`/`meta`). Build via
/// `WireStoredFile::from(row)`.
#[derive(Debug, Serialize)]
struct WireStoredFile {
    id: String,
    object: &'static str,
    filename: String,
    content_type: String,
    /// Size in bytes (renamed from `size_bytes`).
    bytes: i64,
    /// UNIX epoch seconds (converted from the row's RFC3339 `created_at`).
    created_at: i64,
    status: String,
    source: String,
    purpose: String,
}

impl From<StoredFile> for WireStoredFile {
    fn from(row: StoredFile) -> Self {
        // Parse the row's RFC3339 `created_at` back to epoch seconds. If the
        // string is malformed (shouldn't be — SQLite emits `%Y-%m-%dT%H:%M:%fZ`),
        // fall back to 0 so the UI shows "unknown time" rather than "Invalid date".
        let created_at = chrono::DateTime::parse_from_rfc3339(&row.created_at)
            .map(|dt| dt.timestamp())
            .unwrap_or(0);
        WireStoredFile {
            id: row.id,
            object: "file",
            filename: row.filename,
            content_type: row.content_type,
            bytes: row.size_bytes,
            created_at,
            status: row.status,
            source: row.source,
            purpose: row.purpose.unwrap_or_else(|| "user_data".to_string()),
        }
    }
}

/// Mount the file routes onto the shared `AppState` router. Auth is applied by `server.rs`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/files", get(list).post(upload))
        .route("/v1/files/from-data", axum::routing::post(from_data))
        .route("/v1/files/:id", get(get_one).delete(remove))
        .route("/v1/files/:id/content", get(download))
}

/// Resolve the app's filesystem layout. `AppState` carries config but not `Paths`, so we resolve
/// the canonical `~/.writ/` (or `$WRIT_HOME`) layout — the same root the daemon booted from.
fn paths() -> LocalResult<Paths> {
    Paths::resolve()
}

#[derive(Debug, Default, Deserialize)]
struct ListQuery {
    limit: Option<i64>,
    /// Optional `source` filter: upload|api|workflow_output.
    #[serde(default)]
    source: Option<String>,
}

impl ListQuery {
    /// Clamp the requested limit into `1..=MAX_LIMIT`, defaulting when unset.
    fn limit(&self) -> i64 {
        self.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
    }
}

/// `GET /v1/files` — newest-first list of live (not soft-deleted) file handles, capped by `?limit`.
/// Optionally filtered by `?source=`.
async fn list(State(st): State<AppState>, Query(q): Query<ListQuery>) -> LocalResult<Json<Value>> {
    let rows: Vec<StoredFile> = match q.source.as_deref() {
        Some(src) => stored_files::list_by_source(&st.db, src, Some(q.limit())).await?,
        None => stored_files::list(&st.db, Some(q.limit())).await?,
    };
    let wire: Vec<WireStoredFile> = rows.into_iter().map(WireStoredFile::from).collect();
    let count = wire.len();
    Ok(Json(json!({ "data": wire, "count": count })))
}

/// `GET /v1/files/:id` — one live file's metadata or 404 (soft-deleted handles read as absent here).
async fn get_one(State(st): State<AppState>, Path(id): Path<String>) -> LocalResult<Json<WireStoredFile>> {
    let row = stored_files::get_active(&st.db, &id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("file {id}")))?;
    Ok(Json(row.into()))
}

/// `POST /v1/files` — multipart upload. Reads the first `file` part (any field name is accepted,
/// but a part with a filename wins), encrypts-at-rest, and registers an `source='upload'` handle.
/// An optional `source` text part can override the source (e.g. `api`). Returns the new handle.
async fn upload(State(st): State<AppState>, mut mp: Multipart) -> LocalResult<Json<WireStoredFile>> {
    let paths = paths()?;
    let mut bytes: Option<Vec<u8>> = None;
    let mut filename = String::new();
    let mut content_type: Option<String> = None;
    let mut source = "upload".to_string();

    while let Some(mut field) = mp
        .next_field()
        .await
        .map_err(|e| LocalError::BadRequest(format!("multipart read failed: {e}")))?
    {
        let name = field.name().unwrap_or("").to_string();
        let part_filename = field.file_name().map(str::to_string);
        let part_ct = field.content_type().map(str::to_string);

        if part_filename.is_some() || name == "file" {
            // The file content part.
            if let Some(fname) = part_filename {
                filename = fname;
            }
            content_type = part_ct;
            // STREAM the part and enforce the ceiling as we go.
            //
            // `field.bytes()` buffers the whole part into memory FIRST and only then could the size be
            // checked — and axum's `Multipart` reads the request body itself, so `DefaultBodyLimit`
            // never applies to it either. Between the two, an unauthenticated-at-this-layer client
            // could make the daemon allocate an arbitrarily large `Vec` before the 50 MiB rule was
            // consulted. Now the very first chunk that would cross the line ends the request, so at
            // most one chunk beyond the limit is ever held.
            let mut data: Vec<u8> = Vec::new();
            while let Some(chunk) = field
                .chunk()
                .await
                .map_err(|e| LocalError::BadRequest(format!("reading file part failed: {e}")))?
            {
                if data.len() + chunk.len() > MAX_UPLOAD_BYTES {
                    return Err(LocalError::BadRequest(format!(
                        "upload exceeds {MAX_UPLOAD_BYTES} bytes"
                    )));
                }
                data.extend_from_slice(&chunk);
            }
            bytes = Some(data);
        } else if name == "source" {
            // Optional source override (text part).
            let txt = field
                .text()
                .await
                .map_err(|e| LocalError::BadRequest(format!("reading source part failed: {e}")))?;
            let txt = txt.trim();
            if matches!(txt, "upload" | "api" | "workflow_output") {
                source = txt.to_string();
            }
        }
    }

    let bytes = bytes.ok_or_else(|| LocalError::BadRequest("no file part in multipart body".into()))?;
    if filename.is_empty() {
        filename = "upload.bin".to_string();
    }
    // Strip any path components a client may have smuggled into the filename.
    let filename = std::path::Path::new(&filename)
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("upload.bin")
        .to_string();

    let row = storage::create_file(
        &st.db,
        &st.vault,
        &paths,
        &bytes,
        &filename,
        content_type.as_deref(),
        &source,
    )
    .await?;
    Ok(Json(row.into()))
}

/// Body for `POST /v1/files/from-data` — export a workflow's extracted data into a StoredFile.
#[derive(Debug, Deserialize)]
struct FromDataBody {
    workflow_id: i64,
    /// `csv` (default) or `json`.
    #[serde(default)]
    format: Option<String>,
    /// Optional structured-filter array (same schema as the data table's `filters` param).
    #[serde(default)]
    filters: Option<Value>,
}

/// `POST /v1/files/from-data` `{ workflow_id, format?, filters? }` — export the workflow's extracted
/// data (via the shared `data::export_workflow_data_bytes`, which applies the SAME `strip_meta` +
/// `redact_secret_keys` redaction the Data surface uses) into an encrypted-at-rest StoredFile with
/// `source = "workflow_output"`. Returns the new `StoredFile` handle.
async fn from_data(
    State(st): State<AppState>,
    Json(body): Json<FromDataBody>,
) -> LocalResult<Json<WireStoredFile>> {
    let paths = paths()?;
    let format = body.format.as_deref().unwrap_or("csv");
    let filters_str = body.filters.as_ref().map(|v| v.to_string());
    let (bytes, filename, content_type) = super::data::export_workflow_data_bytes(
        &st.db,
        body.workflow_id,
        format,
        filters_str.as_deref(),
    )
    .await?;
    let row = storage::create_file(
        &st.db,
        &st.vault,
        &paths,
        &bytes,
        &filename,
        Some(&content_type),
        "workflow_output",
    )
    .await?;
    Ok(Json(row.into()))
}

/// `GET /v1/files/:id/content` — decrypt the handle's bytes and stream them with the recorded
/// content-type + an `attachment` disposition carrying the original filename. 404 if the handle is
/// absent/soft-deleted or its blob is missing on disk.
async fn download(State(st): State<AppState>, Path(id): Path<String>) -> LocalResult<Response> {
    let paths = paths()?;
    // Pull metadata first so we can set headers (and 404 cleanly before touching disk).
    let row = stored_files::get_active(&st.db, &id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("file {id}")))?;
    let bytes = storage::read_file_bytes(&st.db, &st.vault, &paths, &id).await?;

    // Sanitize the filename for the Content-Disposition header (no CR/LF/quote injection).
    let safe_name: String = row
        .filename
        .chars()
        .filter(|c| !c.is_control() && *c != '"' && *c != '\\')
        .collect();
    let disposition = format!("attachment; filename=\"{safe_name}\"");

    let resp = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, row.content_type)
        .header(header::CONTENT_LENGTH, bytes.len())
        .header(header::CONTENT_DISPOSITION, disposition)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(bytes))
        .map_err(|e| LocalError::Internal(format!("building file response: {e}")))?;
    Ok(resp.into_response())
}

/// `DELETE /v1/files/:id` — soft-delete the handle (stamps `deleted_at`, status `deleted`); the
/// on-disk bytes are reclaimed separately by storage GC. 404 if absent or already deleted.
async fn remove(State(st): State<AppState>, Path(id): Path<String>) -> LocalResult<Json<Value>> {
    let removed = stored_files::soft_delete(&st.db, &id).await?;
    if !removed {
        return Err(LocalError::NotFound(format!("file {id}")));
    }
    Ok(Json(json!({ "id": id, "deleted": true })))
}
