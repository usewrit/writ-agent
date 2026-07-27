//! `/v1/keys` REST handlers — list/create/delete over `store::local_api_keys`.
//!
//! These are the scoped `wlk_` keys external clients/agents (Claude Desktop, n8n, ...) use to call
//! the local API. SECURITY CONTRACT (LOCAL_BACKEND_SPEC §9): the RAW key is generated server-side,
//! shown EXACTLY ONCE in the create response, and NEVER persisted — we store only the `prefix`
//! (`wlk_` + first 6 chars, for UI) and the `key_hash` (sha256 of the full key). The `key_hash` is
//! `#[serde(skip_serializing)]` on the row struct, so it can never leak through list/get responses.
//!
//! House style: thin handlers over the store, `LocalResult<Json<_>>` with `?` propagation, no auth
//! layer here (server.rs applies the loopback bearer + Origin/Host middleware at the router level).

use crate::local::error::{LocalError, LocalResult};
use crate::local::server::AppState;
use crate::local::store::local_api_keys::{self, LocalApiKey, NewLocalApiKey};
use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine;
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Default page size for the list endpoint when `?limit=` is omitted.
const DEFAULT_LIMIT: i64 = 100;
/// Hard cap so a client cannot ask for an unbounded scan.
const MAX_LIMIT: i64 = 200;
/// Raw-key prefix surfaced to clients (matches the schema's `wlk_` convention).
const KEY_PREFIX: &str = "wlk_";

/// Mount the API-key routes onto the shared `AppState` router. Auth is applied by `server.rs`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/keys", get(list).post(create))
        .route("/v1/keys/:id", get(get_one).delete(remove))
}

#[derive(Debug, Default, Deserialize)]
struct ListQuery {
    limit: Option<i64>,
}

impl ListQuery {
    /// Clamp the requested limit into `1..=MAX_LIMIT`, defaulting when unset.
    fn limit(&self) -> i64 {
        self.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
    }
}

/// Body for `POST /v1/keys`. The caller names + scopes the key; the raw secret is minted server-side.
#[derive(Debug, Deserialize)]
struct CreateBody {
    name: String,
    /// CSV scopes (read|run|admin). Defaults to `"run"` at the store layer when omitted.
    #[serde(default)]
    scopes: Option<String>,
}

/// Lowercase-hex encode a byte slice (matches the crate's `sha2` digest-to-hex idiom).
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// `GET /v1/keys` — newest-first list of key records. `key_hash` is never serialized (struct attr).
async fn list(State(st): State<AppState>, Query(q): Query<ListQuery>) -> LocalResult<Json<Value>> {
    let rows = local_api_keys::list(&st.db, Some(q.limit())).await?;
    Ok(Json(json!({ "data": rows, "count": rows.len() })))
}

/// `POST /v1/keys` — mint a new scoped key. Generates a random `wlk_<...>` raw key, stores ONLY its
/// `prefix` + sha256 `key_hash`, and returns the raw `key` ONCE alongside the record. The raw key
/// cannot be recovered later — clients must capture it now.
async fn create(State(st): State<AppState>, Json(body): Json<CreateBody>) -> LocalResult<Json<Value>> {
    if body.name.trim().is_empty() {
        return Err(LocalError::BadRequest("name is required".into()));
    }

    // Mint a CSPRNG raw secret and format the full `wlk_<base64url>` key (mirrors the `wlt_` token).
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let body_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    let key = format!("{KEY_PREFIX}{body_b64}");

    // Prefix = `wlk_` + first 6 chars of the random body (safe to display in the UI).
    let prefix = format!("{KEY_PREFIX}{}", &body_b64[..body_b64.len().min(6)]);

    // key_hash = sha256(full raw key), hex. The raw key is never stored.
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let key_hash = hex(&hasher.finalize());

    let new = NewLocalApiKey {
        name: body.name,
        prefix,
        key_hash,
        scopes: body.scopes,
    };
    let row = local_api_keys::insert(&st.db, &new).await?;

    // Serialize the record (key_hash is skip_serializing) and inject the one-time raw `key`.
    let mut record = serde_json::to_value(&row)?;
    if let Some(obj) = record.as_object_mut() {
        obj.insert("key".to_string(), json!(key));
    }
    Ok(Json(record))
}

/// `GET /v1/keys/:id` — one key record or 404. `key_hash` is never serialized.
async fn get_one(State(st): State<AppState>, Path(id): Path<i64>) -> LocalResult<Json<LocalApiKey>> {
    let row = local_api_keys::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("api key {id}")))?;
    Ok(Json(row))
}

/// `DELETE /v1/keys/:id` — hard-delete a key record. 404 if absent.
async fn remove(State(st): State<AppState>, Path(id): Path<i64>) -> LocalResult<Json<Value>> {
    let removed = local_api_keys::delete(&st.db, id).await?;
    if !removed {
        return Err(LocalError::NotFound(format!("api key {id}")));
    }
    Ok(Json(json!({ "id": id, "deleted": true })))
}
