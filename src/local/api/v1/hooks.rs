//! `/v1/hooks/{token}` — BEARER-EXEMPT inbound webhook ingress.
//!
//! This is the only `/v1` route that does NOT pass the loopback bearer layer: it is mounted on the
//! same router as everything else, but `server::auth_mw` allowlists the `/v1/hooks/` prefix and lets
//! it through WITHOUT requiring a `wlt_`/`wlk_` bearer. (The loopback Origin/Host guard still
//! applies — the daemon is loopback-bound regardless.) Authentication is instead out-of-band:
//!   * the unguessable trigger `token` in the path selects the `webhook_triggers` row, and
//!   * if that row has a `secret_encrypted` (a WF1 Layer-B blob holding the shared HMAC secret), the
//!     caller MUST present a matching `X-Writ-Signature` header — HMAC-SHA256(secret, raw_body),
//!     hex-encoded (a `sha256=` prefix is tolerated) — verified constant-time over the EXACT bytes.
//!
//! On a verified hit we map the JSON body through the trigger's `payload_mapping` into the engine
//! `inputs`, dispatch the linked workflow as `RunSource::Webhook`, bump `trigger_count`, and return
//! `{ run_id, ... }`. When the trigger is configured `wait_for_result`, the run is awaited inline and
//! its `RunResult` is included; otherwise the run is awaited too (the in-process engine is
//! synchronous — there is no background queue here) but the response is shaped as an acknowledgement.
//!
//! House style: thin handler over `store::webhook_triggers` + the `LocalEngine` seam; `tracing` only
//! and NEVER logs the secret, the signature, or the payload values; no `async-trait`.

use crate::local::engine::{Lane, RunRequest, RunSource};
use crate::local::error::{LocalError, LocalResult};
use crate::local::flow;
use crate::local::server::AppState;
use crate::local::store::webhook_triggers::{self, WebhookTrigger};
use crate::local::store::automations;
use crate::local::{auth, vault::Vault};
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Header carrying the HMAC-SHA256 of the raw body (hex; a `sha256=` prefix is tolerated).
const SIGNATURE_HEADER: &str = "x-writ-signature";

/// Mount the webhook ingress route. NOTE: `server::auth_mw` exempts the `/v1/hooks/` prefix from the
/// bearer layer — do not rely on a bearer being present in this handler.
pub fn router() -> Router<AppState> {
    Router::new().route("/v1/hooks/:token", post(ingress))
}

/// Build the row-binding AAD for a trigger's `secret_encrypted` column (anti-relocation). `id` is the
/// stable PK, mirroring the `vault_secrets`/`workflows` AAD convention (`table|column|row`).
fn secret_aad(id: i64) -> String {
    format!("webhook_triggers|secret_encrypted|{id}")
}

/// `POST /v1/hooks/{token}` — resolve the trigger, (optionally) verify the HMAC signature, map the
/// payload to inputs, dispatch the linked workflow, and bump the fire counter.
///
/// We take the RAW body as `Bytes` (not `Json`) so the HMAC is computed over the exact bytes the
/// caller signed; the JSON is parsed afterwards for payload mapping. An empty body maps to `{}`.
async fn ingress(
    State(st): State<AppState>,
    Path(token): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> LocalResult<Json<Value>> {
    // 1. Resolve the trigger by its unguessable token. Unknown/disabled → 404 (don't disclose which).
    let trigger = webhook_triggers::get_by_token(&st.db, &token)
        .await?
        .filter(|t| t.enabled != 0)
        .ok_or_else(|| LocalError::NotFound("webhook trigger".into()))?;

    // 2. If the trigger has a shared secret, the body MUST carry a matching HMAC signature.
    verify_signature(&st.vault, &trigger, &headers, &body)?;

    // 3. This local ingress only dispatches workflow runs (target checks are a separate path).
    if trigger.action != "run_workflow" {
        return Err(LocalError::BadRequest(format!(
            "webhook action '{}' is not supported by the local ingress",
            trigger.action
        )));
    }

    // 4. Parse the JSON body (empty → {}) and map it to engine inputs via `payload_mapping`.
    let payload: Value = if body.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| LocalError::BadRequest(format!("webhook body is not valid JSON: {e}")))?
    };
    let inputs = map_payload(trigger.payload_mapping.as_deref(), &payload);

    // 5. If an enabled `webhook_received` automation with an executable block tree is bound to this
    //    trigger, run its FLOW (conditions / branches / multiple actions) instead of a bare workflow.
    //    The interpreter owns the execution-row lifecycle and may drive several workflows.
    let flow_auto = automations::find_by_webhook_trigger(&st.db, trigger.id)
        .await
        .ok()
        .flatten()
        .filter(|a| flow::has_executable_tree(a.blocks.as_deref()));

    if let Some(auto) = flow_auto {
        tracing::info!(
            webhook_trigger_id = trigger.id,
            automation_id = auto.id,
            "webhook ingress: dispatching automation flow"
        );
        let exec = flow::run_automation(
            &st.db,
            &st.engine,
            &auto,
            flow::FlowTrigger {
                event: "webhook_received".to_string(),
                change_id: None,
                base_inputs: inputs,
                context: json!({ "event": "webhook_received", "payload": payload }),
                source: RunSource::Webhook,
                lane: Lane::Background,
            },
        )
        .await?;
        let _ = webhook_triggers::mark_triggered(&st.db, trigger.id).await;

        let (execution_id, status, results) = match exec {
            Some(e) => (
                Some(e.id),
                e.status.clone(),
                serde_json::from_str::<Value>(&e.action_results).unwrap_or(Value::Null),
            ),
            None => (None, Some("skipped".into()), Value::Null),
        };
        return Ok(Json(if trigger.wait_for_result != 0 {
            json!({ "execution_id": execution_id, "status": status, "results": results, "accepted": true })
        } else {
            json!({ "execution_id": execution_id, "accepted": true })
        }));
    }

    // 6. No flow bound → legacy single-workflow dispatch (requires a linked workflow).
    let workflow_id = trigger.workflow_id.ok_or_else(|| {
        LocalError::BadRequest("webhook trigger has no linked workflow".into())
    })?;
    let req = RunRequest {
        workflow_id,
        inputs,
        source: RunSource::Webhook,
        lane: Lane::Background,
        dry_run: false,
        persona_id: None,
        allow_local_secret_refs: true,
    };
    tracing::info!(
        webhook_trigger_id = trigger.id,
        workflow_id,
        "webhook ingress: dispatching run"
    );
    let result = st.engine.run(req).await?;

    // 7. Record the fire (best-effort; never fail the response on a counter write).
    let _ = webhook_triggers::mark_triggered(&st.db, trigger.id).await;

    // 8. Shape the response. `wait_for_result` callers get the full RunResult inline.
    if trigger.wait_for_result != 0 {
        Ok(Json(json!({
            "run_id": result.run_id,
            "status": result.status,
            "success": result.success,
            "result": serde_json::to_value(&result).unwrap_or(Value::Null),
        })))
    } else {
        Ok(Json(json!({
            "run_id": result.run_id,
            "accepted": true,
        })))
    }
}

/// Verify the HMAC signature when the trigger declares a secret. Fail-closed: a secret-bearing
/// trigger with a missing/garbled/mismatching signature is `401 Unauthorized`. Triggers with NO
/// secret skip verification (the unguessable token is the only credential).
fn verify_signature(
    vault: &Vault,
    trigger: &WebhookTrigger,
    headers: &HeaderMap,
    body: &[u8],
) -> LocalResult<()> {
    let Some(blob) = trigger.secret_encrypted.as_deref().filter(|s| !s.is_empty()) else {
        return Ok(()); // no shared secret → token-only auth
    };

    // Open the shared secret (WF1 Layer-B, row-bound AAD). NEVER log the plaintext.
    let secret = vault.open_field(blob, &secret_aad(trigger.id)).map_err(|_| {
        tracing::warn!(webhook_trigger_id = trigger.id, "could not open webhook secret");
        LocalError::Unauthorized
    })?;

    // Pull + normalize the presented signature (tolerate a `sha256=` scheme prefix; hex, any case).
    let presented = headers
        .get(SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim())
        .map(|s| s.strip_prefix("sha256=").unwrap_or(s))
        .ok_or(LocalError::Unauthorized)?;
    let presented_bytes = match decode_hex(presented) {
        Some(b) => b,
        None => return Err(LocalError::Unauthorized),
    };

    // Compute HMAC-SHA256(secret, raw_body) and compare constant-time. `new_from_slice` accepts any
    // key length, so a malformed (e.g. empty) secret never panics.
    let mut mac =
        HmacSha256::new_from_slice(&secret).map_err(|_| LocalError::Unauthorized)?;
    mac.update(body);
    let expected = mac.finalize().into_bytes();

    if auth::ct_eq(&presented_bytes, &expected) {
        Ok(())
    } else {
        tracing::warn!(webhook_trigger_id = trigger.id, "webhook signature mismatch");
        Err(LocalError::Unauthorized)
    }
}

/// Decode a lowercase/uppercase hex string into bytes. Returns `None` on odd length or a non-hex
/// nibble (treated as an auth failure upstream — never a 500).
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

/// Map the inbound JSON payload to the engine `inputs` object using the trigger's `payload_mapping`.
///
/// `payload_mapping` is an optional JSON-TEXT object of `{ input_name -> source_path }` where
/// `source_path` is a dot path into the payload (e.g. `"order.id"`). When mapping is absent OR not a
/// JSON object, the payload is forwarded as-is when it is itself an object (sensible default), else
/// wrapped as `{"payload": <value>}`. Missing source paths are simply omitted.
fn map_payload(payload_mapping: Option<&str>, payload: &Value) -> Value {
    let mapping = payload_mapping
        .filter(|s| !s.trim().is_empty())
        .and_then(|s| serde_json::from_str::<Value>(s).ok());

    match mapping.as_ref().and_then(|m| m.as_object()) {
        Some(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (input_name, source) in map {
                if let Some(path) = source.as_str() {
                    if let Some(v) = lookup_path(payload, path) {
                        out.insert(input_name.clone(), v.clone());
                    }
                }
            }
            Value::Object(out)
        }
        // No usable mapping: pass an object payload straight through; otherwise wrap it.
        None => match payload {
            Value::Object(_) => payload.clone(),
            other => json!({ "payload": other }),
        },
    }
}

/// Resolve a dot-separated path (`a.b.c`) into a JSON value. Returns `None` if any segment is absent
/// or a non-object is traversed. Array indexing is not supported (keep the mapping grammar simple).
fn lookup_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = value;
    for seg in path.split('.') {
        cur = cur.as_object()?.get(seg)?;
    }
    Some(cur)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::engine::StubEngine;
    use crate::local::store::webhook_triggers::NewWebhookTrigger;
    use crate::local::vault::Vault;
    use std::sync::Arc;

    async fn state() -> AppState {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let vault = Arc::new(Vault::load_or_create(dir.path(), false).unwrap());
        let pool = crate::local::db::open(&dir.path().join("t.db"), &vault.db_key_hex())
            .await
            .unwrap();
        AppState {
            db: pool,
            vault,
            engine: Arc::new(StubEngine),
            config: crate::local::config::LocalConfig::default(),
            token: Arc::new("wlt_test".to_string()),
            health: crate::local::app::health::DaemonHealth::shared(),
            recorder: None,
        }
    }

    fn hmac_hex(secret: &[u8], body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(body);
        mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn hex_roundtrip_and_rejects_garbage() {
        assert_eq!(decode_hex("00ff10"), Some(vec![0x00, 0xff, 0x10]));
        assert_eq!(decode_hex("DEADbeef"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(decode_hex("abc"), None); // odd length
        assert_eq!(decode_hex("zz"), None); // non-hex
        assert_eq!(decode_hex(""), None);
    }

    #[test]
    fn payload_mapping_dot_paths() {
        let payload = json!({ "order": { "id": "A-1", "qty": 3 }, "ignored": true });
        let mapping = r#"{ "order_id": "order.id", "count": "order.qty", "missing": "x.y" }"#;
        let out = map_payload(Some(mapping), &payload);
        assert_eq!(out["order_id"], "A-1");
        assert_eq!(out["count"], 3);
        assert!(out.get("missing").is_none(), "absent paths are omitted");
    }

    #[test]
    fn payload_passthrough_without_mapping() {
        let obj = json!({ "a": 1 });
        assert_eq!(map_payload(None, &obj), obj);
        // A non-object body with no mapping is wrapped.
        let scalar = json!("hello");
        assert_eq!(map_payload(None, &scalar), json!({ "payload": "hello" }));
        // Blank mapping is treated as absent.
        assert_eq!(map_payload(Some("   "), &obj), obj);
    }

    #[tokio::test]
    async fn no_secret_skips_signature_check() {
        let st = state().await;
        let t = webhook_triggers::insert(
            &st.db,
            &NewWebhookTrigger { token: "tok".into(), name: "n".into(), ..Default::default() },
        )
        .await
        .unwrap();
        let headers = HeaderMap::new();
        // No secret → Ok regardless of headers/body.
        assert!(verify_signature(&st.vault, &t, &headers, b"anything").is_ok());
    }

    #[tokio::test]
    async fn secret_requires_matching_hmac() {
        let st = state().await;
        // Seal a shared secret bound to the row's AAD (mirrors what the create path would do).
        let secret = b"super-secret-shared-key";
        let mut t = webhook_triggers::insert(
            &st.db,
            &NewWebhookTrigger { token: "tok2".into(), name: "n".into(), ..Default::default() },
        )
        .await
        .unwrap();
        let blob = st.vault.seal_field(secret, &secret_aad(t.id)).unwrap();
        t.secret_encrypted = Some(blob);

        let body = br#"{"order":{"id":"A-1"}}"#;
        let good = hmac_hex(secret, body);

        // Correct signature (with + without the `sha256=` prefix) verifies.
        let mut headers = HeaderMap::new();
        headers.insert(SIGNATURE_HEADER, good.parse().unwrap());
        assert!(verify_signature(&st.vault, &t, &headers, body).is_ok());

        let mut headers2 = HeaderMap::new();
        headers2.insert(SIGNATURE_HEADER, format!("sha256={good}").parse().unwrap());
        assert!(verify_signature(&st.vault, &t, &headers2, body).is_ok());

        // Wrong signature → Unauthorized.
        let mut bad = HeaderMap::new();
        bad.insert(SIGNATURE_HEADER, hmac_hex(b"wrong-key", body).parse().unwrap());
        assert!(matches!(
            verify_signature(&st.vault, &t, &bad, body),
            Err(LocalError::Unauthorized)
        ));

        // Missing signature header → Unauthorized.
        let empty = HeaderMap::new();
        assert!(matches!(
            verify_signature(&st.vault, &t, &empty, body),
            Err(LocalError::Unauthorized)
        ));

        // Tampered body (same signature) → Unauthorized.
        let mut headers3 = HeaderMap::new();
        headers3.insert(SIGNATURE_HEADER, good.parse().unwrap());
        assert!(matches!(
            verify_signature(&st.vault, &t, &headers3, br#"{"order":{"id":"TAMPERED"}}"#),
            Err(LocalError::Unauthorized)
        ));
    }
}
