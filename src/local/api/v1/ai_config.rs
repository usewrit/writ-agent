//! `/v1/ai/config` — read/update the AI provider configuration the local AI-assist uses.
//!
//! GET  `/v1/ai/config`        → { provider, model, base_url, has_api_key, providers:[...] }
//! PUT  `/v1/ai/config`        { provider, model, base_url?, api_key? } → same shape (updated)
//! POST `/v1/ai/config/test`   {} → { ok, error?, model? }   (does a tiny live completion)
//!
//! Non-secret fields live in the `config` KV table; the API key is VAULT-SEALED (never returned).
//! `api_key` semantics on PUT: omitted/null = leave unchanged, "" = clear, non-empty = set.

use crate::local::ai::provider;
use crate::local::error::LocalResult;
use crate::local::server::AppState;
use crate::models::ai::{AiMessage, AiMessageContent};
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/ai/config", get(get_config).put(put_config))
        .route("/v1/ai/config/test", post(test_config))
        .route("/v1/ai/config/cloud-gateway", post(set_cloud_gateway))
}

/// Build the public config view (never includes the key itself).
async fn config_view(st: &AppState) -> LocalResult<Value> {
    let cfg = provider::resolve_config(&st.db, &st.vault).await?;
    let has_api_key = provider::has_api_key(&st.db).await?;
    let providers: Vec<Value> = provider::provider_catalog()
        .into_iter()
        .map(|p| {
            json!({
                "id": p.id,
                "label": p.label,
                "needs_key": p.needs_key,
                "default_base_url": p.default_base_url,
                "default_model": p.default_model,
                "api_style": p.api_style,
            })
        })
        .collect();
    let (provider_id, model, base_url) = match cfg {
        Some(c) => (c.provider, c.model, c.base_url),
        None => (String::new(), String::new(), None),
    };
    // Per-feature output-token ceilings ("AI usage limits"). `limits` = the currently-stored caps
    // (null per bucket when unset); `limit_defaults` = the built-in budgets used when no cap is set.
    let limits = provider::read_limits(&st.db).await?;
    // Cloud AI gateway toggle: whether it's on, and whether it's usable (linked account required).
    let use_cloud_gateway = provider::cloud_gateway_enabled(&st.db).await;
    let cloud_gateway_available = cloud_linked(st).await;
    Ok(json!({
        "provider": provider_id,
        "model": model,
        "base_url": base_url,
        "has_api_key": has_api_key,
        "providers": providers,
        // The managed cloud AI gateway: `use_cloud_gateway` = routing is ON; `cloud_gateway_available`
        // = a linked account exists so the toggle can be enabled (gated in the UI).
        "use_cloud_gateway": use_cloud_gateway,
        "cloud_gateway_available": cloud_gateway_available,
        "limits": {
            "agent": limits.agent,
            "assist": limits.assist,
            "optimize": limits.optimize,
        },
        "limit_defaults": {
            "agent": provider::DEFAULT_MAX_TOKENS_AGENT,
            "assist": provider::DEFAULT_MAX_TOKENS_ASSIST,
            "optimize": provider::DEFAULT_MAX_TOKENS_OPTIMIZE,
        },
    }))
}

/// Whether a linked cloud account exists (so the cloud AI gateway toggle is usable). Always false in
/// the cloud-free OSS build. A load error is treated as "not linked" so the UI fails closed.
async fn cloud_linked(_st: &AppState) -> bool {
    #[cfg(feature = "cloud")]
    {
        matches!(
            crate::local::cloud::state::LinkState::load(&_st.db).await,
            Ok(Some(link)) if link.is_linked()
        )
    }
    #[cfg(not(feature = "cloud"))]
    {
        false
    }
}

async fn get_config(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    Ok(Json(config_view(&st).await?))
}

#[derive(Debug, Deserialize)]
struct PutBody {
    provider: String,
    #[serde(default)]
    model: String,
    #[serde(default)]
    base_url: Option<String>,
    /// Omitted/null = leave the stored key unchanged; "" = clear; non-empty = set.
    #[serde(default)]
    api_key: Option<String>,
    /// Per-feature AI output-token ceilings. Omitted = leave all caps unchanged; present = apply the
    /// provided bucket fields (each field: omitted = unchanged, null/≤0 = clear, positive = set).
    #[serde(default)]
    limits: Option<AiLimitsUpdate>,
}

/// A partial update to the per-feature caps. Each field is a DOUBLE Option so the handler can tell
/// "field omitted" (`None` → leave unchanged) from "field present but null" (`Some(None)` → clear).
#[derive(Debug, Default, Deserialize)]
struct AiLimitsUpdate {
    #[serde(default, deserialize_with = "de_opt_opt_u32")]
    agent: Option<Option<u32>>,
    #[serde(default, deserialize_with = "de_opt_opt_u32")]
    assist: Option<Option<u32>>,
    #[serde(default, deserialize_with = "de_opt_opt_u32")]
    optimize: Option<Option<u32>>,
}

/// Deserialize a present field into `Some(Option<u32>)` (explicit `null` → `Some(None)`), while a
/// missing field is left as `None` by `#[serde(default)]`. This is the double-Option pattern that
/// distinguishes "omitted" from "present but null".
fn de_opt_opt_u32<'de, D>(de: D) -> Result<Option<Option<u32>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Some(Option::<u32>::deserialize(de)?))
}

async fn put_config(State(st): State<AppState>, Json(body): Json<PutBody>) -> LocalResult<Json<Value>> {
    if body.provider.trim().is_empty() {
        return Err(crate::local::error::LocalError::BadRequest("provider is required".into()));
    }
    provider::save_config(
        &st.db,
        &st.vault,
        body.provider.trim(),
        body.model.trim(),
        body.base_url.as_deref(),
        body.api_key.as_deref(),
    )
    .await?;
    // Apply per-feature caps only when `limits` is present. For each provided bucket, a positive
    // value is stored (clamped) and null/≤0 clears the cap; an omitted bucket is left untouched.
    if let Some(update) = body.limits {
        for (bucket, field) in [
            ("agent", update.agent),
            ("assist", update.assist),
            ("optimize", update.optimize),
        ] {
            if let Some(cap) = field {
                provider::set_limit(&st.db, bucket, cap).await?;
            }
        }
    }
    Ok(Json(config_view(&st).await?))
}

/// Body for `POST /v1/ai/config/cloud-gateway` — a one-click toggle to route ALL local AI through the
/// managed cloud gateway. Independent of the provider form so a user with no local key can still turn
/// it on. Enabling requires a linked account.
#[derive(Debug, Deserialize)]
struct CloudGatewayBody {
    enabled: bool,
}

async fn set_cloud_gateway(State(st): State<AppState>, Json(body): Json<CloudGatewayBody>) -> LocalResult<Json<Value>> {
    if body.enabled && !cloud_linked(&st).await {
        return Err(crate::local::error::LocalError::BadRequest(
            "Link your cloud account first to use the managed AI gateway.".into(),
        ));
    }
    provider::set_cloud_gateway(&st.db, body.enabled).await?;
    Ok(Json(config_view(&st).await?))
}

/// Optional body for `/v1/ai/config/test` — the values currently in the Settings form. When a
/// `provider` is supplied we test THOSE values (no save required); otherwise we test the stored
/// config. The key field, when left untouched (omitted), falls back to the stored (decrypted) key so
/// the user can re-test a model/base-URL change without re-entering a saved key.
#[derive(Debug, Default, Deserialize)]
struct TestBody {
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    base_url: Option<String>,
    #[serde(default)]
    api_key: Option<String>,
}

async fn test_config(State(st): State<AppState>, body: Option<Json<TestBody>>) -> LocalResult<Json<Value>> {
    let body = body.map(|Json(b)| b).unwrap_or_default();
    // The stored config (with its decrypted key) — both the no-body fallback AND the key fallback.
    let stored = provider::resolve_config(&st.db, &st.vault).await?;

    let cfg = match body.provider.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
        // Test the form values directly — works BEFORE the user saves.
        Some(provider) => {
            let api_key = match body.api_key.as_deref() {
                Some(k) if !k.is_empty() => Some(k.to_string()),
                // Key field untouched → reuse the stored (decrypted) key if there is one.
                _ => stored.as_ref().and_then(|c| c.api_key.clone()),
            };
            let base_url = body
                .base_url
                .as_deref()
                .map(str::trim)
                .filter(|b| !b.is_empty())
                .map(|b| b.to_string());
            provider::AiConfig {
                provider: provider.to_string(),
                model: body.model.unwrap_or_default().trim().to_string(),
                base_url,
                api_key,
            }
        }
        // No form values → fall back to the stored config.
        None => match stored {
            Some(c) if !c.provider.trim().is_empty() => c,
            _ => return Ok(Json(json!({ "ok": false, "error": "No AI provider configured." }))),
        },
    };

    let messages = vec![AiMessage {
        role: "user".into(),
        content: AiMessageContent::Text("Reply with exactly: ok".into()),
    }];
    match provider::complete(&cfg, &messages, Some("You are a connectivity check. Reply with the single word: ok"), 16).await {
        Ok(c) => Ok(Json(json!({ "ok": true, "model": c.model }))),
        Err(e) => Ok(Json(json!({ "ok": false, "error": e.to_string() }))),
    }
}
